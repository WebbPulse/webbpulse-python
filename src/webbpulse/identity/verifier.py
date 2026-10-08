"""Verify an access token against the issuer's published JWKS, with no KMS grant.

`TokenService.verify_access_token` reads its keys through `kms:GetPublicKey`, so it is
available only where the signing key ARNs and that grant are, which is the identity
function alone. This module is the reader's half of the same contract: it fetches the
public key set over HTTPS from the issuer's discovery document and verifies RS256 with
`iss`, `aud`, `exp` and `nbf`, so any function holding only the issuer and audience can
resolve a bearer token in process.

The key set is cached across invocations. An unknown `kid` triggers at most one refetch
per `cooldown`, which is what lets a signing key rotation be picked up without turning an
unknown `kid` into an unbounded fetch loop.

`cached_verifier` hands out one verifier per issuer, audience and JWKS URI for the life of
the process, and `verified_bearer_subject` is the optional-auth read on top of it: the
`sub` of a verified Bearer token, or `""` for anything else.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Mapping, Sequence
from typing import TYPE_CHECKING, Any, Final

from webbpulse.identity.service import ACCESS_TOKEN_TYPE, InvalidToken
from webbpulse.identity.tokens import DISCOVERY_PATH, JWKS_PATH, JWS_ALGORITHM

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import Request

    from webbpulse.identity.settings import IdentitySettings

__all__ = [
    "DEFAULT_CACHE_LIFESPAN",
    "DEFAULT_COOLDOWN",
    "DEFAULT_TIMEOUT",
    "JwksVerifier",
    "cached_verifier",
    "clear_verifier_cache",
    "discovery_jwks_uri",
    "verified_bearer_subject",
]

DEFAULT_CACHE_LIFESPAN: Final = 600.0

DEFAULT_COOLDOWN: Final = 30.0

DEFAULT_TIMEOUT: Final = 3.0

_REQUIRED_CLAIMS: Final[list[str]] = ["exp", "iat", "iss", "sub"]

_log = logging.getLogger(__name__)


def discovery_jwks_uri(issuer: str, *, timeout: float = DEFAULT_TIMEOUT) -> str:
    """The `jwks_uri` the issuer's discovery document advertises.

    Read once at construction rather than per request. A discovery document that omits
    `jwks_uri`, or advertises one for a different issuer, is refused rather than guessed.
    """
    import json
    from urllib.request import urlopen

    normalised = issuer.rstrip("/")
    url = f"{normalised}{DISCOVERY_PATH}"
    with urlopen(url, timeout=timeout) as response:
        document = json.loads(response.read())

    if not isinstance(document, dict):
        raise InvalidToken(f"discovery document at {url} is not a JSON object")

    jwks_uri = document.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not jwks_uri:
        raise InvalidToken(f"discovery document at {url} advertises no jwks_uri")
    if not jwks_uri.startswith(f"{normalised}/"):
        raise InvalidToken(f"discovery document at {url} advertises a foreign jwks_uri")
    return jwks_uri


class JwksVerifier:
    """Verifies access tokens against the issuer's JWKS, caching the key set.

    Construct one per execution environment and reuse it: the cache lives on the
    instance, so a per-request instance would fetch the key set on every request.
    """

    def __init__(
        self,
        *,
        issuer: str,
        audience: str | Sequence[str],
        jwks_uri: str | None = None,
        leeway: float = 30.0,
        cache_lifespan: float = DEFAULT_CACHE_LIFESPAN,
        cooldown: float = DEFAULT_COOLDOWN,
        timeout: float = DEFAULT_TIMEOUT,
        client: Any | None = None,
    ) -> None:
        """Resolve the JWKS URI and build the cached key client.

        `jwks_uri` skips the discovery fetch, which is what a caller holding the URL
        directly should pass. `client` is for tests and is used as given.
        """
        if not issuer.strip():
            raise ValueError("issuer is required")
        if not audience:
            raise ValueError("audience is required")

        self._issuer = issuer.rstrip("/")
        self._audience = audience
        self._leeway = leeway
        self._lock = threading.Lock()

        if client is not None:
            self._client = client
            self._jwks_uri = jwks_uri or ""
            return

        self._jwks_uri = jwks_uri or f"{self._issuer}{JWKS_PATH}"

        from jwt import PyJWKClient

        self._client = PyJWKClient(
            self._jwks_uri,
            cache_jwk_set=True,
            lifespan=cache_lifespan,
            cooldown_duration=cooldown,
            timeout=timeout,
        )

    @classmethod
    def from_settings(
        cls, settings: IdentitySettings, *, accept_device_tokens: bool = False, **overrides: Any
    ) -> JwksVerifier:
        """A verifier for the issuer and audience these settings name.

        Reads no signing key ARN, so it builds on a function that has none.
        `accept_device_tokens` also accepts the device login audience
        (`settings.device_token_audience`), which a resource server serving a CLI opts into;
        such a server must also check `device_grant_is_live` for tokens carrying
        `grant: "device"`. Identity's own session routes never accept them.
        """
        audience: str | list[str] = settings.audience
        if accept_device_tokens:
            audience = [settings.audience, settings.device_token_audience]
        return cls(issuer=settings.issuer, audience=audience, **overrides)

    @property
    def jwks_uri(self) -> str:
        """The URL the key set is fetched from."""
        return self._jwks_uri

    def verify(self, token: str, *, expected_type: str | None = ACCESS_TOKEN_TYPE) -> dict[str, Any]:
        """Verify `token` and return its claims, or raise `InvalidToken`.

        RS256 only, and `alg` is checked against the header before any key is fetched so
        an `alg` confusion token is refused without a network call.
        """
        import jwt

        try:
            header = jwt.get_unverified_header(token)
        except Exception as exc:
            raise InvalidToken(f"malformed token header: {exc}") from exc

        if header.get("alg") != JWS_ALGORITHM:
            raise InvalidToken(f"unexpected alg {header.get('alg')!r}")
        if not header.get("kid"):
            raise InvalidToken("token header carries no kid")

        key = self._signing_key(token)

        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key=key,
                algorithms=[JWS_ALGORITHM],
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options={
                    "require": _REQUIRED_CLAIMS,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_signature": True,
                },
            )
        except Exception as exc:
            raise InvalidToken(str(exc)) from exc

        if expected_type is not None and claims.get("typ") != expected_type:
            raise InvalidToken(f"expected typ {expected_type!r}, got {claims.get('typ')!r}")
        return claims

    def _signing_key(self, token: str) -> Any:
        """The public key for this token's `kid`, from the cache or a bounded refetch."""
        with self._lock:
            try:
                return self._client.get_signing_key_from_jwt(token).key
            except Exception as exc:
                _log.debug("No JWKS signing key matched the token's kid.", exc_info=True)
                raise InvalidToken(f"no signing key for the token's kid: {exc}") from exc


_VERIFIERS: dict[tuple[str, tuple[str, ...], str], JwksVerifier] = {}

_VERIFIERS_LOCK = threading.Lock()


def _audiences(audience: str | Sequence[str]) -> tuple[str, ...]:
    """The non-blank audiences, stripped and de-duplicated in order."""
    values = [audience] if isinstance(audience, str) else list(audience)
    cleaned: list[str] = []
    for value in values:
        stripped = value.strip()
        if stripped and stripped not in cleaned:
            cleaned.append(stripped)
    return tuple(cleaned)


def cached_verifier(
    issuer: str,
    audience: str | Sequence[str],
    *,
    jwks_uri: str | None = None,
) -> JwksVerifier | None:
    """The process-wide `JwksVerifier` for this issuer, audience and JWKS URI, or None.

    None when the issuer or every audience is blank, which is how a function without the
    identity environment reads, and when the verifier cannot be built. Blank `jwks_uri`
    means the issuer's default. One instance per key, so its key set cache is shared by
    every caller in the execution environment.
    """
    normalised = issuer.strip().rstrip("/")
    audiences = _audiences(audience)
    if not normalised or not audiences:
        return None
    uri = (jwks_uri or "").strip()
    key = (normalised, audiences, uri)
    with _VERIFIERS_LOCK:
        verifier = _VERIFIERS.get(key)
        if verifier is not None:
            return verifier
        try:
            verifier = JwksVerifier(
                issuer=normalised,
                audience=audiences[0] if len(audiences) == 1 else list(audiences),
                jwks_uri=uri or None,
            )
        except Exception:
            _log.debug("Could not build a JWKS verifier for %s.", normalised, exc_info=True)
            return None
        _VERIFIERS[key] = verifier
        return verifier


def clear_verifier_cache() -> None:
    """Drop every verifier `cached_verifier` built. For tests that change the environment."""
    with _VERIFIERS_LOCK:
        _VERIFIERS.clear()


def verified_bearer_subject(
    request: Request,
    verifier: JwksVerifier | Callable[[str], Mapping[str, Any]] | None,
) -> str:
    """The `sub` of the request's Bearer token verified in process, or `""`.

    `verifier` is a `JwksVerifier` or any callable returning claims, such as
    `TokenService.verify_access_token`. No Bearer header, no verifier, or a token that does
    not verify all answer `""` rather than raise, so a bad or expired token on an optional
    auth route reads as an anonymous caller.
    """
    if verifier is None:
        return ""

    from webbpulse.identity.scopes import bearer_credential

    presented = bearer_credential(request)
    if not presented:
        return ""
    verify = verifier.verify if isinstance(verifier, JwksVerifier) else verifier
    try:
        claims = verify(presented)
    except Exception:
        _log.debug("A Bearer token did not verify.", exc_info=True)
        return ""
    subject = claims.get("sub")
    return subject if isinstance(subject, str) else ""
