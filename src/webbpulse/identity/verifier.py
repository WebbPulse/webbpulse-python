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
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, Final

from webbpulse.identity.service import ACCESS_TOKEN_TYPE, InvalidToken
from webbpulse.identity.tokens import DISCOVERY_PATH, JWKS_PATH, JWS_ALGORITHM

if TYPE_CHECKING:  # pragma: no cover
    from webbpulse.identity.settings import IdentitySettings

__all__ = [
    "DEFAULT_CACHE_LIFESPAN",
    "DEFAULT_COOLDOWN",
    "DEFAULT_TIMEOUT",
    "JwksVerifier",
    "discovery_jwks_uri",
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
    def from_settings(cls, settings: IdentitySettings, **overrides: Any) -> JwksVerifier:
        """A verifier for the issuer and audience these settings name.

        Reads no signing key ARN, so it builds on a function that has none.
        """
        return cls(issuer=settings.issuer, audience=settings.audience, **overrides)

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
