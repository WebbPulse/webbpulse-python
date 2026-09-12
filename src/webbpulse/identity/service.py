"""`TokenService`: minting, local verification, and the two documents, over rotating keys.

Wraps the one-key primitives in `tokens.py` into the multi-key service a product mounts,
where the head of `signing_key_arns` signs and every entry is served in the JWKS.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, Final

from webbpulse.identity.tokens import (
    JWS_ALGORITHM,
    KmsClient,
    KmsSigner,
    build_discovery_document,
    build_jwks,
    public_jwk_from_kms,
)

if TYPE_CHECKING:  # pragma: no cover
    from webbpulse.identity.settings import IdentitySettings

__all__ = [
    "ACCESS_TOKEN_TYPE",
    "MFA_TICKET_TYPE",
    "REGISTERED_CLAIMS",
    "InvalidToken",
    "TokenService",
]

REGISTERED_CLAIMS: Final[frozenset[str]] = frozenset({"iss", "sub", "aud", "exp", "iat", "nbf", "jti", "typ", "sid"})

ACCESS_TOKEN_TYPE: Final = "access"

MFA_TICKET_TYPE: Final = "mfa_ticket"

_log = logging.getLogger(__name__)


class InvalidToken(Exception):
    """Local verification rejected a token.

    One type for every reason, distinguished by `reason`. Safe to log but never to return
    to a caller, since the reason tells an attacker which half of the token to work on.
    """

    def __init__(self, reason: str) -> None:
        """Record the machine-readable reason verification failed."""
        super().__init__(reason)
        self.reason = reason


class TokenService:
    """Mints and verifies access tokens, and serves the JWKS and discovery documents.

    Construct one per execution environment: it caches a JWK per configured key. `client`
    is typed structurally by `KmsClient`, so this module imports no boto3.
    """

    def __init__(self, settings: IdentitySettings, client: KmsClient) -> None:
        """Build the signer for the active key and precompute the discovery document."""
        self._settings = settings
        self._client = client
        self._signer = KmsSigner(client, settings.active_signing_key_arn)
        self._jwk_cache: dict[str, dict[str, str]] = {}
        self._discovery = build_discovery_document(settings.issuer)

    @property
    def settings(self) -> IdentitySettings:
        """The identity settings this service was built from."""
        return self._settings

    @property
    def active_kid(self) -> str:
        """The `kid` new tokens are signed with. The head of `signing_key_arns`."""
        return self._signer.kid

    def discovery(self) -> dict[str, Any]:
        """The OIDC discovery document, built once at construction from the issuer."""
        return self._discovery

    def jwks(self) -> dict[str, Any]:
        """The JWKS, listing every configured key: the active one first, then the previous.

        A key whose `GetPublicKey` fails is omitted rather than fatal, since a failed JWKS
        denies every authorized request. Every key failing is still fatal.
        """
        keys: list[dict[str, str]] = []
        for key_id in self._settings.signing_key_arns:
            jwk = self._jwk_for(key_id)
            if jwk is not None:
                keys.append(jwk)
        if not keys:
            raise RuntimeError(
                "No signing key produced a JWK. Every key in IDENTITY_SIGNING_KEY_ARNS "
                "failed kms:GetPublicKey, so serving an empty JWKS would deny every "
                "authorized request until the gateway's cache expired."
            )
        return build_jwks(keys)

    def _jwk_for(self, key_id: str) -> dict[str, str] | None:
        """The cached JWK for this key id, or `None` when `GetPublicKey` fails."""
        cached = self._jwk_cache.get(key_id)
        if cached is not None:
            return cached
        try:
            jwk = public_jwk_from_kms(self._client, key_id)
        except Exception:
            _log.warning(
                "Signing key %s produced no JWK and is omitted from the JWKS.",
                key_id,
                exc_info=True,
            )
            return None
        self._jwk_cache[key_id] = jwk
        return jwk

    def mint_access_token(
        self,
        subject: str,
        *,
        claims: Mapping[str, Any] | None = None,
        audience: str | Sequence[str] | None = None,
        session_id: str | None = None,
        now: int | None = None,
    ) -> str:
        """A signed RS256 access token for `subject`.

        `claims` are the product's own; any registered claim among them is dropped rather
        than honoured. No `nbf` is set, since `iat` and `exp` already bound the window.
        """
        issued_at = int(time.time()) if now is None else now
        ttl = int(self._settings.access_token_ttl.total_seconds())

        payload: dict[str, Any] = {}
        if claims:
            payload.update({key: value for key, value in claims.items() if key not in REGISTERED_CLAIMS})
        payload.update(
            {
                "iss": self._settings.issuer,
                "sub": subject,
                "aud": list(audience) if isinstance(audience, (list, tuple)) else (audience or self._settings.audience),
                "iat": issued_at,
                "exp": issued_at + ttl,
                "jti": uuid.uuid4().hex,
                "typ": ACCESS_TOKEN_TYPE,
            }
        )
        if session_id:
            payload["sid"] = session_id
        return self._signer.encode(payload)

    def mint_mfa_ticket(
        self,
        subject: str,
        *,
        factors: Sequence[str],
        jti: str,
        now: int | None = None,
    ) -> str:
        """A short-lived ticket standing for "this password was correct, the factor is not".

        Kept apart from an access token by its own `typ`, an `<issuer>/mfa` audience nothing
        else accepts, and a short `exp`. `jti` comes from the caller, which records it.
        """
        issued_at = int(time.time()) if now is None else now
        ttl = int(self._settings.mfa_ticket_ttl.total_seconds())
        payload: dict[str, Any] = {
            "iss": self._settings.issuer,
            "sub": subject,
            "aud": self.mfa_audience,
            "iat": issued_at,
            "exp": issued_at + ttl,
            "jti": jti,
            "typ": MFA_TICKET_TYPE,
            "amr": list(factors),
        }
        return self._signer.encode(payload)

    @property
    def mfa_audience(self) -> str:
        """The audience an MFA ticket carries: `<issuer>/mfa`, per section 3.2."""
        return f"{self._settings.issuer.rstrip('/')}/mfa"

    def verify_mfa_ticket(self, token: str, *, now: int | None = None) -> dict[str, Any]:
        """Verify an MFA ticket and return its claims, or raise `InvalidToken`.

        Asserts `typ` after the signature and audience, since a `typ` read from an
        unverified token is attacker-controlled.
        """
        claims = self.verify_access_token(token, audience=self.mfa_audience, now=now)
        if claims.get("typ") != MFA_TICKET_TYPE:
            raise InvalidToken(f"expected typ {MFA_TICKET_TYPE!r}, got {claims.get('typ')!r}")
        if not claims.get("jti"):
            raise InvalidToken("mfa ticket carries no jti")
        return claims

    def verify_access_token(
        self,
        token: str,
        *,
        audience: str | Sequence[str] | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Verify a token against the configured keys and return its claims.

        Not the production path: behind API Gateway the authorizer has already checked this.
        Selects by the header `kid`; an unknown `kid` is rejected. Raises `InvalidToken`.
        """
        import jwt

        try:
            header = jwt.get_unverified_header(token)
        except Exception as exc:
            raise InvalidToken(f"malformed token header: {exc}") from exc

        kid = header.get("kid")
        if not kid:
            raise InvalidToken("token header carries no kid")
        if header.get("alg") != JWS_ALGORITHM:
            raise InvalidToken(f"unexpected alg {header.get('alg')!r}")

        jwk = self._jwk_by_kid(kid)
        if jwk is None:
            raise InvalidToken(f"unknown kid {kid!r}")

        expected_audience = audience if audience is not None else self._settings.audience
        leeway = self._settings.clock_skew_leeway.total_seconds()
        try:
            key = jwt.PyJWK(dict(jwk), algorithm=JWS_ALGORITHM).key
            claims: dict[str, Any] = jwt.decode(
                token,
                key=key,
                algorithms=[JWS_ALGORITHM],
                audience=expected_audience,
                issuer=self._settings.issuer,
                leeway=leeway,
                options={"require": ["exp", "iat", "iss", "sub"]},
            )
        except Exception as exc:
            raise InvalidToken(str(exc)) from exc

        if now is not None and now >= int(claims["exp"]) + leeway:
            raise InvalidToken("token has expired")
        return claims

    def _jwk_by_kid(self, kid: str) -> dict[str, str] | None:
        """The configured JWK carrying this `kid`, or `None` when none does."""
        for key_id in self._settings.signing_key_arns:
            jwk = self._jwk_for(key_id)
            if jwk is not None and jwk.get("kid") == kid:
                return jwk
        return None
