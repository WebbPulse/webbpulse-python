"""`TokenService`: minting, local verification, and the two documents, over rotating keys.

`tokens.py` holds the primitives, which know about one key at a time: a `KmsSigner` signs
with one key id, `public_jwk_from_kms` reads one key. This module is what turns those into
the thing a service actually mounts, whose defining feature is that there is more than one
key at once.

## Rotation is the whole design

Section 3.5 of `docs/identity-standard.md` settles the mechanism, and it is worth restating
because it is the part that is easy to get subtly wrong.

KMS automatic key rotation is **not** used. It rotates the backing material under a single
key id while `kms:GetPublicKey` keeps answering for the current material, so a token signed
before a rotation stops verifying against the JWKS afterwards, with no `kid` change to
explain it. Every live session breaks at once and nothing in the logs says why.

Instead there are two key ids, and rotation is an ordinary configuration change:

1. Steady state: `signing_key_arns = [current]`. The JWKS lists one key.
2. Introduce: `signing_key_arns = [current, next]`. The JWKS lists both. **Nothing is signed
   with `next` yet**, but every verifier has now seen it. This step must be deployed and
   allowed to propagate before step 3.
3. Promote: `signing_key_arns = [next, current]`. New tokens are signed with `next`; tokens
   already signed with `current` still verify, because `current` is still in the JWKS.
4. Retire: `signing_key_arns = [next]`, once no token signed with `current` can still be
   alive, which is one access-token lifetime, not one refresh lifetime.

The first element is the active signer. Every element appears in the JWKS. That single rule
is what makes each step above a one-line change, and `IdentitySettings.active_signing_key_arn`
and `.previous_signing_key_arns` are just names for the head and the tail.

The dangerous step is doing 3 without 2. Promoting straight to a key the gateway has never
fetched means every request is denied until the authorizer refetches, and section 2.5 notes
the gateway caches the JWKS for its own interval, so the outage lasts as long as that cache.

## Caching

`kms:GetPublicKey` is called once per key per `TokenService` instance, not once per request.
A JWK is a pure function of key material that cannot change under a fixed key id, given that
automatic rotation is off, so caching it for the life of the execution environment is sound
rather than merely convenient. It also matters for cost and latency: the gateway refetches
the JWKS often, and a `GetPublicKey` per fetch would put a KMS call on a hot anonymous path.

The cache is per instance rather than module-global so a test can build a fresh service
without reaching into module state, and so two products in one process cannot share a cache
keyed only by key id.

## Local verification

`verify_access_token` exists for two callers: this package's own tests, and a service that
verifies a token itself rather than behind the gateway authorizer. In production behind API
Gateway it is **not** on the request path. The gateway has already verified the signature,
the issuer, the audience and the expiry before the Lambda is invoked, and re-verifying would
add a KMS-derived JWKS lookup to every request to re-establish what the platform guarantees.
`claims.py` is what production reads. This is the escape hatch, and its docstring says so.
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

if TYPE_CHECKING:  # pragma: no cover - typing only
    from webbpulse.identity.settings import IdentitySettings

__all__ = [
    "ACCESS_TOKEN_TYPE",
    "MFA_TICKET_TYPE",
    "REGISTERED_CLAIMS",
    "InvalidToken",
    "TokenService",
]

#: Claims the token service owns. A product hook returning any of these has the entry
#: dropped rather than honoured: a product able to rewrite `iss` could mint a token for
#: another issuer, and one able to rewrite `exp` could mint one that never expires.
REGISTERED_CLAIMS: Final[frozenset[str]] = frozenset(
    {"iss", "sub", "aud", "exp", "iat", "nbf", "jti", "typ", "sid"}
)

#: The `typ` claim on an access token. Section 3.3. A distinct value per token kind is what
#: stops a refresh token or an MFA ticket being presented where an access token is expected,
#: which is a real confused-deputy bug and not a hypothetical one.
ACCESS_TOKEN_TYPE: Final = "access"

#: The `typ` an MFA ticket carries. Distinct from `ACCESS_TOKEN_TYPE` so that the two can
#: never be confused for one another, per section 3.2.
MFA_TICKET_TYPE: Final = "mfa_ticket"

_log = logging.getLogger(__name__)


class InvalidToken(Exception):
    """Local verification rejected a token.

    One type for every reason: expired, wrong audience, wrong issuer, unknown `kid`, bad
    signature, malformed. The `reason` attribute distinguishes them for a log, and the
    message is safe to log but not to return to a caller, because "unknown kid" and "bad
    signature" tell an attacker which half of the token to keep working on.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class TokenService:
    """Mints and verifies access tokens, and serves the JWKS and discovery documents.

    Construct one per execution environment and hold it in module state. It caches a JWK per
    configured key, so a per-request instance would put a `kms:GetPublicKey` on every
    request to the JWKS, which the gateway fetches often.

    `client` is a KMS client, typed structurally by `KmsClient`, so this module imports no
    boto3 and a test passes a fake. That is the same argument the `identity` extra makes in
    `pyproject.toml` for leaving boto3 out of it.
    """

    def __init__(self, settings: IdentitySettings, client: KmsClient) -> None:
        self._settings = settings
        self._client = client
        self._signer = KmsSigner(client, settings.active_signing_key_arn)
        self._jwk_cache: dict[str, dict[str, str]] = {}
        self._discovery = build_discovery_document(settings.issuer)

    @property
    def settings(self) -> IdentitySettings:
        return self._settings

    @property
    def active_kid(self) -> str:
        """The `kid` new tokens are signed with. The head of `signing_key_arns`."""
        return self._signer.kid

    # ---- documents ---------------------------------------------------------------

    def discovery(self) -> dict[str, Any]:
        """The OIDC discovery document.

        Built once at construction: it is a pure function of the issuer, and rebuilding it
        per request would only create a chance for two requests to disagree.
        """
        return self._discovery

    def jwks(self) -> dict[str, Any]:
        """The JWKS, listing every configured key: the active one first, then the previous.

        Order is not significant to a verifier, which selects by `kid`, but the active key
        is emitted first so that a human reading the document sees the current key at the
        top and so that a verifier that ignores `kid` and tries keys in order succeeds on
        the first attempt for the overwhelming majority of tokens.

        A key whose `GetPublicKey` fails is **omitted rather than fatal**. A retired key id
        left in configuration, or one whose grant was removed early, must not take the JWKS
        down: that document failing is what denies every authorized request in the product,
        which is a far worse outcome than a stale entry going missing. The failure is logged
        at warning level by `_jwk_for`, and every key failing is still fatal, below.
        """
        keys: list[dict[str, str]] = []
        for key_id in self._settings.signing_key_arns:
            jwk = self._jwk_for(key_id)
            if jwk is not None:
                keys.append(jwk)
        if not keys:
            # Every key failed. Returning an empty JWKS would let the gateway cache an empty
            # document and deny everything for its whole cache interval, so fail the request
            # instead and let it retry against a document that might work.
            raise RuntimeError(
                "No signing key produced a JWK. Every key in IDENTITY_SIGNING_KEY_ARNS "
                "failed kms:GetPublicKey, so serving an empty JWKS would deny every "
                "authorized request until the gateway's cache expired."
            )
        return build_jwks(keys)

    def _jwk_for(self, key_id: str) -> dict[str, str] | None:
        cached = self._jwk_cache.get(key_id)
        if cached is not None:
            return cached
        try:
            jwk = public_jwk_from_kms(self._client, key_id)
        except Exception:
            # Deliberately broad: a retired key id left in configuration, a revoked grant
            # and a wrong KeySpec all arrive as different exception types, and every one of
            # them must degrade to omitting one key rather than failing the document.
            _log.warning(
                "Signing key %s produced no JWK and is omitted from the JWKS.",
                key_id,
                exc_info=True,
            )
            return None
        self._jwk_cache[key_id] = jwk
        return jwk

    # ---- minting -----------------------------------------------------------------

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

        `claims` are the product's own, from `IdentityHooks.claims_for`. Any registered
        claim among them is dropped, not honoured: see `REGISTERED_CLAIMS`.

        `nbf` is deliberately **not** set. It buys nothing here, because `iat` and `exp`
        already bound the window, and a `nbf` equal to `iat` is a live source of spurious
        rejections whenever the signer's clock is a second ahead of the verifier's. The
        gateway applies its own small skew allowance to `exp`, and `clock_skew_leeway`
        covers local verification.
        """
        issued_at = int(time.time()) if now is None else now
        ttl = int(self._settings.access_token_ttl.total_seconds())

        payload: dict[str, Any] = {}
        if claims:
            payload.update(
                {key: value for key, value in claims.items() if key not in REGISTERED_CLAIMS}
            )
        payload.update(
            {
                "iss": self._settings.issuer,
                "sub": subject,
                "aud": list(audience)
                if isinstance(audience, (list, tuple))
                else (audience or self._settings.audience),
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

        This is **not** an access token and must never be usable as one. Three things keep
        them apart, and all three are needed:

        - `typ` is `MFA_TICKET_TYPE`, not `access`. Section 3.2 requires every token to carry
          a `typ` that is asserted positively, and `verify_mfa_ticket` refuses anything else.
        - `aud` is `<issuer>/mfa`, an audience nothing else accepts. The API Gateway
          authorizer is configured with the product's own audience, so a ticket presented as
          a bearer token is rejected at the gateway before any code sees it. That is the
          check that holds even if this package's own verification is bypassed.
        - `exp` is `mfa_ticket_ttl`, five minutes by default, rather than the access token's
          lifetime.

        `jti` is supplied by the caller rather than generated here, because the caller has to
        record it to enforce single use. Generating it here would leave the caller to read it
        back out of the encoded token, which works but puts the value that guarantees single
        use somewhere it can be forgotten.

        No `sid`. The ticket precedes the session: there is no refresh family yet, and there
        will not be one unless the second factor succeeds.
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

        Asserts `typ` **after** the signature and audience are checked. Order matters: a
        `typ` read from an unverified token is attacker-controlled, so checking it first
        would be checking a value the attacker wrote.
        """
        claims = self.verify_access_token(token, audience=self.mfa_audience, now=now)
        if claims.get("typ") != MFA_TICKET_TYPE:
            # An access token presented as a ticket lands here. Refusing it is what stops a
            # stolen access token being spent as a second factor.
            raise InvalidToken(f"expected typ {MFA_TICKET_TYPE!r}, got {claims.get('typ')!r}")
        if not claims.get("jti"):
            # Without a jti there is nothing to record, so single use cannot be enforced and
            # the ticket would be replayable for its whole lifetime.
            raise InvalidToken("mfa ticket carries no jti")
        return claims

    # ---- local verification ------------------------------------------------------

    def verify_access_token(
        self,
        token: str,
        *,
        audience: str | Sequence[str] | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Verify a token against the configured keys and return its claims.

        **Not the production path.** Behind API Gateway the authorizer has already checked
        the signature, issuer, audience and expiry before the Lambda runs, and `claims.py`
        reads the result. This exists for tests and for a service verifying a token itself.

        Selection is by the `kid` in the header, across every configured key, which is what
        makes a token signed by the previous key verify during a rotation overlap. A `kid`
        matching no configured key is rejected rather than falling back to trying every key:
        trying them all would make a retired key indistinguishable from a current one and
        would quietly undo step 4 of the rotation.

        Raises `InvalidToken` for every failure.
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
            # Rejected explicitly rather than left to PyJWT, so an `alg: none` or an HS256
            # token signed with the public key as an HMAC secret cannot reach the decoder.
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
            # PyJWT reads the clock itself, so an explicit `now` for a deterministic test
            # is checked here rather than by monkeypatching time inside the library.
            raise InvalidToken("token has expired")
        return claims

    def _jwk_by_kid(self, kid: str) -> dict[str, str] | None:
        for key_id in self._settings.signing_key_arns:
            jwk = self._jwk_for(key_id)
            if jwk is not None and jwk.get("kid") == kid:
                return jwk
        return None
