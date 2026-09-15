"""`LocalAuthorizerMiddleware`: the API Gateway JWT authorizer, stood in for locally.

Deployed, the gateway verifies the access token and the Lambda Web Adapter hands the
function its claims in `x-amzn-request-context`, which is what `identity_claims` and
`identity_subject` read. A local e2e stack has no gateway, so a perfectly valid token
reaches the app carrying no claims and every authorized route answers 401. This module
verifies the bearer token in process against the key set the local signer derives and
publishes the result in the shape those readers already expect, so a product's local
stack needs no second code path.

Shared here rather than copied per product: every product's `e2e-local.yml@v3` stack
wants exactly this, and a copy per composition root is a copy of a security-sensitive
refusal.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Awaitable, Callable, MutableMapping

    from webbpulse.identity.settings import IdentitySettings

__all__ = ["LOCAL_ENVIRONMENT", "REQUEST_CONTEXT_HEADER", "LocalAuthorizerMiddleware"]

LOCAL_ENVIRONMENT: Final = "local"
"""The only environment `LocalAuthorizerMiddleware` will run under."""

REQUEST_CONTEXT_HEADER: Final = b"x-amzn-request-context"
"""The header the Lambda Web Adapter injects, carrying the authorizer's verified claims.

Lower case bytes, which is the spelling an ASGI scope holds.
"""

_AUTHORIZATION_HEADER: Final = b"authorization"

_BEARER_SCHEME: Final = "bearer"


class InProcessKeyClient:
    """Resolves a token's `kid` against a JWKS held in memory.

    `JwksVerifier` would otherwise fetch the key set over HTTP, and on a local stack the
    issuer it would fetch from is this very process, so the request would block the event
    loop waiting on itself. The key set is the one the local signer derives, so it is the
    same document the JWKS route serves without going through the route.
    """

    def __init__(self, jwks: dict[str, Any]) -> None:
        """Index the key set by `kid`, ignoring any key that carries none."""
        from jwt import PyJWK

        keys = jwks.get("keys") or []
        self._keys = {key["kid"]: PyJWK(key) for key in keys if key.get("kid")}

    def get_signing_key_from_jwt(self, token: str) -> Any:
        """The key whose `kid` matches this token's header, raising when none does."""
        import jwt

        kid = jwt.get_unverified_header(token).get("kid")
        if kid not in self._keys:
            raise KeyError(f"no key in the local JWKS carries kid {kid!r}")
        return self._keys[kid]


class LocalAuthorizerMiddleware:
    """Verify the bearer token in process and publish its claims as the gateway would.

    Pure ASGI, so it sits below any FastAPI middleware and the claims are in place before
    a route's dependencies run. Any inbound copy of the request context header is dropped
    before verification, so a caller can never present claims of its own; a request with
    no token, or one this issuer did not sign, is passed through with no claims attached
    and the route's own authorization refuses it.

    Constructing it outside the local environment raises, so no deployment can reach a
    path where a request is authorized by anything but the gateway.
    """

    def __init__(
        self,
        app: Callable[..., Awaitable[None]],
        settings: IdentitySettings,
        environment: str | None = None,
    ) -> None:
        """Wrap `app`, refusing any environment but the local one.

        `environment` defaults to `settings.environment`, which is what a composition root
        holding one settings object should leave it as. Pass it only where the ASGI stack
        is built from an environment the identity settings do not describe.
        """
        resolved = settings.environment if environment is None else environment
        if resolved.strip().lower() != LOCAL_ENVIRONMENT:
            raise ValueError(
                f"LocalAuthorizerMiddleware refuses environment {resolved!r}. It verifies "
                "tokens in process, which must never stand in for the gateway's own "
                "authorizer in a deployed environment."
            )
        self.app = app
        self._settings = settings
        self._verifier: Any = None

    def _build_verifier(self) -> Any:
        """A verifier reading the key set this process signs with, fetching nothing.

        Built lazily: deriving the local signing key is not free, and a stack that never
        sees an authorized request should not pay for it at import time.
        """
        from webbpulse.identity.local_signer import signing_client
        from webbpulse.identity.service import TokenService
        from webbpulse.identity.verifier import JwksVerifier

        jwks = TokenService(self._settings, signing_client(self._settings)).jwks()
        return JwksVerifier.from_settings(self._settings, client=InProcessKeyClient(jwks))

    def _verify(self, token: str) -> dict[str, Any] | None:
        """This token's claims, or `None` when it is not one this issuer signed."""
        from webbpulse.identity.service import InvalidToken

        if self._verifier is None:
            self._verifier = self._build_verifier()
        try:
            claims: dict[str, Any] = self._verifier.verify(token)
        except InvalidToken:
            return None
        return claims

    async def __call__(
        self,
        scope: MutableMapping[str, Any],
        receive: Callable[[], Awaitable[MutableMapping[str, Any]]],
        send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
    ) -> None:
        """Replace the request context header with the claims this token carries."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = [(name, value) for name, value in scope["headers"] if name != REQUEST_CONTEXT_HEADER]
        token = _bearer_token(headers)
        claims = self._verify(token) if token else None
        if claims is not None:
            context = json.dumps({"authorizer": {"jwt": {"claims": claims}}})
            headers.append((REQUEST_CONTEXT_HEADER, context.encode("latin-1")))

        await self.app({**scope, "headers": headers}, receive, send)


def _bearer_token(headers: list[tuple[bytes, bytes]]) -> str:
    """The token from the first `Authorization: Bearer` header, or an empty string."""
    for name, value in headers:
        if name != _AUTHORIZATION_HEADER:
            continue
        scheme, _, rest = value.decode("latin-1").partition(" ")
        return rest.strip() if scheme.lower() == _BEARER_SCHEME else ""
    return ""
