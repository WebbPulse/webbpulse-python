"""`LocalAuthorizerMiddleware`: the refusal, the header strip, and the claims it injects.

Also covers the forward-reference fix: an app mounting the identity router builds its
OpenAPI document, which it could not while `JSONResponse` lived only under `TYPE_CHECKING`.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from webbpulse.identity import (
    REQUEST_CONTEXT_HEADER,
    BaseIdentityHooks,
    IdentitySettings,
    IdentityStores,
    InMemoryCredentialStore,
    InMemoryRefreshTokenStore,
    LocalAuthorizerMiddleware,
    LocalSigner,
    TokenService,
    build_identity_router,
    identity_claims,
    signing_client,
)

ISSUER = "http://127.0.0.1:8000/api/auth"

AUDIENCE = "webbpulse-local-api"

KEY_A = "local-key-a"


def make_settings(**overrides: Any) -> IdentitySettings:
    """Identity settings for a local stack signing in process."""
    base: dict[str, Any] = {
        "environment": "local",
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "signing_key_arns": [KEY_A],
        "signer": "local",
        "email_verification_required": False,
    }
    base.update(overrides)
    return IdentitySettings(**base)


@pytest.fixture(scope="module")
def settings() -> IdentitySettings:
    """One settings object for the module."""
    return make_settings()


@pytest.fixture(scope="module")
def tokens(settings: IdentitySettings) -> TokenService:
    """A token service over the local signer, so minting and verifying share a key."""
    return TokenService(settings, signing_client(settings))


def http_scope(headers: list[tuple[bytes, bytes]] | None = None) -> dict[str, Any]:
    """A minimal HTTP ASGI scope carrying `headers`."""
    return {"type": "http", "path": "/", "method": "GET", "headers": headers or []}


class RecordingApp:
    """An ASGI app that records the scope it was called with and answers nothing."""

    def __init__(self) -> None:
        """Start with no recorded scope."""
        self.scope: dict[str, Any] | None = None

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        """Record the scope this application was handed."""
        self.scope = dict(scope)


def call(middleware: LocalAuthorizerMiddleware, scope: dict[str, Any]) -> None:
    """Drive the middleware once with no-op `receive` and `send`."""

    async def receive() -> dict[str, Any]:
        """Never called by this middleware."""
        return {"type": "http.request"}

    async def send(message: Any) -> None:
        """Never called by this middleware."""

    asyncio.run(middleware(scope, receive, send))


def injected_context(scope: dict[str, Any]) -> dict[str, Any] | None:
    """The request context header the middleware injected, parsed, or `None`."""
    for name, value in scope["headers"]:
        if name == REQUEST_CONTEXT_HEADER:
            parsed: dict[str, Any] = json.loads(value.decode("latin-1"))
            return parsed
    return None


@pytest.mark.parametrize("environment", ["staging", "production", "prod", "Local ish", ""])
def test_it_refuses_any_environment_but_local(settings: IdentitySettings, environment: str) -> None:
    """A deployed stack must be authorized by the gateway and nothing else.

    The explicit argument decides even when the settings say `local`, so an ASGI stack
    built from an environment the identity settings do not describe still refuses.
    """
    with pytest.raises(ValueError, match="refuses environment"):
        LocalAuthorizerMiddleware(RecordingApp(), settings, environment)


def test_it_refuses_the_settings_environment_when_none_is_passed() -> None:
    """With no explicit environment the settings' own field is what is checked."""
    settings = make_settings(environment="staging", issuer="https://example.com/api/auth", signer="kms")
    with pytest.raises(ValueError, match="refuses environment"):
        LocalAuthorizerMiddleware(RecordingApp(), settings)


@pytest.mark.parametrize("environment", ["local", "LOCAL", " local "])
def test_it_accepts_the_local_environment(settings: IdentitySettings, environment: str) -> None:
    """The check is case and whitespace insensitive, as the signer's own refusal is."""
    middleware = LocalAuthorizerMiddleware(RecordingApp(), settings, environment)
    assert middleware.app is not None


def test_it_injects_the_claims_of_a_token_the_local_signer_issued(
    settings: IdentitySettings, tokens: TokenService
) -> None:
    """The whole point: a token this process signed arrives as verified claims."""
    app = RecordingApp()
    middleware = LocalAuthorizerMiddleware(app, settings)
    token = tokens.mint_access_token("u1", claims={"roles": ["admin"]})

    call(middleware, http_scope([(b"authorization", f"Bearer {token}".encode("latin-1"))]))

    assert app.scope is not None
    context = injected_context(app.scope)
    assert context is not None
    claims = context["authorizer"]["jwt"]["claims"]
    assert claims["sub"] == "u1"
    assert claims["iss"] == ISSUER
    assert claims["roles"] == ["admin"]


def test_the_injected_context_is_what_identity_claims_reads(settings: IdentitySettings, tokens: TokenService) -> None:
    """The shape is the reader's, not a new one, so no route needs a second code path."""
    app = RecordingApp()
    middleware = LocalAuthorizerMiddleware(app, settings)
    token = tokens.mint_access_token("u2")

    call(middleware, http_scope([(b"authorization", f"Bearer {token}".encode("latin-1"))]))

    assert app.scope is not None
    from starlette.requests import Request

    claims = identity_claims(Request(app.scope))
    assert claims is not None
    assert claims["sub"] == "u2"


def test_it_drops_a_forged_inbound_context_header(settings: IdentitySettings) -> None:
    """A caller can never present claims of its own, token or no token."""
    app = RecordingApp()
    middleware = LocalAuthorizerMiddleware(app, settings)
    forged = json.dumps({"authorizer": {"jwt": {"claims": {"sub": "attacker", "roles": ["admin"]}}}})

    call(middleware, http_scope([(REQUEST_CONTEXT_HEADER, forged.encode("latin-1"))]))

    assert app.scope is not None
    assert injected_context(app.scope) is None


def test_a_forged_header_is_replaced_by_the_real_claims(settings: IdentitySettings, tokens: TokenService) -> None:
    """The strip happens before verification, so a good token never inherits forged claims."""
    app = RecordingApp()
    middleware = LocalAuthorizerMiddleware(app, settings)
    forged = json.dumps({"authorizer": {"jwt": {"claims": {"sub": "attacker"}}}})
    token = tokens.mint_access_token("u3")

    call(
        middleware,
        http_scope(
            [
                (REQUEST_CONTEXT_HEADER, forged.encode("latin-1")),
                (b"authorization", f"Bearer {token}".encode("latin-1")),
            ]
        ),
    )

    assert app.scope is not None
    context = injected_context(app.scope)
    assert context is not None
    assert context["authorizer"]["jwt"]["claims"]["sub"] == "u3"


@pytest.mark.parametrize(
    "headers",
    [
        [],
        [(b"authorization", b"Bearer not-a-token")],
        [(b"authorization", b"Basic dXNlcjpwdw==")],
        [(b"authorization", b"")],
    ],
    ids=["no header", "garbage token", "wrong scheme", "empty value"],
)
def test_a_bad_or_missing_token_attaches_no_claims(
    settings: IdentitySettings, headers: list[tuple[bytes, bytes]]
) -> None:
    """No claims rather than a refusal here: the route's own authorization answers 401."""
    app = RecordingApp()
    middleware = LocalAuthorizerMiddleware(app, settings)

    call(middleware, http_scope(headers))

    assert app.scope is not None
    assert injected_context(app.scope) is None


def test_a_token_from_another_issuer_attaches_no_claims(settings: IdentitySettings) -> None:
    """A token signed by a different seed is not one this issuer signed."""
    other = make_settings(local_signer_seed="somebody-else")
    token = TokenService(other, LocalSigner(seed="somebody-else")).mint_access_token("u4")
    app = RecordingApp()
    middleware = LocalAuthorizerMiddleware(app, settings)

    call(middleware, http_scope([(b"authorization", f"Bearer {token}".encode("latin-1"))]))

    assert app.scope is not None
    assert injected_context(app.scope) is None


@pytest.mark.parametrize("scope_type", ["lifespan", "websocket"])
def test_a_non_http_scope_passes_straight_through(settings: IdentitySettings, scope_type: str) -> None:
    """Nothing but an HTTP request carries an `Authorization` header to verify."""
    app = RecordingApp()
    middleware = LocalAuthorizerMiddleware(app, settings)

    call(middleware, {"type": scope_type})

    assert app.scope == {"type": scope_type}


def test_the_verifier_is_built_once_and_lazily(settings: IdentitySettings, tokens: TokenService) -> None:
    """Deriving the local key is not free, so it happens on the first token and no sooner."""
    middleware = LocalAuthorizerMiddleware(RecordingApp(), settings)
    assert middleware._verifier is None

    call(middleware, http_scope())
    assert middleware._verifier is None

    token = tokens.mint_access_token("u5")
    call(middleware, http_scope([(b"authorization", f"Bearer {token}".encode("latin-1"))]))
    built = middleware._verifier
    assert built is not None

    call(middleware, http_scope([(b"authorization", f"Bearer {token}".encode("latin-1"))]))
    assert middleware._verifier is built


def identity_app() -> Any:
    """A FastAPI app mounting the identity router the way a product's root does."""
    from fastapi import FastAPI

    settings = make_settings()
    stores = IdentityStores(
        credentials=InMemoryCredentialStore(),
        refresh_tokens=InMemoryRefreshTokenStore(),
    )
    app = FastAPI()
    app.include_router(
        build_identity_router(
            settings,
            BaseIdentityHooks(),
            stores,
            kms_client=signing_client(settings),
            limiter_enabled=False,
        )
    )
    return app


def test_an_app_mounting_the_identity_router_builds_its_openapi_document() -> None:
    """The forward-reference regression: `-> JSONResponse` must resolve at schema time.

    While `JSONResponse` was visible only under `TYPE_CHECKING`, FastAPI could not resolve
    the postponed return annotation and `app.openapi()` raised `PydanticUserError`.
    """
    document = identity_app().openapi()
    assert document["paths"]


def test_the_middleware_authorizes_a_request_to_a_mounted_app(tokens: TokenService) -> None:
    """End to end: wrapped app, minted token, claims readable from the request."""
    from starlette.requests import Request

    seen: list[str] = []

    async def app(scope: Any, receive: Any, send: Any) -> None:
        """Read the subject the middleware published."""
        claims = identity_claims(Request(scope))
        assert claims is not None
        seen.append(claims["sub"])

    middleware = LocalAuthorizerMiddleware(app, make_settings())
    token = tokens.mint_access_token("u6")

    call(middleware, http_scope([(b"authorization", f"Bearer {token}".encode("latin-1"))]))

    assert seen == ["u6"]
