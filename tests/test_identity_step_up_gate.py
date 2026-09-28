"""Tests for `require_recent_auth`, the step-up gate over the verified claims."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from webbpulse.http import register_error_handlers
from webbpulse.identity import (
    STEP_UP_REQUIRED_ERROR_CODE,
    STEP_UP_REQUIRED_MESSAGE,
    require_recent_auth,
    step_up_challenge,
)
from webbpulse.identity.api_keys import FakeApiKeyStore, mint
from webbpulse.identity.claims import AuthorizerClaims
from webbpulse.identity.scopes import FORBIDDEN_ERROR_CODE, claims_or_api_key, require_scopes

if TYPE_CHECKING:
    from collections.abc import Callable

NOW = 1_800_000_000
MAX_AGE = 300
CHALLENGE = (
    'Bearer error="insufficient_user_authentication", '
    'error_description="A more recent authentication is required", max_age=300'
)


def header_claims(request: Request) -> AuthorizerClaims:
    """Claims read from a test header, standing in for a verified authorizer context."""
    claims: dict[str, Any] = {"sub": "user-1", "scope": request.headers.get("x-scope", "")}
    if "x-auth-time" in request.headers:
        claims["auth_time"] = request.headers["x-auth-time"]
    return AuthorizerClaims(claims)


def app_with(guard: Callable[..., Any], **handlers: Any) -> TestClient:
    """A one-route app behind `guard`, with the package's error envelope installed."""
    app = FastAPI()
    register_error_handlers(app, **({"error_codes": True} | handlers))

    @app.post("/danger")
    def danger(claims: AuthorizerClaims = Depends(guard)) -> dict[str, Any]:
        """Echo the subject the guard let through."""
        return {"sub": claims["sub"]}

    return TestClient(app, raise_server_exceptions=False)


def gate(**kwargs: Any) -> Any:
    """`require_recent_auth` with the suite's max age, clock and header claims."""
    kwargs.setdefault("claims_dependency", header_claims)
    return require_recent_auth(MAX_AGE, clock=lambda: NOW, **kwargs)


def test_a_fresh_login_passes() -> None:
    """A login inside the window reaches the route."""
    response = app_with(gate()).post("/danger", headers={"x-auth-time": str(NOW - 10)})

    assert response.status_code == 200
    assert response.json() == {"sub": "user-1"}


def test_a_login_exactly_max_age_old_passes() -> None:
    """The window is inclusive of its edge."""
    response = app_with(gate()).post("/danger", headers={"x-auth-time": str(NOW - MAX_AGE)})

    assert response.status_code == 200


@pytest.mark.parametrize("headers", [{"x-auth-time": str(NOW - MAX_AGE - 1)}, {}, {"x-auth-time": "soon"}])
def test_an_old_undated_or_unreadable_login_is_step_up_required(headers: dict[str, str]) -> None:
    """Too old, missing and unreadable `auth_time` all get the 401 asking for step-up."""
    response = app_with(gate()).post("/danger", headers=headers)

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == CHALLENGE
    body = response.json()
    assert body["error_code"] == STEP_UP_REQUIRED_ERROR_CODE
    assert body["max_age"] == MAX_AGE
    assert body["message"] == STEP_UP_REQUIRED_MESSAGE


def test_the_envelope_is_exactly_the_contract() -> None:
    """The body is the shared envelope plus `max_age`, and nothing else."""
    response = app_with(gate()).post("/danger", headers={"x-request-id": "req-1"})

    body = response.json()
    body.pop("request_id")
    assert body == {
        "success": False,
        "status": 401,
        "message": "A more recent authentication is required.",
        "error_code": "STEP_UP_REQUIRED",
        "max_age": 300,
    }


def test_the_code_renders_without_error_codes_and_in_the_detailed_shape() -> None:
    """The override code and `max_age` survive both the default and the detailed envelopes."""
    plain = app_with(gate(), error_codes=False).post("/danger")
    detailed = app_with(gate(), error_envelope="detailed").post("/danger")

    for response in (plain, detailed):
        assert response.json()["error_code"] == STEP_UP_REQUIRED_ERROR_CODE
        assert response.json()["max_age"] == MAX_AGE


def test_an_api_key_passes_the_gate() -> None:
    """A key has no login to age, so it is not asked to step up."""
    store = FakeApiKeyStore()
    minted = mint(user_id="user-1", tenant_id="t1", scopes=["issues:write"], store=store)
    guard = require_recent_auth(MAX_AGE, claims_dependency=claims_or_api_key(store=store), clock=lambda: NOW)

    response = app_with(guard).post("/danger", headers={"Authorization": f"Bearer {minted.plaintext}"})

    assert response.status_code == 200


def test_the_gate_composes_with_require_scopes() -> None:
    """Scopes are checked first and the login age second, through one chain of dependencies."""
    guard = gate(claims_dependency=require_scopes("admin", claims_dependency=header_claims))
    client = app_with(guard)

    missing_scope = client.post("/danger", headers={"x-auth-time": str(NOW)})
    stale = client.post("/danger", headers={"x-scope": "admin", "x-auth-time": str(NOW - 3600)})
    fresh = client.post("/danger", headers={"x-scope": "admin", "x-auth-time": str(NOW)})

    assert missing_scope.status_code == 403
    assert missing_scope.json()["error_code"] == FORBIDDEN_ERROR_CODE
    assert stale.status_code == 401
    assert stale.json()["error_code"] == STEP_UP_REQUIRED_ERROR_CODE
    assert fresh.status_code == 200


def test_the_default_dependency_refuses_an_unauthenticated_caller_first() -> None:
    """With no authorizer claims the default chain is the plain 401, not a step-up prompt."""
    response = app_with(require_recent_auth(MAX_AGE)).post("/danger")

    assert response.status_code == 401
    assert response.json()["error_code"] == "UNAUTHORIZED"


@pytest.mark.parametrize("value", [0, -5, True, 1.5, "300"])
def test_a_max_age_that_is_not_a_positive_int_is_refused_at_build_time(value: Any) -> None:
    """A bad window fails when the route is built, not on the first request."""
    with pytest.raises(ValueError, match="max_age_seconds"):
        require_recent_auth(value)


def test_the_challenge_header_follows_rfc_9470() -> None:
    """The header names the error, a description and the max age."""
    assert step_up_challenge(300) == CHALLENGE


def test_http_exception_extra_never_overrides_the_base_keys() -> None:
    """An `extra` key naming a base field is dropped, and a 5xx carries no extra at all."""
    from fastapi import HTTPException

    app = FastAPI()
    register_error_handlers(app, error_codes=True)

    @app.get("/clash")
    def clash() -> None:
        """Try to overwrite the status and message through `extra`."""
        raise HTTPException(
            status_code=409,
            detail={"message": "Conflict here.", "extra": {"status": 200, "message": "ok", "hint": "retry"}},
        )

    @app.get("/boom")
    def boom() -> None:
        """A server fault with extra keys."""
        raise HTTPException(status_code=503, detail={"message": "down", "extra": {"hint": "internal"}})

    client = TestClient(app, raise_server_exceptions=False)
    clashed = client.get("/clash").json()
    broke = client.get("/boom").json()

    assert clashed["status"] == 409
    assert clashed["message"] == "Conflict here."
    assert clashed["hint"] == "retry"
    assert "hint" not in broke
