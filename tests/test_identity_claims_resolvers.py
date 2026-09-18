"""The claim resolvers that tolerate an absent authorizer, and the staging gate's shape.

`read_authorizer_claims` raises for a request the native JWT authorizer did not touch.
`identity_claims` and `identity_subject` are the other half: they answer for whichever
authorizer ran, the native one or the staging access gate's Lambda authorizer, and answer
nothing rather than raising when neither did.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import pytest

from webbpulse.identity.claims import (
    GATE_CLAIMS_KEY,
    AuthorizerClaims,
    authorizer_claims,
    gate_claims,
    identity_claims,
    identity_subject,
    subject_dependency,
)

HEADER = "x-amzn-request-context"

NATIVE_CLAIMS = {
    "sub": "user-abc-123",
    "email": "someone@example.com",
    "email_verified": "true",
    "exp": "1757400000",
    "scope": "openid profile",
}

GATE_PAYLOAD = {
    "sub": "user-gate-9",
    "email": "gated@example.com",
    "email_verified": "true",
    "exp": "1757400000",
    "amr": '["pwd"]',
}


def make_request(headers: dict[str, str]) -> Any:
    """Build a minimal Starlette GET request carrying the given headers."""
    from starlette.requests import Request

    raw = [(name.lower().encode(), value.encode()) for name, value in headers.items()]
    return Request({"type": "http", "method": "GET", "path": "/", "headers": raw})


def native_header(claims: dict[str, Any]) -> dict[str, str]:
    """The request-context header a JWT authorizer produces for `claims`."""
    return {HEADER: json.dumps({"authorizer": {"jwt": {"claims": claims}}})}


def gate_header(payload: Any, *, encode: bool = True) -> dict[str, str]:
    """The request-context header the staging gate's Lambda authorizer produces."""
    value = json.dumps(payload) if encode else payload
    return {HEADER: json.dumps({"authorizer": {"lambda": {GATE_CLAIMS_KEY: value}}})}


def test_the_gate_key_mirrors_the_native_path() -> None:
    """The gate context key is the dotted native path, which is the whole convention."""
    assert GATE_CLAIMS_KEY == "jwt.claims"


def test_gate_claims_reads_the_lambda_authorizer_context() -> None:
    """A gate context value decodes to the claim map the gate stringified into it."""
    claims = gate_claims(make_request(gate_header(GATE_PAYLOAD)))
    assert claims == GATE_PAYLOAD


@pytest.mark.parametrize(
    ("headers", "reason"),
    [
        ({}, "no header at all"),
        ({HEADER: "   "}, "a blank header"),
        ({HEADER: "{not json"}, "a header that is not JSON"),
        ({HEADER: json.dumps(["not", "an", "object"])}, "a context that is not an object"),
        ({HEADER: json.dumps({"http": {}})}, "no authorizer section"),
        ({HEADER: json.dumps({"authorizer": {"jwt": {"claims": NATIVE_CLAIMS}}})}, "a native context, not a gate one"),
        ({HEADER: json.dumps({"authorizer": {"lambda": {}}})}, "a lambda context without the key"),
        ({HEADER: json.dumps({"authorizer": {"lambda": {GATE_CLAIMS_KEY: "  "}}})}, "a blank gate value"),
    ],
)
def test_gate_claims_answers_none_for_every_way_it_can_be_absent(headers: dict[str, str], reason: str) -> None:
    """Every absent shape answers `None` rather than raising, because the caller has a fallback."""
    assert gate_claims(make_request(headers)) is None, reason


def test_a_gate_value_that_is_not_json_warns_and_answers_none(caplog: pytest.LogCaptureFixture) -> None:
    """An unparseable gate value is warned about: the two sides disagree about the encoding."""
    with caplog.at_level(logging.WARNING, logger="webbpulse.identity.claims"):
        assert gate_claims(make_request(gate_header("{not json", encode=False))) is None
    assert GATE_CLAIMS_KEY in caplog.text


def test_a_gate_value_that_is_not_an_object_answers_none() -> None:
    """A gate value parsing to a list is not a claim map, so it is nothing."""
    assert gate_claims(make_request(gate_header(["nope"]))) is None


def test_identity_claims_prefers_the_native_authorizer() -> None:
    """With both shapes present the native one wins, since that is the real authorizer."""
    headers = {
        HEADER: json.dumps(
            {
                "authorizer": {
                    "jwt": {"claims": NATIVE_CLAIMS},
                    "lambda": {GATE_CLAIMS_KEY: json.dumps(GATE_PAYLOAD)},
                }
            }
        )
    }
    claims = identity_claims(make_request(headers))
    assert claims is not None
    assert claims["sub"] == "user-abc-123"


def test_identity_claims_falls_back_to_the_gate() -> None:
    """With no native claims the gate's are read and coerced the same way."""
    claims = identity_claims(make_request(gate_header(GATE_PAYLOAD)))
    assert claims is not None
    assert claims["sub"] == "user-gate-9"
    assert claims["email_verified"] is True
    assert claims["exp"] == 1757400000
    assert claims["amr"] == ["pwd"]


def test_gate_claims_arrive_as_an_authorizer_claims_mapping() -> None:
    """The gate path returns the same type as the native path, wire form included."""
    claims = identity_claims(make_request(gate_header(GATE_PAYLOAD)))
    assert isinstance(claims, AuthorizerClaims)
    assert claims.raw["exp"] == "1757400000"


def test_identity_claims_answers_none_when_no_authorizer_ran() -> None:
    """No authorizer of either kind is `None`, which is not the same as a refusal."""
    assert identity_claims(make_request({})) is None


def test_identity_subject_reads_either_shape() -> None:
    """The subject comes back from whichever authorizer published it."""
    assert identity_subject(make_request(native_header(NATIVE_CLAIMS))) == "user-abc-123"
    assert identity_subject(make_request(gate_header(GATE_PAYLOAD))) == "user-gate-9"


@pytest.mark.parametrize(
    "headers",
    [
        {},
        native_header({"email": "someone@example.com"}),
        native_header({"sub": ""}),
    ],
)
def test_identity_subject_is_the_empty_string_for_every_absence(headers: dict[str, str]) -> None:
    """No authorizer, no `sub`, and an empty `sub` all read as `""` so callers branch once."""
    assert identity_subject(make_request(headers)) == ""


def test_identity_subject_stringifies_a_numeric_subject() -> None:
    """A gate that published `sub` as a number still yields the id as a string."""
    assert identity_subject(make_request(gate_header({"sub": 4210}))) == "4210"


def test_the_subject_dependency_returns_the_verified_subject() -> None:
    """The dependency hands back the subject for a request an authorizer touched."""
    dependency = subject_dependency()
    assert asyncio.run(dependency(make_request(native_header(NATIVE_CLAIMS)))) == "user-abc-123"


def test_the_required_subject_dependency_refuses_an_unauthenticated_request() -> None:
    """A required subject that is absent is a 401 with the Bearer challenge."""
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as caught:
        asyncio.run(subject_dependency()(make_request({})))
    assert caught.value.status_code == 401
    assert caught.value.headers == {"WWW-Authenticate": "Bearer"}


def test_an_optional_subject_dependency_answers_empty() -> None:
    """With `required=False` an absent subject is `""` and the route decides."""
    assert asyncio.run(subject_dependency(required=False)(make_request({}))) == ""


def _mounted(dependency: Any, key: str = "subject") -> Any:
    """A one-route app whose only argument is `dependency`, returning a client for it."""
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()

    @app.get("/who")
    def who(resolved: Any = Depends(dependency)) -> dict[str, Any]:
        """Echo whatever the dependency resolved."""
        return {key: resolved if isinstance(resolved, str) else dict(resolved)}

    return TestClient(app, raise_server_exceptions=False)


def test_the_subject_dependency_runs_behind_a_mounted_route() -> None:
    """Mounted on a real app the dependency reads the request rather than a query field.

    FastAPI resolves `request: Request` against this module's globals under postponed
    annotations, so a name visible only under `TYPE_CHECKING` leaves the parameter read as
    a query field and every call answers 422 without the dependency ever running.
    """
    response = _mounted(subject_dependency()).get("/who", headers=native_header(NATIVE_CLAIMS))
    assert response.status_code == 200
    assert response.json() == {"subject": "user-abc-123"}


def test_a_mounted_subject_dependency_still_refuses_an_unauthenticated_request() -> None:
    """The 401 survives the mount: an absent authorizer is not a validation error."""
    response = _mounted(subject_dependency()).get("/who")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_an_optional_subject_dependency_answers_empty_behind_a_route() -> None:
    """With `required=False` a mounted route sees `""` rather than a 422."""
    response = _mounted(subject_dependency(required=False)).get("/who")
    assert response.status_code == 200
    assert response.json() == {"subject": ""}


def test_the_claims_dependency_runs_behind_a_mounted_route() -> None:
    """`authorizer_claims` is annotated the same way and resolves the same globals."""
    response = _mounted(authorizer_claims(), key="claims").get("/who", headers=native_header(NATIVE_CLAIMS))
    assert response.status_code == 200
    assert response.json()["claims"]["sub"] == "user-abc-123"
