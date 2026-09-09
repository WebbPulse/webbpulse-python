"""Tests for `webbpulse.http`.

The `client_ip` cases carry most of the weight. The previous per-app implementation read a
scope key Mangum set and the Web Adapter does not, so on migration it stopped matching and
fell through to a spoofable header without anything failing. These tests pin both the
supported shapes and the refusal to trust `X-Forwarded-For`.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import sys
from typing import Any
from unittest import mock

import pytest
from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from webbpulse.http import (
    DYNAMODB_RETRY_AFTER_SECONDS,
    REQUEST_CONTEXT_HEADER,
    REQUEST_ID_HEADER,
    ErrorSpec,
    bind_user_id,
    client_ip,
    create_app,
    error_body,
    install_dynamodb_handlers,
    mount_all,
    register_error_handlers,
    request_id,
    user_id_dependency,
)
from webbpulse.logging import configure_logging


def _request(
    headers: dict[str, str] | None = None, client: tuple[str, int] | None = None
) -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    scope: dict[str, Any] = {"type": "http", "method": "GET", "path": "/", "headers": raw}
    if client is not None:
        scope["client"] = client
    return Request(scope)


def _context_header(context: dict[str, Any]) -> dict[str, str]:
    return {REQUEST_CONTEXT_HEADER: json.dumps(context)}


def test_client_ip_reads_the_http_api_v2_shape() -> None:
    request = _request(_context_header({"http": {"sourceIp": "203.0.113.7"}}))
    assert client_ip(request) == "203.0.113.7"


def test_client_ip_reads_the_rest_api_v1_shape() -> None:
    """REST APIs use payload format 1.0, where the source IP is under `identity`."""
    request = _request(_context_header({"identity": {"sourceIp": "198.51.100.9"}}))
    assert client_ip(request) == "198.51.100.9"


def test_client_ip_prefers_v2_when_both_are_present() -> None:
    request = _request(
        _context_header(
            {"http": {"sourceIp": "203.0.113.7"}, "identity": {"sourceIp": "198.51.100.9"}}
        )
    )
    assert client_ip(request) == "203.0.113.7"


def test_client_ip_never_trusts_x_forwarded_for() -> None:
    """The leftmost hop is caller controlled, so trusting it lets anyone mint identities."""
    request = _request(
        {**_context_header({"http": {"sourceIp": "203.0.113.7"}}), "X-Forwarded-For": "10.0.0.1"},
    )
    assert client_ip(request) == "203.0.113.7"


def test_client_ip_ignores_x_forwarded_for_even_with_no_request_context() -> None:
    request = _request({"X-Forwarded-For": "10.0.0.1"}, client=("127.0.0.1", 5000))
    assert client_ip(request) == "127.0.0.1", "the peer address, never the spoofable header"


def test_client_ip_falls_back_to_the_peer_for_local_development() -> None:
    request = _request(client=("127.0.0.1", 5000))
    assert client_ip(request) == "127.0.0.1"


def test_client_ip_can_refuse_the_local_fallback() -> None:
    request = _request(client=("127.0.0.1", 5000))
    assert client_ip(request, local_fallback=False) == "unknown"


def test_client_ip_is_unknown_with_nothing_to_go_on() -> None:
    assert client_ip(_request()) == "unknown"


def test_client_ip_survives_a_malformed_context_header() -> None:
    """A parse failure must not 500 the request; it degrades to the fallback."""
    request = _request({REQUEST_CONTEXT_HEADER: "{not json"}, client=("127.0.0.1", 5000))
    assert client_ip(request) == "127.0.0.1"


@pytest.mark.parametrize(
    "context",
    [{"http": {}}, {"identity": {}}, {"http": {"sourceIp": ""}}, {"http": "not-an-object"}],
)
def test_client_ip_handles_a_context_without_a_usable_source_ip(context: dict[str, Any]) -> None:
    request = _request(_context_header(context), client=("127.0.0.1", 5000))
    assert client_ip(request) == "127.0.0.1"


def test_health_route_is_always_two_hundred() -> None:
    """The Web Adapter polls this on every cold start, so it must never touch a dependency."""
    client = TestClient(create_app(service_name="posts", version="1.2.3"))
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert body["service"] == "posts"
    assert body["version"] == "1.2.3"


def test_a_request_id_is_minted_and_echoed() -> None:
    client = TestClient(create_app())
    response = client.get("/health")
    assert response.headers[REQUEST_ID_HEADER]


def test_an_inbound_request_id_is_honoured() -> None:
    client = TestClient(create_app())
    response = client.get("/health", headers={REQUEST_ID_HEADER: "edge-abc"})
    assert response.headers[REQUEST_ID_HEADER] == "edge-abc"


def test_an_oversized_request_id_is_truncated() -> None:
    """An unbounded header would inflate every downstream log line for that request."""
    client = TestClient(create_app())
    response = client.get("/health", headers={REQUEST_ID_HEADER: "x" * 500})
    assert len(response.headers[REQUEST_ID_HEADER]) == 128


def test_the_request_id_is_available_as_a_dependency() -> None:
    router = APIRouter()

    @router.get("/whoami")
    async def whoami(request: Request) -> dict[str, str]:
        return {"rid": request_id(request)}

    client = TestClient(create_app([router]))
    response = client.get("/whoami", headers={REQUEST_ID_HEADER: "known"})
    assert response.json() == {"rid": "known"}


def test_http_exceptions_render_the_error_envelope() -> None:
    router = APIRouter()

    @router.get("/missing")
    async def missing() -> None:
        raise HTTPException(status_code=404, detail="No such post.")

    client = TestClient(create_app([router]))
    response = client.get("/missing")
    assert response.status_code == 404
    body = response.json()
    assert body["success"] is False
    assert body["status"] == 404
    assert body["message"] == "No such post."
    assert body["request_id"]


def test_validation_errors_do_not_echo_the_offending_value() -> None:
    """`exc.errors()` can carry a password or a token, so the input is never returned."""
    router = APIRouter()

    @router.get("/items")
    async def items(count: int) -> dict[str, int]:
        return {"count": count}

    client = TestClient(create_app([router]))
    response = client.get("/items", params={"count": "sup3r-s3cret"})
    assert response.status_code == 422
    body = response.json()
    assert body["success"] is False
    assert "sup3r-s3cret" not in json.dumps(body), "the rejected input must not be echoed back"
    assert body["errors"][0]["loc"] == ["query", "count"]


def test_an_unhandled_exception_becomes_a_generic_five_hundred() -> None:
    router = APIRouter()

    @router.get("/boom")
    async def boom() -> None:
        raise RuntimeError("connection string postgres://user:hunter2@host/db")

    client = TestClient(create_app([router]), raise_server_exceptions=False)
    response = client.get("/boom")
    assert response.status_code == 500
    body = response.json()
    assert body["message"] == "Internal server error."
    assert "hunter2" not in json.dumps(body), "internal detail must not reach the caller"
    assert body["request_id"], "the request id is how the caller's report joins to the log"


def test_cors_headers_are_applied_for_a_listed_origin() -> None:
    app = create_app(cors_allow_origins=["https://webbpulse.com"])
    client = TestClient(app)
    response = client.get("/health", headers={"Origin": "https://webbpulse.com"})
    assert response.headers["access-control-allow-origin"] == "https://webbpulse.com"
    assert response.headers["access-control-allow-credentials"] == "true"


def test_cors_headers_are_present_on_an_error_response() -> None:
    """Without CORS outermost, a browser reports an opaque CORS failure, not the real status."""
    router = APIRouter()

    @router.get("/missing")
    async def missing() -> None:
        raise HTTPException(status_code=404, detail="Gone.")

    app = create_app([router], cors_allow_origins=["https://webbpulse.com"])
    response = TestClient(app).get("/missing", headers={"Origin": "https://webbpulse.com"})
    assert response.status_code == 404
    assert response.headers["access-control-allow-origin"] == "https://webbpulse.com"


def test_wildcard_origins_with_credentials_are_rejected() -> None:
    """The CORS specification forbids the pair, and browsers, not servers, enforce it."""
    with pytest.raises(ValueError, match="wildcard origin"):
        create_app(cors_allow_origins=["*"], cors_allow_credentials=True)


def test_settings_supply_the_cors_configuration() -> None:
    from webbpulse.config import BaseServiceSettings

    settings = BaseServiceSettings(cors_allow_origins=["https://a.example"])
    app = create_app(settings=settings)
    response = TestClient(app).get("/health", headers={"Origin": "https://a.example"})
    assert response.headers["access-control-allow-origin"] == "https://a.example"


def test_routers_can_be_mounted_under_a_prefix() -> None:
    router = APIRouter()

    @router.get("/posts")
    async def posts() -> list[str]:
        return ["a"]

    client = TestClient(create_app([router], router_prefix="/api/v1"))
    assert client.get("/api/v1/posts").status_code == 200


def _domain_app(name: str) -> FastAPI:
    router = APIRouter()

    @router.get("/")
    async def index() -> dict[str, str]:
        return {"domain": name}

    return create_app([router], service_name=name)


def test_mount_all_serves_every_domain_from_one_app() -> None:
    """The local and test composition root, built from the same app objects as production."""
    parent = mount_all(
        {"/api/v1/posts": _domain_app("posts"), "/api/v1/skills": _domain_app("skills")}
    )
    client = TestClient(parent)

    assert client.get("/api/v1/posts/").json() == {"domain": "posts"}
    assert client.get("/api/v1/skills/").json() == {"domain": "skills"}
    assert client.get("/health").json()["status"] == "healthy"


def test_a_mounted_app_keeps_its_own_error_handlers() -> None:
    router = APIRouter()

    @router.get("/boom")
    async def boom() -> None:
        raise HTTPException(status_code=418, detail="Domain specific.")

    parent = mount_all({"/api/v1/posts": create_app([router])})
    response = TestClient(parent).get("/api/v1/posts/boom")
    assert response.status_code == 418
    assert response.json()["message"] == "Domain specific."


def test_mount_all_rejects_a_relative_mount_path() -> None:
    with pytest.raises(ValueError, match="must start with"):
        mount_all({"api/v1/posts": _domain_app("posts")})


def test_a_deliberate_five_hundred_does_not_echo_its_detail() -> None:
    """A 5xx detail goes to the log, never to the caller.

    `raise HTTPException(500, f"could not read {table}")` is a normal thing to write, and
    echoing it hands an attacker internals for free. The request id joins the response to
    the log line that does carry the detail.
    """
    router = APIRouter()

    @router.get("/boom")
    async def boom() -> None:
        raise HTTPException(status_code=500, detail="connection to webbpulse-prod-posts failed")

    client = TestClient(create_app([router]), raise_server_exceptions=False)
    response = client.get("/boom")

    assert response.status_code == 500
    body = response.json()
    assert body["message"] == "Internal server error."
    assert "webbpulse-prod-posts" not in response.text, "the internal detail must not leak"


def test_a_four_hundred_still_carries_its_detail() -> None:
    """Only 5xx is scrubbed. A 4xx detail is written for the caller and must survive."""
    router = APIRouter()

    @router.get("/nope")
    async def nope() -> None:
        raise HTTPException(status_code=404, detail="No such post.")

    client = TestClient(create_app([router]), raise_server_exceptions=False)
    response = client.get("/nope")

    assert response.status_code == 404
    assert response.json()["message"] == "No such post."


def test_cors_exposes_the_rate_limit_headers() -> None:
    """A header a browser cannot read is one the limiter did not emit, to a fetch() caller."""
    app = create_app(cors_allow_origins=["https://webbpulse.com"])
    response = TestClient(app).get("/health", headers={"Origin": "https://webbpulse.com"})

    exposed = {h.strip() for h in response.headers["access-control-expose-headers"].split(",")}
    for header in ("RateLimit", "RateLimit-Policy", "Retry-After", REQUEST_ID_HEADER):
        assert header in exposed, f"{header} must be readable by the browser"
    for header in ("X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"):
        assert header in exposed, f"{header} is emitted, so it must be exposed too"


# ---- the 0.3.0 envelope options ------------------------------------------------------
#
# The whole point of these being options is that a 0.2.0 caller is unaffected, so the
# first test here pins the default body exactly rather than field by field.


def test_the_default_envelope_is_byte_identical_to_0_2_0() -> None:
    """Portfolio reads this body. Adding a key by default would be a breaking change."""
    router = APIRouter()

    @router.get("/missing")
    async def missing() -> None:
        raise HTTPException(status_code=404, detail="No such post.")

    response = TestClient(create_app([router])).get("/missing")
    body = response.json()
    assert set(body) == {"success", "status", "message", "request_id"}, (
        "no error_code and no details unless the service opts in"
    )


def test_error_codes_add_a_stable_code_per_status() -> None:
    router = APIRouter()

    @router.get("/missing")
    async def missing() -> None:
        raise HTTPException(status_code=404, detail="No such post.")

    @router.get("/conflict")
    async def conflict() -> None:
        raise HTTPException(status_code=409, detail="Already exists.")

    client = TestClient(create_app([router], error_codes=True))
    assert client.get("/missing").json()["error_code"] == "NOT_FOUND"
    assert client.get("/conflict").json()["error_code"] == "CONFLICT"


def test_the_four_base_fields_survive_every_option() -> None:
    router = APIRouter()

    @router.get("/missing")
    async def missing() -> None:
        raise HTTPException(status_code=404, detail="No such post.")

    app = create_app([router], error_codes=True, validation_details=True)
    body = TestClient(app).get("/missing").json()
    for field in ("success", "status", "message", "request_id"):
        assert field in body, f"{field} is always present, whatever the options say"


def test_a_route_can_override_the_error_code_at_the_raise_site() -> None:
    """A dict detail carries a per-response code without a global option."""
    router = APIRouter()

    @router.get("/missing")
    async def missing() -> None:
        raise HTTPException(
            status_code=404,
            detail={"message": "No such post.", "error_code": "POST_NOT_FOUND"},
        )

    body = TestClient(create_app([router])).get("/missing").json()
    assert body["message"] == "No such post."
    assert body["error_code"] == "POST_NOT_FOUND", "explicit at the raise site beats the default"


def test_a_dict_detail_without_a_message_does_not_leak_the_dict() -> None:
    router = APIRouter()

    @router.get("/weird")
    async def weird() -> None:
        raise HTTPException(status_code=400, detail={"internal": "table=webbpulse-prod"})

    body = TestClient(create_app([router])).get("/weird").json()
    assert body["message"] == "Request failed."
    assert "webbpulse-prod" not in json.dumps(body), "an unrecognised detail must not be echoed"


def test_validation_details_add_the_flat_field_shape() -> None:
    router = APIRouter()

    @router.get("/items")
    async def items(count: int) -> dict[str, int]:
        return {"count": count}

    app = create_app([router], validation_details=True)
    response = TestClient(app).get("/items", params={"count": "nope"})

    assert response.status_code == 422
    body = response.json()
    assert body["details"][0]["field"] == "count", "the query/body prefix is dropped"
    assert body["details"][0]["message"]
    assert body["details"][0]["type"]
    assert body["errors"], "the 0.2.0 key stays alongside it"


def test_validation_details_never_echo_the_offending_value() -> None:
    """The same guarantee the `errors` key has always had, now for `details` too."""
    router = APIRouter()

    @router.get("/items")
    async def items(count: int) -> dict[str, int]:
        return {"count": count}

    app = create_app([router], validation_details=True, error_codes=True)
    response = TestClient(app).get("/items", params={"count": "sup3r-s3cret"})

    body = response.json()
    assert "sup3r-s3cret" not in json.dumps(body)
    assert body["error_code"] == "VALIDATION_ERROR"


def test_error_body_omits_the_optional_fields_when_unset() -> None:
    request = _request()
    assert set(error_body(500, "Boom.", request)) == {
        "success",
        "status",
        "message",
        "request_id",
    }


def test_error_body_includes_the_optional_fields_when_set() -> None:
    request = _request()
    body = error_body(409, "Conflict.", request, error_code="CONFLICT", details={"a": 1})
    assert body["error_code"] == "CONFLICT"
    assert body["details"] == {"a": 1}
    assert body["success"] is False and body["status"] == 409


# ---- raw routing errors --------------------------------------------------------------
#
# CarModPicker leaked Starlette's own {"detail": "Not Found"} for an unmatched route,
# which is a different shape from every handled error in the same API.


def test_an_unmatched_route_renders_the_envelope() -> None:
    response = TestClient(create_app()).get("/no-such-path")

    assert response.status_code == 404
    body = response.json()
    assert "detail" not in body, "the raw Starlette shape must not survive"
    assert body["success"] is False
    assert body["status"] == 404
    assert body["message"] == "The requested resource was not found."
    assert body["request_id"]


def test_a_wrong_method_renders_the_envelope() -> None:
    router = APIRouter()

    @router.get("/thing")
    async def thing() -> dict[str, bool]:
        return {"ok": True}

    response = TestClient(create_app([router])).post("/thing")

    assert response.status_code == 405
    body = response.json()
    assert "detail" not in body
    assert body["message"] == "That method is not allowed on this resource."


def test_routing_errors_carry_an_error_code_when_enabled() -> None:
    client = TestClient(create_app(error_codes=True))
    assert client.get("/no-such-path").json()["error_code"] == "NOT_FOUND"


# ---- DynamoDB handlers ---------------------------------------------------------------
#
# Opt in, because installing them imports botocore and the base install has no boto3.
# The mapping is the part worth pinning: a failed condition is a 409 and not a 500, and
# throttling is a retryable 503 and not a 500, or a client is told not to bother retrying.


def _client_error(code: str, **extra: Any) -> ClientError:
    """A botocore ClientError shaped the way DynamoDB actually returns one."""
    response: dict[str, Any] = {"Error": {"Code": code, "Message": f"{code} occurred."}, **extra}
    return ClientError(response, "PutItem")  # type: ignore[arg-type]


def _dynamodb_app(raises: ClientError, **kwargs: Any) -> TestClient:
    router = APIRouter()

    @router.get("/write")
    async def write() -> None:
        raise raises

    app = create_app([router], dynamodb_handlers=True, **kwargs)
    return TestClient(app, raise_server_exceptions=False)


def test_a_failed_condition_is_a_conflict_not_a_server_error() -> None:
    """Someone else got there first, which is a caller visible conflict."""
    response = _dynamodb_app(_client_error("ConditionalCheckFailedException")).get("/write")

    assert response.status_code == 409
    body = response.json()
    assert body["success"] is False
    assert body["status"] == 409
    assert body["request_id"]


@pytest.mark.parametrize(
    "code",
    [
        "ProvisionedThroughputExceededException",
        "ThrottlingException",
        "RequestLimitExceeded",
    ],
)
def test_throttling_is_a_retryable_503_with_retry_after(code: str) -> None:
    response = _dynamodb_app(_client_error(code)).get("/write")

    assert response.status_code == 503
    assert response.headers["Retry-After"] == str(DYNAMODB_RETRY_AFTER_SECONDS)
    assert response.json()["status"] == 503


def test_a_missing_table_is_a_five_hundred_and_tells_the_caller_nothing() -> None:
    """A missing table is a deployment fault, never the caller's, and never a 404."""
    error = _client_error("ResourceNotFoundException")
    response = _dynamodb_app(error).get("/write")

    assert response.status_code == 500
    assert response.json()["message"] == "Internal server error."
    assert "ResourceNotFound" not in response.text, "the AWS error text must not leak"


def test_a_missing_table_logs_at_error(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.ERROR, logger="webbpulse.http"):
        _dynamodb_app(_client_error("ResourceNotFoundException")).get("/write")

    assert any(r.levelno == logging.ERROR for r in caplog.records), "a missing table is loud"


def test_a_cancelled_transaction_with_a_failed_condition_is_a_conflict() -> None:
    error = _client_error(
        "TransactionCanceledException",
        CancellationReasons=[{"Code": "None"}, {"Code": "ConditionalCheckFailed"}],
    )
    response = _dynamodb_app(error).get("/write")

    assert response.status_code == 409, "any failed condition in the transaction makes it a 409"


def test_a_cancelled_transaction_without_a_failed_condition_is_a_five_hundred() -> None:
    """Treating the whole class as a 409 would hide a real fault, so the reasons decide."""
    error = _client_error(
        "TransactionCanceledException",
        CancellationReasons=[{"Code": "TransactionConflict"}],
    )
    response = _dynamodb_app(error).get("/write")

    assert response.status_code == 500


def test_a_cancelled_transaction_with_no_reasons_is_a_five_hundred() -> None:
    response = _dynamodb_app(_client_error("TransactionCanceledException")).get("/write")

    assert response.status_code == 500


def test_an_unrecognised_client_error_is_a_generic_five_hundred() -> None:
    error = _client_error("ValidationException")
    response = _dynamodb_app(error).get("/write")

    assert response.status_code == 500
    assert response.json()["message"] == "Internal server error."


def test_dynamodb_errors_carry_an_error_code_when_enabled() -> None:
    client = _dynamodb_app(_client_error("ConditionalCheckFailedException"), error_codes=True)
    assert client.get("/write").json()["error_code"] == "CONFLICT"


def test_dynamodb_handlers_log_with_the_request_id(caplog: pytest.LogCaptureFixture) -> None:
    """The response body carries no AWS detail, so the log line is how the two join up."""
    with caplog.at_level(logging.WARNING, logger="webbpulse.http"):
        response = _dynamodb_app(_client_error("ThrottlingException")).get(
            "/write", headers={REQUEST_ID_HEADER: "trace-me"}
        )

    assert response.json()["request_id"] == "trace-me"
    assert any(getattr(r, "request_id", None) == "trace-me" for r in caplog.records)


def test_install_dynamodb_handlers_can_be_called_on_its_own() -> None:
    """The separate entry point, for an app not built by `create_app`."""
    router = APIRouter()

    @router.get("/write")
    async def write() -> None:
        raise _client_error("ConditionalCheckFailedException")

    app = create_app([router])
    install_dynamodb_handlers(app)

    response = TestClient(app, raise_server_exceptions=False).get("/write")
    assert response.status_code == 409


def test_the_dynamodb_handlers_are_absent_unless_requested() -> None:
    """Without the opt in, a ClientError is just an unhandled exception: a plain 500."""
    router = APIRouter()

    @router.get("/write")
    async def write() -> None:
        raise _client_error("ConditionalCheckFailedException")

    response = TestClient(create_app([router]), raise_server_exceptions=False).get("/write")
    assert response.status_code == 500, "no 409 mapping without dynamodb_handlers=True"


# ---- Caller-supplied exception map ------------------------------------------------------
#
# The case the botocore branches cannot reach. A repository layer that translates a
# conditional check failure into its own class means no `ClientError` ever reaches the
# handler, so before this the consumer kept thin handlers of its own around `error_body`.


class ItemNotFound(Exception):
    """Stand-in for a consumer's own repository exception."""


class ConditionFailed(Exception):
    pass


class TransactionCanceled(Exception):
    pass


_ADOPTION_MAP: dict[type[BaseException], int | ErrorSpec] = {
    ItemNotFound: 404,
    ConditionFailed: 409,
    TransactionCanceled: 409,
}


def _mapped_app(raises: BaseException, **kwargs: Any) -> TestClient:
    router = APIRouter()

    @router.get("/work")
    async def work() -> None:
        raise raises

    app = create_app([router], **kwargs)
    return TestClient(app, raise_server_exceptions=False)


def test_a_mapped_exception_renders_the_envelope_at_its_status() -> None:
    """The whole point: the consumer's own class, no botocore involved."""
    response = _mapped_app(ItemNotFound("post 7"), exception_map=_ADOPTION_MAP).get("/work")

    assert response.status_code == 404
    body = response.json()
    assert body["success"] is False
    assert body["status"] == 404
    assert body["request_id"]
    assert "error_code" not in body, "off unless error_codes=True"


@pytest.mark.parametrize("exc", [ConditionFailed(), TransactionCanceled()])
def test_the_conflict_entries_are_four_oh_nines(exc: BaseException) -> None:
    response = _mapped_app(exc, exception_map=_ADOPTION_MAP).get("/work")
    assert response.status_code == 409


def test_a_mapped_conflict_reads_exactly_like_the_botocore_one() -> None:
    """A consumer dropping its own handlers must not change what callers receive."""
    mapped = _mapped_app(ConditionFailed(), exception_map={ConditionFailed: 409}).get("/work")
    botocore_side = _dynamodb_app(_client_error("ConditionalCheckFailedException")).get("/write")

    assert mapped.json()["message"] == botocore_side.json()["message"]
    assert set(mapped.json()) == set(botocore_side.json())


def test_the_internal_exception_message_never_reaches_the_caller() -> None:
    response = _mapped_app(ItemNotFound("pk=USER#42 sk=SECRET"), exception_map=_ADOPTION_MAP).get(
        "/work"
    )
    assert "SECRET" not in response.text, "the exception's own text must not leak"


def test_a_mapped_status_carries_its_default_message() -> None:
    response = _mapped_app(ItemNotFound(), exception_map={ItemNotFound: 404}).get("/work")
    assert response.json()["message"] == "The requested resource was not found."


def test_an_error_spec_sets_the_message_and_the_code() -> None:
    spec = ErrorSpec(404, message="No such post.", error_code="POST_NOT_FOUND")
    response = _mapped_app(
        ItemNotFound(), exception_map={ItemNotFound: spec}, error_codes=True
    ).get("/work")

    body = response.json()
    assert body["message"] == "No such post."
    assert body["error_code"] == "POST_NOT_FOUND"


def test_an_error_spec_code_is_still_suppressed_without_error_codes() -> None:
    """`error_codes=False` must yield the 0.3.0 body, whatever the spec asks for."""
    spec = ErrorSpec(404, error_code="POST_NOT_FOUND")
    response = _mapped_app(ItemNotFound(), exception_map={ItemNotFound: spec}).get("/work")

    assert "error_code" not in response.json()


def test_a_mapped_status_gets_the_per_status_code_when_enabled() -> None:
    response = _mapped_app(
        ConditionFailed(), exception_map={ConditionFailed: 409}, error_codes=True
    ).get("/work")
    assert response.json()["error_code"] == "CONFLICT"


def test_an_unlisted_status_falls_back_to_a_generic_code() -> None:
    response = _mapped_app(ItemNotFound(), exception_map={ItemNotFound: 418}, error_codes=True).get(
        "/work"
    )

    assert response.status_code == 418
    assert response.json()["error_code"] == "HTTP_ERROR"
    assert response.json()["message"] == "Request failed.", "no wording for an unlisted status"


def test_a_spec_can_ask_for_retry_after() -> None:
    spec = ErrorSpec(503, retry_after=5)
    response = _mapped_app(ConditionFailed(), exception_map={ConditionFailed: spec}).get("/work")

    assert response.status_code == 503
    assert response.headers["Retry-After"] == "5"


def test_the_throttling_retry_after_still_comes_from_the_botocore_path() -> None:
    """The 0.3.0 header on the throttling branch is unchanged by the new parameter."""
    client = _dynamodb_app(_client_error("ThrottlingException"), exception_map=_ADOPTION_MAP)
    response = client.get("/write")

    assert response.status_code == 503
    assert response.headers["Retry-After"] == str(DYNAMODB_RETRY_AFTER_SECONDS)


def test_a_mapped_five_hundred_is_generic_and_logs_at_error(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A message written for an internal exception is not written for a stranger."""
    spec = ErrorSpec(500, message="the shard is wedged")
    with caplog.at_level(logging.ERROR, logger="webbpulse.http"):
        response = _mapped_app(ConditionFailed(), exception_map={ConditionFailed: spec}).get(
            "/work"
        )

    assert response.status_code == 500
    assert response.json()["message"] == "Internal server error."
    assert "wedged" not in response.text
    assert any(r.levelno == logging.ERROR for r in caplog.records)


def test_a_mapped_four_xx_logs_at_warning_with_the_request_id(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="webbpulse.http"):
        response = _mapped_app(ItemNotFound(), exception_map=_ADOPTION_MAP).get(
            "/work", headers={REQUEST_ID_HEADER: "map-me"}
        )

    assert response.json()["request_id"] == "map-me"
    assert any(getattr(r, "request_id", None) == "map-me" for r in caplog.records)
    assert any(getattr(r, "exception_type", None) == "ItemNotFound" for r in caplog.records)
    assert not any(r.levelno >= logging.ERROR for r in caplog.records), "a lost race is not a page"


def test_a_subclass_uses_its_own_entry_rather_than_the_base_one() -> None:
    class Missing(ItemNotFound):
        pass

    response = _mapped_app(Missing(), exception_map={ItemNotFound: 404, Missing: 410}).get("/work")
    assert response.status_code == 410


def test_a_subclass_without_its_own_entry_falls_back_to_the_base() -> None:
    class Missing(ItemNotFound):
        pass

    response = _mapped_app(Missing(), exception_map={ItemNotFound: 404}).get("/work")
    assert response.status_code == 404, "Starlette walks the MRO"


def test_the_map_works_alongside_the_botocore_handlers() -> None:
    """`dynamodb_handlers=True` and `exception_map` are not an either/or."""
    router = APIRouter()

    @router.get("/aws")
    async def aws() -> None:
        raise _client_error("ConditionalCheckFailedException")

    @router.get("/own")
    async def own() -> None:
        raise ItemNotFound()

    app = create_app([router], dynamodb_handlers=True, exception_map=_ADOPTION_MAP)
    client = TestClient(app, raise_server_exceptions=False)

    assert client.get("/aws").status_code == 409
    assert client.get("/own").status_code == 404


def test_the_map_needs_no_botocore_import() -> None:
    """Passing it without `dynamodb_handlers=True` must not reach for the AWS SDK."""
    router = APIRouter()

    @router.get("/own")
    async def own() -> None:
        raise ItemNotFound()

    app = FastAPI()
    app.include_router(router)
    with mock.patch.dict(sys.modules, {"botocore.exceptions": None}):
        register_error_handlers(app, exception_map={ItemNotFound: 404})

    assert TestClient(app, raise_server_exceptions=False).get("/own").status_code == 404


def test_install_dynamodb_handlers_takes_the_map_directly() -> None:
    """The separate entry point, for an app not built by `create_app`."""
    router = APIRouter()

    @router.get("/own")
    async def own() -> None:
        raise ConditionFailed()

    app = create_app([router])
    install_dynamodb_handlers(app, exception_map={ConditionFailed: 409})

    assert TestClient(app, raise_server_exceptions=False).get("/own").status_code == 409


def test_an_unmapped_exception_is_still_a_plain_five_hundred() -> None:
    """Omitting the parameter must leave 0.3.0 behaviour exactly as it was."""
    response = _mapped_app(ItemNotFound()).get("/work")

    assert response.status_code == 500
    assert response.json()["message"] == "Internal server error."


def test_an_exception_outside_the_map_is_unaffected_by_it() -> None:
    response = _mapped_app(RuntimeError("boom"), exception_map=_ADOPTION_MAP).get("/work")

    assert response.status_code == 500
    assert "boom" not in response.text


def test_a_non_exception_key_is_rejected_when_the_app_is_built() -> None:
    """A wiring mistake should fail at import, not as a 500 under load."""
    with pytest.raises(TypeError, match="exception classes"):
        create_app([], exception_map={"ItemNotFound": 404})  # type: ignore[dict-item]


def test_a_nonsense_value_is_rejected_when_the_app_is_built() -> None:
    with pytest.raises(TypeError, match="int status or an ErrorSpec"):
        create_app([], exception_map={ItemNotFound: "404"})  # type: ignore[dict-item]


def test_an_impossible_status_is_rejected_when_the_app_is_built() -> None:
    with pytest.raises(ValueError, match="valid HTTP status"):
        create_app([], exception_map={ItemNotFound: 42})


def test_an_empty_map_installs_nothing_and_raises_nothing() -> None:
    response = _mapped_app(ItemNotFound(), exception_map={}).get("/work")
    assert response.status_code == 500, "an empty map is the same as no map"


# --------------------------------------------------------------------------------------
# The sync dependency trap: `set_user_id` in a `def` dependency binds a context that
# Starlette's threadpool discards, so the handler and every log line after it see `"-"`.
# WebbPulse-Portfolio shipped that shape to production. These tests demonstrate the failure
# and then the fix, end to end, by parsing the JSON that `JsonFormatter` actually emitted.
# --------------------------------------------------------------------------------------


class _User:
    """The minimal shape of a service's user object: something with an `id`."""

    def __init__(self, user_id: str) -> None:
        self.id = user_id


def _resolve_user() -> _User:
    """A service's own user-resolving dependency, deliberately `def` rather than `async`."""
    return _User("u-42")


def _user_id_app(current_user: Any) -> FastAPI:
    """An app whose one route logs, and reports the `user_id` the handler itself can see.

    Two readings, because they can disagree and the disagreement is the whole point. The
    response body is what the handler sees at the moment it runs; the emitted log line is
    what `JsonFormatter` merged in, which is what actually reaches CloudWatch.
    """
    from webbpulse.log_context import user_id_var

    router = APIRouter()

    @router.get("/me")
    async def me(user: Any = Depends(current_user)) -> dict[str, str]:
        logging.getLogger("app.me").info("served")
        return {"handler_user_id": user_id_var.get(), "resolved_id": user.id}

    return create_app([router], instrument=False)


def _call_and_read_log(app: FastAPI, capsys: pytest.CaptureFixture[str]) -> tuple[Any, Any]:
    """Drive `/me` with logging configured, returning the body and the parsed log line."""
    configure_logging(level="INFO", force=True)
    # Discard anything `configure_logging` or the client setup wrote before the request.
    capsys.readouterr()

    body = TestClient(app).get("/me").json()

    lines = [line for line in capsys.readouterr().out.splitlines() if line.strip()]
    served = [
        payload
        for payload in (json.loads(line) for line in lines)
        if payload.get("message") == "served"
    ]
    assert len(served) == 1, lines
    return body, served[0]


def test_set_user_id_in_a_sync_dependency_never_reaches_the_handler_or_the_log(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The trap itself. Nothing raises; `user_id` is simply still the `"-"` placeholder.

    This is the production shape Portfolio shipped: a `def` dependency calling
    `set_user_id`. Starlette runs it through `anyio.to_thread.run_sync`, which copies the
    context into a worker thread, and the copy dies when the call returns.
    """
    from webbpulse.log_context import UNSET, set_user_id

    def current_user() -> _User:
        user = _resolve_user()
        set_user_id(user.id)  # Binds a context that is about to be thrown away.
        return user

    body, log_line = _call_and_read_log(_user_id_app(current_user), capsys)

    # The dependency ran and resolved the right user, which is why this is silent.
    assert body["resolved_id"] == "u-42"
    # And yet neither the handler nor the log line ever saw the id.
    assert body["handler_user_id"] == UNSET
    assert "user_id" not in log_line, (
        "if this key appears, the threadpool context copy now propagates and the "
        "user_id_dependency wrapper can be reconsidered"
    )


def test_user_id_dependency_binds_the_id_for_the_handler_and_the_log(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The fix. The same `def` resolver, wrapped, and the id reaches both readings."""
    body, log_line = _call_and_read_log(_user_id_app(user_id_dependency(_resolve_user)), capsys)

    assert body["resolved_id"] == "u-42"
    assert body["handler_user_id"] == "u-42"
    assert log_line["user_id"] == "u-42"


def test_an_async_dependency_that_awaits_bind_user_id_works_too(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The hand-rolled form of the same fix, for a service that wants its own wrapper."""

    async def current_user() -> _User:
        user = _resolve_user()
        await bind_user_id(user.id)
        return user

    body, log_line = _call_and_read_log(_user_id_app(current_user), capsys)

    assert body["handler_user_id"] == "u-42"
    assert log_line["user_id"] == "u-42"


def test_bind_user_id_returns_the_cleaned_value() -> None:
    """The coercion is `set_user_id`'s, and the return saves the caller repeating it."""
    from webbpulse.log_context import user_id_var

    async def run() -> str:
        return await bind_user_id(" 42\nx ")

    token = user_id_var.set("-")
    try:
        assert asyncio.run(run()) == "42 x"
    finally:
        user_id_var.reset(token)


def test_user_id_dependency_passes_the_resolved_object_through_unchanged() -> None:
    """A drop-in replacement returns the identical object, not a copy or an id."""
    sentinel = _User("u-7")
    dependency = user_id_dependency(lambda: sentinel)
    router = APIRouter()

    @router.get("/same")
    async def same(user: Any = Depends(dependency)) -> dict[str, bool]:
        return {"identical": user is sentinel}

    assert TestClient(create_app([router], instrument=False)).get("/same").json() == {
        "identical": True
    }


def test_user_id_dependency_wraps_an_async_resolver_too() -> None:
    async def current_user() -> _User:
        return _User("u-9")

    router = APIRouter()

    @router.get("/me")
    async def me(user: Any = Depends(user_id_dependency(current_user))) -> dict[str, str]:
        from webbpulse.log_context import user_id_var

        return {"user_id": user_id_var.get()}

    assert TestClient(create_app([router], instrument=False)).get("/me").json()["user_id"] == "u-9"


def test_user_id_dependency_keeps_the_wrapped_dependencys_own_dependencies() -> None:
    """FastAPI resolves the wrapped callable normally, so its signature still works."""

    def current_user(request: Request) -> _User:
        return _User(request.headers["x-test-user"])

    router = APIRouter()

    @router.get("/me")
    async def me(user: Any = Depends(user_id_dependency(current_user))) -> dict[str, str]:
        from webbpulse.log_context import user_id_var

        return {"user_id": user_id_var.get()}

    response = TestClient(create_app([router], instrument=False)).get(
        "/me", headers={"x-test-user": "u-hdr"}
    )
    assert response.json()["user_id"] == "u-hdr"


def test_user_id_dependency_binds_nothing_when_the_resolver_returns_none() -> None:
    """Optional authentication must leave the placeholder, not bind the string 'None'."""
    from webbpulse.log_context import UNSET

    router = APIRouter()

    @router.get("/me")
    async def me(user: Any = Depends(user_id_dependency(lambda: None))) -> dict[str, Any]:
        from webbpulse.log_context import user_id_var

        return {"user_id": user_id_var.get(), "user_is_none": user is None}

    body = TestClient(create_app([router], instrument=False)).get("/me").json()
    assert body == {"user_id": UNSET, "user_is_none": True}


def test_user_id_dependency_binds_nothing_when_the_attribute_is_missing() -> None:
    """A missing id logs without one rather than failing a request that would have worked."""
    from webbpulse.log_context import UNSET

    class _NoId:
        pass

    router = APIRouter()

    @router.get("/me")
    async def me(user: Any = Depends(user_id_dependency(_NoId))) -> dict[str, str]:
        from webbpulse.log_context import user_id_var

        return {"user_id": user_id_var.get()}

    assert TestClient(create_app([router], instrument=False)).get("/me").json()["user_id"] == UNSET


def test_user_id_dependency_honours_a_custom_attribute_name() -> None:
    class _Principal:
        sub = "sub-123"

    router = APIRouter()

    @router.get("/me")
    async def me(
        user: Any = Depends(user_id_dependency(_Principal, attribute="sub")),
    ) -> dict[str, str]:
        from webbpulse.log_context import user_id_var

        return {"user_id": user_id_var.get()}

    body = TestClient(create_app([router], instrument=False)).get("/me").json()
    assert body["user_id"] == "sub-123"


def test_user_id_dependency_honours_an_extract_callable() -> None:
    """For a claims dict or anything else where the id is not a plain attribute."""
    router = APIRouter()
    dependency = user_id_dependency(
        lambda: {"claims": {"sub": "claim-7"}},
        extract=lambda payload: payload["claims"]["sub"],
    )

    @router.get("/me")
    async def me(user: Any = Depends(dependency)) -> dict[str, str]:
        from webbpulse.log_context import user_id_var

        return {"user_id": user_id_var.get()}

    assert (
        TestClient(create_app([router], instrument=False)).get("/me").json()["user_id"] == "claim-7"
    )


def test_user_id_dependency_takes_the_wrapped_callables_name() -> None:
    """So FastAPI's errors and the OpenAPI operation ids name the service's dependency."""
    assert user_id_dependency(_resolve_user).__name__ == "_resolve_user"
    assert user_id_dependency(lambda: None).__name__ == "<lambda>"


def test_user_id_dependency_carries_the_wrapped_callables_docstring() -> None:
    assert user_id_dependency(_resolve_user).__doc__ == inspect.getdoc(_resolve_user)
