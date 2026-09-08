"""Tests for `webbpulse.http`.

The `client_ip` cases carry most of the weight. The previous per-app implementation read a
scope key Mangum set and the Web Adapter does not, so on migration it stopped matching and
fell through to a spoofable header without anything failing. These tests pin both the
supported shapes and the refusal to trust `X-Forwarded-For`.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest
from botocore.exceptions import ClientError
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from webbpulse.http import (
    DYNAMODB_RETRY_AFTER_SECONDS,
    REQUEST_CONTEXT_HEADER,
    REQUEST_ID_HEADER,
    client_ip,
    create_app,
    error_body,
    install_dynamodb_handlers,
    mount_all,
    request_id,
)


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
