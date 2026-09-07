"""Tests for `webbpulse.http`.

The `client_ip` cases carry most of the weight. The previous per-app implementation read a
scope key Mangum set and the Web Adapter does not, so on migration it stopped matching and
fell through to a spoofable header without anything failing. These tests pin both the
supported shapes and the refusal to trust `X-Forwarded-For`.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from webbpulse.http import (
    REQUEST_CONTEXT_HEADER,
    REQUEST_ID_HEADER,
    client_ip,
    create_app,
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
