"""Tests for the conditional GET helpers in `webbpulse.http`."""

from __future__ import annotations

import re
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from pydantic import BaseModel
from starlette.responses import Response

from webbpulse.http import (
    CONDITIONAL_CACHE_CONTROL,
    DEFAULT_CORS_ALLOW_HEADERS,
    conditional_response,
    create_app,
    etag_matches,
    not_modified_response,
    weak_etag,
)

WEAK_ETAG = re.compile(r'^W/"[0-9a-f]{32}"$')


class Issue(BaseModel):
    """A payload model for the tests."""

    id: str
    title: str


def _app() -> FastAPI:
    """An app with a payload-tagged route, a version-tagged route and a POST."""
    app = FastAPI()
    state: dict[str, Any] = {"title": "first", "version": 1, "loads": 0}

    @app.get("/issues")
    async def issues(request: Request) -> Response:
        """The payload is the tag."""
        return conditional_response(request, [Issue(id="1", title=str(state["title"]))])

    @app.get("/versioned")
    async def versioned(request: Request) -> Response:
        """The version is the tag and the payload loads only on a miss."""
        tag = weak_etag(version=str(state["version"]))
        unchanged = not_modified_response(request, tag)
        if unchanged is not None:
            return unchanged
        state["loads"] = int(state["loads"]) + 1
        return conditional_response(request, {"version": state["version"]}, etag=tag)

    @app.post("/issues")
    async def create(request: Request) -> Response:
        """A write never answers 304."""
        return conditional_response(request, {"ok": True}, status_code=201)

    app.state.data = state
    return app


@pytest.fixture
def client() -> TestClient:
    """A test client over the conditional routes."""
    return TestClient(_app())


def test_weak_etag_has_the_documented_format() -> None:
    """A tag is `W/"` plus 32 lowercase hex characters plus `"`."""
    assert WEAK_ETAG.match(weak_etag({"a": 1}))
    assert WEAK_ETAG.match(weak_etag(version=7))


def test_weak_etag_is_stable_over_key_order_and_models() -> None:
    """Key order does not change the tag, and a model tags like its dumped dict."""
    assert weak_etag({"a": 1, "b": 2}) == weak_etag({"b": 2, "a": 1})
    assert weak_etag(Issue(id="1", title="x")) == weak_etag({"id": "1", "title": "x"})
    assert weak_etag({"a": 1}) != weak_etag({"a": 2})


def test_a_version_ignores_the_payload() -> None:
    """With `version`, the payload plays no part in the tag."""
    assert weak_etag({"a": 1}, version="v1") == weak_etag({"a": 2}, version="v1")
    assert weak_etag(version="v1") != weak_etag(version="v2")


@pytest.mark.parametrize(
    ("header", "matches"),
    [
        (None, False),
        ("", False),
        ('W/"abc"', True),
        ('"abc"', True),
        ('"x", W/"abc"', True),
        ("*", True),
        ('W/"abd"', False),
    ],
)
def test_etag_matches_uses_weak_comparison(header: str | None, matches: bool) -> None:
    """Weak and strong forms compare alike, lists and `*` are honoured."""
    assert etag_matches(header, 'W/"abc"') is matches


def test_a_first_get_returns_the_body_and_the_headers(client: TestClient) -> None:
    """The 200 carries the JSON body, a weak ETag and `private, no-cache`."""
    response = client.get("/issues")

    assert response.status_code == 200
    assert response.json() == [{"id": "1", "title": "first"}]
    assert WEAK_ETAG.match(response.headers["etag"])
    assert response.headers["cache-control"] == CONDITIONAL_CACHE_CONTROL


def test_a_matching_if_none_match_gets_an_empty_304(client: TestClient) -> None:
    """Sending the tag back answers 304 with no body and the same headers."""
    etag = client.get("/issues").headers["etag"]

    response = client.get("/issues", headers={"if-none-match": etag})

    assert response.status_code == 304
    assert response.content == b""
    assert response.headers["etag"] == etag
    assert response.headers["cache-control"] == CONDITIONAL_CACHE_CONTROL
    assert "content-type" not in response.headers


def test_a_changed_payload_gets_a_new_200(client: TestClient) -> None:
    """Once the payload changes, the old tag no longer matches."""
    etag = client.get("/issues").headers["etag"]
    client.app.state.data["title"] = "second"  # type: ignore[attr-defined]

    response = client.get("/issues", headers={"If-None-Match": etag})

    assert response.status_code == 200
    assert response.json()[0]["title"] == "second"
    assert response.headers["etag"] != etag


def test_a_version_route_skips_the_load_on_a_hit(client: TestClient) -> None:
    """`not_modified_response` lets a route answer 304 before it loads anything."""
    etag = client.get("/versioned").headers["etag"]

    response = client.get("/versioned", headers={"If-None-Match": etag})

    assert response.status_code == 304
    assert client.app.state.data["loads"] == 1  # type: ignore[attr-defined]


def test_a_post_never_answers_304(client: TestClient) -> None:
    """Only GET and HEAD are conditional."""
    etag = weak_etag({"ok": True})

    response = client.post("/issues", headers={"If-None-Match": etag})

    assert response.status_code == 201
    assert response.json() == {"ok": True}


def test_cors_allows_if_none_match_and_exposes_etag() -> None:
    """A cross-origin poller may send `If-None-Match` and read `ETag`."""
    assert "If-None-Match" in DEFAULT_CORS_ALLOW_HEADERS
    app = create_app(cors_allow_origins=["https://app.example.com"], instrument=False)

    @app.get("/issues")
    async def issues(request: Request) -> Response:
        """A conditional route."""
        return conditional_response(request, {"items": []})

    client = TestClient(app)
    preflight = client.options(
        "/issues",
        headers={
            "Origin": "https://app.example.com",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "if-none-match",
        },
    )
    response = client.get("/issues", headers={"Origin": "https://app.example.com"})

    assert preflight.status_code == 200
    assert "if-none-match" in preflight.headers["access-control-allow-headers"].lower()
    exposed = {h.strip() for h in response.headers["access-control-expose-headers"].split(",")}
    assert "ETag" in exposed
