"""Tests for the fixed-window rate limiter and its FastAPI dependency."""

from __future__ import annotations

import logging
from typing import Any

import pytest
from botocore.exceptions import ClientError
from fastapi import Depends, FastAPI, Request

from webbpulse.ratelimit import (
    RateLimitDecision,
    RateLimiter,
    rate_limit,
    rate_limit_headers,
)


def _decision(**overrides: Any) -> RateLimitDecision:
    """Build an allowed decision, overriding any field by keyword."""
    defaults: dict[str, Any] = {
        "allowed": True,
        "limit": 100,
        "remaining": 50,
        "reset_after": 30,
        "window_seconds": 60,
    }
    return RateLimitDecision(**{**defaults, **overrides})


def test_rate_limit_headers_emit_the_structured_fields() -> None:
    """The RateLimit and RateLimit-Policy structured fields carry r, t, q and w."""
    headers = rate_limit_headers(_decision())

    assert headers["RateLimit"] == '"default";r=50;t=30'
    assert headers["RateLimit-Policy"] == '"default";q=100;w=60'


def test_rate_limit_headers_emit_the_x_prefixed_trio() -> None:
    """The X-RateLimit limit, remaining and reset headers are emitted too."""
    headers = rate_limit_headers(_decision())

    assert headers["X-RateLimit-Limit"] == "100"
    assert headers["X-RateLimit-Remaining"] == "50"
    assert headers["X-RateLimit-Reset"] == "30"


def test_rate_limit_headers_use_the_policy_name() -> None:
    """`policy_name` names the policy in both structured fields."""
    headers = rate_limit_headers(_decision(), policy_name="login")

    assert headers["RateLimit"] == '"login";r=50;t=30'
    assert headers["RateLimit-Policy"] == '"login";q=100;w=60'


def test_rate_limit_headers_clamp_remaining_at_zero() -> None:
    """A negative remaining is clamped to zero, which a structured field requires."""
    headers = rate_limit_headers(_decision(allowed=False, remaining=-5))

    assert headers["RateLimit"] == '"default";r=0;t=30', "r must be clamped, never negative"
    assert headers["X-RateLimit-Remaining"] == "0"


def test_rate_limit_decision_repr_is_readable() -> None:
    """`repr(RateLimitDecision)` includes the `allowed` flag."""
    assert "allowed=True" in repr(_decision())


@pytest.fixture
def limiter(rate_limit_table: Any) -> RateLimiter:
    """A limiter bound to the moto-backed `rate-limits` table."""
    assert rate_limit_table is not None
    return RateLimiter(prefix="", region_name="us-west-2")


def test_check_allows_up_to_the_limit_and_denies_the_next(limiter: RateLimiter) -> None:
    """`check` allows requests up to the limit and denies the one after it."""
    decisions = [limiter.check("198.51.100.1", limit=3, window_seconds=60, now=1_000.0) for _ in range(4)]

    assert [d.allowed for d in decisions] == [True, True, True, False], (
        "the first 3 requests must be allowed and the 4th denied"
    )
    assert decisions[3].failed_open is False


def test_check_decrements_remaining(limiter: RateLimiter) -> None:
    """`remaining` counts down to zero and clamps there."""
    remaining = [limiter.check("198.51.100.2", limit=3, window_seconds=60, now=1_000.0).remaining for _ in range(4)]

    assert remaining == [2, 1, 0, 0], "remaining must count down and then clamp at 0"


def test_a_rejected_request_still_increments_the_counter(limiter: RateLimiter) -> None:
    """A rejected request still counts, so the window has to drain rather than stop growing."""
    for _ in range(5):
        limiter.check("198.51.100.3", limit=2, window_seconds=60, now=1_000.0)

    item = limiter.get({"pk": "default#198.51.100.3#960"})
    assert item is not None, "the counter item must exist for the window"
    assert int(item["count"]) == 5, "every request counts, including the rejected ones"


def test_two_identities_are_independent_counters(limiter: RateLimiter) -> None:
    """Two identities keep separate counters."""
    for _ in range(3):
        limiter.check("198.51.100.4", limit=3, window_seconds=60, now=1_000.0)

    other = limiter.check("198.51.100.5", limit=3, window_seconds=60, now=1_000.0)
    assert other.allowed is True, "a second IP must not inherit the first IP's count"
    assert other.remaining == 2


def test_two_namespaces_are_independent_counters(rate_limit_table: Any) -> None:
    """Two namespaces keep separate counters for the same identity."""
    assert rate_limit_table is not None
    login = RateLimiter(namespace="login", prefix="", region_name="us-west-2")
    search = RateLimiter(namespace="search", prefix="", region_name="us-west-2")

    for _ in range(3):
        login.check("198.51.100.6", limit=3, window_seconds=60, now=1_000.0)

    decision = search.check("198.51.100.6", limit=3, window_seconds=60, now=1_000.0)
    assert decision.allowed is True, "a login limit must not consume the search limit"
    assert decision.remaining == 2


def test_the_fixed_window_rolls_over(limiter: RateLimiter) -> None:
    """A new window is a new key, so the counter starts again and the old item survives."""
    for _ in range(3):
        limiter.check("198.51.100.7", limit=3, window_seconds=60, now=1_000.0)

    exhausted = limiter.check("198.51.100.7", limit=3, window_seconds=60, now=1_010.0)
    assert exhausted.allowed is False, "the 4th request inside the 960..1020 window is over"
    assert exhausted.remaining == 0

    rolled = limiter.check("198.51.100.7", limit=3, window_seconds=60, now=1_100.0)
    assert rolled.allowed is True, "a new window must start a fresh counter"
    assert rolled.remaining == 2, "the count must reset to 1 in the new window"

    old = limiter.get({"pk": "default#198.51.100.7#960"})
    assert old is not None
    assert int(old["count"]) == 4

    fresh = limiter.get({"pk": "default#198.51.100.7#1080"})
    assert fresh is not None
    assert int(fresh["count"]) == 1


def test_reset_after_counts_down_within_the_window(limiter: RateLimiter) -> None:
    """`reset_after` reports the seconds left in the current window."""
    early = limiter.check("198.51.100.8", limit=10, window_seconds=60, now=1_000.0)
    late = limiter.check("198.51.100.8", limit=10, window_seconds=60, now=1_015.0)

    assert early.reset_after == 20, "the window 960..1020 has 20 seconds left at t=1000"
    assert late.reset_after == 5
    assert early.window_seconds == 60


def test_check_writes_a_ttl_in_epoch_seconds(limiter: RateLimiter) -> None:
    """The item's TTL is the window end plus a 60 second grace buffer, in epoch seconds."""
    limiter.check("198.51.100.9", limit=10, window_seconds=60, now=1_000.0)

    item = limiter.get({"pk": "default#198.51.100.9#960"})
    assert item is not None
    assert int(item["expires_at"]) == 1080


def test_check_fails_open_and_logs_a_warning(
    limiter: RateLimiter, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A DynamoDB error fails open and logs one WARNING carrying `rate_limit_failed_open`."""
    error = ClientError(
        {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "slow down"}},
        "UpdateItem",
    )

    def explode(*args: Any, **kwargs: Any) -> Any:
        """Raise the prepared ClientError in place of the DynamoDB call."""
        raise error

    monkeypatch.setattr(limiter, "update", explode)

    with caplog.at_level(logging.WARNING, logger="webbpulse.ratelimit"):
        decision = limiter.check("198.51.100.10", limit=3, window_seconds=60, now=1_000.0)

    assert decision.allowed is True, "a limiter is protective, not authorising; it fails open"
    assert decision.failed_open is True
    assert decision.remaining == decision.limit, "a failed-open decision reports a full quota"

    records = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(records) == 1, f"exactly one WARNING is the compensating control; got {records}"
    assert getattr(records[0], "rate_limit_failed_open", None) is True, (
        "the WARNING must carry rate_limit_failed_open so an alarm can match on it"
    )
    assert getattr(records[0], "error_type", None) == "ClientError"


def test_check_fails_open_on_a_non_botocore_error(
    limiter: RateLimiter, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Any exception from the DynamoDB call fails open, not only a botocore one."""

    def explode(*args: Any, **kwargs: Any) -> Any:
        """Raise a non-botocore error in place of the DynamoDB call."""
        raise RuntimeError("anything at all")

    monkeypatch.setattr(limiter, "update", explode)

    with caplog.at_level(logging.WARNING, logger="webbpulse.ratelimit"):
        decision = limiter.check("198.51.100.11", limit=3, window_seconds=60, now=1_000.0)

    assert decision.allowed is True
    assert decision.failed_open is True


def test_missing_table_fails_open(caplog: pytest.LogCaptureFixture, dynamodb_resource: Any) -> None:
    """With no rate limit table at all, the limiter still lets the request through."""
    assert dynamodb_resource is not None
    limiter = RateLimiter(prefix="", region_name="us-west-2")

    with caplog.at_level(logging.WARNING, logger="webbpulse.ratelimit"):
        decision = limiter.check("198.51.100.12", limit=1, window_seconds=60, now=1_000.0)

    assert decision.allowed is True
    assert decision.failed_open is True


def _app(limiter: RateLimiter, *, limit: int = 2, namespace: str = "default") -> FastAPI:
    """Build an app with one route guarded by the rate limit dependency."""
    app = FastAPI()
    dependency = rate_limit(limit=limit, window_seconds=60, namespace=namespace, limiter=limiter)

    @app.get("/limited")
    async def limited(decision: Any = Depends(dependency)) -> dict[str, Any]:
        """Report the remaining quota from the dependency's decision."""
        return {"remaining": decision.remaining}

    return app


def test_dependency_allows_then_returns_429(limiter: RateLimiter, test_client: Any) -> None:
    """The dependency serves requests up to the limit and then answers 429."""
    client = test_client(_app(limiter), source_ip="198.51.100.20")

    first = client.get("/limited")
    assert first.status_code == 200, first.text
    assert first.json()["remaining"] == 1

    assert client.get("/limited").status_code == 200

    third = client.get("/limited")
    assert third.status_code == 429, "the third request exceeds a limit of 2"


def test_the_429_carries_retry_after_and_the_ratelimit_header(limiter: RateLimiter, test_client: Any) -> None:
    """A 429 carries Retry-After in delta seconds plus the rate limit headers."""
    client = test_client(_app(limiter, namespace="login"), source_ip="198.51.100.21")
    for _ in range(2):
        client.get("/limited")

    rejected = client.get("/limited")
    assert rejected.status_code == 429

    retry_after = rejected.headers["Retry-After"]
    assert retry_after.isdigit(), f"Retry-After must be delta seconds, got {retry_after!r}"
    assert 0 <= int(retry_after) <= 60

    assert rejected.headers["RateLimit"] == f'"login";r=0;t={retry_after}'
    assert rejected.headers["RateLimit-Policy"] == '"login";q=2;w=60'
    assert rejected.headers["X-RateLimit-Remaining"] == "0"


def test_the_dependency_identifies_callers_by_source_ip(limiter: RateLimiter, test_client: Any) -> None:
    """Callers differing only by source IP get separate counters."""
    app = _app(limiter)
    first = test_client(app, source_ip="198.51.100.22")
    second = test_client(app, source_ip="198.51.100.23")

    for _ in range(3):
        first.get("/limited")

    assert second.get("/limited").status_code == 200, "a different IP gets its own counter"


def test_the_dependency_exposes_headers_on_a_successful_response(limiter: RateLimiter, test_client: Any) -> None:
    """The dependency stashes the rate limit headers on `request.state` for a middleware."""
    app = FastAPI()
    dependency = rate_limit(limit=5, window_seconds=60, limiter=limiter)

    @app.get("/state")
    async def state(request: Request, decision: Any = Depends(dependency)) -> dict[str, Any]:
        """Report the headers the dependency stashed on the request state."""
        return dict(request.state.rate_limit_headers)

    client = test_client(app, source_ip="198.51.100.24")
    response = client.get("/state")
    assert response.status_code == 200, response.text
    assert response.json()["RateLimit"] == '"default";r=4;t=' + response.json()["X-RateLimit-Reset"]
    assert Request is not None


def test_the_dependency_accepts_a_custom_key_function(limiter: RateLimiter, test_client: Any) -> None:
    """A custom key function gives each key its own counter."""
    app = FastAPI()
    dependency = rate_limit(
        lambda request: request.headers.get("x-tenant", "anonymous"),
        limit=1,
        window_seconds=60,
        namespace="tenant",
        limiter=limiter,
    )

    @app.get("/tenant")
    async def tenant(decision: Any = Depends(dependency)) -> dict[str, bool]:
        """Answer once the rate limit dependency has allowed the request."""
        return {"ok": True}

    client = test_client(app, source_ip="198.51.100.25")

    assert client.get("/tenant", headers={"x-tenant": "acme"}).status_code == 200
    assert client.get("/tenant", headers={"x-tenant": "acme"}).status_code == 429
    assert client.get("/tenant", headers={"x-tenant": "globex"}).status_code == 200, (
        "a different tenant key must have its own counter"
    )


def test_the_dependency_accepts_an_async_key_function(limiter: RateLimiter, test_client: Any) -> None:
    """An async key function is awaited, so callers key on the string and not a coroutine."""
    app = FastAPI()

    async def key_fn(request: Request) -> str:
        """Key the limiter on the tenant header."""
        return request.headers.get("x-tenant", "anonymous")

    dependency = rate_limit(key_fn, limit=1, window_seconds=60, namespace="async-tenant", limiter=limiter)

    @app.get("/tenant")
    async def tenant(decision: Any = Depends(dependency)) -> dict[str, bool]:
        """Answer once the rate limit dependency has allowed the request."""
        return {"ok": True}

    client = test_client(app, source_ip="198.51.100.26")

    assert client.get("/tenant", headers={"x-tenant": "acme"}).status_code == 200
    assert client.get("/tenant", headers={"x-tenant": "acme"}).status_code == 429, (
        "the awaited key must be the tenant string, so the second request is limited"
    )
    assert client.get("/tenant", headers={"x-tenant": "globex"}).status_code == 200


def test_the_dependency_does_not_block_the_event_loop(limiter: RateLimiter, test_client: Any) -> None:
    """The blocking `check` call runs in a worker thread, not on the thread running the route."""
    import threading

    loop_thread = threading.get_ident()
    seen: dict[str, int] = {}
    original = limiter.check

    def record(*args: Any, **kwargs: Any) -> Any:
        """Record the thread `check` runs on, then delegate to the real method."""
        seen["thread"] = threading.get_ident()
        return original(*args, **kwargs)

    app = FastAPI()
    dependency = rate_limit(limit=5, window_seconds=60, namespace="offload", limiter=limiter)

    @app.get("/offloaded")
    async def offloaded(decision: Any = Depends(dependency)) -> dict[str, int]:
        """Record the thread the route handler runs on."""
        seen["route"] = threading.get_ident()
        return {"ok": 1}

    limiter.check = record  # type: ignore[method-assign]
    try:
        client = test_client(app, source_ip="198.51.100.27")
        assert client.get("/offloaded").status_code == 200
    finally:
        limiter.check = original  # type: ignore[method-assign]

    assert "thread" in seen, "the limiter must have been called"
    assert seen["thread"] != seen["route"], (
        "the DynamoDB call must run in a worker thread, not on the thread running the route"
    )
    assert loop_thread == threading.get_ident()
