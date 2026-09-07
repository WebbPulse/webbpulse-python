"""Tests for the fixed-window rate limiter and its FastAPI dependency."""

from __future__ import annotations

import logging
from typing import Any

import pytest
from botocore.exceptions import ClientError
from fastapi import Depends, FastAPI

from webbpulse.ratelimit import (
    RateLimitDecision,
    RateLimiter,
    rate_limit,
    rate_limit_headers,
)


def _decision(**overrides: Any) -> RateLimitDecision:
    defaults: dict[str, Any] = {
        "allowed": True,
        "limit": 100,
        "remaining": 50,
        "reset_after": 30,
        "window_seconds": 60,
    }
    return RateLimitDecision(**{**defaults, **overrides})


# ---- headers ---------------------------------------------------------------------


def test_rate_limit_headers_emit_the_structured_fields() -> None:
    headers = rate_limit_headers(_decision())

    assert headers["RateLimit"] == '"default";r=50;t=30'
    assert headers["RateLimit-Policy"] == '"default";q=100;w=60'


def test_rate_limit_headers_emit_the_x_prefixed_trio() -> None:
    headers = rate_limit_headers(_decision())

    assert headers["X-RateLimit-Limit"] == "100"
    assert headers["X-RateLimit-Remaining"] == "50"
    assert headers["X-RateLimit-Reset"] == "30"


def test_rate_limit_headers_use_the_policy_name() -> None:
    headers = rate_limit_headers(_decision(), policy_name="login")

    assert headers["RateLimit"] == '"login";r=50;t=30'
    assert headers["RateLimit-Policy"] == '"login";q=100;w=60'


def test_rate_limit_headers_clamp_remaining_at_zero() -> None:
    # The counter keeps climbing past the limit on rejected requests, so `remaining` goes
    # negative internally. A negative `r` is not a valid structured field value.
    headers = rate_limit_headers(_decision(allowed=False, remaining=-5))

    assert headers["RateLimit"] == '"default";r=0;t=30', "r must be clamped, never negative"
    assert headers["X-RateLimit-Remaining"] == "0"


def test_rate_limit_decision_repr_is_readable() -> None:
    assert "allowed=True" in repr(_decision())


# ---- the limiter -----------------------------------------------------------------


@pytest.fixture
def limiter(rate_limit_table: Any) -> RateLimiter:
    """A limiter bound to the moto-backed `rate-limits` table."""
    assert rate_limit_table is not None
    return RateLimiter(prefix="", region_name="us-west-2")


def test_check_allows_up_to_the_limit_and_denies_the_next(limiter: RateLimiter) -> None:
    decisions = [
        limiter.check("198.51.100.1", limit=3, window_seconds=60, now=1_000.0) for _ in range(4)
    ]

    assert [d.allowed for d in decisions] == [True, True, True, False], (
        "the first 3 requests must be allowed and the 4th denied"
    )
    assert decisions[3].failed_open is False


def test_check_decrements_remaining(limiter: RateLimiter) -> None:
    remaining = [
        limiter.check("198.51.100.2", limit=3, window_seconds=60, now=1_000.0).remaining
        for _ in range(4)
    ]

    assert remaining == [2, 1, 0, 0], "remaining must count down and then clamp at 0"


def test_a_rejected_request_still_increments_the_counter(limiter: RateLimiter) -> None:
    # This is what stops a caller sitting at exactly the limit by continuing to send
    # requests that are refused: the window has to drain, not just stop growing.
    for _ in range(5):
        limiter.check("198.51.100.3", limit=2, window_seconds=60, now=1_000.0)

    item = limiter.get({"pk": "default#198.51.100.3#960"})
    assert item is not None, "the counter item must exist for the window"
    assert int(item["count"]) == 5, "every request counts, including the rejected ones"


def test_two_identities_are_independent_counters(limiter: RateLimiter) -> None:
    for _ in range(3):
        limiter.check("198.51.100.4", limit=3, window_seconds=60, now=1_000.0)

    other = limiter.check("198.51.100.5", limit=3, window_seconds=60, now=1_000.0)
    assert other.allowed is True, "a second IP must not inherit the first IP's count"
    assert other.remaining == 2


def test_two_namespaces_are_independent_counters(rate_limit_table: Any) -> None:
    assert rate_limit_table is not None
    login = RateLimiter(namespace="login", prefix="", region_name="us-west-2")
    search = RateLimiter(namespace="search", prefix="", region_name="us-west-2")

    for _ in range(3):
        login.check("198.51.100.6", limit=3, window_seconds=60, now=1_000.0)

    decision = search.check("198.51.100.6", limit=3, window_seconds=60, now=1_000.0)
    assert decision.allowed is True, "a login limit must not consume the search limit"
    assert decision.remaining == 2


def test_the_fixed_window_rolls_over(limiter: RateLimiter) -> None:
    # moto does not expire TTL items and neither does DynamoDB promptly, so the reset is
    # asserted through the window key changing rather than the old item disappearing.
    for _ in range(3):
        limiter.check("198.51.100.7", limit=3, window_seconds=60, now=1_000.0)

    exhausted = limiter.check("198.51.100.7", limit=3, window_seconds=60, now=1_050.0)
    assert exhausted.allowed is False, "still inside the 960..1020 window at t=1050? no"

    rolled = limiter.check("198.51.100.7", limit=3, window_seconds=60, now=1_100.0)
    assert rolled.allowed is True, "a new window must start a fresh counter"
    assert rolled.remaining == 2, "the count must reset to 1 in the new window"

    # The old window's item is untouched, which is what makes the rollover a new key.
    old = limiter.get({"pk": "default#198.51.100.7#960"})
    assert old is not None
    assert int(old["count"]) == 4


def test_reset_after_counts_down_within_the_window(limiter: RateLimiter) -> None:
    early = limiter.check("198.51.100.8", limit=10, window_seconds=60, now=1_000.0)
    late = limiter.check("198.51.100.8", limit=10, window_seconds=60, now=1_015.0)

    assert early.reset_after == 20, "the window 960..1020 has 20 seconds left at t=1000"
    assert late.reset_after == 5
    assert early.window_seconds == 60


def test_check_writes_a_ttl_in_epoch_seconds(limiter: RateLimiter) -> None:
    limiter.check("198.51.100.9", limit=10, window_seconds=60, now=1_000.0)

    item = limiter.get({"pk": "default#198.51.100.9#960"})
    assert item is not None
    # window_end (1020) plus the 60 second grace buffer.
    assert int(item["expires_at"]) == 1080


def test_check_fails_open_and_logs_a_warning(
    limiter: RateLimiter, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    error = ClientError(
        {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "slow down"}},
        "UpdateItem",
    )

    def explode(*args: Any, **kwargs: Any) -> Any:
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
    def explode(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("anything at all")

    monkeypatch.setattr(limiter, "update", explode)

    with caplog.at_level(logging.WARNING, logger="webbpulse.ratelimit"):
        decision = limiter.check("198.51.100.11", limit=3, window_seconds=60, now=1_000.0)

    assert decision.allowed is True
    assert decision.failed_open is True


def test_missing_table_fails_open(caplog: pytest.LogCaptureFixture, dynamodb_resource: Any) -> None:
    # No `rate_limit_table` fixture here, so the table genuinely does not exist. This is the
    # realistic outage shape, and the limiter must still let the request through.
    assert dynamodb_resource is not None
    limiter = RateLimiter(prefix="", region_name="us-west-2")

    with caplog.at_level(logging.WARNING, logger="webbpulse.ratelimit"):
        decision = limiter.check("198.51.100.12", limit=1, window_seconds=60, now=1_000.0)

    assert decision.allowed is True
    assert decision.failed_open is True


# ---- the FastAPI dependency ------------------------------------------------------


def _app(limiter: RateLimiter, *, limit: int = 2, namespace: str = "default") -> FastAPI:
    app = FastAPI()
    dependency = rate_limit(limit=limit, window_seconds=60, namespace=namespace, limiter=limiter)

    @app.get("/limited")
    async def limited(decision: Any = Depends(dependency)) -> dict[str, Any]:
        return {"remaining": decision.remaining}

    return app


def test_dependency_allows_then_returns_429(limiter: RateLimiter, test_client: Any) -> None:
    client = test_client(_app(limiter), source_ip="198.51.100.20")

    first = client.get("/limited")
    assert first.status_code == 200, first.text
    assert first.json()["remaining"] == 1

    assert client.get("/limited").status_code == 200

    third = client.get("/limited")
    assert third.status_code == 429, "the third request exceeds a limit of 2"


def test_the_429_carries_retry_after_and_the_ratelimit_header(
    limiter: RateLimiter, test_client: Any
) -> None:
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


def test_the_dependency_identifies_callers_by_source_ip(
    limiter: RateLimiter, test_client: Any
) -> None:
    # Two clients differ only by the API Gateway source IP, so they must not share a bucket.
    app = _app(limiter)
    first = test_client(app, source_ip="198.51.100.22")
    second = test_client(app, source_ip="198.51.100.23")

    for _ in range(3):
        first.get("/limited")

    assert second.get("/limited").status_code == 200, "a different IP gets its own counter"


def test_the_dependency_exposes_headers_on_a_successful_response(
    limiter: RateLimiter, test_client: Any
) -> None:
    app = FastAPI()
    dependency = rate_limit(limit=5, window_seconds=60, limiter=limiter)

    @app.get("/state")
    async def state(request: Any, decision: Any = Depends(dependency)) -> dict[str, Any]:
        # The dependency stashes the headers on request.state for a middleware to attach.
        return dict(request.state.rate_limit_headers)

    from fastapi import Request

    app.dependency_overrides = {}
    client = test_client(app, source_ip="198.51.100.24")
    response = client.get("/state")
    assert response.status_code == 200, response.text
    assert response.json()["RateLimit"] == '"default";r=4;t=' + response.json()["X-RateLimit-Reset"]
    assert Request is not None


def test_the_dependency_accepts_a_custom_key_function(
    limiter: RateLimiter, test_client: Any
) -> None:
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
        return {"ok": True}

    client = test_client(app, source_ip="198.51.100.25")

    assert client.get("/tenant", headers={"x-tenant": "acme"}).status_code == 200
    assert client.get("/tenant", headers={"x-tenant": "acme"}).status_code == 429
    assert client.get("/tenant", headers={"x-tenant": "globex"}).status_code == 200, (
        "a different tenant key must have its own counter"
    )
