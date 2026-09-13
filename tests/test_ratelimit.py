"""Tests for the fixed-window rate limiter and its FastAPI dependency."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any

import pytest
from botocore.exceptions import ClientError
from fastapi import Depends, FastAPI, Request

from webbpulse.messages import rate_limited
from webbpulse.ratelimit import (
    LimitClass,
    RateLimitDecision,
    RateLimiter,
    classify,
    rate_limit,
    rate_limit_headers,
    rate_limit_middleware,
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
    assert rejected.json()["detail"] == rate_limited(), "the 429 sentence comes from webbpulse.messages"

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


def test_limit_class_matches_everything_when_unconstrained() -> None:
    """A class with neither methods nor prefixes is the catch-all."""
    catch_all = LimitClass(name="default", limit=10, window_seconds=60)

    assert catch_all.matches("POST", "/anything") is True
    assert catch_all.matches("GET", "/") is True


def test_limit_class_matches_on_method() -> None:
    """`methods` restricts a class to those verbs, case-insensitively."""
    reads = LimitClass(name="get", limit=10, window_seconds=60, methods=("GET",))

    assert reads.matches("get", "/api/cars") is True
    assert reads.matches("POST", "/api/cars") is False


def test_limit_class_matches_a_prefix_subtree_not_a_sibling() -> None:
    """`path_prefixes` matches the prefix itself and its subtree, never a sibling."""
    auth = LimitClass(name="auth", limit=5, window_seconds=60, path_prefixes=("/api/auth",))

    assert auth.matches("POST", "/api/auth") is True
    assert auth.matches("POST", "/api/auth/login") is True
    assert auth.matches("POST", "/api/authors") is False, "a prefix must not match a sibling path"


def test_limit_class_exempt_paths_fall_through() -> None:
    """A path in `exempt_paths` does not match its class, so classification continues."""
    auth = LimitClass(
        name="auth",
        limit=5,
        window_seconds=60,
        path_prefixes=("/api/auth",),
        exempt_paths=("/api/auth/refresh",),
    )

    assert auth.matches("POST", "/api/auth/login") is True
    assert auth.matches("POST", "/api/auth/refresh") is False


def test_limit_class_ignores_a_trailing_slash() -> None:
    """`/api/auth/` classifies as `/api/auth` does."""
    auth = LimitClass(name="auth", limit=5, window_seconds=60, path_prefixes=("/api/auth",))

    assert auth.matches("POST", "/api/auth/") is True


def _carmodpicker_classes() -> list[LimitClass]:
    """CarModPicker's four classes, in the order its limiter classifies them."""
    return [
        LimitClass(name="get", limit=60, window_seconds=60, methods=("GET",)),
        LimitClass(
            name="auth",
            limit=5,
            window_seconds=60,
            path_prefixes=("/api/auth",),
            exempt_paths=("/api/auth/refresh", "/api/auth/logout"),
        ),
        LimitClass(name="admin", limit=20, window_seconds=60, path_prefixes=("/api/admin",)),
        LimitClass(name="default", limit=30, window_seconds=60),
    ]


@pytest.mark.parametrize(
    ("method", "path", "expected"),
    [
        ("GET", "/api/cars", "get"),
        ("GET", "/api/auth/login", "get"),
        ("POST", "/api/auth/login", "auth"),
        ("POST", "/api/auth/refresh", "default"),
        ("POST", "/api/auth/logout", "default"),
        ("DELETE", "/api/admin/users/1", "admin"),
        ("POST", "/api/cars", "default"),
    ],
)
def test_classify_reproduces_the_product_class_split(method: str, path: str, expected: str) -> None:
    """`classify` picks the first matching class, reproducing CarModPicker's split.

    A GET is always the read class, even under `/api/auth`, because the read class is first.
    """
    assert classify(method, path, _carmodpicker_classes()).name == expected


def test_classify_raises_without_a_catch_all() -> None:
    """A request matching no class raises rather than going silently uncounted."""
    classes = [LimitClass(name="get", limit=10, window_seconds=60, methods=("GET",))]

    with pytest.raises(LookupError, match="catch-all"):
        classify("POST", "/api/cars", classes)


def test_clear_forgets_a_first_request_counter(rate_limit_table: Any) -> None:
    """`clear` drops the counter, so the next attempt starts a new window at 1."""
    assert rate_limit_table is not None
    limiter = RateLimiter(
        namespace="login", anchor="first_request", count_attribute="failures", prefix="", region_name="us-west-2"
    )

    for _ in range(3):
        limiter.check("198.51.100.40", limit=3, window_seconds=900, now=1_000.0)
    assert limiter.check("198.51.100.40", limit=3, window_seconds=900, now=1_001.0).allowed is False

    limiter.clear("198.51.100.40")

    fresh = limiter.check("198.51.100.40", limit=3, window_seconds=900, now=1_002.0)
    assert fresh.allowed is True, "a cleared identity starts a new window"
    assert fresh.remaining == 2


def test_clear_forgets_a_clock_anchored_counter(limiter: RateLimiter) -> None:
    """`clear` on a clock-anchored limiter needs the window to name the row."""
    for _ in range(3):
        limiter.check("198.51.100.41", limit=3, window_seconds=60, now=1_000.0)

    limiter.clear("198.51.100.41", window_seconds=60, now=1_000.0)

    assert limiter.get({"pk": "default#198.51.100.41#960"}) is None
    assert limiter.check("198.51.100.41", limit=3, window_seconds=60, now=1_000.0).remaining == 2


def test_clear_without_a_window_is_a_logged_no_op(limiter: RateLimiter, caplog: pytest.LogCaptureFixture) -> None:
    """Clearing a clock-anchored limiter without `window_seconds` warns and changes nothing."""
    limiter.check("198.51.100.42", limit=3, window_seconds=60, now=1_000.0)

    with caplog.at_level(logging.WARNING, logger="webbpulse.ratelimit"):
        limiter.clear("198.51.100.42")

    assert limiter.get({"pk": "default#198.51.100.42#960"}) is not None, "the counter must survive a no-op clear"
    assert any("window_seconds" in record.message for record in caplog.records)


def test_clear_swallows_and_logs_a_backend_failure(
    limiter: RateLimiter, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failing `clear` logs `rate_limit_failed_open` rather than raising into the route."""

    def explode(*args: Any, **kwargs: Any) -> Any:
        """Raise in place of the DynamoDB delete."""
        raise RuntimeError("table gone")

    monkeypatch.setattr(limiter, "delete", explode)

    with caplog.at_level(logging.WARNING, logger="webbpulse.ratelimit"):
        limiter.clear("198.51.100.43", window_seconds=60, now=1_000.0)

    records = [r for r in caplog.records if getattr(r, "rate_limit_failed_open", None) is True]
    assert len(records) == 1, "a failed clear must be visible to an alarm"
    assert getattr(records[0], "rate_limit_operation", None) == "clear"


@pytest.fixture
def login_limiter(rate_limit_table: Any) -> RateLimiter:
    """Portfolio's login lockout: a first-request window counting failures only."""
    assert rate_limit_table is not None
    return RateLimiter(
        namespace="login", anchor="first_request", count_attribute="failures", prefix="", region_name="us-west-2"
    )


def test_first_request_anchor_opens_the_window_on_the_first_call(login_limiter: RateLimiter) -> None:
    """The window runs `window_seconds` from the first counted request, not from the clock."""
    first = login_limiter.check("198.51.100.44", limit=5, window_seconds=900, now=1_000.0)

    assert first.allowed is True
    assert first.reset_after == 900, "the window opens on this request, so a full window remains"


def test_first_request_anchor_does_not_extend_on_later_calls(login_limiter: RateLimiter) -> None:
    """A later request inside the window counts but does not push the window out."""
    login_limiter.check("198.51.100.45", limit=5, window_seconds=900, now=1_000.0)

    later = login_limiter.check("198.51.100.45", limit=5, window_seconds=900, now=1_300.0)

    assert later.remaining == 3
    assert later.reset_after == 600, "the window still ends at 1900, so 600 seconds remain"


def test_first_request_anchor_rolls_over_once_the_window_passes(login_limiter: RateLimiter) -> None:
    """Past the window the row is replaced, which opens a new window at a count of 1."""
    for _ in range(5):
        login_limiter.check("198.51.100.46", limit=5, window_seconds=900, now=1_000.0)
    assert login_limiter.check("198.51.100.46", limit=5, window_seconds=900, now=1_100.0).allowed is False

    rolled = login_limiter.check("198.51.100.46", limit=5, window_seconds=900, now=2_000.0)

    assert rolled.allowed is True, "the window has passed, so the lockout is over"
    assert rolled.remaining == 4, "the new window starts at a count of 1"


def test_first_request_anchor_uses_the_named_count_attribute(login_limiter: RateLimiter) -> None:
    """`count_attribute` names the counter, so Portfolio's rows keep saying `failures`."""
    login_limiter.check("198.51.100.47", limit=5, window_seconds=900, now=1_000.0)

    item = login_limiter.get({"pk": "login#198.51.100.47"})
    assert item is not None
    assert int(item["failures"]) == 1
    assert int(item["expires_at"]) == 1900


def test_first_request_anchor_fails_open(
    login_limiter: RateLimiter, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A backend failure in the first-request path fails open and logs, as the clock one does."""

    def explode(*args: Any, **kwargs: Any) -> Any:
        """Raise in place of the DynamoDB update."""
        raise RuntimeError("no table")

    monkeypatch.setattr(login_limiter, "update", explode)

    with caplog.at_level(logging.WARNING, logger="webbpulse.ratelimit"):
        decision = login_limiter.check("198.51.100.48", limit=5, window_seconds=900, now=1_000.0)

    assert decision.allowed is True
    assert decision.failed_open is True
    assert any(getattr(r, "rate_limit_failed_open", None) is True for r in caplog.records)


def test_first_request_anchor_fails_open_when_the_replacing_put_fails(
    login_limiter: RateLimiter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failing rollover `put` fails open rather than raising into the caller."""
    conditional = ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException", "Message": "stale"}},
        "UpdateItem",
    )

    def refuse(*args: Any, **kwargs: Any) -> Any:
        """Raise the conditional failure that drives the rollover path."""
        raise conditional

    def explode(*args: Any, **kwargs: Any) -> Any:
        """Raise in place of the replacing put."""
        raise RuntimeError("put refused")

    monkeypatch.setattr(login_limiter, "update", refuse)
    monkeypatch.setattr(login_limiter, "put", explode)

    decision = login_limiter.check("198.51.100.49", limit=5, window_seconds=900, now=1_000.0)

    assert decision.allowed is True
    assert decision.failed_open is True


def test_a_non_conditional_client_error_fails_open(login_limiter: RateLimiter, monkeypatch: pytest.MonkeyPatch) -> None:
    """A ClientError that is not the conditional failure fails open, never rolls the window."""
    throttled = ClientError(
        {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "slow down"}},
        "UpdateItem",
    )

    def explode(*args: Any, **kwargs: Any) -> Any:
        """Raise a throttling error in place of the DynamoDB update."""
        raise throttled

    monkeypatch.setattr(login_limiter, "update", explode)

    decision = login_limiter.check("198.51.100.50", limit=5, window_seconds=900, now=1_000.0)

    assert decision.failed_open is True


def test_the_login_lockout_counts_failures_only(login_limiter: RateLimiter) -> None:
    """The lockout shape Portfolio runs: count on failure, clear on success.

    A success clears the counter, so a user who mistypes twice and then succeeds is never
    locked out by those two failures.
    """
    for _ in range(2):
        login_limiter.check("198.51.100.51", limit=3, window_seconds=900, now=1_000.0)

    login_limiter.clear("198.51.100.51")

    for _ in range(3):
        assert login_limiter.check("198.51.100.51", limit=3, window_seconds=900, now=1_010.0).allowed is True
    assert login_limiter.check("198.51.100.51", limit=3, window_seconds=900, now=1_010.0).allowed is False


def _middleware_app(
    limiter_classes: Sequence[LimitClass],
    **kwargs: Any,
) -> FastAPI:
    """An app whose whole surface is guarded by the rate limit middleware."""
    app = FastAPI()
    kwargs.setdefault("prefix", "")
    kwargs.setdefault("region_name", "us-west-2")
    app.middleware("http")(rate_limit_middleware(list(limiter_classes), **kwargs))

    @app.get("/api/cars")
    async def cars() -> dict[str, bool]:
        """A read route, in the GET class."""
        return {"ok": True}

    @app.post("/api/auth/login")
    async def login() -> dict[str, bool]:
        """A credential route, in the auth class."""
        return {"ok": True}

    @app.post("/api/auth/refresh")
    async def refresh() -> dict[str, bool]:
        """A route exempted from the auth class, so it falls to the default one."""
        return {"ok": True}

    @app.post("/api/admin/users")
    async def admin() -> dict[str, bool]:
        """An admin route, in the admin class."""
        return {"ok": True}

    @app.get("/health")
    async def health() -> dict[str, bool]:
        """An exempt health check."""
        return {"ok": True}

    return app


def test_middleware_allows_up_to_the_class_limit_then_refuses(rate_limit_table: Any, test_client: Any) -> None:
    """The middleware counts every request against its class and answers 429 once spent."""
    assert rate_limit_table is not None
    classes = [
        LimitClass(name="auth", limit=2, window_seconds=60, path_prefixes=("/api/auth",)),
        LimitClass(name="default", limit=50, window_seconds=60),
    ]
    client = test_client(_middleware_app(classes), source_ip="198.51.100.60")

    assert client.post("/api/auth/login").status_code == 200
    assert client.post("/api/auth/login").status_code == 200
    assert client.post("/api/auth/login").status_code == 429, "the third request exceeds a limit of 2"


def test_middleware_classes_are_independent_counters(rate_limit_table: Any, test_client: Any) -> None:
    """Spending the auth class leaves the read class untouched."""
    assert rate_limit_table is not None
    classes = [
        LimitClass(name="get", limit=50, window_seconds=60, methods=("GET",)),
        LimitClass(name="auth", limit=1, window_seconds=60, path_prefixes=("/api/auth",)),
        LimitClass(name="default", limit=50, window_seconds=60),
    ]
    client = test_client(_middleware_app(classes), source_ip="198.51.100.61")

    client.post("/api/auth/login")
    assert client.post("/api/auth/login").status_code == 429

    assert client.get("/api/cars").status_code == 200, "a read must not spend the credential allowance"


def test_middleware_routes_an_exempt_path_to_the_next_class(rate_limit_table: Any, test_client: Any) -> None:
    """A class's `exempt_paths` entry falls through to the following class."""
    assert rate_limit_table is not None
    classes = [
        LimitClass(
            name="auth",
            limit=1,
            window_seconds=60,
            path_prefixes=("/api/auth",),
            exempt_paths=("/api/auth/refresh",),
        ),
        LimitClass(name="default", limit=50, window_seconds=60),
    ]
    client = test_client(_middleware_app(classes), source_ip="198.51.100.62")

    client.post("/api/auth/login")
    assert client.post("/api/auth/login").status_code == 429

    assert client.post("/api/auth/refresh").status_code == 200, "refresh is counted in the default class"


def test_middleware_skips_exempt_paths_and_methods(rate_limit_table: Any, test_client: Any) -> None:
    """An exempt path and an exempt method are never counted at all."""
    assert rate_limit_table is not None
    classes = [LimitClass(name="default", limit=1, window_seconds=60)]
    client = test_client(_middleware_app(classes, exempt_paths=("/health",)), source_ip="198.51.100.63")

    for _ in range(5):
        assert client.get("/health").status_code == 200, "an exempt path never spends the allowance"

    assert client.options("/api/cars").status_code in {200, 405}
    assert client.get("/api/cars").status_code == 200, "neither the health checks nor the preflight counted"


def test_middleware_exempt_prefixes_match_a_subtree(rate_limit_table: Any, test_client: Any) -> None:
    """`exempt_prefixes` exempts a subtree, where `exempt_paths` exempts one path exactly."""
    assert rate_limit_table is not None
    classes = [LimitClass(name="default", limit=1, window_seconds=60)]
    app = _middleware_app(classes, exempt_paths=("/",), exempt_prefixes=("/api/admin",))
    client = test_client(app, source_ip="198.51.100.64")

    for _ in range(4):
        assert client.post("/api/admin/users").status_code == 200

    assert client.post("/api/auth/login").status_code == 200, "only the admin subtree was exempt"


def test_middleware_adds_the_headers_to_an_allowed_response(rate_limit_table: Any, test_client: Any) -> None:
    """An allowed response carries the RateLimit headers, named for its class."""
    assert rate_limit_table is not None
    classes = [LimitClass(name="auth", limit=5, window_seconds=60, path_prefixes=("/api/auth",))]
    client = test_client(_middleware_app(classes), source_ip="198.51.100.65")

    response = client.post("/api/auth/login")

    assert response.status_code == 200
    assert response.headers["X-RateLimit-Limit"] == "5"
    assert response.headers["X-RateLimit-Remaining"] == "4"
    assert response.headers["RateLimit-Policy"] == '"auth";q=5;w=60'


def test_the_default_renderer_emits_the_envelope_and_retry_after(rate_limit_table: Any, test_client: Any) -> None:
    """Without a renderer the 429 is the package's envelope plus Retry-After."""
    assert rate_limit_table is not None
    classes = [LimitClass(name="default", limit=1, window_seconds=60)]
    client = test_client(_middleware_app(classes), source_ip="198.51.100.66")

    client.post("/api/auth/login")
    rejected = client.post("/api/auth/login")

    assert rejected.status_code == 429
    assert rejected.json() == {"detail": "Too many requests. Try again later."}
    assert rejected.headers["Retry-After"].isdigit()
    assert rejected.headers["X-RateLimit-Remaining"] == "0"


def test_a_renderer_replaces_the_429_body(rate_limit_table: Any, test_client: Any) -> None:
    """A product renderer keeps the envelope its live clients already parse."""
    assert rate_limit_table is not None

    def carmodpicker_429(decision: RateLimitDecision) -> Any:
        """CarModPicker's current 429 body and headers, unchanged."""
        from fastapi.responses import JSONResponse

        retry_after = decision.reset_after or 60
        return JSONResponse(
            status_code=429,
            content={
                "detail": "Too many requests",
                "message": "Rate limit exceeded",
                "retry_after": retry_after,
            },
            headers={"Retry-After": str(retry_after), "X-RateLimit-Remaining-Minute": "0"},
        )

    classes = [LimitClass(name="default", limit=1, window_seconds=60)]
    client = test_client(_middleware_app(classes, renderer=carmodpicker_429), source_ip="198.51.100.67")

    client.post("/api/auth/login")
    rejected = client.post("/api/auth/login")

    assert rejected.status_code == 429
    assert rejected.json() == {
        "detail": "Too many requests",
        "message": "Rate limit exceeded",
        "retry_after": rejected.json()["retry_after"],
    }
    assert rejected.headers["X-RateLimit-Remaining-Minute"] == "0"
    assert "RateLimit-Policy" not in rejected.headers, "a renderer owns the whole refusal"


def test_middleware_identifies_callers_by_source_ip(rate_limit_table: Any, test_client: Any) -> None:
    """Two source IPs get separate counters, from the API Gateway request context."""
    assert rate_limit_table is not None
    classes = [LimitClass(name="default", limit=1, window_seconds=60)]
    app = _middleware_app(classes)
    first = test_client(app, source_ip="198.51.100.68")
    second = test_client(app, source_ip="198.51.100.69")

    first.post("/api/auth/login")
    assert first.post("/api/auth/login").status_code == 429

    assert second.post("/api/auth/login").status_code == 200, "a different IP gets its own counter"


def test_middleware_accepts_a_custom_identity_function(rate_limit_table: Any, test_client: Any) -> None:
    """`identity_fn` keys the counter on whatever the product identifies callers by."""
    assert rate_limit_table is not None
    classes = [LimitClass(name="default", limit=1, window_seconds=60)]
    app = _middleware_app(
        classes,
        identity_fn=lambda request: request.headers.get("x-user", "anonymous"),
    )
    client = test_client(app, source_ip="198.51.100.70")

    assert client.post("/api/auth/login", headers={"x-user": "alice"}).status_code == 200
    assert client.post("/api/auth/login", headers={"x-user": "alice"}).status_code == 429
    assert client.post("/api/auth/login", headers={"x-user": "bob"}).status_code == 200


def test_middleware_fails_open_without_a_table(dynamodb_resource: Any, test_client: Any, caplog: Any) -> None:
    """With no rate limits table the middleware serves every request and logs the fail-open."""
    assert dynamodb_resource is not None
    classes = [LimitClass(name="default", limit=1, window_seconds=60)]
    client = test_client(_middleware_app(classes), source_ip="198.51.100.71")

    with caplog.at_level(logging.WARNING, logger="webbpulse.ratelimit"):
        responses = [client.post("/api/auth/login") for _ in range(3)]

    assert [r.status_code for r in responses] == [200, 200, 200], "a limiter outage costs availability nothing"
    assert any(getattr(r, "rate_limit_failed_open", None) is True for r in caplog.records)


def test_a_failed_open_response_advertises_no_quota(dynamodb_resource: Any, test_client: Any) -> None:
    """A failed-open response carries no RateLimit headers, rather than a full quota."""
    assert dynamodb_resource is not None
    classes = [LimitClass(name="default", limit=1, window_seconds=60)]
    client = test_client(_middleware_app(classes), source_ip="198.51.100.72")

    response = client.post("/api/auth/login")

    assert response.status_code == 200
    assert "X-RateLimit-Limit" not in response.headers, (
        "a limiter that is not counting must not advertise a quota it is not enforcing"
    )


def test_middleware_can_be_switched_off(rate_limit_table: Any, test_client: Any) -> None:
    """`enabled` is consulted per request, so a product can gate on its own settings flag."""
    assert rate_limit_table is not None
    classes = [LimitClass(name="default", limit=1, window_seconds=60)]
    switch = {"on": False}
    app = _middleware_app(classes, enabled=lambda: switch["on"])
    client = test_client(app, source_ip="198.51.100.73")

    for _ in range(4):
        assert client.post("/api/auth/login").status_code == 200

    switch["on"] = True
    client.post("/api/auth/login")
    assert client.post("/api/auth/login").status_code == 429


def test_middleware_uses_the_first_request_anchor_when_asked(rate_limit_table: Any, test_client: Any) -> None:
    """`anchor="first_request"` builds first-request limiters for every class."""
    assert rate_limit_table is not None
    classes = [LimitClass(name="default", limit=1, window_seconds=900)]
    client = test_client(_middleware_app(classes, anchor="first_request"), source_ip="198.51.100.74")

    assert client.post("/api/auth/login").status_code == 200
    rejected = client.post("/api/auth/login")

    assert rejected.status_code == 429
    assert int(rejected.headers["Retry-After"]) > 60, "a first-request window runs its full length from now"


def test_middleware_needs_at_least_one_class() -> None:
    """An empty class list is a configuration error, refused when the middleware is built."""
    with pytest.raises(ValueError, match="at least one LimitClass"):
        rate_limit_middleware([])


def test_middleware_serves_a_request_matching_no_class(rate_limit_table: Any, test_client: Any) -> None:
    """With no catch-all a request matching nothing is served rather than refused."""
    assert rate_limit_table is not None
    classes = [LimitClass(name="get", limit=1, window_seconds=60, methods=("GET",))]
    client = test_client(_middleware_app(classes), source_ip="198.51.100.75")

    assert client.post("/api/auth/login").status_code == 200, "an unclassified request is not counted"

    client.get("/api/cars")
    assert client.get("/api/cars").status_code == 429, "the class that does match still counts"
