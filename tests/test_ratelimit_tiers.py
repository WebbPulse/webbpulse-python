"""Tests for the plan-tier keyed limits and their middleware wiring."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from fastapi import FastAPI, Request

from webbpulse import ratelimit
from webbpulse.ratelimit import (
    TTL_ATTRIBUTE,
    LimitClass,
    PlanLimits,
    Quota,
    RateLimitSubject,
    ScopeLimits,
    TieredLimits,
    TieredRateLimiter,
    rate_limit_middleware,
)

DAY = 86_400 * 20_000

NOW = float(DAY + 3_600 + 5)


def _resolver(request: Request) -> RateLimitSubject | None:
    """Name the subject from test headers, or none when the caller is anonymous."""
    plan = request.headers.get("x-plan")
    if plan is None:
        return None
    return RateLimitSubject(
        plan=plan,
        tenant=request.headers.get("x-tenant"),
        user=request.headers.get("x-user"),
        token=request.headers.get("x-token"),
    )


def _plans() -> dict[str, PlanLimits]:
    """A free and a standard plan shaped like the Standupless cost model's caps."""
    return {
        "free": PlanLimits(
            token=ScopeLimits.combined(Quota(per_minute=3, per_day=5)),
            user=ScopeLimits(read=Quota(per_minute=4), write=Quota(per_minute=2)),
            tenant=ScopeLimits.combined(Quota(per_minute=6)),
        ),
        "standard": PlanLimits(
            user=ScopeLimits(read=Quota(per_minute=10), write=Quota(per_minute=5)),
        ),
    }


def _tiers(**overrides: Any) -> TieredLimits:
    """Exact-count tiers over `_plans`, overriding any field by keyword."""
    defaults: dict[str, Any] = {
        "resolver": _resolver,
        "plans": _plans(),
        "default_plan": "free",
        "max_lease": 1,
    }
    return TieredLimits(**{**defaults, **overrides})


def _limiter(tiers: TieredLimits | None = None, *, clock: Callable[[], float] = lambda: NOW) -> TieredRateLimiter:
    """A tiered limiter on the moto table with a fixed clock."""
    return TieredRateLimiter(tiers or _tiers(), prefix="", region_name="us-west-2", clock=clock)


def _count_updates(monkeypatch: pytest.MonkeyPatch, limiter: TieredRateLimiter) -> list[str]:
    """Record the update expression of every `UpdateItem` the limiter sends."""
    calls: list[str] = []
    original = limiter.update

    def recording(*args: Any, **kwargs: Any) -> Any:
        """Record one call and pass it through."""
        calls.append(kwargs["update_expression"])
        return original(*args, **kwargs)

    monkeypatch.setattr(limiter, "update", recording)
    return calls


def _items(table: Any) -> list[dict[str, Any]]:
    """Every item in the table."""
    return list(table.scan()["Items"])


def test_quota_refuses_a_non_positive_cap() -> None:
    """A zero per-minute cap or daily quota is a configuration error."""
    with pytest.raises(ValueError):
        Quota(per_minute=0)
    with pytest.raises(ValueError):
        Quota(per_minute=1, per_day=0)


def test_tiered_limits_needs_its_default_plan() -> None:
    """The default plan must be one of the plans, or unknown plans would have nowhere to go."""
    with pytest.raises(ValueError, match="default_plan"):
        TieredLimits(resolver=_resolver, plans=_plans(), default_plan="missing")


def test_an_unknown_plan_falls_back_to_the_default() -> None:
    """`limits_for` answers the default plan's name and limits for a plan it does not know."""
    tiers = _tiers()

    assert tiers.limits_for("standard")[0] == "standard"
    assert tiers.limits_for("enterprise") == ("free", _plans()["free"])


def test_get_and_head_are_reads_and_the_rest_writes() -> None:
    """The request class comes from the method."""
    tiers = _tiers()

    assert [tiers.request_class(m) for m in ("GET", "head", "POST", "DELETE")] == ["read", "read", "write", "write"]


def test_check_key_allows_up_to_the_minute_cap(rate_limit_table: Any) -> None:
    """A key is allowed `per_minute` requests and refused the next, until the minute ends."""
    assert rate_limit_table is not None
    limiter = _limiter()
    quota = Quota(per_minute=3)

    decisions = [limiter.check_key("user", "u1", quota, now=NOW) for _ in range(4)]

    assert [d.allowed for d in decisions] == [True, True, True, False]
    assert [d.remaining for d in decisions] == [2, 1, 0, 0]
    assert decisions[3].reset_after == 55, "the refusal resets at the end of the clock minute"
    assert decisions[3].window_seconds == 60
    assert decisions[0].limit_name == "user-all"


def test_one_item_per_key_per_day_holds_the_counters(rate_limit_table: Any) -> None:
    """The minute count, its minute and the day count share one item with a day-end TTL."""
    limiter = _limiter()
    limiter.check_key("user", "u1", Quota(per_minute=5), counter="read", now=NOW)
    limiter.check_key("user", "u1", Quota(per_minute=5), counter="read", now=NOW)

    [item] = _items(rate_limit_table)
    assert item["pk"] == f"tier#user#u1#{DAY}"
    assert item["read_m"] == 2
    assert item["read_d"] == 2
    assert item["read_w"] == DAY + 3_600
    assert item[TTL_ATTRIBUTE] == DAY + 86_400 + 60


def test_each_request_costs_one_update_item(rate_limit_table: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """A cold key rolls the minute in one write and a warm one counts in one write."""
    assert rate_limit_table is not None
    limiter = _limiter()
    calls = _count_updates(monkeypatch, limiter)

    for _ in range(3):
        limiter.check_key("user", "u1", Quota(per_minute=5), now=NOW)

    assert len(calls) == 3
    assert calls[0].startswith("SET"), "the first request of the minute takes the rollover path"
    assert all(call.startswith("ADD") for call in calls[1:])


def test_a_refused_key_is_refused_from_memory(rate_limit_table: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """After a refusal, the rest of the minute costs no writes."""
    assert rate_limit_table is not None
    limiter = _limiter()
    calls = _count_updates(monkeypatch, limiter)
    quota = Quota(per_minute=1)

    limiter.check_key("user", "u1", quota, now=NOW)
    limiter.check_key("user", "u1", quota, now=NOW)
    later = [limiter.check_key("user", "u1", quota, now=NOW + 10) for _ in range(5)]

    assert len(calls) == 2
    assert all(not decision.allowed for decision in later)
    assert later[0].reset_after == 45


def test_the_minute_rolls_over_and_the_day_accumulates(rate_limit_table: Any) -> None:
    """A new minute resets the minute count while the day count keeps growing."""
    limiter = _limiter()
    quota = Quota(per_minute=2)

    first = [limiter.check_key("user", "u1", quota, now=NOW).allowed for _ in range(3)]
    second = [limiter.check_key("user", "u1", quota, now=NOW + 60).allowed for _ in range(2)]

    assert first == [True, True, False]
    assert second == [True, True]
    [item] = _items(rate_limit_table)
    assert item["all_m"] == 2
    assert item["all_d"] == 5, "the refused request still counts toward the day"


def test_the_daily_quota_refuses_until_the_day_ends(rate_limit_table: Any) -> None:
    """Once the day is spent the refusal names the daily quota and resets at midnight UTC."""
    assert rate_limit_table is not None
    limiter = _limiter()
    quota = Quota(per_minute=10, per_day=3)

    allowed = [limiter.check_key("token", "t1", quota, now=NOW + 60 * i).allowed for i in range(3)]
    refused = limiter.check_key("token", "t1", quota, now=NOW + 600)
    still_refused = limiter.check_key("token", "t1", quota, now=NOW + 3_600)

    assert allowed == [True, True, True]
    assert refused.allowed is False
    assert refused.limit == 3
    assert refused.window_seconds == 86_400
    assert refused.reset_after == int(DAY + 86_400 - (NOW + 600))
    assert still_refused.allowed is False
    assert limiter.check_key("token", "t1", quota, now=DAY + 86_400 + 1.0).allowed is True


def test_the_headers_report_the_tighter_quota(rate_limit_table: Any) -> None:
    """With a nearly spent daily quota, the decision reports the day rather than the minute."""
    assert rate_limit_table is not None
    limiter = _limiter()

    decision = limiter.check_key("token", "t1", Quota(per_minute=10, per_day=3), now=NOW)

    assert (decision.limit, decision.remaining, decision.window_seconds) == (3, 2, 86_400)


def test_a_container_behind_the_minute_takes_a_second_write(
    rate_limit_table: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stale prediction costs one failed condition and then counts correctly."""
    assert rate_limit_table is not None
    first = _limiter()
    second = _limiter()
    quota = Quota(per_minute=5)
    second.check_key("user", "u1", quota, now=NOW)
    first.check_key("user", "u1", quota, now=NOW + 60)
    calls = _count_updates(monkeypatch, second)

    decision = second.check_key("user", "u1", quota, now=NOW + 60)

    assert len(calls) == 2
    assert decision.remaining == 3, "both containers' requests count in the new minute"


def test_a_hot_key_claims_a_lease_and_never_exceeds_the_cap(
    rate_limit_table: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Leases cut the writes for a hot key, and two containers together stay under the cap."""
    assert rate_limit_table is not None
    tiers = _tiers(max_lease=10, lease_divisor=2)
    first = _limiter(tiers)
    second = _limiter(tiers)
    first_calls = _count_updates(monkeypatch, first)
    quota = Quota(per_minute=100)

    allowed = 0
    for _ in range(80):
        allowed += first.check_key("user", "hot", quota, now=NOW).allowed
        allowed += second.check_key("user", "hot", quota, now=NOW).allowed

    assert allowed == 100, "exactly the cap is allowed across both containers"
    assert len(first_calls) < 40, "a hot key must not cost a write per request"


def test_a_lease_of_one_is_exact(rate_limit_table: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """`max_lease=1` writes on every allowed request."""
    assert rate_limit_table is not None
    limiter = _limiter()
    calls = _count_updates(monkeypatch, limiter)

    for _ in range(20):
        limiter.check_key("user", "u1", Quota(per_minute=100), now=NOW)

    assert len(calls) == 20


def test_check_key_fails_open(
    rate_limit_table: Any, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A table failure allows the request, logs the fail-open WARNING and emits the metric."""
    assert rate_limit_table is not None
    limiter = _limiter()
    emitted: list[dict[str, Any]] = []
    monkeypatch.setattr(ratelimit, "emit", lambda **kwargs: emitted.append(kwargs))
    monkeypatch.setattr(limiter, "metrics_enabled", True)

    def explode(*args: Any, **kwargs: Any) -> Any:
        """Raise in place of a DynamoDB call."""
        raise RuntimeError("table gone")

    monkeypatch.setattr(limiter, "update", explode)

    decision = limiter.check_key("user", "u1", Quota(per_minute=1), now=NOW)

    assert decision.allowed is True
    assert decision.failed_open is True
    assert any(getattr(record, "rate_limit_failed_open", False) for record in caplog.records)
    assert emitted[0]["dimensions"] == {"LimitClass": "tier", "Operation": "check"}


def test_check_subject_counts_reads_and_writes_separately(rate_limit_table: Any) -> None:
    """A user's read and write quotas are independent counters."""
    assert rate_limit_table is not None
    limiter = _limiter()
    subject = RateLimitSubject(plan="standard", user="u1")

    writes = [limiter.check_subject(subject, "POST") for _ in range(6)]
    read = limiter.check_subject(subject, "GET")

    assert [d.allowed for d in writes if d is not None] == [True] * 5 + [False]
    assert read is not None and read.allowed is True
    assert read.limit_name == "user-read"


def test_check_subject_stops_at_the_first_refusal(rate_limit_table: Any) -> None:
    """A refused token is not also counted against its tenant."""
    limiter = _limiter()
    subject = RateLimitSubject(plan="free", tenant="w1", token="t1")

    for _ in range(4):
        limiter.check_subject(subject, "POST")

    tenant = next(item for item in _items(rate_limit_table) if item["pk"].startswith("tier#tenant#"))
    assert tenant["all_m"] == 3


def test_check_subject_reports_the_tightest_key(rate_limit_table: Any) -> None:
    """An allowed result carries the decision with the least remaining."""
    assert rate_limit_table is not None
    limiter = _limiter()

    decision = limiter.check_subject(RateLimitSubject(plan="free", tenant="w1", user="u1"), "POST")

    assert decision is not None
    assert (decision.limit_name, decision.remaining) == ("user-write", 1)


def test_the_tenant_aggregate_spans_its_users(rate_limit_table: Any) -> None:
    """Different users in one tenant share the tenant's combined counter."""
    assert rate_limit_table is not None
    limiter = _limiter()

    results = [limiter.check_subject(RateLimitSubject(plan="free", tenant="w1", user=f"u{i}"), "GET") for i in range(7)]

    assert [r.allowed for r in results if r is not None] == [True] * 6 + [False]
    assert results[6] is not None and results[6].limit_name == "tenant-all"


def test_check_subject_answers_none_when_nothing_is_limited(rate_limit_table: Any) -> None:
    """A subject whose plan limits none of its keys is left to the IP classes."""
    assert rate_limit_table is not None
    limiter = _limiter()

    assert limiter.check_subject(RateLimitSubject(plan="standard", tenant="w1"), "GET") is None
    assert _items(rate_limit_table) == []


def test_an_unknown_plan_is_counted_under_the_default(rate_limit_table: Any) -> None:
    """A plan the mapping does not know gets the default plan's limits."""
    assert rate_limit_table is not None
    limiter = _limiter()

    decision = limiter.check_subject(RateLimitSubject(plan="legacy", user="u1"), "POST")

    assert decision is not None and decision.limit == 2


def _app(tiers: TieredLimits | None, *, tiered_limiter: TieredRateLimiter | None = None, **kwargs: Any) -> FastAPI:
    """An app guarded by the middleware with one IP class, a credential class and the tiers."""
    app = FastAPI()
    classes = [
        LimitClass(name="auth", limit=2, window_seconds=60, path_prefixes=("/api/auth",)),
        LimitClass(name="default", limit=3, window_seconds=60),
    ]
    app.middleware("http")(
        rate_limit_middleware(
            classes,
            tiers=tiers,
            tiered_limiter=tiered_limiter,
            exempt_paths=("/health",),
            prefix="",
            region_name="us-west-2",
            **kwargs,
        )
    )

    @app.get("/api/issues")
    async def issues() -> dict[str, bool]:
        """A read route."""
        return {"ok": True}

    @app.post("/api/issues")
    async def create() -> dict[str, bool]:
        """A write route."""
        return {"ok": True}

    @app.post("/api/auth/verify")
    async def verify() -> dict[str, bool]:
        """A credential route that stays per IP."""
        return {"ok": True}

    @app.get("/health")
    async def health() -> dict[str, bool]:
        """An exempt route."""
        return {"ok": True}

    return app


FREE_USER = {"x-plan": "free", "x-user": "u1"}


def test_middleware_refuses_a_spent_user_with_the_headers(rate_limit_table: Any, test_client: Any) -> None:
    """The 429 carries Retry-After and the X-RateLimit trio for the user's quota."""
    assert rate_limit_table is not None
    tiers = _tiers()
    client = test_client(_app(tiers, tiered_limiter=_limiter(tiers)))

    ok = [client.post("/api/issues", headers=FREE_USER) for _ in range(2)]
    refused = client.post("/api/issues", headers=FREE_USER)

    assert [r.status_code for r in ok] == [200, 200]
    assert ok[0].headers["X-RateLimit-Limit"] == "2"
    assert ok[0].headers["X-RateLimit-Remaining"] == "1"
    assert ok[0].headers["X-RateLimit-Reset"] == "55"
    assert refused.status_code == 429
    assert refused.headers["Retry-After"] == "55"
    assert refused.headers["X-RateLimit-Remaining"] == "0"
    assert refused.headers["RateLimit-Policy"] == '"user-write";q=2;w=60'


def test_middleware_counts_a_resolved_request_only_by_key(rate_limit_table: Any, test_client: Any) -> None:
    """A resolved request writes its keyed counter and never the IP class row."""
    tiers = _tiers()
    client = test_client(_app(tiers, tiered_limiter=_limiter(tiers)))

    client.get("/api/issues", headers=FREE_USER)

    assert [item["pk"] for item in _items(rate_limit_table)] == [f"tier#user#u1#{DAY}"]


def test_middleware_keeps_anonymous_requests_per_ip(rate_limit_table: Any, test_client: Any) -> None:
    """A request the resolver cannot name falls to the per-IP classes."""
    assert rate_limit_table is not None
    tiers = _tiers()
    client = test_client(_app(tiers, tiered_limiter=_limiter(tiers)))

    statuses = [client.get("/api/issues").status_code for _ in range(4)]

    assert statuses == [200, 200, 200, 429]


def test_middleware_keeps_ip_classes_per_ip(rate_limit_table: Any, test_client: Any) -> None:
    """A class in `ip_classes` is counted per IP even for a resolved subject."""
    assert rate_limit_table is not None
    tiers = _tiers(ip_classes=("auth",))
    client = test_client(_app(tiers, tiered_limiter=_limiter(tiers)))

    statuses = [client.post("/api/auth/verify", headers=FREE_USER).status_code for _ in range(3)]

    assert statuses == [200, 200, 429]
    assert client.post("/api/issues", headers=FREE_USER).status_code == 200, "the user's write quota is untouched"


def test_middleware_falls_back_to_ip_when_the_plan_limits_nothing(rate_limit_table: Any, test_client: Any) -> None:
    """A subject with no limited key is still counted, per IP."""
    assert rate_limit_table is not None
    tiers = _tiers()
    client = test_client(_app(tiers, tiered_limiter=_limiter(tiers)))
    headers = {"x-plan": "standard", "x-tenant": "w1"}

    statuses = [client.get("/api/issues", headers=headers).status_code for _ in range(4)]

    assert statuses == [200, 200, 200, 429]


def test_middleware_awaits_an_async_resolver(rate_limit_table: Any, test_client: Any) -> None:
    """An async resolver is awaited."""
    assert rate_limit_table is not None

    async def resolve(request: Request) -> RateLimitSubject | None:
        """Resolve every request to one free user."""
        return RateLimitSubject(plan="free", user="async-user")

    tiers = _tiers(resolver=resolve)
    client = test_client(_app(tiers, tiered_limiter=_limiter(tiers)))

    statuses = [client.post("/api/issues").status_code for _ in range(3)]

    assert statuses == [200, 200, 429]


def test_a_failing_resolver_falls_back_to_ip(
    rate_limit_table: Any, test_client: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """A resolver that raises is logged, and the request is counted per IP."""
    assert rate_limit_table is not None

    def resolve(request: Request) -> RateLimitSubject | None:
        """Fail on every request."""
        raise RuntimeError("membership lookup failed")

    tiers = _tiers(resolver=resolve)
    client = test_client(_app(tiers, tiered_limiter=_limiter(tiers)))

    assert client.get("/api/issues").status_code == 200
    assert "resolver failed" in caplog.text
    assert [item["pk"].split("#")[0] for item in _items(rate_limit_table)] == ["default"]


def test_middleware_skips_exempt_paths_for_tiers(rate_limit_table: Any, test_client: Any) -> None:
    """An exempt path is never counted, keyed or not."""
    tiers = _tiers()
    client = test_client(_app(tiers, tiered_limiter=_limiter(tiers)))

    client.get("/health", headers=FREE_USER)

    assert _items(rate_limit_table) == []


def test_middleware_builds_its_own_tiered_limiter(rate_limit_table: Any, test_client: Any) -> None:
    """Without an injected limiter the middleware builds one from `tiers`."""
    tiers = _tiers()
    client = test_client(_app(tiers))

    assert client.get("/api/issues", headers=FREE_USER).status_code == 200
    assert _items(rate_limit_table)[0]["pk"].startswith("tier#user#u1#")


def test_middleware_without_tiers_ignores_subject_headers(rate_limit_table: Any, test_client: Any) -> None:
    """No tier config means the per-IP behaviour, whatever the request carries."""
    client = test_client(_app(None))

    statuses = [client.get("/api/issues", headers=FREE_USER).status_code for _ in range(4)]

    assert statuses == [200, 200, 200, 429]
    assert {item["pk"].split("#")[0] for item in _items(rate_limit_table)} == {"default"}


def test_the_lease_cache_is_bounded(rate_limit_table: Any) -> None:
    """The in-process state evicts the least recently used counter past `cache_size`."""
    assert rate_limit_table is not None
    limiter = TieredRateLimiter(_tiers(), cache_size=2, prefix="", region_name="us-west-2", clock=lambda: NOW)

    for key in ("a", "b", "c"):
        limiter.check_key("user", key, Quota(per_minute=5))

    assert [pk.split("#")[2] for pk, _ in limiter._cache] == ["b", "c"]
