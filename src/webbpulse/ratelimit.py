"""Per-identity fixed-window rate limiting on one DynamoDB table.

One `UpdateItem` per request against `<prefix>-rate-limits`, with the window start in the
key and a TTL to reclaim it. Every boto3 error fails open, logs at WARNING with
`rate_limit_failed_open=True`, and emits a `RateLimitFailedOpen` count metric.

Three bindings share that counter: `rate_limit` as a per-route FastAPI dependency,
`rate_limit_middleware` as whole-app ASGI middleware that classifies each request with
`classify`, and `RateLimiter` called directly for a limit a route decides on itself, such
as counting only failed logins.

`TieredLimits` adds keyed limits by token, user and tenant on plan tiers. An app-supplied
resolver names the keys and the plan, and `TieredRateLimiter` counts each key with one
conditional `UpdateItem` holding its minute and daily counters together.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING, Any, Final, Literal, TypeAlias

from webbpulse.dynamodb import Repository
from webbpulse.messages import rate_limited
from webbpulse.metrics import emit, metrics_enabled_from_env

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import Request
    from starlette.responses import Response

__all__ = [
    "FAILED_OPEN_METRIC",
    "RATE_LIMIT_METRICS_NAMESPACE",
    "RATE_LIMIT_TABLE",
    "TTL_ATTRIBUTE",
    "Anchor",
    "LimitClass",
    "PlanLimits",
    "Quota",
    "RateLimitDecision",
    "RateLimitSubject",
    "RateLimiter",
    "ScopeLimits",
    "SubjectResolver",
    "TieredLimits",
    "TieredRateLimiter",
    "classify",
    "default_renderer",
    "identity_from_ip",
    "identity_from_principal",
    "principal_identity",
    "rate_limit",
    "rate_limit_headers",
    "rate_limit_middleware",
]

_log = logging.getLogger(__name__)

RATE_LIMIT_TABLE: Final = "rate-limits"

TTL_ATTRIBUTE: Final = "expires_at"

_TTL_GRACE_SECONDS: Final = 60

RATE_LIMIT_METRICS_NAMESPACE: Final = "WebbPulse/RateLimit"

FAILED_OPEN_METRIC: Final = "RateLimitFailedOpen"

type Anchor = Literal["clock", "first_request"]

type FailOpenOperation = Literal["check", "clear"]


class RateLimitDecision:
    """The outcome of one limiter check."""

    __slots__ = (
        "allowed",
        "failed_open",
        "limit",
        "limit_name",
        "remaining",
        "reset_after",
        "window_seconds",
    )

    def __init__(
        self,
        *,
        allowed: bool,
        limit: int,
        remaining: int,
        reset_after: int,
        window_seconds: int,
        failed_open: bool = False,
        limit_name: str = "default",
    ) -> None:
        """Record one limiter outcome and the quota state that produced it."""
        self.allowed = allowed
        self.limit = limit
        self.remaining = remaining
        self.reset_after = reset_after
        self.window_seconds = window_seconds
        self.failed_open = failed_open
        self.limit_name = limit_name

    def __repr__(self) -> str:
        """Summarise the decision and its quota counters."""
        return (
            f"RateLimitDecision(allowed={self.allowed}, limit={self.limit}, "
            f"remaining={self.remaining}, reset_after={self.reset_after}, "
            f"failed_open={self.failed_open})"
        )


@dataclass(frozen=True, slots=True)
class LimitClass:
    """One named limit: its cap, window, and the requests it applies to.

    A request matches when its method is in `methods` (or `methods` is unset) and its path
    sits under one of `path_prefixes` (or `path_prefixes` is unset), and its path is not in
    `exempt_paths`. `name` is both the counter namespace and the policy name in the headers,
    so two classes never share a row.
    """

    name: str
    limit: int
    window_seconds: int
    methods: Collection[str] | None = None
    path_prefixes: Collection[str] | None = None
    exempt_paths: Collection[str] = ()

    def matches(self, method: str, path: str) -> bool:
        """Whether one request belongs to this class.

        A class with neither `methods` nor `path_prefixes` matches everything, which is what
        makes the last class in a sequence the fallback.
        """
        normalised = _normalise_path(path)
        if normalised in {_normalise_path(exempt) for exempt in self.exempt_paths}:
            return False
        if self.methods is not None and method.upper() not in {m.upper() for m in self.methods}:
            return False
        return self.path_prefixes is None or any(
            _under_prefix(normalised, _normalise_path(prefix)) for prefix in self.path_prefixes
        )


def _normalise_path(path: str) -> str:
    """Drop one trailing slash, so `/api/auth/` and `/api/auth` classify alike."""
    return path.rstrip("/") or path


def _under_prefix(path: str, prefix: str) -> bool:
    """True when `path` is `prefix` itself or sits beneath it."""
    return path == prefix or path.startswith(f"{prefix}/")


def classify(method: str, path: str, classes: Sequence[LimitClass]) -> LimitClass:
    """The first class in `classes` this request matches.

    Order is the policy: put the narrow classes first and a catch-all last. A request that
    matches nothing raises, because silently not counting it is the failure mode worth
    refusing at configuration time.
    """
    for limit_class in classes:
        if limit_class.matches(method, path):
            return limit_class
    raise LookupError(f"No LimitClass matches {method} {path}; end the sequence with a catch-all class.")


def rate_limit_headers(decision: RateLimitDecision, *, policy_name: str | None = None) -> dict[str, str]:
    """Response headers describing the limit, in both header styles.

    The structured `RateLimit` and `RateLimit-Policy` fields are the current IETF draft's,
    and the `X-RateLimit-*` trio is emitted alongside for the clients that parse it.
    `policy_name` defaults to the decision's own limit name.
    """
    name = decision.limit_name if policy_name is None else policy_name
    remaining = max(decision.remaining, 0)
    return {
        "RateLimit": f'"{name}";r={remaining};t={decision.reset_after}',
        "RateLimit-Policy": f'"{name}";q={decision.limit};w={decision.window_seconds}',
        "X-RateLimit-Limit": str(decision.limit),
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Reset": str(decision.reset_after),
    }


if TYPE_CHECKING:
    _FastAPIRequest: TypeAlias = Request  # noqa: UP040
else:
    _FastAPIRequest = None


def _bind_fastapi_request() -> None:
    """Put `fastapi.Request` in this module's globals for FastAPI's annotation lookup.

    `fastapi` is an optional extra, so the name starts as `None` and is bound on first use
    of `rate_limit` rather than imported at module scope.
    """
    global _FastAPIRequest
    if _FastAPIRequest is None:
        from fastapi import Request as ImportedRequest

        _FastAPIRequest = ImportedRequest


def identity_from_ip(request: Request) -> str:
    """Default identity: the API Gateway source IP. See `webbpulse.http.client_ip`."""
    from webbpulse.http import client_ip

    return client_ip(request)


def principal_identity(
    fallback: Callable[[Request], str] = identity_from_ip,
) -> Callable[[Request], str]:
    """An identity function keying a signed-in caller by principal and anyone else by `fallback`.

    A verified authorizer `sub` keys as `user:<sub>`. Every other request, a bearer token or
    API key included, answers `fallback(request)`: the middleware runs before any credential
    is verified, so keying on a presented one would hand each forged value a fresh bucket.
    Pass a product's own IP reader as `fallback` where it covers request shapes `identity_from_ip` does not.

    Keying by principal is what stops a browser, a CLI and agents behind one address from
    sharing a single bucket.
    """

    def identity(request: Request) -> str:
        """The principal key for this request, or the fallback identity."""
        from webbpulse.identity.claims import identity_subject

        subject = identity_subject(request).strip()
        if subject:
            return f"user:{subject}"
        return fallback(request)

    return identity


def identity_from_principal(request: Request) -> str:
    """`principal_identity()` over `identity_from_ip`: verified user first, then source IP."""
    return _default_principal_identity(request)


_default_principal_identity: Final = principal_identity()


class RateLimiter(Repository):
    """Fixed-window counter over the `<prefix>-rate-limits` table.

    `anchor="clock"` puts the window start in the key, so counting is one `UpdateItem` and
    a new window is a new row. `anchor="first_request"` keeps one row per identity whose
    window opens on the first counted request and closes when its TTL passes, which costs a
    conditional update plus, on the rollover, a put. Prefer the clock on a per-request path
    and the first request where the anchor is the point, as a login lockout's is.
    """

    logical_name = RATE_LIMIT_TABLE

    def __init__(
        self,
        *,
        namespace: str = "default",
        anchor: Anchor = "clock",
        count_attribute: str = "count",
        metrics_namespace: str = RATE_LIMIT_METRICS_NAMESPACE,
        metrics_enabled: bool | None = None,
        **kwargs: Any,
    ) -> None:
        """Build a limiter whose `namespace` separates limits sharing the table.

        A login limit and a search limit on the same IP are independent counters.
        `count_attribute` names the counter attribute, for a table already holding rows
        written under another name. `metrics_namespace` is where the fail-open metric goes,
        and `metrics_enabled=None` gates it on `metrics_enabled_from_env()` at emit time.
        """
        super().__init__(**kwargs)
        self.namespace = namespace
        self.anchor: Anchor = anchor
        self.count_attribute = count_attribute
        self.metrics_namespace = metrics_namespace
        self.metrics_enabled = metrics_enabled

    def _key(self, identity: str, window_start: int | None = None) -> str:
        """The partition key for one identity in this namespace.

        A clock-anchored key carries the window start, so the row is immutable within the
        window; a first-request key does not, because the one row carries the window.
        """
        if window_start is None:
            return f"{self.namespace}#{identity}"
        return f"{self.namespace}#{identity}#{window_start}"

    def _emit_failed_open(self, operation: FailOpenOperation) -> None:
        """Emit one `RateLimitFailedOpen` count, dimensioned by limit class and operation.

        The limit class is this limiter's `namespace`, which code chooses, so the dimension
        stays bounded. Any failure is logged and swallowed, never raised into the request.
        """
        try:
            enabled = metrics_enabled_from_env() if self.metrics_enabled is None else self.metrics_enabled
            emit(
                namespace=self.metrics_namespace,
                metrics={FAILED_OPEN_METRIC: 1},
                dimensions={"LimitClass": self.namespace, "Operation": operation},
                enabled=enabled,
            )
        except Exception as exc:
            _log.warning(
                "Failed to emit the rate limit fail-open metric.",
                extra={"rate_limit_namespace": self.namespace, "error_type": type(exc).__name__},
            )

    def _failed_open(
        self,
        operation: FailOpenOperation,
        exc: BaseException,
        *,
        limit: int,
        window_seconds: int,
        reset_after: int,
    ) -> RateLimitDecision:
        """Log one fail-open WARNING, emit the metric, and return the allowing decision."""
        _log.warning(
            "Rate limit check failed; allowing the request.",
            extra={
                "rate_limit_failed_open": True,
                "rate_limit_namespace": self.namespace,
                "rate_limit_operation": operation,
                "error_type": type(exc).__name__,
                "error_message": str(exc),
            },
        )
        self._emit_failed_open(operation)
        return RateLimitDecision(
            allowed=True,
            limit=limit,
            remaining=limit,
            reset_after=reset_after,
            window_seconds=window_seconds,
            failed_open=True,
            limit_name=self.namespace,
        )

    def check(
        self,
        identity: str,
        *,
        limit: int,
        window_seconds: int,
        now: float | None = None,
    ) -> RateLimitDecision:
        """Count this request against `identity` and decide whether to allow it.

        Counted before the decision, so a rejected request still counts and a caller cannot
        hold the counter at exactly the limit. Any boto3 failure fails open with
        `failed_open` set on the decision.
        """
        current = time.time() if now is None else now
        if self.anchor == "first_request":
            return self._check_first_request(identity, limit=limit, window_seconds=window_seconds, now=current)
        return self._check_clock(identity, limit=limit, window_seconds=window_seconds, now=current)

    def _check_clock(
        self,
        identity: str,
        *,
        limit: int,
        window_seconds: int,
        now: float,
    ) -> RateLimitDecision:
        """Count in the clock-aligned window, which is one `UpdateItem`."""
        window_start = int(math.floor(now / window_seconds) * window_seconds)
        window_end = window_start + window_seconds
        reset_after = max(math.ceil(window_end - now), 0)

        try:
            attributes = self.update(
                {"pk": self._key(identity, window_start)},
                update_expression="ADD #c :one SET #ttl = if_not_exists(#ttl, :ttl)",
                expression_names={"#c": self.count_attribute, "#ttl": TTL_ATTRIBUTE},
                expression_values={":one": 1, ":ttl": window_end + _TTL_GRACE_SECONDS},
                return_values="UPDATED_NEW",
            )
        except Exception as exc:
            return self._failed_open("check", exc, limit=limit, window_seconds=window_seconds, reset_after=reset_after)

        count = int((attributes or {}).get(self.count_attribute, 1))
        return RateLimitDecision(
            allowed=count <= limit,
            limit=limit,
            remaining=max(limit - count, 0),
            reset_after=reset_after,
            window_seconds=window_seconds,
            limit_name=self.namespace,
        )

    def _check_first_request(
        self,
        identity: str,
        *,
        limit: int,
        window_seconds: int,
        now: float,
    ) -> RateLimitDecision:
        """Count in a window that opens on the first counted request.

        The conditional update extends the live window; when the TTL has already passed the
        condition fails and the row is replaced, which opens a new window at 1.
        """
        from webbpulse.dynamodb import ConditionFailed

        current = int(now)
        key = {"pk": self._key(identity)}
        expires_at = current + window_seconds

        try:
            attributes = self.update(
                key,
                update_expression="ADD #c :one SET #ttl = if_not_exists(#ttl, :ttl)",
                expression_names={"#c": self.count_attribute, "#ttl": TTL_ATTRIBUTE},
                expression_values={":one": 1, ":ttl": expires_at, ":now": current},
                condition="attribute_not_exists(#ttl) OR #ttl > :now",
                return_values="ALL_NEW",
            )
        except ConditionFailed:
            attributes = None
        except Exception as exc:
            return self._failed_open(
                "check", exc, limit=limit, window_seconds=window_seconds, reset_after=window_seconds
            )

        if attributes is None:
            try:
                self.put({**key, self.count_attribute: 1, TTL_ATTRIBUTE: expires_at})
            except Exception as exc:
                return self._failed_open(
                    "check", exc, limit=limit, window_seconds=window_seconds, reset_after=window_seconds
                )
            count, window_end = 1, expires_at
        else:
            count = int(attributes.get(self.count_attribute, 1))
            window_end = int(attributes.get(TTL_ATTRIBUTE, expires_at))

        return RateLimitDecision(
            allowed=count <= limit,
            limit=limit,
            remaining=max(limit - count, 0),
            reset_after=max(window_end - current, 0),
            window_seconds=window_seconds,
            limit_name=self.namespace,
        )

    def clear(self, identity: str, *, window_seconds: int | None = None, now: float | None = None) -> None:
        """Forget `identity`'s counter, as a successful login forgets its failures.

        A first-request limiter holds one row per identity and needs nothing else. A
        clock-anchored one needs `window_seconds` to name the row, since the window start is
        part of the key; without it the call is a no-op rather than a silent miss, and logs.
        Failures are swallowed, logged and counted, like every other limiter call.
        """
        if self.anchor == "clock" and window_seconds is None:
            _log.warning(
                "Cannot clear a clock-anchored limiter without window_seconds; ignoring the call.",
                extra={"rate_limit_namespace": self.namespace},
            )
            return

        if self.anchor == "clock":
            assert window_seconds is not None
            current = time.time() if now is None else now
            window_start = int(math.floor(current / window_seconds) * window_seconds)
            key = {"pk": self._key(identity, window_start)}
        else:
            key = {"pk": self._key(identity)}

        try:
            self.delete(key)
        except Exception as exc:
            _log.warning(
                "Rate limit clear failed; the counter was left in place.",
                extra={
                    "rate_limit_failed_open": True,
                    "rate_limit_namespace": self.namespace,
                    "rate_limit_operation": "clear",
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                },
            )
            self._emit_failed_open("clear")


_MINUTE_SECONDS: Final = 60

_DAY_SECONDS: Final = 86_400

_TIER_WRITE_ATTEMPTS: Final = 3

type RequestClass = Literal["read", "write"]

type Scope = Literal["token", "user", "tenant"]

SCOPES: Final[tuple[Scope, ...]] = ("token", "user", "tenant")


@dataclass(frozen=True, slots=True)
class Quota:
    """A requests-per-minute cap plus an optional daily quota for one counter."""

    per_minute: int
    per_day: int | None = None

    def __post_init__(self) -> None:
        """Refuse a cap that is not a positive integer."""
        if self.per_minute < 1:
            raise ValueError("Quota.per_minute must be at least 1.")
        if self.per_day is not None and self.per_day < 1:
            raise ValueError("Quota.per_day must be at least 1 when set.")


@dataclass(frozen=True, slots=True)
class ScopeLimits:
    """The read and write quotas for one keyed scope.

    A `None` quota leaves that request class uncounted for the scope. `shared=True` counts
    reads and writes against one counter; build it with `ScopeLimits.combined`.
    """

    read: Quota | None = None
    write: Quota | None = None
    shared: bool = False

    @classmethod
    def combined(cls, quota: Quota) -> ScopeLimits:
        """One quota over reads and writes together, as a workspace aggregate wants."""
        return cls(read=quota, write=quota, shared=True)

    def select(self, request_class: RequestClass) -> tuple[str, Quota] | None:
        """The counter name and quota for one request class, or `None` when uncounted."""
        quota = self.read if request_class == "read" else self.write
        if quota is None:
            return None
        return ("all" if self.shared else request_class, quota)


@dataclass(frozen=True, slots=True)
class PlanLimits:
    """One plan's limits per keyed scope. A `None` scope is never counted."""

    token: ScopeLimits | None = None
    user: ScopeLimits | None = None
    tenant: ScopeLimits | None = None

    def for_scope(self, scope: Scope) -> ScopeLimits | None:
        """The limits for `scope`."""
        limits: ScopeLimits | None = getattr(self, scope)
        return limits


@dataclass(frozen=True, slots=True)
class RateLimitSubject:
    """Who a request is counted against, as the app's resolver names them.

    `token` is an API key or token id, never its secret. Each key that is set and has a quota
    in the plan costs one write, so set only the keys the plan limits.
    """

    plan: str
    tenant: str | None = None
    user: str | None = None
    token: str | None = None

    def key_for(self, scope: Scope) -> str | None:
        """The key for `scope`, or `None` when the resolver did not name one."""
        key: str | None = getattr(self, scope)
        return key


type SubjectResolver = (
    Callable[[Request], RateLimitSubject | None] | Callable[[Request], Awaitable[RateLimitSubject | None]]
)


@dataclass(frozen=True, slots=True)
class TieredLimits:
    """Plan-tier limits keyed by token, user and tenant, and the resolver that picks them.

    `resolver` maps a request to a `RateLimitSubject`, or `None` to leave it on the per-IP
    classes. It must name only verified identities, since an unverified key is a fresh
    bucket per guess. `plans` maps plan names to limits and an unknown plan falls back to
    `default_plan`, which must be one of them. `ip_classes` names `LimitClass` values that
    stay per IP even for a resolved subject, such as a credential class. `max_lease` and
    `lease_divisor` size the in-process token lease; `max_lease=1` makes every request a
    write and the count exact.
    """

    resolver: SubjectResolver
    plans: Mapping[str, PlanLimits]
    default_plan: str = "default"
    read_methods: Collection[str] = ("GET", "HEAD")
    ip_classes: Collection[str] = ()
    max_lease: int = 10
    lease_divisor: int = 8

    def __post_init__(self) -> None:
        """Refuse a default plan that is not in `plans` and a non-positive lease setting."""
        if self.default_plan not in self.plans:
            raise ValueError(f"TieredLimits.default_plan {self.default_plan!r} is not in plans.")
        if self.max_lease < 1 or self.lease_divisor < 1:
            raise ValueError("TieredLimits.max_lease and lease_divisor must be at least 1.")

    def limits_for(self, plan: str) -> tuple[str, PlanLimits]:
        """The plan name actually applied and its limits, falling back to the default."""
        if plan in self.plans:
            return plan, self.plans[plan]
        return self.default_plan, self.plans[self.default_plan]

    def request_class(self, method: str) -> RequestClass:
        """`read` for a method in `read_methods`, otherwise `write`."""
        return "read" if method.upper() in {m.upper() for m in self.read_methods} else "write"


@dataclass(slots=True)
class _LeaseState:
    """What one container knows about one counter in the current minute."""

    minute: int
    written_minute: int | None = None
    tokens: int = 0
    served: int = 0
    previous_served: int = 0
    minute_remaining: int = 0
    day_remaining: int | None = None
    blocked_until: float = 0.0
    blocked_limit: int = 0
    blocked_window: int = _MINUTE_SECONDS


class TieredRateLimiter(RateLimiter):
    """Keyed minute and daily counters over the `<prefix>-rate-limits` table.

    One item per key per UTC day holds, for each counter, the minute count, the minute it
    belongs to and the day count, so a minute cap and a daily quota cost one conditional
    `UpdateItem` together. The first request of a minute resets the minute count with the
    complementary condition, which the in-process state predicts, so a second call happens
    only when another container rolled the minute first.

    A hot key claims a lease of up to `max_lease` counts in one write and serves the rest
    from memory within that minute. A lease is at most one `lease_divisor`th of the local
    rate and of what remains, so it shrinks to 1 near the cap and never lets more through
    than the cap. A key refused for the minute or the day is refused from memory until the
    window ends, so a caller hammering past a refusal costs no writes.
    """

    def __init__(
        self,
        tiers: TieredLimits,
        *,
        namespace: str = "tier",
        cache_size: int = 1024,
        clock: Callable[[], float] = time.time,
        **kwargs: Any,
    ) -> None:
        """Build a limiter for `tiers`, holding lease state for up to `cache_size` counters.

        `clock` supplies the current epoch time when a call passes no `now`.
        """
        kwargs.pop("anchor", None)
        super().__init__(namespace=namespace, **kwargs)
        self.tiers = tiers
        self.clock = clock
        self.cache_size = cache_size
        self._cache: OrderedDict[tuple[str, str], _LeaseState] = OrderedDict()
        self._lock = threading.Lock()

    def check_subject(
        self, subject: RateLimitSubject, method: str, *, now: float | None = None
    ) -> RateLimitDecision | None:
        """Count one request against every key `subject` names that its plan limits.

        Keys are checked token, user, tenant, and the first refusal stops the rest. An
        allowed result is the decision with the least remaining, for the headers. `None`
        means no key was counted, so the caller should fall back to the per-IP classes.
        """
        _, plan = self.tiers.limits_for(subject.plan)
        request_class = self.tiers.request_class(method)
        decisions: list[RateLimitDecision] = []
        for scope in SCOPES:
            key = subject.key_for(scope)
            limits = plan.for_scope(scope)
            if not key or limits is None:
                continue
            selected = limits.select(request_class)
            if selected is None:
                continue
            counter, quota = selected
            decision = self.check_key(scope, key, quota, counter=counter, now=now)
            if not decision.allowed:
                return decision
            decisions.append(decision)
        if not decisions:
            return None
        enforced = [decision for decision in decisions if not decision.failed_open]
        if not enforced:
            return decisions[0]
        return min(enforced, key=lambda decision: decision.remaining)

    def check_key(
        self,
        scope: str,
        key: str,
        quota: Quota,
        *,
        counter: str = "all",
        now: float | None = None,
    ) -> RateLimitDecision:
        """Count one request against `key`'s `counter` under `quota`, and decide.

        Usable directly for a per-route cap such as a search limit. Any boto3 failure fails
        open, as every other limiter call does.
        """
        current = self.clock() if now is None else now
        minute = int(math.floor(current / _MINUTE_SECONDS) * _MINUTE_SECONDS)
        day = int(math.floor(current / _DAY_SECONDS) * _DAY_SECONDS)
        pk = f"{self.namespace}#{scope}#{key}#{day}"
        name = f"{scope}-{counter}"
        cache_key = (pk, counter)

        with self._lock:
            state = self._touch(cache_key, minute)
            if state is not None and state.blocked_until > current:
                return RateLimitDecision(
                    allowed=False,
                    limit=state.blocked_limit,
                    remaining=0,
                    reset_after=max(math.ceil(state.blocked_until - current), 0),
                    window_seconds=state.blocked_window,
                    limit_name=name,
                )
            if state is not None and state.tokens > 0:
                state.tokens -= 1
                state.served += 1
                return self._allowed(state, quota, name, current, minute, day)
            lease = self._lease_size(state, quota)
            same_minute = state is not None and state.written_minute is not None and state.written_minute >= minute

        try:
            attributes = self._claim(pk, counter, lease, minute, day + _DAY_SECONDS, same_minute=same_minute)
        except Exception as exc:
            return self._failed_open(
                "check",
                exc,
                limit=quota.per_minute,
                window_seconds=_MINUTE_SECONDS,
                reset_after=max(math.ceil(minute + _MINUTE_SECONDS - current), 0),
            )

        minute_count = int(attributes.get(f"{counter}_m", lease))
        day_count = int(attributes.get(f"{counter}_d", lease))
        granted = min(lease, quota.per_minute - (minute_count - lease))
        if quota.per_day is not None:
            granted = min(granted, quota.per_day - (day_count - lease))
        granted = max(granted, 0)

        with self._lock:
            state = self._touch(cache_key, minute)
            if state is None:
                state = _LeaseState(minute=minute)
                self._store(cache_key, state)
            state.written_minute = minute
            state.served += 1
            state.minute_remaining = max(quota.per_minute - minute_count, 0)
            state.day_remaining = None if quota.per_day is None else max(quota.per_day - day_count, 0)
            if granted >= 1:
                state.tokens += granted - 1
                return self._allowed(state, quota, name, current, minute, day)
            day_spent = quota.per_day is not None and day_count - lease >= quota.per_day
            if day_spent:
                assert quota.per_day is not None
                state.blocked_until = float(day + _DAY_SECONDS)
                state.blocked_limit = quota.per_day
                state.blocked_window = _DAY_SECONDS
            else:
                state.blocked_until = float(minute + _MINUTE_SECONDS)
                state.blocked_limit = quota.per_minute
                state.blocked_window = _MINUTE_SECONDS
            state.tokens = 0
            return RateLimitDecision(
                allowed=False,
                limit=state.blocked_limit,
                remaining=0,
                reset_after=max(math.ceil(state.blocked_until - current), 0),
                window_seconds=state.blocked_window,
                limit_name=name,
            )

    def _touch(self, cache_key: tuple[str, str], minute: int) -> _LeaseState | None:
        """The cached state for `cache_key`, rolled forward to `minute`. Hold the lock."""
        state = self._cache.get(cache_key)
        if state is None:
            return None
        self._cache.move_to_end(cache_key)
        if state.minute != minute:
            state.previous_served = state.served if state.minute == minute - _MINUTE_SECONDS else 0
            state.served = 0
            state.tokens = 0
            state.minute = minute
        return state

    def _store(self, cache_key: tuple[str, str], state: _LeaseState) -> None:
        """Insert `state`, evicting the least recently used entry past `cache_size`. Hold the lock."""
        self._cache[cache_key] = state
        while len(self._cache) > self.cache_size:
            self._cache.popitem(last=False)

    def _lease_size(self, state: _LeaseState | None, quota: Quota) -> int:
        """How many counts to claim in this write: 1 for a cold key, more for a hot one."""
        if self.tiers.max_lease <= 1 or state is None:
            return 1
        divisor = self.tiers.lease_divisor
        minute_remaining = state.minute_remaining if state.written_minute == state.minute else quota.per_minute
        bounds = [
            self.tiers.max_lease,
            max(state.served, state.previous_served) // divisor,
            minute_remaining // divisor,
        ]
        if quota.per_day is not None and state.day_remaining is not None:
            bounds.append(state.day_remaining // divisor)
        return max(1, min(bounds))

    def _claim(
        self,
        pk: str,
        counter: str,
        lease: int,
        minute: int,
        expires: int,
        *,
        same_minute: bool,
    ) -> dict[str, Any]:
        """Add `lease` to the minute and day counts in one conditional `UpdateItem`.

        The count path holds when the stored minute is this one or later; the rollover path
        holds when it is earlier or absent, and resets the minute count. The two conditions
        are complementary, so the other is tried only when a concurrent writer moved the
        minute between the prediction and the write.
        """
        from webbpulse.dynamodb import ConditionFailed

        names = {
            "#m": f"{counter}_m",
            "#w": f"{counter}_w",
            "#d": f"{counter}_d",
            "#ttl": TTL_ATTRIBUTE,
        }
        values = {":n": lease, ":minute": minute, ":ttl": expires + _TTL_GRACE_SECONDS}
        count_path = (
            "ADD #m :n, #d :n SET #ttl = if_not_exists(#ttl, :ttl)",
            "#w >= :minute",
        )
        rollover_path = (
            "SET #m = :n, #w = :minute, #ttl = if_not_exists(#ttl, :ttl) ADD #d :n",
            "attribute_not_exists(#w) OR #w < :minute",
        )
        first, second = (count_path, rollover_path) if same_minute else (rollover_path, count_path)
        for attempt in range(_TIER_WRITE_ATTEMPTS):
            expression, condition = first if attempt % 2 == 0 else second
            try:
                attributes = self.update(
                    {"pk": pk},
                    update_expression=expression,
                    expression_names=names,
                    expression_values=values,
                    condition=condition,
                    return_values="UPDATED_NEW",
                )
            except ConditionFailed:
                continue
            return attributes or {}
        raise RuntimeError(f"Rate limit counter {pk} stayed contended for {_TIER_WRITE_ATTEMPTS} attempts.")

    def _allowed(
        self,
        state: _LeaseState,
        quota: Quota,
        name: str,
        now: float,
        minute: int,
        day: int,
    ) -> RateLimitDecision:
        """An allowing decision reporting whichever of the minute and day quotas is tighter."""
        minute_left = state.minute_remaining + state.tokens
        limit, window, left, reset_at = quota.per_minute, _MINUTE_SECONDS, minute_left, minute + _MINUTE_SECONDS
        if quota.per_day is not None and state.day_remaining is not None:
            day_left = state.day_remaining + state.tokens
            if day_left < minute_left:
                limit, window, left, reset_at = quota.per_day, _DAY_SECONDS, day_left, day + _DAY_SECONDS
        return RateLimitDecision(
            allowed=True,
            limit=limit,
            remaining=max(left, 0),
            reset_after=max(math.ceil(reset_at - now), 0),
            window_seconds=window,
            limit_name=name,
        )


def rate_limit(
    key_fn: Callable[[Request], str] | Callable[[Request], Awaitable[str]] = identity_from_ip,
    *,
    limit: int,
    window_seconds: int,
    namespace: str = "default",
    limiter: RateLimiter | None = None,
) -> Callable[..., Awaitable[RateLimitDecision]]:
    """Build a FastAPI dependency that enforces one limit, per route.

    Rejection raises `HTTPException(429)` with `Retry-After` and the RateLimit headers,
    which a success instead leaves on `request.state.rate_limit_headers`. The limiter is
    built once, when the dependency is, so the cached table resource is reused.
    """
    from fastapi import HTTPException
    from starlette.concurrency import run_in_threadpool

    resolved = limiter if limiter is not None else RateLimiter(namespace=namespace)

    _bind_fastapi_request()

    async def dependency(request: _FastAPIRequest) -> RateLimitDecision:
        """Count the request in a threadpool, publish the headers, and refuse over the limit.

        The parameter is annotated with the module-level `_FastAPIRequest` because FastAPI
        resolves a dependency's annotations against the defining module's globals.
        """
        produced = key_fn(request)
        identity = await produced if isinstance(produced, Awaitable) else produced

        decision = await run_in_threadpool(
            partial(resolved.check, identity, limit=limit, window_seconds=window_seconds)
        )
        headers = rate_limit_headers(decision, policy_name=namespace)
        request.state.rate_limit_headers = headers

        if not decision.allowed:
            raise HTTPException(
                status_code=429,
                detail=rate_limited(),
                headers={**headers, "Retry-After": str(decision.reset_after)},
            )
        return decision

    return dependency


def default_renderer(decision: RateLimitDecision) -> Response:
    """The package's own 429: the detailed error envelope plus the RateLimit headers.

    The sentence comes from `webbpulse.messages.rate_limited`, carrying the same
    `reset_after` the `Retry-After` header does so the copy names a real number.
    """
    from starlette.responses import JSONResponse

    headers = {**rate_limit_headers(decision), "Retry-After": str(decision.reset_after)}
    return JSONResponse(
        status_code=429,
        content={"detail": rate_limited(retry_after=decision.reset_after)},
        headers=headers,
    )


def rate_limit_middleware(
    classes: Sequence[LimitClass],
    *,
    identity_fn: Callable[[Request], str] = identity_from_ip,
    exempt_paths: Collection[str] = (),
    exempt_prefixes: Collection[str] = (),
    exempt_methods: Collection[str] = ("OPTIONS",),
    anchor: Anchor = "clock",
    renderer: Callable[[RateLimitDecision], Response] | None = None,
    enabled: Callable[[], bool] | None = None,
    limiters: dict[str, RateLimiter] | None = None,
    tiers: TieredLimits | None = None,
    tiered_limiter: TieredRateLimiter | None = None,
    **limiter_kwargs: Any,
) -> Callable[..., Awaitable[Response]]:
    """ASGI middleware counting each request against its matching class.

    Wire it with `app.middleware("http")(rate_limit_middleware([...]))`. Each class gets its
    own `RateLimiter`, namespaced by the class name, so two classes never share a counter.
    `exempt_paths` is matched exactly and `exempt_prefixes` by subtree, which keeps `"/"`
    exempting only itself. `renderer` builds the 429 body, defaulting to the package's
    envelope; pass a product's own while its clients still parse that shape.

    An allowed request carries the RateLimit headers on its response, and a failed-open one
    carries none, so a full quota is never advertised from a limiter that is not counting.

    `enabled` is asked on every request; pass `lambda: settings.rate_limiting_enabled` so the
    middleware follows the environment convention and staging runs unlimited.

    `tiers` adds keyed plan-tier limits. A request its resolver maps to a subject is counted
    against that subject's token, user and tenant keys instead of its IP class, unless its
    class is in `tiers.ip_classes` or its plan limits none of those keys. Without `tiers`
    the middleware behaves exactly as it always has.
    """
    from starlette.concurrency import run_in_threadpool
    from starlette.responses import Response as StarletteResponse

    if not classes:
        raise ValueError("rate_limit_middleware needs at least one LimitClass.")

    resolved_renderer = renderer if renderer is not None else default_renderer
    built: dict[str, RateLimiter] = (
        limiters
        if limiters is not None
        else {
            limit_class.name: RateLimiter(namespace=limit_class.name, anchor=anchor, **limiter_kwargs)
            for limit_class in classes
        }
    )
    tiered: TieredRateLimiter | None = None
    if tiers is not None:
        tiered = tiered_limiter if tiered_limiter is not None else TieredRateLimiter(tiers, **limiter_kwargs)
    ip_classes = frozenset(tiers.ip_classes) if tiers is not None else frozenset()
    exact = {_normalise_path(path) for path in exempt_paths}
    prefixes = tuple(_normalise_path(prefix) for prefix in exempt_prefixes)
    methods = {method.upper() for method in exempt_methods}

    def _exempt(method: str, path: str) -> bool:
        """Whether this request is never counted at all."""
        if method.upper() in methods:
            return True
        normalised = _normalise_path(path)
        if normalised in exact:
            return True
        return any(_under_prefix(normalised, prefix) for prefix in prefixes)

    async def middleware(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Classify the request, count it, and refuse it once its class is spent."""
        if enabled is not None and not enabled():
            return await call_next(request)
        if _exempt(request.method, request.url.path):
            return await call_next(request)

        try:
            limit_class: LimitClass | None = classify(request.method, request.url.path, classes)
        except LookupError:
            limit_class = None

        if tiers is not None and tiered is not None and (limit_class is None or limit_class.name not in ip_classes):
            subject = await _resolve_subject(tiers, request)
            if subject is not None:
                decision = await run_in_threadpool(partial(tiered.check_subject, subject, request.method))
                if decision is not None:
                    request.state.rate_limit_subject = subject
                    plan_name, _ = tiers.limits_for(subject.plan)
                    return await _enforce(request, call_next, decision, decision.limit_name, plan_name)

        if limit_class is None:
            return await call_next(request)

        limiter = built[limit_class.name]
        identity = identity_fn(request)
        decision = await run_in_threadpool(
            partial(
                limiter.check,
                identity,
                limit=limit_class.limit,
                window_seconds=limit_class.window_seconds,
            )
        )
        return await _enforce(request, call_next, decision, limit_class.name, None)

    async def _enforce(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
        decision: RateLimitDecision,
        class_name: str,
        plan_name: str | None,
    ) -> Response:
        """Refuse a spent request, or serve it with the RateLimit headers attached."""
        request.state.rate_limit_decision = decision

        if not decision.allowed:
            extra: dict[str, Any] = {
                "rate_limit_exceeded": True,
                "rate_limit_class": class_name,
                "rate_limit_reset_after": decision.reset_after,
            }
            if plan_name is not None:
                extra["rate_limit_plan"] = plan_name
            _log.warning("Rate limit exceeded.", extra=extra)
            rendered = resolved_renderer(decision)
            assert isinstance(rendered, StarletteResponse)
            return rendered

        response = await call_next(request)
        if not decision.failed_open:
            response.headers.update(rate_limit_headers(decision))
        return response

    return middleware


async def _resolve_subject(tiers: TieredLimits, request: Request) -> RateLimitSubject | None:
    """Run the app's resolver, treating any failure as no subject so the IP limit applies."""
    try:
        produced = tiers.resolver(request)
        subject = await produced if isinstance(produced, Awaitable) else produced
    except Exception as exc:
        _log.warning(
            "Rate limit subject resolver failed; counting the request per IP.",
            extra={"error_type": type(exc).__name__, "error_message": str(exc)},
        )
        return None
    return subject
