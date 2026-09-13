"""Per-identity fixed-window rate limiting on one DynamoDB table.

One `UpdateItem` per request against `<prefix>-rate-limits`, with the window start in the
key and a TTL to reclaim it. Every boto3 error fails open and logs at WARNING with
`rate_limit_failed_open=True`, which is the signal to alarm on.

Three bindings share that counter: `rate_limit` as a per-route FastAPI dependency,
`rate_limit_middleware` as whole-app ASGI middleware that classifies each request with
`classify`, and `RateLimiter` called directly for a limit a route decides on itself, such
as counting only failed logins.
"""

from __future__ import annotations

import logging
import math
import time
from collections.abc import Awaitable, Callable, Collection, Sequence
from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING, Any, Final, Literal, TypeAlias

from webbpulse.dynamodb import Repository
from webbpulse.messages import rate_limited

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import Request
    from starlette.responses import Response

__all__ = [
    "RATE_LIMIT_TABLE",
    "TTL_ATTRIBUTE",
    "Anchor",
    "LimitClass",
    "RateLimitDecision",
    "RateLimiter",
    "classify",
    "default_renderer",
    "identity_from_ip",
    "rate_limit",
    "rate_limit_headers",
    "rate_limit_middleware",
]

_log = logging.getLogger(__name__)

RATE_LIMIT_TABLE: Final = "rate-limits"

TTL_ATTRIBUTE: Final = "expires_at"

_TTL_GRACE_SECONDS: Final = 60

type Anchor = Literal["clock", "first_request"]


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
        **kwargs: Any,
    ) -> None:
        """Build a limiter whose `namespace` separates limits sharing the table.

        A login limit and a search limit on the same IP are independent counters.
        `count_attribute` names the counter attribute, for a table already holding rows
        written under another name.
        """
        super().__init__(**kwargs)
        self.namespace = namespace
        self.anchor: Anchor = anchor
        self.count_attribute = count_attribute

    def _key(self, identity: str, window_start: int | None = None) -> str:
        """The partition key for one identity in this namespace.

        A clock-anchored key carries the window start, so the row is immutable within the
        window; a first-request key does not, because the one row carries the window.
        """
        if window_start is None:
            return f"{self.namespace}#{identity}"
        return f"{self.namespace}#{identity}#{window_start}"

    def _failed_open(
        self,
        operation: str,
        exc: BaseException,
        *,
        limit: int,
        window_seconds: int,
        reset_after: int,
    ) -> RateLimitDecision:
        """Log one fail-open WARNING and return the decision that allows the request."""
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
        from botocore.exceptions import ClientError

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
        except ClientError as exc:
            if _error_code(exc) != "ConditionalCheckFailedException":
                return self._failed_open(
                    "check", exc, limit=limit, window_seconds=window_seconds, reset_after=window_seconds
                )
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
        Failures are swallowed and logged, like every other limiter call.
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


def _error_code(error: Any) -> str:
    """The AWS error code, read defensively so a malformed response yields ""."""
    response = getattr(error, "response", None)
    if not isinstance(response, dict):
        return ""
    return str(response.get("Error", {}).get("Code", ""))


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
    """The package's own 429: the detailed error envelope plus the RateLimit headers."""
    from starlette.responses import JSONResponse

    headers = {**rate_limit_headers(decision), "Retry-After": str(decision.reset_after)}
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests. Try again later."},
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
            limit_class = classify(request.method, request.url.path, classes)
        except LookupError:
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
        request.state.rate_limit_decision = decision

        if not decision.allowed:
            _log.warning(
                "Rate limit exceeded.",
                extra={
                    "rate_limit_exceeded": True,
                    "rate_limit_class": limit_class.name,
                    "rate_limit_reset_after": decision.reset_after,
                },
            )
            rendered = resolved_renderer(decision)
            assert isinstance(rendered, StarletteResponse)
            return rendered

        response = await call_next(request)
        if not decision.failed_open:
            response.headers.update(rate_limit_headers(decision))
        return response

    return middleware
