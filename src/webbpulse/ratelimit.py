"""Per-identity fixed-window rate limiting on one DynamoDB table.

One `UpdateItem` per request against `<prefix>-rate-limits`, with the window start in the
key and a TTL to reclaim it. Every boto3 error fails open and logs at WARNING with
`rate_limit_failed_open=True`, which is the signal to alarm on.
"""

from __future__ import annotations

import logging
import math
import time
from collections.abc import Awaitable, Callable
from functools import partial
from typing import TYPE_CHECKING, Any, Final, TypeAlias

from webbpulse.dynamodb import Repository

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import Request

__all__ = [
    "RATE_LIMIT_TABLE",
    "TTL_ATTRIBUTE",
    "RateLimitDecision",
    "RateLimiter",
    "identity_from_ip",
    "rate_limit",
    "rate_limit_headers",
]

_log = logging.getLogger(__name__)

RATE_LIMIT_TABLE: Final = "rate-limits"

TTL_ATTRIBUTE: Final = "expires_at"

_TTL_GRACE_SECONDS: Final = 60


class RateLimitDecision:
    """The outcome of one limiter check."""

    __slots__ = ("allowed", "failed_open", "limit", "remaining", "reset_after", "window_seconds")

    def __init__(
        self,
        *,
        allowed: bool,
        limit: int,
        remaining: int,
        reset_after: int,
        window_seconds: int,
        failed_open: bool = False,
    ) -> None:
        """Record one limiter outcome and the quota state that produced it."""
        self.allowed = allowed
        self.limit = limit
        self.remaining = remaining
        self.reset_after = reset_after
        self.window_seconds = window_seconds
        self.failed_open = failed_open

    def __repr__(self) -> str:
        """Summarise the decision and its quota counters."""
        return (
            f"RateLimitDecision(allowed={self.allowed}, limit={self.limit}, "
            f"remaining={self.remaining}, reset_after={self.reset_after}, "
            f"failed_open={self.failed_open})"
        )


def rate_limit_headers(decision: RateLimitDecision, *, policy_name: str = "default") -> dict[str, str]:
    """Response headers describing the limit, in both header styles.

    The structured `RateLimit` and `RateLimit-Policy` fields are the current IETF draft's,
    and the `X-RateLimit-*` trio is emitted alongside for the clients that parse it.
    """
    remaining = max(decision.remaining, 0)
    return {
        "RateLimit": f'"{policy_name}";r={remaining};t={decision.reset_after}',
        "RateLimit-Policy": f'"{policy_name}";q={decision.limit};w={decision.window_seconds}',
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
    """Fixed-window counter over the `<prefix>-rate-limits` table."""

    logical_name = RATE_LIMIT_TABLE

    def __init__(self, *, namespace: str = "default", **kwargs: Any) -> None:
        """Build a limiter whose `namespace` separates limits sharing the table.

        A login limit and a search limit on the same IP are independent counters.
        """
        super().__init__(**kwargs)
        self.namespace = namespace

    def _key(self, identity: str, window_start: int) -> str:
        """The partition key for one identity in one window of this namespace."""
        return f"{self.namespace}#{identity}#{window_start}"

    def check(
        self,
        identity: str,
        *,
        limit: int,
        window_seconds: int,
        now: float | None = None,
    ) -> RateLimitDecision:
        """Count this request against `identity` and decide whether to allow it.

        One `UpdateItem`, counted before the decision, so a rejected request still counts.
        Any boto3 failure fails open with `failed_open` set on the decision.
        """
        current = time.time() if now is None else now
        window_start = int(math.floor(current / window_seconds) * window_seconds)
        window_end = window_start + window_seconds
        reset_after = max(math.ceil(window_end - current), 0)

        try:
            attributes = self.update(
                {"pk": self._key(identity, window_start)},
                update_expression="ADD #c :one SET #ttl = if_not_exists(#ttl, :ttl)",
                expression_names={"#c": "count", "#ttl": TTL_ATTRIBUTE},
                expression_values={":one": 1, ":ttl": window_end + _TTL_GRACE_SECONDS},
                return_values="UPDATED_NEW",
            )
        except Exception as exc:
            _log.warning(
                "Rate limit check failed; allowing the request.",
                extra={
                    "rate_limit_failed_open": True,
                    "rate_limit_namespace": self.namespace,
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
            )

        count = int((attributes or {}).get("count", 1))
        return RateLimitDecision(
            allowed=count <= limit,
            limit=limit,
            remaining=max(limit - count, 0),
            reset_after=reset_after,
            window_seconds=window_seconds,
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
                detail="Too many requests. Try again later.",
                headers={**headers, "Retry-After": str(decision.reset_after)},
            )
        return decision

    return dependency
