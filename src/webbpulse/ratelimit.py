"""Per-identity fixed-window rate limiting on one DynamoDB table.

One table per environment, `<prefix>-rate-limits`, partition key `pk` (string), holding a
counter and a TTL. One `UpdateItem` per request, no read before the write.

## The algorithm

A fixed window, not a sliding log. The window a request falls into is computed from the
clock (`floor(now / window) * window`), so the item key carries the window start and a new
window is a new item rather than a mutation of the old one. Counting is a single
`ADD count :one` with a conditional `SET` of the TTL, which is atomic on DynamoDB's side, so
two concurrent requests in different execution environments cannot both read 9 and write 10.

The honest trade of a fixed window is the boundary: a caller can send `limit` requests in
the last instant of one window and `limit` more in the first instant of the next, so the
worst case over a sliding window of the same length is twice the limit. A sliding log fixes
that and costs a read plus an unbounded item. For protecting a login route or an expensive
endpoint from abuse, the fixed window's guarantee is the right one, and it is one write per
request instead of a read plus a write.

## Fail open, deliberately

Every boto3 error is caught, logged at WARNING with `rate_limit_failed_open=True`, and the
request is allowed. A rate limiter is a protective control, not an authorisation control:
if DynamoDB is unavailable, refusing every request converts a dependency blip into a full
outage of the service, which is a strictly worse failure than briefly not enforcing a limit.
Anything that must deny on failure is authorisation and does not belong here.

The WARNING is the compensating control. Alarm on it: a limiter that has been failing open
for a week is invisible otherwise, and that is the state in which it is not protecting
anything at all.

## The table

Terraform creates it as part of the `dynamodb-tables` module::

    rate-limits = {
      hash_key       = "pk"
      attributes     = [{ name = "pk", type = "S" }]
      ttl_attribute  = "expires_at"
      billing_mode   = "PAY_PER_REQUEST"
    }

TTL is what keeps the table from growing without bound. DynamoDB deletes expired items on
its own schedule, typically within a couple of days, so the code never relies on an expired
item being gone: an item whose window has passed is simply a different key.
"""

from __future__ import annotations

import logging
import math
import time
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, Final

from webbpulse.dynamodb import Repository

if TYPE_CHECKING:  # pragma: no cover - typing only
    from fastapi import Request

__all__ = [
    "RATE_LIMIT_TABLE",
    "RateLimitDecision",
    "RateLimiter",
    "identity_from_ip",
    "rate_limit",
    "rate_limit_headers",
]

_log = logging.getLogger(__name__)

#: Logical table name. `webbpulse.dynamodb.table_name` prefixes it per environment.
RATE_LIMIT_TABLE: Final = "rate-limits"

#: TTL attribute on the table. Epoch seconds, as DynamoDB requires.
TTL_ATTRIBUTE: Final = "expires_at"

#: How long past the window end an item is kept before TTL may reclaim it. A small buffer
#: keeps an item alive through clock skew between the writer and DynamoDB's reaper.
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
        self.allowed = allowed
        self.limit = limit
        self.remaining = remaining
        self.reset_after = reset_after
        self.window_seconds = window_seconds
        self.failed_open = failed_open

    def __repr__(self) -> str:
        return (
            f"RateLimitDecision(allowed={self.allowed}, limit={self.limit}, "
            f"remaining={self.remaining}, reset_after={self.reset_after}, "
            f"failed_open={self.failed_open})"
        )


def rate_limit_headers(
    decision: RateLimitDecision, *, policy_name: str = "default"
) -> dict[str, str]:
    """Response headers describing the limit.

    Two styles are emitted, on purpose.

    The IETF draft `draft-ietf-httpapi-ratelimit-headers` **replaced** the older
    `RateLimit-Limit` / `RateLimit-Remaining` / `RateLimit-Reset` triple at draft-07 with two
    structured fields, and the current draft (-11) defines only those::

        RateLimit: "default";r=50;t=30
        RateLimit-Policy: "default";q=100;w=60

    `r` is the remaining quota, `t` the seconds until the window resets, `q` the quota and
    `w` the window length. Emitting the abandoned triple as the standards-track answer would
    be implementing something the draft no longer contains, so this returns the current
    fields. The `X-RateLimit-*` set is emitted alongside because that is what most existing
    clients and libraries actually parse; it has never been standardised, but it is the
    pragmatic compatibility surface and it costs three headers.
    """
    remaining = max(decision.remaining, 0)
    return {
        "RateLimit": f'"{policy_name}";r={remaining};t={decision.reset_after}',
        "RateLimit-Policy": f'"{policy_name}";q={decision.limit};w={decision.window_seconds}',
        "X-RateLimit-Limit": str(decision.limit),
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Reset": str(decision.reset_after),
    }


def identity_from_ip(request: Request) -> str:
    """Default identity: the API Gateway source IP. See `webbpulse.http.client_ip`."""
    from webbpulse.http import client_ip

    return client_ip(request)


class RateLimiter(Repository):
    """Fixed-window counter over the `<prefix>-rate-limits` table."""

    logical_name = RATE_LIMIT_TABLE

    def __init__(self, *, namespace: str = "default", **kwargs: Any) -> None:
        """`namespace` separates limits that share the table, so a login limit and a search
        limit on the same IP are independent counters."""
        super().__init__(**kwargs)
        self.namespace = namespace

    def _key(self, identity: str, window_start: int) -> str:
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

        One `UpdateItem`. The counter is incremented before the decision is made, so a
        rejected request still counts: that is what stops a caller from holding the counter
        at exactly the limit by continuing to send requests that are refused.
        """
        current = time.time() if now is None else now
        window_start = int(math.floor(current / window_seconds) * window_seconds)
        window_end = window_start + window_seconds
        reset_after = max(math.ceil(window_end - current), 0)

        try:
            attributes = self.update(
                {"pk": self._key(identity, window_start)},
                # ADD creates the attribute at zero and increments it when it is absent,
                # which is what makes the first request of a window a single write with no
                # read and no conditional retry.
                update_expression="ADD #c :one SET #ttl = if_not_exists(#ttl, :ttl)",
                expression_names={"#c": "count", "#ttl": TTL_ATTRIBUTE},
                expression_values={":one": 1, ":ttl": window_end + _TTL_GRACE_SECONDS},
                return_values="UPDATED_NEW",
            )
        except Exception as exc:  # Fail open on anything boto3 raises. See below.
            # Deliberately broad. botocore raises ClientError, EndpointConnectionError,
            # NoCredentialsError, ReadTimeoutError and more from different base classes, and
            # the correct response to every one of them is the same: allow the request and
            # make the failure visible.
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
    """Build a FastAPI dependency that enforces one limit.

    Used per route, which is the point: a login route and a read route want very different
    ceilings, and a global middleware cannot express that without a table of path patterns::

        @router.post(
            "/login",
            dependencies=[Depends(rate_limit(limit=10, window_seconds=900, namespace="login"))],
        )
        async def login(...): ...

    On rejection it raises `HTTPException(429)` carrying `Retry-After` and the RateLimit
    headers. On success the headers are attached to the response through `request.state`, so
    a caller can see its remaining quota before it runs out; wire that with
    `RateLimitHeaderMiddleware` or read `request.state.rate_limit_headers` in the route.

    The limiter is constructed once when the dependency is built, not per request, so the
    cached DynamoDB table resource is reused.
    """
    from fastapi import HTTPException
    from fastapi import Request as _Request

    resolved = limiter if limiter is not None else RateLimiter(namespace=namespace)

    async def dependency(request: _Request) -> RateLimitDecision:
        identity = key_fn(request)
        if isinstance(identity, Awaitable):
            identity = await identity

        decision = resolved.check(identity, limit=limit, window_seconds=window_seconds)
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
