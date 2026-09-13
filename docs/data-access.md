# Data access and rate limiting

The DynamoDB repository base and the shared rate limiter. Back to the
[README](../README.md).

## `webbpulse.dynamodb`

A thin repository base over one table, plus the helpers every service was reimplementing.

```python
from webbpulse.dynamodb import Repository


class Posts(Repository):
    logical_name = "posts"

    def by_author(self, author_id: str) -> list[dict]:
        return list(self.iter_query(Key("pk").eq(f"author#{author_id}")))
```

`table_name("posts")` prefixes the logical name from `DYNAMODB_TABLE_PREFIX`, giving
`webbpulse-staging-posts`, which is what the Terraform `dynamodb-tables` module creates. The
boto3 resource is cached per process and created on first use, never at import.

`query` returns a `Page` carrying `items`, `last_evaluated_key`, `count` and `has_more`.
An empty `items` list with a non-`None` cursor is normal and does **not** mean no results,
which is the pagination bug every hand-rolled loop eventually has; `iter_query` follows
`LastEvaluatedKey` across pages so callers need not get it right.

`encode_numbers` recursively converts `float` to `Decimal` via `str`, because boto3 refuses
a float outright and going through `str` avoids the binary float error that `Decimal(0.1)`
carries. `ttl_at(datetime)` and `ttl_in(seconds)` produce the integer epoch **seconds** a
TTL attribute needs; milliseconds are the classic mistake and put expiry fifty thousand
years out. A TTL is a storage reclaim mechanism on DynamoDB's own schedule, never an access
control.

`DynamoError` and its three subclasses `ItemNotFound`, `ConditionFailed` and
`TransactionCanceled` are the vocabulary a repository raises once it has translated a botocore
`ClientError`. Each records what an operator needs on the exception and nothing a response
body should carry: the table and key, the condition expression, the cancellation reasons.
`TransactionCanceled.conditional_check_failed` is the one decision worth not guessing at,
since a cancellation caused by a failed condition is an ordinary lost race and every other
cause is a real fault. `webbpulse.http.install_dynamodb_error_handlers` renders all three,
and [error-handlers.md](error-handlers.md#the-packages-own-dynamodb-exception-types) has the mapping.

## `webbpulse.ratelimit`

Per-identity fixed window counting on one `<prefix>-rate-limits` table, partition key `pk`,
with a TTL. Three bindings share that counter.

**Per route**, as a FastAPI dependency, where a login route and a read route want very
different ceilings:

```python
from fastapi import Depends
from webbpulse.ratelimit import rate_limit

@router.post(
    "/login",
    dependencies=[Depends(rate_limit(limit=10, window_seconds=900, namespace="login"))],
)
async def login(...): ...
```

**Whole app**, as middleware over a sequence of `LimitClass` values. `classify` picks the
first class a request matches, so the narrow classes go first and a catch-all goes last:

```python
from webbpulse.ratelimit import LimitClass, rate_limit_middleware

CLASSES = [
    LimitClass(name="get", limit=60, window_seconds=60, methods=("GET",)),
    LimitClass(
        name="auth",
        limit=5,
        window_seconds=60,
        path_prefixes=("/api/auth",),
        exempt_paths=("/api/auth/refresh", "/api/auth/logout"),
    ),
    LimitClass(name="default", limit=30, window_seconds=60),
]

app.middleware("http")(
    rate_limit_middleware(CLASSES, exempt_paths=("/", "/health"), exempt_prefixes=("/docs",))
)
```

Each class counts in its own row, namespaced by its name, so a page's read fanout cannot
spend the allowance guarding credential endpoints. A class's `exempt_paths` falls through to
the next class; the middleware's `exempt_paths` (matched exactly, so `"/"` exempts only
itself) and `exempt_prefixes` (matched by subtree) skip counting altogether, as does every
method in `exempt_methods`, `OPTIONS` by default. `enabled` is consulted per request for a
product that gates on its own settings flag.

**Directly**, calling `RateLimiter` where a route decides for itself what counts. A login
lockout counts only failures and forgets them on success:

```python
from webbpulse.ratelimit import RateLimiter

limiter = RateLimiter(namespace="login", anchor="first_request", count_attribute="failures")

if not verified:
    decision = limiter.check(ip, limit=5, window_seconds=900)
else:
    limiter.clear(ip)
```

### Windows and anchors

`anchor="clock"`, the default, derives the window from the clock, `floor(now / window) * window`,
so the item key carries the window start and a new window is a new item rather than a mutation.
Counting is a single atomic `ADD count :one` with a conditional `SET` of the TTL, so two
concurrent requests in different execution environments cannot both read 9 and write 10. That
is one write per check, which is what makes it right for the per-request path.

`anchor="first_request"` keeps one row per identity whose window opens on the first counted
request and closes when its TTL passes. It costs a conditional update plus, on the rollover, a
put. Use it where the anchor is the point, as a login lockout's is: the window should run from
the first failure, not from whenever the clock happens to tick over.

A rejected request still counts under both, which stops a caller holding the counter at exactly
the limit. The honest trade of a fixed window is the boundary: a caller can send `limit`
requests at the end of one window and `limit` more at the start of the next. A sliding log fixes
that and costs a read plus an unbounded item; for protecting a login route the fixed window is
the right guarantee at one write per request.

`clear` forgets a counter. A first-request limiter holds one row per identity and needs nothing
else; a clock-anchored one needs `window_seconds` to name the row, and without it the call
warns and does nothing rather than silently missing.

### Failing open

**It fails open.** Every boto3 error is caught, logged at WARNING with
`rate_limit_failed_open=True`, and the request is allowed. A rate limiter is a protective
control, not an authorisation control: if DynamoDB is unavailable, refusing every request
turns a dependency blip into a full outage, which is strictly worse than briefly not
enforcing a limit. The WARNING is the compensating control, so alarm on it, because a
limiter that has been failing open for a week is invisible otherwise. Anything that must
deny on failure is authorisation and does not belong here. A failed-open response carries no
RateLimit headers, so a quota is never advertised from a limiter that is not enforcing one.

### Refusals and headers

Responses carry the current IETF draft fields. `draft-ietf-httpapi-ratelimit-headers`
dropped the old `RateLimit-Limit` / `RateLimit-Remaining` / `RateLimit-Reset` triple at
draft-08 in favour of two RFC 9651 structured fields, and draft-11 of 23 May 2026 defines
only those:

```http
RateLimit: "default";r=4;t=30
RateLimit-Policy: "default";q=10;w=60
```

`r` is the remaining quota, `t` the seconds until reset, `q` the quota and `w` the window.
The `X-RateLimit-*` triple is emitted alongside because that is what most clients actually
parse; the draft mentions it only as a survey of existing practice.

The middleware's 429 body comes from `renderer`, defaulting to `default_renderer`, which
emits `{"detail": ...}` plus `Retry-After` and the headers above. Pass a product's own
renderer to keep an envelope its live clients already parse; a renderer owns the whole
refusal, headers included.
