# Data access and rate limiting

The DynamoDB repository base and the per-route rate limiter. Back to the
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
with a TTL. One `UpdateItem` per request and no read before the write:

```python
from fastapi import Depends
from webbpulse.ratelimit import rate_limit

@router.post(
    "/login",
    dependencies=[Depends(rate_limit(limit=10, window_seconds=900, namespace="login"))],
)
async def login(...): ...
```

Per route, which is the point: a login route and a read route want very different ceilings,
and a global middleware cannot express that without a table of path patterns. `namespace`
keeps limits that share the table independent.

The window comes from the clock, `floor(now / window) * window`, so the item key carries the
window start and a new window is a new item rather than a mutation. Counting is a single
atomic `ADD count :one` with a conditional `SET` of the TTL, so two concurrent requests in
different execution environments cannot both read 9 and write 10. A rejected request still
counts, which stops a caller holding the counter at exactly the limit. The honest trade of a
fixed window is the boundary: a caller can send `limit` requests at the end of one window and
`limit` more at the start of the next. A sliding log fixes that and costs a read plus an
unbounded item; for protecting a login route the fixed window is the right guarantee at one
write per request.

**It fails open.** Every boto3 error is caught, logged at WARNING with
`rate_limit_failed_open=True`, and the request is allowed. A rate limiter is a protective
control, not an authorisation control: if DynamoDB is unavailable, refusing every request
turns a dependency blip into a full outage, which is strictly worse than briefly not
enforcing a limit. The WARNING is the compensating control, so alarm on it, because a
limiter that has been failing open for a week is invisible otherwise. Anything that must
deny on failure is authorisation and does not belong here.

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
