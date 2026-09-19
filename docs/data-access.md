# Data access and rate limiting

The DynamoDB repository base, presigned S3 uploads, the application secrets wrapper and the
shared rate limiter. Back to the
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
cause is a real fault. `UnprocessedItems` joins them for a batch that stayed incomplete after
the retry cap. `webbpulse.http.install_dynamodb_error_handlers` renders all four, and
[error-handlers.md](error-handlers.md#the-packages-own-dynamodb-exception-types) has the mapping.

### Conditional writes

`put`, `update` and `delete` each take a `condition`, and a condition that does not hold
raises `ConditionFailed` rather than a botocore `ClientError`:

```python
from boto3.dynamodb.conditions import Attr
from webbpulse.dynamodb import ConditionFailed

try:
    repo.put(item, condition=Attr("pk").not_exists())
except ConditionFailed:
    raise HTTPException(status_code=409, detail="that slug is taken")
```

Only `ConditionalCheckFailedException` is translated. Every other error code is re-raised
untouched, because a throttle or an access denial is a fault and must not reach the caller as
a 409. The original `ClientError` stays on `__cause__`, so nothing about the failure is lost.
The exception records the table, the rendered condition expression and, where the call had
one, the key it guarded, all for the log rather than the response body.

This is what makes a lost uniqueness race a 409 through `install_dynamodb_error_handlers`
without every product writing the same `except ClientError` decode around every conditional
write.

### Partial updates

`set_attributes(key, attributes)` SETs each named attribute in one `update_item`, returning
the stored item:

```python
user = repo.set_attributes({"id": user_id}, {"name": "Ada", "status": "active"})
```

Every attribute name is aliased whether or not it looks reserved, because DynamoDB's reserved
word list runs to hundreds of ordinary words such as `name`, `status` and `size`, and an
expression naming one directly fails at runtime rather than in review.

The aliases live in a `#set{index}` namespace, which is the part worth not hand-rolling. A
caller that numbers its own aliases `#n0`, `#n1` collides with boto3: rendering an `Attr`
condition mints placeholders from the same `#n0` counter, the two name maps are merged into
one request, the later definition wins, and the update silently writes to the attribute the
condition named instead of the one the caller asked for. A conditional partial update is
therefore safe to express here:

```python
repo.set_attributes({"id": user_id}, {"name": "Ada"}, condition=Attr("state").eq("locked"))
```

An empty mapping is a no-op returning `None`, since DynamoDB rejects an empty
`UpdateExpression`. A failing condition raises `ConditionFailed`.

### Removing attributes

`remove_attributes(key, names)` is the counterpart, and what a sparse index needs:

```python
repo.remove_attributes({"pk": f"user#{user_id}", "sk": f"issue#{issue_id}"}, ["unread_at"])
```

A sparse global secondary index holds only the items carrying its key attribute, so an item
leaves one by having that attribute **deleted**. Setting it to null or to an empty string
keeps the item in the index and keeps it in every query that reads it, which is the bug this
exists to stop: an "unread" index a read never empties. Aliasing follows `set_attributes`, in
its own `#rm{index}` namespace, so a conditional removal cannot collide with the placeholders
boto3 mints for an `Attr` condition either.

Removing an attribute the item does not carry is not an error, since `REMOVE` on an absent
attribute is a no-op to DynamoDB, which makes the call idempotent and a redelivered message
harmless. An empty sequence is a no-op returning `None`, a repeated name is sent once because
DynamoDB refuses an expression naming one path twice, and a failing condition raises
`ConditionFailed`.

### Counters

`increment(key, attribute, by=1)` adds to a numeric attribute and returns what it now holds,
in one `update_item` with `ADD` and `UPDATED_NEW`:

```python
number = repo.increment({"pk": "issue-key#WEB"}, "next")
```

`ADD` treats an absent item and an absent attribute as zero, so a counter needs no seeding.
The number handed back belongs to this caller alone, which makes the helper an allocator
rather than a reading: the read-modify-write a caller would otherwise write loses increments
the moment two requests overlap. Nothing rolls an allocation back, so a caller that fails
after allocating leaves a gap and the sequence is gap-tolerant, not gap-free. A gap-free
sequence costs a lock, and an issue key does not need one. `by` may be negative, which
decrements; zero is a `ValueError` rather than a silent no-op.

### Sortable ids

`new_ulid()` returns 26 Crockford base32 characters whose first 48 bits are the millisecond
timestamp and whose remaining 80 are random, so string ordering is time ordering:

```python
repo.put({"pk": f"org#{org_id}", "sk": f"event#{new_ulid()}", ...})
```

That is what a UUID4 sort key cannot do, and it is why a range key built from a ULID needs no
separate timestamp attribute to sort on. Two ids minted in the same millisecond still differ.
It is implemented in the package rather than pulled from a `ulid` dependency, since the whole
encoding is a dozen lines. Passing a naive datetime is a `ValueError`, the way `ttl_at`
rejects one.

### Idempotency

`IdempotencyStore` wraps a repository and turns a key into a one-shot claim, so a redelivered
message does the work exactly once:

```python
store = IdempotencyStore(Repository("claims"))
if not store.claim(f"order#{message_id}", ttl_seconds=86_400):
    return
```

`claim` is a conditional put on the key's absence: the first caller is told `True` and every
later one `False`, which is the whole decision a handler needs when SQS, EventBridge or a
payment webhook delivers twice. The claim carries a TTL, so the table forgets a key once
replays stop being plausible rather than growing forever; size `ttl_seconds` past the longest
retry the producer will make, because a delivery arriving after expiry is processed again. A
winner that then crashes has still claimed the key, so this makes a duplicate a no-op and not
a job a second worker picks up — `release(key)` is there for a handler that failed after
claiming and wants the retry to proceed rather than wait out the TTL. The key, TTL and
timestamp attribute names are all configurable. `webbpulse.testing.FakeIdempotencyStore` is
the in-process stand-in, and it evaluates expiry on read so a test need not sleep.

### Read-only repositories

A function whose IAM policy grants only reads on a table should fail the same way in a unit
test as it would in staging. `read_only=True` makes every write raise `ReadOnlyTable`
before a client is built:

```python
from webbpulse.dynamodb import ReadOnlyTable, Repository

users = Repository(
    "users",
    read_only=True,
    read_only_hint="Move it from read_tables to tables in terraform/lambda_domains.tf.",
)

users.get({"pk": "user#1"})       # reads pass through
users.put({"pk": "user#1"})       # raises ReadOnlyTable
```

The message names the table and the refused method, and appends `read_only_hint` when the
caller supplied one, so the error can point at the registry entry and the Terraform grant
that have to move together. `ReadOnlyTable` is a `PermissionError` and not a
`DynamoError`, so a broad data-layer handler cannot swallow it.

The guarded names are `WRITE_METHODS`, and the guard is installed on `Repository` itself,
so a product subclass inherits it. The package's own suite classifies every public method
on the class as a read or a write, so a new write method added to `Repository` without
being listed fails that test rather than silently escaping the guard. The refusal happens
before the table resource is resolved, so a read-only repository needs no credentials to
refuse.

### Scanning

`scan` returns the same `Page` as `query`, and `iter_scan` follows `LastEvaluatedKey` the
way `iter_query` does, so neither caller hand-rolls the paging loop:

```python
for item in repo.iter_scan(FilterExpression=Attr("state").eq("open"), max_items=500):
    ...
```

`max_items` stops the walk once that many items have been yielded, which is what makes an
unbounded scan safe to expose. A parallel scan passes `segment` and `total_segments`; giving
one without the other is a `ValueError` rather than a silently partial result.

### Batch reads

`batch_get(keys)` reads up to `BATCH_GET_LIMIT` (100) keys per request and chunks anything
larger. DynamoDB load-sheds by returning `UnprocessedKeys` instead of failing, so the
outstanding keys are retried with exponential backoff from `UNPROCESSED_RETRY_BASE_DELAY`,
and only the outstanding ones are resent. The retry count is capped at
`UNPROCESSED_RETRY_ATTEMPTS` (5, overridable per call with `max_attempts`); once it is
exhausted the call raises `UnprocessedItems` carrying the table, the number of keys still
outstanding and the attempts made. A `while UnprocessedKeys:` loop with no cap is a hang
under sustained throttling, not a slow success, which is why the cap is not optional. Behind
`install_dynamodb_error_handlers` that exception renders as a 503 with `Retry-After` rather
than an opaque 500, because shed load is transient and worth retrying.

Results come back in no particular order, and a key with no item is simply absent rather
than being an error, because a batch read is a lookup and not an assertion.

`get_many(ids)` sits on top of it for the common case of a table keyed on one attribute,
returning the items keyed by that id:

```python
users = users_repo.get_many([m.user_id for m in memberships])
```

It adds the two things a caller otherwise redoes at every call site: de-duplicating the ids,
since `BatchGetItem` rejects a request naming the same key twice, and pairing each item back
to the id that asked for it, since the response comes back unordered. A missing id is omitted
from the result the way `get` answers `None`, and blank ids are dropped rather than sent,
since DynamoDB rejects an empty key attribute. `key_attribute` names the key when it is not
`id`. A composite-key table has no single id to key the result by, so use `batch_get` there.

### Transactions

`transact_write(actions)` applies up to `TRANSACT_WRITE_LIMIT` (100) actions as one
all-or-nothing `TransactWriteItems`. `put_action`, `delete_action`, `update_action` and
`condition_check` build the actions, each optionally taking a `condition`:

```python
repo.transact_write(
    [
        repo.put_action(item, condition=Attr("pk").not_exists()),
        repo.condition_check({"pk": "quota#acct-1"}, condition=Attr("used").lt(100)),
    ],
    client_request_token=request_id,
)
```

A `boto3.dynamodb.conditions` object is rendered into an expression string with its
placeholder maps **inside** the action. That matters: handing a condition object straight to
the low-level client makes boto3 hoist `ExpressionAttributeNames` and
`ExpressionAttributeValues` to the top of the request, which the API rejects. A condition
that is already a string is passed through.

An empty action list is a no-op, so a caller that assembled actions conditionally need not
check. `client_request_token` makes a retry idempotent for ten minutes. A cancellation
raises `TransactionCanceled` with its `CancellationReasons`, and
`conditional_check_failed` separates the ordinary lost race from a real fault.

## `webbpulse.storage`

`presigned_put` mints a URL a browser PUTs an object to directly, so a file never travels
through a Lambda that would have to buffer it and pay for the time:

```python
from webbpulse.storage import presigned_put

upload = presigned_put(
    bucket=settings.uploads_bucket,
    key=f"avatars/{user_id}.png",
    content_type="image/png",
    max_bytes=2 * 1024 * 1024,
)
return {"url": upload.url, "headers": upload.headers}
```

The content type and the ceiling go **into** the signature as `ContentType` and
`ContentLength`, which is the whole point. An unbounded presigned PUT lets whoever holds the
URL store an object of any size and any type under a key the application will later serve,
and neither a check in the frontend nor a check after the upload prevents it. Because the
guard is signed, S3 rejects a request that declares anything else with a 403 at the header
rather than after the body, so the ceiling costs no transfer. It is a ceiling the client
declares, not a byte count S3 measures.

`PresignedUpload` is frozen and carries `url`, `headers`, `bucket`, `key`, `max_bytes` and
`expires_in`, so a route hands the whole thing to the frontend and repeats nothing. The
headers are not advisory: a client that omits or changes one is refused. `expires_in`
defaults to `DEFAULT_EXPIRES_IN` (900 seconds) and is capped at SigV4's own seven-day
`MAX_EXPIRES_IN`; anything outside 1 to that is a `ValueError` before signing, as are an
empty bucket, key or content type and a non-positive `max_bytes`. The client is cached per
region and endpoint with `s3v4` pinned, since a URL signed with v2 is rejected outright in
newer regions. `webbpulse.testing.FakePresigner` records what it was asked to sign, which is
the assertion worth making.

`presigned_get` is the reading half, so a private bucket stays private and a browser still
fetches the object directly:

```python
from webbpulse.storage import presigned_get

download = presigned_get(
    bucket=settings.uploads_bucket,
    key=f"avatars/{user_id}.png",
    response_content_disposition='attachment; filename="avatar.png"',
)
return {"url": download.url}
```

`response_content_type` and `response_content_disposition` are optional and go into the
signature as `ResponseContentType` and `ResponseContentDisposition`, so S3 returns them with
the object and a holder of the URL cannot change them. Omit one and S3 serves the stored
metadata; passing either as an empty string is a `ValueError`, as are an empty bucket or key
and an `expires_in` outside 1 to `MAX_EXPIRES_IN`. `PresignedDownload` is frozen and carries
`url`, `bucket`, `key` and `expires_in`. The URL is a bearer credential for that one key until
it expires, so keep the window short and keep it out of logs.

### What an upload may be, and how it comes back

`UPLOAD_CONTENT_TYPES` is the allow list a declared type is checked against before anything
is signed, and `disposition_for` decides whether the download renders or saves:

```python
from webbpulse.storage import disposition_for, is_allowed_upload, presigned_get, presigned_put

if not is_allowed_upload(content_type):
    raise HTTPException(status_code=415, detail="that file type is not accepted")

upload = presigned_put(bucket, key, content_type, max_bytes=10 * 1024 * 1024)
...
download = presigned_get(
    bucket,
    key,
    response_content_type=attachment.content_type,
    response_content_disposition=disposition_for(attachment.content_type, attachment.filename),
)
```

The check belongs **before** the signing, not after the object lands: the type goes into the
signature, so refusing it here is what keeps the object from existing, while a check
afterwards is a check on something already stored under a key the application will serve.

It is an allow list because a deny list is a list of the attacks already thought of. The list
covers the common image types, PDF, plain text, CSV, JSON, zip and the six Office types in
both the legacy and the OOXML spellings, since a browser sends whichever one the source
application stamped on the file. What is absent is the point: `text/html`, because an HTML
attachment served from the application's own origin is stored cross-site scripting and no
downstream check makes it safe, and `application/octet-stream`, because it is what a browser
sends when it recognises nothing, so admitting it admits everything and the list stops meaning
anything. A type may still *declare* something the bytes are not, which is a separate control:
this stops an object the application will later serve as HTML, not a PNG that is really
something else.

`disposition_for(content_type, filename)` answers `inline` for the types in
`INLINE_CONTENT_TYPES`, the handful a browser displays natively, and `attachment` for
everything else. Defaulting to `attachment` is what makes an unrecognised type safe, since a
downloaded file is inert while an inline one renders in the application's origin.
`image/svg+xml` is an allowed upload and never an inline one, because an SVG is scripted
markup.

The filename is quoted per RFC 6266. An ASCII name is a quoted string with its quotes
escaped, so a name carrying one cannot close the parameter and inject another; a name that is
not ASCII is sent twice, a transliterated `filename` for a legacy client and the RFC 5987
`filename*` carrying the real UTF-8 name, which every current browser prefers. Any directory
separator and any control character is stripped, since the filename is a display name and a
header value, never a path, and a name with nothing left becomes `download` so the header is
always well formed.

Needs the `dynamodb` extra, which is where boto3 already lives.

## `webbpulse.security` application secrets

One JSON secret per service per environment, named by `APP_SECRETS_ARN`, read once per
process and flattened to a map of strings:

```python
from webbpulse.security import apply_app_secrets

settings = Settings()
apply_app_secrets(settings)
```

`app_secrets()` returns the flat map. `flatten_secret` keeps a string as it is and JSON
encodes anything else, so a list or an object survives a round trip through an environment
variable; a `null` is dropped, which is how a secret marks a key absent. `load_app_secrets`
exports every key into `os.environ` (`override=False` lets a locally set value win).
`apply_app_secrets` does that and also assigns each key that matches a settings field,
validated against the field's annotation first, so a malformed secret fails at startup
rather than at the first use of the value. Field matching is case-insensitive, and a key
with no matching field reaches the environment only, since a secret may carry values other
consumers read.

Nothing is fetched at import, so a function touching no secret needs no
`secretsmanager:GetSecretValue` grant. Key names are logged at INFO, which is what makes a
missing one diagnosable; values never are. `reset_secret_cache()` clears this cache and the
parsed one in `webbpulse.config` together, since one is derived from the other.

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
    rate_limit_middleware(
        CLASSES,
        exempt_paths=("/", "/health"),
        exempt_prefixes=("/docs",),
        enabled=lambda: get_settings().rate_limiting_enabled,
    )
)
```

`enabled` is the environment convention from `webbpulse.config`: staging never rate limits,
because the access gate already decides who reaches it and the full e2e suite runs there at
full speed, and every other environment does. Every limiter a service has, the login failure
counter included, reads the same property so one environment name turns all of them off.

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
emits `{"detail": ...}` plus `Retry-After` and the headers above. Its sentence comes from
`webbpulse.messages.rate_limited`, carrying the same wait the header does, so every refusal
in the package words itself once. Pass a product's own renderer to keep an envelope its live
clients already parse; a renderer owns the whole refusal, headers included.
