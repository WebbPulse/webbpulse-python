# Error handlers for DynamoDB and custom exceptions

Mapping botocore `ClientError`s, this package's own DynamoDB exceptions, and a service's own
exception types onto the shared envelope. The envelope itself is in [http.md](http.md). Back
to the [README](../README.md).

## DynamoDB errors

Opt in, because it imports botocore and the base install has no boto3. Needs the `dynamodb`
extra:

```python
app = create_app([posts_router], dynamodb_handlers=True)
# or, for an app not built by create_app:
from webbpulse.http import install_dynamodb_handlers

install_dynamodb_handlers(app)
```

A botocore `ClientError` from DynamoDB then renders the envelope instead of becoming an
opaque 500. The mapping is the part that is easy to get wrong per service:

| AWS error code | Status | Why |
| --- | --- | --- |
| `ConditionalCheckFailedException` | 409 | Someone else got there first. A caller visible conflict, and the normal outcome of an optimistic create, not a server fault. |
| `ProvisionedThroughputExceededException`, `ThrottlingException`, `RequestLimitExceeded` | 503 + `Retry-After` | Transient and retryable. A 500 tells a client not to bother retrying. |
| `ResourceNotFoundException` | 500, logged at error | A missing table is a deployment fault, never the caller's. A 404 would send an operator hunting for a missing record instead of a missing table. |
| `TransactionCanceledException` | 409 or 500 | Inspected, not assumed: 409 when any `CancellationReasons` entry is `ConditionalCheckFailed`, 500 otherwise. Treating the whole class as 409 hides real faults; treating it as 500 pages someone for an ordinary lost race. |

Every branch logs with the request id and the AWS error code, and no branch puts AWS error
text in the response body, so the caller's report joins to the CloudWatch line by request id.

## The service's own exception types

Those branches only fire for a botocore `ClientError` that actually reaches a handler. Most
repository layers translate one first, so `ConditionalCheckFailedException` becomes the
service's own `ConditionFailed` and the handler above never sees it. Hand the types over
instead of keeping thin handlers of your own:

```python
from webbpulse.http import ErrorSpec, create_app

app = create_app(
    [posts_router],
    dynamodb_handlers=True,
    exception_map={ItemNotFound: 404, ConditionFailed: 409, TransactionCanceled: 409},
)
```

A value is either a status or an `ErrorSpec` when the message, the code or a `Retry-After`
needs saying explicitly:

```python
exception_map = {
    ItemNotFound: ErrorSpec(404, message="No such post.", error_code="POST_NOT_FOUND"),
    Throttled: ErrorSpec(503, retry_after=1),
}
```

The response is the envelope `error_body` builds for everything else, so dropping your own
handlers changes nothing a caller can see. The details worth knowing:

- `error_code` appears only under `error_codes=True`, including one an `ErrorSpec` names. The
  spec chooses which code, not whether there is one.
- A message the spec does not give defaults to the wording already used for that status. The
  409 and 503 wordings are the ones the botocore branches send, so a mapped `ConditionFailed`
  reads exactly like a `ConditionalCheckFailedException`.
- A mapped status of 500 or above never echoes its message. It logs at error with a stack
  trace and returns the generic "Internal server error.", because a message written for an
  internal exception is not written for a stranger. A mapped 4xx logs at warning, since a
  lost race is the ordinary outcome rather than a page.
- The exception's own text never reaches the body, so a `raise ItemNotFound(f"pk={pk}")` is
  safe to write.
- The mapping is validated when the app is built. A key that is not an exception class or a
  value that is neither an int nor an `ErrorSpec` raises `TypeError`, and a status outside
  100 to 599 raises `ValueError`. A wiring mistake belongs at import, not in a 500 under load.
- `exception_map` needs no extra of its own. Passing it without `dynamodb_handlers=True`
  installs only these handlers and imports no botocore, so a service with no DynamoDB can use
  it on the base install:

  ```python
  from webbpulse.http import register_error_handlers

  register_error_handlers(app, exception_map={ItemNotFound: 404})
  ```

Starlette walks an exception's MRO, so a subclass without its own entry uses the nearest base
class that has one, and a subclass with its own entry wins.

## The package's own DynamoDB exception types

`exception_map` assumes the service already has exception classes to hand over. For one that
does not, `webbpulse.dynamodb` now defines them, so a repository can raise the package's own
types and the handlers come with them:

```python
from webbpulse.dynamodb import ConditionFailed, ItemNotFound, TransactionCanceled

app = create_app([posts_router], dynamodb_error_handlers=True)
# or, for an app not built by create_app:
from webbpulse.http import install_dynamodb_error_handlers

install_dynamodb_error_handlers(app)
```

| Exception | Status | Why |
| --- | --- | --- |
| `ItemNotFound` | 404 | The table and the key are recorded on the exception for the log and never reach the body, because a key can be a user id or an email address. |
| `ConditionFailed` | 409 | A lost race on an optimistic write. The condition expression stays in the log. |
| `TransactionCanceled` | 409 or 500 | Inspected, not assumed: 409 when `conditional_check_failed`, 500 otherwise, matching the botocore branch. |

All three subclass `DynamoError`, so one `except DynamoError` or one `exception_map` entry
covers the hierarchy, and a service's own subclass inherits the nearest handler without
needing an entry. `not_found_message`, `conflict_message` and `internal_error_message` change
the wording without writing a handler.

A service with its own wording passes a `DynamoDBErrorHandlerOptions` in place of `True`,
which both flags forward, so it does not have to drop to the bare installer to configure the
messages:

```python
from webbpulse.http import DynamoDBErrorHandlerOptions, create_app

app = create_app(
    [posts_router],
    dynamodb_error_handlers=DynamoDBErrorHandlerOptions(
        not_found_message="Resource not found",
        internal_error_message="Internal server error",
    ),
)
```

Each field left unset keeps the package default from `DYNAMODB_ERROR_MESSAGES`, so
`DynamoDBErrorHandlerOptions()` is the same as `True`. `internal_error_message` is the wording
the non-conditional `TransactionCanceled` branch renders, which until 0.24.0 was fixed.

This needs no extra. The types are plain exceptions and importing them pulls in no botocore,
which is the difference from `install_dynamodb_handlers`: that one handles the raw
`ClientError` a repository did not translate, this one handles what a repository raises after
translating it. A service doing both can install both, and the two never contend because they
are keyed on different types.

`dynamodb_error_handlers` composes with `error_envelope`, so these responses are the shape the
rest of the application returns rather than a shape of their own.

`RequestIdMiddleware` honours an inbound `X-Request-ID`, mints a UUID4 otherwise, bounds the
length so a hostile header cannot inflate every downstream log line, echoes it on the
response, and sets it on the active span. Read it in a route with `Depends(request_id)`.

`client_ip(request)` is the piece that most needed sharing. It reads the source IP that API
Gateway itself observed, from the `x-amzn-request-context` header the Web Adapter injects,
handling both payload shapes: `requestContext.http.sourceIp` for an HTTP API (format 2.0)
and `requestContext.identity.sourceIp` for a REST API (format 1.0). It never reads
`X-Forwarded-For`. Behind API Gateway the leftmost hop of that header is whatever the client
sent, so limiting on it lets a caller mint a fresh identity per request by varying one
header, which is worse than not limiting at all because it looks like it works. The
per-app version this replaces read `request.scope["aws.event"]`, which Mangum populated and
the Web Adapter does not, so on migration it silently stopped matching and fell through to
the spoofable header with nothing failing.

`health_router` is liveness only and never touches DynamoDB, deliberately. The Web Adapter
polls this path as its readiness check on every cold start, so a health route that queries a
table adds that query to every cold start and makes the function fail to start when the
table is briefly unavailable. Readiness checks that do touch dependencies belong on a path
the adapter does not poll.

`mount_all` is the second composition root:

```python
app = mount_all({"/api/v1/posts": posts_app, "/api/v1/skills": skills_app})
```

Production runs one entrypoint per domain, each importing only its own routers, which keeps
cold starts cheap and one domain's dependencies invisible to another. Local development,
the test suite and a plain `docker run` want the whole surface on one port, and this builds
it from the very same app objects rather than from a second wiring that can drift. Each
mount path must be the prefix API Gateway routes to that domain's function, so a path that
works locally works in production.
