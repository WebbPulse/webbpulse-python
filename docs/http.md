# HTTP: the app factory and the error envelope

`create_app`, the four-field error envelope, and the envelope variants. Error handlers for
DynamoDB and for a service's own exception types are in
[error-handlers.md](error-handlers.md). Back to the [README](../README.md).

## `webbpulse.http`

`create_app` builds one domain's FastAPI application, adding, in the order a request
traverses them: CORS, the request id middleware, the request log, the structured error
handlers, and a `GET /health` route.

```python
from webbpulse.http import create_app

app = create_app([posts_router], service_name="posts", version="1.4.0", settings=settings)
```

CORS origins come from `settings` or an explicit list. When credentials are allowed the
origin list must be exact and never `"*"`: the CORS specification forbids that pair, and it
is the browser that rejects the response, which makes a server misconfiguration look like a
client bug.

Errors all render in one envelope, so a validation failure, an unhandled exception and a
request to a path that does not exist have the same shape, and none of them leaks a stack
trace to the caller:

```json
{"success": false, "status": 422, "message": "...", "request_id": "..."}
```

Those four fields are always present. Starlette's raw 404 and 405 go through the same
handler, so an unmatched route returns the envelope rather than the `{"detail": "Not Found"}`
that the framework would otherwise emit.

Validation errors return only the location and the reason, never the offending input, which
can be a password or a token.

`user_id_dependency` and `bind_user_id` live here too, and they are how a service gets
`user_id` onto its log lines without hitting the sync-dependency trap. See
[the warning in logging-and-metrics.md](logging-and-metrics.md#do-not-call-set_user_id-from-a-sync-def-fastapi-dependency),
which is the shape to read before wiring authentication.

### The route key header

`RequestIdMiddleware` echoes the request id as `X-Request-ID` and the gateway's own matched
`routeKey` as `X-WebbPulse-Route-Key`, on every response in every environment. The key is
read verbatim from the `x-amzn-request-context` header the Lambda Web Adapter forwards, so
it is absent on a local run, where nothing forwards a request context, and absent whenever
the gateway answered before the function ran.

The access log is the other place that says which route key served a request, and it takes
about half a minute to deliver. This header is the same fact on the response itself, which
is what lets the e2e route cut group prove a cut the moment its probe answers. `route_key`
and `request_context` are exported for a service that wants either directly.

### The request log

`create_app` installs `RequestLoggingMiddleware`, which emits one INFO line per request,
named `request`, on the `webbpulse.http` logger:

```json
{"message": "request", "http_method": "GET", "http_path": "/items/{item_id}",
 "http_status": 200, "duration_ms": 12.4, "request_id": "...", "user_id": "..."}
```

`http_path` is the matched route template, not the raw path, so an id in a path segment does
not give every request its own distinct value. `user_id` appears only once a subject is
bound, which `user_id_dependency` does. A request that raises is logged too, before the
exception propagates.

Nothing that can carry a secret is logged: no body, no header, no token and no query string.

The API Gateway access log records the same request at the edge. This line is the in-process
view, with the route template, the handler's own duration and the authenticated subject.
Pass `request_log=False` where the gateway access log is the only record a service wants.

### Carrying more than the four fields

Some services need a machine readable code, or per-field validation detail for a form. Both
are options rather than defaults, so a service that wants neither gets a body byte identical
to 0.2.0:

```python
app = create_app([posts_router], error_codes=True, validation_details=True)
```

`error_codes=True` adds `error_code`, a stable string per status (`NOT_FOUND`, `CONFLICT`,
`INTERNAL_ERROR`). `validation_details=True` adds `details` to a 422, one entry per offending
field, alongside the `errors` key that 0.2.0 callers already read:

```json
{
  "success": false, "status": 422, "message": "Request validation failed.",
  "request_id": "...", "error_code": "VALIDATION_ERROR",
  "details": [{"field": "email", "message": "value is not a valid email address", "type": "value_error"}]
}
```

The field path is flattened to a dotted string with the `query`/`body` prefix dropped, since
the caller knows where it sent the value. As with `errors`, `details` never carries the
rejected input.

A single route can set its own code without turning any option on, by raising with a mapping
detail:

```python
raise HTTPException(404, {"message": "No such post.", "error_code": "POST_NOT_FOUND"})
```

A mapping detail with no usable `message` renders the generic "Request failed." rather than
being echoed, so an internal dict cannot leak into a response.

### Choosing the envelope shape

`error_codes` and `validation_details` compose one body a key at a time, which is fine for a
service adding a field and awkward for one that has to match a shape it already ships.
`error_envelope` names the whole shape instead, and it applies to every handler installed
here, the unmatched-route 404 included:

```python
app = create_app([posts_router], error_envelope="detailed")
```

| `error_envelope` | Body |
| --- | --- |
| omitted, or `"default"` | The historical shape. `error_code` and `details` appear only under their own options, and a 422 carries `errors`. |
| `"detailed"` | `{"success", "status", "message", "request_id", "error_code"}`, where `error_code` is never absent. A 422 carries a flat `details` list and **no** `errors` key. |
| a callable | Whatever the callable returns. |

`"detailed"` implies `error_codes=True` and `validation_details=True`, so naming the shape is
the whole configuration:

```json
{
  "success": false, "status": 422, "message": "Request validation failed.",
  "request_id": "...", "error_code": "VALIDATION_ERROR",
  "details": [{"field": "email", "message": "value is not a valid email address", "type": "value_error"}]
}
```

That is the shape CarModPicker emits today, which is why it exists: the package can now
express it, so the local handlers that were keeping it are no longer the reason to keep them.

`detailed_error_body` is the same builder by hand, for a service with one handler of its own
left over. It mirrors `error_body` and fills `error_code` from the status when none is given.

No shape ever carries Starlette's `detail`, and a 5xx never echoes its own message, whichever
shape is chosen. A shape is a choice about keys, not a relaxation of either rule.

#### A renderer of your own

A callable receives an `ErrorContext` and returns the body. Every handler routes through it,
so one function covers HTTP errors, validation errors, unhandled faults, routing 404s, mapped
exception types and the DynamoDB branches:

```python
from webbpulse.http import ErrorContext, create_app, request_id


def render(context: ErrorContext) -> dict[str, object]:
    return {
        "ok": False,
        "code": context.error_code,
        "reason": context.message,
        "request_id": request_id(context.request),
    }


app = create_app([posts_router], error_envelope=render)
```

The context carries `status`, `message`, `request`, `error_code`, `details`,
`validation_errors`, `exception` and `extra`. Two fields are worth knowing:

- `validation_errors` is populated only for a 422, as one `{loc, msg, type}` entry per
  offending field, so a renderer can build its own field shape. As everywhere else, it never
  carries the rejected input.
- `error_code` is always supplied to a callable, because the renderer decides whether to emit
  one. `error_codes=False` suppresses the code in the default shape only.

Keep `request_id` in whatever you return. It is the only thing joining a caller's report to
the CloudWatch line, and every operational runbook here assumes it is there.

An unknown shape name raises `ValueError` when the app is built, not as a 500 under load.

## Verifying an inbound signature

`verify_hmac_signature` checks a signed body in constant time. The defaults are GitHub's
`X-Hub-Signature-256` shape, `sha256=<hex>`, which is also what
[webhooks.md](webhooks.md) sends:

```python
from webbpulse.http import SignatureMismatch, verify_hmac_signature

try:
    verify_hmac_signature(await request.body(), request.headers.get("X-Hub-Signature-256"), secret)
except SignatureMismatch:
    raise HTTPException(status_code=401, detail=unauthenticated()) from None
```

It returns `True` on a match and never returns `False`: a caller that forgets to check a
boolean is the failure mode this guards against, so a mismatch raises. Every failure, a
missing header, a wrong prefix, a non-hex digest and a wrong secret, raises the same
`SignatureMismatch`, because telling a caller which one it was is a verification oracle.

The comparison runs through `hmac.compare_digest` on the digest bytes, so neither the length
of the presented value nor how many leading characters matched leaks through the time it
takes. `algorithm=` accepts `sha1`, `sha256` and `sha512` only, so a header cannot name an
arbitrary hash, and `prefix=""` covers a sender that ships a bare hex digest.

For a webhook signed over a timestamp and the body together, verify
`webbpulse.events.webhooks.signed_message(timestamp, body)` rather than `body`, and check
the timestamp with `within_replay_window` before doing any work.

## Paginated responses

`CursorPage` is the response body for a paginated route, and `encode_cursor` and
`decode_cursor` make the data layer's position opaque on the wire:

```python
from webbpulse.http import CursorPage, decode_cursor


@router.get("")
async def list_posts(cursor: str | None = None) -> CursorPage[PostOut]:
    """One page of posts, newest first."""
    start = decode_cursor(cursor, settings.cursor_key) if cursor else None
    page = repositories().posts.query(workspace_id, start_key=start)
    return CursorPage.from_page([PostOut.model_validate(item) for item in page.items],
                                page.last_evaluated_key, settings.cursor_key)
```

The state is serialised compactly with sorted keys, signed with HMAC-SHA256 under the
caller's key, and packed as urlsafe base64 with the padding stripped, so it is opaque, safe
in a query string, and tamper evident. A client that edits it gets `InvalidCursor` rather
than a page of somebody else's rows, and every failure raises that same error with the same
message so nothing about the key is learnable by feeding cursors in.

It is signed, not encrypted: a client can decode what is in it, so a cursor carries keys and
positions, never anything the caller may not already see.

`next_cursor` is `None` exactly when the result set is exhausted, and `has_more` is derived
from it, so the two can never disagree. `from_page` takes the items and
`Page.last_evaluated_key` as arguments rather than a `Page`, so this module never imports
`webbpulse.dynamodb` and stays usable in a service with no `dynamodb` extra installed.

### An API's own plural key

`CursorPage` renders its items under `items`. For an API whose list bodies each name what
they hold, `cursor_page` builds the same page under that key:

```python
from webbpulse.http import cursor_page

IssuesPage = cursor_page(IssueOut, "issues")


@router.get("")
async def list_issues(cursor: str | None = None) -> IssuesPage:
    """One page of issues, newest first."""
    start = decode_cursor(cursor, settings.cursor_key) if cursor else None
    page = repositories().issues.query(workspace_id, start_key=start)
    return IssuesPage.from_page([IssueOut.model_validate(item) for item in page.items],
                                page.last_evaluated_key, settings.cursor_key)
```

The body is `{"issues": [...], "next_cursor": ...}`. The result is a real subclass of
`CursorPage[ItemT]`, so `from_page`, `has_more` and `next_cursor` are the ones above and
nothing is reimplemented. Only the wire name moves: the field is still `items` in Python, so
`page.items` reads the same whichever model a route returns and a helper written against
`CursorPage` keeps working.

It is an alias rather than a renamed field, which is what keeps `items` working for every
existing caller, and the model is constructible by either name. A response renders under the
plural key without a route remembering `by_alias=True`, and FastAPI reads the alias for the
OpenAPI document too, so the schema and the body agree and a generated client is right.

Models are cached per item type, key and name, so a module-level
`IssuesPage = cursor_page(IssueOut, "issues")` and the same call made again return one class.
That matters because two structurally identical models sharing a name collide in the OpenAPI
document and come out as `IssuesPage` and `IssuesPage1`. `model_name` overrides the default,
which is the item type's name plus `Page`.
