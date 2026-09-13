# HTTP: the app factory and the error envelope

`create_app`, the four-field error envelope, and the envelope variants. Error handlers for
DynamoDB and for a service's own exception types are in
[error-handlers.md](error-handlers.md). Back to the [README](../README.md).

## `webbpulse.http`

`create_app` builds one domain's FastAPI application, adding, in the order a request
traverses them: CORS, the request id middleware, the structured error handlers, and a
`GET /health` route.

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
