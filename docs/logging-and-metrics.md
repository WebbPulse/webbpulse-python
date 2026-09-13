# Logging, context, and metrics

Structured JSON logging, the request and user context variables, and CloudWatch EMF
metrics. Tracing lives in [tracing.md](tracing.md). Back to the [README](../README.md).

## `webbpulse.logging`

`configure_logging(level=..., service=..., environment=...)` installs a JSON formatter on
the root logger, writing to stdout. One object per line, with a top-level `level` and an
RFC 3339 `timestamp`:

```json
{"timestamp":"2026-09-07T18:20:31.114Z","level":"ERROR","message":"...","logger":"app.api","trace_id":"...","span_id":"..."}
```

Those two keys are the ones that matter. With a function's log format set to JSON, Lambda
filters events by an application-supplied `level` key and needs a valid RFC 3339
`timestamp` beside it; AWS documents that an unparseable timestamp makes Lambda assign the
event level INFO and stamp its own time, which silently defeats both `application_log_level`
filtering and the `{ $.level = "ERROR" }` metric filter behind the `api-alarms` module.

There is no double wrapping. AWS documents that Lambda "doesn't double-encode any logs that
are already JSON encoded", so a function can set `log_format = "JSON"` and use this
formatter at the same time. Avoid `print()`, which Lambda captures as plain text whatever
the format setting.

Trace and span ids are merged in whenever a span is recording, so a log line and a trace
join on the same value. Anything passed as `extra={...}` becomes a top-level key, which is
what lets a CloudWatch metric filter or an Insights query select on it. `configure_logging`
is idempotent, replaces Lambda's own root handler rather than adding to it, and reattaches
uvicorn's loggers so access lines are JSON too.

### Two escape hatches

Both were added in 0.8.0 and neither changes anything for a caller that does not pass them.

```python
configure_logging(level="DEBUG", formatter="text", stream=sys.stderr)
```

`stream=` moves **every handler the function installs**, which is what a CLI needs when its
own commands write data on stdout and are compared byte for byte. A log line leaking onto
stdout breaks that comparison, and routing only some handlers would leave exactly the
interleaving the argument exists to remove. It defaults to `sys.stdout`, read at call time
rather than at import so a runtime that replaced the stream is honoured.

`formatter=` chooses the rendering: `"json"` (the default, byte identical to 0.7.0),
`"text"` for a human readable `time level logger message` line on a TTY, or a
`logging.Formatter` instance for a service that wants its own. A one-line JSON object is
right in CloudWatch and unreadable in a terminal. `"text"` drops `service` and `environment`
rather than rendering them, since locally there is one of each; a service that wants the
request context in a text line uses `LogContextFilter` and a `%(request_id)s` in its own
format string. A bad selector raises before the existing handlers are torn down, so a typo
does not leave the root logger with nothing attached.

## `webbpulse.log_context`

Two context variables, `request_id` and `user_id`, and the helpers that bind them. The
point is reach: `webbpulse.http.request_id(request)` needs the `Request` object, so a
repository three layers down, a background task or a CLI command cannot use it. A context
variable is visible to all of them, and to a `logging.Filter`, without being threaded
through call signatures.

```python
from webbpulse.log_context import set_user_id, task_context

set_user_id(user.id)  # in the authentication dependency

with task_context("crawler", job_id):  # for work outside any request
    run()
```

`RequestIdMiddleware` binds `request_id_var` itself, so a service that already mounts it
gets this for free. `JsonFormatter` merges the bound values into every record it formats,
which means `configure_logging` plus the middleware is the whole wiring:

```json
{"timestamp":"...","level":"INFO","message":"...","request_id":"01J...","user_id":"42"}
```

An explicit `extra={"request_id": ...}` at a call site wins over the ambient value.

`task_context(name, job_id)` binds `request_id` to `bg:<name>:<job_id or "-">` and
`user_id` to `bg`, so one background task's output is selectable in Logs Insights with
`filter request_id like /^bg:crawler:/`. `bind_context(request_id=..., user_id=...)` is the
general form; both restore the previous values on exit, including when the block raises,
and both nest.

Two escape hatches. `LogContextFilter` is a `logging.Filter` for a service keeping its own
formatter, and unlike the JSON path it always sets both attributes, using `"-"` when
nothing is bound, so a `%(request_id)s` format string does not raise; `attach_log_context()`
installs it on every root handler exactly once. `set_span_context_attributes()` copies the
same values onto the active OpenTelemetry span as `webbpulse.request_id` and
`webbpulse.user_id`, the names `webbpulse.http` already uses.

Values are coerced to strings, stripped of newlines and truncated to 128 characters,
because both can originate from a caller: the request id from an inbound `X-Request-ID`
and the user id from a token claim.

### Do not call `set_user_id` from a sync (`def`) FastAPI dependency

**This is the one way to get `log_context` wrong, it fails silently, and Portfolio shipped
it to production.** A ContextVar bound inside a `def` dependency is invisible to the
handler and to every log line after it:

```python
def get_current_user(token: str = Depends(oauth2)) -> User:  # WRONG: `def`
    user = lookup(token)
    set_user_id(user.id)  # binds a context that is about to be discarded
    return user
```

Nothing raises. The dependency runs, the user resolves, the endpoint returns 200, and
`user_id` reads `"-"` on every line for the rest of the request. Starlette runs a sync
dependency in a threadpool through `anyio.to_thread.run_sync`, which **copies** the context
into the worker thread; the copy is what gets mutated, and it dies when the call returns.

Use `webbpulse.http.user_id_dependency`, which wraps the service's own resolver in an
`async def` and binds the id in the request's own context:

```python
from webbpulse.http import user_id_dependency

CurrentUser = user_id_dependency(get_current_user)  # `get_current_user` may stay `def`


@router.get("/me")
async def me(user: User = Depends(CurrentUser)) -> UserRead: ...
```

The resolved object is passed straight through, so this is a drop-in swap at every call
site: the handler receives the identical object it received before. The wrapped resolver
keeps its own dependencies, may be `def` or `async def`, and needs no change. Pass
`attribute="sub"` when the id is not on `.id`, or `extract=lambda claims: claims["sub"]`
when it is not a plain attribute at all. A resolver returning `None`, which is the optional
authentication shape, binds nothing and leaves the `"-"` placeholder rather than the string
`"None"`.

For a service that prefers its own wrapper, `webbpulse.http.bind_user_id` is the same
binding as an awaitable:

```python
async def get_current_user(...) -> User:
    user = lookup(token)
    await bind_user_id(user.id)
    return user
```

Being a coroutine is the point: writing it in a `def` dependency leaves an un-awaited
coroutine, which Python warns about at runtime and which a suite running under `-W error`
fails on, so the wrong shape stops being silent. `set_user_id` remains correct wherever the
caller owns the context: a middleware, a `task_context` block, a CLI entry point.

## `webbpulse.metrics`

CloudWatch metrics as Embedded Metric Format, one JSON line per flush on stdout.
CloudWatch Logs extracts the metrics from the `_aws` block asynchronously, so a metric
costs a log line and nothing else: no `PutMetricData` in the request path, no
`cloudwatch:PutMetricData` on the execution role, no agent and no extension. The document
is also an ordinary log event, so its dimensions and properties stay queryable in Logs
Insights after the metric has been extracted.

```python
from webbpulse.metrics import emit

emit(
    namespace="CarModPicker/Crawlers",
    dimensions={"AdapterName": name, "Environment": env, "RunType": "live"},
    metrics={
        "Ingested": (ingested, "Count"),
        "ParseFailures": (parse_failures, "Count"),
        "ElapsedSeconds": (elapsed, "Seconds"),
    },
    enabled=settings.environment in {"staging", "production"},
)
```

`MetricsEmitter` is the same thing held open, for several values sharing one dimension set
or for a loop emitting one document per iteration:

```python
with MetricsEmitter(namespace=ns, dimensions={"Environment": env}, enabled=on) as m:
    with timed(m, "ElapsedSeconds", unit="Seconds"):
        results = run()
    m.put("Ingested", len(results), "Count")
```

`namespace` is required and never defaulted. A package-wide default would be one namespace
every service dumped metrics into, which is the one choice that cannot be undone later
without rebuilding every alarm.

**Dimensions must be bounded.** CloudWatch bills per distinct combination of namespace,
metric name and dimension values, so a dimension carrying a user id, a request id or a URL
mints a billable metric per user, per request or per URL. Put unbounded values in
`properties` instead: they are written into the log event, are queryable in Logs Insights,
and create no metric. `set_dimensions` refuses more than nine, which is the CloudWatch
ceiling, and refuses a blank value, which would void the whole document.

`put` rejects a unit outside the CloudWatch set rather than passing it through, because
CloudWatch drops an unknown unit silently. Repeat `put` calls for one name accumulate into
a value array that CloudWatch aggregates, rather than producing a document each.
`enabled=False` makes emission a no-op while still validating, so a typo fails in a test
suite rather than only in production; it is a constructor argument rather than an
environment variable so the policy stays with the service that owns the settings.

`metrics_enabled_from_env` (0.8.0) is the gate that policy usually turns out to be, hoisted
so the next adopter does not hand-roll it a third time:

```python
from webbpulse.metrics import emit, metrics_enabled_from_env

emit(..., enabled=metrics_enabled_from_env(settings.environment))
```

It returns `True` only when `TESTING` is not truthy and the environment is one of
`staging` or `production`, which is exactly the gate CarModPicker's deleted
`core/cloudwatch_emf.py` carried. Both are arguments: `testing_var=`, `environment_var=`
and `allowed=` cover a service that names them differently. Passing no environment reads
`ENVIRONMENT`, so a service without a settings object still works. An unset or blank
environment returns `False`, because a missing variable should fail closed to silence
rather than to production-namespaced noise from an unidentified source. It reads
environment variables and returns a bool, nothing else: `MetricsEmitter(enabled=...)` still
defaults to `True` and a service that never calls this sees no change.

`flush` never raises. A metric reports on the work, and losing the report is better than
failing the work, so a closed stream or a serialisation failure is logged at ERROR and
swallowed. The stream is flushed explicitly, because Lambda freezes the execution
environment the moment the response is written and a buffered line is lost rather than
late.

There is no `aws-embedded-metrics` dependency. Its runtime auto-detection falls back to a
CloudWatch Agent sink that does not exist on Lambda, Fargate or App Runner, which drops
metrics silently unless `AWS_EMF_ENVIRONMENT=Local` is set everywhere, and its asynchronous
flush can lose the last record a process emits. Writing the document directly removes both.
