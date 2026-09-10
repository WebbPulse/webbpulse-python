# webbpulse

Shared infrastructure code for WebbPulse FastAPI services on AWS Lambda.

Every WebbPulse backend had grown its own copy of the same nine concerns: settings and
secret loading, JSON logging, tracing, the FastAPI app factory, rate limiting, the DynamoDB
access layer, password hashing and JWTs, the Lambda entrypoint, and the test fixtures. They had drifted, and the
drift was where the bugs lived. This package is one implementation of each, typed and
tested, so a service imports them instead of maintaining them.

Nothing here runs an AWS call at import time, and the optional dependencies sit behind
extras, so a service installs only the surface it uses.

## Install

From the WebbPulse CodeArtifact repository:

```bash
aws codeartifact login --tool pip \
  --domain webbpulse --domain-owner 432410731887 \
  --repository python --region us-west-2

pip install "webbpulse[fastapi,dynamodb,otel]"
```

For local work on the package itself:

```bash
python3.13 -m venv .venv
.venv/bin/pip install -e ".[aws-otel,dynamodb,fastapi,identity,otel,security,testing]" mypy ruff pytest-cov \
  "boto3-stubs[dynamodb,kms,secretsmanager]" botocore-stubs
.venv/bin/ruff check . && .venv/bin/ruff format --check .
.venv/bin/mypy
.venv/bin/pytest
```

### Extras

The base install carries only `pydantic` and `pydantic-settings`, which every consumer
needs. Everything else is opt-in.

| Extra | Pulls in | Needed by |
| --- | --- | --- |
| `dynamodb` | `boto3`, `botocore` | `webbpulse.dynamodb`, `webbpulse.ratelimit`, and secret loading in `webbpulse.config` |
| `fastapi` | `fastapi`, `starlette`, `uvicorn` | `webbpulse.http`, `webbpulse.lambda_entry`, the `webbpulse.ratelimit` dependency |
| `otel` | the OpenTelemetry SDK, the OTLP HTTP exporter, the FastAPI and botocore instrumentations | `webbpulse.otel` |
| `security` | `PyJWT`, `bcrypt` | `webbpulse.security` |
| `identity` | `PyJWT[crypto]`, `fastapi` | `webbpulse.identity` |
| `testing` | `moto`, `pytest`, `httpx2` | `webbpulse.testing` |

A typical service installs `webbpulse[fastapi,dynamodb,otel]` at runtime and adds
`testing` in its dev dependencies.

Which modules import without their extra matters when adopting one at a time.
`webbpulse.otel` imports on the base install and every entry point in it is a no-op until
the `otel` extra is present, and `config`, `logging`, `dynamodb`, `ratelimit` and
`lambda_entry` import too, raising only when a call actually needs boto3, uvicorn or
FastAPI. `webbpulse.http` imports FastAPI at module scope and so needs the `fastapi`
extra to import at all, and `webbpulse.testing` needs the `testing` extra.
`webbpulse.identity` imports on the base install: it takes a KMS client rather than
building one, and it defers both the `cryptography` and the FastAPI import to the call
that needs it, so serving a JWKS needs the `identity` extra but importing the module
does not. `webbpulse.log_context` and `webbpulse.metrics` need nothing beyond the standard
library and have no extra of their own.

## Modules

### `webbpulse.config`

`BaseServiceSettings` is the pydantic-settings base a service subclasses. It carries only
what is genuinely common: `environment`, `service_name`, `log_level`, `app_secrets_arn`,
and the two CORS fields. Anything domain-specific belongs in the subclass.

```python
from functools import lru_cache
from webbpulse.config import BaseServiceSettings


class Settings(BaseServiceSettings):
    table_prefix: str = "webbpulse-staging"
    google_client_id: str = ""


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
```

Construct settings behind a cache in the service, not at import, so a missing environment
variable fails a request rather than the whole cold start.

List-valued environment variables accept both JSON and the bare comma-separated form, so
`CORS_ALLOW_ORIGINS=https://a.example,https://b.example` works. That needed a custom
settings source: pydantic-settings calls `json.loads` on a complex field *inside* the
source, before any `mode="before"` validator can see it.

`load_json_secret(arn)` reads one Secrets Manager secret whose value is a JSON object and
returns it as a dict, cached per ARN for the life of the process. On Lambda that is once
per execution environment, so a warm invoke never calls Secrets Manager. It is a function,
never a module-level call: an import that reaches Secrets Manager turns every cold start
into a synchronous dependency on another service.

```python
secrets = get_settings().load_secrets()  # {} locally, where no ARN is set
```

A secret that is not a JSON object raises `SecretNotJsonObjectError`. A missing secret or a
denied read lets botocore's `ClientError` propagate, because both are unrecoverable.

### `webbpulse.logging`

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

#### Two escape hatches

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

### `webbpulse.log_context`

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

#### Do not call `set_user_id` from a sync (`def`) FastAPI dependency

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

### `webbpulse.metrics`

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

### `webbpulse.otel`

OpenTelemetry is the only instrumentation in this package. Sentry is gone, and there is no
collector, sidecar or Lambda extension in the request path. The whole pipeline is built in
process by `configure_tracing`, and a service starts with a plain `python -m`, not under
`opentelemetry-instrument`. That is deliberate: an auto-instrumentation configurator calls
`set_tracer_provider` itself, and the global provider is set-once per process, so whichever
of the configurator and `configure_tracing` ran first would win and the other would be
silently ignored. Owning the pipeline in one place removes that race.

```python
from webbpulse.otel import configure_tracing

configure_tracing("webbpulse-staging-posts", environment="staging")
```

Traces go straight to the CloudWatch X-Ray OTLP endpoint,
`https://xray.<region>.amazonaws.com/v1/traces`. Three things about that endpoint are easy
to get wrong, and all three look identical from outside: traces simply never appear.

1. **It authenticates with SigV4.** A plain OTLP exporter posts unsigned, gets a 403, and
   retries it quietly, which looks exactly like having no traffic. The signing comes from
   `OTLPAwsSpanExporter` in `aws-opentelemetry-distro`, which subclasses the plain HTTP
   exporter and swaps in a `requests` session that signs for the `xray` service. Install it
   with the **`aws-otel`** extra:

   ```
   pip install "webbpulse[otel,aws-otel]"
   ```

   `configure_tracing` picks that exporter automatically whenever the resolved endpoint is
   an X-Ray one, and a plain `OTLPSpanExporter` for anything else, such as a local
   collector. An X-Ray endpoint means `xray.<region>.amazonaws.com`, the FIPS form
   `xray-fips.<region>.amazonaws.com`, or an interface VPC endpoint
   `<vpce-id>.xray.<region>.vpce.amazonaws.com`; the signing region is taken from the host
   itself rather than from `AWS_REGION`, which would be the wrong scope for a VPC endpoint. Only the exporter class is used; the distribution's configurator and its
   `opentelemetry-instrument` entry point deliberately are not. When the extra is missing it
   warns, naming the extra, and falls back to the unsigned exporter, because a warned-about
   403 is a better failure than a crashed cold start.
2. **Transaction Search must be enabled on the account.** It is a one-time per-account
   setting that an application cannot make for itself.
3. **The execution role needs X-Ray write access.** Attach `AWSXrayWriteOnlyAccess`,
   `arn:aws:iam::aws:policy/AWSXrayWriteOnlyAccess`. There is no `AWSXrayWriteOnlyPolicy`;
   an ARN built from that name fails a Terraform apply with NoSuchEntity.

The endpoint takes OTLP over HTTP only; there is no gRPC listener. The protocol is not an
environment variable here, because the exporter class is constructed directly, so
`http/protobuf` is implicit in the code rather than something a deployment can get wrong.
Note the host is per-signal: logs go to
`logs.<region>.amazonaws.com/v1/logs` and metrics to `monitoring.<region>.amazonaws.com/v1/metrics`.
This package sends traces only, and CloudWatch handles logs.

`instrument_fastapi(app)` attaches the FastAPI instrumentation, excluding the health route
by default because the Web Adapter polls it on every cold start. Botocore is instrumented
too, so DynamoDB and Secrets Manager calls become spans. All of it is a no-op when the
`otel` extra is absent or when `WEBBPULSE_OTEL_DISABLED` or `OTEL_SDK_DISABLED` is set, so
tests and local runs cost nothing.

#### Sampling: errors are always kept

The decision is 100 percent of traces on staging, 10 percent on production, and errors are
always kept. Head sampling cannot deliver the last clause: `should_sample` runs when the
root span starts, before the request has been handled, so it cannot know the request is
about to fail. `OTEL_TRACES_SAMPLER=parentbased_traceidratio` with an arg of 0.1 therefore
throws away 90 percent of the failures, which is the 90 percent worth keeping.

So the package records every span and decides at export time instead. `configure_tracing`
installs a `TailSamplingSpanProcessor` that buffers ended spans per trace and judges each
trace once at flush time. A trace is exported when **either**:

- any span in it has `StatusCode.ERROR` or an `exception` event (both, because
  `FastAPIInstrumentor` sets the status on a 5xx while `record_exception`, which botocore's
  instrumentation uses, adds the event and does not always set the status), **or**
- its trace id falls below the configured probability.

The probability test is the SDK's own `TraceIdRatioBased` arithmetic, keep when
`trace_id & ((1 << 64) - 1) < round(ratio * (1 << 64))`. Using the identical bound is what
makes the decision a pure function of the trace id, so this service and an upstream one at
the same ratio agree on the same traces without coordinating. A trace API Gateway or X-Ray
already sampled in is sampled in here too, and the tail step only ever adds error traces on
top.

```python
configure_tracing(
    "webbpulse-portfolio-content",
    environment="production",
    sample_ratio=0.1,  # or leave it to WEBBPULSE_OTEL_SAMPLE_RATIO
    always_sample_errors=True,  # the default
)
```

##### The flush is not optional, and it is wired for you

The tail decision is made at flush time, so a Lambda invocation must reach a flush before
the execution environment is frozen. Nothing is exported before it.

Under the Lambda Web Adapter there is no handler to hook, and "after the invocation" is not
a place code can run: the invocation ends when the HTTP response completes and the sandbox
freezes immediately, so a `BackgroundTask`, an `asyncio` task or an `atexit` hook is caught
mid-flight. The flush therefore has to happen inside the request, after the handler has
produced the response and before it is handed back to the adapter.

`instrument_fastapi(app)` installs an ASGI middleware that does exactly that. It is on by
default when `AWS_LAMBDA_FUNCTION_NAME` is set and off otherwise, since a long-lived server
can flush on its own schedule.

The placement is load-bearing and is the reason this is a raw ASGI wrapper rather than a
`BaseHTTPMiddleware` added with `add_middleware`. `FastAPIInstrumentor.instrument_app`
replaces `build_middleware_stack` so that `OpenTelemetryMiddleware` wraps the entire finished
stack, outermost. Anything added the ordinary way runs *inside* it, where the server span has
not ended yet, so the flush would export the previous request's trace and leave the current
one buffered for the sandbox to freeze on. The wrapper therefore goes outside the
instrumented app, and it flushes after that app has fully returned, since the server span is
ended on the way out and not when the last response body chunk is sent.

```python
instrument_fastapi(
    app,
    flush_per_request=None,  # None auto-detects Lambda; True or False decides explicitly
    flush_timeout_millis=1000,  # ceiling on the in-request flush
)
```

That timeout is passed to the exporter as its own deadline, covering the whole export
including its retries, which is what actually bounds how long a request can be held waiting
on telemetry. The flush also runs on a worker thread rather than the event loop: it exports
synchronously over HTTP, and awaiting it inline would stall every other connection the
process is serving, not just the request being flushed. It never raises into the request:
a failure is logged at WARNING and the response is returned unchanged, because telemetry
turning a healthy 200 into a 500 would be worse than the trace it was reporting on.

Call `instrument_fastapi(app)` before the application starts serving. Once the middleware
stack is built, `FastAPIInstrumentor` can no longer inject the server span middleware into
it, so the app would look instrumented and produce no spans at all; that case logs a WARNING
rather than failing quietly.

On the latency cost: the flush only does work when the trace is actually being exported. At
a production ratio of 0.1, roughly nine requests in ten resolve to "drop", the buffered
spans are discarded and no HTTP call is made, so the cost lands almost entirely on the
sampled traces and the errors, which are the requests worth paying for. Staging at 1.0 pays
an export on every request, which is the intended trade for complete traces there.

`flush_tracing()` is the same call for anything that is not a FastAPI app, and
`shutdown_tracing()` flushes too, which covers the container shutdown path.

##### The memory bound

Buffering per trace is capped by `max_spans_per_trace`, default 2048. A trace that exceeds
the cap is resolved immediately rather than being allowed to grow:

| `on_overflow` | behaviour |
| --- | --- |
| `"export"` (default) | the trace is marked sampled and the rest of it streams straight through to the exporter. A trace big enough to overflow is unusual, so keeping it is the useful bias. |
| `"drop"` | the trace is discarded and `dropped_traces` is incremented. Choose it when a hard ceiling on egress matters more than seeing the outlier. |

That bounds one trace. The number of traces is bounded separately by `max_buffered_traces`
(default 1024) and their lifetime by `max_trace_age_seconds` (default 300), because a buffer
is only drained when its trace completes and a flush comes round, so a trace that never
completes would otherwise sit there for the life of the process. Eviction means judging the
trace rather than discarding it, so an error trace that was about to be kept is still
exported, and `evicted_traces` counts it.

The two ceilings catch different failures, and the difference matters:

| bound | evicts | why |
| --- | --- | --- |
| `max_buffered_traces` | the oldest trace with **no spans still open** | judging an in-flight trace early is the partial-trace bug the open-span tracking exists to prevent, so the count bound refuses to do it |
| `max_trace_age_seconds` | the oldest trace, **in flight or not** | the deliberate exception, and the load-bearing one |

The age bound has to be willing to evict an in-flight trace, because otherwise nothing
reclaims a leak. A leaked span or an abandoned request never completes, so a supply of them
pins every buffer while the count bound declines to touch any of it, and under Lambda no
later flush ever comes round. A trace that has been open for five minutes is not a request in
progress, and half of it is worth more than none of it. The total is bounded by
`max_spans_per_trace * max_buffered_traces` and in practice sits far below it.

##### In-flight traces

A trace is judged only once every span in it has ended. `force_flush` resolves the traces
with no open spans and leaves the rest buffered. Without that, one request's flush would
judge another request's half-built trace on whichever spans happened to have ended, usually
dropping it, and then judge the remainder separately when it arrived, so one logical trace
could end up half exported and half discarded. Deferring costs nothing, because the request
that owns the trace flushes when it finishes. `shutdown_tracing()` is the exception: there is
no later, so it resolves everything.

##### Environment variables

There is exactly one, and it is optional:

| Variable | Value | Why |
| --- | --- | --- |
| `WEBBPULSE_OTEL_SAMPLE_RATIO` | `1.0` on staging, `0.1` on production | the tail sampling ratio |

Everything else that used to be needed here is gone. There is no
`OTEL_EXPORTER_OTLP_TRACES_PROTOCOL`, because the exporter class is chosen in code. There is
no `OTEL_PYTHON_DISTRO` or `OTEL_PYTHON_CONFIGURATOR`, because nothing runs under
`opentelemetry-instrument`. There is no `OTEL_TRACES_SAMPLER`, because `configure_tracing`
passes an explicit `ParentBased(root=ALWAYS_ON)` sampler to the `TracerProvider`, which
overrides the environment for the provider this package builds. Terraform sets one variable
per environment and the rest is the package's problem.

`WEBBPULSE_OTEL_SAMPLE_RATIO` falls back to `OTEL_TRACES_SAMPLER_ARG`, but only when
`OTEL_TRACES_SAMPLER` is `traceidratio` or `parentbased_traceidratio`; under any other
sampler name the arg is meaningless and reading it would invent a ratio. An unparseable or
out-of-range value warns and is skipped, so a typo in a Terraform variable costs money
rather than availability. With nothing set the ratio is 1.0.

`WEBBPULSE_OTEL_DISABLED` and the standard `OTEL_SDK_DISABLED` still turn everything off,
and `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` still overrides the endpoint if you want to point a
local run at a collector.

##### Why the sampler is explicit

`ParentBased(root=ALWAYS_ON)` is passed to the provider rather than left to the SDK default.
Without it the SDK falls back to `sampling._get_from_env_or_default()`, which reads
`OTEL_TRACES_SAMPLER` and `OTEL_TRACES_SAMPLER_ARG` from whatever the environment happens to
hold. A ratio sampler there would head-drop 90 percent of spans before any processor saw
them, and no amount of tail logic can recover a span that was never recorded. Being explicit
means a stray `OTEL_TRACES_SAMPLER` in a task definition cannot quietly defeat the design.
`tests/test_otel.py` asserts this directly, by setting `OTEL_TRACES_SAMPLER` to
`parentbased_traceidratio` with an arg of `0.0` and checking spans are still recorded.

The `ParentBased` half matters as much as the `ALWAYS_ON` half: a span whose parent arrived
sampled-out from API Gateway or an X-Ray propagated header still follows that decision, so
an upstream choice is honoured rather than overridden here.

##### A note on `AlwaysRecordSampler`

Worth knowing if this package is ever run alongside the ADOT distribution's configurator
after all. `_customize_sampler` there wraps the configured sampler in `AlwaysRecordSampler`,
which turns a `Decision.DROP` into `Decision.RECORD_ONLY`. A RECORD_ONLY span is still
created and still handed to every registered processor; only its `trace_flags.sampled` bit
is clear. The SDK's own `BatchSpanProcessor` and `SimpleSpanProcessor` open `on_end` with
`if not span.context.trace_flags.sampled: return`, which is why a ratio sampler drops spans
under them.

`TailSamplingSpanProcessor` deliberately does **not** filter on that flag, because the flag
records a head decision and this processor exists to make a later one. `tests/test_otel.py`
reproduces the wrapper over a ratio-0 sampler and asserts an error span still survives.

How the distribution's internals were checked, since it is an optional extra: the 0.19.0
wheel was unpacked and `amazon/opentelemetry/distro/` read directly. The exporter used here
is
`amazon.opentelemetry.distro.exporter.otlp.aws.traces.otlp_aws_span_exporter.OTLPAwsSpanExporter`,
taking `aws_region`, a `botocore` `Session`, and `endpoint`. Credentials are resolved lazily
by `AwsAuthSession` on the first signed request, not at construction, so building it at cold
start adds no IMDS or STS round trip to the critical path.

### `webbpulse.http`

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
[the warning under `log_context`](#do-not-call-set_user_id-from-a-sync-def-fastapi-dependency),
which is the shape to read before wiring authentication.

#### Carrying more than the four fields

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

#### DynamoDB errors

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

#### The service's own exception types

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

### `webbpulse.ratelimit`

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

### `webbpulse.dynamodb`

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

### `webbpulse.lambda_entry`

There is no Lambda handler and no Mangum. The AWS Lambda Web Adapter is an external
extension that starts before the application, turns each invoke into an ordinary HTTP
request against `127.0.0.1:$AWS_LWA_PORT`, and turns the response back. The application is a
normal ASGI server, so the identical image runs on Lambda, in a local container, and
anywhere else.

```python
# app/posts/entrypoint.py
from webbpulse.lambda_entry import run_uvicorn
from webbpulse.logging import configure_logging
from webbpulse.otel import configure_tracing
from app.posts import build_app


def main() -> None:
    configure_logging(level="INFO", service="posts", environment="staging")
    configure_tracing("webbpulse-staging-posts", environment="staging")
    run_uvicorn(build_app())


if __name__ == "__main__":
    main()
```

`run_uvicorn` binds `AWS_LWA_PORT`, falling back to `PORT` and then 8080, which is the
adapter's own precedence. Binding a port the adapter is not polling is the most common Web
Adapter misconfiguration and it presents as the readiness check never passing and the
function timing out with no application logs at all.

The Dockerfile is one `COPY` from a pinned public image. Version 1.0.1 is current, and the
image is multi-arch, so the same line serves arm64 and x86_64:

```dockerfile
# syntax=docker/dockerfile:1.7
FROM public.ecr.aws/docker/library/python:3.13-slim AS build
WORKDIR /build
COPY requirements.txt .
RUN --mount=type=secret,id=codeartifact_token \
    PIP_INDEX_URL="https://aws:$(cat /run/secrets/codeartifact_token)@webbpulse-432410731887.d.codeartifact.us-west-2.amazonaws.com/pypi/python/simple/" \
    pip install --no-cache-dir --target /deps -r requirements.txt

FROM public.ecr.aws/docker/library/python:3.13-slim
COPY --from=public.ecr.aws/awsguru/aws-lambda-adapter:1.0.1 /lambda-adapter /opt/extensions/lambda-adapter
COPY --from=build /deps /var/task
COPY app /var/task/app
ENV PYTHONPATH=/var/task \
    PYTHONUNBUFFERED=1 \
    AWS_LWA_PORT=8080 \
    AWS_LWA_READINESS_CHECK_PATH=/health \
    AWS_LWA_ASYNC_INIT=true
WORKDIR /var/task
CMD ["python", "-m", "app.posts.entrypoint"]
```

Each line there is a real failure mode:

- **`/opt/extensions/lambda-adapter` is the required destination.** Lambda only starts
  binaries it finds in `/opt/extensions`. Copied anywhere else the adapter never runs, the
  function has no handler, and every invoke times out.
- **The CodeArtifact token is a BuildKit secret mount, never a build arg or `ENV`.** Both of
  those persist into the image and are visible in `docker history`.
- **`PYTHONUNBUFFERED=1`** keeps log lines from sitting in a buffer while the execution
  environment is frozen between invokes and arriving attributed to a later request.
- **`AWS_LWA_ASYNC_INIT=true`** lets a slow import finish inside Lambda's 10 second init
  window instead of counting against the first invoke.
- **`AWS_LWA_READINESS_CHECK_PATH=/health`** must point at a route that does no I/O. The
  adapter's default is `/`.

### `webbpulse.security`

bcrypt password hashing and JWT signing, with nothing product specific in either half.
Needs the `security` extra.

```python
from datetime import timedelta
from webbpulse.security import (
    create_token,
    decode_token,
    hash_password,
    needs_rehash,
    verify_password,
)

hashed = hash_password(password)

if verify_password(password, user.hashed_password):
    if needs_rehash(user.hashed_password):
        repos.users.update(user.id, hashed_password=hash_password(password))
    token = create_token({"sub": user.username}, secret, expires_in=timedelta(minutes=30))

claims = decode_token(token, secret)  # raises ExpiredToken or InvalidToken
```

What is shared is turning a password into a hash and a claims mapping into a signed token.
What is **not** shared is what the claims mean: there is no `sub` convention here, no user
model, no database lookup and no notion of an admin. `decode_token` returns the claims and
stops. That is the part that genuinely differs between the two apps, and guessing at it
would force a fork immediately.

**Adoption changes no stored hash and invalidates no issued token.** `DEFAULT_ROUNDS` is
12, which is what both apps already write: CarModPicker passes `rounds=12` explicitly and
Portfolio takes bcrypt's default, which is also 12 on both 4.3.0 and 5.0.0.

**The 72 byte cliff is the reason this is worth sharing.** bcrypt reads at most 72 bytes of
a password, and libraries disagree about what to do with more: bcrypt 4.x truncates
silently, bcrypt 5.0 raises `ValueError`. Portfolio truncates by hand and is safe on
either; CarModPicker does not and is pinned to 5.0.0, so a password over 72 bytes is
currently a 500 rather than a login. This module truncates internally, on a **byte**
boundary rather than a character boundary, so it behaves identically on 4.x and 5.x and
still agrees with every hash either app has already written.

`verify_password` returns `False` for a `None` or empty stored hash, because an OAuth-only
account genuinely has no password and asking every call site to remember that invites the
one that forgets. It is deliberately not constant time across that case; a service wanting
that should verify against a fixed dummy hash, which is a decision bound up with its own
user lookup. `needs_rehash` returns `True` only for a **lower** cost, so a hash written
under a more cautious setting is never quietly re-hashed down.

**PyJWT rather than python-jose**, because `python-jose` is effectively unmaintained and
PyJWT validates more by default. An HS256 token is interchangeable between the two, so
Portfolio switching invalidates no already-issued session. `decode_token` always passes an
explicit `algorithms` list and never reads `alg` from the token header, which is what
refuses both `alg: none` and the RS256-verified-as-an-HMAC confusion. `issuer` and
`audience`, when given, are verified rather than merely returned.

An optional FastAPI dependency returns the decoded claims, and needs the `fastapi` extra:

```python
Claims = Annotated[dict, Depends(bearer_claims(settings.secret_key))]


@router.get("/me")
async def me(claims: Claims, repos: Repos = Depends(get_repos)):
    return repos.users.get_by_username(claims["sub"])
```

It raises `HTTPException(401)` with a mapping detail, so `register_error_handlers` renders
it in the package's existing envelope rather than a new shape, with `error_code`
`TOKEN_EXPIRED` or `INVALID_TOKEN` and a `WWW-Authenticate: Bearer` challenge. With
`auto_error=False` it returns `None` instead of raising, for a route serving both anonymous
and authenticated callers.

### `webbpulse.identity`

App-managed identity: password flows, refresh sessions, configuration, the product policy
seam, storage interfaces, a KMS-backed token service, and the reader for the claims an API
Gateway HTTP API JWT authorizer leaves on a request. Needs the `identity` extra.

This is M2 of `docs/identity-standard.md`. M1 built the foundations; M2 adds the password
and session flows on top of them. Email verification and reset (M3), TOTP and MFA (M4),
passkeys (M5) and OAuth (M6) are still absent.

```python
import boto3
from webbpulse.identity import IdentitySettings, TokenService, build_identity_router

settings = IdentitySettings()  # reads IDENTITY_* from the environment
tokens = TokenService(settings, boto3.client("kms"))

# One per execution environment: it caches a JWK per configured key.
app.include_router(build_identity_router(settings, hooks, stores, tokens=tokens))
```

| Piece | What it owns |
| --- | --- |
| `IdentitySettings` | Section 6.1 as validated settings, `IDENTITY_` prefixed |
| `IdentityHooks` | The product's own policy: who may sign in, what claims they get, and creating the user row |
| `IdentityFlows` | Register, login, change password, refresh, logout, logout-all, with no FastAPI dependency |
| `SessionService` | Refresh families: rotation, reuse detection, the grace window, revocation |
| `TokenService` | Minting, local verification, JWKS, discovery, rotation across keys |
| `authorizer_claims` | Reading and coercing what the authorizer put on the request |
| `CredentialStore` and friends | Storage interfaces, with DynamoDB and in-memory implementations |

**Every route mounts under the issuer's path, so mount the router with no prefix.** The
gateway builds the discovery URL as `issuer + "/.well-known/openid-configuration"` and
`jwks_uri` is advertised the same way, so the issuer decides where the routes live.
`build_identity_router` derives the prefix and places itself there. With the standard's
`https://<host>/api/auth` issuer:

| Route | What it does |
| --- | --- |
| `GET /api/auth/.well-known/openid-configuration` | Discovery, fetched by the gateway at authorizer creation |
| `GET /api/auth/.well-known/jwks.json` | The verification keys, followed out of discovery |
| `GET /api/auth/health` | The probe shape every service in the estate shares |
| `POST /api/auth/register` | Creates an account through the `create_user` hook and signs it in |
| `POST /api/auth/login` | Verifies a password, applies lockout, starts a refresh family |
| `POST /api/auth/password` | Changes a password and revokes every other session |
| `POST /api/auth/refresh` | Rotates the refresh family and returns a new access token |
| `POST /api/auth/logout` | Revokes the presented family |
| `POST /api/auth/logout-all` | Revokes every family for the user |

An issuer with no path gives the same routes at the origin. Adding a prefix of your own
doubles the issuer path and hides the documents from the gateway. **This changed in
0.10.0**: 0.9.0 served the documents at the origin regardless of the issuer, so a product
that compensated with `prefix="/api/auth"` must drop it when upgrading.

**The flow routes mount conditionally.** The six `POST` routes appear only when the product
supplies both `hooks` and a credential store. Called without them the router mounts exactly
what M1 mounted, the two `.well-known` documents and `/health`, so a service that only
serves a JWKS does not acquire a login endpoint by upgrading.

**The access token is returned in the JSON body and the refresh token is a cookie.** The
access token is short-lived, ten minutes by default, and is never set as a cookie: it is
carried in an `Authorization` header where no browser will send it automatically. The
refresh token is the opposite, an httpOnly Secure SameSite=Lax cookie scoped to
`cookie_path`, so no script can read it and no cross-site form can spend it. `cookie_path`
defaults to the issuer's path, the same place the routes mount, so the cookie reaches
exactly what spends it.

**Rotation detects reuse, and reuse revokes the family.** Every refresh consumes the
presented token and mints its successor in one conditional write, so two concurrent
refreshes cannot both succeed. Presenting an already consumed token inside
`refresh_reuse_grace` is treated as a client that raced itself and returns a working
successor; presenting one after that window is treated as a stolen token and revokes the
whole family, signing out both the attacker and the victim.

**Wrong password and unknown email are indistinguishable.** Identical status, body and
`error_code`, and the same cost: a login for an address that does not exist still runs one
bcrypt verification against a dummy hash, so the response time does not answer the question
the body refuses to. Registering an address that is already taken returns 200 with no
session rather than an error, for the same reason.

**Lockout is progressive, never permanent.** Five consecutive failures start a delay that
doubles from one second to a fifteen minute cap, and any success clears it. There is no
hard lock, because a hard lock on a known address is a denial of service anybody can
trigger.

**Passwords follow NIST SP 800-63B.** Eight character minimum, no composition rules, no
expiry, NFKC normalised, and a rejection rather than a silent truncation over 72 UTF-8
bytes. That last cap is bcrypt's, and the message says bytes because a 64 character
password of emoji is well over it.

**Every authorizer claim arrives as a string**, `exp` and `iat` included. That is a verified
finding from the M0 staging spike, and it is why `authorizer_claims` exists rather than a
dictionary access: `exp > time.time()` on a string raises `TypeError`, and `bool("false")`
is `True`. It coerces integers, booleans, space-separated scopes and the bracketed comma
form the gateway emits for array claims, and keeps the raw map on `.raw`.

**Rotation is a list, and its head signs.** `signing_key_arns` puts every configured key in
the JWKS and signs with the first, so each step of section 3.5 is a one-line change: add the
new key, deploy, move it to the front, deploy, drop the old one once no token it signed can
still be alive. A token signed by a previous key verifies for as long as that key is listed.
A `kid` matching no configured key is rejected rather than falling back to trying every key,
which would quietly undo the retirement.

**A key whose `kms:GetPublicKey` fails is omitted from the JWKS rather than failing it.** A
retired key id left in configuration must not deny every authorized request in the product.
Every key failing is still fatal, because an empty JWKS would be cached by the gateway and
deny everything for its whole interval.

**The stores hash what they hold.** Only the SHA-256 of a refresh or verification token is
stored, so a read of the table cannot be turned into a working session. `consume` is one
conditional `UpdateItem` returning the prior state rather than a read followed by a write,
because two concurrent refreshes both reading an unconsumed record is exactly the condition
reuse detection exists to notice.

**RS256, and there was no choice.** The API Gateway documentation for HTTP API JWT
authorizers says, in the token validation workflow, "Check the token's algorithm and
signature by using the public key that is fetched from the issuer's `jwks_uri`. Currently,
only RSA-based algorithms are supported." ES256 is ECDSA and so is excluded. The KMS key is
`RSA_2048` with `RSASSA_PKCS1_V1_5_SHA_256`, not a PSS variant: JWA binds `RS256` to
PKCS1 v1.5, and a PSS signature under an `RS256` header verifies nowhere.

**The private key never leaves KMS.** `KmsSigner` hashes the JWS signing input itself and
calls `kms:Sign` with `MessageType="DIGEST"`, which the KMS documentation describes as
skipping "the hashing step in the signing algorithm". That keeps the request 32 bytes and
puts the 4096 byte `Message` limit permanently out of scope. The returned RSA signature is
"defined by PKCS #1 in RFC 8017", which is exactly what JWS wants, so it is base64url
encoded as-is.

**`kid` is the base64url SHA-256 of the DER SubjectPublicKeyInfo**, so it is a pure function
of the key material: stable across redeploys, identical in every process, and never an AWS
account identifier in a public document. Rotation is by adding a second key rather than
mutating one, and the JWKS serves both through the overlap.

**Both `.well-known` routes must be reachable with no authorizer at all**, including no
staging access gate. API Gateway fetches them itself, holding no cookies. A gate in front of
either one means the JWT authorizer cannot retrieve the key and every authorized route fails
closed.

`verify_access_token` verifies a token locally against the configured keys. It is **not**
the production path: behind API Gateway the authorizer has already checked the signature,
issuer, audience and expiry before the Lambda runs, and re-verifying would add a JWKS lookup
to every request to re-establish what the platform guarantees. It exists for tests and for a
service that verifies a token itself.

`mint_test_token` signs an access token without authenticating anybody, for exercising an
authorizer end to end. It has two independent gates: an `enabled` argument with no default,
so no call site is accidental, and a refusal on `environment` of `production` on top of
that, so one flag left true in the wrong place is still refused. It raises
`TokenMintingDisabled`, which is named for the condition rather than the helper because
pytest collects any class named `Test*`.

### `webbpulse.testing`

Pytest fixtures for a moto-backed table and a `TestClient`. Enable them from a service's
`conftest.py`:

```python
pytest_plugins = ["webbpulse.testing"]
```

| Fixture or helper | What it gives you |
| --- | --- |
| `aws_credentials` | Placeholder credentials and region, so a mis-scoped mock cannot reach a real account |
| `dynamodb_resource` | A moto-mocked DynamoDB resource, with the package's cached resource cleared on both sides |
| `create_table(...)` | One on-demand table with an optional range key and TTL |
| `rate_limit_table` | The `rate-limits` table shaped exactly as Terraform creates it |
| `test_client(app, source_ip=...)` | A `TestClient` whose requests carry a realistic API Gateway request context |
| `make_request_context_headers(...)` | That header on its own, in either payload shape |

`test_client` is the one worth knowing about. Without the injected context header a
`TestClient` request has no API Gateway context at all, so `client_ip` falls back to the
peer address and a service's rate limit tests pass while never covering the branch that
actually runs in production.

## CI and releases

`.github/workflows/ci.yml` calls `WebbPulse/.github/.github/workflows/python-ci.yml@v1` on
every push and pull request, overriding the inputs that assume a backend service: this
package sits at the repository root and installs from `pyproject.toml`. A second job in the
same file runs mypy, because the reusable workflow has no type checking step and this
package ships `py.typed`, so its annotations are part of its contract.

`.github/workflows/publish.yml` calls
`WebbPulse/.github/.github/workflows/codeartifact-publish-python.yml@v1` on `v*` tags,
publishing to CodeArtifact domain `webbpulse`, repository `python`, in `us-west-2`. That
workflow is idempotent: it looks the version up first and skips with a notice rather than
failing, so re-running an already released tag stays green.

### Required repository configuration

| Secret | Used by | Value |
| --- | --- | --- |
| `CODEARTIFACT_PUBLISH_ROLE_ARN` | `publish.yml` | ARN of the OIDC role in the artifacts account allowed to publish to CodeArtifact |
| `CODEARTIFACT_DOMAIN_OWNER` | `publish.yml` | `432410731887`, the account that owns the `webbpulse` domain |

Both are passed straight through to the reusable workflow, which needs
`codeartifact:GetAuthorizationToken` and `sts:GetServiceBearerToken` on the assumed role.
The `publish` GitHub Environment named in `publish.yml` is where the release approval and
the environment-scoped secrets live; create it in repository settings. `ci.yml` needs no
secrets, because this package's own dependencies all come from PyPI.

### Cutting a release

The tag decides only *when* the workflow runs. The version that is published comes from
`src/webbpulse/_version.py` through hatchling, so set `__version__` and tag the same commit:

```bash
# edit src/webbpulse/_version.py to 0.2.0, commit it, then
git tag v0.2.0 && git push origin v0.2.0
```

Deriving the version from the tag instead would leave an sdist built outside a checkout
unversioned, and CodeArtifact rejects that.

## Per-app migration notes

Both backends grew these concerns independently, so the migration is mostly deletion. What
follows is what each app replaces, and what has to stay.

### CarModPicker

`backend/app/`. The app factory in `main.py` configures root logging inline, calls
`init_sentry()` before building the `FastAPI` object, then adds CORS, two
`@app.middleware("http")` functions and the error handlers.

| Shared module | Replaces |
| --- | --- |
| `config` | the pydantic-settings base and `.env` wiring in `core/config.py`, and the CORS origin parsing. The app's own fields become a subclass |
| `logging` | `core/logging.py` and the inline `logging.basicConfig` block in `main.py` |
| `log_context` | `core/log_context.py` in full: both ContextVars, `RequestContextFilter` and `bg_log_context` |
| `metrics` | `core/cloudwatch_emf.py` in full, and the `aws-embedded-metrics` dependency with it |
| `otel` | `core/sentry.py` in full, and its call from `main.py` |
| `http` | `api/utils/response_patterns.py`, `api/middleware/error_handler.py`, `api/middleware/request_context.py`, and the CORS block in `main.py` |
| `ratelimit` | `api/middleware/rate_limiter.py` in full, including `RateLimitConfig` and the eight `RATE_LIMIT_*` settings fields |
| `dynamodb` | `db/dynamo/client.py`, `serialization.py`, `errors.py`, and the generic body of `repository.py` |
| `security` | the password and JWT halves of `api/dependencies/auth.py`: `verify_password`, `get_password_hash`, `create_access_token` and the raw `jwt.decode` calls repeated across `endpoints/auth/core.py`. The user lookup, the `disabled` and `email_verified` checks and the admin dependencies stay |
| `lambda_entry` | `app/lambda_handler.py` entirely. The bare `Mangum(app, lifespan="off")` has no replacement import; the Web Adapter takes its place |
| `testing` | the moto and `reset_clients` fixture plumbing in `tests/conftest.py` |

Two things change behaviour rather than just moving:

- **Rate limiting becomes shared state.** The current limiter is in-process, eight
  `defaultdict(list)` timestamp lists, which counts per execution environment. Under Lambda
  that means the real ceiling is the configured limit multiplied by the number of warm
  environments, and it resets on every cold start. Moving to the DynamoDB table makes the
  limit mean what it says. The response headers change too: the per-minute and per-hour
  `X-RateLimit-*-Minute` / `-Hour` pairs become the single window described above, so any
  client parsing them needs checking.
- **Client IP stops trusting the caller.** `rate_limiter.py` reads the leftmost
  `X-Forwarded-For` hop and falls back to `request.client.host`. Behind API Gateway that
  leftmost hop is client-supplied, so the current limiter can be bypassed with one header.
  `client_ip` reads the API Gateway request context instead.

Secret loading also changes shape. `core/secrets.py` writes every key of the secret into
`os.environ`; `load_json_secret` returns a dict and caches it, leaving the environment
alone.

Staying in the app: the 25 `TableSpec` definitions, `car_inference.py` and
`category_inference.py`, the SES templates, `db/dynamo/search.py`,
`authorization.py`, the `chrome-extension://` CORS regex and the `null` origin, the
`X-Admin-Cron-Key` header, the `RUN_STARTUP_TASKS` seeding, and the sitemap routes. The
CORS regex and extra header mean `create_app` gets `cors_allow_origins` explicitly and the
app adds its own regex, rather than passing `settings` alone.

### WebbPulse-Portfolio

`backend/app/`. Smaller and closer to the shared shape already, but with no error envelope
and no request id at all.

| Shared module | Replaces |
| --- | --- |
| `config` | the `SECRET_FIELDS` / `resolve_secrets` validator, `LOCALHOST_ORIGINS` and `parse_cors_origins` in `config.py` |
| `logging` | `core/logging.py`, `RequestLoggingMiddleware` in `core/middleware.py`, and the `POWERTOOLS_*` settings |
| `log_context` | nothing. Portfolio has no request id or correlation context at all, so this is new capability |
| `metrics` | nothing. Portfolio emits no custom metrics today; this is what it would use when it starts |
| `otel` | the Powertools `inject_lambda_context` correlation wrapper |
| `http` | `TrailingSlashMiddleware`, the CORS block and the `/health` route in `main.py`. The error envelope and request id are new capability, not a replacement |
| `ratelimit` | `core/login_limiter.py` in full, including its `client_ip()` |
| `dynamodb` | `db/client.py` and `db/serializer.py` verbatim, the generic `Repository` base, and `table_name()` |
| `security` | the password and JWT halves of `core/security.py`: `_encode`, `verify_password`, `get_password_hash`, `create_access_token` and `verify_token`. `get_current_user` and `require_admin` stay, rebuilt on `bearer_claims` |
| `lambda_entry` | `app/lambda_handler.py` and `scripts/build_lambda.sh` |
| `testing` | the `mock_aws` fixture, `create_all_tables`, `db_client.reset()` and `secrets.reset_cache()` in `tests/conftest.py` |

Four things to watch:

- **`client_ip()` is the bug this package exists to fix.** It reads
  `request.scope["aws.event"]["requestContext"]["http"]["sourceIp"]` first. Mangum populates
  `aws.event`; the Web Adapter does not. So on migration that branch silently stops matching
  and the function falls through to the leftmost `X-Forwarded-For`, making the login limiter
  bypassable with one header, with nothing failing and no error logged.
- **The limiter moves table and gains fail-open.** Login failures are currently
  `LOGIN_FAIL#<ip>` items in the shared `meta` table; they move to the dedicated
  `<prefix>-rate-limits` table. The current code also propagates any `ClientError` other
  than the conditional failure, so DynamoDB being unavailable currently fails the login
  request closed. The shared limiter fails open and logs a WARNING instead.
- **`/health` must stop querying DynamoDB.** It currently calls `database_status()`, which
  reads the site content item. The Web Adapter polls that path on every cold start, so it
  has to become the liveness-only route; move the dependency check to a separate path.
- **Importing the app currently requires secrets.** The `resolve_secrets` validator raises
  when a secret field is still unset, so importing anything under `app/` fails without them.
  Settings construction moves behind an `lru_cache` accessor so that becomes a request-time
  failure rather than an import-time one.

Staying in the app: `PostRepository` and the per-entity ordering, `core/admin.py`,
`core/site_content.py` and `SeedMiddleware` (which must not be wired into the public
entrypoint), `api/seo.py`, the constant-time `_DUMMY_HASH` timing equaliser, the integer ids
and `skip`/`limit` the frontend depends on, and the trailing-slash tolerance.

### Adopting `log_context` and `metrics`

Both are additive, so each can land on its own without touching the other or anything
already migrated.

**CarModPicker** is an import swap and one deletion each.

- `core/log_context.py` is deleted. The three call sites that import from it,
  `api/dependencies/auth.py`, `api/middleware/request_context.py` and `core/sentry.py`,
  import from `webbpulse.log_context` instead. `RequestContextFilter` becomes
  `LogContextFilter` and `bg_log_context` becomes `task_context`, which is the same
  contract under a name that is not abbreviated; both emit the identical
  `bg:<task>:<job>` string, so no saved Logs Insights query changes. `tests/conftest.py`'s
  `caplog_with_context` fixture and `tests/test_log_propagation.py` follow the same
  rename. `core/logging.py`'s `_attach_request_context` becomes a call to
  `attach_log_context()`.
- `api/middleware/request_context.py` can go entirely once `RequestIdMiddleware` is
  mounted, since that middleware now sets `request.state` and binds the ContextVar and
  echoes the header, which is everything the local one did. Until then the local
  middleware keeps working: it sets the same ContextVar under the same name.
- `core/logging.py`'s local `configure_logging` wrapper can go as of 0.8.0. It existed for
  two reasons and both are now arguments: `stream=sys.stderr` for the commands whose stdout
  is data and is compared byte for byte, and `formatter="text"` for a readable line on a
  TTY. The deployed call passes neither and is byte identical to what it emits today.
- `core/cloudwatch_emf.py` is a straight deletion, not a swap. It has no call site left:
  `emit_crawler_run_metrics` served a crawler tree that the DynamoDB and Lambda migration
  removed, which CarModPicker's own `docs/migration/split-plan.md` already lists as dead
  code to delete on the way through. Deleting it drops `aws-embedded-metrics` from
  `requirements.txt` and `requirements-lambda.txt` and lets `AWS_EMF_ENVIRONMENT=Local`
  come out of the Terraform, since there is no sink to auto-detect any more.
- `webbpulse.metrics` is then what CarModPicker uses for its *next* metric rather than a
  replacement for a current one. The shape is preserved regardless: `emit` with a
  `namespace`, three `Count` and `Seconds` metrics and `AdapterName`/`Environment`/`RunType`
  dimensions reproduces the old document byte for byte, so a restored crawler would keep
  plan 02-05's alarm matching. That equivalence is pinned by a test in this package.
- The gate that module carried, silent unless `TESTING` is not `"true"` and the environment
  is staging or production, is `metrics_enabled_from_env` as of 0.8.0 rather than something
  to reimplement at the next call site.

**WebbPulse-Portfolio** gains capability rather than replacing any.

- It has no request id today. Mounting `RequestIdMiddleware`, which the `http` migration
  already brings, is what starts populating `request_id` on every log line, with no other
  change.
- Its logger is `aws_lambda_powertools.Logger`, whose `inject_lambda_context` correlation
  wrapper does not run under the Web Adapter, since there is no handler to decorate. That
  is the gap `log_context` fills, and it is why the Powertools dependency can go at the
  same time as `core/logging.py`.
- Its `get_current_user` is a `def` dependency, so the `set_user_id` call in it binds
  nothing. That is the trap above, and the fix is to wrap it once at the call site with
  `user_id_dependency`; the resolver itself does not have to change and can stay `def`.
- It emits no custom metrics. `webbpulse.metrics` is what it uses when it starts, with its
  own namespace; nothing has to change for the adoption itself.

### Not shared, deliberately

The **primitives** of authentication are shared as of 0.5.0, in `webbpulse.security`. Up to
0.4.0 they were not, on the grounds that the two apps disagreed on JWT library, bcrypt major
version, 72 byte truncation and default rounds. Checking that reasoning found half of it
wrong: the default cost is 12 on both bcrypt 4.3.0 and 5.0.0, and CarModPicker passes 12
explicitly, so no stored hash changes. The truncation difference was real, and was already a
live 500 in CarModPicker rather than a reason to keep two copies. Hashes verify across both
bcrypt majors and HS256 tokens across both JWT libraries, both verified in the test suite.

What stays per-app is the **policy** above those primitives, and it is most of the file in
each case: which claim carries the identity, the user lookup behind it, whether an inactive
or unverified account may authenticate, the admin and superuser checks, the per-user session
expiry clamp, the constant-time `_DUMMY_HASH` equaliser, and every OAuth, WebAuthn and TOTP
flow. `decode_token` returns the claims and stops; the rest is the service's.
