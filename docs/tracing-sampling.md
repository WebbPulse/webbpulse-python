# Tracing: sampling and the Lambda flush

The tail sampler that always keeps an error trace, its memory bound, the shutdown flush, and
the environment variables that configure export. The rest of `webbpulse.otel` is in
[tracing.md](tracing.md). Back to the [README](../README.md).

### Sampling: errors are always kept

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

#### The flush is not optional, and it is wired for you

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

#### The memory bound

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

#### In-flight traces

A trace is judged only once every span in it has ended. `force_flush` resolves the traces
with no open spans and leaves the rest buffered. Without that, one request's flush would
judge another request's half-built trace on whichever spans happened to have ended, usually
dropping it, and then judge the remainder separately when it arrived, so one logical trace
could end up half exported and half discarded. Deferring costs nothing, because the request
that owns the trace flushes when it finishes. `shutdown_tracing()` is the exception: there is
no later, so it resolves everything.

#### Environment variables

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

#### Why the sampler is explicit

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

#### A note on `AlwaysRecordSampler`

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
