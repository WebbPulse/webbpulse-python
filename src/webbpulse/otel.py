"""OpenTelemetry tracing, exported to AWS X-Ray over the OTLP endpoint.

OpenTelemetry is the only instrumentation in this package. There is no Sentry, no vendor
SDK, no ADOT collector, no sidecar and no Lambda extension. Everything below runs in
process, in the application, built by `configure_tracing`.

That last point is a deliberate design choice rather than an omission. The obvious
alternative is to launch under `opentelemetry-instrument` and let the ADOT distribution's
configurator build the pipeline from environment variables. It is rejected here because
that configurator calls `set_tracer_provider` itself, and the global provider is set-once
per process: whichever of the configurator and `configure_tracing` ran first would win and
the other would be silently ignored, giving either a provider with no tail sampling or one
with no signed exporter, with nothing in the logs to say which. Owning the whole pipeline in
one place removes that race. It also means a service starts with a plain
`python -m app.entrypoints.<domain>` rather than an instrumentation wrapper, which is what
the container images actually do.

Only the distribution's *exporter class* is borrowed, and only for the signing it provides.

## The X-Ray OTLP endpoint

CloudWatch exposes an OTLP trace endpoint at `https://xray.<region>.amazonaws.com/v1/traces`
which accepts OTLP over HTTP with a protobuf or JSON body. There is no gRPC listener. The
protocol is not configured by environment variable here: `_build_span_exporter` constructs
an HTTP protobuf exporter class directly, so `http/protobuf` is implicit in the code rather
than something a deployment can get wrong.

Three things about it are easy to get wrong and each looks identical from the outside,
which is traces silently never appearing:

1. **The endpoint authenticates with SigV4.** A plain OTLP exporter posts unsigned and gets
   a 403, which the exporter then retries quietly, so it looks exactly like having no
   traffic. Signing is not something this module implements: `OTLPAwsSpanExporter` from
   `aws-opentelemetry-distro` subclasses the plain HTTP exporter and swaps in a `requests`
   session that signs each request for the `xray` service. Install it with the `aws-otel`
   extra, `pip install "webbpulse[otel,aws-otel]"`. `_build_span_exporter` selects it
   automatically for an X-Ray endpoint, and warns and falls back to the unsigned exporter
   when the extra is missing rather than crashing a cold start.
2. **Transaction Search has to be enabled on the account** for the endpoint to accept
   spans. It is a one-time per-account setting, not something an application can do.
3. **The execution role needs write access to X-Ray.** Attach the `AWSXrayWriteOnlyAccess`
   managed policy, `arn:aws:iam::aws:policy/AWSXrayWriteOnlyAccess`, which grants
   `xray:PutTraceSegments`, `xray:PutTelemetryRecords` and the three sampling reads. Active
   tracing with no permission records nothing. Note there is no `AWSXrayWriteOnlyPolicy`:
   that name does not exist in the managed policy reference, so an ARN built from it fails
   a Terraform apply with NoSuchEntity.

## Sampling: why this module tail samples

The decision is 100 percent of traces on staging, 10 percent on production, and errors are
*always* kept. Head sampling cannot deliver the last clause. A head sampler runs in
`should_sample` at the moment the root span starts, which is before the request has been
handled, so it cannot know whether the request is about to fail. Setting
`OTEL_TRACES_SAMPLER=parentbased_traceidratio` with an arg of 0.1 therefore throws away 90
percent of the failures too, which is exactly the 90 percent worth keeping.

So this module records everything and decides at export time instead:

* The provider is built with an explicit `ParentBased(root=ALWAYS_ON)` sampler. Every root
  span is recorded, and a span with an upstream parent follows that parent's decision, so a
  sampled-out decision arriving from API Gateway or an X-Ray propagated header is still
  honoured rather than being overridden here.
* `TailSamplingSpanProcessor` sits in front of the real exporter. Ended spans are buffered
  in memory, keyed by trace id, and nothing is handed to the exporter until a flush.
* At flush time each buffered trace is judged once. It is exported if **either** any span in
  it carries `StatusCode.ERROR` or an `exception` event, **or** its trace id falls below the
  configured probability. Otherwise every span in it is dropped and a counter moves.

The probability test is the SDK's own `TraceIdRatioBased` arithmetic, reimplemented here
because the SDK exposes it only through a `Sampler` and a tail decision has no
`should_sample` call to make: keep when
`trace_id & ((1 << 64) - 1) < round(ratio * (1 << 64))`. Using the identical bound matters
because it makes the decision a pure function of the trace id, so this service and any
upstream or downstream service configured at the same ratio agree on the same traces
without coordinating. A trace that API Gateway or an upstream service already sampled in is
therefore also sampled in here, and the tail step only ever *adds* the error traces on top.

## The memory bound

Buffering is per trace and unbounded buffering in a Lambda is a way to run out of memory on
a slow request that produces thousands of spans. `max_spans_per_trace` (default 2048) caps
it. When a trace exceeds the cap the buffer for that trace is not grown any further and the
overflow is resolved by `on_overflow`:

* `"export"` (the default) marks the trace as sampled immediately and streams that trace's
  spans straight through to the exporter from then on. A trace big enough to overflow is
  unusual by definition, so keeping it is the useful bias, and the memory is bounded because
  nothing further accumulates for it.
* `"drop"` discards the trace and increments `dropped_traces`. Choose it when a hard ceiling
  on egress matters more than seeing the outlier.

That bounds one trace. The *number* of traces is bounded separately by
`max_buffered_traces` (default 1024), because a buffer is only drained when its trace
completes and a flush comes round: a trace that never completes, because the request was
abandoned or a span was leaked, would otherwise sit there for the life of the process. Past
the ceiling the oldest completed trace is evicted, and evicting means judging it now rather
than discarding it, so an error trace that was about to be kept is still exported. A trace
with spans still open is never evicted, for the same reason a flush never judges one.

The total is therefore bounded by `max_spans_per_trace * max_buffered_traces`, and in
practice sits far below it, because under the Web Adapter a flush runs on every request.

## Flushing and in-flight traces

A trace is only judged once every span in it has ended. `on_start` and `on_end` keep a
per-trace count of open spans, and `force_flush` resolves only the traces at zero, leaving
the rest buffered. Without that, one request's flush would judge another request's
half-built trace on whichever spans happened to have ended, usually dropping it, and then
judge the remainder separately when it arrived, so a single logical trace could end up half
exported and half discarded. Deferring costs nothing, because the request that owns the
trace flushes when it finishes. `shutdown` is the exception: there is no later, so it
resolves everything, in flight or not.

## Lambda and force_flush

A Lambda invocation ends when the response is written, and the execution environment is
frozen immediately afterwards. The tail decision is made at flush time, so the flush is not
optional: without it the buffered spans sit in a frozen process until the next invoke, and
are lost entirely when the environment is reclaimed.

Under the Lambda Web Adapter there is no handler to hook, and "after the invocation" is not
a place code can run: a `BackgroundTask`, an `asyncio` task or an `atexit` hook all schedule
work that the freeze catches mid-flight. The flush therefore has to happen *inside* the
request, after the handler has produced the response and before that response is handed
back to the adapter. `instrument_fastapi` installs a Starlette middleware that does exactly
that. It is on by default when `AWS_LAMBDA_FUNCTION_NAME` is set and off otherwise, since a
long-lived server can flush on its own schedule; `flush_per_request` overrides the
detection either way. The flush is bounded by `flush_timeout_millis` and never raises into
the request, because a telemetry failure that turned a healthy 200 into a 500 would be
worse than the trace it was reporting on.

`flush_tracing()` is the same call for anything that is not a FastAPI app, and
`shutdown_tracing()` flushes too, which covers the container shutdown path.

## Cold start

`configure_tracing` is a function called from the composition root, never module-level work.
Instrumentation is applied once per process and guarded, so a warm invoke does nothing.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import TYPE_CHECKING, Any, Final, Literal, cast

if TYPE_CHECKING:  # pragma: no cover - typing only
    from fastapi import FastAPI
    from opentelemetry.context import Context
    from opentelemetry.sdk.trace import ReadableSpan, Span, SpanProcessor
    from opentelemetry.sdk.trace.export import SpanExporter

__all__ = [
    "OTEL_DISABLED_ENV",
    "SAMPLE_RATIO_ENV",
    "TailSamplingSpanProcessor",
    "configure_tracing",
    "flush_tracing",
    "instrument_fastapi",
    "is_tracing_enabled",
    "resolve_sample_ratio",
    "shutdown_tracing",
    "xray_otlp_endpoint",
]

_log = logging.getLogger(__name__)

#: Set this to any of `1`, `true`, `yes`, `on` to make every entry point here a no-op.
OTEL_DISABLED_ENV: Final = "WEBBPULSE_OTEL_DISABLED"

#: The tail sampling probability, `0.0` to `1.0`. Terraform sets this per environment.
SAMPLE_RATIO_ENV: Final = "WEBBPULSE_OTEL_SAMPLE_RATIO"

_TRUTHY: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})

#: The SDK's `TraceIdRatioBased` compares the low 64 bits of the trace id, for compatibility
#: with 64 bit trace ids. Matching that exactly is what makes the decision here agree with an
#: upstream service running the stock sampler at the same ratio.
_TRACE_ID_LIMIT: Final = (1 << 64) - 1

#: The event name the SDK gives `Span.record_exception`, and therefore the name FastAPI and
#: botocore instrumentation produce for a failed call.
_EXCEPTION_EVENT_NAME: Final = "exception"

#: Per-trace buffer ceiling. 2048 spans is far above a normal request against this estate and
#: still small enough that a handful of concurrent traces cannot exhaust a 512MB Lambda.
_DEFAULT_MAX_SPANS_PER_TRACE: Final = 2048

#: Ceiling on the number of traces buffered at once. Under the Web Adapter a flush runs every
#: request, so a single-digit number of traces is buffered in practice; 1024 is far above
#: that and still bounds a leak.
_DEFAULT_MAX_BUFFERED_TRACES: Final = 1024

#: How long a trace may sit buffered before it is judged early. This is what reclaims a trace
#: whose spans never end, which the count bound alone cannot, since it refuses to evict an
#: in-flight trace. Comfortably longer than any request that has not already hit the Lambda
#: timeout, so a real request is never judged early.
_DEFAULT_MAX_TRACE_AGE_SECONDS: Final = 300.0

#: Default ceiling on an export, and so on the in-request flush. Short on purpose: it is
#: latency a user is waiting on, and a flush that cannot finish in a second is one whose
#: spans are better dropped than paid for. This is passed to the exporter as its `timeout`,
#: which it applies as a deadline across the whole export including retries. That is the only
#: thing that actually bounds the flush, because the flush itself exports synchronously: left
#: at the exporter's own default the worst case is 10 seconds with six retries behind it.
_DEFAULT_FLUSH_TIMEOUT_MILLIS: Final = 1000

OverflowPolicy = Literal["export", "drop"]

# Set once configure_tracing has installed a provider, so a second call is a no-op rather
# than a second span processor quietly double-exporting every span.
_CONFIGURED = False

# The processor configure_tracing installed, kept so flush_tracing can reach it without
# depending on the provider exposing its processors.
_PROCESSOR: TailSamplingSpanProcessor | None = None

#: The export deadline `configure_tracing` gave the exporter, so `instrument_fastapi` can
#: default the in-request flush to the same value. Two different numbers here would be
#: misleading, since the exporter's is the one that binds.
_EXPORT_TIMEOUT_MILLIS: int = _DEFAULT_FLUSH_TIMEOUT_MILLIS

#: Marks an app whose middleware stack already carries the flush wrapper.
_FLUSH_WRAPPED_ATTR: Final = "_webbpulse_flush_wrapped"


def is_tracing_enabled() -> bool:
    """Whether tracing should be set up at all.

    Disabled explicitly by `WEBBPULSE_OTEL_DISABLED`, and by OpenTelemetry's own
    `OTEL_SDK_DISABLED`, which the specification defines and which tooling already honours.
    """
    if os.environ.get(OTEL_DISABLED_ENV, "").strip().lower() in _TRUTHY:
        return False
    return os.environ.get("OTEL_SDK_DISABLED", "").strip().lower() not in _TRUTHY


def xray_otlp_endpoint(region: str | None = None) -> str:
    """The CloudWatch X-Ray OTLP trace endpoint for a region.

    Falls back to `AWS_REGION`, which Lambda always sets, and then to `us-west-2`, which is
    the only region this estate runs in.
    """
    resolved = (
        region
        or os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
        or "us-west-2"
    )
    return f"https://xray.{resolved}.amazonaws.com/v1/traces"


def _coerce_ratio(raw: str, source: str) -> float | None:
    """Parse a ratio from an environment variable, refusing anything outside `[0.0, 1.0]`."""
    try:
        value = float(raw)
    except (TypeError, ValueError):
        _log.warning("Ignoring unparseable sampling ratio.", extra={"source": source, "value": raw})
        return None
    if not 0.0 <= value <= 1.0:
        _log.warning(
            "Ignoring out-of-range sampling ratio; it must be between 0.0 and 1.0.",
            extra={"source": source, "value": raw},
        )
        return None
    return value


def resolve_sample_ratio(explicit: float | None = None) -> float:
    """The tail sampling probability, from the argument or the environment.

    Precedence, first match wins:

    1. `explicit`, the `sample_ratio` keyword passed to `configure_tracing`.
    2. `WEBBPULSE_OTEL_SAMPLE_RATIO`, which is what Terraform sets per environment.
    3. `OTEL_TRACES_SAMPLER_ARG`, but only when `OTEL_TRACES_SAMPLER` is `traceidratio` or
       `parentbased_traceidratio`. Reading the arg under any other sampler name would invent
       a ratio out of a value the specification says is meaningless there.
    4. `1.0`, keeping every trace, which is the safe default for a new service.

    An unparseable or out-of-range value is warned about and skipped rather than raising, so
    a typo in a Terraform variable degrades to more traces rather than to a cold start crash.
    """
    if explicit is not None:
        if not 0.0 <= explicit <= 1.0:
            raise ValueError(f"sample_ratio must be between 0.0 and 1.0, got {explicit!r}")
        return explicit

    candidates: list[tuple[str, str]] = []
    if raw := os.environ.get(SAMPLE_RATIO_ENV, "").strip():
        candidates.append((SAMPLE_RATIO_ENV, raw))

    # `OTEL_TRACES_SAMPLER_ARG` only carries a ratio under the two ratio samplers. Under
    # `always_on` it is unset or meaningless, and reading it there would invent a ratio.
    sampler = os.environ.get("OTEL_TRACES_SAMPLER", "").strip().lower()
    is_ratio_sampler = sampler in ("traceidratio", "parentbased_traceidratio")
    if is_ratio_sampler and (raw := os.environ.get("OTEL_TRACES_SAMPLER_ARG", "").strip()):
        candidates.append(("OTEL_TRACES_SAMPLER_ARG", raw))

    for source, raw in candidates:
        if (value := _coerce_ratio(raw, source)) is not None:
            return value

    return 1.0


def _ratio_bound(ratio: float) -> int:
    """The keep threshold for a ratio, identical to `TraceIdRatioBased.get_bound_for_rate`."""
    return round(ratio * (_TRACE_ID_LIMIT + 1))


def _trace_id_is_sampled(trace_id: int, bound: int) -> bool:
    """The SDK's `TraceIdRatioBased` decision, as a pure function of the trace id.

    The SDK only exposes this through `Sampler.should_sample`, which a tail decision has no
    call to make: by export time the span has already been created and its sampling flag set.
    Reimplementing the arithmetic rather than approximating it is what keeps this service in
    agreement with an upstream one running the stock sampler at the same ratio, so a trace is
    either kept end to end or dropped end to end instead of being kept in fragments.
    """
    return (trace_id & _TRACE_ID_LIMIT) < bound


def _span_signals_error(span: ReadableSpan) -> bool:
    """Whether a span marks its trace as one that must be kept.

    Two signals, because instrumentations use both. `FastAPIInstrumentor` sets
    `StatusCode.ERROR` on a 5xx response, while `record_exception`, which the SDK calls from
    `Span.__exit__` and which botocore's instrumentation calls on a client error, adds an
    `exception` event and does not always set the status.
    """
    from opentelemetry.trace import StatusCode

    if span.status.status_code is StatusCode.ERROR:
        return True
    return any(event.name == _EXCEPTION_EVENT_NAME for event in span.events or ())


class TailSamplingSpanProcessor:
    """Buffers spans per trace and decides at flush time whether to export the trace.

    Structurally a `SpanProcessor`, but deliberately not a subclass of one: this module
    imports on the base install, where `opentelemetry.sdk` is absent, so naming the SDK base
    class here would make `import webbpulse.otel` fail without the `otel` extra. The SDK's
    `SpanProcessor` declares no abstract methods, and the five hooks the SDK actually invokes
    on a registered processor are `on_start`, `_on_ending`, `on_end`, `force_flush` and
    `shutdown`, all of which are implemented below. `_on_ending` is private but not optional:
    `Span.end` calls it unconditionally through the multi-processor, so omitting it raises an
    `AttributeError` on the first span that ends.

    This is the processor that performs the actual export, so it wraps the real exporter
    rather than sitting alongside one. Register exactly one of these and no
    `BatchSpanProcessor` for the same exporter, or every kept trace is exported twice.

    Args:
        exporter: the `SpanExporter` a kept trace is handed to. Normally the OTLP HTTP
            exporter; an `InMemorySpanExporter` in tests.
        sample_ratio: probability in `[0.0, 1.0]` that a non-error trace is kept.
        always_sample_errors: keep a trace when any of its spans has `StatusCode.ERROR` or an
            `exception` event. Turning this off reduces the processor to a tail-side
            reimplementation of head ratio sampling, which is only useful for comparison.
        max_spans_per_trace: per-trace buffer ceiling.
        on_overflow: what to do with a trace that exceeds the ceiling. `"export"` keeps it
            and streams the rest of it straight through; `"drop"` discards it.
        max_buffered_traces: ceiling on the *number* of traces buffered at once, which is the
            other half of the memory bound. See `_evict_oldest`.
    """

    def __init__(
        self,
        exporter: SpanExporter,
        *,
        sample_ratio: float = 1.0,
        always_sample_errors: bool = True,
        max_spans_per_trace: int = _DEFAULT_MAX_SPANS_PER_TRACE,
        on_overflow: OverflowPolicy = "export",
        max_buffered_traces: int = _DEFAULT_MAX_BUFFERED_TRACES,
        max_trace_age_seconds: float = _DEFAULT_MAX_TRACE_AGE_SECONDS,
    ) -> None:
        if not 0.0 <= sample_ratio <= 1.0:
            raise ValueError(f"sample_ratio must be between 0.0 and 1.0, got {sample_ratio!r}")
        if max_spans_per_trace < 1:
            raise ValueError(f"max_spans_per_trace must be at least 1, got {max_spans_per_trace!r}")
        if on_overflow not in ("export", "drop"):
            raise ValueError(f"on_overflow must be 'export' or 'drop', got {on_overflow!r}")
        if max_buffered_traces < 1:
            raise ValueError(f"max_buffered_traces must be at least 1, got {max_buffered_traces!r}")
        if max_trace_age_seconds <= 0:
            raise ValueError(
                f"max_trace_age_seconds must be positive, got {max_trace_age_seconds!r}"
            )

        self._exporter = exporter
        self._sample_ratio = sample_ratio
        self._bound = _ratio_bound(sample_ratio)
        self._always_sample_errors = always_sample_errors
        self._max_spans_per_trace = max_spans_per_trace
        self._on_overflow: OverflowPolicy = on_overflow
        self._max_buffered_traces = max_buffered_traces
        self._max_trace_age_seconds = max_trace_age_seconds

        # on_end runs on whichever thread ended the span, and uvicorn serves on a thread
        # pool, so the buffers need a lock even though a Lambda invocation is one request.
        self._lock = threading.Lock()
        # Insertion-ordered, which `_evict_oldest` relies on to find the oldest trace.
        self._buffers: dict[int, list[ReadableSpan]] = {}
        # Spans started but not yet ended, per trace. A trace is only safe to judge at zero:
        # judging it earlier judges a partial trace, and the spans that arrive afterwards are
        # then judged again as if they were a second, separate trace.
        self._open_spans: dict[int, int] = {}
        # When each buffered trace was first seen, for the age bound. Insertion-ordered, so
        # the oldest is first and `_evict_locked` can stop scanning at the first young one.
        self._started_at: dict[int, float] = {}
        # Traces already resolved to "keep" by an overflow, whose later spans stream through.
        self._overflowed_keep: set[int] = set()
        # Traces already resolved to "drop" by an overflow, whose later spans are discarded.
        self._overflowed_drop: set[int] = set()
        self._shutdown = False

        #: Traces discarded because they exceeded the cap under `on_overflow="drop"`. Read it
        #: from a test or log it on shutdown; it is the only trace of an overflow drop.
        self.dropped_traces = 0
        #: Traces dropped by the ratio, which is the ordinary non-error path.
        self.sampled_out_traces = 0
        #: Traces handed to the exporter.
        self.exported_traces = 0
        #: Traces evicted because too many were buffered at once. Distinct from
        #: `dropped_traces`, which counts the per-trace span cap.
        self.evicted_traces = 0

    @property
    def sample_ratio(self) -> float:
        return self._sample_ratio

    def on_start(self, span: Span, parent_context: Context | None = None) -> None:
        """Count the span as in flight, so a flush knows the trace is not complete yet.

        Without this a `force_flush` from one request judges a trace that another request is
        still building. The partial trace is judged on the spans that happen to have ended,
        typically dropped, and the spans that arrive afterwards are judged all over again as
        if they were a separate trace, so one logical trace can be half exported and half
        discarded. Counting starts and ends and only resolving traces at zero is what makes
        the decision per trace rather than per flush.
        """
        context = span.get_span_context()
        if context is None:
            return
        with self._lock:
            self._open_spans[context.trace_id] = self._open_spans.get(context.trace_id, 0) + 1

    def _on_ending(self, span: Span) -> None:
        """Called by `Span.end` before `on_end`. Nothing to mutate before the buffer."""

    def on_end(self, span: ReadableSpan) -> None:
        """Buffer an ended span, or stream it through if its trace already overflowed.

        Note what is *not* here: the SDK's own `BatchSpanProcessor` and `SimpleSpanProcessor`
        both open with `if not span.context.trace_flags.sampled: return`. Filtering on that
        flag would defeat the point, because the flag records a head decision and this
        processor exists to make a later one. It also matters under the ADOT distro, whose
        `AlwaysRecordSampler` turns a head `DROP` into `RECORD_ONLY`: such a span is fully
        recorded but has the flag clear, and it is exactly the span a failing request under a
        low ratio produces.
        """
        if self._shutdown:
            return
        context = span.get_span_context()
        if context is None:
            return
        trace_id = context.trace_id

        stream: list[ReadableSpan] = []
        with self._lock:
            complete = self._close_span_locked(trace_id)

            if trace_id in self._overflowed_drop:
                if complete:
                    self._overflowed_drop.discard(trace_id)
                return
            if trace_id in self._overflowed_keep:
                # Already resolved to keep, so nothing accumulates for this trace.
                stream = [span]
                if complete:
                    self._overflowed_keep.discard(trace_id)
            else:
                buffer = self._buffers.setdefault(trace_id, [])
                self._started_at.setdefault(trace_id, time.monotonic())
                if len(buffer) < self._max_spans_per_trace:
                    buffer.append(span)
                    self._evict_locked()
                else:
                    stream = self._resolve_overflow_locked(trace_id, buffer, span)

        # Deliberately outside the lock. `export` is an HTTP round trip to the X-Ray
        # endpoint, and holding the lock across it would make every `on_end` in the process
        # block on the network, serialising span completion behind telemetry egress.
        self._export(stream)

    def _close_span_locked(self, trace_id: int) -> bool:
        """Decrement a trace's open-span count. Returns whether it just reached zero.

        An overflowed trace stays counted here even though its buffer is gone, because the
        count is what tells the marker when it is safe to drop. Without that the markers are
        the one structure nothing ever reclaims: `force_flush` only walks `_buffers`, and an
        overflowed trace has no buffer, so its marker would live for the process. Under
        `on_overflow="drop"` a retained marker also means a later trace that happened to
        reuse the id would be discarded in silence.
        """
        remaining = self._open_spans.get(trace_id)
        if remaining is None:
            return False
        if remaining <= 1:
            del self._open_spans[trace_id]
            return True
        self._open_spans[trace_id] = remaining - 1
        return False

    def _resolve_overflow_locked(
        self, trace_id: int, buffer: list[ReadableSpan], span: ReadableSpan
    ) -> list[ReadableSpan]:
        """Resolve a trace that hit the per-trace cap. Returns the spans to export."""
        del self._buffers[trace_id]
        self._started_at.pop(trace_id, None)
        if self._on_overflow == "drop":
            self._overflowed_drop.add(trace_id)
            self.dropped_traces += 1
            _log.warning(
                "Dropped a trace that exceeded the tail sampling buffer cap.",
                extra={
                    "otel_trace_id": f"{trace_id:032x}",
                    "max_spans_per_trace": self._max_spans_per_trace,
                },
            )
            return []

        self._overflowed_keep.add(trace_id)
        _log.warning(
            "Exporting a trace that exceeded the tail sampling buffer cap without a "
            "sampling decision.",
            extra={
                "otel_trace_id": f"{trace_id:032x}",
                "max_spans_per_trace": self._max_spans_per_trace,
            },
        )
        return [*buffer, span]

    def _evict_locked(self) -> None:
        """Keep the buffer bounded in both count and age.

        Two ceilings, because they catch different failures. `max_buffered_traces` bounds how
        many traces are held at once, and `max_trace_age_seconds` bounds how long any one of
        them is held. The age bound is the load-bearing one: the count bound can only evict a
        trace with no spans still open, since evicting an in-flight trace early is the
        partial-judgement bug this class exists to avoid, so a supply of traces that never
        complete, a leaked span or an abandoned request, would otherwise pin every buffer and
        the count bound would never fire. Under Lambda nothing else ever reclaims those.

        Eviction means judging the trace now, not discarding it, so an error trace that was
        about to be kept is still exported. Age eviction is the one place a trace can be
        judged while still in flight, which is a deliberate trade: a trace that has been open
        for five minutes is not a request in progress, it is a leak, and half of it is worth
        more than none of it.
        """
        now = time.monotonic()
        deadline = now - self._max_trace_age_seconds
        # Insertion-ordered, so the oldest is first and the scan stops at the first trace
        # young enough to keep. Ages only need checking while something is actually old.
        for trace_id, started in list(self._started_at.items()):
            if started > deadline:
                break
            self._evict_one_locked(trace_id, reason="age")

        while len(self._buffers) > self._max_buffered_traces:
            evictable = next(
                (t for t in self._buffers if not self._open_spans.get(t)),
                None,
            )
            if evictable is None:
                # Everything buffered is still in flight, so there is nothing safe to evict
                # on count alone. The per-trace cap still bounds each one and the age bound
                # will reclaim them once they are genuinely stale.
                return
            self._evict_one_locked(evictable, reason="count")

    def _evict_one_locked(self, trace_id: int, *, reason: str) -> None:
        """Resolve one trace early and account for it. Called with the lock held."""
        spans = self._buffers.pop(trace_id, None)
        self._started_at.pop(trace_id, None)
        if spans is None:
            return
        self.evicted_traces += 1
        _log.warning(
            "Evicting a buffered trace before its request flushed.",
            extra={
                "otel_trace_id": f"{trace_id:032x}",
                "eviction_reason": reason,
                "open_spans": self._open_spans.get(trace_id, 0),
                "max_buffered_traces": self._max_buffered_traces,
                "max_trace_age_seconds": self._max_trace_age_seconds,
            },
        )
        if self._should_keep(trace_id, spans):
            self.exported_traces += 1
            # Under the lock by necessity: the caller holds it. Eviction is a pathological
            # path, so a blocking export there is the right trade against the bookkeeping
            # needed to defer it.
            self._export(spans)
        else:
            self.sampled_out_traces += 1

    def _export(self, spans: list[ReadableSpan]) -> None:
        """Hand spans to the exporter. Must not be called with the lock held, except from
        `_evict_one_locked`, which documents why it is the exception."""
        if not spans:
            return
        try:
            self._exporter.export(spans)
        except Exception:  # pragma: no cover - an exporter must never break the request
            _log.exception("The span exporter raised while exporting a sampled trace.")

    def _should_keep(self, trace_id: int, spans: list[ReadableSpan]) -> bool:
        """The tail decision for one buffered trace."""
        if self._always_sample_errors and any(_span_signals_error(span) for span in spans):
            return True
        return _trace_id_is_sampled(trace_id, self._bound)

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        """Resolve every *completed* buffered trace and export the ones that are kept.

        This is where the tail decision happens, so a Lambda invocation must reach it before
        the process is frozen. Returns the wrapped exporter's own flush result.

        A trace with spans still open is left buffered rather than judged. Under a
        concurrent server one request's flush would otherwise resolve another request's
        half-built trace, drop it on the strength of the spans that happened to have ended,
        and then judge the rest of it separately when it arrives. Leaving it alone costs
        nothing: the request that owns it flushes when it finishes.
        """
        to_export: list[list[ReadableSpan]] = []
        with self._lock:
            complete = [
                trace_id for trace_id in self._buffers if not self._open_spans.get(trace_id)
            ]
            for trace_id in complete:
                spans = self._buffers.pop(trace_id)
                self._started_at.pop(trace_id, None)
                # Only now is this trace's overflow marker meaningless. Clearing markers for
                # a trace that is still open would let its tail start buffering again and be
                # judged a second time, so a "keep" could become a "drop", and under
                # `on_overflow="drop"` fragments of a dropped trace could be exported.
                self._overflowed_keep.discard(trace_id)
                self._overflowed_drop.discard(trace_id)
                if self._should_keep(trace_id, spans):
                    self.exported_traces += 1
                    to_export.append(spans)
                else:
                    self.sampled_out_traces += 1

        # Outside the lock, for the same reason as `on_end`.
        for spans in to_export:
            self._export(spans)

        flush = getattr(self._exporter, "force_flush", None)
        if callable(flush):
            result = flush(timeout_millis)
            return bool(result) if result is not None else True
        return True

    def shutdown(self) -> None:
        """Resolve everything still buffered, in flight or not, then shut the exporter down.

        `force_flush` deliberately leaves in-flight traces alone because their owning request
        will flush them later. At shutdown there is no later, so an incomplete trace is
        judged on what it has rather than discarded silently: a half-recorded error trace is
        still the most useful thing in the buffer.
        """
        with self._lock:
            self._open_spans.clear()
        self.force_flush()
        self._shutdown = True
        self._exporter.shutdown()


def _xray_region(endpoint: str) -> str | None:
    """The region an X-Ray OTLP endpoint signs for, or `None` if it is not one.

    Two host shapes are X-Ray, and both must be recognised precisely, because getting either
    half wrong is a silent 403:

    * `xray.<region>.amazonaws.com`, the public endpoint.
    * `xray-fips.<region>.amazonaws.com`, the FIPS 140-3 endpoint, which is a real endpoint
      in botocore's endpoint data and signs for `xray` exactly like the public one. Missing
      it means a caller who is required to use FIPS gets an unsigned exporter and a silent
      403, which is the worst possible failure for the one caller who cannot simply switch.
    * `<vpce-id>.xray.<region>.vpce.amazonaws.com`, the interface VPC endpoint, which a
      function in a private subnet with no NAT gateway has to use.

    A substring test for `.amazonaws.com` would match any AWS-hosted OTLP endpoint and sign
    requests that should not be signed, and reading the region from `AWS_REGION` instead of
    the host would sign a VPC endpoint or an explicit cross-region endpoint for the wrong
    region, which fails as a credential scope mismatch rather than as anything legible.
    """
    from urllib.parse import urlparse

    parsed = urlparse(endpoint)
    if not parsed.path.startswith("/v1/traces"):
        return None
    labels = (parsed.hostname or "").lower().split(".")

    # xray.<region>.amazonaws.com and xray-fips.<region>.amazonaws.com
    if (
        len(labels) == 4
        and labels[0] in ("xray", "xray-fips")
        and labels[2:] == ["amazonaws", "com"]
    ):
        return labels[1]
    # <vpce-id>.xray.<region>.vpce.amazonaws.com
    if len(labels) == 6 and labels[1] == "xray" and labels[3:] == ["vpce", "amazonaws", "com"]:
        return labels[2]
    return None


def _is_xray_endpoint(endpoint: str) -> bool:
    """Whether an endpoint is a CloudWatch X-Ray OTLP one, which requires SigV4."""
    return _xray_region(endpoint) is not None


def _region_for_endpoint(endpoint: str) -> str:
    """The region to sign for, taken from the endpoint host rather than guessed.

    `https://xray.us-west-2.amazonaws.com/v1/traces` signs for `us-west-2`, and so does its
    VPC endpoint form. Deriving it from the endpoint rather than from `AWS_REGION` keeps the
    signature correct when a caller passes an explicit cross-region endpoint, where the two
    would disagree and the request would be rejected as a signature mismatch. The environment
    is only the fallback for a host that carries no region at all.
    """
    region = _xray_region(endpoint)
    if region is not None:
        return region
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-west-2"


def _build_span_exporter(endpoint: str, timeout_millis: int) -> SpanExporter:
    """The exporter for an endpoint: SigV4 signing for X-Ray, plain OTLP for anything else.

    The X-Ray OTLP endpoint authenticates with SigV4 and rejects an unsigned request with a
    403, which the exporter retries quietly, so an unsigned export is indistinguishable from
    having no traffic. The signing is not implemented here; it comes from
    `aws-opentelemetry-distro`, whose `OTLPAwsSpanExporter` subclasses the plain HTTP
    exporter and swaps in a `requests` session that signs each request for the `xray`
    service. Install it with the `aws-otel` extra.

    This is constructed directly rather than being left to the ADOT configurator. The
    configurator only runs under `opentelemetry-instrument`, and it calls
    `set_tracer_provider` itself, which is set-once per process: whichever of it and
    `configure_tracing` ran first would win and the other would be silently ignored. Owning
    the exporter here removes that race, and it is what lets a service start with a plain
    `python -m` rather than an instrumentation wrapper.

    Falls back to the unsigned exporter when the distro is absent, after warning, because a
    warned-about 403 is a better failure than a cold start crash.

    `timeout_millis` is what actually bounds the in-request flush. The exporter treats its
    `timeout`, in seconds, as a deadline across the whole export including its retries, and
    the flush is synchronous, so this constructor argument and nothing else decides how long
    a request can be held waiting on telemetry. Left at the exporter's default it is 10
    seconds with six retries behind it, which is longer than most of the API Gateway
    timeouts it would be sitting inside.
    """
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

    # The exporter takes seconds. At least one second, because a sub-second deadline makes
    # even a healthy export fail on a cold TLS handshake.
    timeout_seconds = max(1, round(timeout_millis / 1000))

    if not _is_xray_endpoint(endpoint):
        return OTLPSpanExporter(endpoint=endpoint, timeout=timeout_seconds)

    try:
        import botocore.session
        from amazon.opentelemetry.distro.exporter.otlp.aws.traces.otlp_aws_span_exporter import (
            OTLPAwsSpanExporter,
        )
    except ImportError:
        _log.warning(
            "Exporting to the X-Ray OTLP endpoint without aws-opentelemetry-distro installed. "
            "That endpoint requires SigV4 signing, so spans will be rejected with 403 and the "
            "exporter will retry silently, which looks exactly like having no traffic. "
            "Install it with the 'aws-otel' extra: pip install 'webbpulse[otel,aws-otel]'.",
            extra={"otlp_endpoint": endpoint},
        )
        return OTLPSpanExporter(endpoint=endpoint, timeout=timeout_seconds)

    # botocore resolves credentials lazily, on the first signed request rather than here, so
    # building this at cold start does not add an IMDS or STS round trip to the critical path.
    # `OTLPAwsSpanExporter` subclasses `OTLPSpanExporter`, but the distro ships no stubs so
    # mypy sees it as Any; the cast restores the contract this function promises.
    return cast(
        "SpanExporter",
        OTLPAwsSpanExporter(
            aws_region=_region_for_endpoint(endpoint),
            session=botocore.session.Session(),
            endpoint=endpoint,
            timeout=timeout_seconds,
        ),
    )


def configure_tracing(
    service_name: str,
    *,
    environment: str | None = None,
    endpoint: str | None = None,
    resource_attributes: dict[str, str] | None = None,
    sample_ratio: float | None = None,
    always_sample_errors: bool = True,
    max_spans_per_trace: int = _DEFAULT_MAX_SPANS_PER_TRACE,
    on_overflow: OverflowPolicy = "export",
    max_buffered_traces: int = _DEFAULT_MAX_BUFFERED_TRACES,
    max_trace_age_seconds: float = _DEFAULT_MAX_TRACE_AGE_SECONDS,
    export_timeout_millis: int = _DEFAULT_FLUSH_TIMEOUT_MILLIS,
    force: bool = False,
) -> bool:
    """Set up the tracer provider and the tail sampling span exporter. Returns whether it did.

    Safe to call when the `otel` extra is not installed, when tracing is disabled by
    environment variable, and more than once. In each of those cases it returns `False` and
    leaves the global tracer provider alone, which means the API's no-op spans stay in
    place and instrumented code keeps working without a provider.

    Call it from the composition root before creating the FastAPI app, so the FastAPI
    instrumentation attaches to a real provider::

        configure_tracing("webbpulse-staging-posts", environment="staging")
        app = create_app([posts_router])

    Sampling is tail based: every span is recorded and the keep-or-drop decision is made per
    trace at flush time, so a failing request is kept whatever the ratio says. See the module
    docstring. `sample_ratio` defaults to `WEBBPULSE_OTEL_SAMPLE_RATIO`, which is how
    Terraform sets 1.0 on staging and 0.1 on production without a code change.

    Args:
        service_name: `service.name` on every span from this process.
        environment: `deployment.environment.name`, and the superseded `deployment.environment`.
        endpoint: OTLP traces endpoint. Defaults to `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` and
            then to this region's X-Ray endpoint.
        resource_attributes: extra resource attributes, applied last so they win.
        sample_ratio: probability a non-error trace is kept. `None` reads the environment.
        always_sample_errors: keep a trace when any span in it has `StatusCode.ERROR` or an
            `exception` event, regardless of the ratio.
        max_spans_per_trace: per-trace buffer ceiling.
        on_overflow: `"export"` keeps a trace that exceeds the ceiling, `"drop"` discards it.
        max_buffered_traces: ceiling on how many traces are buffered at once.
        max_trace_age_seconds: how long a trace may sit buffered before it is judged early,
            which is what reclaims a trace whose spans never end.
        export_timeout_millis: deadline on one export, retries included. This is the real
            bound on how long an in-request flush can hold a response, because the exporter
            enforces it and the flush is synchronous.
        force: reconfigure even if a provider was already installed by an earlier call.
    """
    global _CONFIGURED, _PROCESSOR
    if _CONFIGURED and not force:
        return False
    if not is_tracing_enabled():
        _log.debug("OpenTelemetry tracing disabled by environment; skipping setup.")
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.sampling import ALWAYS_ON, ParentBased
    except ImportError:
        _log.debug("OpenTelemetry SDK not installed; install webbpulse[otel] to enable tracing.")
        return False

    resolved_endpoint = (
        endpoint or os.environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") or xray_otlp_endpoint()
    )

    attributes: dict[str, Any] = {"service.name": service_name, "service.namespace": "webbpulse"}
    if environment:
        # `deployment.environment.name` is the current semantic convention; the older
        # `deployment.environment` is kept alongside it because CloudWatch and a good deal
        # of existing tooling still group on that one.
        attributes["deployment.environment.name"] = environment
        attributes["deployment.environment"] = environment
    if function_name := os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        attributes["faas.name"] = function_name
    if version := os.environ.get("AWS_LAMBDA_FUNCTION_VERSION"):
        attributes["faas.version"] = version
    if resource_attributes:
        attributes.update(resource_attributes)

    ratio = resolve_sample_ratio(sample_ratio)

    # The sampler is passed explicitly rather than left to the SDK. `TracerProvider.__init__`
    # falls back to `sampling._get_from_env_or_default()` when it is not, and that reads
    # `OTEL_TRACES_SAMPLER`: an operator who sets `parentbased_traceidratio` with an arg of
    # 0.1 would then get head sampling that drops 90 percent of spans before this processor
    # ever sees them, silently defeating "errors are always sampled". ALWAYS_ON under a
    # ParentBased root records every locally started trace while still deferring to a
    # sampled-out decision propagated from upstream.
    provider = TracerProvider(
        sampler=ParentBased(root=ALWAYS_ON), resource=Resource.create(attributes)
    )
    processor = TailSamplingSpanProcessor(
        _build_span_exporter(resolved_endpoint, export_timeout_millis),
        sample_ratio=ratio,
        always_sample_errors=always_sample_errors,
        max_spans_per_trace=max_spans_per_trace,
        on_overflow=on_overflow,
        max_buffered_traces=max_buffered_traces,
        max_trace_age_seconds=max_trace_age_seconds,
    )
    global _EXPORT_TIMEOUT_MILLIS
    _EXPORT_TIMEOUT_MILLIS = export_timeout_millis
    # This processor is the export path. Adding a BatchSpanProcessor for the same exporter
    # alongside it would export every kept trace twice and every dropped one once.
    # The cast is the price of not subclassing the SDK's SpanProcessor, which would make this
    # module unimportable on the base install. See the class docstring.
    provider.add_span_processor(cast("SpanProcessor", processor))
    trace.set_tracer_provider(provider)

    _instrument_botocore()
    _CONFIGURED = True
    _PROCESSOR = processor
    _log.info(
        "OpenTelemetry tracing configured.",
        extra={
            "otlp_endpoint": resolved_endpoint,
            "otel_service_name": service_name,
            "otel_sample_ratio": ratio,
            "otel_always_sample_errors": always_sample_errors,
        },
    )
    return True


def _instrument_botocore() -> None:
    """Instrument boto3 and botocore so DynamoDB and Secrets Manager calls become spans."""
    try:
        from opentelemetry.instrumentation.botocore import BotocoreInstrumentor
    except ImportError:
        return
    # The instrumentation packages ship no type information for their constructors.
    instrumentor = BotocoreInstrumentor()  # type: ignore[no-untyped-call]
    if not instrumentor.is_instrumented_by_opentelemetry:
        instrumentor.instrument()


def _running_on_lambda() -> bool:
    """Whether this process is a Lambda execution environment.

    `AWS_LAMBDA_FUNCTION_NAME` is set by the runtime itself, so it is true under the Web
    Adapter as well, where there is no handler to hook and the ASGI app is all there is.
    """
    return bool(os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))


class _FlushTracingASGIMiddleware:
    """A pure ASGI wrapper that flushes buffered spans once the response is complete.

    Why ASGI and not `BaseHTTPMiddleware`. `FastAPIInstrumentor.instrument_app` does not add
    a middleware to the app's list; it replaces `build_middleware_stack` so that
    `OpenTelemetryMiddleware` wraps the entire finished stack, outermost. Anything registered
    with `add_middleware` therefore runs *inside* it, and inside it the server span has not
    ended yet: the span ends when `OpenTelemetryMiddleware` sees the response go by, which is
    after every inner middleware has returned.

    A flush from inside that boundary is a full request out of step. It exports whatever the
    previous request left buffered and leaves the current request's own trace behind, which
    under the Web Adapter means the sandbox freezes on it and it is lost. The failure is
    worst exactly where it matters most: at a 0.1 ratio a 500's error trace is judged
    keep-worthy, buffered, and then frozen and discarded, so the traces this whole design
    exists to keep are the ones that go missing.

    So this wraps the instrumented application from the outside instead, and flushes after
    the inner application has fully returned. That last detail matters as much as being
    outermost: `OpenTelemetryMiddleware` ends the server span *after* the terminal
    `http.response.body` message has been sent, so flushing on that message is still one span
    too early, and the tail step correctly refuses to judge a trace that has a span open.
    Returning from `await self.app(...)` is the first moment the trace is complete.

    Under the Web Adapter the invocation ends when the HTTP response completes, and the
    sandbox freezes immediately afterwards. The response body has already gone out by the
    time this flush runs, so the client is not waiting on the export, but the process is
    still thawed, which is the window this needs.
    """

    def __init__(self, app: Any, timeout_millis: int) -> None:
        self.app = app
        self._timeout_millis = timeout_millis

    def _flush(self) -> None:
        try:
            flush_tracing(self._timeout_millis)
        except Exception:
            # Bounded and swallowed. The response has already been sent, and a telemetry
            # failure that propagated from here would surface as a broken connection.
            _log.warning(
                "Flushing spans at the end of the request failed; this request's trace may "
                "be lost.",
                exc_info=True,
            )

    async def _flush_async(self) -> None:
        """Run the flush off the event loop.

        `flush_tracing` exports synchronously, over HTTP. Calling it directly from this
        coroutine would block the event loop for the duration, which on a server handling
        more than one request at a time stalls every other connection, not just this one.
        A worker thread keeps the stall to this request.
        """
        import asyncio

        await asyncio.get_running_loop().run_in_executor(None, self._flush)

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        try:
            await self.app(scope, receive, send)
        except Exception:
            # The trace of a request that blew up is the one most worth having, and an
            # unhandled exception here means the server span was ended by the instrumentation
            # on its way out, so the trace is complete and ready to judge.
            await self._flush_async()
            raise
        await self._flush_async()


def instrument_fastapi(
    app: FastAPI,
    *,
    excluded_urls: str | None = None,
    flush_per_request: bool | None = None,
    flush_timeout_millis: int | None = None,
) -> None:
    """Instrument one FastAPI app so each request becomes a server span.

    A no-op when the `otel` extra is absent or tracing is disabled. `excluded_urls` is a
    comma separated list of path patterns; the health route is excluded by default because
    the Web Adapter polls it on every cold start and API Gateway health checks would
    otherwise dominate the trace volume for no diagnostic value.

    Because sampling here is tail based, nothing is exported until a flush, and on Lambda the
    only safe place for that flush is inside the request. This wraps the instrumented app in
    an ASGI middleware that flushes once the response is complete. It is on by default when
    `AWS_LAMBDA_FUNCTION_NAME` is set and off otherwise, since a long-lived server can flush
    on its own schedule; pass `flush_per_request` to decide explicitly.

    Args:
        app: the FastAPI application to instrument.
        excluded_urls: comma separated path patterns to leave untraced.
        flush_per_request: force the flush middleware on or off. `None` means auto-detect.
        flush_timeout_millis: ceiling on that flush, in milliseconds. `None` uses the export
            deadline `configure_tracing` already gave the exporter, which is the value that
            actually binds; passing a larger number here does not extend it.
    """
    if not is_tracing_enabled():
        return
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    except ImportError:
        return

    if getattr(app, "middleware_stack", None) is not None:
        # The stack is built on startup and `instrument_app` can only inject the server span
        # middleware while it is still being built. Past that point instrumenting produces an
        # app that looks instrumented and emits no spans at all, which is a far more
        # confusing failure than not instrumenting, so say so.
        _log.warning(
            "instrument_fastapi was called on an application that has already started, so "
            "its middleware stack is built and the server span middleware cannot be "
            "installed. No request spans will be recorded. Call instrument_fastapi during "
            "application construction, before the app starts.",
        )

    FastAPIInstrumentor.instrument_app(
        app, excluded_urls=excluded_urls if excluded_urls is not None else "health,ready"
    )

    should_flush = _running_on_lambda() if flush_per_request is None else flush_per_request
    if should_flush:
        timeout = _EXPORT_TIMEOUT_MILLIS if flush_timeout_millis is None else flush_timeout_millis
        _wrap_with_flush(app, timeout)


def _wrap_with_flush(app: FastAPI, timeout_millis: int) -> None:
    """Put the flush wrapper outside everything, including the OTel server span middleware.

    `app.add_middleware` is not usable for this. `instrument_app` replaces
    `build_middleware_stack` so `OpenTelemetryMiddleware` ends up outermost, so an added
    middleware would run inside it, before the server span has ended. `add_middleware` also
    raises on an app that has already started.

    Wrapping `build_middleware_stack` instead puts this outside the OTel middleware and
    composes with it, since each wrapper decorates whatever the previous one produced. The
    stack is rebuilt lazily on startup, so this takes effect for a stack that has not been
    built yet.

    Guarded by a sentinel, because wrapping is not idempotent: two `instrument_fastapi` calls
    on the same app would otherwise nest two flush layers and flush twice per request, and
    each layer would pay its own thread hop.
    """
    if getattr(app, _FLUSH_WRAPPED_ATTR, False):
        return
    setattr(app, _FLUSH_WRAPPED_ATTR, True)

    built = app.build_middleware_stack

    def build_middleware_stack() -> Any:
        return _FlushTracingASGIMiddleware(built(), timeout_millis)

    app.build_middleware_stack = build_middleware_stack  # type: ignore[method-assign]
    # An app that is already running has a built stack that the rebuild above will not reach,
    # so patch the live one too. It will not carry server spans, for the reason warned about
    # in `instrument_fastapi`, but it still flushes whatever else is buffered.
    if getattr(app, "middleware_stack", None) is not None:
        app.middleware_stack = _FlushTracingASGIMiddleware(app.middleware_stack, timeout_millis)


def flush_tracing(timeout_millis: int = 30000) -> bool:
    """Resolve and export the traces buffered so far. Returns whether a flush happened.

    This is where the tail sampling decision is made, so on Lambda it has to run before the
    invocation returns and the execution environment is frozen. Under the Web Adapter the
    process outlives an invoke, so the practical place is the end of a request rather than a
    handler epilogue.

    Falls back to the provider's own `force_flush` when this module did not install the
    processor, which covers a provider set up by the ADOT configurator.
    """
    if _PROCESSOR is not None:
        return _PROCESSOR.force_flush(timeout_millis)
    try:
        from opentelemetry import trace
    except ImportError:
        return False
    provider_flush = getattr(trace.get_tracer_provider(), "force_flush", None)
    if callable(provider_flush):
        provider_flush(timeout_millis)
        return True
    return False


def shutdown_tracing() -> None:
    """Flush and shut down the tracer provider.

    Worth calling from a container's shutdown path. It matters much less under the Web
    Adapter than it did under a Lambda handler: the process stays alive between invokes, so
    `flush_tracing` gets its own chance to run per request rather than being frozen mid-batch.
    Shutting the provider down flushes the tail buffers, so nothing recorded is lost.
    """
    global _CONFIGURED, _PROCESSOR
    try:
        from opentelemetry import trace
    except ImportError:
        return
    provider = trace.get_tracer_provider()
    shutdown = getattr(provider, "shutdown", None)
    if callable(shutdown):
        shutdown()
    _CONFIGURED = False
    _PROCESSOR = None
