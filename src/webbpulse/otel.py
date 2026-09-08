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

Either way the buffer for a single trace never exceeds the cap, and the total buffer never
exceeds `max_spans_per_trace` times the number of concurrently open traces, which under the
Web Adapter on Lambda is normally one.

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

OverflowPolicy = Literal["export", "drop"]

# Set once configure_tracing has installed a provider, so a second call is a no-op rather
# than a second span processor quietly double-exporting every span.
_CONFIGURED = False

# The processor configure_tracing installed, kept so flush_tracing can reach it without
# depending on the provider exposing its processors.
_PROCESSOR: TailSamplingSpanProcessor | None = None


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
    """

    def __init__(
        self,
        exporter: SpanExporter,
        *,
        sample_ratio: float = 1.0,
        always_sample_errors: bool = True,
        max_spans_per_trace: int = _DEFAULT_MAX_SPANS_PER_TRACE,
        on_overflow: OverflowPolicy = "export",
    ) -> None:
        if not 0.0 <= sample_ratio <= 1.0:
            raise ValueError(f"sample_ratio must be between 0.0 and 1.0, got {sample_ratio!r}")
        if max_spans_per_trace < 1:
            raise ValueError(f"max_spans_per_trace must be at least 1, got {max_spans_per_trace!r}")
        if on_overflow not in ("export", "drop"):
            raise ValueError(f"on_overflow must be 'export' or 'drop', got {on_overflow!r}")

        self._exporter = exporter
        self._sample_ratio = sample_ratio
        self._bound = _ratio_bound(sample_ratio)
        self._always_sample_errors = always_sample_errors
        self._max_spans_per_trace = max_spans_per_trace
        self._on_overflow: OverflowPolicy = on_overflow

        # on_end runs on whichever thread ended the span, and uvicorn serves on a thread
        # pool, so the buffers need a lock even though a Lambda invocation is one request.
        self._lock = threading.Lock()
        self._buffers: dict[int, list[ReadableSpan]] = {}
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

    @property
    def sample_ratio(self) -> float:
        return self._sample_ratio

    def on_start(self, span: Span, parent_context: Context | None = None) -> None:
        """Required by the `SpanProcessor` interface. The tail decision needs no start hook."""

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

        with self._lock:
            if trace_id in self._overflowed_drop:
                return
            if trace_id in self._overflowed_keep:
                # Already resolved to keep, so nothing accumulates for this trace.
                self._export([span])
                return

            buffer = self._buffers.setdefault(trace_id, [])
            if len(buffer) < self._max_spans_per_trace:
                buffer.append(span)
                return

            # The cap is reached. Resolve the trace now, one way or the other, so the buffer
            # for it stops growing.
            del self._buffers[trace_id]
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
                return

            self._overflowed_keep.add(trace_id)
            _log.warning(
                "Exporting a trace that exceeded the tail sampling buffer cap without a "
                "sampling decision.",
                extra={
                    "otel_trace_id": f"{trace_id:032x}",
                    "max_spans_per_trace": self._max_spans_per_trace,
                },
            )
            self._export([*buffer, span])

    def _export(self, spans: list[ReadableSpan]) -> None:
        """Hand spans to the exporter. Called with the lock held."""
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
        """Resolve every buffered trace and export the ones that are kept.

        This is where the tail decision happens, so a Lambda invocation must reach it before
        the process is frozen. Returns the wrapped exporter's own flush result.
        """
        with self._lock:
            buffers, self._buffers = self._buffers, {}
            self._overflowed_keep.clear()
            self._overflowed_drop.clear()

            for trace_id, spans in buffers.items():
                if self._should_keep(trace_id, spans):
                    self.exported_traces += 1
                    self._export(spans)
                else:
                    self.sampled_out_traces += 1

        flush = getattr(self._exporter, "force_flush", None)
        if callable(flush):
            result = flush(timeout_millis)
            return bool(result) if result is not None else True
        return True

    def shutdown(self) -> None:
        """Flush what is buffered, then shut the exporter down."""
        self.force_flush()
        self._shutdown = True
        self._exporter.shutdown()


def _is_xray_endpoint(endpoint: str) -> bool:
    """Whether an endpoint is the CloudWatch X-Ray OTLP one, which requires SigV4."""
    return ".amazonaws.com/v1/traces" in endpoint


def _region_for_endpoint(endpoint: str) -> str:
    """The region to sign for, taken from the endpoint host rather than guessed.

    `https://xray.us-west-2.amazonaws.com/v1/traces` signs for `us-west-2`. Deriving it from
    the endpoint rather than from `AWS_REGION` keeps the signature correct when a caller
    passes an explicit cross-region endpoint, where the two would disagree and the request
    would be rejected as a signature mismatch.
    """
    from urllib.parse import urlparse

    host = (urlparse(endpoint).hostname or "").split(".")
    if len(host) >= 3 and host[0] == "xray":
        return host[1]
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-west-2"


def _build_span_exporter(endpoint: str) -> SpanExporter:
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
    """
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

    if not _is_xray_endpoint(endpoint):
        return OTLPSpanExporter(endpoint=endpoint)

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
        return OTLPSpanExporter(endpoint=endpoint)

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
        _build_span_exporter(resolved_endpoint),
        sample_ratio=ratio,
        always_sample_errors=always_sample_errors,
        max_spans_per_trace=max_spans_per_trace,
        on_overflow=on_overflow,
    )
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


#: Default ceiling on the in-request flush. Short on purpose: it is latency a user is
#: waiting on, and a flush that cannot finish in a second is one whose spans are better
#: dropped than paid for. The exporter keeps its own longer timeout for the HTTP call.
_DEFAULT_FLUSH_TIMEOUT_MILLIS: Final = 1000


def _running_on_lambda() -> bool:
    """Whether this process is a Lambda execution environment.

    `AWS_LAMBDA_FUNCTION_NAME` is set by the runtime itself, so it is true under the Web
    Adapter as well, where there is no handler to hook and the ASGI app is all there is.
    """
    return bool(os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))


def _flush_middleware_factory(timeout_millis: int) -> Any:
    """Build the flush middleware. Imported lazily so Starlette stays an optional extra."""
    from starlette.middleware.base import BaseHTTPMiddleware

    class _FlushTracingMiddleware(BaseHTTPMiddleware):
        """Flush buffered spans after the handler and before the response is returned.

        The placement is the whole point. Under the Lambda Web Adapter an invocation ends
        when the HTTP response completes, and the execution environment is frozen
        immediately afterwards: a background task, a `BackgroundTask` on the response, or an
        `atexit` hook all run too late and are frozen mid-flush, losing the trace. So the
        flush happens inline, after `call_next` has produced the response and before that
        response is handed back to the adapter.

        It never raises into the request. A telemetry failure that turned a healthy 200 into
        a 500 would be far worse than the missing trace it is reporting.
        """

        async def dispatch(self, request: Any, call_next: Any) -> Any:
            response = await call_next(request)
            try:
                flush_tracing(timeout_millis)
            except Exception:
                # Bounded and swallowed: the response is already built and correct.
                _log.warning(
                    "Flushing spans before returning the response failed; "
                    "this request's trace may be lost.",
                    exc_info=True,
                )
            return response

    return _FlushTracingMiddleware


def instrument_fastapi(
    app: FastAPI,
    *,
    excluded_urls: str | None = None,
    flush_per_request: bool | None = None,
    flush_timeout_millis: int = _DEFAULT_FLUSH_TIMEOUT_MILLIS,
) -> None:
    """Instrument one FastAPI app so each request becomes a server span.

    A no-op when the `otel` extra is absent or tracing is disabled. `excluded_urls` is a
    comma separated list of path patterns; the health route is excluded by default because
    the Web Adapter polls it on every cold start and API Gateway health checks would
    otherwise dominate the trace volume for no diagnostic value.

    Because sampling here is tail based, nothing is exported until a flush, and on Lambda the
    only safe place for that flush is inside the request. This adds a middleware that flushes
    after the handler and before the response is returned. It is on by default when
    `AWS_LAMBDA_FUNCTION_NAME` is set and off otherwise, since a long-lived server can flush
    on its own schedule; pass `flush_per_request` to decide explicitly.

    Args:
        app: the FastAPI application to instrument.
        excluded_urls: comma separated path patterns to leave untraced.
        flush_per_request: force the flush middleware on or off. `None` means auto-detect.
        flush_timeout_millis: ceiling on that flush, in milliseconds.
    """
    if not is_tracing_enabled():
        return
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    except ImportError:
        return
    FastAPIInstrumentor.instrument_app(
        app, excluded_urls=excluded_urls if excluded_urls is not None else "health,ready"
    )

    should_flush = _running_on_lambda() if flush_per_request is None else flush_per_request
    if not should_flush:
        return
    try:
        middleware = _flush_middleware_factory(flush_timeout_millis)
    except ImportError:  # pragma: no cover - starlette ships with fastapi
        _log.warning("Starlette is not installed, so spans will not be flushed per request.")
        return
    app.add_middleware(middleware)


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
