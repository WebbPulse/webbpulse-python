"""OpenTelemetry tracing, exported to AWS X-Ray over the OTLP endpoint.

Builds the whole pipeline in process from `configure_tracing`: a SigV4-signed OTLP
exporter behind a tail sampling processor that always keeps error traces.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import TYPE_CHECKING, Any, Final, Literal, cast

if TYPE_CHECKING:  # pragma: no cover
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

OTEL_DISABLED_ENV: Final = "WEBBPULSE_OTEL_DISABLED"

SAMPLE_RATIO_ENV: Final = "WEBBPULSE_OTEL_SAMPLE_RATIO"

_TRUTHY: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})

_TRACE_ID_LIMIT: Final = (1 << 64) - 1

_EXCEPTION_EVENT_NAME: Final = "exception"

_DEFAULT_MAX_SPANS_PER_TRACE: Final = 2048

_DEFAULT_MAX_BUFFERED_TRACES: Final = 1024

_DEFAULT_MAX_TRACE_AGE_SECONDS: Final = 300.0

_DEFAULT_FLUSH_TIMEOUT_MILLIS: Final = 1000

OverflowPolicy = Literal["export", "drop"]

_CONFIGURED = False

_PROCESSOR: TailSamplingSpanProcessor | None = None

_EXPORT_TIMEOUT_MILLIS: int = _DEFAULT_FLUSH_TIMEOUT_MILLIS

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

    First match wins: `explicit`, then `WEBBPULSE_OTEL_SAMPLE_RATIO`, then
    `OTEL_TRACES_SAMPLER_ARG` under a ratio sampler, then `1.0`.
    """
    if explicit is not None:
        if not 0.0 <= explicit <= 1.0:
            raise ValueError(f"sample_ratio must be between 0.0 and 1.0, got {explicit!r}")
        return explicit

    candidates: list[tuple[str, str]] = []
    if raw := os.environ.get(SAMPLE_RATIO_ENV, "").strip():
        candidates.append((SAMPLE_RATIO_ENV, raw))

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

    Reimplemented rather than approximated so this service agrees with an upstream one
    running the stock sampler at the same ratio.
    """
    return (trace_id & _TRACE_ID_LIMIT) < bound


def _span_signals_error(span: ReadableSpan) -> bool:
    """Whether a span marks its trace as one that must be kept.

    Two signals, since instrumentations use both: `StatusCode.ERROR` and an `exception`
    event, which does not always set the status.
    """
    from opentelemetry.trace import StatusCode

    if span.status.status_code is StatusCode.ERROR:
        return True
    return any(event.name == _EXCEPTION_EVENT_NAME for event in span.events or ())


def _is_non_positive_timeout_error(error: ValueError) -> bool:
    """Whether a `ValueError` is urllib3 rejecting a timeout that had already expired.

    Matched on the message because urllib3 raises a bare `ValueError` with nothing else to
    key on. Kept tight so an unrelated `ValueError` still gets its ERROR and traceback.
    """
    message = str(error).lower()
    return "timeout" in message and "less than or equal to 0" in message


class TailSamplingSpanProcessor:
    """Buffers spans per trace and decides at flush time whether to export the trace.

    Structurally a `SpanProcessor` but not a subclass, so this module still imports without
    the `otel` extra. It performs the export itself, so register no `BatchSpanProcessor`
    alongside it for the same exporter.

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
        """Validate the sampling and buffering limits and set up the per-trace buffers."""
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

        self._lock = threading.Lock()
        self._buffers: dict[int, list[ReadableSpan]] = {}
        self._open_spans: dict[int, int] = {}
        self._started_at: dict[int, float] = {}
        self._overflowed_keep: set[int] = set()
        self._overflowed_drop: set[int] = set()
        self._shutdown = False

        self.dropped_traces = 0
        self.sampled_out_traces = 0
        self.exported_traces = 0
        self.evicted_traces = 0

    @property
    def sample_ratio(self) -> float:
        """The probability a non-error trace is kept."""
        return self._sample_ratio

    def on_start(self, span: Span, parent_context: Context | None = None) -> None:
        """Count the span as in flight, so a flush knows the trace is not complete yet.

        Only resolving a trace at zero open spans is what makes the decision per trace
        rather than per flush.
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

        Deliberately does not filter on `trace_flags.sampled`: that flag records a head
        decision, and this processor exists to make a later one.
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

        self._export(stream)

    def _close_span_locked(self, trace_id: int) -> bool:
        """Decrement a trace's open-span count. Returns whether it just reached zero.

        An overflowed trace stays counted here even though its buffer is gone, because the
        count is what tells its overflow marker when it is safe to drop.
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

        Eviction judges the trace now rather than discarding it. The count bound only evicts
        a completed trace; the age bound is what reclaims one whose spans never end.
        """
        now = time.monotonic()
        deadline = now - self._max_trace_age_seconds
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
            self._export(spans)
        else:
            self.sampled_out_traces += 1

    def _export(self, spans: list[ReadableSpan]) -> None:
        """Hand spans to the exporter.

        Must not be called with the lock held, except from `_evict_one_locked`.
        """
        if not spans:
            return
        try:
            self._exporter.export(spans)
        except ValueError as error:
            if _is_non_positive_timeout_error(error):
                _log.warning(
                    "Dropping a span batch: the exporter deadline had already passed. This is "
                    "expected when a frozen Lambda sandbox is thawed mid-export and does not "
                    "indicate an application fault.",
                    extra={"span_count": len(spans), "exporter_error": str(error)},
                )
                return
            _log.exception("The span exporter raised while exporting a sampled trace.")
        except Exception:  # pragma: no cover
            _log.exception("The span exporter raised while exporting a sampled trace.")

    def _should_keep(self, trace_id: int, spans: list[ReadableSpan]) -> bool:
        """The tail decision for one buffered trace."""
        if self._always_sample_errors and any(_span_signals_error(span) for span in spans):
            return True
        return _trace_id_is_sampled(trace_id, self._bound)

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        """Resolve every completed buffered trace and export the ones that are kept.

        This is where the tail decision happens, so a Lambda invocation must reach it before
        the process is frozen. A trace with spans still open is left buffered.
        """
        to_export: list[list[ReadableSpan]] = []
        with self._lock:
            complete = [
                trace_id for trace_id in self._buffers if not self._open_spans.get(trace_id)
            ]
            for trace_id in complete:
                spans = self._buffers.pop(trace_id)
                self._started_at.pop(trace_id, None)
                self._overflowed_keep.discard(trace_id)
                self._overflowed_drop.discard(trace_id)
                if self._should_keep(trace_id, spans):
                    self.exported_traces += 1
                    to_export.append(spans)
                else:
                    self.sampled_out_traces += 1

        for spans in to_export:
            self._export(spans)

        flush = getattr(self._exporter, "force_flush", None)
        if callable(flush):
            result = flush(timeout_millis)
            return bool(result) if result is not None else True
        return True

    def shutdown(self) -> None:
        """Resolve everything still buffered, in flight or not, then shut the exporter down.

        Unlike `force_flush` there is no later, so an incomplete trace is judged on what it
        has rather than discarded silently.
        """
        with self._lock:
            self._open_spans.clear()
        self.force_flush()
        self._shutdown = True
        self._exporter.shutdown()


def _xray_region(endpoint: str) -> str | None:
    """The region an X-Ray OTLP endpoint signs for, or `None` if it is not one.

    Recognises the public, FIPS and interface VPC endpoint host shapes exactly, since a
    looser match would sign requests that should not be signed.
    """
    from urllib.parse import urlparse

    parsed = urlparse(endpoint)
    if not parsed.path.startswith("/v1/traces"):
        return None
    labels = (parsed.hostname or "").lower().split(".")

    if (
        len(labels) == 4
        and labels[0] in ("xray", "xray-fips")
        and labels[2:] == ["amazonaws", "com"]
    ):
        return labels[1]
    if len(labels) == 6 and labels[1] == "xray" and labels[3:] == ["vpce", "amazonaws", "com"]:
        return labels[2]
    return None


def _is_xray_endpoint(endpoint: str) -> bool:
    """Whether an endpoint is a CloudWatch X-Ray OTLP one, which requires SigV4."""
    return _xray_region(endpoint) is not None


def _region_for_endpoint(endpoint: str) -> str:
    """The region to sign for, taken from the endpoint host rather than guessed.

    Deriving it from the endpoint keeps the signature correct for an explicit cross-region
    endpoint. The environment is only the fallback for a host carrying no region.
    """
    region = _xray_region(endpoint)
    if region is not None:
        return region
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-west-2"


class _ReresolvingCredentials:
    """Credentials that ask botocore for the current values on every signature.

    Works around the distro caching a non-refreshable `Credentials` object, which under
    Lambda's env-var provider freezes the signing key at cold start and 403s once it expires.
    """

    def __init__(self, session: Any) -> None:
        """Hold the botocore session the credentials are re-resolved from."""
        self._session = session

    def _current(self) -> Any:
        """The credentials to sign with right now, re-resolved if they cannot refresh."""
        from botocore.credentials import RefreshableCredentials

        credentials = self._session.get_credentials()
        if isinstance(credentials, RefreshableCredentials):
            return credentials
        if getattr(self._session, "_credentials", None) is not None:
            self._session._credentials = None
            credentials = self._session.get_credentials()
        return credentials

    def get_frozen_credentials(self) -> Any:
        """The current frozen credentials, raising when none can be resolved."""
        credentials = self._current()
        if credentials is None:
            from botocore.exceptions import NoCredentialsError

            raise NoCredentialsError()
        return credentials.get_frozen_credentials()

    @property
    def access_key(self) -> Any:
        """The current access key id."""
        return self.get_frozen_credentials().access_key

    @property
    def secret_key(self) -> Any:
        """The current secret access key."""
        return self.get_frozen_credentials().secret_key

    @property
    def token(self) -> Any:
        """The current session token."""
        return self.get_frozen_credentials().token


class _RefreshingCredentialSession:
    """A botocore session whose `get_credentials` hands back `_ReresolvingCredentials`.

    The distro still latches onto one credentials object, but that object resolves afresh
    each read. Everything else is delegated to the real session.
    """

    def __init__(self, session: Any) -> None:
        """Wrap a real botocore session with re-resolving credentials."""
        self._session = session
        self._credentials = _ReresolvingCredentials(session)

    def get_credentials(self) -> Any:
        """The re-resolving credentials object the distro will cache."""
        return self._credentials

    def __getattr__(self, name: str) -> Any:
        """Delegate everything else to the wrapped session."""
        return getattr(self._session, name)


_MIN_EXPORT_TIMEOUT_SECONDS: Final = 0.001


class _PositiveTimeoutSession:
    """A `requests` session that refuses to pass a non-positive timeout to urllib3.

    A frozen and thawed Lambda sandbox leaves the exporter computing a negative remaining
    deadline, which urllib3 rejects with a `ValueError` the retry loop does not catch.
    """

    def __init__(self, session: Any) -> None:
        """Wrap a real `requests` session whose timeouts need clamping."""
        self._session = session

    def post(self, *args: Any, timeout: Any = None, **kwargs: Any) -> Any:
        """POST through the wrapped session with the timeout clamped positive."""
        return self._session.post(*args, timeout=_clamp_timeout(timeout), **kwargs)

    def request(self, *args: Any, timeout: Any = None, **kwargs: Any) -> Any:
        """Make a request through the wrapped session with the timeout clamped positive."""
        return self._session.request(*args, timeout=_clamp_timeout(timeout), **kwargs)

    def __getattr__(self, name: str) -> Any:
        """Delegate everything else to the wrapped session."""
        return getattr(self._session, name)


def _clamp_timeout(timeout: Any) -> Any:
    """Raise a non-positive timeout to the floor, leaving anything else alone.

    A tuple is the `(connect, read)` form and both halves are clamped. Anything that is not
    a number, `None` included, is passed through unchanged.
    """
    if isinstance(timeout, tuple):
        return tuple(_clamp_timeout(part) for part in timeout)
    if isinstance(timeout, bool) or not isinstance(timeout, int | float):
        return timeout
    return max(_MIN_EXPORT_TIMEOUT_SECONDS, timeout)


def _build_span_exporter(endpoint: str, timeout_millis: int) -> SpanExporter:
    """The exporter for an endpoint: SigV4 signing for X-Ray, plain OTLP for anything else.

    Signing comes from `aws-opentelemetry-distro`; without it this warns and falls back to
    the unsigned exporter. `timeout_millis` is the deadline that bounds an in-request flush.
    """
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

    timeout_seconds = max(1, round(timeout_millis / 1000))

    if not _is_xray_endpoint(endpoint):
        exporter = OTLPSpanExporter(endpoint=endpoint, timeout=timeout_seconds)
        _guard_export_timeouts(exporter)
        return exporter

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
        exporter = OTLPSpanExporter(endpoint=endpoint, timeout=timeout_seconds)
        _guard_export_timeouts(exporter)
        return exporter

    signing_exporter = OTLPAwsSpanExporter(
        aws_region=_region_for_endpoint(endpoint),
        session=_RefreshingCredentialSession(botocore.session.Session()),
        endpoint=endpoint,
        timeout=timeout_seconds,
    )
    _guard_export_timeouts(signing_exporter)
    return cast("SpanExporter", signing_exporter)


def _guard_export_timeouts(exporter: Any) -> None:
    """Wrap an exporter's `requests` session so a clock jump cannot produce a `ValueError`.

    Swaps the private `_session` after construction, guarded so a future rename loses only
    the clamp rather than breaking exports.
    """
    session = getattr(exporter, "_session", None)
    if session is None:  # pragma: no cover
        return
    exporter._session = _PositiveTimeoutSession(session)


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

    Safe to call without the `otel` extra, with tracing disabled, and more than once; each
    of those returns `False`. Call it from the composition root before creating the app.

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
        attributes["deployment.environment.name"] = environment
        attributes["deployment.environment"] = environment
    if function_name := os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        attributes["faas.name"] = function_name
    if version := os.environ.get("AWS_LAMBDA_FUNCTION_VERSION"):
        attributes["faas.version"] = version
    if resource_attributes:
        attributes.update(resource_attributes)

    ratio = resolve_sample_ratio(sample_ratio)

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
    instrumentor = BotocoreInstrumentor()  # type: ignore[no-untyped-call]
    if not instrumentor.is_instrumented_by_opentelemetry:
        instrumentor.instrument()


def _running_on_lambda() -> bool:
    """Whether this process is a Lambda execution environment.

    True under the Web Adapter too, since the runtime sets `AWS_LAMBDA_FUNCTION_NAME`.
    """
    return bool(os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))


class _FlushTracingASGIMiddleware:
    """A pure ASGI wrapper that flushes buffered spans once the response is complete.

    Wraps the instrumented app from the outside, so the flush runs after the server span has
    ended and the trace is complete. Returning from the inner app is the first such moment.
    """

    def __init__(self, app: Any, timeout_millis: int) -> None:
        """Wrap the instrumented ASGI app with a bounded end-of-request flush."""
        self.app = app
        self._timeout_millis = timeout_millis

    def _flush(self) -> None:
        """Flush buffered spans, never letting a telemetry failure reach the response."""
        try:
            flush_tracing(self._timeout_millis)
        except Exception:
            _log.warning(
                "Flushing spans at the end of the request failed; this request's trace may "
                "be lost.",
                exc_info=True,
            )

    async def _flush_async(self) -> None:
        """Run the flush in a worker thread, since it exports synchronously over HTTP."""
        import asyncio

        await asyncio.get_running_loop().run_in_executor(None, self._flush)

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        """Serve the request, then flush this request's completed trace."""
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        try:
            await self.app(scope, receive, send)
        except Exception:
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

    A no-op when the `otel` extra is absent or tracing is disabled. On Lambda it also wraps
    the app in an ASGI middleware that flushes buffered spans once the response is complete.

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

    Wraps `build_middleware_stack` rather than using `add_middleware`, which would land
    inside the OTel middleware. Guarded by a sentinel, since wrapping is not idempotent.
    """
    if getattr(app, _FLUSH_WRAPPED_ATTR, False):
        return
    setattr(app, _FLUSH_WRAPPED_ATTR, True)

    built = app.build_middleware_stack

    def build_middleware_stack() -> Any:
        """Build the app's stack and wrap it in the flush middleware."""
        return _FlushTracingASGIMiddleware(built(), timeout_millis)

    app.build_middleware_stack = build_middleware_stack  # type: ignore[method-assign]
    if getattr(app, "middleware_stack", None) is not None:
        app.middleware_stack = _FlushTracingASGIMiddleware(app.middleware_stack, timeout_millis)


def flush_tracing(timeout_millis: int = 30000) -> bool:
    """Resolve and export the traces buffered so far. Returns whether a flush happened.

    On Lambda this has to run before the execution environment is frozen. Falls back to the
    provider's own `force_flush` when this module did not install the processor.
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

    Worth calling from a container's shutdown path: shutting the provider down flushes the
    tail buffers, so nothing recorded is lost.
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
