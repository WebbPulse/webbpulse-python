"""Tests for `webbpulse.otel`."""

from __future__ import annotations

import threading
import time
from typing import Any, ClassVar, cast

import pytest
from opentelemetry import trace as trace_api
from pytest import MonkeyPatch

from webbpulse import otel
from webbpulse.otel import (
    OTEL_DISABLED_ENV,
    SAMPLE_RATIO_ENV,
    TailSamplingSpanProcessor,
    configure_tracing,
    flush_tracing,
    is_tracing_enabled,
    resolve_sample_ratio,
    shutdown_tracing,
    xray_otlp_endpoint,
)


def _clear_global_tracer_provider() -> None:
    """Undo `trace.set_tracer_provider` so the next call actually installs a provider.

    OpenTelemetry allows the global provider to be set exactly once per process: a second
    `set_tracer_provider` logs "Overriding of current TracerProvider is not allowed" and
    keeps the first one. Resetting only `otel._CONFIGURED` is therefore not enough, because
    the second test would silently assert against the first test's provider. There is no
    public API for this, so the private globals are reset directly.
    """
    from opentelemetry import trace

    trace._TRACER_PROVIDER = None
    trace._TRACER_PROVIDER_SET_ONCE._done = False


@pytest.fixture(autouse=True)
def _reset_provider() -> Any:
    """The tracer provider is a process global, so each test starts from a clean one."""
    otel._CONFIGURED = False
    otel._PROCESSOR = None
    _clear_global_tracer_provider()
    yield
    otel._CONFIGURED = False
    otel._PROCESSOR = None
    _clear_global_tracer_provider()


@pytest.fixture(autouse=True)
def _clear_sampling_env(monkeypatch: MonkeyPatch) -> None:
    """Each test starts from an environment with no sampling configuration in it.

    Otherwise a stray `OTEL_TRACES_SAMPLER_ARG` in the developer's shell, or one left by an
    earlier test, would change the ratio a later test resolves.
    """
    for name in (SAMPLE_RATIO_ENV, "OTEL_TRACES_SAMPLER", "OTEL_TRACES_SAMPLER_ARG"):
        monkeypatch.delenv(name, raising=False)


def test_the_xray_endpoint_matches_the_documented_shape() -> None:
    """`https://xray.<region>.amazonaws.com/v1/traces`, per the CloudWatch OTLP endpoint docs."""
    assert xray_otlp_endpoint("us-west-2") == "https://xray.us-west-2.amazonaws.com/v1/traces"


def test_the_endpoint_region_comes_from_the_lambda_environment(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    assert xray_otlp_endpoint() == "https://xray.eu-west-1.amazonaws.com/v1/traces"


def test_the_endpoint_defaults_to_the_only_region_this_estate_uses(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    assert xray_otlp_endpoint() == "https://xray.us-west-2.amazonaws.com/v1/traces"


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
def test_tracing_can_be_disabled_by_env_var(monkeypatch: MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(OTEL_DISABLED_ENV, value)
    assert is_tracing_enabled() is False


def test_the_specification_disable_flag_is_honoured(monkeypatch: MonkeyPatch) -> None:
    """`OTEL_SDK_DISABLED` is defined by the OpenTelemetry specification itself."""
    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)
    monkeypatch.setenv("OTEL_SDK_DISABLED", "true")
    assert is_tracing_enabled() is False


def test_tracing_is_enabled_by_default(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)
    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)
    assert is_tracing_enabled() is True


def test_configure_tracing_is_a_no_op_when_disabled(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv(OTEL_DISABLED_ENV, "1")
    assert configure_tracing("posts") is False


def test_configure_tracing_installs_a_provider(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)
    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)

    assert configure_tracing("posts", environment="staging") is True

    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider

    provider = trace.get_tracer_provider()
    assert isinstance(provider, TracerProvider)

    attributes = provider.resource.attributes
    assert attributes["service.name"] == "posts"
    assert attributes["service.namespace"] == "webbpulse"
    assert attributes["deployment.environment.name"] == "staging"
    # The superseded key is kept alongside because CloudWatch still groups on it.
    assert attributes["deployment.environment"] == "staging"

    shutdown_tracing()


def test_configure_tracing_is_idempotent(monkeypatch: MonkeyPatch) -> None:
    """A second BatchSpanProcessor would double-export every span."""
    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)
    assert configure_tracing("posts") is True
    assert configure_tracing("posts") is False
    shutdown_tracing()


def test_lambda_resource_attributes_are_detected(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "webbpulse-staging-posts")
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_VERSION", "7")

    configure_tracing("posts")

    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider

    provider = trace.get_tracer_provider()
    assert isinstance(provider, TracerProvider)
    assert provider.resource.attributes["faas.name"] == "webbpulse-staging-posts"
    assert provider.resource.attributes["faas.version"] == "7"
    shutdown_tracing()


def test_custom_resource_attributes_win(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)
    configure_tracing("posts", resource_attributes={"service.version": "2.1.0"})

    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider

    provider = trace.get_tracer_provider()
    assert isinstance(provider, TracerProvider)
    assert provider.resource.attributes["service.version"] == "2.1.0"
    shutdown_tracing()


def _without_adot_distro(monkeypatch: MonkeyPatch) -> None:
    """Make the distro import fail the way a minimal install does.

    The exporter is chosen by a guarded `import`, not by a feature flag, so the only honest
    way to test the fallback is to make that import raise. The dev environment installs the
    `aws-otel` extra, so the module really is importable here.
    """
    import builtins

    real_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name.startswith("amazon.opentelemetry"):
            raise ImportError(f"No module named {name!r}")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", fake_import)


def test_an_unsigned_xray_export_warns(
    monkeypatch: MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Without SigV4 the endpoint returns 403 and the exporter retries silently.

    That failure is indistinguishable from having no traffic, so the warning is the only
    signal a software engineer gets that the `aws-otel` extra is missing.
    """
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

    _without_adot_distro(monkeypatch)

    with caplog.at_level("WARNING", logger="webbpulse.otel"):
        exporter = otel._build_span_exporter("https://xray.us-west-2.amazonaws.com/v1/traces", 1000)

    assert any("SigV4" in record.message for record in caplog.records)
    assert any("aws-otel" in record.message for record in caplog.records)
    # Warned, but still usable: a 403 that says so beats crashing the cold start.
    assert type(exporter) is OTLPSpanExporter


def test_an_xray_endpoint_gets_the_signing_exporter() -> None:
    """The whole point of the extra: X-Ray must get the SigV4 subclass, not the plain one."""
    from amazon.opentelemetry.distro.exporter.otlp.aws.traces.otlp_aws_span_exporter import (
        OTLPAwsSpanExporter,
    )

    exporter = otel._build_span_exporter("https://xray.eu-west-1.amazonaws.com/v1/traces", 1000)

    assert isinstance(exporter, OTLPAwsSpanExporter)


def test_no_warning_when_the_distro_is_present(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING", logger="webbpulse.otel"):
        otel._build_span_exporter("https://xray.us-west-2.amazonaws.com/v1/traces", 1000)

    assert not [r for r in caplog.records if "SigV4" in r.message]


def test_a_non_aws_endpoint_gets_the_plain_exporter(
    monkeypatch: MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A local collector needs no SigV4, so it must not be signed and must not warn."""
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

    _without_adot_distro(monkeypatch)

    with caplog.at_level("WARNING", logger="webbpulse.otel"):
        exporter = otel._build_span_exporter("http://localhost:4318/v1/traces", 1000)

    assert type(exporter) is OTLPSpanExporter
    assert not [r for r in caplog.records if "SigV4" in r.message]


def test_the_signing_region_comes_from_the_endpoint(monkeypatch: MonkeyPatch) -> None:
    """An explicit cross-region endpoint must be signed for its own region, not AWS_REGION.

    Signing `xray.eu-west-1` for `us-west-2` produces a credential scope mismatch and a 403,
    so the host wins over the environment.
    """
    monkeypatch.setenv("AWS_REGION", "us-west-2")

    assert (
        otel._region_for_endpoint("https://xray.eu-west-1.amazonaws.com/v1/traces") == "eu-west-1"
    )


def test_the_signing_region_falls_back_to_the_environment(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_REGION", "ap-southeast-2")
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)

    assert otel._region_for_endpoint("https://otlp.example.com/v1/traces") == "ap-southeast-2"


def test_instrumenting_an_app_does_not_break_it(monkeypatch: MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    from webbpulse.http import create_app

    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)
    configure_tracing("posts")
    app = create_app(service_name="posts")

    assert TestClient(app).get("/health").status_code == 200
    shutdown_tracing()


def test_instrumenting_is_skipped_when_disabled(monkeypatch: MonkeyPatch) -> None:
    from fastapi import FastAPI

    from webbpulse.otel import instrument_fastapi

    monkeypatch.setenv(OTEL_DISABLED_ENV, "1")
    # The assertion is simply that this does not raise and does not install anything.
    instrument_fastapi(FastAPI())


# --------------------------------------------------------------------------------------
# Tail sampling
#
# The unit under test is `TailSamplingSpanProcessor` driven through a real `TracerProvider`
# with an `InMemorySpanExporter`, so the assertions are about what an exporter would
# actually receive rather than about the processor's internal bookkeeping.
# --------------------------------------------------------------------------------------


def _tail_harness(ratio: float, **kwargs: Any) -> tuple[Any, TailSamplingSpanProcessor, Any]:
    """An exporter, the processor under test, and a tracer feeding it.

    A local `TracerProvider` rather than the global one, so these tests never contend with
    the set-once global and can run in any order.
    """
    from opentelemetry.sdk.trace import SpanProcessor, TracerProvider
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    from opentelemetry.sdk.trace.sampling import ALWAYS_ON, ParentBased

    exporter = InMemorySpanExporter()
    processor = TailSamplingSpanProcessor(exporter, sample_ratio=ratio, **kwargs)
    # The same sampler `configure_tracing` installs: everything is recorded so the tail step
    # is the only thing making a decision.
    provider = TracerProvider(sampler=ParentBased(root=ALWAYS_ON))
    # The processor is structurally a SpanProcessor but deliberately not a subclass of one;
    # see its docstring for why. The cast is the same one `configure_tracing` makes.
    provider.add_span_processor(cast("SpanProcessor", processor))
    return exporter, processor, provider.get_tracer("test")


def test_an_error_trace_is_kept_even_at_ratio_zero() -> None:
    """The whole point of the tail step. At 0.0 a ratio decision keeps nothing."""
    from opentelemetry.trace import Status, StatusCode

    exporter, processor, tracer = _tail_harness(0.0)

    with tracer.start_as_current_span("failing") as span:
        span.set_status(Status(StatusCode.ERROR))
    processor.force_flush()

    assert [s.name for s in exporter.get_finished_spans()] == ["failing"]
    assert processor.exported_traces == 1
    assert processor.sampled_out_traces == 0


def test_an_exception_event_keeps_a_trace_without_an_error_status() -> None:
    """`record_exception` adds an `exception` event and does not always set the status.

    Botocore's instrumentation is the case that matters: a failed AWS call records the
    exception on the span, so keying only on `StatusCode.ERROR` would miss it.
    """
    exporter, processor, tracer = _tail_harness(0.0)

    with pytest.raises(ValueError, match="boom"), tracer.start_as_current_span("calling"):
        raise ValueError("boom")
    processor.force_flush()

    exported = exporter.get_finished_spans()
    assert [s.name for s in exported] == ["calling"]
    assert any(event.name == "exception" for event in exported[0].events)


def test_an_exception_event_alone_is_enough(monkeypatch: MonkeyPatch) -> None:
    """A span carrying only the event, with an unset status, still keeps its trace."""
    from opentelemetry.trace import StatusCode

    exporter, processor, tracer = _tail_harness(0.0)

    span = tracer.start_span("recorded")
    span.record_exception(RuntimeError("noted"))
    span.end()
    processor.force_flush()

    exported = exporter.get_finished_spans()
    assert len(exported) == 1
    # The status was never set, so this trace was kept purely on the event.
    assert exported[0].status.status_code is not StatusCode.ERROR


def test_a_non_error_trace_is_dropped_at_ratio_zero() -> None:
    exporter, processor, tracer = _tail_harness(0.0)

    with tracer.start_as_current_span("healthy"):
        pass
    processor.force_flush()

    assert exporter.get_finished_spans() == ()
    assert processor.sampled_out_traces == 1
    assert processor.exported_traces == 0


def test_a_non_error_trace_is_kept_at_ratio_one() -> None:
    exporter, processor, tracer = _tail_harness(1.0)

    with tracer.start_as_current_span("healthy"):
        pass
    processor.force_flush()

    assert [s.name for s in exporter.get_finished_spans()] == ["healthy"]
    assert processor.exported_traces == 1


def test_an_error_keeps_every_span_in_its_trace() -> None:
    """A trace is kept or dropped whole. A root plus its children arrive together."""
    from opentelemetry.trace import Status, StatusCode

    exporter, processor, tracer = _tail_harness(0.0)

    with tracer.start_as_current_span("root"):
        with tracer.start_as_current_span("child-ok"):
            pass
        with tracer.start_as_current_span("child-bad") as bad:
            bad.set_status(Status(StatusCode.ERROR))
    processor.force_flush()

    assert {s.name for s in exporter.get_finished_spans()} == {"root", "child-ok", "child-bad"}


def test_errors_can_be_opted_out_of() -> None:
    """`always_sample_errors=False` reduces the processor to pure ratio sampling."""
    from opentelemetry.trace import Status, StatusCode

    exporter, processor, tracer = _tail_harness(0.0, always_sample_errors=False)

    with tracer.start_as_current_span("failing") as span:
        span.set_status(Status(StatusCode.ERROR))
    processor.force_flush()

    assert exporter.get_finished_spans() == ()
    assert processor.sampled_out_traces == 1


def test_nothing_is_exported_before_a_flush() -> None:
    """The decision needs the whole trace, so a span that has ended is still only buffered.

    This is what makes the flush at the end of a Lambda invocation mandatory rather than an
    optimisation.
    """
    exporter, processor, tracer = _tail_harness(1.0)

    with tracer.start_as_current_span("healthy"):
        pass

    assert exporter.get_finished_spans() == ()
    processor.force_flush()
    assert len(exporter.get_finished_spans()) == 1


# --------------------------------------------------------------------------------------
# The ratio decision itself
# --------------------------------------------------------------------------------------


def test_the_bound_matches_the_sdk_sampler() -> None:
    """The tail decision has to agree with `TraceIdRatioBased` or it stops composing.

    An upstream service running the stock head sampler at the same ratio must reach the same
    verdict on the same trace id, otherwise a trace is kept in fragments.
    """
    from opentelemetry.sdk.trace.sampling import TraceIdRatioBased

    for ratio in (0.0, 0.05, 0.1, 0.5, 1.0):
        assert otel._ratio_bound(ratio) == TraceIdRatioBased.get_bound_for_rate(ratio)


def test_the_keep_decision_matches_the_sdk_sampler() -> None:
    """Same arithmetic, span by span, across a spread of trace ids."""
    from opentelemetry.sdk.trace.sampling import Decision, TraceIdRatioBased

    sampler = TraceIdRatioBased(0.5)
    bound = otel._ratio_bound(0.5)

    for trace_id in (1, 2**63 - 1, 2**63, 2**64 - 1, 2**127, 0xDEADBEEF):
        sdk_decision = sampler.should_sample(None, trace_id, "span").decision
        expected = sdk_decision is Decision.RECORD_AND_SAMPLE
        assert otel._trace_id_is_sampled(trace_id, bound) is expected


def test_the_decision_at_half_is_deterministic_by_trace_id() -> None:
    """The same trace id always lands the same way, and the split is by the low 64 bits.

    Explicit ids rather than a statistical check, so this test cannot flake.
    """
    bound = otel._ratio_bound(0.5)

    # The low 64 bits below the midpoint are kept.
    assert otel._trace_id_is_sampled(0x0000_0000_0000_0001, bound) is True
    assert otel._trace_id_is_sampled((1 << 63) - 1, bound) is True
    # At or above the midpoint they are dropped.
    assert otel._trace_id_is_sampled(1 << 63, bound) is False
    assert otel._trace_id_is_sampled((1 << 64) - 1, bound) is False
    # Only the low 64 bits count, so the high half cannot change the verdict.
    assert otel._trace_id_is_sampled((0xFFFF_FFFF_FFFF_FFFF << 64) | 1, bound) is True


def test_a_trace_kept_at_a_low_ratio_is_kept_at_a_higher_one() -> None:
    """The bound is monotonic, so raising the ratio only ever adds traces."""
    low, high = otel._ratio_bound(0.1), otel._ratio_bound(0.5)
    kept_at_low = [i for i in range(0, 1 << 64, 1 << 55) if otel._trace_id_is_sampled(i, low)]

    assert kept_at_low
    assert all(otel._trace_id_is_sampled(i, high) for i in kept_at_low)


# --------------------------------------------------------------------------------------
# The buffer cap
# --------------------------------------------------------------------------------------


def test_a_trace_over_the_cap_is_exported_by_default() -> None:
    """`on_overflow="export"` keeps the outlier, which is the useful bias for a big trace."""
    exporter, processor, tracer = _tail_harness(0.0, max_spans_per_trace=3)

    with tracer.start_as_current_span("root"):
        for i in range(6):
            with tracer.start_as_current_span(f"child-{i}"):
                pass
    processor.force_flush()

    # Every span in the trace arrives: the buffered ones and the ones streamed through after.
    assert len(exporter.get_finished_spans()) == 7
    assert processor.dropped_traces == 0


def test_a_trace_over_the_cap_can_be_dropped_with_a_counter() -> None:
    exporter, processor, tracer = _tail_harness(1.0, max_spans_per_trace=3, on_overflow="drop")

    with tracer.start_as_current_span("root"):
        for i in range(6):
            with tracer.start_as_current_span(f"child-{i}"):
                pass
    processor.force_flush()

    # Dropped despite ratio 1.0: the cap is a memory bound, not a sampling decision.
    assert exporter.get_finished_spans() == ()
    assert processor.dropped_traces == 1


def test_the_buffer_never_grows_past_the_cap() -> None:
    """The memory bound is the claim being tested, so assert on the buffer itself."""
    _, processor, tracer = _tail_harness(1.0, max_spans_per_trace=4, on_overflow="drop")

    with tracer.start_as_current_span("root"):
        for i in range(20):
            with tracer.start_as_current_span(f"child-{i}"):
                pass

    assert all(len(buffer) <= 4 for buffer in processor._buffers.values())


def test_a_trace_under_the_cap_is_unaffected() -> None:
    exporter, processor, tracer = _tail_harness(1.0, max_spans_per_trace=100)

    with tracer.start_as_current_span("root"), tracer.start_as_current_span("child"):
        pass
    processor.force_flush()

    assert len(exporter.get_finished_spans()) == 2
    assert processor.dropped_traces == 0


def test_traces_are_decided_independently() -> None:
    """One trace overflowing must not resolve another one."""
    exporter, processor, tracer = _tail_harness(1.0, max_spans_per_trace=2, on_overflow="drop")

    with tracer.start_as_current_span("big"):
        for i in range(5):
            with tracer.start_as_current_span(f"child-{i}"):
                pass
    with tracer.start_as_current_span("small"):
        pass
    processor.force_flush()

    assert [s.name for s in exporter.get_finished_spans()] == ["small"]
    assert processor.dropped_traces == 1


def test_the_constructor_rejects_nonsense() -> None:
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    with pytest.raises(ValueError, match="sample_ratio"):
        TailSamplingSpanProcessor(exporter, sample_ratio=1.5)
    with pytest.raises(ValueError, match="max_spans_per_trace"):
        TailSamplingSpanProcessor(exporter, max_spans_per_trace=0)
    with pytest.raises(ValueError, match="on_overflow"):
        TailSamplingSpanProcessor(exporter, on_overflow="explode")  # type: ignore[arg-type]


def test_shutdown_flushes_what_is_buffered() -> None:
    """The container shutdown path must not lose a trace that was already decided keep."""
    exporter, processor, tracer = _tail_harness(1.0)

    with tracer.start_as_current_span("healthy"):
        pass
    processor.shutdown()

    assert len(exporter.get_finished_spans()) == 1


def test_an_exporter_that_raises_does_not_break_the_request() -> None:
    """A failing exporter must never surface as a 500 on the request that produced the span."""
    from opentelemetry.sdk.trace import SpanProcessor, TracerProvider
    from opentelemetry.sdk.trace.export import SpanExporter
    from opentelemetry.sdk.trace.sampling import ALWAYS_ON, ParentBased

    class Exploding(SpanExporter):
        def export(self, spans: Any) -> Any:
            raise RuntimeError("network gone")

    processor = TailSamplingSpanProcessor(Exploding(), sample_ratio=1.0)
    provider = TracerProvider(sampler=ParentBased(root=ALWAYS_ON))
    provider.add_span_processor(cast("SpanProcessor", processor))

    with provider.get_tracer("test").start_as_current_span("healthy"):
        pass
    assert processor.force_flush() is True


# --------------------------------------------------------------------------------------
# Resolving the ratio from the environment
# --------------------------------------------------------------------------------------


def test_the_ratio_defaults_to_keeping_everything() -> None:
    """A service with nothing configured should not silently lose traces."""
    assert resolve_sample_ratio() == 1.0


def test_an_explicit_ratio_wins_over_the_environment(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv(SAMPLE_RATIO_ENV, "0.5")
    assert resolve_sample_ratio(0.1) == 0.1


def test_an_explicit_ratio_out_of_range_is_a_programming_error() -> None:
    """An argument is code, so it raises. An environment variable is config, so it warns."""
    with pytest.raises(ValueError, match="sample_ratio"):
        resolve_sample_ratio(1.5)


def test_the_package_env_var_sets_the_ratio(monkeypatch: MonkeyPatch) -> None:
    """This is the variable Terraform sets: 1.0 on staging, 0.1 on production."""
    monkeypatch.setenv(SAMPLE_RATIO_ENV, "0.1")
    assert resolve_sample_ratio() == 0.1


def test_the_sampler_arg_is_the_fallback_under_a_ratio_sampler(monkeypatch: MonkeyPatch) -> None:
    """A service already configured the OpenTelemetry way keeps its ratio."""
    monkeypatch.setenv("OTEL_TRACES_SAMPLER", "parentbased_traceidratio")
    monkeypatch.setenv("OTEL_TRACES_SAMPLER_ARG", "0.25")
    assert resolve_sample_ratio() == 0.25


def test_the_bare_ratio_sampler_name_is_honoured_too(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("OTEL_TRACES_SAMPLER", "traceidratio")
    monkeypatch.setenv("OTEL_TRACES_SAMPLER_ARG", "0.4")
    assert resolve_sample_ratio() == 0.4


def test_the_sampler_arg_is_ignored_under_a_non_ratio_sampler(monkeypatch: MonkeyPatch) -> None:
    """Under `always_on` the arg is meaningless, and reading it would invent a ratio.

    This is the case that matters in production: `OTEL_TRACES_SAMPLER=always_on` is what has
    to be set so the ADOT configurator does not install a head sampler that pre-drops spans,
    and a stale `OTEL_TRACES_SAMPLER_ARG` left beside it must not become the tail ratio.
    """
    monkeypatch.setenv("OTEL_TRACES_SAMPLER", "always_on")
    monkeypatch.setenv("OTEL_TRACES_SAMPLER_ARG", "0.01")
    assert resolve_sample_ratio() == 1.0


def test_the_package_env_var_beats_the_sampler_arg(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv(SAMPLE_RATIO_ENV, "0.9")
    monkeypatch.setenv("OTEL_TRACES_SAMPLER", "traceidratio")
    monkeypatch.setenv("OTEL_TRACES_SAMPLER_ARG", "0.01")
    assert resolve_sample_ratio() == 0.9


@pytest.mark.parametrize("value", ["not-a-number", "-0.5", "2.0", ""])
def test_an_unusable_ratio_degrades_to_keeping_everything(
    monkeypatch: MonkeyPatch, value: str
) -> None:
    """A typo in a Terraform variable should cost money, not availability."""
    monkeypatch.setenv(SAMPLE_RATIO_ENV, value)
    assert resolve_sample_ratio() == 1.0


def test_a_bad_package_var_still_falls_through_to_the_sampler_arg(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setenv(SAMPLE_RATIO_ENV, "banana")
    monkeypatch.setenv("OTEL_TRACES_SAMPLER", "traceidratio")
    monkeypatch.setenv("OTEL_TRACES_SAMPLER_ARG", "0.3")
    assert resolve_sample_ratio() == 0.3


# --------------------------------------------------------------------------------------
# configure_tracing wiring
# --------------------------------------------------------------------------------------


def test_configure_tracing_installs_an_always_on_sampler(monkeypatch: MonkeyPatch) -> None:
    """The head sampler must not pre-drop, or "errors are always sampled" is a lie.

    `TracerProvider.__init__` falls back to `sampling._get_from_env_or_default()` when no
    sampler is passed, and that reads `OTEL_TRACES_SAMPLER`. This asserts the explicit
    sampler wins, so an operator setting a ratio sampler in the environment, or the ADOT
    configurator doing it, cannot silently defeat the tail step.
    """
    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)
    monkeypatch.setenv("OTEL_TRACES_SAMPLER", "parentbased_traceidratio")
    monkeypatch.setenv("OTEL_TRACES_SAMPLER_ARG", "0.0")

    assert configure_tracing("posts") is True

    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.sampling import ALWAYS_ON, ParentBased

    provider = trace.get_tracer_provider()
    assert isinstance(provider, TracerProvider)
    assert isinstance(provider.sampler, ParentBased)
    assert provider.sampler._root is ALWAYS_ON

    # And the ratio still came from the environment, so an operator setting 0.0 gets 0.0.
    assert otel._PROCESSOR is not None
    assert otel._PROCESSOR.sample_ratio == 0.0
    shutdown_tracing()


def test_configure_tracing_takes_the_ratio_as_a_keyword(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)

    configure_tracing("posts", sample_ratio=0.1, always_sample_errors=False)

    assert otel._PROCESSOR is not None
    assert otel._PROCESSOR.sample_ratio == 0.1
    assert otel._PROCESSOR._always_sample_errors is False
    shutdown_tracing()


def test_configure_tracing_registers_exactly_one_processor(monkeypatch: MonkeyPatch) -> None:
    """A BatchSpanProcessor alongside the tail one would double-export every kept trace."""
    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)

    configure_tracing("posts")

    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider

    provider = trace.get_tracer_provider()
    assert isinstance(provider, TracerProvider)
    processors = provider._active_span_processor._span_processors
    assert len(processors) == 1
    assert isinstance(processors[0], TailSamplingSpanProcessor)
    shutdown_tracing()


def test_flush_tracing_is_safe_with_no_provider(monkeypatch: MonkeyPatch) -> None:
    """A service that never configured tracing can still call the flush hook."""
    monkeypatch.setenv(OTEL_DISABLED_ENV, "1")
    otel._PROCESSOR = None
    # The API's default provider has no force_flush, so this reports that it did nothing.
    assert flush_tracing() is False


def test_flush_tracing_drives_the_installed_processor(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)
    configure_tracing("posts", sample_ratio=1.0)

    assert otel._PROCESSOR is not None
    assert flush_tracing() is True
    shutdown_tracing()


def test_a_record_only_span_is_still_tail_sampled() -> None:
    """The ADOT distro's `AlwaysRecordSampler` behaviour, reproduced without the distro.

    `aws-opentelemetry-distro` wraps whatever `OTEL_TRACES_SAMPLER` names in an
    `AlwaysRecordSampler`, which turns a `Decision.DROP` into `Decision.RECORD_ONLY`. A
    RECORD_ONLY span is created and passed to every processor, but its context has the
    sampled flag clear, and the SDK's own `BatchSpanProcessor` and `SimpleSpanProcessor` both
    open `on_end` with `if not span.context.trace_flags.sampled: return`.

    `TailSamplingSpanProcessor` deliberately does not filter on that flag: the flag is a head
    decision and this processor exists to make a later one. The stub below is the distro's
    wrapper reimplemented over a ratio-0 sampler, and the assertion is that an error trace
    survives it. That is the safety net behind the `OTEL_TRACES_SAMPLER=always_on` guidance:
    even if the distro's provider wins the `set_tracer_provider` race with a ratio sampler
    configured, the error trace is still recorded and still kept.
    """
    from opentelemetry.sdk.trace import SpanProcessor, TracerProvider
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    from opentelemetry.sdk.trace.sampling import (
        Decision,
        Sampler,
        SamplingResult,
        TraceIdRatioBased,
    )
    from opentelemetry.trace import Status, StatusCode

    class AlwaysRecord(Sampler):
        """The distro's wrapper: DROP becomes RECORD_ONLY, everything else passes through."""

        def __init__(self, root: Sampler) -> None:
            self._root = root

        def should_sample(
            self,
            parent_context: Any = None,
            trace_id: int = 0,
            name: str = "",
            kind: Any = None,
            attributes: Any = None,
            links: Any = None,
            trace_state: Any = None,
        ) -> SamplingResult:
            result = self._root.should_sample(
                parent_context, trace_id, name, kind, attributes, links, trace_state
            )
            if result.decision is Decision.DROP:
                return SamplingResult(Decision.RECORD_ONLY, attributes or {}, result.trace_state)
            return result

        def get_description(self) -> str:
            return "AlwaysRecord"

    exporter = InMemorySpanExporter()
    processor = TailSamplingSpanProcessor(exporter, sample_ratio=0.0)
    provider = TracerProvider(sampler=AlwaysRecord(TraceIdRatioBased(0.0)))
    provider.add_span_processor(cast("SpanProcessor", processor))

    with provider.get_tracer("test").start_as_current_span("failing") as span:
        # The head sampler dropped it, so the wire flag is clear, but it is still recording.
        assert span.get_span_context().trace_flags.sampled is False
        assert span.is_recording() is True
        span.set_status(Status(StatusCode.ERROR))
    processor.force_flush()

    assert [s.name for s in exporter.get_finished_spans()] == ["failing"]


def _recording_flush(calls: list[int]) -> Any:
    """A `flush_tracing` stand-in that records that it was called."""

    def fake_flush(timeout_millis: int = 30000) -> bool:
        calls.append(timeout_millis)
        return True

    return fake_flush


def _app_with_flush_middleware(*, flush_per_request: bool | None = True) -> Any:
    """A minimal FastAPI app carrying the flush middleware, with tracing configured."""
    from fastapi import FastAPI

    from webbpulse.otel import instrument_fastapi

    configure_tracing("posts", endpoint="http://localhost:4318/v1/traces")
    app = FastAPI()

    @app.get("/thing")
    def thing() -> dict[str, str]:
        return {"ok": "yes"}

    instrument_fastapi(app, flush_per_request=flush_per_request)
    return app


def test_the_middleware_flushes_before_returning_the_response(monkeypatch: MonkeyPatch) -> None:
    """Under the Web Adapter the sandbox freezes once the response completes.

    So the flush has to happen while the request is still in flight. Recording the order
    proves it ran before the response was handed back, not after.
    """
    from fastapi.testclient import TestClient

    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)
    calls: list[int] = []
    monkeypatch.setattr(otel, "flush_tracing", _recording_flush(calls))

    app = _app_with_flush_middleware()
    with TestClient(app) as client:
        response = client.get("/thing")

    assert response.status_code == 200
    assert calls == [1000]
    shutdown_tracing()


def test_a_flush_failure_does_not_change_the_response(monkeypatch: MonkeyPatch) -> None:
    """Telemetry must never turn a healthy 200 into a 500.

    The response is already built by the time the flush runs, so a raising exporter is
    logged and swallowed rather than allowed to propagate out of the middleware.
    """
    from fastapi.testclient import TestClient

    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)

    def boom(timeout_millis: int = 30000) -> bool:
        raise RuntimeError("exporter is down")

    monkeypatch.setattr(otel, "flush_tracing", boom)

    app = _app_with_flush_middleware()
    with TestClient(app) as client:
        response = client.get("/thing")

    assert response.status_code == 200
    assert response.json() == {"ok": "yes"}
    shutdown_tracing()


def test_the_flush_middleware_is_off_outside_lambda(monkeypatch: MonkeyPatch) -> None:
    """A long-lived server flushes on its own schedule and should not pay per request."""
    from fastapi.testclient import TestClient

    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)
    monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME", raising=False)
    calls: list[int] = []
    monkeypatch.setattr(otel, "flush_tracing", _recording_flush(calls))

    app = _app_with_flush_middleware(flush_per_request=None)
    with TestClient(app) as client:
        assert client.get("/thing").status_code == 200

    assert calls == []
    shutdown_tracing()


def test_the_flush_middleware_is_on_under_lambda(monkeypatch: MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "webbpulse-staging-posts")
    calls: list[int] = []
    monkeypatch.setattr(otel, "flush_tracing", _recording_flush(calls))

    app = _app_with_flush_middleware(flush_per_request=None)
    with TestClient(app) as client:
        assert client.get("/thing").status_code == 200

    assert calls == [1000]
    shutdown_tracing()


def _real_pipeline_app(ratio: float) -> tuple[Any, Any]:
    """A real FastAPI app whose tail processor exports into memory, wired end to end.

    Deliberately not a monkeypatched `flush_tracing`: the defect this guards against is one
    of *ordering* relative to the OTel server span middleware, and a stubbed flush records
    that it was called without recording whether the server span had ended by then.
    """
    from fastapi import FastAPI
    from opentelemetry import trace
    from opentelemetry.sdk.trace import SpanProcessor, TracerProvider
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    from opentelemetry.sdk.trace.sampling import ALWAYS_ON, ParentBased

    from webbpulse.otel import instrument_fastapi

    exporter = InMemorySpanExporter()
    processor = TailSamplingSpanProcessor(exporter, sample_ratio=ratio)
    provider = TracerProvider(sampler=ParentBased(root=ALWAYS_ON))
    provider.add_span_processor(cast("SpanProcessor", processor))
    trace.set_tracer_provider(provider)
    otel._PROCESSOR = processor

    app = FastAPI()

    @app.get("/thing")
    def thing() -> dict[str, str]:
        return {"ok": "yes"}

    @app.get("/boom")
    def boom() -> dict[str, str]:
        raise RuntimeError("kaboom")

    instrument_fastapi(app, excluded_urls="", flush_per_request=True)
    return app, exporter


def test_the_request_own_server_span_is_exported_before_the_response_returns() -> None:
    """The flush must run OUTSIDE the OTel middleware, not inside it.

    `instrument_app` replaces `build_middleware_stack` so `OpenTelemetryMiddleware` wraps the
    whole stack. A flush registered with `add_middleware` runs inside that, before the server
    span has ended, so it exports the *previous* request's trace and leaves this one
    buffered. Under the Web Adapter the sandbox then freezes on the buffered trace and it is
    lost. Asserting on the span names, rather than on a flush having been called, is what
    makes this test able to see the difference.
    """
    from fastapi.testclient import TestClient

    app, exporter = _real_pipeline_app(1.0)
    with TestClient(app) as client:
        assert client.get("/thing").status_code == 200

    names = [s.name for s in exporter.get_finished_spans()]
    assert names, "the request's own trace was still buffered when the response returned"
    assert any("/thing" in name for name in names), names
    shutdown_tracing()


def test_an_error_trace_is_exported_at_ratio_zero_through_the_real_stack() -> None:
    """The whole point of the design, asserted end to end rather than on the processor alone.

    At ratio 0.0 nothing is kept except errors. If the flush ran a request out of step, the
    500's trace would be judged keep-worthy and then left buffered, which is the exact case
    the tail sampling exists for.
    """
    from fastapi.testclient import TestClient

    app, exporter = _real_pipeline_app(0.0)
    with TestClient(app, raise_server_exceptions=False) as client:
        assert client.get("/boom").status_code == 500

    names = [s.name for s in exporter.get_finished_spans()]
    assert names, "the error trace was judged keep-worthy and then left buffered"
    shutdown_tracing()


def test_a_non_error_request_exports_nothing_at_ratio_zero() -> None:
    """The other half: the flush firing must not mean the trace is kept regardless."""
    from fastapi.testclient import TestClient

    app, exporter = _real_pipeline_app(0.0)
    with TestClient(app) as client:
        assert client.get("/thing").status_code == 200

    assert exporter.get_finished_spans() == ()
    shutdown_tracing()


def test_a_flush_leaves_a_concurrent_in_flight_trace_alone() -> None:
    """One request's flush must not judge another request's half-built trace.

    Reproduces the concurrent case directly: trace A is still open when trace B finishes and
    flushes. Judging A on the spans that happen to have ended so far would drop it, and the
    rest of A would then be judged all over again as if it were a separate trace, so one
    logical trace ends up half exported and half discarded. At ratio 0.0 with an ERROR on A's
    root, A must survive intact once it actually completes.
    """
    from opentelemetry.trace import Status, StatusCode

    exporter, processor, tracer = _tail_harness(0.0)

    a_root = tracer.start_span("a-root")
    with trace_api.use_span(a_root, end_on_exit=False):
        child = tracer.start_span("a-child")
        child.end()

    # Trace B completes and flushes while A is still open.
    with tracer.start_as_current_span("b-root"):
        pass
    processor.force_flush()

    assert exporter.get_finished_spans() == (), "an in-flight trace was judged early"

    a_root.set_status(Status(StatusCode.ERROR))
    a_root.end()
    processor.force_flush()

    assert sorted(s.name for s in exporter.get_finished_spans()) == ["a-child", "a-root"]


def test_a_flush_still_exports_traces_that_are_complete() -> None:
    """The in-flight guard must not stall traces that are genuinely finished."""
    exporter, processor, tracer = _tail_harness(1.0)

    open_root = tracer.start_span("open-root")
    with tracer.start_as_current_span("done-root"):
        pass
    processor.force_flush()

    assert [s.name for s in exporter.get_finished_spans()] == ["done-root"]
    open_root.end()


def test_shutdown_resolves_a_trace_that_is_still_in_flight() -> None:
    """`force_flush` defers an open trace because its request will flush later.

    At shutdown there is no later, so a half-recorded error trace is judged on what it has
    rather than discarded silently.
    """
    from opentelemetry.trace import Status, StatusCode

    exporter, processor, tracer = _tail_harness(0.0)

    root = tracer.start_span("dangling")
    with trace_api.use_span(root, end_on_exit=False):
        child = tracer.start_span("dangling-child")
        child.set_status(Status(StatusCode.ERROR))
        child.end()

    processor.force_flush()
    assert exporter.get_finished_spans() == ()

    processor.shutdown()
    assert [s.name for s in exporter.get_finished_spans()] == ["dangling-child"]


def test_too_many_buffered_traces_evicts_the_oldest() -> None:
    """The per-trace cap bounds one trace; this bounds the number of them.

    A trace is only drained when it completes and a flush comes round, so without a ceiling
    on the count a leaked or abandoned trace sits in the buffer for the life of the process.
    """
    exporter, processor, tracer = _tail_harness(1.0, max_buffered_traces=2)

    for i in range(4):
        with tracer.start_as_current_span(f"root-{i}"):
            pass

    # Evicting resolves the trace rather than discarding it, so at ratio 1.0 the evicted
    # ones are exported rather than lost.
    assert processor.evicted_traces == 2
    assert sorted(s.name for s in exporter.get_finished_spans()) == ["root-0", "root-1"]
    assert len(processor._buffers) == 2


def test_eviction_still_honours_the_error_rule() -> None:
    """An evicted trace is judged, not dumped, so an error survives eviction at ratio 0."""
    from opentelemetry.trace import Status, StatusCode

    exporter, processor, tracer = _tail_harness(0.0, max_buffered_traces=1)

    with tracer.start_as_current_span("failing") as span:
        span.set_status(Status(StatusCode.ERROR))
    for i in range(2):
        with tracer.start_as_current_span(f"fine-{i}"):
            pass

    assert [s.name for s in exporter.get_finished_spans()] == ["failing"]
    assert processor.sampled_out_traces >= 1


def test_eviction_skips_traces_that_are_still_open() -> None:
    """Evicting an in-flight trace would reintroduce the partial-judgement bug."""
    exporter, _processor, tracer = _tail_harness(1.0, max_buffered_traces=1)

    open_root = tracer.start_span("still-open")
    with trace_api.use_span(open_root, end_on_exit=False):
        child = tracer.start_span("open-child")
        child.end()
    for i in range(2):
        with tracer.start_as_current_span(f"complete-{i}"):
            pass

    names = [s.name for s in exporter.get_finished_spans()]
    assert "open-child" not in names, "an in-flight trace was evicted and judged early"
    open_root.end()


def test_a_flush_does_not_reset_an_open_traces_overflow_decision() -> None:
    """Clearing overflow markers for a still-open trace would re-judge its tail.

    Under `on_overflow="drop"` that means fragments of an already-dropped trace get exported
    later, which is worse than either honest outcome.
    """
    exporter, processor, tracer = _tail_harness(1.0, max_spans_per_trace=2, on_overflow="drop")

    root = tracer.start_span("over-root")
    with trace_api.use_span(root, end_on_exit=False):
        for i in range(3):
            child = tracer.start_span(f"over-child-{i}")
            child.end()
        assert processor.dropped_traces == 1

        processor.force_flush()

        # Still open, so the drop decision must still stand for the rest of the trace.
        late = tracer.start_span("over-child-late")
        late.end()
    root.end()
    processor.force_flush()

    assert exporter.get_finished_spans() == (), "a dropped trace leaked a fragment"


def test_an_export_does_not_hold_the_lock() -> None:
    """`export` is an HTTP round trip; holding the lock across it serialises every on_end.

    The exporter here reaches back into the processor's lock, which deadlocks if the export
    happens while it is held.
    """
    from opentelemetry.sdk.trace import SpanProcessor, TracerProvider
    from opentelemetry.sdk.trace.export import SpanExportResult
    from opentelemetry.sdk.trace.sampling import ALWAYS_ON, ParentBased

    seen: list[int] = []

    class ReentrantExporter:
        def export(self, spans: Any) -> Any:
            # Would block forever if `_export` were called under a held non-reentrant lock.
            acquired = processor._lock.acquire(timeout=2)
            assert acquired, "export ran while the processor lock was held"
            processor._lock.release()
            seen.extend(range(len(spans)))
            return SpanExportResult.SUCCESS

        def shutdown(self) -> None: ...

    processor = TailSamplingSpanProcessor(cast("Any", ReentrantExporter()), sample_ratio=1.0)
    provider = TracerProvider(sampler=ParentBased(root=ALWAYS_ON))
    provider.add_span_processor(cast("SpanProcessor", processor))

    with provider.get_tracer("test").start_as_current_span("work"):
        pass
    processor.force_flush()

    assert seen == [0]


def test_the_vpc_endpoint_form_is_detected_and_signed_for_its_own_region(
    monkeypatch: MonkeyPatch,
) -> None:
    """A function in a private subnet with no NAT gateway uses the interface VPC endpoint.

    It is still X-Ray and still needs signing, and signing it for `AWS_REGION` rather than
    the region in the host is a credential scope mismatch, which surfaces only as a 403.
    """
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    endpoint = "https://vpce-123-abc.xray.us-west-2.vpce.amazonaws.com/v1/traces"

    assert otel._is_xray_endpoint(endpoint) is True
    assert otel._region_for_endpoint(endpoint) == "us-west-2"


def test_another_aws_hosted_otlp_endpoint_is_not_treated_as_xray() -> None:
    """A substring match on `.amazonaws.com` would sign endpoints that must not be signed."""
    assert otel._is_xray_endpoint("https://otlp.example.amazonaws.com/v1/traces") is False
    assert otel._is_xray_endpoint("https://logs.us-west-2.amazonaws.com/v1/logs") is False
    assert otel._is_xray_endpoint("http://localhost:4318/v1/traces") is False
    assert otel._is_xray_endpoint("https://xray.us-west-2.amazonaws.com/v1/traces") is True


def test_an_overflowed_trace_leaves_no_marker_behind() -> None:
    """The overflow markers are the one structure nothing else reclaims.

    `force_flush` only walks `_buffers`, and `_resolve_overflow_locked` deletes the buffer
    entry before adding the marker, so an overflowed trace is never in the set the flush
    discards from. Left unfixed the markers grow without bound, uncapped by
    `max_buffered_traces`, and under `on_overflow="drop"` a later trace that reused the id
    would be discarded in silence.
    """
    _exporter, processor, tracer = _tail_harness(1.0, max_spans_per_trace=2, on_overflow="drop")

    for i in range(50):
        root = tracer.start_span(f"root-{i}")
        with trace_api.use_span(root, end_on_exit=False):
            for j in range(3):
                child = tracer.start_span(f"child-{j}")
                child.end()
        root.end()
        processor.force_flush()

    assert processor.dropped_traces == 50
    assert processor._overflowed_drop == set(), "overflow markers leaked"
    assert processor._overflowed_keep == set()
    assert processor._open_spans == {}
    assert processor._started_at == {}


def test_an_overflowed_keep_trace_also_clears_its_marker() -> None:
    exporter, processor, tracer = _tail_harness(1.0, max_spans_per_trace=2, on_overflow="export")

    root = tracer.start_span("over-root")
    with trace_api.use_span(root, end_on_exit=False):
        for j in range(3):
            child = tracer.start_span(f"c{j}")
            child.end()
    root.end()

    assert processor._overflowed_keep == set()
    assert [s.name for s in exporter.get_finished_spans()][-1] == "over-root"


def test_traces_that_never_complete_are_reclaimed_by_age() -> None:
    """The count bound alone cannot reclaim a leak.

    It refuses to evict an in-flight trace, correctly, so a supply of traces whose spans
    never end pins every buffer and the count bound never fires. Under Lambda nothing else
    ever reclaims them. The age bound is the only thing that does.
    """
    _exporter, processor, tracer = _tail_harness(
        1.0, max_buffered_traces=10, max_trace_age_seconds=0.05
    )

    leaked = []
    for i in range(50):
        root = tracer.start_span(f"leak-{i}")
        with trace_api.use_span(root, end_on_exit=False):
            child = tracer.start_span(f"leak-child-{i}")
            child.end()
        leaked.append(root)

    time.sleep(0.06)
    # Any subsequent span drives the sweep.
    with tracer.start_as_current_span("trigger"):
        pass

    assert processor.evicted_traces > 0, "leaked traces were never reclaimed"
    assert len(processor._buffers) <= 11
    for root in leaked:
        root.end()


def test_age_eviction_still_honours_the_error_rule() -> None:
    """Evicting by age judges the trace, so a stale error trace is exported, not binned."""
    from opentelemetry.trace import Status, StatusCode

    exporter, _processor, tracer = _tail_harness(0.0, max_trace_age_seconds=0.05)

    root = tracer.start_span("stale-failing")
    with trace_api.use_span(root, end_on_exit=False):
        child = tracer.start_span("stale-child")
        child.set_status(Status(StatusCode.ERROR))
        child.end()

    time.sleep(0.06)
    with tracer.start_as_current_span("trigger"):
        pass

    assert [s.name for s in exporter.get_finished_spans()] == ["stale-child"]
    root.end()


def test_a_young_in_flight_trace_is_not_evicted_by_age() -> None:
    """The age bound must not turn into the partial-judgement bug for ordinary requests."""
    exporter, processor, tracer = _tail_harness(1.0, max_trace_age_seconds=300.0)

    root = tracer.start_span("in-progress")
    with trace_api.use_span(root, end_on_exit=False):
        child = tracer.start_span("in-progress-child")
        child.end()
    with tracer.start_as_current_span("other"):
        pass

    assert "in-progress-child" not in [s.name for s in exporter.get_finished_spans()]
    assert processor.evicted_traces == 0
    root.end()


def test_the_exporter_is_given_the_export_deadline() -> None:
    """`flush_timeout_millis` only bounds anything if the exporter is told about it.

    The flush exports synchronously and `OTLPSpanExporter.force_flush` is a no-op, so the
    exporter's own `timeout`, a deadline across the whole export including retries, is the
    only thing that decides how long a request can be held waiting on telemetry.
    """
    exporter = otel._build_span_exporter("http://localhost:4318/v1/traces", 2000)
    assert exporter._timeout == 2  # type: ignore[attr-defined]

    signed = otel._build_span_exporter("https://xray.us-west-2.amazonaws.com/v1/traces", 3000)
    assert signed._timeout == 3  # type: ignore[attr-defined]

    # A sub-second deadline would fail even a healthy export on a cold TLS handshake.
    floored = otel._build_span_exporter("http://localhost:4318/v1/traces", 100)
    assert floored._timeout == 1  # type: ignore[attr-defined]


async def _noop_asgi_app(scope: Any, receive: Any, send: Any) -> None:
    """A minimal downstream app, standing in for the instrumented stack."""
    return None


async def _noop_receive() -> dict[str, Any]:
    return {"type": "http.request"}


async def _noop_send(message: dict[str, Any]) -> None:
    return None


def test_a_slow_export_does_not_stall_the_whole_event_loop() -> None:
    """The flush is synchronous HTTP, so it must not run on the event loop.

    Awaiting it inline stalls every other connection the process is serving for the length of
    the export, not just the request being flushed, and an export is exactly the operation
    slow enough for that to matter. A ticker coroutine stands in for those other connections:
    while the export is in flight it keeps running if the flush is on a worker thread, and
    cannot advance at all if the flush is holding the loop.
    """
    import asyncio

    from opentelemetry.sdk.trace import SpanProcessor, TracerProvider
    from opentelemetry.sdk.trace.export import SpanExportResult
    from opentelemetry.sdk.trace.sampling import ALWAYS_ON, ParentBased

    release_export = threading.Event()

    class BlockingExporter:
        def __init__(self) -> None:
            self.calls = 0

        def export(self, spans: Any) -> Any:
            self.calls += 1
            # Stands in for an export against a slow or unreachable endpoint.
            release_export.wait(timeout=5)
            return SpanExportResult.SUCCESS

        def shutdown(self) -> None: ...

    blocking = BlockingExporter()
    processor = TailSamplingSpanProcessor(cast("Any", blocking), sample_ratio=1.0)
    provider = TracerProvider(sampler=ParentBased(root=ALWAYS_ON))
    provider.add_span_processor(cast("SpanProcessor", processor))
    tracer = provider.get_tracer("test")
    otel._PROCESSOR = processor
    middleware = otel._FlushTracingASGIMiddleware(_noop_asgi_app, 1000)

    # A completed trace sitting in the buffer, so the flush has something real to export.
    with tracer.start_as_current_span("request"):
        pass

    ticks = 0

    async def ticker() -> None:
        nonlocal ticks
        while not release_export.is_set():
            await asyncio.sleep(0.01)
            ticks += 1

    async def drive() -> None:
        nonlocal ticks
        tick_task = asyncio.ensure_future(ticker())
        await asyncio.sleep(0.05)
        before = ticks

        # Release the export from outside the loop, so how long it blocks is fixed by the
        # clock rather than by anything the loop does or fails to do.
        def release_after_delay() -> None:
            time.sleep(0.3)
            release_export.set()

        threading.Thread(target=release_after_delay, daemon=True).start()

        await middleware({"type": "http"}, _noop_receive, _noop_send)

        gained = ticks - before
        await tick_task
        assert blocking.calls == 1, "the flush never exported"
        assert gained > 0, (
            f"the event loop made no progress ({gained} ticks) while the export was in "
            "flight, so the flush is blocking it"
        )

    asyncio.run(asyncio.wait_for(drive(), timeout=10))
    shutdown_tracing()


def test_the_flush_wrapper_is_installed_only_once() -> None:
    """Two instrument_fastapi calls must not nest two flush layers and flush twice."""
    from fastapi import FastAPI

    from webbpulse.otel import instrument_fastapi

    configure_tracing("posts", endpoint="http://localhost:4318/v1/traces")
    app = FastAPI()

    @app.get("/thing")
    def thing() -> dict[str, str]:
        return {"ok": "yes"}

    instrument_fastapi(app, flush_per_request=True)
    instrument_fastapi(app, flush_per_request=True)

    stack = app.build_middleware_stack()
    layers = 0
    node: Any = stack
    while isinstance(node, otel._FlushTracingASGIMiddleware):
        layers += 1
        node = node.app
    assert layers == 1, f"the flush wrapper nested {layers} deep"
    shutdown_tracing()


def test_instrumenting_a_started_app_warns_that_there_will_be_no_spans(
    monkeypatch: MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """An app whose stack is built cannot take the server span middleware.

    Instrumenting it produces something that looks instrumented and emits nothing, which is
    more confusing than not instrumenting at all, so it has to say so.
    """
    from fastapi import FastAPI

    from webbpulse.otel import instrument_fastapi

    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)
    configure_tracing("posts", endpoint="http://localhost:4318/v1/traces")
    app = FastAPI()
    app.build_middleware_stack()
    app.middleware_stack = app.build_middleware_stack()

    with caplog.at_level("WARNING", logger="webbpulse.otel"):
        instrument_fastapi(app, flush_per_request=True)

    assert any("already started" in r.message for r in caplog.records)
    shutdown_tracing()


def test_the_fips_endpoint_is_detected_and_signed_for_its_own_region(
    monkeypatch: MonkeyPatch,
) -> None:
    """`xray-fips.<region>.amazonaws.com` is a real endpoint and needs signing like any other.

    Missing it means the one caller who is required to use FIPS, and cannot simply switch,
    silently gets an unsigned exporter and a 403.
    """
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    endpoint = "https://xray-fips.us-gov-west-1.amazonaws.com/v1/traces"

    assert otel._is_xray_endpoint(endpoint) is True
    assert otel._region_for_endpoint(endpoint) == "us-gov-west-1"


# --------------------------------------------------------------------------------------
# SigV4 credential freshness
#
# These drive the real `AwsAuthSession` from `aws-opentelemetry-distro` rather than a stand
# in for it, because the defect being guarded against lives in that class: it resolves
# credentials once and signs from the cached object forever. A fake session would prove
# nothing about whether the workaround actually lands.
# --------------------------------------------------------------------------------------


def _lambda_style_env(monkeypatch: MonkeyPatch, access_key: str) -> None:
    """The credential environment a Lambda execution environment has.

    Three variables and deliberately no `AWS_CREDENTIAL_EXPIRATION`, which is what makes
    botocore's `EnvProvider` hand back a plain non-refreshable `Credentials` object. Any
    ambient profile is cleared too: `AWS_PROFILE` makes the resolver skip the env provider
    entirely, so a developer's shell would otherwise change what is under test.
    """
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", access_key)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", f"secret-for-{access_key}")
    monkeypatch.setenv("AWS_SESSION_TOKEN", f"token-for-{access_key}")
    for name in ("AWS_CREDENTIAL_EXPIRATION", "AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
        monkeypatch.delenv(name, raising=False)


def _signing_probe(monkeypatch: MonkeyPatch, exporter: Any) -> tuple[Any, list[str]]:
    """A callable that posts once through the exporter's signing session, and the keys it used.

    The real `AwsAuthSession.request` runs, so the signing under test is the distro's own.
    Only the `requests.Session.request` underneath it is replaced, which is the first point
    at which the finished `Authorization` header is observable. The access key id is read
    back out of that header, which is where X-Ray reads it from too.
    """
    import requests

    signed: list[str] = []
    auth_session = exporter._session._session

    def fake_request(
        self: Any, method: Any = None, url: Any = None, *args: Any, **kwargs: Any
    ) -> Any:
        header = dict(kwargs.get("headers") or {}).get("Authorization", "")
        signed.append(header.split("Credential=")[1].split("/")[0])

        class _Response:
            ok = True
            status_code = 200
            reason = "OK"

        return _Response()

    monkeypatch.setattr(requests.Session, "request", fake_request)

    def post_once() -> None:
        auth_session.request("POST", "https://xray.us-west-2.amazonaws.com/v1/traces", data=b"")

    return post_once, signed


def test_rotated_lambda_credentials_are_picked_up_by_the_next_export(
    monkeypatch: MonkeyPatch,
) -> None:
    """The 403 loop this fixes: a warm sandbox outliving the credentials it started with.

    Lambda rewrites the credential environment variables when it renews the execution role,
    but the plain `Credentials` object botocore builds from them never re-reads them, and the
    distro caches that object for the life of the process. A container that survives longer
    than its credentials then signs every export with an expired token and X-Ray rejects all
    of them. The second signature here must use the new key, not the one from cold start.
    """
    _lambda_style_env(monkeypatch, "AKIAFIRSTKEY")

    exporter = otel._build_span_exporter("https://xray.us-west-2.amazonaws.com/v1/traces", 1000)
    post_once, signed = _signing_probe(monkeypatch, exporter)

    post_once()
    _lambda_style_env(monkeypatch, "AKIASECONDKEY")
    post_once()

    assert signed == ["AKIAFIRSTKEY", "AKIASECONDKEY"]


def test_unchanged_credentials_still_sign_consistently(monkeypatch: MonkeyPatch) -> None:
    """Re-resolving must not be mistaken for something that changes on its own.

    The steady state is by far the common one, so it gets an assertion of its own: nothing
    rotated, so both exports sign with the same key.
    """
    _lambda_style_env(monkeypatch, "AKIASTABLEKEY")

    exporter = otel._build_span_exporter("https://xray.us-west-2.amazonaws.com/v1/traces", 1000)
    post_once, signed = _signing_probe(monkeypatch, exporter)

    post_once()
    post_once()

    assert signed == ["AKIASTABLEKEY", "AKIASTABLEKEY"]


def test_refreshable_credentials_are_left_to_refresh_themselves() -> None:
    """A provider that already rotates is not second guessed.

    `RefreshableCredentials` talks to IMDS or the container credential endpoint on its own
    schedule, and re-running the resolver chain around it would throw that away. The
    workaround must apply only to the credentials that genuinely cannot refresh.
    """
    from botocore.credentials import RefreshableCredentials

    refreshable = RefreshableCredentials(
        "AKIAREFRESHABLE",
        "secret",
        "token",
        _far_future(),
        refresh_using=lambda: {},
        method="test",
    )

    class _Session:
        _credentials = refreshable
        cleared = False

        def get_credentials(self) -> Any:
            return refreshable

    session = _Session()
    credentials = otel._ReresolvingCredentials(session)

    assert credentials._current() is refreshable
    # The memo is untouched, so the provider chain was never re-run.
    assert session._credentials is refreshable


def test_missing_credentials_raise_rather_than_sign_unsigned() -> None:
    """No credentials is a real failure and must surface as one.

    Returning `None` here would let the request go out unsigned and collect a 403 that says
    nothing about why, which is the exact silent failure the rest of this module exists to
    prevent. `AwsAuthSession` catches and logs the raise with its reason attached.
    """
    from botocore.exceptions import NoCredentialsError

    class _Session:
        _credentials = None

        def get_credentials(self) -> Any:
            return None

    credentials = otel._ReresolvingCredentials(_Session())

    with pytest.raises(NoCredentialsError):
        credentials.get_frozen_credentials()


def _far_future() -> Any:
    """An expiry far enough out that `RefreshableCredentials` never tries to refresh."""
    import datetime

    return datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)


# --------------------------------------------------------------------------------------
# Export timeouts across a sandbox freeze
#
# `OTLPSpanExporter.export` derives each retry's HTTP timeout by subtracting wall clock time
# from a deadline it fixed at the start. A Lambda freeze makes that difference negative and
# urllib3 raises `ValueError` rather than treating it as expired, which is not a
# `RequestException` and so escapes upstream's own retry handling entirely.
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        (-221.002, otel._MIN_EXPORT_TIMEOUT_SECONDS),
        (0, otel._MIN_EXPORT_TIMEOUT_SECONDS),
        (0.0, otel._MIN_EXPORT_TIMEOUT_SECONDS),
        (5.0, 5.0),
        (None, None),
    ],
)
def test_a_non_positive_timeout_is_raised_to_the_floor(given: Any, expected: Any) -> None:
    """Only the non-positive values move. `None` means "no timeout" and is left alone."""
    assert otel._clamp_timeout(given) == expected


def test_both_halves_of_a_connect_read_timeout_are_clamped() -> None:
    """`requests` also accepts the tuple form, and urllib3 validates each half separately."""
    assert otel._clamp_timeout((-3.0, 4.0)) == (otel._MIN_EXPORT_TIMEOUT_SECONDS, 4.0)


def test_a_frozen_then_thawed_export_does_not_raise(monkeypatch: MonkeyPatch) -> None:
    """The end to end shape of the bug, driven through the real upstream exporter.

    Time is moved forward past the exporter's own deadline between constructing it and
    exporting, which is what a sandbox freeze does. Without the clamp the session receives a
    negative timeout; with it the post still happens and nothing propagates.
    """
    import opentelemetry.exporter.otlp.proto.http.trace_exporter as upstream

    exporter = otel._build_span_exporter("http://localhost:4318/v1/traces", 1000)

    seen: list[Any] = []

    class _Transport:
        headers: ClassVar[dict[str, str]] = {}

        def post(self, *args: Any, timeout: Any = None, **kwargs: Any) -> Any:
            seen.append(timeout)

            class _Response:
                ok = True
                status_code = 200
                reason = "OK"

            return _Response()

    # Swapped *underneath* whatever `_build_span_exporter` installed, so the clamp that is
    # under test is the one the real wiring put there rather than one this test added.
    guarded = cast("Any", exporter)._session
    assert isinstance(guarded, otel._PositiveTimeoutSession)
    guarded._session = _Transport()

    # The freeze: wall clock jumps well past the deadline `export` fixed for itself.
    monkeypatch.setattr(upstream, "time", lambda: time.time() + 3600)

    exporter.export([])

    assert seen, "the exporter never reached the session"
    assert all(value > 0 for value in seen), seen


def test_a_thawed_sandbox_does_not_log_an_error(caplog: pytest.LogCaptureFixture) -> None:
    """Losing spans to a freeze is not an application fault and must not page anyone.

    `_export` logs at ERROR, and a log metric filter turns that into a CloudWatch alarm. A
    request that was served correctly and only lost some of its telemetry has to come out
    below that line, while still being recorded.
    """

    class _RaisingExporter:
        def export(self, spans: Any) -> None:
            raise ValueError(
                "Attempted to set connect timeout to -221.00219130516052, but the timeout "
                "cannot be set to a value less than or equal to 0."
            )

    processor = TailSamplingSpanProcessor(cast("Any", _RaisingExporter()), sample_ratio=1.0)

    with caplog.at_level("WARNING", logger="webbpulse.otel"):
        processor._export([cast("Any", object())])

    assert not [record for record in caplog.records if record.levelname == "ERROR"]
    warnings = [record for record in caplog.records if record.levelname == "WARNING"]
    assert len(warnings) == 1
    assert "deadline had already passed" in warnings[0].message


def test_a_genuine_exporter_error_is_still_an_error(caplog: pytest.LogCaptureFixture) -> None:
    """The downgrade is narrow on purpose: everything else keeps its ERROR and its traceback.

    Blanket-silencing the exporter would trade a false alarm for a missing one, which is the
    worse of the two.
    """

    class _RaisingExporter:
        def export(self, spans: Any) -> None:
            raise ValueError("encoded span batch is malformed")

    processor = TailSamplingSpanProcessor(cast("Any", _RaisingExporter()), sample_ratio=1.0)

    with caplog.at_level("WARNING", logger="webbpulse.otel"):
        processor._export([cast("Any", object())])

    errors = [record for record in caplog.records if record.levelname == "ERROR"]
    assert len(errors) == 1
    assert "The span exporter raised" in errors[0].message


def test_a_non_value_error_from_the_exporter_is_still_an_error(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The pre-existing catch-all is unchanged: an exporter must never break the request."""

    class _RaisingExporter:
        def export(self, spans: Any) -> None:
            raise RuntimeError("the endpoint went away")

    processor = TailSamplingSpanProcessor(cast("Any", _RaisingExporter()), sample_ratio=1.0)

    with caplog.at_level("WARNING", logger="webbpulse.otel"):
        processor._export([cast("Any", object())])

    assert [record for record in caplog.records if record.levelname == "ERROR"]


def test_the_timeout_guard_survives_an_upstream_rename(caplog: pytest.LogCaptureFixture) -> None:
    """`_session` is private to upstream, so losing it must degrade rather than crash."""

    class _NoSession:
        pass

    exporter = _NoSession()
    otel._guard_export_timeouts(exporter)

    assert not hasattr(exporter, "_session")
