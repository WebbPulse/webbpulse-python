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
    SHUTDOWN_FLUSH_TIMEOUT_ENV,
    TailSamplingSpanProcessor,
    configure_tracing,
    flush_tracing,
    is_tracing_enabled,
    resolve_sample_ratio,
    resolve_shutdown_flush_timeout,
    shutdown_tracing,
    xray_otlp_endpoint,
)


def _clear_global_tracer_provider() -> None:
    """Reset the set-once global tracer provider so the next install actually takes effect."""
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
    """Each test starts from an environment with no sampling configuration in it."""
    for name in (
        SAMPLE_RATIO_ENV,
        SHUTDOWN_FLUSH_TIMEOUT_ENV,
        "OTEL_TRACES_SAMPLER",
        "OTEL_TRACES_SAMPLER_ARG",
    ):
        monkeypatch.delenv(name, raising=False)


def test_the_xray_endpoint_matches_the_documented_shape() -> None:
    """`https://xray.<region>.amazonaws.com/v1/traces`, per the CloudWatch OTLP endpoint docs."""
    assert xray_otlp_endpoint("us-west-2") == "https://xray.us-west-2.amazonaws.com/v1/traces"


def test_the_endpoint_region_comes_from_the_lambda_environment(monkeypatch: MonkeyPatch) -> None:
    """`AWS_REGION` picks the region in the generated X-Ray endpoint."""
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    assert xray_otlp_endpoint() == "https://xray.eu-west-1.amazonaws.com/v1/traces"


def test_the_endpoint_defaults_to_the_only_region_this_estate_uses(
    monkeypatch: MonkeyPatch,
) -> None:
    """With no region in the environment the endpoint falls back to us-west-2."""
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    assert xray_otlp_endpoint() == "https://xray.us-west-2.amazonaws.com/v1/traces"


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
def test_tracing_can_be_disabled_by_env_var(monkeypatch: MonkeyPatch, value: str) -> None:
    """Every truthy spelling of the disable variable turns tracing off."""
    monkeypatch.setenv(OTEL_DISABLED_ENV, value)
    assert is_tracing_enabled() is False


def test_the_specification_disable_flag_is_honoured(monkeypatch: MonkeyPatch) -> None:
    """`OTEL_SDK_DISABLED` is defined by the OpenTelemetry specification itself."""
    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)
    monkeypatch.setenv("OTEL_SDK_DISABLED", "true")
    assert is_tracing_enabled() is False


def test_tracing_is_enabled_by_default(monkeypatch: MonkeyPatch) -> None:
    """With neither disable variable set, tracing is on."""
    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)
    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)
    assert is_tracing_enabled() is True


def test_configure_tracing_is_a_no_op_when_disabled(monkeypatch: MonkeyPatch) -> None:
    """`configure_tracing` reports False and installs nothing when tracing is disabled."""
    monkeypatch.setenv(OTEL_DISABLED_ENV, "1")
    assert configure_tracing("posts") is False


def test_configure_tracing_installs_a_provider(monkeypatch: MonkeyPatch) -> None:
    """The installed provider carries the service, namespace and environment attributes."""
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
    assert attributes["deployment.environment"] == "staging"

    shutdown_tracing()


def test_configure_tracing_is_idempotent(monkeypatch: MonkeyPatch) -> None:
    """A second BatchSpanProcessor would double-export every span."""
    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)
    assert configure_tracing("posts") is True
    assert configure_tracing("posts") is False
    shutdown_tracing()


def test_lambda_resource_attributes_are_detected(monkeypatch: MonkeyPatch) -> None:
    """The Lambda function name and version become `faas.name` and `faas.version`."""
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
    """Attributes passed to `configure_tracing` land on the resource."""
    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)
    configure_tracing("posts", resource_attributes={"service.version": "2.1.0"})

    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider

    provider = trace.get_tracer_provider()
    assert isinstance(provider, TracerProvider)
    assert provider.resource.attributes["service.version"] == "2.1.0"
    shutdown_tracing()


def _without_adot_distro(monkeypatch: MonkeyPatch) -> None:
    """Make the ADOT distro import fail the way a minimal install does."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        """Raise ImportError for the distro, delegating everything else."""
        if name.startswith("amazon.opentelemetry"):
            raise ImportError(f"No module named {name!r}")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", fake_import)


def test_an_unsigned_xray_export_warns(
    monkeypatch: MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Without the distro an X-Ray endpoint warns about SigV4 and still returns a usable exporter."""
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

    _without_adot_distro(monkeypatch)

    with caplog.at_level("WARNING", logger="webbpulse.otel"):
        exporter = otel._build_span_exporter("https://xray.us-west-2.amazonaws.com/v1/traces", 1000)

    assert any("SigV4" in record.message for record in caplog.records)
    assert any("aws-otel" in record.message for record in caplog.records)
    assert type(exporter) is OTLPSpanExporter


def test_an_xray_endpoint_gets_the_signing_exporter() -> None:
    """The whole point of the extra: X-Ray must get the SigV4 subclass, not the plain one."""
    from amazon.opentelemetry.distro.exporter.otlp.aws.traces.otlp_aws_span_exporter import (
        OTLPAwsSpanExporter,
    )

    exporter = otel._build_span_exporter("https://xray.eu-west-1.amazonaws.com/v1/traces", 1000)

    assert isinstance(exporter, OTLPAwsSpanExporter)


def test_no_warning_when_the_distro_is_present(caplog: pytest.LogCaptureFixture) -> None:
    """With the distro installed, building an X-Ray exporter emits no SigV4 warning."""
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
    """An explicit cross-region endpoint must be signed for its own region, not AWS_REGION."""
    monkeypatch.setenv("AWS_REGION", "us-west-2")

    assert (
        otel._region_for_endpoint("https://xray.eu-west-1.amazonaws.com/v1/traces") == "eu-west-1"
    )


def test_the_signing_region_falls_back_to_the_environment(monkeypatch: MonkeyPatch) -> None:
    """An endpoint with no region in its host is signed for `AWS_REGION`."""
    monkeypatch.setenv("AWS_REGION", "ap-southeast-2")
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)

    assert otel._region_for_endpoint("https://otlp.example.com/v1/traces") == "ap-southeast-2"


def test_instrumenting_an_app_does_not_break_it(monkeypatch: MonkeyPatch) -> None:
    """An instrumented app still serves `/health` normally."""
    from fastapi.testclient import TestClient

    from webbpulse.http import create_app

    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)
    configure_tracing("posts")
    app = create_app(service_name="posts")

    assert TestClient(app).get("/health").status_code == 200
    shutdown_tracing()


def test_instrumenting_is_skipped_when_disabled(monkeypatch: MonkeyPatch) -> None:
    """`instrument_fastapi` neither raises nor installs anything when tracing is disabled."""
    from fastapi import FastAPI

    from webbpulse.otel import instrument_fastapi

    monkeypatch.setenv(OTEL_DISABLED_ENV, "1")
    instrument_fastapi(FastAPI())


def _tail_harness(ratio: float, **kwargs: Any) -> tuple[Any, TailSamplingSpanProcessor, Any]:
    """An in-memory exporter, the processor under test, and a tracer feeding it."""
    from opentelemetry.sdk.trace import SpanProcessor, TracerProvider
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    from opentelemetry.sdk.trace.sampling import ALWAYS_ON, ParentBased

    exporter = InMemorySpanExporter()
    processor = TailSamplingSpanProcessor(exporter, sample_ratio=ratio, **kwargs)
    provider = TracerProvider(sampler=ParentBased(root=ALWAYS_ON))
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
    """A recorded exception event keeps the trace even when the status is not ERROR."""
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
    assert exported[0].status.status_code is not StatusCode.ERROR


def test_a_non_error_trace_is_dropped_at_ratio_zero() -> None:
    """At ratio 0.0 a healthy trace is sampled out and nothing is exported."""
    exporter, processor, tracer = _tail_harness(0.0)

    with tracer.start_as_current_span("healthy"):
        pass
    processor.force_flush()

    assert exporter.get_finished_spans() == ()
    assert processor.sampled_out_traces == 1
    assert processor.exported_traces == 0


def test_a_non_error_trace_is_kept_at_ratio_one() -> None:
    """At ratio 1.0 a healthy trace is exported."""
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
    """An ended span stays buffered until a flush, so the flush is mandatory."""
    exporter, processor, tracer = _tail_harness(1.0)

    with tracer.start_as_current_span("healthy"):
        pass

    assert exporter.get_finished_spans() == ()
    processor.force_flush()
    assert len(exporter.get_finished_spans()) == 1


def test_the_bound_matches_the_sdk_sampler() -> None:
    """The tail decision has to agree with `TraceIdRatioBased` or it stops composing."""
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
    """The same trace id always lands the same way, and the split is by the low 64 bits."""
    bound = otel._ratio_bound(0.5)

    assert otel._trace_id_is_sampled(0x0000_0000_0000_0001, bound) is True
    assert otel._trace_id_is_sampled((1 << 63) - 1, bound) is True
    assert otel._trace_id_is_sampled(1 << 63, bound) is False
    assert otel._trace_id_is_sampled((1 << 64) - 1, bound) is False
    assert otel._trace_id_is_sampled((0xFFFF_FFFF_FFFF_FFFF << 64) | 1, bound) is True


def test_a_trace_kept_at_a_low_ratio_is_kept_at_a_higher_one() -> None:
    """The bound is monotonic, so raising the ratio only ever adds traces."""
    low, high = otel._ratio_bound(0.1), otel._ratio_bound(0.5)
    kept_at_low = [i for i in range(0, 1 << 64, 1 << 55) if otel._trace_id_is_sampled(i, low)]

    assert kept_at_low
    assert all(otel._trace_id_is_sampled(i, high) for i in kept_at_low)


def test_a_trace_over_the_cap_is_exported_by_default() -> None:
    """`on_overflow="export"` keeps the outlier, which is the useful bias for a big trace."""
    exporter, processor, tracer = _tail_harness(0.0, max_spans_per_trace=3)

    with tracer.start_as_current_span("root"):
        for i in range(6):
            with tracer.start_as_current_span(f"child-{i}"):
                pass
    processor.force_flush()

    assert len(exporter.get_finished_spans()) == 7
    assert processor.dropped_traces == 0


def test_a_trace_over_the_cap_can_be_dropped_with_a_counter() -> None:
    """`on_overflow="drop"` discards the trace even at ratio 1.0 and counts it."""
    exporter, processor, tracer = _tail_harness(1.0, max_spans_per_trace=3, on_overflow="drop")

    with tracer.start_as_current_span("root"):
        for i in range(6):
            with tracer.start_as_current_span(f"child-{i}"):
                pass
    processor.force_flush()

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
    """A trace smaller than the cap is exported whole and nothing is dropped."""
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
    """Out of range ratio, zero span cap and an unknown overflow mode each raise ValueError."""
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
        """A span exporter whose `export` always raises."""

        def export(self, spans: Any) -> Any:
            """Raise instead of exporting."""
            raise RuntimeError("network gone")

    processor = TailSamplingSpanProcessor(Exploding(), sample_ratio=1.0)
    provider = TracerProvider(sampler=ParentBased(root=ALWAYS_ON))
    provider.add_span_processor(cast("SpanProcessor", processor))

    with provider.get_tracer("test").start_as_current_span("healthy"):
        pass
    assert processor.force_flush() is True


def test_the_ratio_defaults_to_keeping_everything() -> None:
    """A service with nothing configured should not silently lose traces."""
    assert resolve_sample_ratio() == 1.0


def test_an_explicit_ratio_wins_over_the_environment(monkeypatch: MonkeyPatch) -> None:
    """An argument beats `SAMPLE_RATIO_ENV`."""
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
    """`traceidratio` without the parentbased prefix also supplies the ratio."""
    monkeypatch.setenv("OTEL_TRACES_SAMPLER", "traceidratio")
    monkeypatch.setenv("OTEL_TRACES_SAMPLER_ARG", "0.4")
    assert resolve_sample_ratio() == 0.4


def test_the_sampler_arg_is_ignored_under_a_non_ratio_sampler(monkeypatch: MonkeyPatch) -> None:
    """Under `always_on` the arg is meaningless, and reading it would invent a ratio."""
    monkeypatch.setenv("OTEL_TRACES_SAMPLER", "always_on")
    monkeypatch.setenv("OTEL_TRACES_SAMPLER_ARG", "0.01")
    assert resolve_sample_ratio() == 1.0


def test_the_package_env_var_beats_the_sampler_arg(monkeypatch: MonkeyPatch) -> None:
    """`SAMPLE_RATIO_ENV` takes precedence over `OTEL_TRACES_SAMPLER_ARG`."""
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
    """An unparseable package variable falls back to the sampler arg rather than to 1.0."""
    monkeypatch.setenv(SAMPLE_RATIO_ENV, "banana")
    monkeypatch.setenv("OTEL_TRACES_SAMPLER", "traceidratio")
    monkeypatch.setenv("OTEL_TRACES_SAMPLER_ARG", "0.3")
    assert resolve_sample_ratio() == 0.3


def test_configure_tracing_installs_an_always_on_sampler(monkeypatch: MonkeyPatch) -> None:
    """The head sampler must not pre-drop, or "errors are always sampled" is a lie."""
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

    assert otel._PROCESSOR is not None
    assert otel._PROCESSOR.sample_ratio == 0.0
    shutdown_tracing()


def test_configure_tracing_takes_the_ratio_as_a_keyword(monkeypatch: MonkeyPatch) -> None:
    """`sample_ratio` and `always_sample_errors` reach the installed processor."""
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
    assert flush_tracing() is False


def test_flush_tracing_drives_the_installed_processor(monkeypatch: MonkeyPatch) -> None:
    """With tracing configured, `flush_tracing` reports that it flushed."""
    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)
    configure_tracing("posts", sample_ratio=1.0)

    assert otel._PROCESSOR is not None
    assert flush_tracing() is True
    shutdown_tracing()


def test_a_record_only_span_is_still_tail_sampled() -> None:
    """A RECORD_ONLY span with the sampled flag clear is still kept when its trace errors."""
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
            """Wrap the root sampler whose DROP decisions are upgraded."""
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
            """Delegate to the root sampler, turning a DROP into RECORD_ONLY."""
            result = self._root.should_sample(
                parent_context, trace_id, name, kind, attributes, links, trace_state
            )
            if result.decision is Decision.DROP:
                return SamplingResult(Decision.RECORD_ONLY, attributes or {}, result.trace_state)
            return result

        def get_description(self) -> str:
            """Name this sampler for the SDK."""
            return "AlwaysRecord"

    exporter = InMemorySpanExporter()
    processor = TailSamplingSpanProcessor(exporter, sample_ratio=0.0)
    provider = TracerProvider(sampler=AlwaysRecord(TraceIdRatioBased(0.0)))
    provider.add_span_processor(cast("SpanProcessor", processor))

    with provider.get_tracer("test").start_as_current_span("failing") as span:
        assert span.get_span_context().trace_flags.sampled is False
        assert span.is_recording() is True
        span.set_status(Status(StatusCode.ERROR))
    processor.force_flush()

    assert [s.name for s in exporter.get_finished_spans()] == ["failing"]


def _recording_flush(calls: list[int]) -> Any:
    """A `flush_tracing` stand-in that records that it was called."""

    def fake_flush(timeout_millis: int = 30000) -> bool:
        """Record the timeout it was called with and report success."""
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
        """Return a trivial payload."""
        return {"ok": "yes"}

    instrument_fastapi(app, flush_per_request=flush_per_request)
    return app


def test_the_middleware_flushes_before_returning_the_response(monkeypatch: MonkeyPatch) -> None:
    """The flush runs while the request is still in flight, with the per-request timeout."""
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
    """Telemetry must never turn a healthy 200 into a 500."""
    from fastapi.testclient import TestClient

    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)

    def boom(timeout_millis: int = 30000) -> bool:
        """Raise instead of flushing."""
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
    """Under Lambda the middleware defaults on and flushes once per request."""
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
    """A real FastAPI app whose tail processor exports into memory, wired end to end."""
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
        """Return a trivial payload."""
        return {"ok": "yes"}

    @app.get("/boom")
    def boom() -> dict[str, str]:
        """Raise so the request produces an error trace."""
        raise RuntimeError("kaboom")

    instrument_fastapi(app, excluded_urls="", flush_per_request=True)
    return app, exporter


def test_the_request_own_server_span_is_exported_before_the_response_returns() -> None:
    """The flush must run outside the OTel middleware so the request's own span is exported."""
    from fastapi.testclient import TestClient

    app, exporter = _real_pipeline_app(1.0)
    with TestClient(app) as client:
        assert client.get("/thing").status_code == 200

    names = [s.name for s in exporter.get_finished_spans()]
    assert names, "the request's own trace was still buffered when the response returned"
    assert any("/thing" in name for name in names), names
    shutdown_tracing()


def test_an_error_trace_is_exported_at_ratio_zero_through_the_real_stack() -> None:
    """At ratio 0.0 a 500's trace is still exported through the real FastAPI stack."""
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
    """One request's flush must not judge another request's half-built trace."""
    from opentelemetry.trace import Status, StatusCode

    exporter, processor, tracer = _tail_harness(0.0)

    a_root = tracer.start_span("a-root")
    with trace_api.use_span(a_root, end_on_exit=False):
        child = tracer.start_span("a-child")
        child.end()

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
    """Shutdown judges an open trace on what it has rather than discarding it silently."""
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
    """`max_buffered_traces` bounds the number of buffered traces by resolving the oldest."""
    exporter, processor, tracer = _tail_harness(1.0, max_buffered_traces=2)

    for i in range(4):
        with tracer.start_as_current_span(f"root-{i}"):
            pass

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
    """A flush must leave an open trace's overflow drop decision standing for its later spans."""
    exporter, processor, tracer = _tail_harness(1.0, max_spans_per_trace=2, on_overflow="drop")

    root = tracer.start_span("over-root")
    with trace_api.use_span(root, end_on_exit=False):
        for i in range(3):
            child = tracer.start_span(f"over-child-{i}")
            child.end()
        assert processor.dropped_traces == 1

        processor.force_flush()

        late = tracer.start_span("over-child-late")
        late.end()
    root.end()
    processor.force_flush()

    assert exporter.get_finished_spans() == (), "a dropped trace leaked a fragment"


def test_an_export_does_not_hold_the_lock() -> None:
    """`export` is an HTTP round trip, so the processor lock must not be held across it."""
    from opentelemetry.sdk.trace import SpanProcessor, TracerProvider
    from opentelemetry.sdk.trace.export import SpanExportResult
    from opentelemetry.sdk.trace.sampling import ALWAYS_ON, ParentBased

    seen: list[int] = []

    class ReentrantExporter:
        """An exporter that reaches back for the processor lock while exporting."""

        def export(self, spans: Any) -> Any:
            """Assert the processor lock is free, then record the batch size."""
            acquired = processor._lock.acquire(timeout=2)
            assert acquired, "export ran while the processor lock was held"
            processor._lock.release()
            seen.extend(range(len(spans)))
            return SpanExportResult.SUCCESS

        def shutdown(self) -> None:
            """Do nothing."""

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
    """An X-Ray interface VPC endpoint is recognised and signed for the region in its host."""
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
    """Repeated overflow drops leave no overflow markers or open-span bookkeeping behind."""
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
    """Under `on_overflow="export"` the keep marker is cleared once the trace completes."""
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
    """The age bound reclaims buffers for traces whose spans never end."""
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
    """The flush timeout reaches the exporter's own timeout, with a one second floor."""
    exporter = otel._build_span_exporter("http://localhost:4318/v1/traces", 2000)
    assert exporter._timeout == 2  # type: ignore[attr-defined]

    signed = otel._build_span_exporter("https://xray.us-west-2.amazonaws.com/v1/traces", 3000)
    assert signed._timeout == 3  # type: ignore[attr-defined]

    floored = otel._build_span_exporter("http://localhost:4318/v1/traces", 100)
    assert floored._timeout == 1  # type: ignore[attr-defined]


async def _noop_asgi_app(scope: Any, receive: Any, send: Any) -> None:
    """A minimal downstream app, standing in for the instrumented stack."""
    return None


async def _noop_receive() -> dict[str, Any]:
    """Return a single empty HTTP request message."""
    return {"type": "http.request"}


async def _noop_send(message: dict[str, Any]) -> None:
    """Discard the outgoing ASGI message."""
    return None


def test_a_slow_export_does_not_stall_the_whole_event_loop() -> None:
    """The synchronous flush runs off the event loop, so other coroutines keep making progress."""
    import asyncio

    from opentelemetry.sdk.trace import SpanProcessor, TracerProvider
    from opentelemetry.sdk.trace.export import SpanExportResult
    from opentelemetry.sdk.trace.sampling import ALWAYS_ON, ParentBased

    release_export = threading.Event()

    class BlockingExporter:
        """An exporter that blocks in `export` until it is released."""

        def __init__(self) -> None:
            """Start with no recorded export calls."""
            self.calls = 0

        def export(self, spans: Any) -> Any:
            """Block until released, standing in for a slow endpoint."""
            self.calls += 1
            release_export.wait(timeout=5)
            return SpanExportResult.SUCCESS

        def shutdown(self) -> None:
            """Do nothing."""

    blocking = BlockingExporter()
    processor = TailSamplingSpanProcessor(cast("Any", blocking), sample_ratio=1.0)
    provider = TracerProvider(sampler=ParentBased(root=ALWAYS_ON))
    provider.add_span_processor(cast("SpanProcessor", processor))
    tracer = provider.get_tracer("test")
    otel._PROCESSOR = processor
    middleware = otel._FlushTracingASGIMiddleware(_noop_asgi_app, 1000)

    with tracer.start_as_current_span("request"):
        pass

    ticks = 0

    async def ticker() -> None:
        """Count loop iterations until the export is released."""
        nonlocal ticks
        while not release_export.is_set():
            await asyncio.sleep(0.01)
            ticks += 1

    async def drive() -> None:
        """Run the middleware against a blocking export and assert the loop kept ticking."""
        nonlocal ticks
        tick_task = asyncio.ensure_future(ticker())
        await asyncio.sleep(0.05)
        before = ticks

        def release_after_delay() -> None:
            """Release the export from outside the loop after a fixed delay."""
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
        """Return a trivial payload."""
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
    """An app whose middleware stack is already built warns that it cannot be instrumented."""
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
    """`xray-fips.<region>.amazonaws.com` is a real endpoint and needs signing like any other."""
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    endpoint = "https://xray-fips.us-gov-west-1.amazonaws.com/v1/traces"

    assert otel._is_xray_endpoint(endpoint) is True
    assert otel._region_for_endpoint(endpoint) == "us-gov-west-1"


def _lambda_style_env(monkeypatch: MonkeyPatch, access_key: str) -> None:
    """Set the three Lambda credential variables and clear anything that would bypass them."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", access_key)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", f"secret-for-{access_key}")
    monkeypatch.setenv("AWS_SESSION_TOKEN", f"token-for-{access_key}")
    for name in ("AWS_CREDENTIAL_EXPIRATION", "AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
        monkeypatch.delenv(name, raising=False)


def _signing_probe(monkeypatch: MonkeyPatch, exporter: Any) -> tuple[Any, list[str]]:
    """A callable that posts once through the exporter's signing session, and the keys it used."""
    import requests

    signed: list[str] = []
    auth_session = exporter._session._session

    def fake_request(
        self: Any, method: Any = None, url: Any = None, *args: Any, **kwargs: Any
    ) -> Any:
        """Record the access key id from the Authorization header and return a stub response."""
        header = dict(kwargs.get("headers") or {}).get("Authorization", "")
        signed.append(header.split("Credential=")[1].split("/")[0])

        class _Response:
            """A minimal successful HTTP response."""

            ok = True
            status_code = 200
            reason = "OK"

        return _Response()

    monkeypatch.setattr(requests.Session, "request", fake_request)

    def post_once() -> None:
        """Post one signed request through the exporter's session."""
        auth_session.request("POST", "https://xray.us-west-2.amazonaws.com/v1/traces", data=b"")

    return post_once, signed


def test_rotated_lambda_credentials_are_picked_up_by_the_next_export(
    monkeypatch: MonkeyPatch,
) -> None:
    """Rewriting the credential environment makes the next export sign with the new key."""
    _lambda_style_env(monkeypatch, "AKIAFIRSTKEY")

    exporter = otel._build_span_exporter("https://xray.us-west-2.amazonaws.com/v1/traces", 1000)
    post_once, signed = _signing_probe(monkeypatch, exporter)

    post_once()
    _lambda_style_env(monkeypatch, "AKIASECONDKEY")
    post_once()

    assert signed == ["AKIAFIRSTKEY", "AKIASECONDKEY"]


def test_unchanged_credentials_still_sign_consistently(monkeypatch: MonkeyPatch) -> None:
    """With nothing rotated, both exports sign with the same key."""
    _lambda_style_env(monkeypatch, "AKIASTABLEKEY")

    exporter = otel._build_span_exporter("https://xray.us-west-2.amazonaws.com/v1/traces", 1000)
    post_once, signed = _signing_probe(monkeypatch, exporter)

    post_once()
    post_once()

    assert signed == ["AKIASTABLEKEY", "AKIASTABLEKEY"]


def test_refreshable_credentials_are_left_to_refresh_themselves() -> None:
    """`RefreshableCredentials` are returned as they are, without re-running the resolver chain."""
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
        """A botocore session stand-in holding refreshable credentials."""

        _credentials = refreshable
        cleared = False

        def get_credentials(self) -> Any:
            """Return the refreshable credentials."""
            return refreshable

    session = _Session()
    credentials = otel._ReresolvingCredentials(session)

    assert credentials._current() is refreshable
    assert session._credentials is refreshable


def test_missing_credentials_raise_rather_than_sign_unsigned() -> None:
    """With no credentials resolvable, freezing them raises `NoCredentialsError`."""
    from botocore.exceptions import NoCredentialsError

    class _Session:
        """A botocore session stand-in that resolves no credentials."""

        _credentials = None

        def get_credentials(self) -> Any:
            """Return no credentials."""
            return None

    credentials = otel._ReresolvingCredentials(_Session())

    with pytest.raises(NoCredentialsError):
        credentials.get_frozen_credentials()


def _far_future() -> Any:
    """An expiry far enough out that `RefreshableCredentials` never tries to refresh."""
    import datetime

    return datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)


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
    """A clock jump past the exporter's deadline still yields a positive timeout and no raise."""
    import opentelemetry.exporter.otlp.proto.http.trace_exporter as upstream

    exporter = otel._build_span_exporter("http://localhost:4318/v1/traces", 1000)

    seen: list[Any] = []

    class _Transport:
        """A requests session stand-in that records the timeout it was given."""

        headers: ClassVar[dict[str, str]] = {}

        def post(self, *args: Any, timeout: Any = None, **kwargs: Any) -> Any:
            """Record the timeout and return a stub successful response."""
            seen.append(timeout)

            class _Response:
                """A minimal successful HTTP response."""

                ok = True
                status_code = 200
                reason = "OK"

            return _Response()

    guarded = cast("Any", exporter)._session
    assert isinstance(guarded, otel._PositiveTimeoutSession)
    guarded._session = _Transport()

    monkeypatch.setattr(upstream, "time", lambda: time.time() + 3600)

    exporter.export([])

    assert seen, "the exporter never reached the session"
    assert all(value > 0 for value in seen), seen


def test_a_thawed_sandbox_does_not_log_an_error(caplog: pytest.LogCaptureFixture) -> None:
    """A non-positive timeout ValueError is logged once at WARNING, never at ERROR."""

    class _RaisingExporter:
        """An exporter that raises the urllib3 non-positive timeout ValueError."""

        def export(self, spans: Any) -> None:
            """Raise the timeout ValueError a thawed sandbox produces."""
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
    """An unrelated ValueError from the exporter keeps its ERROR log."""

    class _RaisingExporter:
        """An exporter that raises an unrelated ValueError."""

        def export(self, spans: Any) -> None:
            """Raise a ValueError that is not the timeout one."""
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
        """An exporter that raises a RuntimeError."""

        def export(self, spans: Any) -> None:
            """Raise a non-ValueError exception."""
            raise RuntimeError("the endpoint went away")

    processor = TailSamplingSpanProcessor(cast("Any", _RaisingExporter()), sample_ratio=1.0)

    with caplog.at_level("WARNING", logger="webbpulse.otel"):
        processor._export([cast("Any", object())])

    assert [record for record in caplog.records if record.levelname == "ERROR"]


def test_the_timeout_guard_survives_an_upstream_rename(caplog: pytest.LogCaptureFixture) -> None:
    """`_session` is private to upstream, so losing it must degrade rather than crash."""

    class _NoSession:
        """An exporter stand-in with no `_session` attribute."""

    exporter = _NoSession()
    otel._guard_export_timeouts(exporter)

    assert not hasattr(exporter, "_session")


def test_the_shutdown_flush_timeout_defaults_to_the_lambda_grace_period() -> None:
    """300 ms, which fits inside the slice Lambda gives the runtime before SIGKILL."""
    assert resolve_shutdown_flush_timeout() == 300


def test_an_explicit_shutdown_flush_timeout_wins(monkeypatch: MonkeyPatch) -> None:
    """The argument beats the environment, matching `resolve_sample_ratio`."""
    monkeypatch.setenv(SHUTDOWN_FLUSH_TIMEOUT_ENV, "900")
    assert resolve_shutdown_flush_timeout(250) == 250


def test_the_env_var_sets_the_shutdown_flush_timeout(monkeypatch: MonkeyPatch) -> None:
    """Configuration comes through the environment, as everywhere else in this module."""
    monkeypatch.setenv(SHUTDOWN_FLUSH_TIMEOUT_ENV, "450")
    assert resolve_shutdown_flush_timeout() == 450


def test_the_shutdown_flush_timeout_is_clamped_to_the_shutdown_budget(
    monkeypatch: MonkeyPatch,
) -> None:
    """No configuration may push the flush past the whole 2000 ms shutdown phase."""
    monkeypatch.setenv(SHUTDOWN_FLUSH_TIMEOUT_ENV, "60000")
    assert resolve_shutdown_flush_timeout() == 1500
    assert resolve_shutdown_flush_timeout(60000) == 1500


@pytest.mark.parametrize("raw", ["nonsense", "0", "-5"])
def test_an_unusable_shutdown_flush_timeout_falls_back_to_the_default(
    monkeypatch: MonkeyPatch, caplog: pytest.LogCaptureFixture, raw: str
) -> None:
    """A bad value warns and degrades rather than raising on the shutdown path."""
    monkeypatch.setenv(SHUTDOWN_FLUSH_TIMEOUT_ENV, raw)

    with caplog.at_level("WARNING", logger="webbpulse.otel"):
        assert resolve_shutdown_flush_timeout() == 300

    assert [record for record in caplog.records if record.levelname == "WARNING"]


def test_an_explicit_non_positive_shutdown_timeout_is_a_programming_error() -> None:
    """An argument is the caller's own code, so it raises rather than degrading silently."""
    with pytest.raises(ValueError, match="at least 1"):
        resolve_shutdown_flush_timeout(0)


def _app_with_lifespan(
    ratio: float = 1.0, *, record_on_shutdown: list[str] | None = None
) -> tuple[Any, Any]:
    """A real app with an explicit lifespan, exporting into memory through the tail processor.

    The explicit `lifespan=` is the point: it is what every service in this estate passes, and
    it is what makes `router.on_shutdown` unusable as a hook.
    """
    from contextlib import asynccontextmanager

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

    @asynccontextmanager
    async def lifespan(_app: Any) -> Any:
        """Record a span on the way out, as a client being closed at shutdown would."""
        yield
        if record_on_shutdown is not None:
            record_on_shutdown.append("app-shutdown")
            tracer = trace.get_tracer("test")
            with tracer.start_as_current_span("closing-the-client"):
                pass

    app = FastAPI(lifespan=lifespan)

    @app.get("/thing")
    def thing() -> dict[str, str]:
        """Return a trivial payload."""
        return {"ok": "yes"}

    instrument_fastapi(app, excluded_urls="", flush_per_request=False)
    return app, exporter


def test_a_span_recorded_just_before_shutdown_is_exported() -> None:
    """The gap this closes: a trace still buffered when the container goes away.

    `flush_per_request=False` is what leaves the request's own trace buffered, which is the
    same state a trace with a still-open span is in when the response returns.
    """
    from fastapi.testclient import TestClient

    app, exporter = _app_with_lifespan()

    with TestClient(app) as client:
        assert client.get("/thing").status_code == 200
        assert exporter.get_finished_spans() == (), "nothing should be exported before shutdown"

    names = [span.name for span in exporter.get_finished_spans()]
    assert names, "the buffered trace was lost when the lifespan shut down"
    assert any("/thing" in name for name in names), names


def test_the_shutdown_flush_runs_after_the_apps_own_lifespan_shutdown() -> None:
    """A span recorded while the app closes its own resources still gets exported."""
    from fastapi.testclient import TestClient

    order: list[str] = []
    app, exporter = _app_with_lifespan(record_on_shutdown=order)

    with TestClient(app) as client:
        assert client.get("/thing").status_code == 200

    assert order == ["app-shutdown"]
    names = [span.name for span in exporter.get_finished_spans()]
    assert "closing-the-client" in names, names


def test_the_lifespan_wrapper_is_installed_only_once() -> None:
    """Wrapping twice would flush twice, and the second flush has nothing left to export."""
    from fastapi import FastAPI

    from webbpulse.otel import instrument_fastapi

    configure_tracing("posts", endpoint="http://localhost:4318/v1/traces")
    app = FastAPI()
    first = app.router.lifespan_context

    instrument_fastapi(app, flush_per_request=False)
    wrapped = app.router.lifespan_context
    assert wrapped is not first

    instrument_fastapi(app, flush_per_request=False)
    assert app.router.lifespan_context is wrapped
    shutdown_tracing()


def test_the_lifespan_wrapper_can_be_turned_off() -> None:
    """A consumer owning its own shutdown path must be able to opt out."""
    from fastapi import FastAPI

    from webbpulse.otel import instrument_fastapi

    configure_tracing("posts", endpoint="http://localhost:4318/v1/traces")
    app = FastAPI()
    first = app.router.lifespan_context

    instrument_fastapi(app, flush_per_request=False, flush_on_shutdown=False)

    assert app.router.lifespan_context is first
    shutdown_tracing()


def test_a_shutdown_flush_failure_does_not_break_the_shutdown(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An export that fails on the way out must not turn into a failed container shutdown."""
    from fastapi.testclient import TestClient

    app, _ = _app_with_lifespan()

    def boom(spans: Any) -> None:
        """Raise instead of exporting."""
        raise RuntimeError("the endpoint went away")

    assert otel._PROCESSOR is not None
    monkeypatched = otel._PROCESSOR
    cast("Any", monkeypatched)._exporter.export = boom

    with caplog.at_level("WARNING", logger="webbpulse.otel"), TestClient(app) as client:
        assert client.get("/thing").status_code == 200

    assert not [record for record in caplog.records if record.levelname == "ERROR"]
    assert [record for record in caplog.records if record.levelname == "WARNING"]


def test_a_teardown_export_failure_is_a_single_warning_without_a_traceback(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The flush-on-exit path must not page anyone with an ERROR and a stack trace."""

    class _RaisingExporter:
        """An exporter that fails the way a torn-down sandbox does."""

        def export(self, spans: Any) -> None:
            """Raise as a connection against a dying sandbox would."""
            raise OSError("connection reset by peer")

        def shutdown(self) -> None:
            """Shut down without complaint."""

    processor = TailSamplingSpanProcessor(cast("Any", _RaisingExporter()), sample_ratio=1.0)

    with caplog.at_level("WARNING", logger="webbpulse.otel"):
        processor._tearing_down = True
        processor._export([cast("Any", object())])

    assert not [record for record in caplog.records if record.levelname == "ERROR"]
    warnings = [record for record in caplog.records if record.levelname == "WARNING"]
    assert len(warnings) == 1
    assert warnings[0].exc_info is None
    assert "shutting down" in warnings[0].message


def test_an_export_failure_outside_teardown_keeps_its_error_and_traceback(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Quieting the teardown path must not quiet a real in-request export failure."""

    class _RaisingExporter:
        """An exporter that raises mid-request."""

        def export(self, spans: Any) -> None:
            """Raise a genuine failure."""
            raise OSError("connection reset by peer")

    processor = TailSamplingSpanProcessor(cast("Any", _RaisingExporter()), sample_ratio=1.0)

    with caplog.at_level("WARNING", logger="webbpulse.otel"):
        processor._export([cast("Any", object())])

    errors = [record for record in caplog.records if record.levelname == "ERROR"]
    assert len(errors) == 1
    assert errors[0].exc_info is not None


def test_processor_shutdown_never_raises() -> None:
    """Shutdown runs on the way out, where a raise can only make things worse."""

    class _HostileExporter:
        """An exporter that fails at both export and shutdown."""

        def export(self, spans: Any) -> None:
            """Raise on export."""
            raise RuntimeError("export is down")

        def force_flush(self, timeout_millis: int = 30000) -> bool:
            """Raise on flush."""
            raise RuntimeError("flush is down")

        def shutdown(self) -> None:
            """Raise on shutdown."""
            raise RuntimeError("shutdown is down")

    processor = TailSamplingSpanProcessor(cast("Any", _HostileExporter()), sample_ratio=1.0)

    processor.shutdown(250)

    assert processor._shutdown is True


def test_the_shutdown_flush_is_bounded_by_the_timeout() -> None:
    """The bound is what keeps the flush inside Lambda's grace period."""
    seen: list[int] = []

    class _RecordingExporter:
        """An exporter that records the flush deadline it was given."""

        def export(self, spans: Any) -> None:
            """Accept the batch."""

        def force_flush(self, timeout_millis: int = 30000) -> bool:
            """Record the deadline and report success."""
            seen.append(timeout_millis)
            return True

        def shutdown(self) -> None:
            """Shut down without complaint."""

    processor = TailSamplingSpanProcessor(cast("Any", _RecordingExporter()), sample_ratio=1.0)
    processor.shutdown(275)

    assert seen == [275]


def test_shutdown_tracing_passes_the_timeout_through_to_the_processor() -> None:
    """`shutdown_tracing` is the public door onto the bounded processor shutdown."""
    seen: list[int] = []

    class _RecordingExporter:
        """An exporter that records the flush deadline it was given."""

        def export(self, spans: Any) -> None:
            """Accept the batch."""

        def force_flush(self, timeout_millis: int = 30000) -> bool:
            """Record the deadline and report success."""
            seen.append(timeout_millis)
            return True

        def shutdown(self) -> None:
            """Shut down without complaint."""

    otel._PROCESSOR = TailSamplingSpanProcessor(cast("Any", _RecordingExporter()), sample_ratio=1.0)

    shutdown_tracing(300)

    assert seen == [300]
    assert otel._PROCESSOR is None


def test_shutdown_tracing_without_a_timeout_is_still_backward_compatible() -> None:
    """The old no-argument call must keep working for any consumer already making it."""
    configure_tracing("posts", endpoint="http://localhost:4318/v1/traces")

    shutdown_tracing()

    assert otel._PROCESSOR is None
    assert otel._CONFIGURED is False
