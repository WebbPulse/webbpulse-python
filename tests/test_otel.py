"""Tests for `webbpulse.otel`."""

from __future__ import annotations

from typing import Any

import pytest
from pytest import MonkeyPatch

from webbpulse import otel
from webbpulse.otel import (
    OTEL_DISABLED_ENV,
    configure_tracing,
    is_tracing_enabled,
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
    _clear_global_tracer_provider()
    yield
    otel._CONFIGURED = False
    _clear_global_tracer_provider()


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


def test_an_unsigned_xray_export_warns(
    monkeypatch: MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Without SigV4 the endpoint returns 403 and the exporter retries silently.

    That failure is indistinguishable from having no traffic, so the warning is the only
    signal a software engineer gets that the ADOT distro is missing.
    """
    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)
    monkeypatch.setattr(otel, "_has_adot_distro", lambda: False)

    with caplog.at_level("WARNING", logger="webbpulse.otel"):
        configure_tracing("posts", endpoint="https://xray.us-west-2.amazonaws.com/v1/traces")

    assert any("SigV4" in record.message for record in caplog.records)
    shutdown_tracing()


def test_no_warning_when_the_distro_is_present(
    monkeypatch: MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)
    monkeypatch.setattr(otel, "_has_adot_distro", lambda: True)

    with caplog.at_level("WARNING", logger="webbpulse.otel"):
        configure_tracing("posts", endpoint="https://xray.us-west-2.amazonaws.com/v1/traces")

    assert not [r for r in caplog.records if "SigV4" in r.message]
    shutdown_tracing()


def test_no_signing_warning_for_a_non_aws_endpoint(
    monkeypatch: MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A local collector needs no SigV4, so the warning must not fire for it."""
    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)
    monkeypatch.setattr(otel, "_has_adot_distro", lambda: False)

    with caplog.at_level("WARNING", logger="webbpulse.otel"):
        configure_tracing("posts", endpoint="http://localhost:4318/v1/traces")

    assert not [r for r in caplog.records if "SigV4" in r.message]
    shutdown_tracing()


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
