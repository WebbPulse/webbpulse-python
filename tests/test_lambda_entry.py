"""Tests for `webbpulse.lambda_entry`.

Port resolution is covered closely: binding a port the Web Adapter is not polling
presents as a readiness check that never passes, with no application logs at all.
"""

from __future__ import annotations

from typing import Any

import pytest
from pytest import LogCaptureFixture, MonkeyPatch

from webbpulse import lambda_entry
from webbpulse.lambda_entry import (
    ADAPTER_IMAGE,
    AWS_LWA_PORT_ENV,
    DEFAULT_PORT,
    is_lambda,
    resolve_port,
    run_uvicorn,
)


@pytest.fixture(autouse=True)
def _clear_port_environment(monkeypatch: MonkeyPatch) -> None:
    """Neither variable may leak in from the surrounding shell."""
    monkeypatch.delenv(AWS_LWA_PORT_ENV, raising=False)
    monkeypatch.delenv("PORT", raising=False)
    monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME", raising=False)


def test_the_default_port_is_the_adapters_default() -> None:
    """The adapter's documented default for AWS_LWA_PORT is 8080."""
    assert DEFAULT_PORT == 8080
    assert resolve_port() == 8080


def test_aws_lwa_port_wins(monkeypatch: MonkeyPatch) -> None:
    """AWS_LWA_PORT sets the resolved port."""
    monkeypatch.setenv(AWS_LWA_PORT_ENV, "9000")
    assert resolve_port() == 9000


def test_port_is_the_documented_fallback(monkeypatch: MonkeyPatch) -> None:
    """The adapter reads AWS_LWA_PORT and falls back to PORT, which is not deprecated."""
    monkeypatch.setenv("PORT", "7000")
    assert resolve_port() == 7000


def test_aws_lwa_port_takes_precedence_over_port(monkeypatch: MonkeyPatch) -> None:
    """With both set, AWS_LWA_PORT wins over PORT."""
    monkeypatch.setenv(AWS_LWA_PORT_ENV, "9000")
    monkeypatch.setenv("PORT", "7000")
    assert resolve_port() == 9000, "AWS_LWA_PORT is the adapter's own variable and wins"


def test_a_non_numeric_port_is_ignored_and_warned(
    monkeypatch: MonkeyPatch, caplog: LogCaptureFixture
) -> None:
    """A non-numeric port falls back to the default and logs a warning instead of crashing."""
    monkeypatch.setenv(AWS_LWA_PORT_ENV, "not-a-port")
    with caplog.at_level("WARNING"):
        assert resolve_port() == DEFAULT_PORT
    assert "not an integer" in caplog.text


def test_an_empty_port_falls_through(monkeypatch: MonkeyPatch) -> None:
    """A blank AWS_LWA_PORT falls through to PORT."""
    monkeypatch.setenv(AWS_LWA_PORT_ENV, "   ")
    monkeypatch.setenv("PORT", "7001")
    assert resolve_port() == 7001


def test_an_explicit_default_is_honoured() -> None:
    """With no environment set, `resolve_port` returns the caller's default."""
    assert resolve_port(default=1234) == 1234


def test_is_lambda_reads_the_function_name(monkeypatch: MonkeyPatch) -> None:
    """`is_lambda` is true only when AWS_LAMBDA_FUNCTION_NAME is set."""
    assert is_lambda() is False
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "webbpulse-staging-posts")
    assert is_lambda() is True


def test_the_adapter_image_is_pinned_to_an_exact_version() -> None:
    """An unpinned or `latest` adapter would change under the service without a deploy."""
    assert ADAPTER_IMAGE == "public.ecr.aws/awsguru/aws-lambda-adapter:1.0.1"
    tag = ADAPTER_IMAGE.rsplit(":", 1)[1]
    assert tag != "latest"
    assert all(part.isdigit() for part in tag.split(".")), "the tag must be a version"


def test_run_uvicorn_binds_the_resolved_port(monkeypatch: MonkeyPatch) -> None:
    """The port uvicorn binds must be the one the adapter polls, or nothing ever starts."""
    captured: dict[str, Any] = {}

    def fake_run(app: Any, **kwargs: Any) -> None:
        """Record the arguments `run_uvicorn` passes to uvicorn."""
        captured["app"] = app
        captured.update(kwargs)

    import uvicorn

    monkeypatch.setattr(uvicorn, "run", fake_run)
    monkeypatch.setenv(AWS_LWA_PORT_ENV, "9100")

    run_uvicorn("myapp:app")

    assert captured["app"] == "myapp:app"
    assert captured["port"] == 9100
    assert captured["host"] == "0.0.0.0"
    assert captured["log_config"] is None
    assert captured["access_log"] is False


def test_run_uvicorn_accepts_an_explicit_port_and_extra_kwargs(monkeypatch: MonkeyPatch) -> None:
    """An explicit port and extra kwargs are passed through to uvicorn."""
    captured: dict[str, Any] = {}

    def fake_run(app: Any, **kwargs: Any) -> None:
        """Record the keyword arguments `run_uvicorn` passes to uvicorn."""
        captured.update(kwargs)

    import uvicorn

    monkeypatch.setattr(uvicorn, "run", fake_run)
    monkeypatch.setenv(AWS_LWA_PORT_ENV, "9100")

    run_uvicorn("myapp:app", port=5555, access_log=True, timeout_keep_alive=65)

    assert captured["port"] == 5555, "an explicit port overrides the environment"
    assert captured["access_log"] is True, "a caller may opt the access log back in"
    assert captured["timeout_keep_alive"] == 65


def test_the_module_docstring_documents_the_pinned_adapter_image() -> None:
    """The README and the Dockerfile snippet must not drift from ADAPTER_IMAGE."""
    docstring = lambda_entry.__doc__ or ""
    assert ADAPTER_IMAGE in docstring
    assert "/opt/extensions/lambda-adapter" in docstring
