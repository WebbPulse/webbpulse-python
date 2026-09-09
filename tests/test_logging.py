"""Tests for `webbpulse.logging`.

The assertions here are mostly about the exact key names, because those are what CloudWatch
and the `api-alarms` metric filter select on. A rename that looks harmless breaks alarming
silently, so the names are pinned by test.
"""

from __future__ import annotations

import io
import json
import logging
import re
import sys
from datetime import datetime
from typing import Any
from unittest import mock

import pytest

from webbpulse.logging import (
    JsonFormatter,
    TextFormatter,
    configure_logging,
    get_logger,
)

# RFC 3339 with milliseconds and a Z suffix. Lambda requires this exact shape to parse the
# timestamp; anything else makes it stamp its own time and force the level to INFO.
_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


def _record(**kwargs: Any) -> logging.LogRecord:
    defaults: dict[str, Any] = {
        "name": "app.api",
        "level": logging.INFO,
        "pathname": "/app/api.py",
        "lineno": 10,
        "msg": "hello",
        "args": (),
        "exc_info": None,
    }
    defaults.update(kwargs)
    return logging.LogRecord(**defaults)


def _format(record: logging.LogRecord, **formatter_kwargs: Any) -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads(JsonFormatter(**formatter_kwargs).format(record))
    return parsed


def test_the_output_is_one_json_object_per_line() -> None:
    line = JsonFormatter().format(_record())
    assert "\n" not in line, "a multi-line log record becomes several CloudWatch events"
    assert json.loads(line)["message"] == "hello"


def test_level_is_a_top_level_key() -> None:
    """`{ $.level = "ERROR" }` is the metric filter in the api-alarms module."""
    assert _format(_record(level=logging.ERROR))["level"] == "ERROR"


def test_timestamp_is_rfc3339_with_a_z_suffix() -> None:
    payload = _format(_record())
    assert _RFC3339.match(payload["timestamp"]), payload["timestamp"]
    # Also assert it actually parses, so the regex cannot pass on a nonsense date.
    datetime.fromisoformat(payload["timestamp"].replace("Z", "+00:00"))


def test_the_logger_name_is_carried() -> None:
    assert _format(_record(name="app.posts"))["logger"] == "app.posts"


def test_service_and_environment_are_added_when_given() -> None:
    payload = _format(_record(), service="posts", environment="staging")
    assert payload["service"] == "posts"
    assert payload["environment"] == "staging"


def test_extra_fields_become_top_level_keys() -> None:
    """This is what makes an Insights query able to select on an application field."""
    record = _record()
    record.user_id = "u-1"
    record.duration_ms = 12.5
    payload = _format(record)
    assert payload["user_id"] == "u-1"
    assert payload["duration_ms"] == 12.5


def test_reserved_logrecord_attributes_are_not_emitted() -> None:
    """Emitting every LogRecord attribute would double the size of every log line."""
    payload = _format(_record())
    for noisy in ("args", "msg", "levelno", "pathname", "relativeCreated", "thread"):
        assert noisy not in payload


def test_exceptions_use_lambdas_own_key_names() -> None:
    try:
        raise ValueError("boom")
    except ValueError:
        import sys

        payload = _format(_record(level=logging.ERROR, exc_info=sys.exc_info()))

    assert payload["errorType"] == "ValueError"
    assert payload["errorMessage"] == "boom"
    assert isinstance(payload["stackTrace"], list), "a list matches Lambda's own JSON format"
    assert any("ValueError" in line for line in payload["stackTrace"])


def test_an_unserialisable_value_does_not_lose_the_line() -> None:
    """Losing a log line to a TypeError is always worse than losing exact typing in it."""

    class Opaque:
        def __str__(self) -> str:
            return "opaque-value"

    record = _record()
    record.thing = Opaque()
    assert _format(record)["thing"] == "opaque-value"


def test_message_formatting_arguments_are_applied() -> None:
    assert _format(_record(msg="hello %s", args=("world",)))["message"] == "hello world"


def test_configure_logging_is_idempotent() -> None:
    """A warm Lambda re-import must not stack handlers and emit every line twice."""
    configure_logging(level="INFO", force=True)
    first = len(logging.getLogger().handlers)
    configure_logging(level="INFO")
    configure_logging(level="INFO")
    assert len(logging.getLogger().handlers) == first == 1


def test_configure_logging_replaces_lambdas_handler() -> None:
    """Leaving Lambda's own handler attached emits every record twice, in two formats."""
    root = logging.getLogger()
    root.addHandler(logging.StreamHandler())
    configure_logging(level="DEBUG", force=True)
    assert len(root.handlers) == 1
    assert isinstance(root.handlers[0].formatter, JsonFormatter)
    assert root.level == logging.DEBUG


def test_uvicorn_loggers_are_reattached_to_the_root() -> None:
    """Uvicorn sets propagate=False, which would bypass the JSON formatter entirely."""
    uvicorn_logger = logging.getLogger("uvicorn.access")
    uvicorn_logger.propagate = False
    uvicorn_logger.addHandler(logging.StreamHandler())

    configure_logging(force=True)

    assert uvicorn_logger.propagate is True
    assert uvicorn_logger.handlers == []


def test_botocore_is_held_at_warning() -> None:
    """botocore at DEBUG logs every request and response, including credentials."""
    configure_logging(level="DEBUG", force=True)
    assert logging.getLogger("botocore").level == logging.WARNING


def test_configured_logging_emits_parseable_json(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(level="INFO", service="posts", environment="staging", force=True)
    get_logger("app.posts").info("served", extra={"path": "/api/v1/posts"})

    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["level"] == "INFO"
    assert payload["message"] == "served"
    assert payload["path"] == "/api/v1/posts"
    assert payload["service"] == "posts"


def test_trace_ids_are_merged_when_a_span_is_recording() -> None:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider

    provider = TracerProvider()
    tracer = provider.get_tracer(__name__)

    with tracer.start_as_current_span("unit"):
        span_context = trace.get_current_span().get_span_context()
        payload = _format(_record())

    assert payload["trace_id"] == format(span_context.trace_id, "032x")
    assert payload["span_id"] == format(span_context.span_id, "016x")
    assert len(payload["trace_id"]) == 32, "OTLP expects a 32 character hex trace id"
    assert len(payload["span_id"]) == 16


def test_trace_ids_are_absent_outside_a_span() -> None:
    """A service with no tracing configured must still log cleanly."""
    payload = _format(_record())
    assert "trace_id" not in payload
    assert "span_id" not in payload


# --------------------------------------------------------------------------------------
# The 0.8.0 escape hatches. CarModPicker kept a local wrapper module because neither of
# these existed. The first assertion in each pair is that the default did not move.
# --------------------------------------------------------------------------------------


def test_the_default_stream_is_still_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(level="INFO", force=True)
    get_logger("app.api").info("served")

    captured = capsys.readouterr()
    assert json.loads(captured.out.strip())["message"] == "served"
    assert captured.err == "", "the default must not have moved to stderr"


def test_stream_routes_every_handler_the_function_installs(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Two CMP commands write data on stdout and are diffed byte for byte.

    A single log line leaking onto stdout breaks that comparison, so the assertion is that
    stdout is *empty*, not merely that stderr has the line.
    """
    configure_logging(level="INFO", force=True, stream=sys.stderr)
    get_logger("app.api").info("served")
    get_logger("uvicorn.access").warning("slow")

    captured = capsys.readouterr()
    assert captured.out == "", "stdout must stay clean for the command's own output"
    messages = [json.loads(line)["message"] for line in captured.err.splitlines() if line.strip()]
    assert messages == ["served", "slow"]


def test_the_root_still_carries_exactly_one_handler_with_a_custom_stream() -> None:
    """A second handler left on the root is the shape that would defeat `stream=`."""
    configure_logging(force=True, stream=io.StringIO())
    assert len(logging.getLogger().handlers) == 1


def test_stream_is_read_at_call_time_not_at_import() -> None:
    """A runtime that replaced `sys.stdout` after import must still be honoured."""
    replacement = io.StringIO()
    with mock.patch.object(sys, "stdout", replacement):
        configure_logging(level="INFO", force=True)
        get_logger("app.api").info("served")
    assert json.loads(replacement.getvalue().strip())["message"] == "served"


def test_the_default_formatter_is_json_and_unchanged(
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging(level="INFO", service="posts", environment="staging", force=True)
    handler = logging.getLogger().handlers[0]
    assert isinstance(handler.formatter, JsonFormatter)

    get_logger("app.api").info("served")
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["service"] == "posts"
    assert payload["environment"] == "staging"


def test_the_text_formatter_is_one_readable_line(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(level="INFO", formatter="text", force=True)
    get_logger("app.api").warning("served")

    line = capsys.readouterr().out.strip()
    assert "\n" not in line
    with pytest.raises(json.JSONDecodeError):
        json.loads(line)
    assert line.endswith("WARNING  app.api served")


def test_the_text_formatter_still_renders_a_traceback(
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging(level="INFO", formatter="text", force=True)
    try:
        raise RuntimeError("boom")
    except RuntimeError:
        get_logger("app.api").exception("failed")

    out = capsys.readouterr().out
    assert "RuntimeError: boom" in out
    assert "Traceback (most recent call last)" in out


def test_text_ignores_service_and_environment_rather_than_rendering_them(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Locally there is one service and one environment, so repeating them is noise."""
    configure_logging(formatter="text", service="posts", environment="dev", force=True)
    get_logger("app.api").info("served")

    line = capsys.readouterr().out.strip()
    assert "posts" not in line
    assert "dev" not in line


def test_a_formatter_instance_is_installed_as_given(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The escape hatch for a service whose format is neither of the two selectors."""
    supplied = logging.Formatter("custom|%(levelname)s|%(message)s")
    configure_logging(formatter=supplied, service="posts", force=True)

    assert logging.getLogger().handlers[0].formatter is supplied
    get_logger("app.api").info("served")
    assert capsys.readouterr().out.strip() == "custom|INFO|served"


def test_an_unknown_formatter_selector_is_rejected() -> None:
    with pytest.raises(ValueError, match=re.escape("'json', 'text' or a logging.Formatter")):
        configure_logging(formatter="logfmt", force=True)  # type: ignore[arg-type]


def test_a_bad_formatter_leaves_the_previous_configuration_in_place(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Resolving before teardown is what keeps the root logger from ending up handlerless."""
    configure_logging(level="INFO", force=True)
    with pytest.raises(ValueError):
        configure_logging(formatter="logfmt", force=True)  # type: ignore[arg-type]

    assert len(logging.getLogger().handlers) == 1
    get_logger("app.api").info("still here")
    assert json.loads(capsys.readouterr().out.strip())["message"] == "still here"


def test_the_text_formatter_accepts_a_format_string() -> None:
    assert TextFormatter().format(_record()).endswith("INFO     app.api hello")
    assert TextFormatter("%(message)s").format(_record()) == "hello"
