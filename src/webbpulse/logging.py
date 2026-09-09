"""JSON logging that CloudWatch and Lambda both read correctly.

One formatter, one setup function. The formatter emits a single JSON object per line with
a top-level `level` key and an RFC 3339 `timestamp`, and merges the active OpenTelemetry
trace and span ids when a span is recording.

**Why those two keys specifically.** With a function's log format set to JSON, Lambda
filters log events by an application-supplied `level` key and requires a valid RFC 3339
`timestamp` alongside it. The AWS documentation is explicit that when it cannot parse the
timestamp it assigns the event level INFO and stamps its own time, which silently defeats
`application_log_level` filtering. Emitting both is what makes CloudWatch level filtering
and the `{ $.level = "ERROR" }` metric filter in the `api-alarms` Terraform module work.

**Why this does not fight Lambda's own JSON format.** Lambda does not re-encode output that
is already JSON: "AWS Lambda doesn't double-encode any logs that are already JSON encoded."
So a service can set `log_format = "JSON"` on the function and use this formatter at the
same time, and the log event in CloudWatch is the object below rather than that object
nested inside Lambda's. The one thing to avoid is `print()`, which Lambda captures as plain
text regardless of the format setting.

**The two escape hatches, and why they exist.** The defaults above are the deployed shape
and nothing about them changed in 0.8.0. What was missing was a way out of them, which cost
CarModPicker a local wrapper module it could not delete:

* `stream=` moves every handler this function installs. A CLI whose commands write data on
  stdout and are compared byte for byte cannot also have log lines land there, so it passes
  `stream=sys.stderr` and gets its stdout back. Note "every handler": routing only some of
  them would leave the interleaving that the argument exists to remove.
* `formatter=` chooses the rendering. `"json"` is the default and is byte identical to
  0.7.0; `"text"` is a human readable line for a TTY, and a `logging.Formatter` instance is
  accepted for a service that wants its own. A one-line JSON object is the right thing in
  CloudWatch and the wrong thing in a terminal, and reading it in a terminal was previously
  the thing a local wrapper was written to fix.

Neither hatch is reached by the deployed path. A service that passes neither argument gets
the 0.7.0 handler, on the 0.7.0 stream, with the 0.7.0 formatter.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any, Final, Literal, TextIO

__all__ = [
    "TEXT_LOG_FORMAT",
    "FormatterSpec",
    "JsonFormatter",
    "TextFormatter",
    "configure_logging",
    "get_logger",
]

# Attributes `logging.LogRecord` sets itself. Anything outside this set arrived through
# `extra={...}` and belongs in the emitted object.
_RESERVED: Final[frozenset[str]] = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)

# Set once by `configure_logging` so repeated calls (a warm Lambda re-import, a test that
# builds several apps) do not stack duplicate handlers on the root logger.
_CONFIGURED = False


def _trace_context() -> dict[str, str]:
    """Return the current trace and span ids, or `{}` when there is no recording span.

    Imported lazily and guarded, because `webbpulse.logging` is in the base install and
    OpenTelemetry is behind the `otel` extra. A service that has not installed it logs
    perfectly well without trace ids rather than failing to import.

    The ids are formatted as lower-case hex of the OpenTelemetry width, 32 characters for a
    trace id and 16 for a span id, which is what the OTLP wire format and the CloudWatch
    console both expect. Note this is *not* the X-Ray `1-<8 hex>-<24 hex>` form; correlating
    a log line to a trace in the console works from the raw hex id.
    """
    try:
        from opentelemetry import trace
    except ImportError:
        return {}

    span = trace.get_current_span()
    context = span.get_span_context()
    # An invalid context is the no-op span returned when tracing is off or outside a span.
    if not context.is_valid:
        return {}
    return {
        "trace_id": format(context.trace_id, "032x"),
        "span_id": format(context.span_id, "016x"),
    }


def _request_context() -> dict[str, str]:
    """Return the bound request and user ids, or `{}` when nothing is bound.

    `webbpulse.log_context` is in the base install like this module, so unlike
    `_trace_context` there is nothing optional to guard: the import cannot fail. Merging it
    here rather than making every service attach a `logging.Filter` is what makes the two
    keys appear on a log line for free once `configure_logging` has run.

    Merged after the `extra={...}` loop below and only into keys that are still absent, so
    `logger.info(..., extra={"request_id": explicit})` at a call site wins over the ambient
    value rather than being overwritten by it.
    """
    from webbpulse.log_context import current_context

    return current_context()


class JsonFormatter(logging.Formatter):
    """Render a `LogRecord` as one line of JSON.

    The shape matches the keys Lambda uses for its own JSON format, so a log group holding
    both this output and anything Lambda emits itself stays queryable with one set of
    CloudWatch Logs Insights expressions::

        {"timestamp": "...", "level": "INFO", "message": "...", "logger": "app.api",
         "trace_id": "...", "span_id": "...", ...extra}

    Exceptions add `errorType`, `errorMessage` and `stackTrace`, again matching Lambda's
    names rather than inventing new ones.
    """

    def __init__(self, *, service: str | None = None, environment: str | None = None) -> None:
        super().__init__()
        self._static: dict[str, str] = {}
        if service:
            self._static["service"] = service
        if environment:
            self._static["environment"] = environment

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            # RFC 3339 with milliseconds and a Z suffix. Lambda parses this; a bare
            # `asctime` with a comma before the milliseconds does not qualify.
            "timestamp": datetime.fromtimestamp(record.created, UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
        }
        payload.update(self._static)
        payload.update(_trace_context())

        if record.exc_info:
            exc_type, exc_value, _ = record.exc_info
            if exc_type is not None:
                payload["errorType"] = exc_type.__name__
            if exc_value is not None:
                payload["errorMessage"] = str(exc_value)
            payload["stackTrace"] = self.formatException(record.exc_info).splitlines()
        if record.stack_info:
            payload["stackInfo"] = self.formatStack(record.stack_info).splitlines()

        # Anything passed as `extra={...}` becomes a top-level key, which is what makes a
        # CloudWatch metric filter or an Insights query able to select on it.
        for key, value in record.__dict__.items():
            if key not in _RESERVED and key not in payload and not key.startswith("_"):
                payload[key] = value

        # The ambient request context is merged last and only fills gaps, so an explicit
        # `extra={"request_id": ...}` at the call site beats the bound value rather than
        # being silently overwritten by it.
        for key, value in _request_context().items():
            payload.setdefault(key, value)

        # `default=str` keeps a stray UUID, Decimal or datetime from turning a log call into
        # a TypeError. Losing exact typing in a log line is always better than losing the line.
        return json.dumps(payload, default=str, separators=(",", ":"))


#: The format string `formatter="text"` renders. Deliberately not the stdlib default, which
#: is the bare message: a line with no time, level or logger name is unreadable the moment
#: two components log at once, which is the normal state of a service running locally.
TEXT_LOG_FORMAT: Final = "%(asctime)s %(levelname)-8s %(name)s %(message)s"


class TextFormatter(logging.Formatter):
    """One human readable line per record, for a TTY.

    The `service` and `environment` a `JsonFormatter` writes as keys are dropped rather
    than rendered: locally there is one service and one environment, so repeating both on
    every line is noise. The bound request context is not appended either, for the same
    reason plus one more, that `LogContextFilter` already exists for a service that wants
    `%(request_id)s` in its own format string and stacking a second mechanism on top of it
    would give two ways to get the same field.

    This is a thin subclass rather than a bare `logging.Formatter` so a caller can name the
    class in an `isinstance` check, and so the format string lives with the class that uses
    it rather than at whichever call site constructed it.
    """

    def __init__(self, fmt: str | None = None, datefmt: str | None = None) -> None:
        super().__init__(fmt or TEXT_LOG_FORMAT, datefmt)


#: What `configure_logging(formatter=...)` accepts. The two string selectors cover the two
#: cases that exist, and the instance escape hatch means a service with a third does not
#: have to wait for this package to grow a selector for it.
FormatterSpec = Literal["json", "text"] | logging.Formatter


def _resolve_formatter(
    spec: FormatterSpec,
    *,
    service: str | None,
    environment: str | None,
) -> logging.Formatter:
    """Turn a `formatter=` argument into the formatter instance to install.

    A `logging.Formatter` instance is returned as given. `service` and `environment` are not
    pushed into it: the caller built it and owns what it renders, and silently mutating a
    caller's formatter is worse than ignoring two arguments it did not ask for.
    """
    if isinstance(spec, logging.Formatter):
        return spec
    if spec == "json":
        return JsonFormatter(service=service, environment=environment)
    if spec == "text":
        return TextFormatter()
    raise ValueError(f"formatter must be 'json', 'text' or a logging.Formatter, got {spec!r}")


def configure_logging(
    *,
    level: str = "INFO",
    service: str | None = None,
    environment: str | None = None,
    force: bool = False,
    stream: TextIO | None = None,
    formatter: FormatterSpec = "json",
) -> None:
    """Install a formatter on the root logger, writing to stdout by default.

    Idempotent: calling it twice does not double every log line. Pass `force=True` to
    reconfigure anyway, which tests need.

    Handlers are replaced rather than added. Lambda installs its own handler on the root
    logger, and leaving it in place means every record is emitted twice, once as this JSON
    and once in Lambda's format. Uvicorn's loggers are also reattached to the root here so
    access and error lines arrive as JSON like everything else.

    Args:
        level: Root log level, case insensitive.
        service: Written as a `service` key by `JsonFormatter`. Ignored by `"text"` and by
            a caller-supplied formatter instance.
        environment: As `service`, written as an `environment` key.
        force: Reconfigure even though a previous call already did.
        stream: Where every handler this function installs writes. Defaults to
            `sys.stdout`, which is what Lambda and a container both read. Pass
            `sys.stderr` when stdout carries data rather than logs, as it does for a CLI
            command whose output is compared byte for byte.
        formatter: `"json"` (the default, and byte identical to 0.7.0), `"text"` for a
            human readable line on a TTY, or a `logging.Formatter` instance for a service
            that wants its own.

    Raises:
        ValueError: `formatter` is a string outside `"json"` and `"text"`.
    """
    global _CONFIGURED
    if _CONFIGURED and not force:
        return

    # Resolved before anything is torn down, so a bad `formatter` argument raises with the
    # previous configuration still in place rather than leaving the root logger with no
    # handler at all.
    resolved = _resolve_formatter(formatter, service=service, environment=environment)

    root = logging.getLogger()
    for existing in root.handlers[:]:
        root.removeHandler(existing)

    # `sys.stdout` is read here rather than defaulted in the signature, so a test or a
    # Lambda runtime that replaced the stream after import gets the replacement.
    handler = logging.StreamHandler(stream if stream is not None else sys.stdout)
    handler.setFormatter(resolved)
    root.addHandler(handler)
    root.setLevel(level.upper())

    # Uvicorn configures these with its own handlers and `propagate = False`, so without
    # this they bypass the formatter entirely and land in CloudWatch as plain text.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uvicorn_logger = logging.getLogger(name)
        uvicorn_logger.handlers.clear()
        uvicorn_logger.propagate = True

    # botocore at DEBUG logs every request and response including headers. That is a large
    # volume of CloudWatch ingestion and it can carry credentials, so it stays at WARNING
    # unless a service raises it deliberately.
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """`logging.getLogger`, re-exported so a service imports logging from one place."""
    return logging.getLogger(name)
