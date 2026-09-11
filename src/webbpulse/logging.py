"""JSON logging that CloudWatch and Lambda both read correctly.

One formatter and one setup function. Each line is a JSON object with a top-level `level`
and an RFC 3339 `timestamp`, which is what Lambda log-level filtering needs, plus the
active trace and span ids. `stream=` and `formatter=` are the escape hatches.
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

_CONFIGURED = False


def _trace_context() -> dict[str, str]:
    """Return the current trace and span ids, or `{}` when there is no recording span.

    The import is guarded, since OpenTelemetry is behind the `otel` extra. The ids are
    lower-case hex of the OpenTelemetry width, not the X-Ray form.
    """
    try:
        from opentelemetry import trace
    except ImportError:
        return {}

    span = trace.get_current_span()
    context = span.get_span_context()
    if not context.is_valid:
        return {}
    return {
        "trace_id": format(context.trace_id, "032x"),
        "span_id": format(context.span_id, "016x"),
    }


def _request_context() -> dict[str, str]:
    """Return the bound request and user ids, or `{}` when nothing is bound.

    Merged into a record only where a key is still absent, so an explicit `extra=` value at
    the call site wins over the ambient one.
    """
    from webbpulse.log_context import current_context

    return current_context()


class JsonFormatter(logging.Formatter):
    """Render a `LogRecord` as one line of JSON.

    The keys match the ones Lambda uses for its own JSON format, including `errorType`,
    `errorMessage` and `stackTrace` for an exception, so one query reads both.
    """

    def __init__(self, *, service: str | None = None, environment: str | None = None) -> None:
        """Record the optional `service` and `environment` keys to stamp on every line."""
        super().__init__()
        self._static: dict[str, str] = {}
        if service:
            self._static["service"] = service
        if environment:
            self._static["environment"] = environment

    def format(self, record: logging.LogRecord) -> str:
        """Render the record, its exception info, its `extra` keys and the bound context."""
        payload: dict[str, Any] = {
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

        for key, value in record.__dict__.items():
            if key not in _RESERVED and key not in payload and not key.startswith("_"):
                payload[key] = value

        for key, value in _request_context().items():
            payload.setdefault(key, value)

        return json.dumps(payload, default=str, separators=(",", ":"))


TEXT_LOG_FORMAT: Final = "%(asctime)s %(levelname)-8s %(name)s %(message)s"


class TextFormatter(logging.Formatter):
    """One human readable line per record, for a TTY.

    The `service`, `environment` and bound request context keys are dropped: locally they
    are noise, and `LogContextFilter` already covers a format string that wants them.
    """

    def __init__(self, fmt: str | None = None, datefmt: str | None = None) -> None:
        """Format records with `TEXT_LOG_FORMAT` unless the caller supplies its own."""
        super().__init__(fmt or TEXT_LOG_FORMAT, datefmt)


FormatterSpec = Literal["json", "text"] | logging.Formatter


def _resolve_formatter(
    spec: FormatterSpec,
    *,
    service: str | None,
    environment: str | None,
) -> logging.Formatter:
    """Turn a `formatter=` argument into the formatter instance to install.

    A `logging.Formatter` instance is returned unchanged, since the caller owns what it
    renders.
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

    Idempotent unless `force` is set, and it replaces existing handlers so Lambda's own
    handler cannot emit every record a second time. Raises `ValueError` for a bad
    `formatter`.
    """
    global _CONFIGURED
    if _CONFIGURED and not force:
        return

    resolved = _resolve_formatter(formatter, service=service, environment=environment)

    root = logging.getLogger()
    for existing in root.handlers[:]:
        root.removeHandler(existing)

    handler = logging.StreamHandler(stream if stream is not None else sys.stdout)
    handler.setFormatter(resolved)
    root.addHandler(handler)
    root.setLevel(level.upper())

    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uvicorn_logger = logging.getLogger(name)
        uvicorn_logger.handlers.clear()
        uvicorn_logger.propagate = True

    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """`logging.getLogger`, re-exported so a service imports logging from one place."""
    return logging.getLogger(name)
