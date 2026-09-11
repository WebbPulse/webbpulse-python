"""Request and correlation context, carried on context variables.

The request and user ids live on `contextvars`, so every log record, span and error report
in the same task sees them without being threaded through call signatures. Both default to
the `"-"` placeholder, and every setter returns a token to reset through.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Final

__all__ = [
    "UNSET",
    "LogContextFilter",
    "attach_log_context",
    "bind_context",
    "current_context",
    "log_context",
    "request_id_var",
    "set_request_id",
    "set_span_context_attributes",
    "set_user_id",
    "task_context",
    "user_id_var",
]

UNSET: Final = "-"

request_id_var: ContextVar[str] = ContextVar("webbpulse_request_id", default=UNSET)

user_id_var: ContextVar[str] = ContextVar("webbpulse_user_id", default=UNSET)

_REQUEST_ID_ATTRIBUTE: Final = "webbpulse.request_id"
_USER_ID_ATTRIBUTE: Final = "webbpulse.user_id"

_MAX_VALUE_LENGTH: Final = 128


def _clean(value: object) -> str:
    """Coerce a context value to a bounded, single-line string.

    Newlines are stripped, since one would split a log line, and the result is truncated so
    a caller-supplied id cannot inflate every record.
    """
    if value is None:
        return UNSET
    text = str(value).replace("\n", " ").replace("\r", " ").strip()
    if not text:
        return UNSET
    return text[:_MAX_VALUE_LENGTH]


def set_request_id(value: object) -> Token[str]:
    """Bind the request id for the current context, returning the reset token."""
    return request_id_var.set(_clean(value))


def set_user_id(value: object) -> Token[str]:
    """Bind the user id for the current context, returning the reset token.

    A request needs no matching reset: the binding was copied into the request's task and
    dies with it.
    """
    return user_id_var.set(_clean(value))


def current_context() -> dict[str, str]:
    """The bound context as a dict, omitting anything still unset.

    Omitting rather than reporting `"-"` is what makes this safe to merge into a log
    payload or a span.
    """
    context: dict[str, str] = {}
    request_id = request_id_var.get()
    if request_id != UNSET:
        context["request_id"] = request_id
    user_id = user_id_var.get()
    if user_id != UNSET:
        context["user_id"] = user_id
    return context


class LogContextFilter(logging.Filter):
    """Copy the bound context onto every record, for a service with its own formatter.

    Unlike `current_context`, it always sets both attributes, falling back to `UNSET`, so a
    format string referencing them cannot raise. An `extra=` value at the call site wins.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Set `request_id` and `user_id` on the record unless it already carries them."""
        if not hasattr(record, "request_id"):
            record.request_id = request_id_var.get()
        if not hasattr(record, "user_id"):
            record.user_id = user_id_var.get()
        return True


def attach_log_context(logger: logging.Logger | None = None) -> None:
    """Attach `LogContextFilter` to every handler on `logger`, at most once each.

    Defaults to the root logger, and is idempotent so a composition root that runs twice
    does not stack duplicate filters.
    """
    target = logger if logger is not None else logging.getLogger()
    for handler in target.handlers:
        if not any(isinstance(existing, LogContextFilter) for existing in handler.filters):
            handler.addFilter(LogContextFilter())


def set_span_context_attributes() -> None:
    """Copy the bound context onto the active OpenTelemetry span.

    A no-op without the `otel` extra or without a recording span, and it never raises.
    """
    try:
        from opentelemetry import trace
    except ImportError:  # pragma: no cover
        return

    span = trace.get_current_span()
    if not span.get_span_context().is_valid:
        return
    for key, value in (
        (_REQUEST_ID_ATTRIBUTE, request_id_var.get()),
        (_USER_ID_ATTRIBUTE, user_id_var.get()),
    ):
        if value != UNSET:
            span.set_attribute(key, value)


@contextmanager
def bind_context(*, request_id: object = None, user_id: object = None) -> Iterator[dict[str, str]]:
    """Bind either field for the duration of the block, restoring both on exit.

    A `None` field leaves whatever is already bound in place, so an inner block can narrow
    the user without disturbing the request id. Yields the resulting context.
    """
    tokens: list[tuple[ContextVar[str], Token[str]]] = []
    if request_id is not None:
        tokens.append((request_id_var, set_request_id(request_id)))
    if user_id is not None:
        tokens.append((user_id_var, set_user_id(user_id)))
    try:
        yield current_context()
    finally:
        for variable, token in reversed(tokens):
            variable.reset(token)


@contextmanager
def task_context(task_name: str, job_id: object = None) -> Iterator[dict[str, str]]:
    """Bind a synthetic context for work that runs outside a request.

    The request id takes the greppable shape `bg:<task_name>:<job_id>` and the user id is
    `"bg"`, so a log query can select one background task's output.
    """
    with bind_context(
        request_id=f"bg:{task_name}:{_clean(job_id)}",
        user_id="bg",
    ) as context:
        yield context


log_context = task_context
