"""Request and correlation context, carried on context variables.

`webbpulse.http.RequestIdMiddleware` already mints a request id and hangs it on
`request.state`, which is what the error envelope reads. That is enough for a response
body and nothing else: `request.state` is reachable only from code holding the `Request`
object, so a repository three layers down, a background task, or a CLI command cannot see
it, and neither can a `logging.Filter`. This module is the other half. The same id also
goes onto a context variable, and from there it reaches every log record, every OTel span
and every error report in the same task without being threaded through call signatures.

## What it composes with

* **`webbpulse.logging`.** `JsonFormatter` merges `current_context()` into every record it
  formats, so a service that calls `configure_logging` gets `request_id` and `user_id` as
  top-level keys with no further wiring. `LogContextFilter` is the same fields for a
  service that keeps its own formatter, attached to a handler rather than the formatter.
* **`webbpulse.otel`.** `set_span_context_attributes()` copies the same values onto the
  active span as `webbpulse.request_id` and `webbpulse.user_id`, which is the attribute
  name `RequestIdMiddleware` already uses, so a log line and a span join on one string.
* **`webbpulse.http`.** `RequestIdMiddleware` binds `request_id_var` for the life of the
  request as well as setting `request.state`, so a service that already mounts it gets the
  log correlation with no code change at all. The authentication dependency calls
  `set_user_id` once it has resolved a principal.

## Why context variables rather than thread locals

Starlette runs a request in an `asyncio` task and a `def` endpoint in a worker thread from
a pool that is shared across requests. A thread local is therefore wrong twice: it leaks
between requests that reuse a pool thread, and it is invisible to code that awaited across
a hop. `contextvars` are copied into a task at creation and into a thread by
`anyio.to_thread.run_sync`, which is exactly the propagation wanted here.

## The defaults are strings, not None

Both fields default to `"-"` rather than `None`. A CloudWatch Logs Insights query filtering
on a field can distinguish a placeholder from a missing key, but a metric filter pattern
cannot, and neither can a human scanning lines. A constant placeholder makes "no request
scope" visible instead of silently absent, and it is what CarModPicker's log lines already
carry, so adoption does not change any existing query.

## Resetting is by token, never by re-setting the default

Every setter returns a token and the scope helpers reset through it. Setting a context
variable back to `"-"` on the way out looks equivalent and is not: it flattens nesting, so
an inner scope exiting would clear an outer scope's value rather than restoring it. That
matters for a background task started inside a request, which is the case the tokens exist
for.
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

#: The value both context variables carry outside any bound scope. A placeholder rather
#: than `None` so the key is always present and always a string, which is what a metric
#: filter pattern and a Logs Insights `filter` clause both need.
UNSET: Final = "-"

#: The current request or correlation id. Set by `webbpulse.http.RequestIdMiddleware`, by
#: `task_context` for work outside a request, or directly by a CLI entry point.
request_id_var: ContextVar[str] = ContextVar("webbpulse_request_id", default=UNSET)

#: The authenticated principal's id, once authentication has resolved one. Set after the
#: request id, because a request has an id before it has a user and often never gets one.
user_id_var: ContextVar[str] = ContextVar("webbpulse_user_id", default=UNSET)

#: Span attribute names. `webbpulse.request_id` is the name `webbpulse.http` already sets,
#: so the two paths agree rather than producing two attributes for one value.
_REQUEST_ID_ATTRIBUTE: Final = "webbpulse.request_id"
_USER_ID_ATTRIBUTE: Final = "webbpulse.user_id"

#: Bound on a value's length. A request id can arrive from an inbound `X-Request-ID` header
#: and a user id from a token claim, so both are caller-influenced, and an unbounded value
#: would be copied onto every log line and every span for the rest of the request.
_MAX_VALUE_LENGTH: Final = 128


def _clean(value: object) -> str:
    """Coerce a context value to a bounded, single-line string.

    A `UUID`, an `int` primary key and a `str` all reach here from real call sites, so the
    coercion is deliberate rather than a type error waiting to happen. Newlines are
    stripped because a value containing one would split a JSON log line in a plain-text
    handler and break log parsing downstream.
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

    Called from the authentication dependency once the principal is known. There is no
    matching reset at the end of the request: the context variable was copied into the
    request's task, so it dies with the task rather than leaking into the next request.
    """
    return user_id_var.set(_clean(value))


def current_context() -> dict[str, str]:
    """The bound context as a dict, omitting anything still unset.

    Omission rather than a `"-"` value is what makes this safe to merge into a log payload
    or a span: a caller that has set neither field gets `{}` and no keys are added. The
    placeholder is applied by `LogContextFilter`, which has to produce an attribute either
    way because a format string referencing `%(request_id)s` fails without one.
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

    A service using `webbpulse.logging.configure_logging` needs none of this: the JSON
    formatter merges `current_context()` itself. This exists for the other case, a
    `logging.Formatter` with a format string like `[req=%(request_id)s user=%(user_id)s]`,
    which raises rather than degrading if the attributes are absent. So unlike
    `current_context`, this always sets both attributes, using `UNSET` when nothing is
    bound.

    A record that already carries the attribute, because it was passed through
    `extra={"request_id": ...}` at the call site, is left alone. An explicit value at the
    call site is more specific than the ambient one and should win.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "request_id"):
            record.request_id = request_id_var.get()
        if not hasattr(record, "user_id"):
            record.user_id = user_id_var.get()
        return True


def attach_log_context(logger: logging.Logger | None = None) -> None:
    """Attach `LogContextFilter` to every handler on `logger`, at most once each.

    Defaults to the root logger. The idempotence is load bearing rather than defensive:
    a composition root that runs at import and again from an entry point's `main()` would
    otherwise stack a second instance on every handler, evaluating the same filter twice
    per record for no gain.
    """
    target = logger if logger is not None else logging.getLogger()
    for handler in target.handlers:
        if not any(isinstance(existing, LogContextFilter) for existing in handler.filters):
            handler.addFilter(LogContextFilter())


def set_span_context_attributes() -> None:
    """Copy the bound context onto the active OpenTelemetry span.

    A no-op when the `otel` extra is not installed, or when there is no recording span,
    which is the normal state in a test and in any service that has not called
    `configure_tracing`. Never raises: telemetry that turns a healthy request into a 500 is
    worse than the attribute it was trying to record.
    """
    try:
        from opentelemetry import trace
    except ImportError:  # pragma: no cover - otel extra absent
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

    Passing `None` for a field leaves whatever is already bound in place, so an inner
    block can narrow the user without disturbing the request id::

        with bind_context(request_id=incoming_id):
            with bind_context(user_id=principal.id):
                ...

    Yields the resulting context so a caller can log or assert on it without a second
    lookup.
    """
    tokens: list[tuple[ContextVar[str], Token[str]]] = []
    if request_id is not None:
        tokens.append((request_id_var, set_request_id(request_id)))
    if user_id is not None:
        tokens.append((user_id_var, set_user_id(user_id)))
    try:
        yield current_context()
    finally:
        # Reversed so nested binds of the same variable unwind in the order they were
        # made. Resetting an outer token before an inner one raises in `contextvars`.
        for variable, token in reversed(tokens):
            variable.reset(token)


@contextmanager
def task_context(task_name: str, job_id: object = None) -> Iterator[dict[str, str]]:
    """Bind a synthetic context for work that runs outside a request.

    A crawler run, a scheduled sweep, an EventBridge callback and a CLI command all log,
    and all of them would otherwise carry the `"-"` placeholder and be indistinguishable
    from each other in a log group. This gives each one a greppable id of the shape
    `bg:<task_name>:<job_id or "-">` with `user_id` of `"bg"`, so a CloudWatch Logs
    Insights query can select one task's output::

        filter request_id like /^bg:crawler:/

    The shape is deliberate and is what CarModPicker's `bg_log_context` already emits, so
    adopting this module does not invalidate a saved query or a dashboard.
    """
    with bind_context(
        request_id=f"bg:{task_name}:{_clean(job_id)}",
        user_id="bg",
    ) as context:
        yield context


#: `bg_log_context` under its WebbPulse name. `task_context` is the name to use; this alias
#: exists so a call site can be moved to the package in one commit and renamed in another.
log_context = task_context
