"""Tests for `webbpulse.log_context`.

The field names and the `bg:<task>:<job>` shape are pinned here because Logs Insights
queries and saved dashboards select on them, and no type checker catches a rename.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from webbpulse.http import RequestIdMiddleware, request_id
from webbpulse.log_context import (
    UNSET,
    LogContextFilter,
    attach_log_context,
    bind_context,
    current_context,
    log_context,
    request_id_var,
    set_request_id,
    set_span_context_attributes,
    set_user_id,
    task_context,
    user_id_var,
)
from webbpulse.logging import JsonFormatter


@pytest.fixture(autouse=True)
def _clean_context() -> Any:
    """Reset both context variables around every test, so no binding leaks between them."""
    rid = request_id_var.set(UNSET)
    uid = user_id_var.set(UNSET)
    yield
    request_id_var.reset(rid)
    user_id_var.reset(uid)


def _record(**kwargs: Any) -> logging.LogRecord:
    """Build a plain INFO log record, overriding any field by keyword."""
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


def test_nothing_is_bound_by_default() -> None:
    """With nothing bound, both variables hold the placeholder and the context is empty."""
    assert request_id_var.get() == UNSET
    assert user_id_var.get() == UNSET
    assert current_context() == {}


def test_current_context_omits_unset_fields_rather_than_placeholdering_them() -> None:
    """`current_context` reports only the bound fields, not placeholders."""
    set_request_id("abc")
    assert current_context() == {"request_id": "abc"}


def test_current_context_reports_both_when_both_are_bound() -> None:
    """`current_context` reports the request id and the user id together."""
    set_request_id("abc")
    set_user_id("user-1")
    assert current_context() == {"request_id": "abc", "user_id": "user-1"}


def test_a_non_string_value_is_coerced() -> None:
    """A non-string value is stored as its string form."""
    set_user_id(42)
    assert user_id_var.get() == "42"


def test_none_becomes_the_placeholder_rather_than_the_string_none() -> None:
    """Setting None binds the placeholder, not the text "None"."""
    set_request_id(None)
    assert request_id_var.get() == UNSET


def test_a_blank_value_becomes_the_placeholder() -> None:
    """A whitespace only value binds the placeholder."""
    set_request_id("   ")
    assert request_id_var.get() == UNSET


def test_a_value_is_stripped() -> None:
    """Surrounding whitespace is stripped from a bound value."""
    set_request_id("  abc  ")
    assert request_id_var.get() == "abc"


def test_newlines_are_flattened_so_one_record_stays_one_line() -> None:
    """Newlines and carriage returns become spaces, keeping a record on one line."""
    set_request_id("a\nb\rc")
    assert request_id_var.get() == "a b c"


def test_a_long_value_is_truncated() -> None:
    """A bound value is truncated to 128 characters."""
    set_request_id("x" * 500)
    assert len(request_id_var.get()) == 128


def test_a_setter_returns_a_token_that_restores_the_previous_value() -> None:
    """A setter returns a token that `reset` uses to restore the previous value."""
    set_request_id("outer")
    token = set_request_id("inner")
    assert request_id_var.get() == "inner"
    request_id_var.reset(token)
    assert request_id_var.get() == "outer"


def test_bind_context_binds_and_restores() -> None:
    """`bind_context` yields what it bound and clears it on exit."""
    with bind_context(request_id="r1", user_id="u1") as bound:
        assert bound == {"request_id": "r1", "user_id": "u1"}
        assert current_context() == {"request_id": "r1", "user_id": "u1"}
    assert current_context() == {}


def test_bind_context_leaves_an_omitted_field_alone() -> None:
    """A field `bind_context` was not given keeps its outer value throughout."""
    set_request_id("outer-request")
    with bind_context(user_id="u1"):
        assert request_id_var.get() == "outer-request"
        assert user_id_var.get() == "u1"
    assert request_id_var.get() == "outer-request"
    assert user_id_var.get() == UNSET


def test_bind_context_nests_and_unwinds_in_order() -> None:
    """Nested binds unwind to the enclosing value, then to the placeholder."""
    with bind_context(request_id="r1"):
        with bind_context(request_id="r2"):
            assert request_id_var.get() == "r2"
        assert request_id_var.get() == "r1"
    assert request_id_var.get() == UNSET


def test_bind_context_restores_when_the_body_raises() -> None:
    """The binding is restored even when the body raises."""
    with pytest.raises(RuntimeError), bind_context(request_id="r1"):
        raise RuntimeError("boom")
    assert current_context() == {}


def test_bind_context_with_no_arguments_binds_nothing() -> None:
    """`bind_context()` with no arguments binds and yields nothing."""
    with bind_context() as bound:
        assert bound == {}


def test_task_context_produces_the_greppable_background_shape() -> None:
    """`task_context` binds `bg:<task>:<job>` as the request id and `bg` as the user id."""
    with task_context("crawler", "job-7") as bound:
        assert bound == {"request_id": "bg:crawler:job-7", "user_id": "bg"}
    assert current_context() == {}


def test_task_context_without_a_job_id_uses_the_placeholder() -> None:
    """With no job id, the job segment is the placeholder."""
    with task_context("sweep"):
        assert request_id_var.get() == "bg:sweep:-"


def test_task_context_coerces_a_non_string_job_id() -> None:
    """A non-string job id is rendered as its string form."""
    with task_context("sweep", 99):
        assert request_id_var.get() == "bg:sweep:99"


def test_log_context_is_the_same_callable_under_the_legacy_name() -> None:
    """`log_context` is an alias of `task_context`."""
    assert log_context is task_context


def test_task_context_restores_an_outer_request_scope() -> None:
    """A task scope nested in a request scope restores the request binding on exit."""
    with bind_context(request_id="r1", user_id="u1"):
        with task_context("crawler"):
            assert request_id_var.get() == "bg:crawler:-"
        assert current_context() == {"request_id": "r1", "user_id": "u1"}


def test_the_filter_always_sets_both_attributes_even_when_unbound() -> None:
    """The filter passes the record and sets both attributes to the placeholder."""
    record = _record()
    assert LogContextFilter().filter(record) is True
    assert record.request_id == UNSET  # type: ignore[attr-defined]
    assert record.user_id == UNSET  # type: ignore[attr-defined]


def test_the_filter_copies_the_bound_values() -> None:
    """The filter copies the bound request id and user id onto the record."""
    set_request_id("r1")
    set_user_id("u1")
    record = _record()
    LogContextFilter().filter(record)
    assert record.request_id == "r1"  # type: ignore[attr-defined]
    assert record.user_id == "u1"  # type: ignore[attr-defined]


def test_the_filter_leaves_an_explicit_call_site_value_alone() -> None:
    """A value already on the record wins over the ambient binding."""
    set_request_id("ambient")
    record = _record()
    record.request_id = "explicit"
    LogContextFilter().filter(record)
    assert record.request_id == "explicit"  # type: ignore[attr-defined]


def test_a_percent_style_format_string_works_with_the_filter_attached() -> None:
    """With the filter attached, a percent-style format can reference both fields."""
    set_request_id("r1")
    set_user_id("u1")
    record = _record()
    LogContextFilter().filter(record)
    formatter = logging.Formatter("[req=%(request_id)s user=%(user_id)s] %(message)s")
    assert formatter.format(record) == "[req=r1 user=u1] hello"


def test_attach_log_context_adds_the_filter_once_per_handler() -> None:
    """Calling `attach_log_context` twice installs only one filter on the handler."""
    logger = logging.getLogger("test.attach.once")
    logger.handlers.clear()
    handler = logging.StreamHandler()
    logger.addHandler(handler)
    try:
        attach_log_context(logger)
        attach_log_context(logger)
        installed = [f for f in handler.filters if isinstance(f, LogContextFilter)]
        assert len(installed) == 1
    finally:
        logger.handlers.clear()


def test_attach_log_context_defaults_to_the_root_logger() -> None:
    """With no argument, `attach_log_context` installs the filter on the root logger."""
    root = logging.getLogger()
    handler = logging.StreamHandler()
    root.addHandler(handler)
    try:
        attach_log_context()
        assert any(isinstance(f, LogContextFilter) for f in handler.filters)
    finally:
        root.removeHandler(handler)


def test_the_json_formatter_merges_the_bound_context_with_no_filter_attached() -> None:
    """`JsonFormatter` picks up the bound context without any filter attached."""
    set_request_id("r1")
    set_user_id("u1")
    payload = json.loads(JsonFormatter().format(_record()))
    assert payload["request_id"] == "r1"
    assert payload["user_id"] == "u1"


def test_the_json_formatter_omits_the_keys_when_nothing_is_bound() -> None:
    """With nothing bound, neither key appears in the JSON payload."""
    payload = json.loads(JsonFormatter().format(_record()))
    assert "request_id" not in payload
    assert "user_id" not in payload


def test_an_explicit_extra_beats_the_ambient_context_in_json() -> None:
    """A value set on the record wins over the ambient binding in the JSON payload."""
    set_request_id("ambient")
    record = _record()
    record.request_id = "explicit"
    payload = json.loads(JsonFormatter().format(record))
    assert payload["request_id"] == "explicit"


def test_the_background_shape_survives_json_formatting() -> None:
    """A task scope's `bg:` request id and `bg` user id reach the JSON payload intact."""
    with task_context("crawler", "job-7"):
        payload = json.loads(JsonFormatter().format(_record()))
    assert payload["request_id"] == "bg:crawler:job-7"
    assert payload["user_id"] == "bg"


class _FakeSpanContext:
    """A span context stub carrying only the validity flag the module reads."""

    def __init__(self, valid: bool) -> None:
        """Record whether this context should report itself as valid."""
        self.is_valid = valid


class _FakeSpan:
    """A span stub that records the attributes set on it."""

    def __init__(self, valid: bool = True) -> None:
        """Build a span whose context is valid unless told otherwise."""
        self._context = _FakeSpanContext(valid)
        self.attributes: dict[str, str] = {}

    def get_span_context(self) -> _FakeSpanContext:
        """Return this span's context stub."""
        return self._context

    def set_attribute(self, key: str, value: str) -> None:
        """Record an attribute set on this span."""
        self.attributes[key] = value


def test_span_attributes_use_the_names_the_http_middleware_already_uses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The span attributes are `webbpulse.request_id` and `webbpulse.user_id`."""
    from opentelemetry import trace

    span = _FakeSpan()
    monkeypatch.setattr(trace, "get_current_span", lambda: span)
    set_request_id("r1")
    set_user_id("u1")
    set_span_context_attributes()
    assert span.attributes == {
        "webbpulse.request_id": "r1",
        "webbpulse.user_id": "u1",
    }


def test_span_attributes_skip_an_unbound_field(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unbound field is not set as a span attribute."""
    from opentelemetry import trace

    span = _FakeSpan()
    monkeypatch.setattr(trace, "get_current_span", lambda: span)
    set_request_id("r1")
    set_span_context_attributes()
    assert span.attributes == {"webbpulse.request_id": "r1"}


def test_span_attributes_are_a_no_op_without_a_recording_span(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With an invalid span context, no attributes are set."""
    from opentelemetry import trace

    span = _FakeSpan(valid=False)
    monkeypatch.setattr(trace, "get_current_span", lambda: span)
    set_request_id("r1")
    set_span_context_attributes()
    assert span.attributes == {}


def test_the_context_propagates_into_an_asyncio_task() -> None:
    """A task created inside a bound scope inherits the binding."""

    seen: dict[str, str] = {}

    async def child() -> None:
        """Record the context the task inherited."""
        seen.update(current_context())

    async def main() -> None:
        """Bind a context and await a child task inside it."""
        with bind_context(request_id="r1", user_id="u1"):
            await asyncio.create_task(child())

    asyncio.run(main())
    assert seen == {"request_id": "r1", "user_id": "u1"}


def test_a_binding_in_one_thread_does_not_leak_into_another() -> None:
    """Each thread starts from an empty context, so a binding does not leak across threads."""

    seen: dict[str, str] = {}

    def worker() -> None:
        """Record the context this thread starts with."""
        seen.update(current_context())

    set_request_id("main-thread")
    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()
    assert seen == {}


def test_the_request_id_middleware_binds_the_context_for_the_whole_request() -> None:
    """The middleware binds the incoming id so the context, request state and log record agree."""
    app = FastAPI()
    app.add_middleware(RequestIdMiddleware)
    seen: dict[str, Any] = {}

    @app.get("/probe")
    def probe(request: Request) -> dict[str, str]:
        """Record the context, the request state id and a formatted log record."""
        seen["context"] = current_context()
        seen["state"] = request_id(request)
        seen["record"] = json.loads(JsonFormatter().format(_record()))
        return {"ok": "yes"}

    with TestClient(app) as client:
        response = client.get("/probe", headers={"X-Request-ID": "edge-supplied-id"})

    assert response.headers["X-Request-ID"] == "edge-supplied-id"
    assert seen["context"] == {"request_id": "edge-supplied-id"}
    assert seen["state"] == "edge-supplied-id"
    assert seen["record"]["request_id"] == "edge-supplied-id"


def test_the_request_id_middleware_does_not_leak_the_id_past_the_request() -> None:
    """The context is empty again once the request has finished."""
    app = FastAPI()
    app.add_middleware(RequestIdMiddleware)

    @app.get("/probe")
    def probe() -> dict[str, str]:
        """Answer with a fixed body."""
        return {"ok": "yes"}

    with TestClient(app) as client:
        client.get("/probe")

    assert current_context() == {}
