"""Tests for `ExceptionGroupMiddleware`, the outermost guard `create_app` always installs.

The failure this guards against is a `BaseExceptionGroup` reaching uvicorn, which under the
Lambda Web Adapter kills the worker and every other request sharing it. Starlette collapses
a group holding exactly one leaf, so the cases that matter are a group with several leaves
and a group nested inside another group, both of which escape unchanged.

The fan-out middleware here is a `BaseHTTPMiddleware` whose `dispatch` starts a second task,
which is the smallest faithful reproduction of a real stack where an instrumentation layer
or a background task fails alongside the route. The OpenTelemetry ASGI middleware is exercised
separately, in `test_the_otel_instrumented_stack_never_leaks_a_group`, and skipped when the
`otel` extra is absent.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import anyio
import httpx
import pytest
from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from webbpulse.http import ExceptionGroupMiddleware, create_app, guard_exception_groups


class DomainFailure(Exception):
    """A product's own exception type, the kind a service registers a handler for."""


class _FanOutMiddleware(BaseHTTPMiddleware):
    """A `BaseHTTPMiddleware` running the request beside a sidecar whose teardown fails.

    Two leaves in one `anyio` task group is the shape Starlette cannot collapse, and this is
    how a real stack produces one: the route fails, the surrounding task group tears the
    sidecar down, and the sidecar's own cleanup fails on the way out. The route's exception
    is collected first, so it is the leaf the guard must report.

    `call_next` raising is what makes this faithful rather than contrived. It leaves the
    application's own error handlers out of the picture, exactly as they are when a
    `BaseHTTPMiddleware` sits between them and the route.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Run the application beside a sidecar task that fails as it is cancelled."""

        async def sidecar() -> None:
            """Wait until cancelled, then fail during teardown."""
            try:
                await anyio.sleep_forever()
            finally:
                raise ValueError("the sidecar task failed on the way out")

        async with anyio.create_task_group() as group:
            group.start_soon(sidecar)
            response = await call_next(request)
            group.cancel_scope.cancel()
            return response
        raise AssertionError("the task group cannot swallow the sidecar failure")


class _RaisingMiddleware(BaseHTTPMiddleware):
    """A `BaseHTTPMiddleware` that fails in `dispatch`, above the application's handlers.

    This is where an exception a service registered a handler for genuinely escapes those
    handlers: a middleware runs outside `ExceptionMiddleware`, so nothing matches it on the
    way out, and the task group around `dispatch` turns it into a group. An authentication or
    tenant-resolution middleware raising the product's own type is the everyday version.
    """

    def __init__(self, app: Any, *, error: BaseException) -> None:
        """Wrap `app` and raise `error` alongside a sidecar whose teardown also fails."""
        super().__init__(app)
        self._error = error

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Start a sidecar that fails on teardown, then fail the request itself."""

        async def sidecar() -> None:
            """Wait until cancelled, then fail during teardown."""
            try:
                await anyio.sleep_forever()
            finally:
                raise ValueError("the sidecar task failed on the way out")

        async with anyio.create_task_group() as group:
            group.start_soon(sidecar)
            raise self._error
        raise AssertionError("the task group cannot swallow the raised error")


def _http_scope(**overrides: Any) -> dict[str, Any]:
    """A minimal HTTP scope, enough for the guard to build a `Request` from."""
    scope: dict[str, Any] = {
        "type": "http",
        "method": "GET",
        "path": "/boom",
        "raw_path": b"/boom",
        "query_string": b"",
        "headers": [],
    }
    scope.update(overrides)
    return scope


async def _empty_receive() -> dict[str, Any]:
    """Report the request body as empty."""
    return {"type": "http.request", "body": b"", "more_body": False}


def _collect_into(sent: list[dict[str, Any]]) -> Any:
    """A `send` callable that appends every ASGI message to `sent`."""

    async def send(message: dict[str, Any]) -> None:
        """Record one outgoing ASGI message."""
        sent.append(message)

    return send


def _boom_router(error: BaseException | None = None) -> APIRouter:
    """A router whose one route raises `error`, defaulting to a plain `RuntimeError`."""
    failure = error if error is not None else RuntimeError("connection string postgres://u:hunter2@h/db")
    router = APIRouter()

    @router.get("/boom")
    async def boom() -> None:
        """Raise the configured failure."""
        raise failure

    return router


def test_a_plain_runtime_error_inside_a_group_renders_the_five_hundred_envelope() -> None:
    """A multi-leaf group holding a `RuntimeError` renders the standard 500, not a crash."""
    app = create_app([_boom_router()])
    app.add_middleware(_FanOutMiddleware)

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/boom")

    assert response.status_code == 500
    body = response.json()
    assert body["success"] is False
    assert body["status"] == 500
    assert body["message"] == "Internal server error."
    assert body["request_id"], "the request id is how the caller's report joins to the log"
    assert "hunter2" not in json.dumps(body), "internal detail must not reach the caller"
    assert response.headers["content-type"].startswith("application/json")


def test_a_registered_handler_still_runs_when_its_exception_arrives_in_a_group() -> None:
    """A domain exception wrapped in a group renders its own handler's response."""
    app = create_app([_boom_router()])

    @app.exception_handler(DomainFailure)
    async def _domain_failure(request: Request, exc: DomainFailure) -> JSONResponse:
        """Render the product's own 409 for a claimed widget."""
        return JSONResponse(status_code=409, content={"handled": True, "detail": str(exc)})

    app.add_middleware(_RaisingMiddleware, error=DomainFailure("the widget was already claimed"))

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/boom")

    assert response.status_code == 409, response.text
    assert response.json() == {"handled": True, "detail": "the widget was already claimed"}


def test_a_group_with_several_leaves_reports_the_first_non_cancellation_leaf(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The reported leaf is the first that is not a cancellation, and the rest are logged."""
    app = create_app([_boom_router()])

    @app.exception_handler(DomainFailure)
    async def _domain_failure(request: Request, exc: DomainFailure) -> JSONResponse:
        """Prove which leaf was chosen by rendering a status only this leaf produces."""
        return JSONResponse(status_code=418, content={"leaf": type(exc).__name__})

    app.add_middleware(_RaisingMiddleware, error=DomainFailure("the middleware refused it"))

    client = TestClient(app, raise_server_exceptions=False)
    with caplog.at_level(logging.ERROR, logger="webbpulse.http"):
        response = client.get("/boom")

    assert response.status_code == 418, response.text
    assert response.json() == {"leaf": "DomainFailure"}

    records = [record for record in caplog.records if "several leaves" in record.getMessage()]
    assert records, "the leaves that were not reported must still reach the log"
    record = records[0]
    assert record.reported_leaf == "DomainFailure"  # type: ignore[attr-defined]
    assert any("the sidecar task failed on the way out" in entry for entry in record.other_leaves)  # type: ignore[attr-defined]
    assert record.request_id  # type: ignore[attr-defined]


def test_a_group_of_only_cancellations_is_re_raised_rather_than_rendered() -> None:
    """A group whose every leaf is a cancellation carries no fault, so it is not answered.

    Turning it into a 500 would invent a failure for a request that was cancelled, and would
    swallow the cancellation the surrounding scope is waiting to observe. The guard is driven
    directly here because Starlette collapses a single-leaf group before the guard would see
    it, and a multi-leaf all-cancellation group is not something a route can be made to raise
    on demand.
    """
    group: BaseExceptionGroup[BaseException] = BaseExceptionGroup(
        "cancelled",
        [asyncio.CancelledError(), asyncio.CancelledError()],
    )

    async def failing_app(scope: Any, receive: Any, send: Any) -> None:
        """Raise the all-cancellation group."""
        raise group

    sent: list[dict[str, Any]] = []
    with pytest.raises(BaseExceptionGroup) as caught:
        anyio.run(ExceptionGroupMiddleware(failing_app), _http_scope(), _empty_receive, _collect_into(sent))

    assert not sent, "nothing may be sent for a request that was only cancelled"
    assert all(isinstance(leaf, asyncio.CancelledError) for leaf in caught.value.exceptions)


def test_a_cancellation_beside_a_fault_is_reported_as_the_fault() -> None:
    """A `BaseExceptionGroup` mixing a cancellation with a fault renders the fault.

    This is the exact shape that killed the worker in production: mixing a `CancelledError`
    into the group makes it a `BaseExceptionGroup` rather than an `ExceptionGroup`, so it is
    not an `Exception` and no handler, not even the catch-all, matches it.
    """
    group: BaseExceptionGroup[BaseException] = BaseExceptionGroup(
        "mixed",
        [asyncio.CancelledError(), RuntimeError("the real fault")],
    )
    assert not isinstance(group, Exception), "the premise of the bug is that no handler matches"

    async def failing_app(scope: Any, receive: Any, send: Any) -> None:
        """Raise the mixed group."""
        raise group

    sent: list[dict[str, Any]] = []
    anyio.run(ExceptionGroupMiddleware(failing_app), _http_scope(), _empty_receive, _collect_into(sent))

    assert sent[0]["status"] == 500
    assert json.loads(sent[1]["body"])["message"] == "Internal server error."


def test_a_response_that_has_already_started_is_not_given_a_second_response(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A stream that fails mid-body re-raises the leaf rather than sending a second start.

    Sending an error body after `http.response.start` is not possible: the status and headers
    are already on the wire. A truncated body plus a logged fault is the only honest outcome,
    and re-raising the leaf lets the server decide what to do with a half-sent response.
    """

    async def streaming_then_failing(scope: Any, receive: Any, send: Any) -> None:
        """Start a response, send one chunk, then raise a group."""
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": b"first-chunk", "more_body": True})
        raise ExceptionGroup("late", [RuntimeError("the stream failed after it started")])

    sent: list[dict[str, Any]] = []
    with (
        caplog.at_level(logging.ERROR, logger="webbpulse.http"),
        pytest.raises(RuntimeError, match="the stream failed after it started"),
    ):
        anyio.run(
            ExceptionGroupMiddleware(streaming_then_failing),
            _http_scope(),
            _empty_receive,
            _collect_into(sent),
        )

    starts = [message for message in sent if message["type"] == "http.response.start"]
    assert len(starts) == 1, "a second response start would corrupt the connection"
    assert any("already started" in record.getMessage() for record in caplog.records), (
        "a response that cannot be replaced must still be reported"
    )


def test_a_cross_origin_request_to_a_failing_route_keeps_its_cors_headers() -> None:
    """The guard sits outside CORS, so it has to add the headers CORS would have added."""
    app = create_app([_boom_router()], cors_allow_origins=["https://webbpulse.com"])
    app.add_middleware(_FanOutMiddleware)

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/boom", headers={"Origin": "https://webbpulse.com"})

    assert response.status_code == 500
    assert response.headers["access-control-allow-origin"] == "https://webbpulse.com"
    assert response.headers["access-control-allow-credentials"] == "true"


def test_a_cors_preflight_is_answered_even_when_the_route_behind_it_fails() -> None:
    """A preflight still gets its CORS headers while the route behind it is failing.

    The guard is above `CORSMiddleware`, so a preflight it had to answer itself would lose
    every CORS header and the browser would report a CORS failure rather than the real fault.
    The fan-out middleware is outermost here, above CORS, which is the arrangement that puts
    a preflight at risk in the first place.
    """
    app = create_app([_boom_router()], cors_allow_origins=["https://webbpulse.com"])
    app.add_middleware(_FanOutMiddleware)

    client = TestClient(app, raise_server_exceptions=False)
    response = client.options(
        "/boom",
        headers={
            "Origin": "https://webbpulse.com",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "content-type,x-request-id",
        },
    )

    assert response.headers["access-control-allow-origin"] == "https://webbpulse.com", (
        "a preflight must carry its CORS headers whatever happened behind it"
    )


def test_an_unlisted_origin_gets_no_cors_headers_on_the_five_hundred() -> None:
    """The guard must not turn itself into a way around the origin allow list."""
    app = create_app([_boom_router()], cors_allow_origins=["https://webbpulse.com"])
    app.add_middleware(_FanOutMiddleware)

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/boom", headers={"Origin": "https://evil.example"})

    assert response.status_code == 500
    assert "access-control-allow-origin" not in response.headers


@pytest.mark.anyio
async def test_the_group_never_reaches_an_asgi_transport() -> None:
    """With `raise_app_exceptions=False` the transport sees a 500, never a group."""
    app = create_app([_boom_router()])
    app.add_middleware(_FanOutMiddleware)

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/boom")

    assert response.status_code == 500
    assert response.json()["message"] == "Internal server error."


@pytest.mark.anyio
async def test_the_group_never_reaches_a_transport_that_does_raise() -> None:
    """Even with `raise_app_exceptions=True` nothing escapes, because nothing is raised."""
    app = create_app([_boom_router()])
    app.add_middleware(_FanOutMiddleware)

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=True)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/boom")

    assert response.status_code == 500


def test_a_nested_group_is_unwrapped_all_the_way_to_its_leaf() -> None:
    """Unwrapping is recursive, since one task group's group can hold another's."""
    inner = ExceptionGroup("inner", [DomainFailure("deep")])
    outer: BaseExceptionGroup[BaseException] = ExceptionGroup("outer", [inner, ValueError("shallow")])

    async def failing_app(scope: Any, receive: Any, send: Any) -> None:
        """Raise the nested group, standing in for a stack that produced one."""
        raise outer

    app = create_app()

    @app.exception_handler(DomainFailure)
    async def _domain_failure(request: Request, exc: DomainFailure) -> JSONResponse:
        """Prove the deep leaf is the one that was chosen."""
        return JSONResponse(status_code=418, content={"leaf": str(exc)})

    guarded = ExceptionGroupMiddleware(failing_app)
    handlers = {DomainFailure: _domain_failure}
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        """Report the request body as empty."""
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        """Collect what the guard sent."""
        sent.append(message)

    scope: dict[str, Any] = {
        "type": "http",
        "method": "GET",
        "path": "/boom",
        "raw_path": b"/boom",
        "query_string": b"",
        "headers": [],
        "starlette.exception_handlers": (handlers, {}),
        "app": app,
    }

    anyio.run(guarded, scope, receive, send)

    assert sent[0]["status"] == 418
    assert json.loads(sent[1]["body"]) == {"leaf": "deep"}


def test_the_guard_is_idempotent_unless_a_rewrap_is_asked_for() -> None:
    """A second plain call changes nothing, so an app cannot be wrapped twice by accident."""
    app = create_app()
    first = app.build_middleware_stack
    guard_exception_groups(app)
    assert app.build_middleware_stack is first, "create_app already installed the guard"

    guard_exception_groups(app, rewrap=True)
    assert app.build_middleware_stack is not first, "a rewrap must put a new layer outside"


def test_create_app_puts_a_guard_outside_the_stack_and_under_server_errors() -> None:
    """The backstop is outermost and the working guard sits under the innermost server errors."""
    from starlette.middleware.errors import ServerErrorMiddleware

    app = create_app()
    stack = app.build_middleware_stack()
    assert isinstance(stack, ExceptionGroupMiddleware), "the backstop must be outermost"

    layers: list[Any] = []
    current: Any = stack
    while current is not None and len(layers) < 32:
        layers.append(current)
        current = getattr(current, "app", None)

    server_errors = [index for index, layer in enumerate(layers) if isinstance(layer, ServerErrorMiddleware)]
    assert server_errors, "create_app must still install Starlette's own last resort"
    innermost = server_errors[-1]
    assert isinstance(layers[innermost + 1], ExceptionGroupMiddleware), (
        "a group must be unwrapped before the catch-all Exception handler can flatten it"
    )


def test_a_non_http_scope_passes_straight_through() -> None:
    """A lifespan or websocket scope is forwarded untouched, with no group handling."""
    seen: list[str] = []

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        """Record the scope type it was handed."""
        seen.append(scope["type"])

    async def receive() -> dict[str, Any]:
        """Never called, but required by the signature."""
        return {"type": "lifespan.startup"}

    async def send(message: dict[str, Any]) -> None:
        """Never called, but required by the signature."""

    anyio.run(ExceptionGroupMiddleware(inner), {"type": "lifespan"}, receive, send)
    assert seen == ["lifespan"]


def _otel_stack() -> FastAPI:
    """An app carrying the OpenTelemetry ASGI middleware plus a `BaseHTTPMiddleware`."""
    from webbpulse.otel import configure_tracing, instrument_fastapi

    configure_tracing("posts", endpoint="http://localhost:4318/v1/traces")
    app = FastAPI()
    app.include_router(_boom_router())
    app.add_middleware(_FanOutMiddleware)
    instrument_fastapi(app, excluded_urls="", flush_per_request=False, flush_on_shutdown=False)
    guard_exception_groups(app, rewrap=True)
    return app


def test_the_otel_instrumented_stack_never_leaks_a_group(monkeypatch: pytest.MonkeyPatch) -> None:
    """With the OTel server span middleware on the stack the group is still contained.

    This is the exact shape the production failure was reported in: the OTel ASGI middleware
    re-raises whatever the application raised, so before the guard the group travelled all
    the way out to uvicorn.
    """
    pytest.importorskip("opentelemetry.instrumentation.fastapi")
    from webbpulse.otel import OTEL_DISABLED_ENV, shutdown_tracing

    monkeypatch.delenv(OTEL_DISABLED_ENV, raising=False)
    app = _otel_stack()
    try:
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/boom")
    finally:
        shutdown_tracing(1)

    assert response.status_code == 500
