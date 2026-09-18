"""Tests for the shared stream consumer route.

Covers a product-style consumer: records dispatched one by one, the partial failure
envelope, the gateway guard, the event name filter, and how the route's path resolves.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from webbpulse.events import (
    APP_EVENTS_PATH_ENV,
    DEFAULT_EVENTS_PATH,
    EVENTS_PATH_ENV,
    LWA_PASS_THROUGH_PATH_ENV,
    arrived_through_api_gateway,
    batch_item_failures,
    event_records,
    events_path,
    record_id,
    register_stream_consumer,
    stream_consumer_app,
)

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Mapping

fastapi = pytest.importorskip("fastapi")

from fastapi import APIRouter, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

GATEWAY_CONTEXT = json.dumps({"requestId": "req-1", "http": {"method": "POST"}})


@pytest.fixture(autouse=True)
def _clear_path_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """No inherited adapter configuration, so every test starts at `/events`."""
    monkeypatch.delenv(EVENTS_PATH_ENV, raising=False)
    monkeypatch.delenv(LWA_PASS_THROUGH_PATH_ENV, raising=False)


def _stream_event(*records: Mapping[str, Any]) -> dict[str, Any]:
    """One DynamoDB Streams batch wrapping the given records."""
    return {"Records": list(records)}


def _remove(event_id: str, user_id: str) -> dict[str, Any]:
    """One `REMOVE` record for `user_id`, in the attribute-value shape the stream sends."""
    return {
        "eventID": event_id,
        "eventName": "REMOVE",
        "dynamodb": {"Keys": {"id": {"S": user_id}}},
    }


def test_the_path_prefers_the_explicit_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    """`IDENTITY_EVENTS_PATH` wins, then `APP_EVENTS_PATH`, then the adapter's own, then `/events`."""
    assert events_path() == DEFAULT_EVENTS_PATH

    monkeypatch.setenv(LWA_PASS_THROUGH_PATH_ENV, "/stream")
    assert events_path() == "/stream"

    monkeypatch.setenv(APP_EVENTS_PATH_ENV, "/app-events")
    assert events_path() == "/app-events"

    monkeypatch.setenv(EVENTS_PATH_ENV, "purge/")
    assert events_path() == "/purge"


def test_the_platform_modules_application_variable_is_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """`APP_EVENTS_PATH` is the half of the pair the application is meant to read.

    The `lambda-function` module emits one `events_path` input as both
    `AWS_LWA_PASS_THROUGH_PATH`, for the adapter, and `APP_EVENTS_PATH`, for the application,
    so the two cannot drift. Reading only the adapter's variable left the application half of
    that promise unkept and the route mounted at the default while the adapter posted
    elsewhere.
    """
    monkeypatch.setenv(APP_EVENTS_PATH_ENV, "consume/")

    assert events_path() == "/consume"


def test_the_route_mounts_at_the_application_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    """End to end: a function wired by the module serves where the adapter posts."""
    monkeypatch.setenv(APP_EVENTS_PATH_ENV, "/events-app")
    app = stream_consumer_app(lambda record: None, title="Views consumer")

    with TestClient(app) as client:
        assert client.post("/events-app", json=_stream_event()).status_code == 200
        assert client.post(DEFAULT_EVENTS_PATH, json=_stream_event()).status_code == 404


def test_the_route_mounts_at_the_resolved_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """The route follows the adapter's pass-through path without the caller naming it."""
    monkeypatch.setenv(LWA_PASS_THROUGH_PATH_ENV, "/consume")
    app = stream_consumer_app(lambda record: None, title="Votes consumer")

    with TestClient(app) as client:
        assert client.post("/consume", json=_stream_event()).status_code == 200
        assert client.post(DEFAULT_EVENTS_PATH, json=_stream_event()).status_code == 404


def test_an_explicit_path_overrides_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """A caller that knows its path does not have to set an environment variable."""
    monkeypatch.setenv(LWA_PASS_THROUGH_PATH_ENV, "/consume")
    app = stream_consumer_app(lambda record: None, title="Votes consumer", path="/pinned")

    with TestClient(app) as client:
        assert client.post("/pinned", json=_stream_event()).status_code == 200


def test_every_record_reaches_the_handler() -> None:
    """A product consumer sees each record once, in order, and answers no failures."""
    seen: list[str] = []
    app = stream_consumer_app(lambda record: seen.append(record_id(record)), title="Votes consumer")

    with TestClient(app) as client:
        response = client.post(DEFAULT_EVENTS_PATH, json=_stream_event(_remove("evt-1", "u1"), _remove("evt-2", "u2")))

    assert response.json() == {"batchItemFailures": []}
    assert seen == ["evt-1", "evt-2"]


def test_a_raising_record_is_the_only_one_reported() -> None:
    """A partial failure retries that record alone; the rest of the batch stays handled."""
    handled: list[str] = []

    def handle(record: Mapping[str, Any]) -> None:
        """Fail the second record and record the others."""
        if record_id(record) == "evt-2":
            raise RuntimeError("the write failed")
        handled.append(record_id(record))

    app = stream_consumer_app(handle, title="Votes consumer")
    batch = _stream_event(_remove("evt-1", "u1"), _remove("evt-2", "u2"), _remove("evt-3", "u3"))

    with TestClient(app) as client:
        response = client.post(DEFAULT_EVENTS_PATH, json=batch)

    assert response.status_code == 200
    assert response.json() == {"batchItemFailures": [{"itemIdentifier": "evt-2"}]}
    assert handled == ["evt-1", "evt-3"]


def test_an_sqs_record_is_reported_under_its_message_id() -> None:
    """A queue consumer's failures name `messageId`, which is what SQS matches."""

    def handle(record: Mapping[str, Any]) -> None:
        """Fail every record."""
        raise RuntimeError("the write failed")

    app = stream_consumer_app(handle, title="Price alerts consumer")

    with TestClient(app) as client:
        response = client.post(DEFAULT_EVENTS_PATH, json={"Records": [{"messageId": "msg-1", "body": "{}"}]})

    assert response.json() == {"batchItemFailures": [{"itemIdentifier": "msg-1"}]}


def test_event_names_filter_the_batch() -> None:
    """Only the named event types reach the handler, the way the purge takes only REMOVE."""
    seen: list[str] = []
    app = stream_consumer_app(
        lambda record: seen.append(record_id(record)),
        title="Purge consumer",
        event_names={"REMOVE"},
    )
    batch = _stream_event(
        {"eventID": "evt-1", "eventName": "INSERT"},
        _remove("evt-2", "u2"),
        {"eventID": "evt-3", "eventName": "MODIFY"},
    )

    with TestClient(app) as client:
        response = client.post(DEFAULT_EVENTS_PATH, json=batch)

    assert response.json() == {"batchItemFailures": []}
    assert seen == ["evt-2"]


def test_a_gateway_originated_request_is_refused() -> None:
    """A consumer is queue and stream only, so a gateway call gets a 404, not a refusal."""
    seen: list[str] = []
    app = stream_consumer_app(lambda record: seen.append(record_id(record)), title="Votes consumer")

    with TestClient(app) as client:
        response = client.post(
            DEFAULT_EVENTS_PATH,
            json=_stream_event(_remove("evt-1", "u1")),
            headers={"x-amzn-request-context": GATEWAY_CONTEXT},
        )

    assert response.status_code == 404
    assert seen == []


def test_the_adapters_pass_through_is_admitted() -> None:
    """The adapter sends the literal `null` context on a pass-through, which is not a gateway call."""
    seen: list[str] = []
    app = stream_consumer_app(lambda record: seen.append(record_id(record)), title="Votes consumer")

    with TestClient(app) as client:
        response = client.post(
            DEFAULT_EVENTS_PATH,
            json=_stream_event(_remove("evt-1", "u1")),
            headers={"x-amzn-request-context": "null", "x-amzn-lambda-context": json.dumps({"request_id": "r"})},
        )

    assert response.status_code == 200
    assert seen == ["evt-1"]


def test_the_guard_can_be_turned_off() -> None:
    """A consumer that does answer gateway traffic opts out rather than forking the route."""
    app = stream_consumer_app(lambda record: None, title="Votes consumer", guard_gateway=False)

    with TestClient(app) as client:
        response = client.post(
            DEFAULT_EVENTS_PATH,
            json=_stream_event(_remove("evt-1", "u1")),
            headers={"x-amzn-request-context": GATEWAY_CONTEXT},
        )

    assert response.status_code == 200


def test_a_batch_handler_owns_the_envelope() -> None:
    """`per_record=False` hands the whole event over, for a handler that already reports failures."""
    seen: list[Any] = []

    def handle(event: Mapping[str, Any]) -> dict[str, list[dict[str, str]]]:
        """Return the envelope directly, the way a product's `handle` does today."""
        seen.append(event)
        return batch_item_failures(["evt-9"])

    app = stream_consumer_app(handle, title="Votes consumer", per_record=False)
    batch = _stream_event(_remove("evt-1", "u1"))

    with TestClient(app) as client:
        response = client.post(DEFAULT_EVENTS_PATH, json=batch)

    assert response.json() == {"batchItemFailures": [{"itemIdentifier": "evt-9"}]}
    assert seen == [batch]


def test_an_empty_or_malformed_batch_answers_no_failures() -> None:
    """Nothing to do is a success, so the mapping does not retry a batch with no records."""
    app = stream_consumer_app(lambda record: None, title="Votes consumer")

    with TestClient(app) as client:
        assert client.post(DEFAULT_EVENTS_PATH, json={"Records": []}).json() == {"batchItemFailures": []}
        assert client.post(DEFAULT_EVENTS_PATH, json=[]).json() == {"batchItemFailures": []}
        assert client.post(DEFAULT_EVENTS_PATH, json={"Records": "nope"}).json() == {"batchItemFailures": []}


def test_the_consumer_app_keeps_health_and_hides_the_schema() -> None:
    """The root routes come along, and the one route is not part of any published API."""
    app = stream_consumer_app(lambda record: None, title="Votes consumer", version="1.2.3")

    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/openapi.json").status_code == 404


def test_the_primitive_mounts_on_an_existing_router() -> None:
    """`register_stream_consumer` is the half a product mounts beside its own routes."""
    router = APIRouter(prefix="/internal")
    seen: list[str] = []
    register_stream_consumer(router, lambda record: seen.append(record_id(record)))

    app = FastAPI()
    app.include_router(router)

    with TestClient(app) as client:
        response = client.post("/internal/events", json=_stream_event(_remove("evt-1", "u1")))

    assert response.json() == {"batchItemFailures": []}
    assert seen == ["evt-1"]


def test_middleware_is_added_in_order() -> None:
    """A product's own middleware still applies, without hand-building the app."""
    from starlette.middleware.base import BaseHTTPMiddleware

    class StampMiddleware(BaseHTTPMiddleware):
        """Stamp a header so the test can see the middleware ran."""

        async def dispatch(self, request: Any, call_next: Any) -> Any:
            """Add the marker header to every response."""
            response = await call_next(request)
            response.headers["X-Stamp"] = "on"
            return response

    app = stream_consumer_app(lambda record: None, title="Votes consumer", middleware=[StampMiddleware])

    with TestClient(app) as client:
        response = client.post(DEFAULT_EVENTS_PATH, json=_stream_event())

    assert response.headers["X-Stamp"] == "on"


def test_event_records_takes_only_mappings() -> None:
    """A record that is not an object is skipped rather than raising inside the route."""
    assert event_records({"Records": [{"eventID": "a"}, "nope", 3]}) == [{"eventID": "a"}]
    assert event_records(None) == []
    assert event_records({"Records": {"eventID": "a"}}) == []


def test_a_record_with_no_identifier_reports_an_empty_string() -> None:
    """An unidentifiable record still gets an entry, so the batch is not silently dropped."""
    assert record_id({}) == ""
    assert record_id({"eventID": "a", "messageId": "b"}) == "a"


def test_a_bare_request_id_is_not_a_gateway_call() -> None:
    """The runtime adds a request id to both paths, so it proves nothing on its own."""

    class _Request:
        """The smallest thing the guard reads."""

        def __init__(self, headers: dict[str, str]) -> None:
            """Hold the headers the guard inspects."""
            self.headers = headers

    assert not arrived_through_api_gateway(_Request({}))
    assert not arrived_through_api_gateway(_Request({"x-amzn-request-context": "null"}))
    assert not arrived_through_api_gateway(_Request({"x-amzn-request-context": "{}"}))
    assert arrived_through_api_gateway(_Request({"x-amzn-request-context": GATEWAY_CONTEXT}))
    assert arrived_through_api_gateway(_Request({"x-amzn-request-context": "not json"}))
