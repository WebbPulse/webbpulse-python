"""The stream and queue consumer route, once, for any domain.

A consumer Lambda runs behind the AWS Lambda Web Adapter, which posts a non-HTTP
invocation as a JSON body to its pass-through path and returns the response body as the
function's result. That makes a stream handler an ordinary POST route, and every consumer
writes the same one: resolve the path, refuse anything that arrived through API Gateway,
run each record, and answer the `ReportBatchItemFailures` envelope so the event source
mapping retries only the records that raised.

`register_stream_consumer` is the primitive and mounts that route on a router.
`stream_consumer_app` is the entrypoint-shaped wrapper that also brings the root routes and
the error handlers. `webbpulse.identity.events` is built on the primitive.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable, Collection, Mapping, Sequence
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import APIRouter, FastAPI

__all__ = [
    "BATCH_FAILURES_KEY",
    "DEFAULT_EVENTS_PATH",
    "EVENTS_PATH_ENV",
    "FAILURE_ITEM_KEY",
    "LWA_PASS_THROUGH_PATH_ENV",
    "BatchHandler",
    "RecordHandler",
    "arrived_through_api_gateway",
    "batch_item_failures",
    "event_records",
    "events_path",
    "record_id",
    "register_stream_consumer",
    "stream_consumer_app",
]

_log = logging.getLogger(__name__)

DEFAULT_EVENTS_PATH: Final = "/events"

EVENTS_PATH_ENV: Final = "IDENTITY_EVENTS_PATH"

LWA_PASS_THROUGH_PATH_ENV: Final = "AWS_LWA_PASS_THROUGH_PATH"

BATCH_FAILURES_KEY: Final = "batchItemFailures"

FAILURE_ITEM_KEY: Final = "itemIdentifier"

type RecordHandler = Callable[[Mapping[str, Any]], None]
"""Handles one stream or queue record, raising to have that record retried."""

type BatchHandler = Callable[[Mapping[str, Any]], Mapping[str, list[dict[str, str]]]]
"""Handles a whole event, returning the batch item failure envelope itself."""

_FastAPIRequest: Any = None


def _bind_fastapi_request() -> None:
    """Put `fastapi.Request` in this module's globals for FastAPI's annotation lookup."""
    global _FastAPIRequest
    if _FastAPIRequest is None:
        from fastapi import Request as _Request

        _FastAPIRequest = _Request


def events_path() -> str:
    """The path the stream route mounts at, absolute and without a trailing slash.

    `IDENTITY_EVENTS_PATH` wins, then `AWS_LWA_PASS_THROUGH_PATH`, which is the adapter's
    own variable and the one that actually decides where the invocation is posted, then
    `/events`, which is the adapter's default.
    """
    for name in (EVENTS_PATH_ENV, LWA_PASS_THROUGH_PATH_ENV):
        raw = os.environ.get(name, "").strip()
        if raw:
            return "/" + raw.strip("/")
    return DEFAULT_EVENTS_PATH


def arrived_through_api_gateway(request: Any) -> bool:
    """Whether this request reached the function through API Gateway rather than the adapter's pass-through.

    The adapter stamps `x-amzn-request-context` on every invocation it forwards. Behind API
    Gateway it is the gateway's request context, a JSON object; on a pass-through it is the
    literal `null`, because there was no HTTP request at the edge to describe. Only a JSON
    object counts, so a bare request id header, which the runtime adds to both, proves nothing.
    """
    from webbpulse.http import REQUEST_CONTEXT_HEADER

    raw = (request.headers.get(REQUEST_CONTEXT_HEADER) or "").strip()
    if not raw:
        return False
    try:
        context = json.loads(raw)
    except ValueError:
        return True
    return isinstance(context, Mapping) and bool(context)


def event_records(event: Any) -> list[Mapping[str, Any]]:
    """The `Records` of one event, or an empty list for anything that is not a batch."""
    if not isinstance(event, Mapping):
        return []
    records = event.get("Records", [])
    if not isinstance(records, Sequence) or isinstance(records, str | bytes):
        return []
    return [record for record in records if isinstance(record, Mapping)]


def record_id(record: Mapping[str, Any]) -> str:
    """The identifier a failed record is reported under.

    `eventID` for a DynamoDB Streams or Kinesis record, `messageId` for an SQS one, which
    is what each source's event source mapping matches against `batchItemFailures`.
    """
    for key in ("eventID", "messageId", "eventId"):
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def batch_item_failures(ids: Sequence[str]) -> dict[str, list[dict[str, str]]]:
    """The `ReportBatchItemFailures` envelope naming the records to retry."""
    return {BATCH_FAILURES_KEY: [{FAILURE_ITEM_KEY: item_id} for item_id in ids]}


def register_stream_consumer(
    router: APIRouter,
    handler: RecordHandler | BatchHandler,
    *,
    path: str | None = None,
    event_names: Collection[str] | None = None,
    per_record: bool = True,
    guard_gateway: bool = True,
    log_event: str = "stream.batch",
) -> None:
    """Mount the POST route that runs `handler` per record with the batch failure envelope.

    `path` defaults to `events_path()`. With `per_record=True`, `handler` is a
    `RecordHandler` called once per record and a raise adds that record to
    `batchItemFailures`; with `per_record=False` it is a `BatchHandler` handed the whole
    event, and whatever envelope it returns is the response. `event_names` filters on the
    record's `eventName`, the way the identity purge takes only `REMOVE`.

    `guard_gateway` is on by default: a consumer is queue and stream only and has no reason
    to answer a gateway request, so one gets a 404 rather than a refusal that would confirm
    the route exists. The route is excluded from the schema either way.
    """
    from fastapi import HTTPException
    from fastapi.responses import JSONResponse

    _bind_fastapi_request()
    route_path = path if path is not None else events_path()
    wanted = frozenset(event_names) if event_names is not None else None

    @router.post(route_path, include_in_schema=False)
    async def consume_events(request: _FastAPIRequest) -> JSONResponse:
        """Run one batch of stream or queue records, reporting per-record failures."""
        if guard_gateway and arrived_through_api_gateway(request):
            raise HTTPException(status_code=404, detail="Not Found.")

        event = await request.json()

        if not per_record:
            batch_handler: BatchHandler = handler  # type: ignore[assignment]
            return JSONResponse(dict(batch_handler(event if isinstance(event, Mapping) else {})))

        record_handler: RecordHandler = handler  # type: ignore[assignment]
        records = event_records(event)
        failures: list[str] = []
        handled = 0

        for record in records:
            if wanted is not None and record.get("eventName") not in wanted:
                continue
            try:
                record_handler(record)
            except Exception:
                _log.exception(
                    "Handling a stream record failed; the event source mapping will retry it.",
                    extra={
                        "event": f"{log_event}.record_failed",
                        "record_id": record_id(record),
                    },
                )
                failures.append(record_id(record))
            else:
                handled += 1

        _log.info(
            "Handled a stream batch.",
            extra={
                "event": log_event,
                "records": len(records),
                "handled": handled,
                "failed": len(failures),
            },
        )
        return JSONResponse(batch_item_failures(failures))


def stream_consumer_app(
    handler: RecordHandler | BatchHandler,
    *,
    title: str,
    path: str | None = None,
    event_names: Collection[str] | None = None,
    per_record: bool = True,
    guard_gateway: bool = True,
    log_event: str = "stream.batch",
    service_name: str = "webbpulse",
    version: str = "0.0.0",
    middleware: Sequence[Any] = (),
    **fastapi_kwargs: Any,
) -> FastAPI:
    """A consumer application: root routes, error handlers, and the events route.

    The shape every consumer entrypoint hand-rolls. No CORS and no rate limiter, neither of
    which applies on the adapter's loopback, and no OpenAPI document, since the one route
    is not part of any API. Each entry of `middleware` is passed to `app.add_middleware`,
    either a class or a `(class, kwargs)` pair.
    """
    from fastapi import APIRouter

    from webbpulse.http import create_app

    fastapi_kwargs.setdefault("openapi_url", None)
    app = create_app(
        title=title,
        version=version,
        service_name=service_name,
        instrument=fastapi_kwargs.pop("instrument", False),
        **fastapi_kwargs,
    )

    for entry in middleware:
        if isinstance(entry, tuple):
            middleware_class, options = entry
            app.add_middleware(middleware_class, **options)
        else:
            app.add_middleware(entry)

    router = APIRouter()
    register_stream_consumer(
        router,
        handler,
        path=path,
        event_names=event_names,
        per_record=per_record,
        guard_gateway=guard_gateway,
        log_event=log_event,
    )
    app.include_router(router)
    return app
