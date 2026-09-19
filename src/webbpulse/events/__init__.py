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

The producing side lives here too: `EventEnvelope` is the shape a domain event is published
in and `enqueue` puts one on an SQS queue. `deserialize_image` reads a DynamoDB Streams
record image back into plain Python values, `source_table` says which table a record came
from, for a consumer reading more than one stream, and `record_sequence` reads the sequence
number a consumer orders and dedupes on.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final, Literal, Protocol

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import APIRouter, FastAPI

__all__ = [
    "APP_EVENTS_PATH_ENV",
    "BATCH_FAILURES_KEY",
    "DEFAULT_EVENTS_PATH",
    "DEFAULT_EVENT_VERSION",
    "EVENTS_PATH_ENV",
    "FAILURE_ITEM_KEY",
    "LWA_PASS_THROUGH_PATH_ENV",
    "BatchHandler",
    "EnqueueResult",
    "EventEnvelope",
    "ImageName",
    "QueueClient",
    "RecordHandler",
    "arrived_through_api_gateway",
    "batch_item_failures",
    "deserialize_image",
    "enqueue",
    "event_records",
    "events_path",
    "record_id",
    "record_sequence",
    "register_stream_consumer",
    "source_table",
    "stream_consumer_app",
]

_log = logging.getLogger(__name__)

DEFAULT_EVENTS_PATH: Final = "/events"

EVENTS_PATH_ENV: Final = "IDENTITY_EVENTS_PATH"

APP_EVENTS_PATH_ENV: Final = "APP_EVENTS_PATH"

LWA_PASS_THROUGH_PATH_ENV: Final = "AWS_LWA_PASS_THROUGH_PATH"

BATCH_FAILURES_KEY: Final = "batchItemFailures"

FAILURE_ITEM_KEY: Final = "itemIdentifier"

type RecordHandler = Callable[[Mapping[str, Any]], None]
"""Handles one stream or queue record, raising to have that record retried."""

type BatchHandler = Callable[[Mapping[str, Any]], Mapping[str, list[dict[str, str]]]]
"""Handles a whole event, returning the batch item failure envelope itself."""

type ImageName = Literal["NewImage", "OldImage"]
"""Which side of a DynamoDB Streams record to read, the one after or the one before."""

DEFAULT_EVENT_VERSION: Final = 1


class QueueClient(Protocol):
    """The one SQS call `enqueue` makes.

    A Protocol, so a boto3 SQS client and `webbpulse.testing.FakeQueue` both satisfy it
    without inheritance.
    """

    def send_message(self, **kwargs: Any) -> Mapping[str, Any]:
        """Send one message, returning at least `MessageId`."""
        ...


@dataclass(frozen=True, slots=True)
class EventEnvelope:
    """One domain event, in the shape every consumer can read without knowing the producer.

    `name` is the dotted event name, such as `"user.deleted"`, and `version` is that name's
    schema version, so a consumer can refuse a payload it was not written for. `scope` is the
    workspace or tenant the event belongs to and is what a FIFO queue groups on by default,
    which keeps one tenant's ordering independent of another's. `occurred_at` defaults to now
    in UTC and `event_id` to a fresh uuid4, so a producer that supplies neither still emits a
    deduplicable, ordered event.
    """

    name: str
    payload: Mapping[str, Any]
    version: int = DEFAULT_EVENT_VERSION
    scope: str | None = None
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict[str, Any]:
        """The JSON-ready mapping, with `occurred_at` as an RFC 3339 string in UTC.

        `scope` is omitted rather than sent as null when the event is not tenant scoped, so a
        consumer's `"scope" in body` reads as "this event names a tenant".
        """
        body: dict[str, Any] = {
            "event_id": self.event_id,
            "name": self.name,
            "version": self.version,
            "occurred_at": _rfc3339(self.occurred_at),
            "payload": dict(self.payload),
        }
        if self.scope is not None:
            body["scope"] = self.scope
        return body

    def to_json(self) -> str:
        """The message body `enqueue` sends, compact and with sorted keys."""
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_dict(cls, body: Mapping[str, Any]) -> EventEnvelope:
        """Read an envelope back from a received message body.

        A missing `occurred_at`, or one that does not parse, becomes now rather than raising:
        a consumer that cannot read the timestamp should still handle the event.
        """
        raw_payload = body.get("payload")
        return cls(
            name=str(body.get("name", "")),
            payload=raw_payload if isinstance(raw_payload, Mapping) else {},
            version=int(body.get("version", DEFAULT_EVENT_VERSION)),
            scope=body["scope"] if isinstance(body.get("scope"), str) else None,
            occurred_at=_parse_rfc3339(body.get("occurred_at")),
            event_id=str(body.get("event_id") or uuid.uuid4()),
        )


@dataclass(frozen=True, slots=True)
class EnqueueResult:
    """What SQS answered for one sent message."""

    message_id: str
    event_id: str


def _rfc3339(moment: datetime) -> str:
    """`moment` as an RFC 3339 string in UTC, with a `Z` rather than `+00:00`."""
    aware = moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)
    return aware.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_rfc3339(raw: Any) -> datetime:
    """Read an RFC 3339 string into an aware UTC datetime, falling back to now."""
    if isinstance(raw, str) and raw:
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(UTC)
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
    return datetime.now(UTC)


def enqueue(
    queue_url: str,
    payload: EventEnvelope | Mapping[str, Any],
    *,
    client: QueueClient | None = None,
    group_id: str | None = None,
    dedup_id: str | None = None,
    delay_seconds: int | None = None,
    attributes: Mapping[str, str] | None = None,
) -> EnqueueResult:
    """Put one event on `queue_url` and return what SQS answered.

    `payload` is an `EventEnvelope` or the mapping to wrap in one. On a FIFO queue, which is
    a `queue_url` ending in `.fifo`, `group_id` defaults to the envelope's `scope` and
    `dedup_id` to its `event_id`, so a retried send of the same envelope is deduplicated and
    one tenant's events stay ordered among themselves. Both are sent only on a FIFO queue,
    which rejects them outright on a standard one.

    `client` is the SQS client to send through; it is built on first use when omitted, so
    importing this module needs no boto3 and no credentials.
    """
    envelope = payload if isinstance(payload, EventEnvelope) else EventEnvelope(name="", payload=payload)
    sqs = client if client is not None else _sqs_client()

    request: dict[str, Any] = {"QueueUrl": queue_url, "MessageBody": envelope.to_json()}
    if queue_url.endswith(".fifo"):
        group = group_id if group_id is not None else envelope.scope
        if group:
            request["MessageGroupId"] = group
        request["MessageDeduplicationId"] = dedup_id if dedup_id is not None else envelope.event_id
    if delay_seconds is not None:
        request["DelaySeconds"] = delay_seconds
    if attributes:
        request["MessageAttributes"] = {
            key: {"DataType": "String", "StringValue": value} for key, value in attributes.items()
        }

    response = sqs.send_message(**request)
    message_id = str(response.get("MessageId", ""))
    _log.info(
        "Enqueued an event.",
        extra={
            "event": "events.enqueued",
            "event_name": envelope.name,
            "event_id": envelope.event_id,
            "message_id": message_id,
        },
    )
    return EnqueueResult(message_id=message_id, event_id=envelope.event_id)


def _sqs_client() -> Any:
    """An SQS client built on demand, never at import time."""
    import boto3

    return boto3.client("sqs")


def deserialize_image(record: Mapping[str, Any], image: ImageName = "NewImage") -> dict[str, Any]:
    """One DynamoDB Streams record image as plain Python values.

    A stream record carries its item in DynamoDB's attribute-value shape, `{"id": {"S": "u-1"}}`,
    which every consumer otherwise unwraps by hand. This runs botocore's own `TypeDeserializer`
    over it, so numbers come back as `Decimal` and sets as `set`, exactly as a boto3 resource
    read of the same item would. A record with no such image, which is a `REMOVE` asked for its
    `NewImage`, is an empty mapping rather than an error, since that is a shape and not a failure.
    """
    from boto3.dynamodb.types import TypeDeserializer

    section = record.get("dynamodb")
    if not isinstance(section, Mapping):
        return {}
    raw = section.get(image)
    if not isinstance(raw, Mapping):
        return {}
    deserializer = TypeDeserializer()
    return {key: deserializer.deserialize(value) for key, value in raw.items()}


def record_sequence(record: Mapping[str, Any]) -> int:
    """The `dynamodb.SequenceNumber` of one DynamoDB Streams record, as an integer.

    A stream orders the records for one partition key by this number and it only ever
    increases within that key, so it is what a consumer compares to order two changes to one
    item and to drop a redelivery: an event source mapping retries a whole batch, so a
    handler sees the same record again and can skip it by storing the highest sequence it
    has applied per item and ignoring anything at or below it.

    The stream carries the value as a decimal string, and one far exceeds 64 bits, which is
    why it comes back as a Python `int` rather than a float or the raw string: `int` is
    arbitrary precision so the comparison is exact, while string comparison would order
    `"100"` before `"99"` and a float would lose the low digits.

    Ordering holds only within one partition key. Two records for different items carry
    comparable numbers that mean nothing across items, so this is for per-item ordering and
    never for a global sequence.

    Args:
        record: One record from a DynamoDB Streams batch.

    Returns:
        The sequence number.

    Raises:
        ValueError: When the record carries no `dynamodb.SequenceNumber`, or one that is not
            a decimal integer. A consumer deduping on the sequence cannot place a record
            without one, and treating a missing number as zero would replay every record it
            had already applied.
    """
    section = record.get("dynamodb")
    if not isinstance(section, Mapping):
        raise ValueError("The record carries no dynamodb section, so it has no sequence number.")

    raw = section.get("SequenceNumber")
    if not isinstance(raw, str | int) or isinstance(raw, bool):
        raise ValueError(f"The record's SequenceNumber is not a number: {raw!r}")

    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"The record's SequenceNumber is not a decimal integer: {raw!r}") from exc


def source_table(record: Mapping[str, Any]) -> str:
    """The table name a DynamoDB Streams record came from, read off its `eventSourceARN`.

    One consumer behind two streams gets both tables' records on one route, and the record
    itself says which table only in its source ARN, which every such consumer otherwise
    splits by hand. The ARN is
    `arn:aws:dynamodb:<region>:<account>:table/<name>/stream/<label>`, and the name is the
    segment after `table/`.

    The name comes back as the stream carries it, which is the physical table name and so
    still prefixed: matching it against `webbpulse.dynamodb.table_name("views")` rather than
    against `"views"` is what keeps a consumer working across environments.

    Args:
        record: One record from a DynamoDB Streams batch.

    Raises:
        ValueError: When the record carries no `eventSourceARN`, or one that is not a
            DynamoDB stream ARN. A consumer discriminating on the table cannot do anything
            useful with a record it cannot place, and guessing a table would route the record
            to the wrong handler, so this refuses rather than returning an empty string.
    """
    raw = record.get("eventSourceARN")
    if not isinstance(raw, str) or not raw:
        raise ValueError("The record carries no eventSourceARN, so it names no table.")

    prefix, separator, remainder = raw.partition(":table/")
    if not separator or not prefix.startswith("arn:") or ":dynamodb:" not in prefix:
        raise ValueError(f"Not a DynamoDB stream ARN, so it names no table: {raw!r}")

    name = remainder.partition("/")[0]
    if not name:
        raise ValueError(f"The stream ARN names an empty table: {raw!r}")
    return name


_FastAPIRequest: Any = None


def _bind_fastapi_request() -> None:
    """Put `fastapi.Request` in this module's globals for FastAPI's annotation lookup."""
    global _FastAPIRequest
    if _FastAPIRequest is None:
        from fastapi import Request as _Request

        _FastAPIRequest = _Request


def events_path() -> str:
    """The path the stream route mounts at, absolute and without a trailing slash.

    `IDENTITY_EVENTS_PATH` wins, then `APP_EVENTS_PATH`, then `AWS_LWA_PASS_THROUGH_PATH`,
    which is the adapter's own variable and the one that actually decides where the
    invocation is posted, then `/events`, which is the adapter's default.

    `APP_EVENTS_PATH` is the application-facing half of the pair the `lambda-function`
    module emits for a wired `sqs_event_sources` or `dynamodb_stream_event_sources`: one
    `events_path` input reaches the function as both variables, the adapter reading one and
    the application the other, so they cannot drift apart. Reading it rather than only the
    adapter's variable is what keeps that promise on this side, and since both come from one
    input they agree whichever is consulted first.
    """
    for name in (EVENTS_PATH_ENV, APP_EVENTS_PATH_ENV, LWA_PASS_THROUGH_PATH_ENV):
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
