"""Tests for the producing half of `webbpulse.events`.

Covers the envelope's wire shape and its round trip, what `enqueue` sends on a standard
queue against a FIFO one, and `deserialize_image` over the attribute-value shapes a
DynamoDB Streams record actually carries.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest

from webbpulse.events import (
    DEFAULT_EVENT_VERSION,
    EventEnvelope,
    deserialize_image,
    enqueue,
)
from webbpulse.testing import FakeQueue

STANDARD_QUEUE = "https://sqs.us-west-2.amazonaws.com/432410731887/events"

FIFO_QUEUE = "https://sqs.us-west-2.amazonaws.com/432410731887/events.fifo"


def test_an_envelope_defaults_the_identity_and_the_moment() -> None:
    """A producer that supplies neither still emits a deduplicable, ordered event."""
    envelope = EventEnvelope(name="user.deleted", payload={"user_id": "u-1"})

    assert envelope.version == DEFAULT_EVENT_VERSION
    assert envelope.scope is None
    assert envelope.event_id
    assert envelope.occurred_at.tzinfo is not None

    other = EventEnvelope(name="user.deleted", payload={"user_id": "u-1"})
    assert other.event_id != envelope.event_id


def test_the_wire_shape_is_sorted_compact_and_utc() -> None:
    """`to_json` is the reproducible body a signature or a dedup id can be taken over."""
    envelope = EventEnvelope(
        name="post.created",
        payload={"b": 2, "a": 1},
        scope="ws-1",
        occurred_at=datetime(2026, 9, 17, 12, 30, tzinfo=UTC),
        event_id="evt-1",
    )

    body = envelope.to_json()
    assert body == json.dumps(json.loads(body), separators=(",", ":"), sort_keys=True)
    assert ", " not in body

    decoded = json.loads(body)
    assert decoded["occurred_at"] == "2026-09-17T12:30:00Z"
    assert decoded["scope"] == "ws-1"
    assert decoded["payload"] == {"a": 1, "b": 2}


def test_an_unscoped_event_omits_the_scope_rather_than_sending_null() -> None:
    """`"scope" in body` reads as "this event names a tenant", which null would break."""
    body = EventEnvelope(name="system.rebooted", payload={}).to_dict()

    assert "scope" not in body


def test_an_envelope_round_trips_through_its_dict() -> None:
    """What a consumer reads back is what the producer sent."""
    original = EventEnvelope(
        name="user.invited",
        payload={"email": "a@example.com"},
        version=2,
        scope="ws-9",
        occurred_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        event_id="evt-7",
    )

    restored = EventEnvelope.from_dict(original.to_dict())

    assert restored == original


@pytest.mark.parametrize("occurred_at", [None, "", "not-a-timestamp", 17])
def test_an_unreadable_timestamp_becomes_now_rather_than_raising(occurred_at: Any) -> None:
    """A consumer that cannot read the timestamp should still handle the event."""
    restored = EventEnvelope.from_dict({"name": "x", "payload": {}, "occurred_at": occurred_at})

    assert restored.occurred_at.tzinfo is not None


def test_a_non_mapping_payload_reads_back_as_empty() -> None:
    """A malformed body does not hand a consumer a payload it cannot index."""
    restored = EventEnvelope.from_dict({"name": "x", "payload": ["not", "a", "mapping"]})

    assert restored.payload == {}


def test_a_standard_queue_sends_no_fifo_arguments() -> None:
    """SQS rejects a group or a dedup id outright on a standard queue."""
    queue = FakeQueue()

    result = enqueue(
        STANDARD_QUEUE,
        EventEnvelope(name="user.deleted", payload={"user_id": "u-1"}, scope="ws-1"),
        client=queue,
    )

    request = queue.requests[0]
    assert request["QueueUrl"] == STANDARD_QUEUE
    assert "MessageGroupId" not in request
    assert "MessageDeduplicationId" not in request
    assert result.message_id == "msg-1"
    assert queue.last_body["name"] == "user.deleted"


def test_a_fifo_queue_groups_on_the_scope_and_dedups_on_the_event_id() -> None:
    """One tenant's ordering stays independent, and a retried send is deduplicated."""
    queue = FakeQueue()
    envelope = EventEnvelope(name="user.deleted", payload={}, scope="ws-1", event_id="evt-1")

    result = enqueue(FIFO_QUEUE, envelope, client=queue)

    request = queue.requests[0]
    assert request["MessageGroupId"] == "ws-1"
    assert request["MessageDeduplicationId"] == "evt-1"
    assert result.event_id == "evt-1"


def test_explicit_fifo_arguments_win_over_the_envelope() -> None:
    """A producer that groups on something other than the tenant can say so."""
    queue = FakeQueue()
    envelope = EventEnvelope(name="user.deleted", payload={}, scope="ws-1", event_id="evt-1")

    enqueue(FIFO_QUEUE, envelope, client=queue, group_id="shard-3", dedup_id="dedup-9")

    request = queue.requests[0]
    assert request["MessageGroupId"] == "shard-3"
    assert request["MessageDeduplicationId"] == "dedup-9"


def test_a_fifo_send_without_a_scope_omits_the_group() -> None:
    """An ungrouped FIFO send is the caller's problem to name, not a group of empty string."""
    queue = FakeQueue()

    enqueue(FIFO_QUEUE, EventEnvelope(name="x", payload={}, event_id="evt-2"), client=queue)

    assert "MessageGroupId" not in queue.requests[0]
    assert queue.requests[0]["MessageDeduplicationId"] == "evt-2"


def test_a_bare_mapping_is_wrapped_in_an_envelope() -> None:
    """A producer with no event name still sends the envelope shape a consumer reads."""
    queue = FakeQueue()

    enqueue(STANDARD_QUEUE, {"user_id": "u-1"}, client=queue)

    body = queue.last_body
    assert body["payload"] == {"user_id": "u-1"}
    assert body["name"] == ""
    assert body["event_id"]


def test_the_optional_send_arguments_reach_sqs() -> None:
    """A delay and message attributes are passed through in SQS's own spelling."""
    queue = FakeQueue()

    enqueue(
        STANDARD_QUEUE,
        EventEnvelope(name="x", payload={}),
        client=queue,
        delay_seconds=30,
        attributes={"tenant": "ws-1"},
    )

    request = queue.requests[0]
    assert request["DelaySeconds"] == 30
    assert request["MessageAttributes"] == {"tenant": {"DataType": "String", "StringValue": "ws-1"}}


def test_a_failing_send_raises_for_the_producer_to_handle() -> None:
    """`enqueue` does not swallow an SQS failure; a producer decides what it means."""
    queue = FakeQueue(failing=1)

    with pytest.raises(RuntimeError):
        enqueue(STANDARD_QUEUE, EventEnvelope(name="x", payload={}), client=queue)

    assert len(queue.requests) == 1


def test_an_image_comes_back_as_plain_python_values() -> None:
    """The attribute-value shape is unwrapped exactly as a boto3 resource read would."""
    record = {
        "eventName": "MODIFY",
        "dynamodb": {
            "NewImage": {
                "id": {"S": "u-1"},
                "count": {"N": "3"},
                "active": {"BOOL": True},
                "tags": {"SS": ["a", "b"]},
                "profile": {"M": {"name": {"S": "Ada"}}},
                "scores": {"L": [{"N": "1"}, {"N": "2"}]},
                "deleted_at": {"NULL": True},
            }
        },
    }

    item = deserialize_image(record)

    assert item["id"] == "u-1"
    assert item["count"] == Decimal("3")
    assert item["active"] is True
    assert item["tags"] == {"a", "b"}
    assert item["profile"] == {"name": "Ada"}
    assert item["scores"] == [Decimal("1"), Decimal("2")]
    assert item["deleted_at"] is None


def test_the_old_image_is_selectable() -> None:
    """A `REMOVE` consumer reads the row that was deleted, not the one that was not written."""
    record = {
        "eventName": "REMOVE",
        "dynamodb": {"OldImage": {"id": {"S": "u-1"}, "email": {"S": "a@example.com"}}},
    }

    assert deserialize_image(record, "OldImage") == {"id": "u-1", "email": "a@example.com"}
    assert deserialize_image(record, "NewImage") == {}


@pytest.mark.parametrize(
    "record",
    [
        {},
        {"dynamodb": None},
        {"dynamodb": {}},
        {"dynamodb": {"NewImage": None}},
        {"dynamodb": "not-a-mapping"},
    ],
)
def test_a_missing_image_is_an_empty_mapping_not_an_error(record: Any) -> None:
    """A `REMOVE` asked for its `NewImage` is a shape, not a failure."""
    assert deserialize_image(record) == {}
