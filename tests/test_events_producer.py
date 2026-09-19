"""Tests for the producing half of `webbpulse.events`.

Covers the envelope's wire shape and its round trip, what `enqueue` sends on a standard
queue against a FIFO one, `deserialize_image` over the attribute-value shapes a DynamoDB
Streams record actually carries, `source_table` over the ARNs it carries them under, and
`record_sequence` over the numbers a consumer orders and dedupes on.
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
    record_sequence,
    source_table,
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


VIEWS_STREAM_ARN = (
    "arn:aws:dynamodb:us-west-2:432410731887:table/webbpulse-staging-views/stream/2026-09-17T00:00:00.000"
)

ISSUES_STREAM_ARN = (
    "arn:aws:dynamodb:us-west-2:432410731887:table/webbpulse-staging-issues/stream/2026-09-17T00:00:00.000"
)


def test_the_table_name_comes_off_the_stream_arn() -> None:
    """The segment after `table/` is the name, and the stream label after it is not part of it."""
    assert source_table({"eventSourceARN": VIEWS_STREAM_ARN}) == "webbpulse-staging-views"


def test_two_streams_on_one_route_are_told_apart() -> None:
    """The reason the helper exists: one consumer behind two streams discriminates on this."""
    records = [{"eventSourceARN": VIEWS_STREAM_ARN}, {"eventSourceARN": ISSUES_STREAM_ARN}]

    assert [source_table(record) for record in records] == [
        "webbpulse-staging-views",
        "webbpulse-staging-issues",
    ]


def test_the_name_comes_back_prefixed_as_the_stream_carries_it() -> None:
    """The physical table name, so a consumer matches it against `table_name(...)` and not a logical one."""
    assert source_table({"eventSourceARN": VIEWS_STREAM_ARN}).startswith("webbpulse-staging-")


def test_a_record_with_no_source_arn_is_refused() -> None:
    """A record that names no table cannot be routed, and guessing one would route it wrongly."""
    with pytest.raises(ValueError, match="no eventSourceARN"):
        source_table({"eventName": "INSERT"})


@pytest.mark.parametrize(
    "arn",
    [
        "arn:aws:sqs:us-west-2:432410731887:events",
        "arn:aws:dynamodb:us-west-2:432410731887:stream/2026-09-17T00:00:00.000",
        "webbpulse-staging-views",
        "table/webbpulse-staging-views",
        "",
    ],
)
def test_anything_that_is_not_a_dynamodb_stream_arn_is_refused(arn: str) -> None:
    """An SQS ARN, a truncated one and a bare name each raise rather than yielding a guess."""
    with pytest.raises(ValueError):
        source_table({"eventSourceARN": arn})


@pytest.mark.parametrize("value", [None, 123, ["arn"]])
def test_a_non_string_source_arn_is_refused(value: Any) -> None:
    """A malformed record raises rather than being parsed as whatever it happens to be."""
    with pytest.raises(ValueError, match="no eventSourceARN"):
        source_table({"eventSourceARN": value})


def test_an_arn_naming_an_empty_table_is_refused() -> None:
    """`table//stream/...` names nothing, so it is a failure rather than an empty string."""
    with pytest.raises(ValueError, match="empty table"):
        source_table({"eventSourceARN": "arn:aws:dynamodb:us-west-2:432410731887:table//stream/2026"})


def test_a_sequence_number_comes_back_as_an_integer() -> None:
    """The stream carries a decimal string and this returns the `int` a comparison needs."""
    assert record_sequence({"dynamodb": {"SequenceNumber": "100000000000000000001"}}) == 100000000000000000001


def test_a_sequence_number_beyond_64_bits_keeps_every_digit() -> None:
    """Python `int` is arbitrary precision, so a long stream number is exact and not rounded."""
    raw = "1" + "0" * 40 + "7"
    assert record_sequence({"dynamodb": {"SequenceNumber": raw}}) == int(raw)


def test_sequence_numbers_order_numerically_rather_than_lexically() -> None:
    """`"100"` is after `"99"` as an integer, which is the ordering bug this call removes."""
    later = record_sequence({"dynamodb": {"SequenceNumber": "100"}})
    earlier = record_sequence({"dynamodb": {"SequenceNumber": "99"}})
    assert later > earlier


def test_an_already_applied_record_is_recognised_by_its_sequence() -> None:
    """A redelivered record carries the same number, so a consumer can skip it."""
    record = {"eventID": "e-1", "dynamodb": {"SequenceNumber": "42"}}
    assert record_sequence(record) == record_sequence(dict(record))


def test_a_record_with_no_dynamodb_section_is_refused() -> None:
    """An SQS record has no sequence number, and zero would replay everything already applied."""
    with pytest.raises(ValueError, match="no dynamodb section"):
        record_sequence({"messageId": "m-1"})


def test_a_record_with_no_sequence_number_is_refused() -> None:
    """A DynamoDB section missing the number is a malformed record rather than a zero."""
    with pytest.raises(ValueError, match="not a number"):
        record_sequence({"dynamodb": {"Keys": {}}})


@pytest.mark.parametrize("value", [None, ["1"], {"N": "1"}, True])
def test_a_non_numeric_sequence_number_is_refused(value: Any) -> None:
    """Anything that is not a string or an integer raises, including a bool masquerading as one."""
    with pytest.raises(ValueError, match="not a number"):
        record_sequence({"dynamodb": {"SequenceNumber": value}})


def test_a_sequence_number_that_is_not_decimal_is_refused() -> None:
    """A string that is not a decimal integer raises rather than becoming a partial parse."""
    with pytest.raises(ValueError, match="not a decimal integer"):
        record_sequence({"dynamodb": {"SequenceNumber": "12ab"}})


def test_an_integer_sequence_number_is_accepted() -> None:
    """A hand-built test record may carry an `int`, and that is the same number."""
    assert record_sequence({"dynamodb": {"SequenceNumber": 42}}) == 42


def test_the_sequence_sits_beside_the_image_on_one_record() -> None:
    """One record answers both calls, which is what a consumer reads together."""
    record = {
        "eventName": "MODIFY",
        "dynamodb": {"SequenceNumber": "7", "NewImage": {"id": {"S": "i-1"}}},
    }
    assert record_sequence(record) == 7
    assert deserialize_image(record) == {"id": "i-1"}
