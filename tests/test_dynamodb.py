"""Tests for the DynamoDB repository base.

The moto-backed tests build a repository with `endpoint_url=None` and rely on the
`dynamodb_resource` fixture having cleared the cached boto3 resource, so the repository
resolves its table inside the mock rather than against a real account.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

from webbpulse.dynamodb import (
    TABLE_PREFIX_ENV,
    Page,
    Repository,
    encode_numbers,
    now_iso,
    table_name,
    ttl_at,
    ttl_in,
)
from webbpulse.testing import create_table

# Epoch seconds are ~1.7e9 today; epoch milliseconds are ~1.7e12. Anything at or above this
# bound is the milliseconds mistake the `ttl_at` docstring warns about.
_MILLISECONDS_MAGNITUDE = 1_000_000_000_000


def test_now_iso_ends_with_z_and_parses() -> None:
    value = now_iso()
    assert value.endswith("Z"), f"now_iso must normalise the offset to Z, got {value!r}"
    assert "+00:00" not in value, f"the +00:00 offset must be replaced, got {value!r}"

    parsed = datetime.fromisoformat(value)
    assert parsed.tzinfo is not None, "the parsed timestamp must stay timezone aware"
    assert parsed.utcoffset() == timedelta(0), "the parsed timestamp must be UTC"


def test_now_iso_has_second_precision() -> None:
    # timespec="seconds" is what keeps the range key sortable at a fixed width.
    assert "." not in now_iso(), "now_iso must not emit fractional seconds"


def test_ttl_at_rejects_a_naive_datetime() -> None:
    with pytest.raises(ValueError, match="aware datetime"):
        ttl_at(datetime(2026, 1, 1, 12, 0, 0))  # noqa: DTZ001 - naive on purpose


def test_ttl_at_returns_epoch_seconds_not_milliseconds() -> None:
    moment = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
    value = ttl_at(moment)

    assert isinstance(value, int), "a DynamoDB TTL must be an integer Number"
    assert value == 1767225600, f"2026-01-01T00:00:00Z is 1767225600 epoch seconds, got {value}"
    assert value < _MILLISECONDS_MAGNITUDE, (
        f"ttl_at must return seconds (~1e9), not milliseconds (~1e12); got {value}"
    )


def test_ttl_at_truncates_toward_zero() -> None:
    moment = datetime(2026, 1, 1, 0, 0, 0, 999_999, tzinfo=UTC)
    assert ttl_at(moment) == 1767225600, "sub-second precision must be dropped, not rounded up"


def test_ttl_in_is_roughly_now_plus_the_offset() -> None:
    before = int(datetime.now(UTC).timestamp())
    value = ttl_in(3600)
    after = int(datetime.now(UTC).timestamp())

    assert before + 3600 <= value <= after + 3600, (
        f"ttl_in(3600) must land an hour ahead; got {value} against a now of {before}..{after}"
    )
    assert value < _MILLISECONDS_MAGNITUDE, "ttl_in must return seconds, not milliseconds"


def test_ttl_in_accepts_a_negative_offset() -> None:
    # Backdating is legitimate: it is how a caller writes an already-expired item.
    assert ttl_in(-60) < int(datetime.now(UTC).timestamp())


def test_table_name_with_an_explicit_prefix() -> None:
    assert table_name("rate-limits", "webbpulse-staging") == "webbpulse-staging-rate-limits"


def test_table_name_with_an_explicit_empty_prefix_ignores_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An explicit "" must win over the environment; that is the local and moto case.
    monkeypatch.setenv(TABLE_PREFIX_ENV, "webbpulse-prod")
    assert table_name("rate-limits", "") == "rate-limits"


def test_table_name_reads_the_environment_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(TABLE_PREFIX_ENV, "webbpulse-staging")
    assert table_name("rate-limits") == "webbpulse-staging-rate-limits"


def test_table_name_without_any_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(TABLE_PREFIX_ENV, raising=False)
    assert table_name("rate-limits") == "rate-limits"


def test_encode_numbers_converts_float_via_str() -> None:
    # Decimal(0.1) is 0.1000000000000000055511151231257827; Decimal("0.1") is exactly 0.1.
    result = encode_numbers(0.1)
    assert result == Decimal("0.1"), f"the conversion must go via str; got {result!r}"
    assert result != Decimal(0.1), "Decimal(float) would carry the binary float error"


def test_encode_numbers_recurses_into_dicts_and_lists() -> None:
    encoded = encode_numbers({"a": 0.1, "b": [0.2, {"c": 0.3}], "d": (0.4,)})

    assert encoded == {
        "a": Decimal("0.1"),
        "b": [Decimal("0.2"), {"c": Decimal("0.3")}],
        "d": [Decimal("0.4")],
    }
    # A tuple becomes a list because DynamoDB has no tuple type.
    assert isinstance(encoded["d"], list)


def test_encode_numbers_leaves_str_bytes_and_int_alone() -> None:
    # str and bytes are Sequences, so a naive recursion would explode them into characters.
    assert encode_numbers("0.1") == "0.1"
    assert encode_numbers(b"bytes") == b"bytes"
    assert encode_numbers(7) == 7
    assert isinstance(encode_numbers(7), int), "an int must not be widened to Decimal"
    assert encode_numbers(None) is None
    assert encode_numbers(True) is True


def test_encode_numbers_leaves_an_existing_decimal_alone() -> None:
    value = Decimal("1.25")
    assert encode_numbers(value) is value


def test_page_has_more_follows_the_cursor() -> None:
    exhausted = Page(items=[{"pk": "a"}], last_evaluated_key=None, count=1, scanned_count=1)
    assert exhausted.has_more is False

    # An empty page with a cursor is normal after a FilterExpression and is not the end.
    more = Page(items=[], last_evaluated_key={"pk": "a"}, count=0, scanned_count=10)
    assert more.has_more is True, "an empty page with a cursor still has more to come"


def test_page_repr_is_readable() -> None:
    page = Page(items=[{"pk": "a"}], last_evaluated_key=None, count=1, scanned_count=2)
    assert "has_more=False" in repr(page)


def test_repository_requires_a_logical_name() -> None:
    with pytest.raises(ValueError, match="logical table name"):
        Repository()


def test_repository_takes_the_logical_name_from_the_class() -> None:
    class Widgets(Repository):
        logical_name = "widgets"

    assert Widgets(prefix="webbpulse-staging").table_name == "webbpulse-staging-widgets"


def test_repository_argument_overrides_the_class_attribute() -> None:
    class Widgets(Repository):
        logical_name = "widgets"

    assert Widgets("gadgets", prefix="").table_name == "gadgets"


@pytest.fixture
def items_repo(dynamodb_resource: Any) -> Repository:
    """A repository over a hash-only `items` table inside the moto mock."""
    create_table(dynamodb_resource, "items")
    return Repository("items", prefix="", region_name="us-west-2")


@pytest.fixture
def events_repo(dynamodb_resource: Any) -> Repository:
    """A repository over an `events` table with a range key, for pagination tests."""
    create_table(dynamodb_resource, "events", range_key="sk")
    return Repository("events", prefix="", region_name="us-west-2")


def test_put_get_update_delete_round_trip(items_repo: Repository) -> None:
    items_repo.put({"pk": "widget-1", "name": "Widget", "price": 9.99})

    fetched = items_repo.get({"pk": "widget-1"})
    assert fetched is not None, "the item just written must be readable"
    assert fetched["name"] == "Widget"
    assert fetched["price"] == Decimal("9.99"), "the float must have been stored as a Decimal"

    updated = items_repo.update(
        {"pk": "widget-1"},
        update_expression="SET #n = :n",
        # `name` is a DynamoDB reserved word, which is why the alias is not optional here.
        expression_names={"#n": "name"},
        expression_values={":n": "Renamed"},
        return_values="ALL_NEW",
    )
    assert updated is not None
    assert updated["name"] == "Renamed"

    items_repo.delete({"pk": "widget-1"})
    assert items_repo.get({"pk": "widget-1"}) is None


def test_get_returns_none_for_a_missing_item(items_repo: Repository) -> None:
    assert items_repo.get({"pk": "does-not-exist"}) is None


def test_get_with_a_consistent_read(items_repo: Repository) -> None:
    items_repo.put({"pk": "widget-1", "name": "Widget"})
    fetched = items_repo.get({"pk": "widget-1"}, consistent=True)
    assert fetched is not None


def test_update_returning_none_when_no_values_are_requested(items_repo: Repository) -> None:
    items_repo.put({"pk": "counter", "count": 0})
    assert items_repo.update(
        {"pk": "counter"},
        update_expression="ADD #c :one",
        expression_names={"#c": "count"},
        expression_values={":one": 1},
    ) is None, "ReturnValues=NONE must yield None rather than an empty dict"


def test_delete_of_an_absent_item_is_not_an_error(items_repo: Repository) -> None:
    items_repo.delete({"pk": "never-existed"})


def test_put_with_a_condition_raises_on_a_duplicate(items_repo: Repository) -> None:
    items_repo.put({"pk": "unique-1", "name": "First"}, condition=Attr("pk").not_exists())

    with pytest.raises(ClientError) as excinfo:
        items_repo.put({"pk": "unique-1", "name": "Second"}, condition=Attr("pk").not_exists())

    assert excinfo.value.response["Error"]["Code"] == "ConditionalCheckFailedException"

    # The failed write must not have clobbered the original.
    existing = items_repo.get({"pk": "unique-1"})
    assert existing is not None
    assert existing["name"] == "First"


def test_delete_with_a_failing_condition_raises(items_repo: Repository) -> None:
    items_repo.put({"pk": "guarded", "state": "locked"})
    with pytest.raises(ClientError):
        items_repo.delete({"pk": "guarded"}, condition=Attr("state").eq("unlocked"))
    assert items_repo.get({"pk": "guarded"}) is not None


def test_put_many_writes_every_item(items_repo: Repository) -> None:
    items_repo.put_many([{"pk": f"bulk-{i}", "index": i, "ratio": i / 4} for i in range(30)])

    first = items_repo.get({"pk": "bulk-0"})
    last = items_repo.get({"pk": "bulk-29"})
    assert first is not None and last is not None, "put_many must write across batch chunks"
    assert last["ratio"] == Decimal("7.25"), "put_many must encode floats like put does"


def test_put_many_with_no_items_is_a_no_op(items_repo: Repository) -> None:
    items_repo.put_many([])


def _seed_events(repo: Repository, count: int = 15) -> None:
    repo.put_many([{"pk": "session-1", "sk": f"{i:04d}", "index": i} for i in range(count)])


def test_query_returns_one_page_and_a_cursor(events_repo: Repository) -> None:
    _seed_events(events_repo)

    page = events_repo.query(Key("pk").eq("session-1"), limit=5)
    assert len(page.items) == 5
    assert page.count == 5
    assert page.has_more is True, "15 items at a limit of 5 must leave a cursor"
    assert [item["sk"] for item in page.items] == ["0000", "0001", "0002", "0003", "0004"]


def test_query_descending_and_projection(events_repo: Repository) -> None:
    _seed_events(events_repo)

    page = events_repo.query(
        Key("pk").eq("session-1"), limit=3, ascending=False, projection="sk"
    )
    assert [item["sk"] for item in page.items] == ["0014", "0013", "0012"]
    assert set(page.items[0]) == {"sk"}, "a projection must limit the attributes returned"


def test_query_follows_an_explicit_start_key(events_repo: Repository) -> None:
    _seed_events(events_repo)

    first = events_repo.query(Key("pk").eq("session-1"), limit=5)
    second = events_repo.query(
        Key("pk").eq("session-1"), limit=5, start_key=first.last_evaluated_key
    )
    assert [item["sk"] for item in second.items] == ["0005", "0006", "0007", "0008", "0009"]


def test_query_for_a_missing_partition_is_empty(events_repo: Repository) -> None:
    _seed_events(events_repo)
    page = events_repo.query(Key("pk").eq("session-absent"))
    assert page.items == []
    assert page.has_more is False


def test_iter_query_walks_every_page(events_repo: Repository) -> None:
    _seed_events(events_repo)

    collected = list(events_repo.iter_query(Key("pk").eq("session-1"), page_size=5))
    assert len(collected) == 15, "iter_query must follow LastEvaluatedKey across all 3 pages"
    assert [item["sk"] for item in collected] == [f"{i:04d}" for i in range(15)]


def test_iter_query_bounds_the_result_with_max_items(events_repo: Repository) -> None:
    _seed_events(events_repo)

    collected = list(events_repo.iter_query(Key("pk").eq("session-1"), max_items=7, page_size=5))
    assert len(collected) == 7, "max_items must stop the walk mid-page"
    assert [item["sk"] for item in collected] == [f"{i:04d}" for i in range(7)]


def test_iter_query_max_items_larger_than_the_result_set(events_repo: Repository) -> None:
    _seed_events(events_repo)
    assert len(list(events_query := events_repo.iter_query(
        Key("pk").eq("session-1"), max_items=500, page_size=5
    ))) == 15
    assert events_query is not None


def test_iter_query_with_a_filter_survives_empty_pages(events_repo: Repository) -> None:
    # DynamoDB applies a filter after reading a page, so the early pages here come back
    # empty with a cursor. Treating that as the end is the bug `iter_query` exists to avoid.
    _seed_events(events_repo)

    collected = list(
        events_repo.iter_query(
            Key("pk").eq("session-1"),
            page_size=2,
            filter_expression=Attr("index").eq(14),
        )
    )
    assert [item["sk"] for item in collected] == ["0014"], (
        "a match on the last page must still be yielded despite earlier empty pages"
    )


def test_iter_query_passes_a_start_key_through(events_repo: Repository) -> None:
    _seed_events(events_repo)

    collected = list(
        events_repo.iter_query(
            Key("pk").eq("session-1"), page_size=5, start_key={"pk": "session-1", "sk": "0009"}
        )
    )
    assert [item["sk"] for item in collected] == [f"{i:04d}" for i in range(10, 15)]
