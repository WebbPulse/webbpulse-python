"""Tests for the DynamoDB repository base in `webbpulse.dynamodb`.

The moto-backed tests rely on the `dynamodb_resource` fixture clearing the cached boto3
resource, so a repository resolves its table inside the mock rather than a real account.
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
    WRITE_METHODS,
    ConditionFailed,
    DynamoError,
    Page,
    ReadOnlyTable,
    Repository,
    encode_numbers,
    now_iso,
    table_name,
    ttl_at,
    ttl_in,
)
from webbpulse.testing import create_table

_MILLISECONDS_MAGNITUDE = 1_000_000_000_000


def test_now_iso_ends_with_z_and_parses() -> None:
    """`now_iso` emits a Z suffixed UTC timestamp that round trips through fromisoformat."""
    value = now_iso()
    assert value.endswith("Z"), f"now_iso must normalise the offset to Z, got {value!r}"
    assert "+00:00" not in value, f"the +00:00 offset must be replaced, got {value!r}"

    parsed = datetime.fromisoformat(value)
    assert parsed.tzinfo is not None, "the parsed timestamp must stay timezone aware"
    assert parsed.utcoffset() == timedelta(0), "the parsed timestamp must be UTC"


def test_now_iso_has_second_precision() -> None:
    """`now_iso` emits whole seconds, keeping a range key sortable at fixed width."""
    assert "." not in now_iso(), "now_iso must not emit fractional seconds"


def test_ttl_at_rejects_a_naive_datetime() -> None:
    """`ttl_at` raises on a datetime with no timezone."""
    with pytest.raises(ValueError, match="aware datetime"):
        ttl_at(datetime(2026, 1, 1, 12, 0, 0))


def test_ttl_at_returns_epoch_seconds_not_milliseconds() -> None:
    """`ttl_at` returns an int of epoch seconds, which is what DynamoDB TTL expects."""
    moment = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
    value = ttl_at(moment)

    assert isinstance(value, int), "a DynamoDB TTL must be an integer Number"
    assert value == 1767225600, f"2026-01-01T00:00:00Z is 1767225600 epoch seconds, got {value}"
    assert value < _MILLISECONDS_MAGNITUDE, f"ttl_at must return seconds (~1e9), not milliseconds (~1e12); got {value}"


def test_ttl_at_truncates_toward_zero() -> None:
    """Sub-second precision is dropped rather than rounded up."""
    moment = datetime(2026, 1, 1, 0, 0, 0, 999_999, tzinfo=UTC)
    assert ttl_at(moment) == 1767225600, "sub-second precision must be dropped, not rounded up"


def test_ttl_in_is_roughly_now_plus_the_offset() -> None:
    """`ttl_in` lands the given number of seconds ahead of now, in epoch seconds."""
    before = int(datetime.now(UTC).timestamp())
    value = ttl_in(3600)
    after = int(datetime.now(UTC).timestamp())

    assert before + 3600 <= value <= after + 3600, (
        f"ttl_in(3600) must land an hour ahead; got {value} against a now of {before}..{after}"
    )
    assert value < _MILLISECONDS_MAGNITUDE, "ttl_in must return seconds, not milliseconds"


def test_ttl_in_accepts_a_negative_offset() -> None:
    """A negative offset backdates the TTL, which is how a caller writes an expired item."""
    assert ttl_in(-60) < int(datetime.now(UTC).timestamp())


def test_table_name_with_an_explicit_prefix() -> None:
    """An explicit prefix is joined to the logical name with a hyphen."""
    assert table_name("rate-limits", "webbpulse-staging") == "webbpulse-staging-rate-limits"


def test_table_name_with_an_explicit_empty_prefix_ignores_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An explicit empty prefix wins over the environment variable."""
    monkeypatch.setenv(TABLE_PREFIX_ENV, "webbpulse-prod")
    assert table_name("rate-limits", "") == "rate-limits"


def test_table_name_reads_the_environment_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no argument, the prefix comes from the table prefix environment variable."""
    monkeypatch.setenv(TABLE_PREFIX_ENV, "webbpulse-staging")
    assert table_name("rate-limits") == "webbpulse-staging-rate-limits"


def test_table_name_without_any_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no prefix configured, the logical name is used unchanged."""
    monkeypatch.delenv(TABLE_PREFIX_ENV, raising=False)
    assert table_name("rate-limits") == "rate-limits"


def test_encode_numbers_converts_float_via_str() -> None:
    """A float is converted through str, so it carries no binary float error."""
    result = encode_numbers(0.1)
    assert result == Decimal("0.1"), f"the conversion must go via str; got {result!r}"
    assert result != Decimal(0.1), (  # noqa: RUF032
        "Decimal(float) would carry the binary float error"
    )


def test_encode_numbers_recurses_into_dicts_and_lists() -> None:
    """Nested dicts, lists and tuples are encoded, with a tuple becoming a list."""
    encoded = encode_numbers({"a": 0.1, "b": [0.2, {"c": 0.3}], "d": (0.4,)})

    assert encoded == {
        "a": Decimal("0.1"),
        "b": [Decimal("0.2"), {"c": Decimal("0.3")}],
        "d": [Decimal("0.4")],
    }
    assert isinstance(encoded["d"], list)


def test_encode_numbers_leaves_str_bytes_and_int_alone() -> None:
    """Strings, bytes, ints, None and bools pass through untouched and unwidened."""
    assert encode_numbers("0.1") == "0.1"
    assert encode_numbers(b"bytes") == b"bytes"
    assert encode_numbers(7) == 7
    assert isinstance(encode_numbers(7), int), "an int must not be widened to Decimal"
    assert encode_numbers(None) is None
    assert encode_numbers(True) is True


def test_encode_numbers_leaves_an_existing_decimal_alone() -> None:
    """An existing Decimal is returned as the same object."""
    value = Decimal("1.25")
    assert encode_numbers(value) is value


def test_page_has_more_follows_the_cursor() -> None:
    """`Page.has_more` tracks the cursor, so an empty page with a cursor still has more."""
    exhausted = Page(items=[{"pk": "a"}], last_evaluated_key=None, count=1, scanned_count=1)
    assert exhausted.has_more is False

    more = Page(items=[], last_evaluated_key={"pk": "a"}, count=0, scanned_count=10)
    assert more.has_more is True, "an empty page with a cursor still has more to come"


def test_page_repr_is_readable() -> None:
    """`repr(Page)` includes the `has_more` flag."""
    page = Page(items=[{"pk": "a"}], last_evaluated_key=None, count=1, scanned_count=2)
    assert "has_more=False" in repr(page)


def test_repository_requires_a_logical_name() -> None:
    """Constructing a `Repository` with no logical name raises."""
    with pytest.raises(ValueError, match="logical table name"):
        Repository()


def test_repository_takes_the_logical_name_from_the_class() -> None:
    """A subclass's `logical_name` attribute supplies the table name."""

    class Widgets(Repository):
        """A repository over the widgets table."""

        logical_name = "widgets"

    assert Widgets(prefix="webbpulse-staging").table_name == "webbpulse-staging-widgets"


def test_repository_argument_overrides_the_class_attribute() -> None:
    """A constructor argument wins over the class `logical_name`."""

    class Widgets(Repository):
        """A repository over the widgets table."""

        logical_name = "widgets"

    assert Widgets("gadgets", prefix="").table_name == "gadgets"


@pytest.fixture
def items_repo(dynamodb_resource: Any) -> Repository:
    """A repository over a hash-only `items` table inside the moto mock."""
    create_table(dynamodb_resource, "items")
    return Repository("items", prefix="", region_name="us-west-2")


@pytest.fixture
def users_repo(dynamodb_resource: Any) -> Repository:
    """A repository over a `users` table keyed on `id`, for the `get_many` tests."""
    create_table(dynamodb_resource, "users", hash_key="id")
    return Repository("users", prefix="", region_name="us-west-2")


@pytest.fixture
def events_repo(dynamodb_resource: Any) -> Repository:
    """A repository over an `events` table with a range key, for pagination tests."""
    create_table(dynamodb_resource, "events", range_key="sk")
    return Repository("events", prefix="", region_name="us-west-2")


def test_put_get_update_delete_round_trip(items_repo: Repository) -> None:
    """An item survives put, get, update and delete, with floats stored as Decimals."""
    items_repo.put({"pk": "widget-1", "name": "Widget", "price": 9.99})

    fetched = items_repo.get({"pk": "widget-1"})
    assert fetched is not None, "the item just written must be readable"
    assert fetched["name"] == "Widget"
    assert fetched["price"] == Decimal("9.99"), "the float must have been stored as a Decimal"

    updated = items_repo.update(
        {"pk": "widget-1"},
        update_expression="SET #n = :n",
        expression_names={"#n": "name"},
        expression_values={":n": "Renamed"},
        return_values="ALL_NEW",
    )
    assert updated is not None
    assert updated["name"] == "Renamed"

    items_repo.delete({"pk": "widget-1"})
    assert items_repo.get({"pk": "widget-1"}) is None


def test_get_returns_none_for_a_missing_item(items_repo: Repository) -> None:
    """`get` returns None rather than raising for an absent key."""
    assert items_repo.get({"pk": "does-not-exist"}) is None


def test_get_with_a_consistent_read(items_repo: Repository) -> None:
    """`consistent=True` still reads back the written item."""
    items_repo.put({"pk": "widget-1", "name": "Widget"})
    fetched = items_repo.get({"pk": "widget-1"}, consistent=True)
    assert fetched is not None


def test_update_returning_none_when_no_values_are_requested(items_repo: Repository) -> None:
    """With no `return_values`, `update` yields None rather than an empty dict."""
    items_repo.put({"pk": "counter", "count": 0})
    assert (
        items_repo.update(
            {"pk": "counter"},
            update_expression="ADD #c :one",
            expression_names={"#c": "count"},
            expression_values={":one": 1},
        )
        is None
    ), "ReturnValues=NONE must yield None rather than an empty dict"


def test_delete_of_an_absent_item_is_not_an_error(items_repo: Repository) -> None:
    """Deleting a key that was never written is a no-op."""
    items_repo.delete({"pk": "never-existed"})


def test_put_with_a_condition_raises_on_a_duplicate(items_repo: Repository) -> None:
    """A failed condition raises `ConditionFailed` and leaves the item intact."""
    items_repo.put({"pk": "unique-1", "name": "First"}, condition=Attr("pk").not_exists())

    with pytest.raises(ConditionFailed) as excinfo:
        items_repo.put({"pk": "unique-1", "name": "Second"}, condition=Attr("pk").not_exists())

    assert excinfo.value.table == "items", "the failure must name the table it guarded"
    assert "attribute_not_exists" in excinfo.value.condition, (
        f"the rendered condition must be recorded, got {excinfo.value.condition!r}"
    )

    existing = items_repo.get({"pk": "unique-1"})
    assert existing is not None
    assert existing["name"] == "First"


def test_a_failed_condition_keeps_the_client_error_as_its_cause(items_repo: Repository) -> None:
    """`ConditionFailed` chains the botocore error, so nothing about the failure is lost."""
    items_repo.put({"pk": "unique-1", "name": "First"}, condition=Attr("pk").not_exists())

    with pytest.raises(ConditionFailed) as excinfo:
        items_repo.put({"pk": "unique-1", "name": "Second"}, condition=Attr("pk").not_exists())

    cause = excinfo.value.__cause__
    assert isinstance(cause, ClientError), f"the ClientError must stay as the cause, got {cause!r}"
    assert cause.response["Error"]["Code"] == "ConditionalCheckFailedException"


def test_a_non_condition_client_error_is_re_raised_untouched(
    items_repo: Repository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only a failed condition becomes `ConditionFailed`; a throttle stays a `ClientError`.

    A throttle or an access denial is a fault the caller must not mistake for a lost race,
    which a blanket translation would hide behind a 409.
    """

    def _throttle(**kwargs: Any) -> None:
        raise ClientError(
            {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "slow down"}},
            "PutItem",
        )

    monkeypatch.setattr(items_repo.table, "put_item", _throttle)
    with pytest.raises(ClientError) as excinfo:
        items_repo.put({"pk": "throttled"}, condition=Attr("pk").not_exists())
    assert excinfo.value.response["Error"]["Code"] == "ProvisionedThroughputExceededException"


def test_delete_with_a_failing_condition_raises(items_repo: Repository) -> None:
    """A delete whose condition fails raises `ConditionFailed` and leaves the item in place."""
    items_repo.put({"pk": "guarded", "state": "locked"})
    with pytest.raises(ConditionFailed) as excinfo:
        items_repo.delete({"pk": "guarded"}, condition=Attr("state").eq("unlocked"))
    assert excinfo.value.key == {"pk": "guarded"}, "a conditional delete must record the key it guarded"
    assert items_repo.get({"pk": "guarded"}) is not None


def test_update_with_a_failing_condition_raises(items_repo: Repository) -> None:
    """An update whose condition fails raises `ConditionFailed` and writes nothing."""
    items_repo.put({"pk": "guarded", "state": "locked"})

    with pytest.raises(ConditionFailed) as excinfo:
        items_repo.update(
            {"pk": "guarded"},
            update_expression="SET #s = :s",
            expression_names={"#s": "state"},
            expression_values={":s": "open"},
            condition=Attr("state").eq("unlocked"),
        )

    assert excinfo.value.key == {"pk": "guarded"}, "a conditional update must record the key it guarded"
    stored = items_repo.get({"pk": "guarded"})
    assert stored is not None
    assert stored["state"] == "locked", "a refused update must leave the item untouched"


def test_an_unconditional_write_still_raises_the_raw_client_error(
    items_repo: Repository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no condition there is no conflict to report, so the botocore error is untouched."""

    def _boom(**kwargs: Any) -> None:
        raise ClientError({"Error": {"Code": "ValidationException", "Message": "bad"}}, "PutItem")

    monkeypatch.setattr(items_repo.table, "put_item", _boom)
    with pytest.raises(ClientError):
        items_repo.put({"pk": "whatever"})


def test_put_many_writes_every_item(items_repo: Repository) -> None:
    """`put_many` writes across batch chunks and encodes floats like `put` does."""
    items_repo.put_many([{"pk": f"bulk-{i}", "index": i, "ratio": i / 4} for i in range(30)])

    first = items_repo.get({"pk": "bulk-0"})
    last = items_repo.get({"pk": "bulk-29"})
    assert first is not None and last is not None, "put_many must write across batch chunks"
    assert last["ratio"] == Decimal("7.25"), "put_many must encode floats like put does"


def test_put_many_with_no_items_is_a_no_op(items_repo: Repository) -> None:
    """`put_many` with an empty list does nothing."""
    items_repo.put_many([])


def _seed_events(repo: Repository, count: int = 15) -> None:
    """Write `count` events under one partition with zero padded sort keys."""
    repo.put_many([{"pk": "session-1", "sk": f"{i:04d}", "index": i} for i in range(count)])


def test_query_returns_one_page_and_a_cursor(events_repo: Repository) -> None:
    """`query` honours the limit and leaves a cursor when more items remain."""
    _seed_events(events_repo)

    page = events_repo.query(Key("pk").eq("session-1"), limit=5)
    assert len(page.items) == 5
    assert page.count == 5
    assert page.has_more is True, "15 items at a limit of 5 must leave a cursor"
    assert [item["sk"] for item in page.items] == ["0000", "0001", "0002", "0003", "0004"]


def test_query_descending_and_projection(events_repo: Repository) -> None:
    """`ascending=False` reverses the order and a projection limits the attributes."""
    _seed_events(events_repo)

    page = events_repo.query(Key("pk").eq("session-1"), limit=3, ascending=False, projection="sk")
    assert [item["sk"] for item in page.items] == ["0014", "0013", "0012"]
    assert set(page.items[0]) == {"sk"}, "a projection must limit the attributes returned"


def test_query_follows_an_explicit_start_key(events_repo: Repository) -> None:
    """Passing a previous page's cursor as `start_key` resumes where it stopped."""
    _seed_events(events_repo)

    first = events_repo.query(Key("pk").eq("session-1"), limit=5)
    second = events_repo.query(Key("pk").eq("session-1"), limit=5, start_key=first.last_evaluated_key)
    assert [item["sk"] for item in second.items] == ["0005", "0006", "0007", "0008", "0009"]


def test_query_for_a_missing_partition_is_empty(events_repo: Repository) -> None:
    """A query on an unused partition returns an empty page with no cursor."""
    _seed_events(events_repo)
    page = events_repo.query(Key("pk").eq("session-absent"))
    assert page.items == []
    assert page.has_more is False


def test_iter_query_walks_every_page(events_repo: Repository) -> None:
    """`iter_query` follows LastEvaluatedKey across every page, in order."""
    _seed_events(events_repo)

    collected = list(events_repo.iter_query(Key("pk").eq("session-1"), page_size=5))
    assert len(collected) == 15, "iter_query must follow LastEvaluatedKey across all 3 pages"
    assert [item["sk"] for item in collected] == [f"{i:04d}" for i in range(15)]


def test_iter_query_bounds_the_result_with_max_items(events_repo: Repository) -> None:
    """`max_items` stops the walk mid-page."""
    _seed_events(events_repo)

    collected = list(events_repo.iter_query(Key("pk").eq("session-1"), max_items=7, page_size=5))
    assert len(collected) == 7, "max_items must stop the walk mid-page"
    assert [item["sk"] for item in collected] == [f"{i:04d}" for i in range(7)]


def test_iter_query_max_items_larger_than_the_result_set(events_repo: Repository) -> None:
    """A `max_items` above the result count yields every item."""
    _seed_events(events_repo)
    assert (
        len(list(events_query := events_repo.iter_query(Key("pk").eq("session-1"), max_items=500, page_size=5))) == 15
    )
    assert events_query is not None


def test_iter_query_with_a_filter_survives_empty_pages(events_repo: Repository) -> None:
    """A filtered walk keeps going past empty pages that still carry a cursor."""
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
    """`start_key` is forwarded, so the walk begins after that key."""
    _seed_events(events_repo)

    collected = list(
        events_repo.iter_query(Key("pk").eq("session-1"), page_size=5, start_key={"pk": "session-1", "sk": "0009"})
    )
    assert [item["sk"] for item in collected] == [f"{i:04d}" for i in range(10, 15)]


def test_set_attributes_writes_every_named_attribute(items_repo: Repository) -> None:
    """`set_attributes` SETs each attribute and returns the stored item."""
    items_repo.put({"pk": "widget-1", "name": "Widget", "state": "draft"})

    updated = items_repo.set_attributes({"pk": "widget-1"}, {"name": "Renamed", "state": "live", "size": 3})

    assert updated is not None
    assert updated["name"] == "Renamed"
    assert updated["state"] == "live"
    assert updated["size"] == 3


def test_set_attributes_aliases_reserved_words(items_repo: Repository) -> None:
    """Every name is aliased, so a DynamoDB reserved word such as `status` is writable."""
    items_repo.put({"pk": "widget-1"})

    updated = items_repo.set_attributes({"pk": "widget-1"}, {"status": "active", "size": 2, "name": "Widget"})

    assert updated is not None
    assert updated["status"] == "active", "a reserved word must be aliased rather than rejected"


def test_set_attributes_with_a_condition_does_not_collide_with_boto3_aliases(
    items_repo: Repository,
) -> None:
    """A SET alongside an `Attr` condition writes the SET's attribute, not the condition's.

    The regression this guards: aliases numbered `#n0` collide with the placeholders boto3
    mints for a condition from its own `#n0` counter. The two maps merge into one request,
    the later definition wins, and the update silently writes to the attribute the condition
    named. The `#set{index}` namespace cannot collide, so `state` here must stay untouched.
    """
    items_repo.put({"pk": "widget-1", "state": "locked", "name": "Before"})

    updated = items_repo.set_attributes(
        {"pk": "widget-1"},
        {"name": "After"},
        condition=Attr("state").eq("locked"),
    )

    assert updated is not None
    assert updated["name"] == "After", "the SET must have written the attribute it named"
    assert updated["state"] == "locked", "the condition's attribute must not have been overwritten"


def test_set_attributes_with_a_failing_condition_raises(items_repo: Repository) -> None:
    """A conditional `set_attributes` that loses its race raises `ConditionFailed`."""
    items_repo.put({"pk": "widget-1", "state": "locked", "name": "Before"})

    with pytest.raises(ConditionFailed):
        items_repo.set_attributes(
            {"pk": "widget-1"},
            {"name": "After"},
            condition=Attr("state").eq("unlocked"),
        )

    stored = items_repo.get({"pk": "widget-1"})
    assert stored is not None
    assert stored["name"] == "Before", "a refused update must leave the item untouched"


def test_set_attributes_with_nothing_to_set_is_a_no_op(items_repo: Repository) -> None:
    """An empty mapping returns None rather than sending an empty UpdateExpression."""
    items_repo.put({"pk": "widget-1", "name": "Widget"})
    assert items_repo.set_attributes({"pk": "widget-1"}, {}) is None


def test_set_attributes_encodes_floats(items_repo: Repository) -> None:
    """`set_attributes` goes through `update`, so a float still stores as a Decimal."""
    items_repo.put({"pk": "widget-1"})
    updated = items_repo.set_attributes({"pk": "widget-1"}, {"price": 9.99})
    assert updated is not None
    assert updated["price"] == Decimal("9.99")


def test_get_many_returns_items_keyed_by_id(users_repo: Repository) -> None:
    """`get_many` pairs each item back to the id that asked for it."""
    users_repo.put_many([{"id": f"user-{i}", "name": f"User {i}"} for i in range(3)])

    found = users_repo.get_many(["user-0", "user-2"])

    assert set(found) == {"user-0", "user-2"}
    assert found["user-2"]["name"] == "User 2"


def test_get_many_omits_misses(users_repo: Repository) -> None:
    """An id with no row is absent from the result, the way `get` answers None."""
    users_repo.put({"id": "user-0"})
    found = users_repo.get_many(["user-0", "never-existed"])
    assert set(found) == {"user-0"}, "a missing id must be omitted rather than raising"


def test_get_many_de_duplicates_ids(users_repo: Repository) -> None:
    """Repeated ids are collapsed, since BatchGetItem rejects a duplicated key."""
    users_repo.put({"id": "user-0", "name": "User 0"})
    found = users_repo.get_many(["user-0", "user-0", "user-0"])
    assert found == {"user-0": {"id": "user-0", "name": "User 0"}}


def test_get_many_drops_blank_ids(users_repo: Repository) -> None:
    """A blank id is dropped, since DynamoDB rejects an empty key attribute."""
    users_repo.put({"id": "user-0"})
    assert set(users_repo.get_many(["user-0", ""])) == {"user-0"}


def test_get_many_with_no_ids_is_empty(users_repo: Repository) -> None:
    """An empty list costs no call and yields an empty mapping."""
    assert users_repo.get_many([]) == {}


def test_get_many_chunks_beyond_the_batch_limit(users_repo: Repository) -> None:
    """More than `BATCH_GET_LIMIT` ids are chunked, so a long member list is one call path."""
    wanted = [f"user-{i:03d}" for i in range(150)]
    users_repo.put_many([{"id": user_id} for user_id in wanted])

    found = users_repo.get_many(wanted)

    assert len(found) == 150, f"every id across both chunks must come back, got {len(found)}"
    assert set(found) == set(wanted)


def test_get_many_honours_a_custom_key_attribute(items_repo: Repository) -> None:
    """A table keyed by something other than `id` names its key attribute."""
    items_repo.put_many([{"pk": "widget-1"}, {"pk": "widget-2"}])
    found = items_repo.get_many(["widget-1", "widget-2"], key_attribute="pk")
    assert set(found) == {"widget-1", "widget-2"}


def test_remove_attributes_deletes_every_named_attribute(items_repo: Repository) -> None:
    """`remove_attributes` REMOVEs each attribute and returns what the item now holds."""
    items_repo.put({"pk": "widget-1", "name": "Widget", "unread_at": "2026-09-17", "state": "open"})

    updated = items_repo.remove_attributes({"pk": "widget-1"}, ["unread_at", "state"])

    assert updated is not None
    assert "unread_at" not in updated, "a removed attribute must be gone, not emptied"
    assert "state" not in updated
    assert updated["name"] == "Widget", "an attribute not named must survive untouched"


def test_remove_attributes_leaves_a_sparse_index(items_repo: Repository) -> None:
    """The attribute is deleted rather than set to a marker, which is what empties the index.

    A sparse global secondary index holds only the items carrying its key attribute. Setting
    that attribute to null or to an empty string keeps the item in the index and keeps it in
    every query that reads it, so only a `REMOVE` takes it out.
    """
    items_repo.put({"pk": "widget-1", "unread_at": "2026-09-17"})

    items_repo.remove_attributes({"pk": "widget-1"}, ["unread_at"])

    stored = items_repo.get({"pk": "widget-1"})
    assert stored is not None
    assert "unread_at" not in stored, "the index key must be absent, since a marker still indexes"


def test_remove_attributes_aliases_reserved_words(items_repo: Repository) -> None:
    """Every name is aliased, so a DynamoDB reserved word such as `status` is removable."""
    items_repo.put({"pk": "widget-1", "status": "active", "size": 2, "name": "Widget"})

    updated = items_repo.remove_attributes({"pk": "widget-1"}, ["status", "size", "name"])

    assert updated is not None
    assert set(updated) == {"pk"}, "a reserved word must be aliased rather than rejected"


def test_remove_attributes_with_a_condition_does_not_collide_with_boto3_aliases(
    items_repo: Repository,
) -> None:
    """A REMOVE alongside an `Attr` condition deletes its own attribute, not the condition's.

    The same collision `set_attributes` guards against: aliases numbered `#n0` meet the
    placeholders boto3 mints for a condition from its own `#n0` counter, the maps merge, and
    the later definition wins. The `#rm{index}` namespace cannot collide, so `state` here
    must survive.
    """
    items_repo.put({"pk": "widget-1", "state": "locked", "unread_at": "2026-09-17"})

    updated = items_repo.remove_attributes(
        {"pk": "widget-1"},
        ["unread_at"],
        condition=Attr("state").eq("locked"),
    )

    assert updated is not None
    assert "unread_at" not in updated, "the REMOVE must have deleted the attribute it named"
    assert updated["state"] == "locked", "the condition's attribute must not have been removed"


def test_remove_attributes_with_a_failing_condition_raises(items_repo: Repository) -> None:
    """A conditional `remove_attributes` that loses its race raises `ConditionFailed`."""
    items_repo.put({"pk": "widget-1", "state": "locked", "unread_at": "2026-09-17"})

    with pytest.raises(ConditionFailed):
        items_repo.remove_attributes(
            {"pk": "widget-1"},
            ["unread_at"],
            condition=Attr("state").eq("unlocked"),
        )

    stored = items_repo.get({"pk": "widget-1"})
    assert stored is not None
    assert stored["unread_at"] == "2026-09-17", "a refused removal must leave the item untouched"


def test_remove_attributes_with_nothing_to_remove_is_a_no_op(items_repo: Repository) -> None:
    """An empty sequence returns None rather than sending an empty UpdateExpression."""
    items_repo.put({"pk": "widget-1", "name": "Widget"})
    assert items_repo.remove_attributes({"pk": "widget-1"}, []) is None


def test_remove_attributes_de_duplicates_names(items_repo: Repository) -> None:
    """A repeated name is sent once, since DynamoDB refuses an expression naming one path twice."""
    items_repo.put({"pk": "widget-1", "unread_at": "2026-09-17"})

    updated = items_repo.remove_attributes({"pk": "widget-1"}, ["unread_at", "unread_at"])

    assert updated is not None
    assert "unread_at" not in updated


def test_remove_attributes_on_an_absent_attribute_is_not_an_error(items_repo: Repository) -> None:
    """REMOVE on an attribute the item lacks is a no-op, which makes a redelivery harmless."""
    items_repo.put({"pk": "widget-1", "name": "Widget"})

    updated = items_repo.remove_attributes({"pk": "widget-1"}, ["unread_at"])

    assert updated is not None
    assert updated["name"] == "Widget"


def test_remove_attributes_honours_return_values(items_repo: Repository) -> None:
    """`return_values` reaches DynamoDB, so a caller wanting no read back pays for none."""
    items_repo.put({"pk": "widget-1", "unread_at": "2026-09-17"})
    assert items_repo.remove_attributes({"pk": "widget-1"}, ["unread_at"], return_values="NONE") is None


_READ_METHODS: frozenset[str] = frozenset(
    {
        "batch_get",
        "get",
        "get_many",
        "iter_query",
        "iter_scan",
        "query",
        "scan",
    }
)


def _public_methods() -> frozenset[str]:
    """Every public callable declared on `Repository` itself."""
    return frozenset(name for name, value in vars(Repository).items() if not name.startswith("_") and callable(value))


def test_write_methods_covers_every_public_method_that_is_not_a_read() -> None:
    """Every public `Repository` method is classified, so a new write cannot slip past.

    Enumerated from the class rather than restated, so adding a method to `Repository`
    without listing it in `WRITE_METHODS` or `_READ_METHODS` fails here.
    """
    unclassified = _public_methods() - set(WRITE_METHODS) - _READ_METHODS
    assert not unclassified, (
        f"new public Repository methods are unclassified: {sorted(unclassified)}. "
        "Add each to WRITE_METHODS in webbpulse.dynamodb if it writes, or to _READ_METHODS here."
    )


def test_every_write_method_is_guarded_on_a_read_only_repository() -> None:
    """Each name in `WRITE_METHODS` raises `ReadOnlyTable` before any client is built."""
    repository = Repository("guarded", read_only=True)

    for method in WRITE_METHODS:
        with pytest.raises(ReadOnlyTable) as raised:
            getattr(repository, method)()
        assert raised.value.method == method, f"{method} must report its own name"
        assert raised.value.table == repository.table_name, f"{method} must name the table"


def test_read_only_refusal_names_the_table_and_the_callers_hint() -> None:
    """The message carries the table, the method and the caller-supplied hint."""
    repository = Repository("posts", read_only=True, read_only_hint="Move it to the write grant.")

    with pytest.raises(ReadOnlyTable) as raised:
        repository.put({"pk": "a"})

    message = str(raised.value)
    assert repository.table_name in message, f"the table must be named, got {message!r}"
    assert "put()" in message, f"the refused method must be named, got {message!r}"
    assert "Move it to the write grant." in message, f"the hint must be carried, got {message!r}"
    assert raised.value.hint == "Move it to the write grant."


def test_read_only_refusal_omits_a_hint_that_was_not_supplied() -> None:
    """Without a hint the message is still complete, and `hint` is `None`."""
    with pytest.raises(ReadOnlyTable) as raised:
        Repository("posts", read_only=True).delete({"pk": "a"})

    assert raised.value.hint is None, "an unsupplied hint must stay None"
    assert str(raised.value).endswith("only reads."), f"got {str(raised.value)!r}"


def test_read_only_is_a_permission_error_but_not_a_dynamo_error() -> None:
    """A broad data-layer handler must not swallow the mistake the guard exists to expose."""
    assert issubclass(ReadOnlyTable, PermissionError)
    assert not issubclass(ReadOnlyTable, DynamoError)


def test_a_read_only_repository_refuses_before_touching_the_network() -> None:
    """No table resource is built, which is what makes the guard safe without credentials."""
    repository = Repository("posts", read_only=True)

    with pytest.raises(ReadOnlyTable):
        repository.put({"pk": "a"})

    assert repository._table is None, "the refusal must happen before the table is resolved"


def test_reads_pass_through_a_read_only_repository(dynamodb_resource: Any) -> None:
    """A read-only repository reads exactly like a normal one."""
    create_table(dynamodb_resource, "readable")
    Repository("readable").put({"pk": "a", "value": 1})

    repository = Repository("readable", read_only=True)

    assert repository.read_only is True
    assert repository.get({"pk": "a"}) == {"pk": "a", "value": Decimal(1)}
    assert repository.query(Key("pk").eq("a")).count == 1


def test_a_repository_is_writable_by_default(dynamodb_resource: Any) -> None:
    """The flag is opt-in, so every existing caller is unaffected."""
    create_table(dynamodb_resource, "writable")
    repository = Repository("writable")

    assert repository.read_only is False
    repository.put({"pk": "a"})
    assert repository.get({"pk": "a"}) == {"pk": "a"}


def test_read_only_applies_to_a_product_subclass(dynamodb_resource: Any) -> None:
    """A domain subclass inherits the guard, since it lives on `Repository` itself."""

    class Posts(Repository):
        """A product repository over the posts table."""

        logical_name = "posts"

    with pytest.raises(ReadOnlyTable):
        Posts(read_only=True).put({"pk": "a"})
