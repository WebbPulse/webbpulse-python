"""Tests for the counter, ULID and idempotency helpers in `webbpulse.dynamodb`.

These are the three pieces a product writes badly on its own: a read-modify-write counter
that loses increments, a UUID4 range key that does not sort by time, and a "have I seen
this message" check that is a get followed by a put. Each test here asserts the property
that makes the shared helper worth importing rather than merely that it returns something.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from webbpulse.dynamodb import (
    ULID_LENGTH,
    IdempotencyStore,
    Repository,
    new_ulid,
)
from webbpulse.testing import FakeIdempotencyStore, create_table

TABLE = "counters"

CLAIMS_TABLE = "claims"

_CROCKFORD = set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")


class Counters(Repository):
    """A repository over the counter test table, keyed by `pk` alone."""

    logical_name = TABLE


@pytest.fixture
def counters(dynamodb_resource: Any) -> Counters:
    """A repository over a freshly created `counters` table inside the moto mock."""
    create_table(dynamodb_resource, TABLE)
    return Counters(prefix="")


@pytest.fixture
def claims(dynamodb_resource: Any) -> IdempotencyStore:
    """An idempotency store over a freshly created `claims` table with a TTL attribute."""
    create_table(dynamodb_resource, CLAIMS_TABLE, ttl_attribute="expires_at")
    return IdempotencyStore(Repository(CLAIMS_TABLE, prefix=""))


def test_increment_creates_the_item_it_counts_on(counters: Counters) -> None:
    """The first increment needs no seeded row, because `ADD` treats absence as zero."""
    assert counters.increment({"pk": "issue-key#WEB"}, "next") == 1


def test_increment_returns_the_value_after_the_call(counters: Counters) -> None:
    """Each call hands back the number it allocated, never the one before it."""
    key = {"pk": "issue-key#WEB"}
    assert [counters.increment(key, "next") for _ in range(4)] == [1, 2, 3, 4]


def test_increment_allocates_each_value_once(counters: Counters) -> None:
    """No two calls return the same number, which is the whole point of an allocator."""
    key = {"pk": "issue-key#WEB"}
    allocated = [counters.increment(key, "next") for _ in range(50)]
    assert len(set(allocated)) == 50, "a read-modify-write counter would hand out duplicates"


def test_increment_by_a_larger_step(counters: Counters) -> None:
    """A step other than one reserves that many values in a single call."""
    key = {"pk": "issue-key#WEB"}
    counters.increment(key, "next")
    assert counters.increment(key, "next", by=10) == 11


def test_increment_accepts_a_negative_step(counters: Counters) -> None:
    """A negative step decrements, so one helper serves a quota being returned."""
    key = {"pk": "seats#acct-1"}
    counters.increment(key, "used", by=5)
    assert counters.increment(key, "used", by=-2) == 3


def test_increment_by_zero_is_refused(counters: Counters) -> None:
    """Zero reads as a counter bump and does nothing, so it is refused at the call."""
    with pytest.raises(ValueError, match="non-zero"):
        counters.increment({"pk": "issue-key#WEB"}, "next", by=0)


def test_increment_counts_each_attribute_separately(counters: Counters) -> None:
    """Two counters on one item do not share a value."""
    key = {"pk": "issue-key#WEB"}
    counters.increment(key, "opened")
    counters.increment(key, "opened")
    assert counters.increment(key, "closed") == 1


def test_increment_persists_what_it_returned(counters: Counters) -> None:
    """The number handed back is the one a later read sees."""
    key = {"pk": "issue-key#WEB"}
    counters.increment(key, "next", by=7)
    item = counters.get(key)
    assert item is not None
    assert int(item["next"]) == 7


def test_a_ulid_is_twenty_six_crockford_characters() -> None:
    """The encoding is fixed width, which is what makes string ordering time ordering."""
    value = new_ulid()
    assert len(value) == ULID_LENGTH, f"a ULID is {ULID_LENGTH} characters, got {value!r}"
    assert set(value) <= _CROCKFORD, f"a ULID uses Crockford base32 only, got {value!r}"


def test_ulids_minted_in_order_sort_in_order() -> None:
    """Ids from increasing timestamps compare in the same order as their timestamps."""
    base = datetime(2026, 1, 1, tzinfo=UTC)
    ids = [new_ulid(base + timedelta(seconds=index)) for index in range(20)]
    assert ids == sorted(ids), "a ULID must sort lexicographically by time"


def test_two_ulids_in_the_same_millisecond_differ() -> None:
    """The 80 random bits keep a burst inside one millisecond collision free."""
    moment = datetime(2026, 1, 1, tzinfo=UTC)
    assert len({new_ulid(moment) for _ in range(500)}) == 500


def test_ulids_share_the_timestamp_prefix_within_a_millisecond() -> None:
    """The leading ten characters are the timestamp, so they match for the same moment."""
    moment = datetime(2026, 1, 1, tzinfo=UTC)
    assert new_ulid(moment)[:10] == new_ulid(moment)[:10]


def test_a_later_ulid_beats_an_earlier_one_by_a_millisecond() -> None:
    """One millisecond is enough to order two ids, which is the format's resolution."""
    moment = datetime(2026, 1, 1, tzinfo=UTC)
    assert new_ulid(moment) < new_ulid(moment + timedelta(milliseconds=1))


def test_new_ulid_defaults_to_now() -> None:
    """A call with no moment lands between two ids bracketing it in time."""
    before = new_ulid(datetime.now(UTC) - timedelta(seconds=1))
    value = new_ulid()
    after = new_ulid(datetime.now(UTC) + timedelta(seconds=1))
    assert before < value < after


def test_new_ulid_rejects_a_naive_datetime() -> None:
    """A naive moment is ambiguous, the way `ttl_at` rejects one."""
    with pytest.raises(ValueError, match="aware datetime"):
        new_ulid(datetime(2026, 1, 1, 12, 0, 0))


def test_new_ulid_rejects_a_moment_outside_the_epoch() -> None:
    """A timestamp wider than 48 bits would wrap and silently stop sorting."""
    with pytest.raises(ValueError, match="48-bit"):
        new_ulid(datetime(1969, 1, 1, tzinfo=UTC))


def test_the_first_claim_on_a_key_wins(claims: IdempotencyStore) -> None:
    """Nobody has claimed the key, so this caller owns the work."""
    assert claims.claim("order#1", 60) is True


def test_a_second_claim_on_the_same_key_loses(claims: IdempotencyStore) -> None:
    """The duplicate delivery is told it lost rather than doing the work twice."""
    claims.claim("order#1", 60)
    assert claims.claim("order#1", 60) is False


def test_claims_on_different_keys_both_win(claims: IdempotencyStore) -> None:
    """The claim is per key, so one message never blocks another."""
    assert claims.claim("order#1", 60) is True
    assert claims.claim("order#2", 60) is True


def test_a_claim_writes_a_ttl_and_a_timestamp(claims: IdempotencyStore) -> None:
    """The row carries the TTL the table expires on and when it was taken."""
    claims.claim("order#1", 60)
    item = claims.repository.get({"pk": "order#1"})
    assert item is not None
    assert int(item["expires_at"]) > int(datetime.now(UTC).timestamp())
    assert item["claimed_at"].endswith("Z")


def test_releasing_a_claim_lets_the_next_delivery_win(claims: IdempotencyStore) -> None:
    """A handler that failed after claiming releases rather than waiting out the TTL."""
    claims.claim("order#1", 60)
    claims.release("order#1")
    assert claims.claim("order#1", 60) is True


def test_releasing_an_unclaimed_key_is_not_an_error(claims: IdempotencyStore) -> None:
    """Release is idempotent, so a cleanup path need not check first."""
    claims.release("never-claimed")


def test_a_claim_needs_a_positive_ttl(claims: IdempotencyStore) -> None:
    """A zero or negative window would claim nothing, so it is refused at the call."""
    with pytest.raises(ValueError, match="positive ttl_seconds"):
        claims.claim("order#1", 0)


def test_the_store_honours_custom_attribute_names(dynamodb_resource: Any) -> None:
    """A product's own table shape is configured rather than forcing the defaults."""
    create_table(dynamodb_resource, "custom-claims", hash_key="id", ttl_attribute="ttl")
    store = IdempotencyStore(
        Repository("custom-claims", prefix=""),
        key_attribute="id",
        ttl_attribute="ttl",
        claimed_at_attribute="taken_at",
    )
    assert store.claim("order#1", 60) is True
    item = store.repository.get({"id": "order#1"})
    assert item is not None
    assert "ttl" in item and "taken_at" in item


def test_the_fake_store_answers_the_same_way() -> None:
    """The fake wins once and loses after, so a handler typed against the real store fits."""
    store = FakeIdempotencyStore()
    assert store.claim("order#1", 60) is True
    assert store.claim("order#1", 60) is False


def test_the_fake_store_forgets_a_key_once_its_window_passes() -> None:
    """Expiry is evaluated on read, so a replay after the window wins without sleeping."""
    clock = iter([0.0, 61.0])
    store = FakeIdempotencyStore(now=lambda: next(clock))
    assert store.claim("order#1", 60) is True
    assert store.claim("order#1", 60) is True


def test_the_fake_store_records_every_key_it_was_asked_about() -> None:
    """Winners and losers alike are recorded, which is how a test proves a handler claimed."""
    store = FakeIdempotencyStore()
    store.claim("order#1", 60)
    store.claim("order#1", 60)
    store.claim("order#2", 60)
    assert store.claims == ["order#1", "order#1", "order#2"]


def test_the_fake_store_releases_a_key() -> None:
    """Release frees the key on the fake exactly as it does on the real store."""
    store = FakeIdempotencyStore()
    store.claim("order#1", 60)
    store.release("order#1")
    assert store.claim("order#1", 60) is True


def test_the_fake_store_refuses_a_non_positive_ttl() -> None:
    """The fake refuses what the real store refuses, so a test cannot pass against one only."""
    store = FakeIdempotencyStore()
    with pytest.raises(ValueError, match="positive ttl_seconds"):
        store.claim("order#1", -1)
