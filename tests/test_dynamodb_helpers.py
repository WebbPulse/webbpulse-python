"""Tests for the batch, transaction and scan-paging helpers in `webbpulse.dynamodb`.

These are the helpers both products had written for themselves, and the retry cap is the
one that matters: Portfolio's `UnprocessedKeys` loop has neither backoff nor a bound, so a
throttled table hangs the caller. The cap is tested by injecting `UnprocessedKeys` on every
response and proving the call raises rather than spinning.
"""

from __future__ import annotations

from typing import Any

import pytest
from boto3.dynamodb.conditions import Attr

from webbpulse.dynamodb import (
    BATCH_GET_LIMIT,
    TRANSACT_WRITE_LIMIT,
    UNPROCESSED_RETRY_ATTEMPTS,
    Repository,
    TransactionCanceled,
    UnprocessedItems,
    transact_write,
)
from webbpulse.testing import create_table

TABLE = "widgets"

OTHER_TABLE = "gadgets"


class Widgets(Repository):
    """A repository over the test table, keyed by `pk` alone."""

    logical_name = TABLE


@pytest.fixture
def widgets(dynamodb_resource: Any) -> Widgets:
    """A repository over a freshly created `widgets` table inside the moto mock."""
    create_table(dynamodb_resource, TABLE)
    return Widgets(prefix="")


@pytest.fixture
def gadgets(dynamodb_resource: Any) -> Repository:
    """A second table, so a transaction spanning two tables is exercisable."""
    create_table(dynamodb_resource, OTHER_TABLE)
    return Repository(OTHER_TABLE, prefix="")


def seed(repo: Repository, count: int, *, prefix: str = "w") -> list[dict[str, Any]]:
    """Write `count` numbered items and return them."""
    items = [{"pk": f"{prefix}-{index:04d}", "n": index} for index in range(count)]
    repo.put_many(items)
    return items


def test_batch_get_returns_every_item_asked_for(widgets: Widgets) -> None:
    """Every key that has an item comes back, order aside."""
    seed(widgets, 5)
    found = widgets.batch_get([{"pk": f"w-{index:04d}"} for index in range(5)])
    assert sorted(item["pk"] for item in found) == [f"w-{index:04d}" for index in range(5)]


def test_batch_get_omits_a_key_with_no_item(widgets: Widgets) -> None:
    """A key with nothing behind it is simply absent, the way `get` answers `None`."""
    seed(widgets, 2)
    found = widgets.batch_get([{"pk": "w-0000"}, {"pk": "missing"}])
    assert [item["pk"] for item in found] == ["w-0000"]


def test_batch_get_of_nothing_is_not_a_call(widgets: Widgets) -> None:
    """An empty key list short circuits, so a caller need not guard the call."""
    assert widgets.batch_get([]) == []


def test_batch_get_chunks_past_the_hundred_key_limit(widgets: Widgets) -> None:
    """More keys than `BatchGetItem` accepts are split across calls rather than refused."""
    total = BATCH_GET_LIMIT + 37
    seed(widgets, total)
    found = widgets.batch_get([{"pk": f"w-{index:04d}"} for index in range(total)])
    assert len(found) == total


def test_batch_get_honours_a_projection(widgets: Widgets) -> None:
    """A projection reaches the request, so only the named attributes come back."""
    seed(widgets, 2)
    found = widgets.batch_get([{"pk": "w-0000"}], projection="pk")
    assert found == [{"pk": "w-0000"}]


def test_a_max_attempts_below_one_is_refused(widgets: Widgets) -> None:
    """Zero attempts would silently return nothing, so it is refused at the call."""
    with pytest.raises(ValueError, match="at least 1"):
        widgets.batch_get([{"pk": "w-0000"}], max_attempts=0)


class UnprocessedStub:
    """A `batch_get_item` that always leaves the keys it was given unprocessed.

    Stands in for a table shedding load: DynamoDB answers 200 with `UnprocessedKeys` rather
    than raising, and can keep doing so indefinitely.
    """

    def __init__(self, table_name: str, *, responses_before_success: int | None = None) -> None:
        """Record the table and, optionally, how many refusals precede a success."""
        self.table_name = table_name
        self.responses_before_success = responses_before_success
        self.calls: list[dict[str, Any]] = []

    def batch_get_item(self, *, RequestItems: dict[str, Any]) -> dict[str, Any]:
        """Answer with everything still unprocessed, until the configured attempt."""
        self.calls.append(RequestItems)
        keys = RequestItems[self.table_name]["Keys"]
        if self.responses_before_success is not None and len(self.calls) > self.responses_before_success:
            return {"Responses": {self.table_name: [{"pk": key["pk"]} for key in keys]}, "UnprocessedKeys": {}}
        return {
            "Responses": {self.table_name: []},
            "UnprocessedKeys": {self.table_name: {"Keys": keys, "ConsistentRead": False}},
        }


@pytest.fixture
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record and skip the backoff pauses, so the retry tests do not actually wait."""
    import time

    slept: list[float] = []

    def record(seconds: float) -> None:
        """Record a pause without taking it."""
        slept.append(seconds)

    monkeypatch.setattr(time, "sleep", record)
    return slept


def stub_client(monkeypatch: pytest.MonkeyPatch, repo: Repository, stub: UnprocessedStub) -> None:
    """Point the repository's batch calls at `stub` instead of the moto client."""
    import webbpulse.dynamodb as module

    class FakeResource:
        """Just enough of the service resource to hand back the stub as `meta.client`."""

        meta = type("Meta", (), {"client": stub})()

    monkeypatch.setattr(module, "_resource", lambda *args, **kwargs: FakeResource())


def test_batch_get_raises_rather_than_looping_when_keys_stay_unprocessed(
    widgets: Widgets, monkeypatch: pytest.MonkeyPatch, no_sleep: list[float]
) -> None:
    """Keys unprocessed on every attempt raise at the cap. This is the latent hang."""
    stub = UnprocessedStub(widgets.table_name)
    stub_client(monkeypatch, widgets, stub)

    with pytest.raises(UnprocessedItems) as caught:
        widgets.batch_get([{"pk": "w-0000"}, {"pk": "w-0001"}])

    assert caught.value.count == 2
    assert caught.value.attempts == UNPROCESSED_RETRY_ATTEMPTS
    assert caught.value.table == widgets.table_name
    assert len(stub.calls) == UNPROCESSED_RETRY_ATTEMPTS


def test_the_retry_cap_is_configurable(
    widgets: Widgets, monkeypatch: pytest.MonkeyPatch, no_sleep: list[float]
) -> None:
    """`max_attempts` bounds the calls exactly, so a hot path can give up sooner."""
    stub = UnprocessedStub(widgets.table_name)
    stub_client(monkeypatch, widgets, stub)

    with pytest.raises(UnprocessedItems) as caught:
        widgets.batch_get([{"pk": "w-0000"}], max_attempts=2)

    assert caught.value.attempts == 2
    assert len(stub.calls) == 2


def test_the_backoff_between_attempts_doubles(
    widgets: Widgets, monkeypatch: pytest.MonkeyPatch, no_sleep: list[float]
) -> None:
    """Each retry waits twice as long, which is what makes the retry a backoff."""
    stub_client(monkeypatch, widgets, UnprocessedStub(widgets.table_name))

    with pytest.raises(UnprocessedItems):
        widgets.batch_get([{"pk": "w-0000"}], max_attempts=4)

    assert no_sleep == [0.05, 0.1, 0.2]


def test_unprocessed_keys_are_retried_and_eventually_succeed(
    widgets: Widgets, monkeypatch: pytest.MonkeyPatch, no_sleep: list[float]
) -> None:
    """A table that sheds load twice and then answers yields the items, not an error."""
    stub = UnprocessedStub(widgets.table_name, responses_before_success=2)
    stub_client(monkeypatch, widgets, stub)

    found = widgets.batch_get([{"pk": "w-0000"}])
    assert found == [{"pk": "w-0000"}]
    assert len(stub.calls) == 3
    assert len(no_sleep) == 2


def test_a_retry_asks_only_for_the_keys_still_outstanding(
    widgets: Widgets, monkeypatch: pytest.MonkeyPatch, no_sleep: list[float]
) -> None:
    """The retry sends DynamoDB's own `UnprocessedKeys` back, not the original request."""
    stub = UnprocessedStub(widgets.table_name, responses_before_success=1)
    stub_client(monkeypatch, widgets, stub)

    widgets.batch_get([{"pk": "w-0000"}])
    assert stub.calls[1][widgets.table_name]["Keys"] == [{"pk": "w-0000"}]


def test_iter_scan_yields_every_item_across_pages(widgets: Widgets) -> None:
    """Paging is followed to exhaustion, which is the loop both products hand-rolled."""
    seed(widgets, 25)
    assert len({item["pk"] for item in widgets.iter_scan(page_size=4)}) == 25


def test_iter_scan_survives_an_empty_filtered_page(widgets: Widgets) -> None:
    """An empty page with a cursor still set is normal after a filter, not the end."""
    seed(widgets, 30)
    found = list(widgets.iter_scan(page_size=2, filter_expression=Attr("n").eq(29)))
    assert [item["pk"] for item in found] == ["w-0029"]


def test_iter_scan_stops_at_max_items(widgets: Widgets) -> None:
    """`max_items` bounds the work, so an unbounded scan cannot walk the whole table."""
    seed(widgets, 20)
    assert len(list(widgets.iter_scan(max_items=7, page_size=3))) == 7


def test_iter_scan_of_an_empty_table_yields_nothing(widgets: Widgets) -> None:
    """No items is an empty iterator rather than one empty page's worth of nothing."""
    assert list(widgets.iter_scan()) == []


def test_scan_returns_a_page_with_a_cursor(widgets: Widgets) -> None:
    """One page carries its own cursor, for a caller paginating for a client."""
    seed(widgets, 10)
    page = widgets.scan(limit=4)
    assert len(page.items) == 4
    assert page.has_more

    second = widgets.scan(limit=4, start_key=page.last_evaluated_key)
    assert {item["pk"] for item in second.items}.isdisjoint({item["pk"] for item in page.items})


def test_a_half_specified_parallel_scan_is_refused(widgets: Widgets) -> None:
    """DynamoDB rejects one of the pair, so the repository rejects it before the call."""
    with pytest.raises(ValueError, match="segment and total_segments"):
        widgets.scan(segment=0)


def test_a_parallel_scan_covers_the_table_across_its_segments(widgets: Widgets) -> None:
    """Every segment together sees every item, which is the point of a parallel scan."""
    seed(widgets, 12)
    seen: set[str] = set()
    for segment in range(3):
        seen.update(item["pk"] for item in widgets.iter_scan(segment=segment, total_segments=3))
    assert len(seen) == 12


def test_transact_write_applies_every_action(widgets: Widgets) -> None:
    """A transaction's writes all land, which is the point of running them as one."""
    widgets.put({"pk": "to-delete"})
    transact_write(
        [
            widgets.put_action({"pk": "created", "n": 1}),
            widgets.delete_action({"pk": "to-delete"}),
        ]
    )
    assert widgets.get({"pk": "created"}) == {"pk": "created", "n": 1}
    assert widgets.get({"pk": "to-delete"}) is None


def test_transact_write_of_nothing_is_a_no_op(widgets: Widgets) -> None:
    """An empty action list does nothing, so a caller assembling actions need not check."""
    transact_write([])


def test_too_many_actions_is_refused_before_the_call(widgets: Widgets) -> None:
    """Past DynamoDB's cap the whole transaction would be rejected, so it never goes."""
    actions = [widgets.put_action({"pk": f"w-{index}"}) for index in range(TRANSACT_WRITE_LIMIT + 1)]
    with pytest.raises(ValueError, match=str(TRANSACT_WRITE_LIMIT)):
        transact_write(actions)


def test_a_failed_condition_cancels_the_whole_transaction(widgets: Widgets) -> None:
    """One refused condition rolls back every other action in the transaction."""
    widgets.put({"pk": "taken"})
    with pytest.raises(TransactionCanceled) as caught:
        transact_write(
            [
                widgets.put_action({"pk": "would-be-created"}),
                widgets.put_action({"pk": "taken"}, condition=Attr("pk").not_exists()),
            ]
        )

    assert caught.value.conditional_check_failed
    assert widgets.get({"pk": "would-be-created"}) is None


def test_a_condition_check_asserts_on_an_item_it_does_not_write(widgets: Widgets) -> None:
    """A ConditionCheck refuses the transaction without touching the item it guards."""
    widgets.put({"pk": "guard", "state": "closed"})
    with pytest.raises(TransactionCanceled):
        transact_write(
            [
                widgets.condition_check({"pk": "guard"}, condition=Attr("state").eq("open")),
                widgets.put_action({"pk": "dependent"}),
            ]
        )
    assert widgets.get({"pk": "dependent"}) is None


def test_an_update_action_applies_its_expression(widgets: Widgets) -> None:
    """An Update action inside a transaction applies the same expression `update` would."""
    widgets.put({"pk": "counted", "n": 1})
    transact_write(
        [
            widgets.update_action(
                {"pk": "counted"},
                update_expression="SET #n = :two",
                expression_values={":two": 2},
                expression_names={"#n": "n"},
            )
        ]
    )
    item = widgets.get({"pk": "counted"})
    assert item is not None
    assert int(item["n"]) == 2


def test_a_transaction_spans_two_tables(widgets: Widgets, gadgets: Repository) -> None:
    """Actions name their own table, so one transaction covers both."""
    widgets.transact_write([widgets.put_action({"pk": "a"}), gadgets.put_action({"pk": "b"})])
    assert widgets.get({"pk": "a"}) is not None
    assert gadgets.get({"pk": "b"}) is not None


def test_a_repeated_client_request_token_is_the_same_transaction(widgets: Widgets) -> None:
    """The idempotency token makes a retry after an ambiguous failure safe."""
    actions = [widgets.put_action({"pk": "once", "n": 1})]
    transact_write(actions, client_request_token="token-0001")
    transact_write(actions, client_request_token="token-0001")
    assert widgets.get({"pk": "once"}) is not None


def test_a_non_cancellation_client_error_is_not_swallowed(widgets: Widgets) -> None:
    """Only a cancellation becomes `TransactionCanceled`; every other fault propagates."""
    from botocore.exceptions import ClientError

    with pytest.raises(ClientError) as caught:
        transact_write([{"Put": {"TableName": "no-such-table", "Item": {"pk": "x"}}}])
    assert not isinstance(caught.value, TransactionCanceled)
