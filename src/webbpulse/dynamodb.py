"""A thin repository base over a DynamoDB table. No ORM.

`Repository` wraps one table with pagination, float-to-Decimal encoding and TTL helpers,
and callers keep passing DynamoDB's own vocabulary. Nothing opens a connection at import.
"""

from __future__ import annotations

import os
from collections.abc import Iterator, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:  # pragma: no cover
    from mypy_boto3_dynamodb.service_resource import DynamoDBServiceResource, Table

__all__ = [
    "BATCH_GET_LIMIT",
    "TABLE_PREFIX_ENV",
    "TRANSACT_WRITE_LIMIT",
    "UNPROCESSED_RETRY_ATTEMPTS",
    "UNPROCESSED_RETRY_BASE_DELAY",
    "ConditionFailed",
    "DynamoError",
    "ItemNotFound",
    "Page",
    "Repository",
    "TransactionCanceled",
    "UnprocessedItems",
    "encode_numbers",
    "now_iso",
    "reset_resource_cache",
    "table_name",
    "transact_write",
    "ttl_at",
    "ttl_in",
]


class DynamoError(Exception):
    """Base class for every error the repository layer raises.

    A service's own hierarchy can subclass this so one `exception_map` entry or one call to
    `install_dynamodb_error_handlers` covers every type under it.
    """


class ItemNotFound(DynamoError):
    """No item exists in `table` under `key`.

    The table name and the key are recorded for the log, never for the response body, because
    a key can be a user id or an email address.
    """

    def __init__(self, table: str, key: Mapping[str, Any] | None = None) -> None:
        """Record the table and the key that had no item."""
        self.table = table
        self.key = dict(key) if key is not None else None
        super().__init__(f"{table}: no item with key {self.key}")


class UnprocessedItems(DynamoError):
    """A batch left keys or items unprocessed after the retry cap was reached.

    Raised rather than looping forever or silently returning a short result: sustained
    throttling can leave the same keys unprocessed on every attempt, so the caller has to
    learn that the read or write was incomplete.
    """

    def __init__(self, table: str, count: int, attempts: int) -> None:
        """Record the table, how many keys or items were left, and how many attempts ran."""
        self.table = table
        self.count = count
        self.attempts = attempts
        super().__init__(f"{table}: {count} item(s) still unprocessed after {attempts} attempts")


class ConditionFailed(DynamoError):
    """A conditional write was rejected because its condition did not hold.

    The ordinary outcome of losing a race on an optimistic create or an optimistic update, so
    it renders as a 409 rather than a fault.
    """

    def __init__(self, table: str, condition: str = "", key: Mapping[str, Any] | None = None) -> None:
        """Record the table, the condition expression, and the key it guarded."""
        self.table = table
        self.condition = condition
        self.key = dict(key) if key is not None else None
        super().__init__(f"{table}: condition failed ({condition}) for key {self.key}")


class TransactionCanceled(DynamoError):
    """A transactional write was cancelled, carrying DynamoDB's per-item reasons.

    Inspect `conditional_check_failed` rather than assuming: a cancellation caused by a failed
    condition is a caller-visible conflict, and every other cause is a real fault.
    """

    def __init__(self, reasons: Sequence[Mapping[str, Any]] | None = None) -> None:
        """Record DynamoDB's cancellation reasons, one per item in the transaction."""
        self.reasons = [dict(reason) for reason in reasons or ()]
        super().__init__(f"transaction canceled: {self.reasons}")

    @property
    def conditional_check_failed(self) -> bool:
        """True when any item was cancelled by a failed conditional check."""
        return any(reason.get("Code") == "ConditionalCheckFailed" for reason in self.reasons)


TABLE_PREFIX_ENV: Final = "DYNAMODB_TABLE_PREFIX"

DEFAULT_PAGE_SIZE: Final = 100

BATCH_GET_LIMIT: Final = 100
"""DynamoDB's hard cap on the keys one `BatchGetItem` accepts."""

TRANSACT_WRITE_LIMIT: Final = 100
"""DynamoDB's hard cap on the actions one `TransactWriteItems` accepts."""

UNPROCESSED_RETRY_ATTEMPTS: Final = 5
"""How many times an unprocessed batch is retried before the call gives up.

Bounded on purpose: DynamoDB can return the same keys unprocessed indefinitely under
sustained throttling, so an unbounded loop is a hang rather than a retry.
"""

UNPROCESSED_RETRY_BASE_DELAY: Final = 0.05
"""The first backoff pause, in seconds. Each attempt doubles it."""

_CONDITIONAL_CHECK_FAILED: Final = "ConditionalCheckFailed"

_TRANSACTION_CANCELED: Final = "TransactionCanceledException"

type Item = dict[str, Any]
type Key = Mapping[str, Any]


def now_iso() -> str:
    """The current UTC time as an ISO 8601 string normalised to a `Z` suffix."""
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def ttl_at(moment: datetime) -> int:
    """Convert an aware datetime to the integer epoch seconds a DynamoDB TTL wants.

    A naive datetime is rejected, since its offset is ambiguous.
    """
    if moment.tzinfo is None:
        raise ValueError("ttl_at requires an aware datetime; a naive one is ambiguous.")
    return int(moment.timestamp())


def ttl_in(seconds: float) -> int:
    """Epoch seconds `seconds` from now, for a TTL attribute.

    DynamoDB deletes expired items on its own schedule, so a TTL reclaims storage and is
    never an access control.
    """
    return ttl_at(datetime.now(UTC) + timedelta(seconds=seconds))


def table_name(logical_name: str, prefix: str | None = None) -> str:
    """Build the physical table name from the logical one and the environment prefix.

    An empty prefix returns the logical name unchanged, which is what local development
    and moto want.
    """
    resolved = prefix if prefix is not None else os.environ.get(TABLE_PREFIX_ENV, "")
    return f"{resolved}-{logical_name}" if resolved else logical_name


def encode_numbers(value: Any) -> Any:
    """Recursively convert `float` to `Decimal` so an item is writable.

    boto3's DynamoDB resource refuses `float` outright. The conversion goes via `str`, so
    0.1 stays 0.1 rather than picking up binary float error.
    """
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, Mapping):
        return {k: encode_numbers(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [encode_numbers(v) for v in value]
    return value


class Page:
    """One page of query or scan results plus the cursor for the next one.

    `last_evaluated_key` is `None` exactly when the result set is exhausted; an empty
    `items` list with a cursor still set is normal after a `FilterExpression`.
    """

    __slots__ = ("count", "items", "last_evaluated_key", "scanned_count")

    def __init__(
        self,
        items: list[Item],
        last_evaluated_key: Item | None,
        count: int,
        scanned_count: int,
    ) -> None:
        """Store one page of results and its cursor."""
        self.items = items
        self.last_evaluated_key = last_evaluated_key
        self.count = count
        self.scanned_count = scanned_count

    @property
    def has_more(self) -> bool:
        """Whether another page exists, which an empty page can still report as true."""
        return self.last_evaluated_key is not None

    def __repr__(self) -> str:
        """Summarise the page sizes without dumping every item."""
        return (
            f"Page(items={len(self.items)}, has_more={self.has_more}, "
            f"count={self.count}, scanned_count={self.scanned_count})"
        )


def _chunks(values: Sequence[Any], size: int) -> Iterator[list[Any]]:
    """Split `values` into consecutive lists of at most `size`."""
    for start in range(0, len(values), size):
        yield list(values[start : start + size])


def _apply_condition(action: dict[str, Any], condition: Any) -> None:
    """Render `condition` into `action` as an expression plus its placeholder maps.

    A `boto3.dynamodb.conditions` object is translated by the resource layer, which for a
    transaction action hoists its placeholders to the top of the request where the API
    rejects them. Building the expression here keeps the names and values inside the action
    they belong to. A condition that is already a string is used as it stands.
    """
    if isinstance(condition, str):
        action["ConditionExpression"] = condition
        return

    from boto3.dynamodb.conditions import ConditionExpressionBuilder

    built = ConditionExpressionBuilder().build_expression(condition, is_key_condition=False)
    action["ConditionExpression"] = built.condition_expression
    if built.attribute_name_placeholders:
        names = dict(action.get("ExpressionAttributeNames", {}))
        names.update(built.attribute_name_placeholders)
        action["ExpressionAttributeNames"] = names
    if built.attribute_value_placeholders:
        values = dict(action.get("ExpressionAttributeValues", {}))
        values.update(encode_numbers(built.attribute_value_placeholders))
        action["ExpressionAttributeValues"] = values


def transact_write(
    actions: Sequence[Mapping[str, Any]],
    *,
    region_name: str | None = None,
    endpoint_url: str | None = None,
    client_request_token: str | None = None,
) -> None:
    """Apply `actions` as one all-or-nothing `TransactWriteItems`.

    Each action is DynamoDB's own shape, a single-key mapping of `Put`, `Update`, `Delete`
    or `ConditionCheck` to its arguments; `Repository.put_action` and its siblings build
    them. An empty sequence is a no-op rather than an error, so a caller that assembled
    actions conditionally need not check.

    Args:
        actions: The transaction's actions, at most `TRANSACT_WRITE_LIMIT` of them.
        region_name: Region for the client, defaulting to the ambient configuration.
        endpoint_url: Endpoint for the client, for DynamoDB Local.
        client_request_token: An idempotency token. DynamoDB treats a repeat of the same
            token within ten minutes as the same transaction, which makes a retry after an
            ambiguous network failure safe.

    Raises:
        ValueError: When more actions are given than DynamoDB accepts. Raised before the
            call, since the service would reject the whole transaction anyway.
        TransactionCanceled: When DynamoDB cancelled the transaction, carrying the
            per-action reasons. Check `conditional_check_failed` to tell an ordinary lost
            race from a real fault.
    """
    if not actions:
        return
    if len(actions) > TRANSACT_WRITE_LIMIT:
        raise ValueError(f"transact_write accepts at most {TRANSACT_WRITE_LIMIT} actions, got {len(actions)}.")

    from botocore.exceptions import ClientError

    kwargs: dict[str, Any] = {"TransactItems": [dict(action) for action in actions]}
    if client_request_token is not None:
        kwargs["ClientRequestToken"] = client_request_token

    client = _resource(region_name, endpoint_url).meta.client
    try:
        client.transact_write_items(**kwargs)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != _TRANSACTION_CANCELED:
            raise
        reasons = exc.response.get("CancellationReasons", [])
        raise TransactionCanceled(reasons) from exc


@lru_cache(maxsize=4)
def _resource(region_name: str | None, endpoint_url: str | None) -> DynamoDBServiceResource:
    """Create the DynamoDB service resource once per process, per region and endpoint.

    `endpoint_url` is here for DynamoDB Local during local development.
    """
    import boto3

    resource: DynamoDBServiceResource = boto3.resource("dynamodb", region_name=region_name, endpoint_url=endpoint_url)
    return resource


def reset_resource_cache() -> None:
    """Clear the cached resource. Tests need this between moto contexts."""
    _resource.cache_clear()


class Repository:
    """Typed helpers over one DynamoDB table.

    Subclass it per domain and add the queries that domain needs. The table resource is
    resolved on first access, so constructing a repository at module scope stays free.
    """

    logical_name: str = ""

    def __init__(
        self,
        logical_name: str | None = None,
        *,
        prefix: str | None = None,
        region_name: str | None = None,
        endpoint_url: str | None = None,
    ) -> None:
        """Resolve the physical table name and defer creating the table resource."""
        resolved = logical_name or self.logical_name
        if not resolved:
            raise ValueError("A Repository needs a logical table name, as a class attribute or an argument.")
        self.logical_name = resolved
        self.table_name = table_name(resolved, prefix)
        self._region_name = region_name
        self._endpoint_url = endpoint_url
        self._table: Table | None = None

    @property
    def table(self) -> Table:
        """The boto3 `Table` resource, created on first use."""
        if self._table is None:
            self._table = _resource(self._region_name, self._endpoint_url).Table(self.table_name)
        return self._table

    def get(self, key: Key, *, consistent: bool = False) -> Item | None:
        """Fetch one item by its full primary key, or `None` when it is absent.

        `consistent=True` doubles the read cost and is rejected against a secondary index.
        """
        response = self.table.get_item(Key=dict(key), ConsistentRead=consistent)
        item = response.get("Item")
        return dict(item) if item is not None else None

    def query(
        self,
        key_condition: Any,
        *,
        index_name: str | None = None,
        filter_expression: Any | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        start_key: Item | None = None,
        ascending: bool = True,
        consistent: bool = False,
        projection: str | None = None,
    ) -> Page:
        """Run one query and return a single `Page`.

        `limit` bounds the items DynamoDB reads, not the items left after a filter, so
        prefer `iter_query` unless you are paginating for a client.
        """
        kwargs: dict[str, Any] = {
            "KeyConditionExpression": key_condition,
            "Limit": limit,
            "ScanIndexForward": ascending,
        }
        if index_name is not None:
            kwargs["IndexName"] = index_name
        else:
            kwargs["ConsistentRead"] = consistent
        if filter_expression is not None:
            kwargs["FilterExpression"] = filter_expression
        if start_key is not None:
            kwargs["ExclusiveStartKey"] = start_key
        if projection is not None:
            kwargs["ProjectionExpression"] = projection

        response = self.table.query(**kwargs)
        return Page(
            items=[dict(item) for item in response.get("Items", [])],
            last_evaluated_key=response.get("LastEvaluatedKey"),
            count=int(response.get("Count", 0)),
            scanned_count=int(response.get("ScannedCount", 0)),
        )

    def iter_query(
        self,
        key_condition: Any,
        *,
        max_items: int | None = None,
        page_size: int = DEFAULT_PAGE_SIZE,
        **kwargs: Any,
    ) -> Iterator[Item]:
        """Yield every matching item, following `LastEvaluatedKey` across pages.

        The default read path: it handles empty filtered pages, and `max_items` bounds the
        work so an unfiltered call cannot walk an entire partition.
        """
        yielded = 0
        start_key: Item | None = kwargs.pop("start_key", None)
        while True:
            page = self.query(key_condition, limit=page_size, start_key=start_key, **kwargs)
            for item in page.items:
                yield item
                yielded += 1
                if max_items is not None and yielded >= max_items:
                    return
            if not page.has_more:
                return
            start_key = page.last_evaluated_key

    def put(self, item: Item, *, condition: Any | None = None) -> None:
        """Write one item, converting any `float` to `Decimal` on the way.

        Pass a `condition` such as `Attr("pk").not_exists()` to make the write a create
        rather than an upsert.
        """
        kwargs: dict[str, Any] = {"Item": encode_numbers(item)}
        if condition is not None:
            kwargs["ConditionExpression"] = condition
        self.table.put_item(**kwargs)

    def update(
        self,
        key: Key,
        *,
        update_expression: str,
        expression_values: Mapping[str, Any] | None = None,
        expression_names: Mapping[str, str] | None = None,
        condition: Any | None = None,
        return_values: str = "NONE",
    ) -> Item | None:
        """Apply an `UpdateExpression` to one item and optionally return the result.

        `expression_names` exists for DynamoDB reserved words such as `name` or `status`.
        """
        kwargs: dict[str, Any] = {
            "Key": dict(key),
            "UpdateExpression": update_expression,
            "ReturnValues": return_values,
        }
        if expression_values:
            kwargs["ExpressionAttributeValues"] = encode_numbers(dict(expression_values))
        if expression_names:
            kwargs["ExpressionAttributeNames"] = dict(expression_names)
        if condition is not None:
            kwargs["ConditionExpression"] = condition

        response = self.table.update_item(**kwargs)
        attributes = response.get("Attributes")
        if attributes is None:
            return None
        return dict(attributes)

    def delete(self, key: Key, *, condition: Any | None = None) -> None:
        """Delete one item by primary key. Deleting an absent item is not an error."""
        kwargs: dict[str, Any] = {"Key": dict(key)}
        if condition is not None:
            kwargs["ConditionExpression"] = condition
        self.table.delete_item(**kwargs)

    def put_many(self, items: Sequence[Item]) -> None:
        """Write many items through a batch writer, which handles retries and chunking.

        BatchWriteItem has no conditional form, so this is an unconditional upsert.
        """
        with self.table.batch_writer() as batch:
            for item in items:
                batch.put_item(Item=encode_numbers(item))

    def delete_many(self, keys: Sequence[Key]) -> int:
        """Delete many items through a batch writer, returning how many were requested.

        BatchWriteItem has no conditional form and reports nothing about what existed, so the
        count is the number of keys sent rather than the number of rows that were there.
        """
        if not keys:
            return 0
        with self.table.batch_writer() as batch:
            for key in keys:
                batch.delete_item(Key=dict(key))
        return len(keys)

    def scan(
        self,
        *,
        filter_expression: Any | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        start_key: Item | None = None,
        index_name: str | None = None,
        consistent: bool = False,
        projection: str | None = None,
        segment: int | None = None,
        total_segments: int | None = None,
    ) -> Page:
        """Read one page of a full table or index scan.

        A scan reads every item and charges for every item read, filtered or not, so reach
        for `query` whenever a key condition can express the same thing. `segment` and
        `total_segments` together run one worker of a parallel scan.

        Raises:
            ValueError: When only one of `segment` and `total_segments` is given, which
                DynamoDB rejects.
        """
        if (segment is None) != (total_segments is None):
            raise ValueError("A parallel scan needs both segment and total_segments, or neither.")

        kwargs: dict[str, Any] = {"Limit": limit}
        if index_name is not None:
            kwargs["IndexName"] = index_name
        else:
            kwargs["ConsistentRead"] = consistent
        if filter_expression is not None:
            kwargs["FilterExpression"] = filter_expression
        if start_key is not None:
            kwargs["ExclusiveStartKey"] = start_key
        if projection is not None:
            kwargs["ProjectionExpression"] = projection
        if segment is not None:
            kwargs["Segment"] = segment
            kwargs["TotalSegments"] = total_segments

        response = self.table.scan(**kwargs)
        return Page(
            items=[dict(item) for item in response.get("Items", [])],
            last_evaluated_key=response.get("LastEvaluatedKey"),
            count=int(response.get("Count", 0)),
            scanned_count=int(response.get("ScannedCount", 0)),
        )

    def iter_scan(
        self,
        *,
        max_items: int | None = None,
        page_size: int = DEFAULT_PAGE_SIZE,
        **kwargs: Any,
    ) -> Iterator[Item]:
        """Yield every item in the table or index, following `LastEvaluatedKey` across pages.

        The scan counterpart of `iter_query`, and the reason neither product should keep its
        own paging loop: an empty page with a cursor still set is normal after a filter and
        is the bug a hand-rolled loop reliably has. `max_items` bounds the work, since an
        unbounded scan of a large table is rarely what was wanted.
        """
        yielded = 0
        start_key: Item | None = kwargs.pop("start_key", None)
        while True:
            page = self.scan(limit=page_size, start_key=start_key, **kwargs)
            for item in page.items:
                yield item
                yielded += 1
                if max_items is not None and yielded >= max_items:
                    return
            if not page.has_more:
                return
            start_key = page.last_evaluated_key

    def batch_get(
        self,
        keys: Sequence[Key],
        *,
        consistent: bool = False,
        projection: str | None = None,
        max_attempts: int = UNPROCESSED_RETRY_ATTEMPTS,
    ) -> list[Item]:
        """Fetch many items by primary key, chunked, retried with backoff, and capped.

        `BatchGetItem` takes at most `BATCH_GET_LIMIT` keys and may return some of them
        under `UnprocessedKeys` rather than failing, which is DynamoDB shedding load. Those
        keys are retried with exponential backoff, and after `max_attempts` the call raises
        `UnprocessedItems` rather than looping: under sustained throttling the same keys can
        come back unprocessed forever, so an uncapped loop is a hang, not a retry.

        Order is not preserved and a key with no item is simply absent from the result, the
        same way `get` answers `None`.

        Raises:
            ValueError: When `max_attempts` is below one.
            UnprocessedItems: When keys were still unprocessed after the last attempt.
        """
        if max_attempts < 1:
            raise ValueError(f"max_attempts must be at least 1, got {max_attempts}.")
        if not keys:
            return []

        import time

        client = _resource(self._region_name, self._endpoint_url).meta.client
        found: list[Item] = []
        for chunk in _chunks([dict(key) for key in keys], BATCH_GET_LIMIT):
            request: dict[str, Any] = {self.table_name: {"Keys": chunk, "ConsistentRead": consistent}}
            if projection is not None:
                request[self.table_name]["ProjectionExpression"] = projection

            for attempt in range(max_attempts):
                response = client.batch_get_item(RequestItems=request)
                found.extend(dict(item) for item in response.get("Responses", {}).get(self.table_name, []))

                unprocessed: dict[str, Any] = dict(response.get("UnprocessedKeys", {}))
                pending = list(unprocessed.get(self.table_name, {}).get("Keys", []))
                if not pending:
                    break
                if attempt == max_attempts - 1:
                    raise UnprocessedItems(self.table_name, len(pending), max_attempts)
                time.sleep(UNPROCESSED_RETRY_BASE_DELAY * (2**attempt))
                request = dict(unprocessed)
        return found

    def put_action(self, item: Item, *, condition: Any | None = None) -> dict[str, Any]:
        """A `TransactWriteItems` Put action for `item`, for `transact_write`."""
        action: dict[str, Any] = {"TableName": self.table_name, "Item": encode_numbers(item)}
        if condition is not None:
            _apply_condition(action, condition)
        return {"Put": action}

    def delete_action(self, key: Key, *, condition: Any | None = None) -> dict[str, Any]:
        """A `TransactWriteItems` Delete action for `key`, for `transact_write`."""
        action: dict[str, Any] = {"TableName": self.table_name, "Key": dict(key)}
        if condition is not None:
            _apply_condition(action, condition)
        return {"Delete": action}

    def update_action(
        self,
        key: Key,
        *,
        update_expression: str,
        expression_values: Mapping[str, Any] | None = None,
        expression_names: Mapping[str, str] | None = None,
        condition: Any | None = None,
    ) -> dict[str, Any]:
        """A `TransactWriteItems` Update action for `key`, for `transact_write`."""
        action: dict[str, Any] = {
            "TableName": self.table_name,
            "Key": dict(key),
            "UpdateExpression": update_expression,
        }
        if expression_values:
            action["ExpressionAttributeValues"] = encode_numbers(dict(expression_values))
        if expression_names:
            action["ExpressionAttributeNames"] = dict(expression_names)
        if condition is not None:
            _apply_condition(action, condition)
        return {"Update": action}

    def condition_check(self, key: Key, *, condition: Any) -> dict[str, Any]:
        """A `TransactWriteItems` ConditionCheck on `key`, for `transact_write`.

        The action that asserts something about an item the transaction does not write,
        which is how a uniqueness reservation is held across a multi-item write.
        """
        action: dict[str, Any] = {"TableName": self.table_name, "Key": dict(key)}
        _apply_condition(action, condition)
        return {"ConditionCheck": action}

    def transact_write(
        self,
        actions: Sequence[Mapping[str, Any]],
        *,
        client_request_token: str | None = None,
    ) -> None:
        """Run `actions` as one transaction against this repository's client configuration.

        The same call as the module-level `transact_write`, reached from a repository so the
        region and endpoint match the table's. Actions may name other tables.
        """
        transact_write(
            actions,
            region_name=self._region_name,
            endpoint_url=self._endpoint_url,
            client_request_token=client_request_token,
        )
