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
    "TABLE_PREFIX_ENV",
    "ConditionFailed",
    "DynamoError",
    "ItemNotFound",
    "Page",
    "Repository",
    "TransactionCanceled",
    "encode_numbers",
    "now_iso",
    "reset_resource_cache",
    "table_name",
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
