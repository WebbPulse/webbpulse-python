"""A thin repository base over a DynamoDB table. No ORM.

The repository layer is the seam the platform migration keeps: a domain service talks to a
`Repository`, and everything below it (the boto3 resource, pagination, Decimal handling,
TTL arithmetic) lives here rather than being rewritten per domain.

What this deliberately is not: an ORM, a single table abstraction, or a query builder. It
does not know about entities, it does not map classes to items, and it does not hide
`KeyConditionExpression`. Callers pass DynamoDB's own vocabulary and get plain dicts back.
The value is in the parts that are genuinely repetitive and genuinely easy to get wrong,
which is pagination, float rejection, and remembering that a TTL is a Unix timestamp in
seconds rather than an ISO string.

Nothing here opens a connection at import. The resource is created on first use and cached
per `(region, endpoint)`, so importing a repository module is free.
"""

from __future__ import annotations

import os
from collections.abc import Iterator, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:  # pragma: no cover - typing only
    from mypy_boto3_dynamodb.service_resource import DynamoDBServiceResource, Table

__all__ = [
    "TABLE_PREFIX_ENV",
    "Page",
    "Repository",
    "encode_numbers",
    "now_iso",
    "reset_resource_cache",
    "table_name",
    "ttl_at",
    "ttl_in",
]

# Terraform names every table `<prefix>-<logical name>`, and the prefix arrives here.
TABLE_PREFIX_ENV: Final = "DYNAMODB_TABLE_PREFIX"

# DynamoDB's own cap on a BatchGetItem/scan page is separate; this is just a sane default
# for a query page so an unbounded `query` does not pull an entire partition into memory.
DEFAULT_PAGE_SIZE: Final = 100

type Item = dict[str, Any]
type Key = Mapping[str, Any]


def now_iso() -> str:
    """The current UTC time as an ISO 8601 string with a `Z` suffix.

    Both applications store timestamps as sortable ISO strings rather than epoch numbers,
    because a range key that reads as a date is worth more in the console than the few
    bytes it costs. `datetime.now(UTC).isoformat()` yields `+00:00`; this normalises to
    `Z` so every item in the estate sorts and compares identically.
    """
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def ttl_at(moment: datetime) -> int:
    """Convert an aware datetime to the integer epoch seconds a DynamoDB TTL wants.

    DynamoDB's TTL attribute must be a Number holding Unix epoch **seconds**. Milliseconds
    are the classic mistake: a millisecond value is a timestamp roughly fifty thousand
    years out, so the item is simply never expired and the table grows forever.
    """
    if moment.tzinfo is None:
        raise ValueError("ttl_at requires an aware datetime; a naive one is ambiguous.")
    return int(moment.timestamp())


def ttl_in(seconds: float) -> int:
    """Epoch seconds `seconds` from now, for a TTL attribute.

    Note that DynamoDB deletes expired items on its own schedule, typically within a couple
    of days of expiry, so a TTL is a storage reclaim mechanism and never an access control.
    Anything that must stop being readable at a deadline has to check the deadline on read.
    """
    return ttl_at(datetime.now(UTC) + timedelta(seconds=seconds))


def table_name(logical_name: str, prefix: str | None = None) -> str:
    """Build the physical table name from the logical one and the environment prefix.

    `table_name("rate-limits")` with `DYNAMODB_TABLE_PREFIX=webbpulse-staging` gives
    `webbpulse-staging-rate-limits`, which is what the Terraform `dynamodb-tables` module
    creates. An empty prefix returns the logical name unchanged, which is what local
    development and moto want.
    """
    resolved = prefix if prefix is not None else os.environ.get(TABLE_PREFIX_ENV, "")
    return f"{resolved}-{logical_name}" if resolved else logical_name


def encode_numbers(value: Any) -> Any:
    """Recursively convert `float` to `Decimal` so an item is writable.

    boto3's DynamoDB resource refuses `float` outright rather than silently rounding it,
    which is the right call but produces a `TypeError` deep inside the serializer that says
    nothing about which field was at fault. Passing user supplied JSON through this first
    turns that into a working write.

    The conversion goes via `str` rather than `Decimal(float)` on purpose: `Decimal(0.1)`
    is 0.1000000000000000055511151231257827, while `Decimal("0.1")` is 0.1.
    """
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, Mapping):
        return {k: encode_numbers(v) for k, v in value.items()}
    # str and bytes are Sequences; excluding them here is not optional.
    if isinstance(value, (list, tuple)):
        return [encode_numbers(v) for v in value]
    return value


class Page:
    """One page of query or scan results plus the cursor for the next one.

    `last_evaluated_key` is `None` exactly when the result set is exhausted. An empty
    `items` list with a non-`None` cursor is normal and does **not** mean "no results":
    DynamoDB applies a `FilterExpression` after reading the page, so a filtered query can
    return zero items several pages in a row and still have matches further on. Treating an
    empty page as the end is one of the most common DynamoDB bugs, which is why
    `iter_query` exists below and why callers should prefer it.
    """

    __slots__ = ("count", "items", "last_evaluated_key", "scanned_count")

    def __init__(
        self,
        items: list[Item],
        last_evaluated_key: Item | None,
        count: int,
        scanned_count: int,
    ) -> None:
        self.items = items
        self.last_evaluated_key = last_evaluated_key
        self.count = count
        self.scanned_count = scanned_count

    @property
    def has_more(self) -> bool:
        """Whether another page exists. See the note above about empty pages."""
        return self.last_evaluated_key is not None

    def __repr__(self) -> str:
        return (
            f"Page(items={len(self.items)}, has_more={self.has_more}, "
            f"count={self.count}, scanned_count={self.scanned_count})"
        )


@lru_cache(maxsize=4)
def _resource(region_name: str | None, endpoint_url: str | None) -> DynamoDBServiceResource:
    """Create the DynamoDB service resource once per process, per region and endpoint.

    Cached because client construction parses botocore's JSON service model, which costs
    real time on a cold start and nothing at all afterwards. `endpoint_url` is here for
    DynamoDB Local during local development.
    """
    import boto3  # Imported lazily: the base install has no boto3.

    resource: DynamoDBServiceResource = boto3.resource(
        "dynamodb", region_name=region_name, endpoint_url=endpoint_url
    )
    return resource


def reset_resource_cache() -> None:
    """Clear the cached resource. Tests need this between moto contexts."""
    _resource.cache_clear()


class Repository:
    """Typed helpers over one DynamoDB table.

    Subclass it per domain and add the queries that domain needs::

        class RateLimitRepository(Repository):
            logical_name = "rate-limits"

            def window(self, identity: str) -> dict | None:
                return self.get({"pk": identity})

    The table resource is resolved on first access, not in `__init__`, so constructing a
    repository at module scope stays free.
    """

    #: Logical table name; the environment prefix is applied by `table_name`.
    logical_name: str = ""

    def __init__(
        self,
        logical_name: str | None = None,
        *,
        prefix: str | None = None,
        region_name: str | None = None,
        endpoint_url: str | None = None,
    ) -> None:
        resolved = logical_name or self.logical_name
        if not resolved:
            raise ValueError(
                "A Repository needs a logical table name, as a class attribute or an argument."
            )
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

    # ---- reads -------------------------------------------------------------------

    def get(self, key: Key, *, consistent: bool = False) -> Item | None:
        """Fetch one item by its full primary key, or `None` when it is absent.

        `consistent=True` doubles the read cost and is only meaningful on the base table,
        never on a global secondary index, where DynamoDB rejects it outright.
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

        `limit` bounds the items DynamoDB *reads*, not the items it returns after a filter,
        which is why the returned page can hold fewer items than `limit` and still have
        more to come. Use `iter_query` unless you are genuinely paginating for a client.
        """
        kwargs: dict[str, Any] = {
            "KeyConditionExpression": key_condition,
            "Limit": limit,
            "ScanIndexForward": ascending,
        }
        if index_name is not None:
            kwargs["IndexName"] = index_name
        else:
            # ConsistentRead is invalid against a GSI, so only send it on the base table.
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

        This is the method to reach for by default. It handles the empty-page-with-a-cursor
        case correctly, and `max_items` bounds the work so an unfiltered call cannot walk an
        entire partition by accident.
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

    # ---- writes ------------------------------------------------------------------

    def put(self, item: Item, *, condition: Any | None = None) -> None:
        """Write one item, converting any `float` to `Decimal` on the way.

        Pass `condition=Attr("pk").not_exists()` to make the write a create rather than an
        upsert; DynamoDB then raises `ConditionalCheckFailedException` on a clash.
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

        `expression_names` exists for reserved words; DynamoDB's reserved word list is long
        and includes things like `name`, `status` and `count`, so an update that fails with
        a syntax error on an innocuous attribute almost always needs one.
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
        # The stubs declare Attributes as always present. DynamoDB omits it entirely
        # when ReturnValues is NONE, so the runtime check stays despite the type.
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

        BatchWriteItem has no conditional form, so this is an unconditional upsert of every
        item. It also does not return the old values, and unprocessed items are retried by
        the writer rather than surfaced.
        """
        with self.table.batch_writer() as batch:
            for item in items:
                batch.put_item(Item=encode_numbers(item))
