"""A thin repository base over a DynamoDB table. No ORM.

`Repository` wraps one table with pagination, float-to-Decimal encoding and TTL helpers,
and callers keep passing DynamoDB's own vocabulary. Nothing opens a connection at import.
"""

from __future__ import annotations

import os
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from functools import lru_cache, wraps
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:  # pragma: no cover
    from mypy_boto3_dynamodb.service_resource import DynamoDBServiceResource, Table

__all__ = [
    "BATCH_GET_LIMIT",
    "TABLE_PREFIX_ENV",
    "TRANSACT_WRITE_LIMIT",
    "ULID_LENGTH",
    "UNPROCESSED_RETRY_ATTEMPTS",
    "UNPROCESSED_RETRY_BASE_DELAY",
    "WRITE_METHODS",
    "ConditionFailed",
    "DynamoError",
    "IdempotencyStore",
    "ItemNotFound",
    "Page",
    "ReadOnlyTable",
    "Repository",
    "TransactionCanceled",
    "UnprocessedItems",
    "encode_numbers",
    "new_ulid",
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

ULID_LENGTH: Final = 26
"""How many characters a ULID renders as, fixed so string ordering is time ordering.

Twenty-six base32 digits hold 130 bits for a 128-bit value, so the leading digit carries only
the top two bits and never exceeds `7`. Encoding from 125 bits instead would drop the low
three and break ordering inside a millisecond.
"""

_CROCKFORD_BASE32: Final = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
"""Crockford's alphabet, which drops I, L, O and U so a transcribed id cannot be misread."""

_ULID_RANDOM_BITS: Final = 80

_ULID_RANDOM_BYTES: Final = _ULID_RANDOM_BITS // 8

_ULID_MAX_TIMESTAMP: Final = 1 << 48

_CONDITIONAL_CHECK_FAILED: Final = "ConditionalCheckFailed"

_CONDITIONAL_CHECK_FAILED_EXCEPTION: Final = "ConditionalCheckFailedException"

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


def new_ulid(moment: datetime | None = None) -> str:
    """A ULID: 26 Crockford base32 characters that sort lexicographically by time.

    The first 48 bits are the millisecond timestamp and the remaining 80 are random, so
    string ordering is time ordering and two ids minted in the same millisecond still differ.
    That is what a UUID4 range key cannot do, and it is why a sort key built from a ULID needs
    no separate timestamp attribute.

    Implemented here rather than taken from a `ulid` package, since the whole encoding is
    twelve lines and the package deliberately carries no dependency it does not need. Crockford
    base32 excludes I, L, O and U, so a transcribed id cannot be misread.

    Args:
        moment: The aware datetime the id records, defaulting to now. A naive one is rejected,
            the way `ttl_at` rejects one, since its offset is ambiguous.

    Raises:
        ValueError: When `moment` is naive, or falls outside the 48 bits the format holds.
    """
    when = moment if moment is not None else datetime.now(UTC)
    if when.tzinfo is None:
        raise ValueError("new_ulid requires an aware datetime; a naive one is ambiguous.")
    milliseconds = int(when.timestamp() * 1000)
    if not 0 <= milliseconds < _ULID_MAX_TIMESTAMP:
        raise ValueError(f"new_ulid takes a moment inside the 48-bit ULID epoch, got {when.isoformat()}.")
    value = (milliseconds << _ULID_RANDOM_BITS) | int.from_bytes(os.urandom(_ULID_RANDOM_BYTES), "big")
    shifts = range((ULID_LENGTH - 1) * 5, -1, -5)
    digits = [_CROCKFORD_BASE32[(value >> shift) & 0x1F] for shift in shifts]
    return "".join(digits)


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


class ReadOnlyTable(PermissionError):
    """A write reached a repository built with `read_only=True`.

    Raised in tests and local runs, so a code path that writes to a table the function only
    holds a read grant on fails the suite instead of returning an AccessDenied in staging.
    The message names the table, the method, and whatever hint the caller registered. It is
    a `PermissionError` and deliberately not a `DynamoError`, so a broad data-layer handler
    cannot swallow the mistake it exists to expose.
    """

    def __init__(self, table: str, method: str, hint: str | None = None) -> None:
        """Name the table and the refused write, with the caller's hint when there is one."""
        message = f"{method}() on the {table!r} table, which this caller only reads."
        if hint:
            message = f"{message} {hint}"
        super().__init__(message)
        self.table = table
        self.method = method
        self.hint = hint


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


def _describe_condition(condition: Any) -> str:
    """Render `condition` as a short string for a `ConditionFailed` message and log.

    A `boto3.dynamodb.conditions` object has no useful `str`, so it is built into its
    expression text. Building it can only be best effort, since a caller may pass anything
    the resource layer accepts, and a failure to describe a condition must never replace the
    conflict the caller actually needs to see.
    """
    if isinstance(condition, str):
        return condition
    try:
        from boto3.dynamodb.conditions import ConditionExpressionBuilder

        built = ConditionExpressionBuilder().build_expression(condition, is_key_condition=False)
    except Exception:
        return repr(condition)
    return str(built.condition_expression)


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

    `read_only=True` mirrors a function whose IAM policy grants only reads on the table:
    reads go through untouched and every write in `WRITE_METHODS` raises `ReadOnlyTable`
    before a client is built, so the mismatch fails a unit test rather than surfacing as a
    DynamoDB AccessDenied in staging.
    """

    logical_name: str = ""

    def __init__(
        self,
        logical_name: str | None = None,
        *,
        prefix: str | None = None,
        region_name: str | None = None,
        endpoint_url: str | None = None,
        read_only: bool = False,
        read_only_hint: str | None = None,
    ) -> None:
        """Resolve the physical table name and defer creating the table resource.

        `read_only_hint` is appended to the `ReadOnlyTable` message, so the product can say
        which registry entry and which Terraform grant have to move together.
        """
        resolved = logical_name or self.logical_name
        if not resolved:
            raise ValueError("A Repository needs a logical table name, as a class attribute or an argument.")
        self.logical_name = resolved
        self.table_name = table_name(resolved, prefix)
        self._region_name = region_name
        self._endpoint_url = endpoint_url
        self._read_only = read_only
        self._read_only_hint = read_only_hint
        self._table: Table | None = None

    @property
    def read_only(self) -> bool:
        """Whether this repository refuses writes."""
        return self._read_only

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

    @contextmanager
    def _conditional(self, condition: Any, key: Key | None) -> Iterator[None]:
        """Turn a rejected condition inside the block into `ConditionFailed`.

        Every conditional write goes through here so a lost race is one exception type rather
        than a raw `ClientError` each caller has to decode. Only
        `ConditionalCheckFailedException` is translated; every other code is re-raised
        untouched, since a throttle or an access denial is a fault, not a conflict. The
        `ClientError` stays as `__cause__`, so nothing about the original failure is lost.
        """
        from botocore.exceptions import ClientError

        try:
            yield
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != _CONDITIONAL_CHECK_FAILED_EXCEPTION:
                raise
            raise ConditionFailed(self.table_name, _describe_condition(condition), key) from exc

    def put(self, item: Item, *, condition: Any | None = None) -> None:
        """Write one item, converting any `float` to `Decimal` on the way.

        Pass a `condition` such as `Attr("pk").not_exists()` to make the write a create
        rather than an upsert.

        Raises:
            ConditionFailed: When a `condition` was given and did not hold, which is the
                ordinary outcome of losing an optimistic create rather than a fault.
        """
        encoded = encode_numbers(item)
        kwargs: dict[str, Any] = {"Item": encoded}
        if condition is None:
            self.table.put_item(**kwargs)
            return
        kwargs["ConditionExpression"] = condition
        with self._conditional(condition, None):
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

        Raises:
            ConditionFailed: When a `condition` was given and did not hold.
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

        if condition is None:
            response = self.table.update_item(**kwargs)
        else:
            with self._conditional(condition, key):
                response = self.table.update_item(**kwargs)
        attributes = response.get("Attributes")
        if attributes is None:
            return None
        return dict(attributes)

    def set_attributes(
        self,
        key: Key,
        attributes: Mapping[str, Any],
        *,
        condition: Any | None = None,
        return_values: str = "ALL_NEW",
    ) -> Item | None:
        """`SET` each of `attributes` on one item, aliasing every name.

        The update a product otherwise hand-rolls for a partial write, and hand-rolls
        wrongly twice over. Every attribute name is aliased whether or not it looks
        reserved, because DynamoDB's reserved word list runs to hundreds of ordinary words
        such as `name`, `status` and `size`, and an expression naming one directly is
        rejected at runtime rather than caught in review.

        The aliases are minted in the `#set{index}` namespace on purpose. A caller that
        numbers its own aliases `#n0`, `#n1` collides with boto3: rendering an `Attr`
        condition mints placeholders from the same `#n0` counter, and the two maps are
        merged into one request where the later definition silently wins and the update
        writes to the condition's attribute. `#set{index}` cannot collide with a generated
        name, so a conditional partial update is safe to express.

        Args:
            key: The item's full primary key.
            attributes: The attribute names and values to set. An empty mapping is a no-op
                returning `None`, since DynamoDB rejects an empty `UpdateExpression`.
            condition: An optional condition guarding the write.
            return_values: DynamoDB's `ReturnValues`, defaulting to `ALL_NEW` so the caller
                sees the stored item rather than issuing a second read.

        Raises:
            ConditionFailed: When a `condition` was given and did not hold.
        """
        values = dict(attributes)
        if not values:
            return None
        names = {f"#set{index}": name for index, name in enumerate(values)}
        expression_values = {f":set{index}": value for index, value in enumerate(values.values())}
        assignments = ", ".join(f"#set{index} = :set{index}" for index in range(len(values)))
        return self.update(
            key,
            update_expression=f"SET {assignments}",
            expression_values=expression_values,
            expression_names=names,
            condition=condition,
            return_values=return_values,
        )

    def remove_attributes(
        self,
        key: Key,
        names: Sequence[str],
        *,
        condition: Any | None = None,
        return_values: str = "ALL_NEW",
    ) -> Item | None:
        """`REMOVE` each of `names` from one item, aliasing every name.

        The counterpart to `set_attributes`, and the update a sparse global secondary index
        needs. DynamoDB indexes only the items that carry the index's key attribute, so an
        item leaves a sparse index by having that attribute deleted and not by having it set
        to null or to an empty string, either of which keeps the item in the index and keeps
        it in every query that reads it. Writing a marker where a `REMOVE` belongs is the
        mistake this exists to stop: an "unread" index that a read never empties.

        Aliasing follows `set_attributes` for the same reason, in its own `#rm{index}`
        namespace, so a conditional removal cannot collide with the `#n{index}` placeholders
        boto3 mints while rendering an `Attr` condition.

        Removing an attribute the item does not have is not an error, since `REMOVE` on an
        absent attribute is a no-op to DynamoDB, which makes the call idempotent and a second
        delivery of the same message harmless.

        Args:
            key: The item's full primary key.
            names: The attribute names to remove. An empty sequence is a no-op returning
                `None`, since DynamoDB rejects an empty `UpdateExpression`. A name repeated
                is sent once, because DynamoDB refuses an expression naming one path twice.
            condition: An optional condition guarding the write.
            return_values: DynamoDB's `ReturnValues`, defaulting to `ALL_NEW` so the caller
                sees what the item now holds rather than issuing a second read.

        Raises:
            ConditionFailed: When a `condition` was given and did not hold.
        """
        wanted = list(dict.fromkeys(names))
        if not wanted:
            return None
        aliases = {f"#rm{index}": name for index, name in enumerate(wanted)}
        removals = ", ".join(f"#rm{index}" for index in range(len(wanted)))
        return self.update(
            key,
            update_expression=f"REMOVE {removals}",
            expression_names=aliases,
            condition=condition,
            return_values=return_values,
        )

    def increment(self, key: Key, attribute: str, by: int = 1) -> int:
        """Atomically add `by` to a numeric attribute and return what it now holds.

        One `update_item` with `ADD`, which creates the item and treats an absent attribute as
        zero, so a counter needs no seeding and two concurrent callers cannot both read 9 and
        write 10. The read-modify-write a caller would otherwise hand-roll loses increments
        under any concurrency at all.

        The returned value is the counter after this call, which makes the helper an allocator:
        the number it hands back belongs to this caller alone. Nothing rolls it back, so a
        caller that fails after allocating leaves a gap, and the sequence is
        gap-tolerant rather than gap-free. A gap-free sequence costs a lock.

        `by` may be negative, which decrements. Zero is refused, since it reads as an increment
        and does nothing.

        Raises:
            ValueError: When `by` is zero.
        """
        if by == 0:
            raise ValueError("increment needs a non-zero amount; zero would be a no-op that reads as a counter bump.")
        attributes = self.update(
            key,
            update_expression="ADD #attribute :by",
            expression_names={"#attribute": attribute},
            expression_values={":by": by},
            return_values="UPDATED_NEW",
        )
        if attributes is None:
            raise DynamoError(f"{self.table_name}: update_item returned no attributes for {attribute}")
        return int(attributes[attribute])

    def delete(self, key: Key, *, condition: Any | None = None) -> None:
        """Delete one item by primary key. Deleting an absent item is not an error.

        Raises:
            ConditionFailed: When a `condition` was given and did not hold.
        """
        kwargs: dict[str, Any] = {"Key": dict(key)}
        if condition is None:
            self.table.delete_item(**kwargs)
            return
        kwargs["ConditionExpression"] = condition
        with self._conditional(condition, key):
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

    def get_many(
        self,
        ids: Sequence[str],
        *,
        key_attribute: str = "id",
        consistent: bool = False,
        projection: str | None = None,
        max_attempts: int = UNPROCESSED_RETRY_ATTEMPTS,
    ) -> dict[str, Item]:
        """Fetch many items by a single-attribute key and return them keyed by that id.

        The read behind any "render these people" or "name these workspaces" screen, which
        a caller otherwise writes as a loop of `get` calls: one round trip per row, and a
        latency that grows with the list. `batch_get` already chunks at `BATCH_GET_LIMIT`
        and retries unprocessed keys, and this adds the two things a caller then has to do
        by hand every time: de-duplicating the ids, since `BatchGetItem` rejects a request
        naming the same key twice, and pairing each item back to the id that asked for it,
        since a batch response comes back in no particular order.

        A missing id is simply absent from the result, the way `get` answers `None`, so the
        caller decides whether a gap is an error. Blank ids are dropped rather than sent,
        since DynamoDB rejects an empty key attribute.

        Only for a table whose primary key is one attribute. A composite key has no single
        id to key the result by, so use `batch_get` there.

        Raises:
            UnprocessedItems: When keys were still unprocessed after the last attempt.
        """
        wanted = [value for value in dict.fromkeys(ids) if value]
        if not wanted:
            return {}
        items = self.batch_get(
            [{key_attribute: value} for value in wanted],
            consistent=consistent,
            projection=projection,
            max_attempts=max_attempts,
        )
        return {str(item[key_attribute]): item for item in items if key_attribute in item}

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


WRITE_METHODS: Final[tuple[str, ...]] = (
    "condition_check",
    "delete",
    "delete_action",
    "delete_many",
    "increment",
    "put",
    "put_action",
    "put_many",
    "remove_attributes",
    "set_attributes",
    "transact_write",
    "update",
    "update_action",
)


def _install_write_guards() -> None:
    """Wrap every name in `WRITE_METHODS` so a read-only repository refuses it.

    The guard lives on `Repository` itself rather than on a subclass, so a repository a
    product subclasses inherits it without having to be rebuilt read only, and the check
    is one attribute test on the normal path.
    """
    for method in WRITE_METHODS:
        original = getattr(Repository, method)
        setattr(Repository, method, _guarded(original, method))


def _guarded(original: Any, method: str) -> Any:
    """`original`, refusing to run when the repository was built read only."""

    @wraps(original)
    def guard(self: Repository, *args: Any, **kwargs: Any) -> Any:
        """Raise `ReadOnlyTable` on a read-only repository, else call through."""
        if self._read_only:
            raise ReadOnlyTable(self.table_name, method, self._read_only_hint)
        return original(self, *args, **kwargs)

    return guard


_install_write_guards()


class IdempotencyStore:
    """One-shot claims on a key, so a retried delivery does the work exactly once.

    `claim` is a conditional put on the key's absence: the first caller wins and every later
    one is told it lost, which is the whole decision a handler needs when SQS, EventBridge or
    a payment webhook delivers the same message twice. The claim carries a TTL, so the table
    forgets a key once replays are no longer plausible rather than growing forever.

    The window is the honest limit. A TTL is reclaimed on DynamoDB's own schedule, so a
    delivery arriving after expiry is processed again; size `ttl_seconds` past the longest
    retry the producer will make. A winner that then crashes has still claimed the key, so
    this makes a duplicate a no-op, not a job a second worker picks up.
    """

    def __init__(
        self,
        repository: Repository,
        *,
        key_attribute: str = "pk",
        ttl_attribute: str = "expires_at",
        claimed_at_attribute: str = "claimed_at",
    ) -> None:
        """Wrap one repository, naming the key, TTL and timestamp attributes it writes."""
        self.repository = repository
        self.key_attribute = key_attribute
        self.ttl_attribute = ttl_attribute
        self.claimed_at_attribute = claimed_at_attribute

    def claim(self, key: str, ttl_seconds: float) -> bool:
        """Claim `key` for this caller, answering whether it won.

        True means nobody had claimed it and the caller owns the work. False means a live
        claim already exists and this delivery is a duplicate to drop. A claim whose TTL has
        passed may still be present, since DynamoDB deletes on its own schedule, and it holds
        the key until it goes: expiry is the reclaim, never a guarantee of promptness.

        Raises:
            ValueError: When `ttl_seconds` is not positive, which would claim nothing.
        """
        if ttl_seconds <= 0:
            raise ValueError(f"claim needs a positive ttl_seconds, got {ttl_seconds}.")

        from boto3.dynamodb.conditions import Attr

        item: Item = {
            self.key_attribute: key,
            self.ttl_attribute: ttl_in(ttl_seconds),
            self.claimed_at_attribute: now_iso(),
        }
        try:
            self.repository.put(item, condition=Attr(self.key_attribute).not_exists())
        except ConditionFailed:
            return False
        return True

    def release(self, key: str) -> None:
        """Drop a claim, letting the next delivery of `key` win.

        For a handler that failed after claiming and wants the retry to do the work rather
        than wait out the TTL. Releasing a key nobody claimed is not an error.
        """
        self.repository.delete({self.key_attribute: key})
