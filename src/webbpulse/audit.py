"""A tenant audit log: who did what to which target, when, append-only and scrubbed of secrets.

One partition per tenant (a workspace, an org, whatever the product scopes by) with a ULID
sort key, so the newest page is one descending query and a time range is a key condition
rather than a filter. An optional GSI keyed on `<tenant>#<target type>#<target id>` answers
"everything that happened to this target" the same way. Rows are written once with a
conditional put and never edited; the only removals are the optional TTL and a whole-tenant
purge.

Every payload, `before` and `after` passes through `Redaction` when an `AuditEvent` is
built, so no store, recorder or caller path can persist a value under a secret-looking key
or a value shaped like a credential. A product narrows that further per action with an
allowlist in its `AuditCatalogue`. A store reads its rows back with `AuditEvent.restore`,
which keeps what was written rather than scrubbing it again.

`AuditLogStore` is the storage Protocol, with `DynamoAuditLogStore` over a
`webbpulse.dynamodb.Repository` and `InMemoryAuditLogStore` for tests. `AuditRecorder` is the
best-effort write path a request handler calls, and `audit_csv` renders a spreadsheet-safe
export.
"""

from __future__ import annotations

import csv
import dataclasses
import io
import json
import logging
import re
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from enum import Enum
from typing import TYPE_CHECKING, Any, Final, Protocol

from webbpulse.dynamodb import (
    ConditionFailed,
    InvalidStartKey,
    ReadOnlyTable,
    decode_start_key,
    encode_start_key,
    new_ulid,
)
from webbpulse.identity.api_keys import API_KEY_PREFIX, PREFIX_DISPLAY_LENGTH
from webbpulse.identity.storage import TableAttribute, TableIndex, TableSpec

if TYPE_CHECKING:  # pragma: no cover
    from webbpulse.dynamodb import Repository

__all__ = [
    "AUDIT_TABLE",
    "AUDIT_TABLE_SPEC",
    "AUDIT_TARGET_INDEX",
    "CSV_COLUMNS",
    "DEFAULT_PAGE_SIZE",
    "DEFAULT_SECRET_KEYS",
    "DEFAULT_SECRET_VALUE_PATTERNS",
    "MAX_PAGE_SIZE",
    "REDACTED",
    "SYSTEM_ACTOR",
    "AuditAction",
    "AuditActor",
    "AuditAttributes",
    "AuditCatalogue",
    "AuditEvent",
    "AuditEventExists",
    "AuditLogStore",
    "AuditPage",
    "AuditQuery",
    "AuditRecorder",
    "AuditTarget",
    "DynamoAuditLogStore",
    "FakeAuditLogStore",
    "InMemoryAuditLogStore",
    "Redaction",
    "audit_csv",
    "audit_table_spec",
    "changed_fields",
    "csv_safe",
    "cursor_scope",
    "iter_events",
    "time_floor",
]

_log = logging.getLogger(__name__)

AUDIT_TABLE: Final = "audit"
"""The logical table name, prefixed by the environment like every other table."""

AUDIT_TARGET_INDEX: Final = "target_key-event_id-index"
"""The GSI listing one target's events newest first: hash `target_key`, range `event_id`.

`target_key` is `<tenant>#<target type>#<target id>` and written only on an event that names a
target, so the index is sparse and a query on it can never reach another tenant.
"""

DEFAULT_PAGE_SIZE: Final = 50
MAX_PAGE_SIZE: Final = 1000

MAX_ROUNDS: Final = 10
"""How many filtered reads one page may take before it answers with what it found and a cursor."""

REDACTED: Final = "[redacted]"
"""What a scrubbed value is replaced with."""

_MAX_DEPTH: Final = 32
_ULID_PATTERN: Final = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
_TIME_PREFIX_LENGTH: Final = 10
_FORMULA_PREFIXES: Final = ("=", "+", "-", "@", "\t", "\r")

DEFAULT_SECRET_KEYS: Final[frozenset[str]] = frozenset(
    {
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "api_key",
        "apikey",
        "private_key",
        "secret_key",
        "secret_value",
        "access_key",
        "secret_access_key",
        "session_token",
        "credential",
        "credentials",
        "authorization",
        "cookie",
        "signature",
        "otp",
        "totp",
        "recovery_code",
        "recovery_codes",
        "client_secret",
        "webhook_secret",
        "plaintext",
    }
)
"""Key names whose value is always scrubbed, matched on the whole snake-cased key or its last segments.

`access_token`, `db_password` and `client_secret` are scrubbed; `token_id`, `token_name` and
`secret_name` are not, because they end in an identifier rather than the secret itself.
"""

_DISPLAYED_SECRET_LENGTH: Final = PREFIX_DISPLAY_LENGTH - len(API_KEY_PREFIX)

DEFAULT_SECRET_VALUE_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(rf"\b(?:wpk|wps)_[A-Za-z0-9_\-]{{{_DISPLAYED_SECRET_LENGTH + 1},}}"),
    re.compile(r"\b(?:sk|rk|whsec)_[A-Za-z0-9_\-]{8,}"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/\-]{16,}"),
)
"""Values shaped like a credential, scrubbed wherever they appear, whatever key holds them.

A `wpk_` or `wps_` value must run past the `PREFIX_DISPLAY_LENGTH` characters an API key
shows in the clear, so `webbpulse.identity.api_keys.display_prefix` is kept and a full key is
scrubbed.
"""


def _now() -> datetime:
    """The current moment, aware and UTC."""
    return datetime.now(UTC)


def _aware(moment: datetime) -> datetime:
    """`moment` as an aware datetime, reading a naive one as UTC."""
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


def time_floor(moment: datetime) -> str:
    """The time prefix every event id minted at or after `moment` sorts at or above.

    A naive `moment` is read as UTC.
    """
    return new_ulid(_aware(moment))[:_TIME_PREFIX_LENGTH]


def _snake(key: str) -> str:
    """A key lowercased with dashes, dots and spaces as underscores, camelCase split."""
    split = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
    return re.sub(r"[\s.\-]+", "_", split).lower()


@dataclass(frozen=True, slots=True)
class Redaction:
    """How a payload is scrubbed before it is stored.

    `allow`, when set, keeps only those top-level keys and drops the rest. `secret_keys` are
    scrubbed at any depth whether allowed or not, and every string matching one of
    `secret_values` is replaced whole. Values are normalised to JSON: datetimes become ISO
    8601, enums their value, tuples and sets lists, and a `Decimal` an int or a float.
    Anything else raises `TypeError`, since its string form could carry anything.
    """

    allow: frozenset[str] | None = None
    secret_keys: frozenset[str] = DEFAULT_SECRET_KEYS
    secret_values: tuple[re.Pattern[str], ...] = DEFAULT_SECRET_VALUE_PATTERNS

    def is_secret_key(self, key: str) -> bool:
        """Whether a value under `key` is scrubbed: the snake-cased key is a secret name or ends in one."""
        name = _snake(key)
        if name in self.secret_keys:
            return True
        parts = name.split("_")
        return any("_".join(parts[index:]) in self.secret_keys for index in range(1, len(parts)))

    def is_secret_value(self, value: str) -> bool:
        """Whether `value` looks like a credential."""
        return any(pattern.search(value) for pattern in self.secret_values)

    def apply(self, payload: Mapping[str, Any] | None) -> dict[str, Any]:
        """The scrubbed, JSON-safe copy of `payload`, empty when it is `None`."""
        if payload is None:
            return {}
        kept = payload if self.allow is None else {key: value for key, value in payload.items() if key in self.allow}
        return self._mapping(kept, 0)

    def _mapping(self, value: Mapping[Any, Any], depth: int) -> dict[str, Any]:
        """One mapping scrubbed key by key."""
        result: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = raw_key.value if isinstance(raw_key, Enum) else raw_key
            if not isinstance(key, str):
                raise TypeError(f"Audit payload keys must be strings, got {type(key).__name__}.")
            result[key] = REDACTED if self.is_secret_key(key) else self._value(item, depth + 1)
        return result

    def _value(self, value: Any, depth: int) -> Any:
        """One value scrubbed and normalised to JSON."""
        if depth > _MAX_DEPTH:
            raise ValueError(f"Audit payloads may nest at most {_MAX_DEPTH} levels.")
        if value is None or isinstance(value, bool | int | float):
            return value
        if isinstance(value, str):
            return REDACTED if self.is_secret_value(value) else value
        if isinstance(value, Enum):
            return self._value(value.value, depth)
        if isinstance(value, Decimal):
            return int(value) if value == value.to_integral_value() else float(value)
        if isinstance(value, datetime):
            return _aware(value).isoformat()
        if isinstance(value, date):
            return value.isoformat()
        if isinstance(value, Mapping):
            return self._mapping(value, depth)
        if isinstance(value, set | frozenset):
            return [self._value(item, depth + 1) for item in sorted(value, key=str)]
        if isinstance(value, list | tuple):
            return [self._value(item, depth + 1) for item in value]
        raise TypeError(f"Audit payloads hold JSON values only, got {type(value).__name__}.")


_DEFAULT_REDACTION: Final = Redaction()


@dataclass(frozen=True, slots=True)
class AuditActor:
    """Who did it: an id, what kind of principal, the client it came through, and how it signed in.

    `kind` is the product's own vocabulary, such as `user`, `api_key`, `service` or `system`.
    `source` names the client, such as `web`, `api`, `cli` or `mcp`. `amr` holds the
    authentication methods of the session, such as `pwd` and `otp`.
    """

    id: str
    kind: str = "user"
    source: str = ""
    ip: str = ""
    amr: tuple[str, ...] = ()


SYSTEM_ACTOR: Final = AuditActor(id="system", kind="system", source="system")
"""The actor of an event no signed-in request carried, such as a webhook or a scheduled job."""


@dataclass(frozen=True, slots=True)
class AuditTarget:
    """What it was done to: a type such as `workspace` or `token`, its id, and a display label."""

    type: str = ""
    id: str = ""
    label: str = ""

    def __bool__(self) -> bool:
        """Whether this names a target: both a type and an id."""
        return bool(self.type and self.id)


_NO_TARGET: Final = AuditTarget()


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One audit event, scrubbed on construction.

    `event_id` defaults to a ULID minted at `occurred_at`, which is what makes a time range a
    key condition; one given explicitly must be a ULID. `payload` is the event's JSON detail,
    and `before` and `after` the changed fields of an update. All three pass through the
    default `Redaction`, so none can hold a secret-looking key or value; only `restore`, the
    read path of a store, skips it. `expires_at` is the
    epoch second the TTL removes the row, or `None` to keep it.
    """

    tenant_id: str
    action: str
    actor: AuditActor
    target: AuditTarget = _NO_TARGET
    payload: Mapping[str, Any] = field(default_factory=dict)
    before: Mapping[str, Any] | None = None
    after: Mapping[str, Any] | None = None
    occurred_at: datetime = field(default_factory=_now)
    event_id: str = ""
    expires_at: int | None = None

    def __post_init__(self) -> None:
        """Refuse an event with no tenant or action, mint the id, and scrub every payload."""
        if not self.tenant_id:
            raise ValueError("An audit event needs a tenant_id.")
        if "#" in self.tenant_id:
            raise ValueError("An audit tenant_id cannot contain '#'.")
        if not self.action:
            raise ValueError("An audit event needs an action.")
        if not self.actor.id:
            raise ValueError("An audit event needs an actor id.")
        if "#" in self.target.type:
            raise ValueError("An audit target type cannot contain '#'.")
        occurred = _aware(self.occurred_at)
        object.__setattr__(self, "occurred_at", occurred)
        if not self.event_id:
            object.__setattr__(self, "event_id", new_ulid(occurred))
        elif not _ULID_PATTERN.match(self.event_id):
            raise ValueError("An audit event_id must be a ULID.")
        object.__setattr__(self, "payload", _DEFAULT_REDACTION.apply(self.payload))
        if self.before is not None:
            object.__setattr__(self, "before", _DEFAULT_REDACTION.apply(self.before))
        if self.after is not None:
            object.__setattr__(self, "after", _DEFAULT_REDACTION.apply(self.after))

    @classmethod
    def restore(
        cls,
        *,
        tenant_id: str,
        action: str,
        actor: AuditActor,
        event_id: str,
        occurred_at: datetime,
        target: AuditTarget = _NO_TARGET,
        payload: Mapping[str, Any] | None = None,
        before: Mapping[str, Any] | None = None,
        after: Mapping[str, Any] | None = None,
        expires_at: int | None = None,
    ) -> AuditEvent:
        """An event read back from a store exactly as it was written, without scrubbing it again.

        The read path of a store. The shape is still checked, but `payload`, `before` and
        `after` are kept as given, so a value the write path let through, or a row written
        before a product adopted this module, reads back unchanged.
        """
        event = cls(
            tenant_id=tenant_id,
            action=action,
            actor=actor,
            target=target,
            occurred_at=occurred_at,
            event_id=event_id,
            expires_at=expires_at,
        )
        object.__setattr__(event, "payload", dict(payload or {}))
        object.__setattr__(event, "before", dict(before) if before is not None else None)
        object.__setattr__(event, "after", dict(after) if after is not None else None)
        return event

    @property
    def target_key(self) -> str:
        """`<tenant>#<target type>#<target id>`, or empty when the event names no target."""
        return target_key(self.tenant_id, self.target) if self.target else ""


def target_key(tenant_id: str, target: AuditTarget) -> str:
    """The target index key of `target` inside `tenant_id`."""
    return f"{tenant_id}#{target.type}#{target.id}"


class AuditEventExists(ValueError):
    """An event with this tenant and id is already stored; the log is append-only."""


@dataclass(frozen=True, slots=True)
class AuditQuery:
    """What one listing narrows to.

    `since` is inclusive and `until` exclusive, naive values read as UTC, both key conditions.
    `target` uses the target index when the store has one. `actor_id` and `action` are filters.
    """

    since: datetime | None = None
    until: datetime | None = None
    actor_id: str | None = None
    action: str | None = None
    target: AuditTarget | None = None


@dataclass(frozen=True, slots=True)
class AuditPage:
    """One page of events newest first, and the cursor to the next, `None` at the end.

    A page can hold fewer events than asked for, even none, and still carry a cursor when a
    filter left a read short.
    """

    events: list[AuditEvent]
    next_cursor: str | None


def cursor_scope(tenant_id: str, target: AuditTarget | None = None) -> str:
    """The scope a cursor is minted under, so it resumes only the listing it came from."""
    if target:
        return f"audit:{tenant_id}:target:{target.type}#{target.id}"
    return f"audit:{tenant_id}"


class AuditLogStore(Protocol):
    """Append-only storage for audit events, every read scoped to one tenant."""

    def append(self, event: AuditEvent) -> AuditEvent:
        """Store a new event and return it.

        Raises:
            AuditEventExists: When an event with the same tenant and id is already stored.
        """
        ...

    def list_events(
        self,
        tenant_id: str,
        query: AuditQuery | None = None,
        *,
        limit: int = DEFAULT_PAGE_SIZE,
        cursor: str | None = None,
    ) -> AuditPage:
        """One page of the tenant's events newest first.

        Raises:
            ValueError: When `tenant_id` is empty or `limit` is outside 1 to `MAX_PAGE_SIZE`.
            InvalidStartKey: When `cursor` came from another listing or is malformed.
        """
        ...

    def purge_tenant(self, tenant_id: str) -> int:
        """Delete the tenant's whole log, for a tenant purge, answering how many rows went."""
        ...


def _check_listing(tenant_id: str, limit: int) -> None:
    """Refuse a listing that could span tenants or read without bound."""
    if not tenant_id:
        raise ValueError("An audit listing needs a tenant_id.")
    if not 1 <= limit <= MAX_PAGE_SIZE:
        raise ValueError(f"limit must be between 1 and {MAX_PAGE_SIZE}, got {limit}.")


def _bounds(query: AuditQuery) -> tuple[str | None, str | None] | None:
    """The event id bounds of a query's time range, or `None` when the range is empty."""
    low = time_floor(query.since) if query.since is not None else None
    high = time_floor(query.until) if query.until is not None else None
    if low is not None and high is not None and low >= high:
        return None
    return low, high


def _within(event_id: str, low: str | None, high: str | None) -> bool:
    """Whether an event id falls inside `[low, high)`."""
    return (low is None or event_id >= low) and (high is None or event_id < high)


def _matches(event: AuditEvent, query: AuditQuery) -> bool:
    """Whether an event passes a query's filters, the time range aside."""
    if query.actor_id and event.actor.id != query.actor_id:
        return False
    if query.action and event.action != query.action:
        return False
    return not (query.target and (event.target.type, event.target.id) != (query.target.type, query.target.id))


@dataclass(frozen=True, slots=True)
class AuditAttributes:
    """The stored names of the attributes a product may already have named differently.

    The defaults suit a new table. A product with an existing one maps its names here, so it
    adopts this module with no data migration.
    """

    tenant_id: str = "tenant_id"
    event_id: str = "event_id"
    action: str = "action"
    occurred_at: str = "occurred_at"
    expires_at: str = "expires_at"
    target_key: str = "target_key"


def audit_table_spec(
    attributes: AuditAttributes | None = None,
    *,
    logical_name: str = AUDIT_TABLE,
    target_index: str | None = AUDIT_TARGET_INDEX,
) -> TableSpec:
    """The table an audit log needs: hash the tenant, range the ULID, TTL on the expiry.

    `target_index=None` leaves the target GSI out; target listings then filter the tenant
    partition instead.
    """
    names = attributes or AuditAttributes()
    keys = [TableAttribute(names.tenant_id, "S"), TableAttribute(names.event_id, "S")]
    indexes: tuple[TableIndex, ...] = ()
    if target_index is not None:
        keys.append(TableAttribute(names.target_key, "S"))
        indexes = (TableIndex(name=target_index, hash_key=names.target_key, range_key=names.event_id),)
    return TableSpec(
        logical_name=logical_name,
        attributes=tuple(keys),
        hash_key=names.tenant_id,
        range_key=names.event_id,
        global_secondary_indexes=indexes,
        ttl_attribute=names.expires_at,
    )


AUDIT_TABLE_SPEC: Final = audit_table_spec()
"""The default `audit` table: hash `tenant_id`, range `event_id`, `AUDIT_TARGET_INDEX`, TTL `expires_at`."""


def _plain(value: Any) -> Any:
    """A value read back from DynamoDB with every `Decimal` as an int or a float."""
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, list | tuple | set):
        return [_plain(item) for item in value]
    return value


def _iso(moment: datetime) -> str:
    """An aware moment as ISO 8601 in UTC with a `Z` suffix."""
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_moment(raw: Any) -> datetime:
    """A stored timestamp back as an aware datetime."""
    if isinstance(raw, datetime):
        return _aware(raw)
    text = str(raw)
    return _aware(datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text))


class DynamoAuditLogStore:
    """`AuditLogStore` over a `webbpulse.dynamodb.Repository`.

    `attributes` maps the stored names, and `target_index=None` serves target listings by
    filtering the tenant partition, for a table provisioned without the GSI.
    """

    def __init__(
        self,
        repository: Repository,
        *,
        attributes: AuditAttributes | None = None,
        target_index: str | None = AUDIT_TARGET_INDEX,
    ) -> None:
        """Bind the store to its table, its attribute names and its target index."""
        self._repo = repository
        self._names = attributes or AuditAttributes()
        self._target_index = target_index

    def _to_item(self, event: AuditEvent) -> dict[str, Any]:
        """The stored item for an event."""
        names = self._names
        item: dict[str, Any] = {
            names.tenant_id: event.tenant_id,
            names.event_id: event.event_id,
            names.action: event.action,
            names.occurred_at: _iso(event.occurred_at),
            "actor_id": event.actor.id,
            "actor_kind": event.actor.kind,
            "source": event.actor.source,
            "ip": event.actor.ip,
            "amr": list(event.actor.amr),
            "target_type": event.target.type,
            "target_id": event.target.id,
            "target_label": event.target.label,
        }
        if event.payload:
            item["payload"] = dict(event.payload)
        if event.before is not None:
            item["before"] = dict(event.before)
        if event.after is not None:
            item["after"] = dict(event.after)
        if event.expires_at is not None:
            item[names.expires_at] = event.expires_at
        if event.target:
            item[names.target_key] = event.target_key
        return item

    def _from_item(self, item: Mapping[str, Any]) -> AuditEvent:
        """An event back from its stored item, tolerating absent optional attributes."""
        names = self._names
        raw_payload = item.get("payload")
        raw_before = item.get("before")
        raw_after = item.get("after")
        raw_expiry = item.get(names.expires_at)
        return AuditEvent.restore(
            tenant_id=str(item[names.tenant_id]),
            event_id=str(item[names.event_id]),
            action=str(item.get(names.action, "")),
            occurred_at=_parse_moment(item[names.occurred_at]),
            actor=AuditActor(
                id=str(item.get("actor_id", "")),
                kind=str(item.get("actor_kind", "")),
                source=str(item.get("source", "")),
                ip=str(item.get("ip", "")),
                amr=tuple(str(method) for method in item.get("amr") or ()),
            ),
            target=AuditTarget(
                type=str(item.get("target_type", "")),
                id=str(item.get("target_id", "")),
                label=str(item.get("target_label", "")),
            ),
            payload=_plain(raw_payload) if isinstance(raw_payload, Mapping) else {},
            before=_plain(raw_before) if isinstance(raw_before, Mapping) else None,
            after=_plain(raw_after) if isinstance(raw_after, Mapping) else None,
            expires_at=int(raw_expiry) if raw_expiry is not None else None,
        )

    def append(self, event: AuditEvent) -> AuditEvent:
        """Store a new event with a conditional put, so a row is never overwritten."""
        from boto3.dynamodb.conditions import Attr

        try:
            self._repo.put(self._to_item(event), condition=Attr(self._names.event_id).not_exists())
        except ConditionFailed as exc:
            raise AuditEventExists(f"Audit event {event.event_id} already exists.") from exc
        return event

    def list_events(
        self,
        tenant_id: str,
        query: AuditQuery | None = None,
        *,
        limit: int = DEFAULT_PAGE_SIZE,
        cursor: str | None = None,
    ) -> AuditPage:
        """One page newest first, reading on through filtered reads up to `MAX_ROUNDS`."""
        from boto3.dynamodb.conditions import Attr
        from boto3.dynamodb.conditions import Key as KeyCondition

        _check_listing(tenant_id, limit)
        wanted = query or AuditQuery()
        target = wanted.target if wanted.target else None
        scope = cursor_scope(tenant_id, target)
        start = decode_start_key(cursor, scope=scope)
        bounds = _bounds(wanted)
        if bounds is None:
            return AuditPage(events=[], next_cursor=None)
        low, high = bounds
        names = self._names
        if start is not None:
            resumed = start.get(names.event_id)
            if start.get(names.tenant_id) != tenant_id or not isinstance(resumed, str):
                raise InvalidStartKey
            if not _within(resumed, low, None) or (high is not None and resumed >= high):
                raise InvalidStartKey

        index_name: str | None = None
        condition: Any
        filters: Any = None
        if target is not None and self._target_index is not None:
            index_name = self._target_index
            condition = KeyCondition(names.target_key).eq(target_key(tenant_id, target))
        else:
            condition = KeyCondition(names.tenant_id).eq(tenant_id)
            if target is not None:
                filters = Attr("target_type").eq(target.type) & Attr("target_id").eq(target.id)
        if low is not None and high is not None:
            condition = condition & KeyCondition(names.event_id).between(low, high)
        elif low is not None:
            condition = condition & KeyCondition(names.event_id).gte(low)
        elif high is not None:
            condition = condition & KeyCondition(names.event_id).lt(high)
        if wanted.actor_id:
            matched = Attr("actor_id").eq(wanted.actor_id)
            filters = matched if filters is None else filters & matched
        if wanted.action:
            matched = Attr(names.action).eq(wanted.action)
            filters = matched if filters is None else filters & matched

        events: list[AuditEvent] = []
        last: dict[str, Any] | None = dict(start) if start else None
        for _ in range(MAX_ROUNDS):
            page = self._repo.query(
                condition,
                index_name=index_name,
                filter_expression=filters,
                limit=limit - len(events),
                start_key=last,
                ascending=False,
            )
            events.extend(self._from_item(item) for item in page.items)
            last = dict(page.last_evaluated_key) if page.last_evaluated_key else None
            if last is None or len(events) >= limit:
                break
        return AuditPage(events=events, next_cursor=encode_start_key(last, scope=scope))

    def purge_tenant(self, tenant_id: str) -> int:
        """Delete the tenant's partition a page at a time, so a retried purge deletes only what is left."""
        from boto3.dynamodb.conditions import Key as KeyCondition

        if not tenant_id:
            return 0
        names = self._names
        removed = 0
        while True:
            items = self._repo.query(KeyCondition(names.tenant_id).eq(tenant_id), limit=100, consistent=True).items
            if not items:
                return removed
            keys = [{names.tenant_id: item[names.tenant_id], names.event_id: item[names.event_id]} for item in items]
            removed += self._repo.delete_many(keys)


class InMemoryAuditLogStore:
    """Dict-backed `AuditLogStore` with the same ordering, filters and cursors as the table."""

    def __init__(self) -> None:
        """Start with no events."""
        self._events: dict[tuple[str, str], AuditEvent] = {}

    @property
    def events(self) -> list[AuditEvent]:
        """Every stored event, oldest first, for a test to assert on."""
        return [self._events[key] for key in sorted(self._events)]

    def append(self, event: AuditEvent) -> AuditEvent:
        """Store a new event, refusing a duplicate id as the conditional put does."""
        key = (event.tenant_id, event.event_id)
        if key in self._events:
            raise AuditEventExists(f"Audit event {event.event_id} already exists.")
        self._events[key] = event
        return event

    def list_events(
        self,
        tenant_id: str,
        query: AuditQuery | None = None,
        *,
        limit: int = DEFAULT_PAGE_SIZE,
        cursor: str | None = None,
    ) -> AuditPage:
        """One page newest first, with a cursor in the table's own key shape."""
        _check_listing(tenant_id, limit)
        wanted = query or AuditQuery()
        target = wanted.target if wanted.target else None
        scope = cursor_scope(tenant_id, target)
        start = decode_start_key(cursor, scope=scope)
        bounds = _bounds(wanted)
        if bounds is None:
            return AuditPage(events=[], next_cursor=None)
        low, high = bounds
        resume: str | None = None
        if start is not None:
            resumed = start.get("event_id")
            if start.get("tenant_id") != tenant_id or not isinstance(resumed, str):
                raise InvalidStartKey
            if not _within(resumed, low, None) or (high is not None and resumed >= high):
                raise InvalidStartKey
            resume = resumed
        candidates = sorted(
            (
                event
                for (tenant, event_id), event in self._events.items()
                if tenant == tenant_id
                and _within(event_id, low, high)
                and (resume is None or event_id < resume)
                and _matches(event, wanted)
            ),
            key=lambda event: event.event_id,
            reverse=True,
        )
        page = candidates[:limit]
        more = len(candidates) > limit
        next_cursor = (
            encode_start_key({"tenant_id": tenant_id, "event_id": page[-1].event_id}, scope=scope)
            if more and page
            else None
        )
        return AuditPage(events=page, next_cursor=next_cursor)

    def purge_tenant(self, tenant_id: str) -> int:
        """Delete every event of one tenant."""
        doomed = [key for key in self._events if key[0] == tenant_id]
        for key in doomed:
            del self._events[key]
        return len(doomed)


FakeAuditLogStore = InMemoryAuditLogStore
"""The name a test reaches for, aliasing `InMemoryAuditLogStore`."""


def iter_events(
    store: AuditLogStore,
    tenant_id: str,
    query: AuditQuery | None = None,
    *,
    max_items: int | None = None,
    page_size: int = 100,
) -> Iterator[AuditEvent]:
    """Every matching event newest first, following cursors, stopping after `max_items`."""
    yielded = 0
    cursor: str | None = None
    while True:
        page = store.list_events(tenant_id, query, limit=page_size, cursor=cursor)
        for event in page.events:
            yield event
            yielded += 1
            if max_items is not None and yielded >= max_items:
                return
        if page.next_cursor is None:
            return
        cursor = page.next_cursor


@dataclass(frozen=True, slots=True)
class AuditAction:
    """One action a product records: its display label and, optionally, the payload fields it may carry.

    `payload_fields` is an allowlist applied to `payload`, `before` and `after`; `None` keeps
    every field, still under the default secret scrubbing.
    """

    label: str
    payload_fields: frozenset[str] | None = None


class AuditCatalogue:
    """The fixed set of actions a product records, so a filter can offer them and a typo fails loudly."""

    def __init__(self, actions: Mapping[str, AuditAction | str], *, redaction: Redaction | None = None) -> None:
        """Take each action as an `AuditAction` or a bare label, and the product's base redaction."""
        self._actions: dict[str, AuditAction] = {
            name: action if isinstance(action, AuditAction) else AuditAction(label=action)
            for name, action in actions.items()
        }
        self._redaction = redaction or _DEFAULT_REDACTION

    def __contains__(self, action: object) -> bool:
        """Whether `action` is in the catalogue."""
        return action in self._actions

    def __iter__(self) -> Iterator[str]:
        """The action names in declaration order."""
        return iter(self._actions)

    def __len__(self) -> int:
        """How many actions the catalogue holds."""
        return len(self._actions)

    def label(self, action: str) -> str:
        """The display label of `action`, or the action itself when unknown."""
        known = self._actions.get(action)
        return known.label if known is not None else action

    def event_types(self) -> list[tuple[str, str]]:
        """Every action and its label, for a filter dropdown."""
        return [(name, action.label) for name, action in self._actions.items()]

    def redaction_for(self, action: str) -> Redaction:
        """The redaction one action's payloads pass through: the base one with the action's allowlist."""
        known = self._actions.get(action)
        if known is None or known.payload_fields is None:
            return self._redaction
        return dataclasses.replace(self._redaction, allow=known.payload_fields)


class AuditRecorder:
    """The write path a handler calls after a change lands, best effort by default.

    An unknown action or a payload that is not JSON raises, since both are programming
    errors. A store failure is logged and answers `None`, so recording never fails the
    change it describes; `best_effort=False` re-raises it instead. A `ReadOnlyTable` refusal,
    a function without the audit grant, is skipped quietly.
    """

    def __init__(
        self,
        store: AuditLogStore,
        catalogue: AuditCatalogue,
        *,
        retention: timedelta | None = None,
        best_effort: bool = True,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Bind the recorder to its store and catalogue, with an optional retention for the TTL."""
        self.store = store
        self.catalogue = catalogue
        self.retention = retention
        self.best_effort = best_effort
        self._clock = clock or _now

    def build(
        self,
        tenant_id: str,
        action: str,
        *,
        actor: AuditActor,
        target: AuditTarget | None = None,
        payload: Mapping[str, Any] | None = None,
        before: Mapping[str, Any] | None = None,
        after: Mapping[str, Any] | None = None,
        occurred_at: datetime | None = None,
    ) -> AuditEvent:
        """The event `record` would store, scrubbed by the action's redaction, without storing it.

        `target` is kept as given, so a target with only a label keeps it; the event joins the
        target index only when the target has both a type and an id.

        Raises:
            ValueError: When `action` is not in the catalogue.
        """
        if action not in self.catalogue:
            raise ValueError(f"Unknown audit action {action!r}.")
        redaction = self.catalogue.redaction_for(action)
        moment = _aware(occurred_at) if occurred_at is not None else self._clock()
        expires_at = int((moment + self.retention).timestamp()) if self.retention is not None else None
        return AuditEvent(
            tenant_id=tenant_id,
            action=action,
            actor=actor,
            target=target if target is not None else _NO_TARGET,
            payload=redaction.apply(payload),
            before=redaction.apply(before) if before is not None else None,
            after=redaction.apply(after) if after is not None else None,
            occurred_at=moment,
            expires_at=expires_at,
        )

    def record(
        self,
        tenant_id: str,
        action: str,
        *,
        actor: AuditActor,
        target: AuditTarget | None = None,
        payload: Mapping[str, Any] | None = None,
        before: Mapping[str, Any] | None = None,
        after: Mapping[str, Any] | None = None,
        occurred_at: datetime | None = None,
    ) -> AuditEvent | None:
        """Store one event and return it, or `None` when the store refused or failed."""
        event = self.build(
            tenant_id,
            action,
            actor=actor,
            target=target,
            payload=payload,
            before=before,
            after=after,
            occurred_at=occurred_at,
        )
        try:
            return self.store.append(event)
        except ReadOnlyTable:
            _log.info("audit_skipped", extra={"audit_action": action, "tenant_id": tenant_id})
            if not self.best_effort:
                raise
            return None
        except Exception:
            _log.exception("audit_write_failed", extra={"audit_action": action, "tenant_id": tenant_id})
            if not self.best_effort:
                raise
            return None


def changed_fields(before: Mapping[str, Any], after: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Only the fields of `after` whose value differs from `before`, as the before and after an update carries."""
    keys = [key for key in after if before.get(key) != after.get(key)]
    return {key: before.get(key) for key in keys}, {key: after.get(key) for key in keys}


def csv_safe(value: str) -> str:
    """A cell a spreadsheet will not run as a formula."""
    return "'" + value if value.startswith(_FORMULA_PREFIXES) else value


CSV_COLUMNS: Final[tuple[str, ...]] = (
    "occurred_at",
    "action",
    "label",
    "actor_id",
    "actor_name",
    "actor_kind",
    "source",
    "ip",
    "amr",
    "target_type",
    "target_id",
    "target_label",
    "payload",
    "before",
    "after",
)
"""The default export columns. `event_id` and `tenant_id` are also available."""


def _json_cell(value: Mapping[str, Any] | None) -> str:
    """A payload as compact sorted JSON, or empty."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")) if value else ""


def _cells(event: AuditEvent, catalogue: AuditCatalogue | None, actor_names: Mapping[str, str]) -> dict[str, str]:
    """Every exportable column of one event."""
    return {
        "tenant_id": event.tenant_id,
        "event_id": event.event_id,
        "occurred_at": event.occurred_at.isoformat(),
        "action": event.action,
        "label": catalogue.label(event.action) if catalogue is not None else event.action,
        "actor_id": event.actor.id,
        "actor_name": actor_names.get(event.actor.id, ""),
        "actor_kind": event.actor.kind,
        "source": event.actor.source,
        "ip": event.actor.ip,
        "amr": " ".join(event.actor.amr),
        "target_type": event.target.type,
        "target_id": event.target.id,
        "target_label": event.target.label,
        "payload": _json_cell(event.payload),
        "before": _json_cell(event.before) if event.before is not None else "",
        "after": _json_cell(event.after) if event.after is not None else "",
    }


def audit_csv(
    events: Iterable[AuditEvent],
    *,
    catalogue: AuditCatalogue | None = None,
    actor_names: Mapping[str, str] | None = None,
    columns: Sequence[str] = CSV_COLUMNS,
    headers: Mapping[str, str] | None = None,
) -> str:
    """Events as CSV, every cell guarded against formula injection.

    `columns` picks and orders the columns and `headers` renames them in the header row, so
    a product keeps the export its users already know.

    Raises:
        ValueError: When a column is not one an event has.
    """
    known = set(CSV_COLUMNS) | {"tenant_id", "event_id"}
    unknown = [column for column in columns if column not in known]
    if unknown:
        raise ValueError(f"Unknown audit CSV columns: {', '.join(unknown)}.")
    names = actor_names or {}
    renamed = headers or {}
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([renamed.get(column, column) for column in columns])
    for event in events:
        cells = _cells(event, catalogue, names)
        writer.writerow([csv_safe(cells[column]) for column in columns])
    return buffer.getvalue()
