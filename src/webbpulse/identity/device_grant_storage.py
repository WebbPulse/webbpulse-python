"""Storage for the OAuth device authorization grant (RFC 8628): pending codes and live grants.

Two tables alongside the identity ones, following the same rules: only hashes of anything
bearer-like are stored, every state change is one conditional operation, and every TTL is
storage reclamation with the deadline re-checked in code.
"""

from __future__ import annotations

import dataclasses
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, Literal

from webbpulse.identity.storage import IDENTITY_TTL_ATTRIBUTE, TableAttribute, TableIndex, TableSpec, is_expired

if TYPE_CHECKING:  # pragma: no cover
    from webbpulse.dynamodb import Repository

__all__ = [
    "DEVICE_CODES_TABLE",
    "DEVICE_CODE_USER_CODE_INDEX",
    "DEVICE_GRANTS_TABLE",
    "DEVICE_GRANT_TABLES",
    "DEVICE_GRANT_USER_INDEX",
    "DeviceCodeRecord",
    "DeviceCodeStatus",
    "DeviceCodeStore",
    "DeviceGrantRecord",
    "DeviceGrantStore",
    "DeviceGrantStores",
    "DynamoDeviceCodeStore",
    "DynamoDeviceGrantStore",
    "InMemoryDeviceCodeStore",
    "InMemoryDeviceGrantStore",
]

DEVICE_CODES_TABLE: Final = "device-codes"
DEVICE_GRANTS_TABLE: Final = "device-grants"

DEVICE_CODE_USER_CODE_INDEX: Final = "user_code_hash-index"
DEVICE_GRANT_USER_INDEX: Final = "user_id-index"

type DeviceCodeStatus = Literal["pending", "approved", "denied"]


@dataclass(frozen=True, slots=True)
class DeviceCodeRecord:
    """One device authorization request, from `/device/code` until the client collects it.

    Keyed by the hash of the device code the client polls with, and findable by the hash of
    the user code a person types. `scopes` is what the client asked for until approval, and
    exactly what was granted after it. `last_polled_at` and `interval` pace the client.
    """

    device_code_hash: str
    user_code_hash: str
    client_id: str
    scopes: tuple[str, ...]
    created_at: str
    expires_at: int
    interval: int
    status: DeviceCodeStatus = "pending"
    user_id: str = ""
    auth_time: int = 0
    last_polled_at: int = 0


@dataclass(frozen=True, slots=True)
class DeviceGrantRecord:
    """One approved device session: the scopes it holds and its rotating refresh token.

    `expires_at` is the session cap and never moves. `refresh_hash` is the only refresh
    token that rotates; `previous_refresh_hash` is the one it replaced, kept so presenting
    it again is recognised as reuse and ends the grant.
    """

    grant_id: str
    user_id: str
    client_id: str
    scopes: tuple[str, ...]
    created_at: str
    expires_at: int
    refresh_hash: str
    auth_time: int = 0
    previous_refresh_hash: str = ""
    generation: int = 1
    revoked: bool = False
    last_used_at: str = ""

    def live(self) -> bool:
        """Whether the grant is neither revoked nor past its session cap."""
        return not self.revoked and not is_expired(self.expires_at)


class DeviceCodeStore(ABC):
    """The `device-codes` table: hash `device_code_hash`, GSI `user_code_hash-index`, TTL `expires_at`."""

    @abstractmethod
    def put(self, record: DeviceCodeRecord) -> None:
        """Write a freshly issued device authorization request."""

    @abstractmethod
    def get(self, device_code_hash: str) -> DeviceCodeRecord | None:
        """The request, strongly consistent, or `None` when unknown or expired."""

    @abstractmethod
    def find_by_user_code(self, user_code_hash: str) -> DeviceCodeRecord | None:
        """The live request a typed user code names, or `None`."""

    @abstractmethod
    def decide(
        self,
        device_code_hash: str,
        *,
        status: DeviceCodeStatus,
        user_id: str,
        scopes: tuple[str, ...],
        auth_time: int,
    ) -> bool:
        """Move a pending request to approved or denied, answering whether it was still pending.

        Conditional on the pending state, so a code can be decided once and only once.
        """

    @abstractmethod
    def record_poll(self, device_code_hash: str, *, now: int, interval: int) -> bool:
        """Stamp a poll when the last one was at least `interval` seconds ago.

        Answers `False` when the client polled too soon, which is `slow_down`.
        """

    @abstractmethod
    def slow_down(self, device_code_hash: str, *, interval: int) -> None:
        """Raise the interval a too-eager client must now respect."""

    @abstractmethod
    def consume(self, device_code_hash: str) -> DeviceCodeRecord | None:
        """Atomically remove a decided request and return it, or `None` when already taken."""


class DeviceGrantStore(ABC):
    """The `device-grants` table: hash `grant_id`, GSI `user_id-index`, TTL at the session cap."""

    @abstractmethod
    def put(self, record: DeviceGrantRecord) -> None:
        """Write a new grant."""

    @abstractmethod
    def get(self, grant_id: str) -> DeviceGrantRecord | None:
        """The grant, strongly consistent, or `None` when unknown."""

    @abstractmethod
    def rotate(self, grant_id: str, *, presented_hash: str, successor_hash: str, used_at: str) -> bool:
        """Swap the refresh hash when `presented_hash` is still current and the grant live.

        One conditional write, so two concurrent refreshes cannot both win.
        """

    @abstractmethod
    def revoke(self, grant_id: str) -> bool:
        """Mark a grant revoked, answering whether it existed. Idempotent."""

    @abstractmethod
    def list_for_user(self, user_id: str) -> list[DeviceGrantRecord]:
        """Every grant this user holds. Backed by the GSI, so it may be stale."""

    def revoke_all_for_user(self, user_id: str) -> int:
        """Revoke every grant this user holds, answering how many were live."""
        revoked = 0
        for record in self.list_for_user(user_id):
            if not record.revoked and self.revoke(record.grant_id):
                revoked += 1
        return revoked


@dataclass(frozen=True, slots=True)
class DeviceGrantStores:
    """The two stores the device grant takes, in one object."""

    codes: DeviceCodeStore
    grants: DeviceGrantStore


class InMemoryDeviceCodeStore(DeviceCodeStore):
    """Dict-backed `DeviceCodeStore`, honouring the TTL the real table reclaims on."""

    def __init__(self) -> None:
        """Start with an empty backing dict."""
        self._items: dict[str, DeviceCodeRecord] = {}

    def put(self, record: DeviceCodeRecord) -> None:
        """Write a request."""
        self._items[record.device_code_hash] = record

    def get(self, device_code_hash: str) -> DeviceCodeRecord | None:
        """The request, or `None` when unknown or expired."""
        record = self._items.get(device_code_hash)
        if record is None or is_expired(record.expires_at):
            return None
        return record

    def find_by_user_code(self, user_code_hash: str) -> DeviceCodeRecord | None:
        """The live request a user code names, or `None`."""
        for record in self._items.values():
            if record.user_code_hash == user_code_hash and not is_expired(record.expires_at):
                return record
        return None

    def decide(
        self,
        device_code_hash: str,
        *,
        status: DeviceCodeStatus,
        user_id: str,
        scopes: tuple[str, ...],
        auth_time: int,
    ) -> bool:
        """Decide a pending request once."""
        record = self.get(device_code_hash)
        if record is None or record.status != "pending":
            return False
        self._items[device_code_hash] = dataclasses.replace(
            record, status=status, user_id=user_id, scopes=scopes, auth_time=auth_time
        )
        return True

    def record_poll(self, device_code_hash: str, *, now: int, interval: int) -> bool:
        """Stamp a poll unless it came too soon."""
        record = self._items.get(device_code_hash)
        if record is None:
            return True
        if record.last_polled_at and now - record.last_polled_at < interval:
            return False
        self._items[device_code_hash] = dataclasses.replace(record, last_polled_at=now)
        return True

    def slow_down(self, device_code_hash: str, *, interval: int) -> None:
        """Raise the polling interval."""
        record = self._items.get(device_code_hash)
        if record is not None:
            self._items[device_code_hash] = dataclasses.replace(record, interval=interval)

    def consume(self, device_code_hash: str) -> DeviceCodeRecord | None:
        """Remove a decided request once."""
        record = self._items.get(device_code_hash)
        if record is None or record.status == "pending":
            return None
        return self._items.pop(device_code_hash)


class InMemoryDeviceGrantStore(DeviceGrantStore):
    """Dict-backed `DeviceGrantStore`."""

    def __init__(self) -> None:
        """Start with an empty backing dict."""
        self._items: dict[str, DeviceGrantRecord] = {}

    def put(self, record: DeviceGrantRecord) -> None:
        """Write a grant."""
        self._items[record.grant_id] = record

    def get(self, grant_id: str) -> DeviceGrantRecord | None:
        """The grant, or `None`."""
        return self._items.get(grant_id)

    def rotate(self, grant_id: str, *, presented_hash: str, successor_hash: str, used_at: str) -> bool:
        """Swap the refresh hash when the presented one is still current."""
        record = self._items.get(grant_id)
        if record is None or record.revoked or record.refresh_hash != presented_hash:
            return False
        self._items[grant_id] = dataclasses.replace(
            record,
            refresh_hash=successor_hash,
            previous_refresh_hash=presented_hash,
            generation=record.generation + 1,
            last_used_at=used_at,
        )
        return True

    def revoke(self, grant_id: str) -> bool:
        """Mark a grant revoked."""
        record = self._items.get(grant_id)
        if record is None:
            return False
        self._items[grant_id] = dataclasses.replace(record, revoked=True)
        return True

    def list_for_user(self, user_id: str) -> list[DeviceGrantRecord]:
        """Every grant this user holds."""
        return [record for record in self._items.values() if record.user_id == user_id]


class DynamoDeviceCodeStore(DeviceCodeStore):
    """`DeviceCodeStore` over a `webbpulse.dynamodb.Repository`, with a `user_code_hash-index` GSI."""

    def __init__(self, repository: Repository, *, user_code_index: str = DEVICE_CODE_USER_CODE_INDEX) -> None:
        """Bind this store to its repository and the name of its user code index."""
        self._repo = repository
        self._index = user_code_index

    def put(self, record: DeviceCodeRecord) -> None:
        """Write a request."""
        self._repo.put(_code_item(record))

    def get(self, device_code_hash: str) -> DeviceCodeRecord | None:
        """The request, strongly consistent, or `None` when unknown or expired."""
        item = self._repo.get({"device_code_hash": device_code_hash}, consistent=True)
        if item is None:
            return None
        record = _code_from_item(item)
        return None if is_expired(record.expires_at) else record

    def find_by_user_code(self, user_code_hash: str) -> DeviceCodeRecord | None:
        """The live request a user code names, read back consistently from the table."""
        from boto3.dynamodb.conditions import Key

        for item in self._repo.iter_query(Key("user_code_hash").eq(user_code_hash), index_name=self._index):
            record = self.get(str(item["device_code_hash"]))
            if record is not None:
                return record
        return None

    def decide(
        self,
        device_code_hash: str,
        *,
        status: DeviceCodeStatus,
        user_id: str,
        scopes: tuple[str, ...],
        auth_time: int,
    ) -> bool:
        """Decide a pending request with one update conditioned on it still being pending."""
        return self._conditional_update(
            device_code_hash,
            update="SET #status = :status, user_id = :user, scopes = :scopes, auth_time = :auth",
            condition="#status = :pending",
            names={"#status": "status"},
            values={
                ":status": status,
                ":user": user_id,
                ":scopes": list(scopes),
                ":auth": auth_time,
                ":pending": "pending",
            },
        )

    def record_poll(self, device_code_hash: str, *, now: int, interval: int) -> bool:
        """Stamp a poll with one update conditioned on the previous one being old enough."""
        return self._conditional_update(
            device_code_hash,
            update="SET last_polled_at = :now",
            condition="attribute_not_exists(last_polled_at) OR last_polled_at <= :cutoff",
            names={},
            values={":now": now, ":cutoff": now - interval},
            missing_ok=True,
        )

    def slow_down(self, device_code_hash: str, *, interval: int) -> None:
        """Raise the polling interval."""
        self._conditional_update(
            device_code_hash,
            update="SET #interval = :interval",
            condition="attribute_exists(device_code_hash)",
            names={"#interval": "interval"},
            values={":interval": interval},
        )

    def consume(self, device_code_hash: str) -> DeviceCodeRecord | None:
        """Delete a decided request, one `DeleteItem` conditioned on it no longer being pending."""
        from botocore.exceptions import ClientError

        try:
            response = self._repo.table.delete_item(
                Key={"device_code_hash": device_code_hash},
                ConditionExpression="#status <> :pending",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={":pending": "pending"},
                ReturnValues="ALL_OLD",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                raise
            return None
        attributes = response.get("Attributes")
        return _code_from_item(attributes) if attributes else None

    def _conditional_update(
        self,
        device_code_hash: str,
        *,
        update: str,
        condition: str,
        names: Mapping[str, str],
        values: Mapping[str, Any],
        missing_ok: bool = False,
    ) -> bool:
        """Run one conditional update, answering whether its condition held."""
        from botocore.exceptions import ClientError

        exists = "attribute_exists(device_code_hash)"
        kwargs: dict[str, Any] = {
            "Key": {"device_code_hash": device_code_hash},
            "UpdateExpression": update,
            "ConditionExpression": f"{exists} AND ({condition})",
            "ExpressionAttributeValues": dict(values),
        }
        if names:
            kwargs["ExpressionAttributeNames"] = dict(names)
        try:
            self._repo.table.update_item(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                raise
            return missing_ok and self.get(device_code_hash) is None
        return True


class DynamoDeviceGrantStore(DeviceGrantStore):
    """`DeviceGrantStore` over a `webbpulse.dynamodb.Repository`, with a `user_id-index` GSI."""

    def __init__(self, repository: Repository, *, user_index: str = DEVICE_GRANT_USER_INDEX) -> None:
        """Bind this store to its repository and the name of its user index."""
        self._repo = repository
        self._user_index = user_index

    def put(self, record: DeviceGrantRecord) -> None:
        """Write a grant."""
        self._repo.put(
            {
                "grant_id": record.grant_id,
                "user_id": record.user_id,
                "client_id": record.client_id,
                "scopes": list(record.scopes),
                "created_at": record.created_at,
                "refresh_hash": record.refresh_hash,
                "previous_refresh_hash": record.previous_refresh_hash,
                "generation": record.generation,
                "auth_time": record.auth_time,
                "revoked": record.revoked,
                "last_used_at": record.last_used_at,
                IDENTITY_TTL_ATTRIBUTE: record.expires_at,
            }
        )

    def get(self, grant_id: str) -> DeviceGrantRecord | None:
        """The grant, strongly consistent, or `None`."""
        item = self._repo.get({"grant_id": grant_id}, consistent=True)
        return None if item is None else _grant_from_item(item)

    def rotate(self, grant_id: str, *, presented_hash: str, successor_hash: str, used_at: str) -> bool:
        """Swap the refresh hash with one update conditioned on the presented hash being current."""
        from botocore.exceptions import ClientError

        try:
            self._repo.table.update_item(
                Key={"grant_id": grant_id},
                UpdateExpression=(
                    "SET refresh_hash = :next, previous_refresh_hash = :presented, "
                    "generation = generation + :one, last_used_at = :used"
                ),
                ConditionExpression="refresh_hash = :presented AND revoked = :false",
                ExpressionAttributeValues={
                    ":next": successor_hash,
                    ":presented": presented_hash,
                    ":one": 1,
                    ":used": used_at,
                    ":false": False,
                },
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                raise
            return False
        return True

    def revoke(self, grant_id: str) -> bool:
        """Mark a grant revoked with an update conditioned on the row existing."""
        from botocore.exceptions import ClientError

        try:
            self._repo.table.update_item(
                Key={"grant_id": grant_id},
                UpdateExpression="SET revoked = :true",
                ConditionExpression="attribute_exists(grant_id)",
                ExpressionAttributeValues={":true": True},
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                raise
            return False
        return True

    def list_for_user(self, user_id: str) -> list[DeviceGrantRecord]:
        """Every grant this user holds, through the GSI."""
        from boto3.dynamodb.conditions import Key

        items = self._repo.iter_query(Key("user_id").eq(user_id), index_name=self._user_index)
        return [_grant_from_item(item) for item in items]


def _code_item(record: DeviceCodeRecord) -> dict[str, Any]:
    """The DynamoDB item for a `DeviceCodeRecord`."""
    return {
        "device_code_hash": record.device_code_hash,
        "user_code_hash": record.user_code_hash,
        "client_id": record.client_id,
        "scopes": list(record.scopes),
        "created_at": record.created_at,
        "interval": record.interval,
        "status": record.status,
        "user_id": record.user_id,
        "auth_time": record.auth_time,
        "last_polled_at": record.last_polled_at,
        IDENTITY_TTL_ATTRIBUTE: record.expires_at,
    }


def _code_from_item(item: Mapping[str, Any]) -> DeviceCodeRecord:
    """Build a `DeviceCodeRecord` from a DynamoDB item."""
    status = str(item.get("status", "pending"))
    return DeviceCodeRecord(
        device_code_hash=str(item["device_code_hash"]),
        user_code_hash=str(item.get("user_code_hash", "")),
        client_id=str(item.get("client_id", "")),
        scopes=tuple(str(value) for value in item.get("scopes", [])),
        created_at=str(item.get("created_at", "")),
        expires_at=int(item.get(IDENTITY_TTL_ATTRIBUTE, 0)),
        interval=int(item.get("interval", 0)),
        status="approved" if status == "approved" else "denied" if status == "denied" else "pending",
        user_id=str(item.get("user_id", "")),
        auth_time=int(item.get("auth_time", 0)),
        last_polled_at=int(item.get("last_polled_at", 0)),
    )


def _grant_from_item(item: Mapping[str, Any]) -> DeviceGrantRecord:
    """Build a `DeviceGrantRecord` from a DynamoDB item."""
    return DeviceGrantRecord(
        grant_id=str(item["grant_id"]),
        user_id=str(item.get("user_id", "")),
        client_id=str(item.get("client_id", "")),
        scopes=tuple(str(value) for value in item.get("scopes", [])),
        created_at=str(item.get("created_at", "")),
        expires_at=int(item.get(IDENTITY_TTL_ATTRIBUTE, 0)),
        refresh_hash=str(item.get("refresh_hash", "")),
        previous_refresh_hash=str(item.get("previous_refresh_hash", "")),
        generation=int(item.get("generation", 1)),
        auth_time=int(item.get("auth_time", 0)),
        revoked=bool(item.get("revoked", False)),
        last_used_at=str(item.get("last_used_at", "")),
    )


DEVICE_GRANT_TABLES: Final[tuple[TableSpec, ...]] = (
    TableSpec(
        logical_name=DEVICE_CODES_TABLE,
        attributes=(TableAttribute("device_code_hash", "S"), TableAttribute("user_code_hash", "S")),
        hash_key="device_code_hash",
        global_secondary_indexes=(
            TableIndex(name=DEVICE_CODE_USER_CODE_INDEX, hash_key="user_code_hash", projection_type="KEYS_ONLY"),
        ),
        ttl_attribute=IDENTITY_TTL_ATTRIBUTE,
    ),
    TableSpec(
        logical_name=DEVICE_GRANTS_TABLE,
        attributes=(TableAttribute("grant_id", "S"), TableAttribute("user_id", "S")),
        hash_key="grant_id",
        global_secondary_indexes=(TableIndex(name=DEVICE_GRANT_USER_INDEX, hash_key="user_id"),),
        ttl_attribute=IDENTITY_TTL_ATTRIBUTE,
    ),
)
"""The two tables the device grant adds, in `TableSpec` form.

Kept separate from `TABLES`, so a product that mounts identity without the device grant
flag provisions nothing it does not use.
"""
