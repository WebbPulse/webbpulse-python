"""Storage for the OAuth device authorization grant (RFC 8628): pending codes and live grants.

Two tables alongside the identity ones, following the same rules: only hashes of anything
bearer-like are stored, every state change is one conditional operation, and every TTL is
storage reclamation with the deadline re-checked in code.

The `device-codes` table also holds three kinds of bookkeeping item under the same hash key,
so the grant needs no table, index or key attribute beyond the two it provisions: a
`user#<user code hash>` reservation that makes a user code unique while it lives, a
`fail#<user id>#<window>` counter of failed user code lookups, and an `owner#<user id>`
set of the device code hashes a person decided, so `purge_user` can find them without a
scan. None carries `user_code_hash`, so none appears in the index, and no device code
hashes to any of them.
"""

from __future__ import annotations

import dataclasses
import time
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

_RESERVATION_PREFIX: Final = "user#"
_FAILURE_PREFIX: Final = "fail#"
_OWNER_PREFIX: Final = "owner#"
_BOOKKEEPING_PREFIXES: Final = (_RESERVATION_PREFIX, _FAILURE_PREFIX, _OWNER_PREFIX)

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
    it again is recognised: inside the grace window after `rotated_at` it is a lost race and
    answered idempotently, and after it, reuse that ends the grant.
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
    rotated_at: int = 0

    def live(self) -> bool:
        """Whether the grant is neither revoked nor past its session cap."""
        return not self.revoked and not is_expired(self.expires_at)


class DeviceCodeStore(ABC):
    """The `device-codes` table: hash `device_code_hash`, GSI `user_code_hash-index`, TTL `expires_at`."""

    @abstractmethod
    def put(self, record: DeviceCodeRecord) -> bool:
        """Write a freshly issued request, answering `False` when its user code is taken.

        One conditional write covering the request and its user code reservation, so two
        live requests can never share a user code; the caller draws another and retries.
        """

    @abstractmethod
    def get(self, device_code_hash: str, *, include_expired: bool = False) -> DeviceCodeRecord | None:
        """The request, strongly consistent, or `None` when unknown, or expired unless asked for."""

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
    def consume(self, device_code_hash: str, *, now: int | None = None) -> DeviceCodeRecord | None:
        """Atomically remove a decided, unexpired request and return it, or `None` otherwise."""

    @abstractmethod
    def failed_lookups(self, user_id: str, *, now: int, window: int) -> int:
        """How many user code lookups this user has failed in the current window."""

    @abstractmethod
    def record_failed_lookup(self, user_id: str, *, now: int, window: int) -> int:
        """Count one failed user code lookup for this user, answering the new total."""

    def delete_all_for_user(self, user_id: str, *, now: int | None = None, window: int = 0) -> int:
        """Delete every request this user decided and their failure counters. Used by `purge_user`.

        Answers how many requests went. `window` is the failure counter window, so the
        current and previous counters can be named and removed.
        """
        raise NotImplementedError


class DeviceGrantStore(ABC):
    """The `device-grants` table: hash `grant_id`, GSI `user_id-index`, TTL at the session cap."""

    @abstractmethod
    def put(self, record: DeviceGrantRecord) -> None:
        """Write a new grant."""

    @abstractmethod
    def get(self, grant_id: str) -> DeviceGrantRecord | None:
        """The grant, strongly consistent, or `None` when unknown."""

    @abstractmethod
    def rotate(
        self, grant_id: str, *, presented_hash: str, successor_hash: str, used_at: str, rotated_at: int = 0
    ) -> bool:
        """Swap the refresh hash when `presented_hash` is still current and the grant live.

        One conditional write, so two concurrent refreshes cannot both win. `rotated_at` is
        stamped so the loser can be recognised inside the grace window.
        """

    @abstractmethod
    def revoke(self, grant_id: str) -> bool:
        """Mark a grant revoked, answering whether it existed. Idempotent."""

    @abstractmethod
    def delete(self, grant_id: str) -> bool:
        """Delete a grant outright, answering whether it existed."""

    @abstractmethod
    def list_for_user(self, user_id: str) -> list[DeviceGrantRecord]:
        """Every grant this user holds. Backed by the GSI, so it may be stale."""

    def delete_all_for_user(self, user_id: str) -> int:
        """Delete every grant this user holds, answering how many went. Used by `purge_user`."""
        deleted = 0
        for record in self.list_for_user(user_id):
            if self.delete(record.grant_id):
                deleted += 1
        return deleted

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
        """Start with empty backing dicts."""
        self._items: dict[str, DeviceCodeRecord] = {}
        self._reservations: dict[str, int] = {}
        self._failures: dict[str, int] = {}

    def put(self, record: DeviceCodeRecord) -> bool:
        """Write a request unless a live one already holds its user code."""
        held = self._reservations.get(record.user_code_hash)
        if held is not None and not is_expired(held):
            return False
        if record.device_code_hash in self._items:
            return False
        self._reservations[record.user_code_hash] = record.expires_at
        self._items[record.device_code_hash] = record
        return True

    def get(self, device_code_hash: str, *, include_expired: bool = False) -> DeviceCodeRecord | None:
        """The request, or `None` when unknown, or expired unless asked for."""
        record = self._items.get(device_code_hash)
        if record is None or (is_expired(record.expires_at) and not include_expired):
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

    def consume(self, device_code_hash: str, *, now: int | None = None) -> DeviceCodeRecord | None:
        """Remove a decided, unexpired request once."""
        moment = int(time.time()) if now is None else now
        record = self._items.get(device_code_hash)
        if record is None or record.status == "pending" or record.expires_at <= moment:
            return None
        return self._items.pop(device_code_hash)

    def failed_lookups(self, user_id: str, *, now: int, window: int) -> int:
        """Failed lookups for this user in the current window."""
        return self._failures.get(_failure_key(user_id, now=now, window=window), 0)

    def delete_all_for_user(self, user_id: str, *, now: int | None = None, window: int = 0) -> int:
        """Delete this user's decided requests and failure counters."""
        mine = [key for key, record in self._items.items() if record.user_id == user_id]
        for key in mine:
            del self._items[key]
        prefix = f"{_FAILURE_PREFIX}{user_id}#"
        for key in [key for key in self._failures if key.startswith(prefix)]:
            del self._failures[key]
        return len(mine)

    def record_failed_lookup(self, user_id: str, *, now: int, window: int) -> int:
        """Count one failed lookup."""
        key = _failure_key(user_id, now=now, window=window)
        self._failures[key] = self._failures.get(key, 0) + 1
        return self._failures[key]


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

    def rotate(
        self, grant_id: str, *, presented_hash: str, successor_hash: str, used_at: str, rotated_at: int = 0
    ) -> bool:
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
            rotated_at=rotated_at,
        )
        return True

    def delete(self, grant_id: str) -> bool:
        """Delete a grant."""
        return self._items.pop(grant_id, None) is not None

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

    def put(self, record: DeviceCodeRecord) -> bool:
        """Write the request and its user code reservation in one conditional transaction."""
        from boto3.dynamodb.conditions import Attr

        from webbpulse.dynamodb import TransactionCanceled

        now = int(time.time())
        vacant = Attr("device_code_hash").not_exists() | Attr(IDENTITY_TTL_ATTRIBUTE).lt(now)
        reservation = {
            "device_code_hash": f"{_RESERVATION_PREFIX}{record.user_code_hash}",
            IDENTITY_TTL_ATTRIBUTE: record.expires_at,
        }
        try:
            self._repo.transact_write(
                [
                    self._repo.put_action(reservation, condition=vacant),
                    self._repo.put_action(_code_item(record), condition=Attr("device_code_hash").not_exists()),
                ]
            )
        except TransactionCanceled as exc:
            if not exc.conditional_check_failed:
                raise
            return False
        return True

    def get(self, device_code_hash: str, *, include_expired: bool = False) -> DeviceCodeRecord | None:
        """The request, strongly consistent, or `None` when unknown, or expired unless asked for."""
        if device_code_hash.startswith(_BOOKKEEPING_PREFIXES):
            return None
        item = self._repo.get({"device_code_hash": device_code_hash}, consistent=True)
        if item is None:
            return None
        record = _code_from_item(item)
        return None if is_expired(record.expires_at) and not include_expired else record

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
        """Decide a pending request with one update conditioned on it still being pending.

        A decided request is then listed under its person's `owner#` item, so `purge_user`
        can delete it; that item lives as long as the longest a request can.
        """
        decided = self._conditional_update(
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
        if decided and user_id:
            from webbpulse.identity.settings import MAX_DEVICE_CODE_TTL

            self._repo.table.update_item(
                Key={"device_code_hash": f"{_OWNER_PREFIX}{user_id}"},
                UpdateExpression="ADD codes :code SET #expires = :expires",
                ExpressionAttributeNames={"#expires": IDENTITY_TTL_ATTRIBUTE},
                ExpressionAttributeValues={
                    ":code": {device_code_hash},
                    ":expires": int(time.time()) + int(MAX_DEVICE_CODE_TTL.total_seconds()),
                },
            )
        return decided

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

    def consume(self, device_code_hash: str, *, now: int | None = None) -> DeviceCodeRecord | None:
        """Delete a decided request, one `DeleteItem` conditioned on it being decided and unexpired."""
        from botocore.exceptions import ClientError

        moment = int(time.time()) if now is None else now
        try:
            response = self._repo.table.delete_item(
                Key={"device_code_hash": device_code_hash},
                ConditionExpression="#status <> :pending AND #expires > :now",
                ExpressionAttributeNames={"#status": "status", "#expires": IDENTITY_TTL_ATTRIBUTE},
                ExpressionAttributeValues={":pending": "pending", ":now": moment},
                ReturnValues="ALL_OLD",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                raise
            return None
        attributes = response.get("Attributes")
        return _code_from_item(attributes) if attributes else None

    def failed_lookups(self, user_id: str, *, now: int, window: int) -> int:
        """Failed lookups for this user in the current window, read consistently."""
        item = self._repo.get({"device_code_hash": _failure_key(user_id, now=now, window=window)}, consistent=True)
        if item is None or int(item.get(IDENTITY_TTL_ATTRIBUTE, 0)) <= now:
            return 0
        return int(item.get("failures", 0))

    def delete_all_for_user(self, user_id: str, *, now: int | None = None, window: int = 0) -> int:
        """Delete the requests listed under this user's `owner#` item, the item, and their failure counters."""
        owner_key = {"device_code_hash": f"{_OWNER_PREFIX}{user_id}"}
        owner = self._repo.get(owner_key, consistent=True)
        deleted = 0
        for code_hash in sorted(str(code) for code in (owner or {}).get("codes", ()) or ()):
            if not self._owned(code_hash, user_id):
                continue
            response = self._repo.table.delete_item(Key={"device_code_hash": code_hash}, ReturnValues="ALL_OLD")
            if response.get("Attributes"):
                deleted += 1
        self._repo.table.delete_item(Key=owner_key)
        if window > 0:
            moment = int(time.time()) if now is None else now
            for offset in (0, window):
                self._repo.table.delete_item(
                    Key={"device_code_hash": _failure_key(user_id, now=moment - offset, window=window)}
                )
        return deleted

    def _owned(self, device_code_hash: str, user_id: str) -> bool:
        """Whether this request is still there and decided by `user_id`."""
        if device_code_hash.startswith(_BOOKKEEPING_PREFIXES):
            return False
        record = self.get(device_code_hash, include_expired=True)
        return record is not None and record.user_id == user_id

    def record_failed_lookup(self, user_id: str, *, now: int, window: int) -> int:
        """Count one failed lookup with an atomic `ADD`, expiring the counter with its window."""
        response = self._repo.table.update_item(
            Key={"device_code_hash": _failure_key(user_id, now=now, window=window)},
            UpdateExpression="ADD failures :one SET #expires = if_not_exists(#expires, :expires)",
            ExpressionAttributeNames={"#expires": IDENTITY_TTL_ATTRIBUTE},
            ExpressionAttributeValues={":one": 1, ":expires": (now // window + 1) * window},
            ReturnValues="UPDATED_NEW",
        )
        attributes: Mapping[str, Any] = response.get("Attributes") or {}
        return int(attributes.get("failures", 1))

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
                "rotated_at": record.rotated_at,
                IDENTITY_TTL_ATTRIBUTE: record.expires_at,
            }
        )

    def get(self, grant_id: str) -> DeviceGrantRecord | None:
        """The grant, strongly consistent, or `None`."""
        item = self._repo.get({"grant_id": grant_id}, consistent=True)
        return None if item is None else _grant_from_item(item)

    def rotate(
        self, grant_id: str, *, presented_hash: str, successor_hash: str, used_at: str, rotated_at: int = 0
    ) -> bool:
        """Swap the refresh hash with one update conditioned on the presented hash being current."""
        from botocore.exceptions import ClientError

        try:
            self._repo.table.update_item(
                Key={"grant_id": grant_id},
                UpdateExpression=(
                    "SET refresh_hash = :next, previous_refresh_hash = :presented, "
                    "generation = generation + :one, last_used_at = :used, rotated_at = :rotated"
                ),
                ConditionExpression="refresh_hash = :presented AND revoked = :false",
                ExpressionAttributeValues={
                    ":next": successor_hash,
                    ":presented": presented_hash,
                    ":one": 1,
                    ":used": used_at,
                    ":rotated": rotated_at,
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

    def delete(self, grant_id: str) -> bool:
        """Delete a grant, answering whether a row was there."""
        response = self._repo.table.delete_item(Key={"grant_id": grant_id}, ReturnValues="ALL_OLD")
        return bool(response.get("Attributes"))

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
        rotated_at=int(item.get("rotated_at", 0)),
    )


def _failure_key(user_id: str, *, now: int, window: int) -> str:
    """The `device-codes` key of a user's failed lookup counter for the window `now` falls in."""
    return f"{_FAILURE_PREFIX}{user_id}#{now // window}"


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
