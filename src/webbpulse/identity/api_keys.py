"""Long-lived API keys for machine callers, and the adapter onto the authorizer's claims.

A key is minted once, shown once, and stored only as a SHA-256 hash, exactly as the refresh
and emailed-link tokens are. Verification is one point lookup on that hash, so a key costs
the same as a token does and nothing in the table can be replayed if the table leaks.

A key is a delegation, never a promotion: the scopes it carries are the scopes its minter
held at mint time, and a request must intersect them with the minter's live membership
through `effective_scopes` before authorizing anything. The stored scope set is a ceiling,
and a key whose owner has lost a role keeps a claim it can no longer spend.
"""

from __future__ import annotations

import dataclasses
import hashlib
import logging
import secrets
import uuid
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

from webbpulse.dynamodb import ReadOnlyTable, now_iso
from webbpulse.identity.claims import AuthorizerClaims
from webbpulse.identity.storage import (
    TableAttribute,
    TableIndex,
    TableSpec,
    constant_time_equals,
)

if TYPE_CHECKING:  # pragma: no cover
    from webbpulse.dynamodb import Repository

__all__ = [
    "ACTOR_API_KEY",
    "ACTOR_CLAIM",
    "API_KEYS_TABLE",
    "API_KEY_PREFIX",
    "API_KEY_TABLE",
    "API_KEY_TENANT_INDEX",
    "API_KEY_USER_INDEX",
    "KEY_BYTES",
    "KIND_USER",
    "PREFIX_DISPLAY_LENGTH",
    "TENANT_CLAIM",
    "ApiKeyRecord",
    "ApiKeyStore",
    "DynamoApiKeyStore",
    "FakeApiKeyStore",
    "InMemoryApiKeyStore",
    "MintedApiKey",
    "claims_for_key",
    "effective_scopes",
    "hash_key",
    "is_api_key",
    "mint",
    "new_key",
    "new_key_id",
    "revoke",
    "revoke_by_id",
    "verify",
    "verify_for_tenant",
]

_log = logging.getLogger(__name__)

API_KEYS_TABLE: Final = "api-keys"
"""The logical table name, prefixed by the environment like every other identity table."""

API_KEY_USER_INDEX: Final = "user_id-created_at-index"
"""The GSI that lists one user's keys, newest last, for a settings page and for purge."""

API_KEY_TENANT_INDEX: Final = "tenant_id-created_at-index"
"""The GSI that lists one tenant's keys, newest last, for a multi-tenant admin page.

A multi-tenant product's key list is "every key in this workspace", which the `key_hash`
partition cannot answer and `API_KEY_USER_INDEX` answers only one person at a time. Without
this index that listing is a scan, so a product either grew its own table beside this one or
paid for a scan on a human-facing page. Both are what this index removes.
"""

API_KEY_PREFIX: Final = "wpk_"
"""The literal every plaintext key starts with.

A fixed prefix is what lets a bearer credential be told apart from a JWT without parsing it,
and it is what secret scanners match on to catch a key pushed to a repository.
"""

KEY_BYTES: Final = 32
"""256 bits of CSPRNG entropy in the secret half, matching `storage.new_token`."""

PREFIX_DISPLAY_LENGTH: Final = 12
"""How much of the plaintext is kept in the clear, so a person can tell two keys apart.

Twelve characters covers `wpk_` plus eight of the secret. That leaves well over 200 bits
unknown, so the displayed prefix narrows a guess by nothing that matters.
"""

TENANT_CLAIM: Final = "tenant_id"
"""The claim carrying the tenant a key acts inside, matching what the gateway emits."""

ACTOR_CLAIM: Final = "actor_kind"
"""The claim naming what kind of caller this is, so a route can refuse a key outright."""

ACTOR_API_KEY: Final = "api_key"
"""The `ACTOR_CLAIM` value marking a request authenticated by an API key rather than a user."""

KIND_USER: Final = "user"
"""The default `kind`: a key that acts as the person who minted it.

A free-form string rather than an enum, because what kinds exist is a product's decision. A
second kind is usually a service key acting as the tenant rather than as a person, which
matters because it survives its minter leaving, but nothing here depends on that meaning.
"""


def new_key_id() -> str:
    """A fresh key id: a revoke handle that is not the secret and not its hash.

    A uuid4 rather than a ULID, so this module does not depend on an id scheme outside it. The
    id is not a credential and orders nothing, so its only requirement is uniqueness.
    """
    return uuid.uuid4().hex


def new_key() -> str:
    """A fresh plaintext key: `API_KEY_PREFIX` followed by 256 base64url bits.

    `secrets.token_urlsafe` rather than `uuid4`, for the same reason `storage.new_token`
    gives: a uuid's 122 bits and fixed version characters are a poor shape for a value whose
    only job is to be unguessable.
    """
    return f"{API_KEY_PREFIX}{secrets.token_urlsafe(KEY_BYTES)}"


def hash_key(plaintext: str) -> str:
    """The stored form of a key: hex SHA-256 of its UTF-8 bytes, prefix included.

    SHA-256 and not bcrypt, because the secret half carries 256 bits from a CSPRNG and there
    is nothing to brute-force. Hex because the value is the table's partition key.
    """
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def is_api_key(candidate: str) -> bool:
    """Whether a presented bearer credential is shaped like one of this package's API keys.

    A prefix test only. It decides which verifier a bearer value is handed to, never whether
    the value is genuine, so a JWT is not run through the key lookup and a key is not run
    through signature verification.
    """
    return candidate.startswith(API_KEY_PREFIX)


def display_prefix(plaintext: str) -> str:
    """The clear-text fragment stored for display, truncated to `PREFIX_DISPLAY_LENGTH`."""
    return plaintext[:PREFIX_DISPLAY_LENGTH]


def _now() -> datetime:
    """The current UTC time, as one seam every expiry check in this module shares."""
    return datetime.now(UTC)


def _normalise_scopes(scopes: Iterable[str]) -> tuple[str, ...]:
    """De-duplicate and sort a scope set, dropping blanks.

    Sorted so a record's scopes render and compare the same way whatever order the caller
    passed them in, and so the `scope` claim a key produces is stable across mints.
    """
    return tuple(sorted({scope.strip() for scope in scopes if scope.strip()}))


@dataclass(frozen=True, slots=True)
class ApiKeyRecord:
    """One stored API key. Holds the hash and never the plaintext.

    `prefix` is the only clear-text fragment, and exists so a person can recognise a key in a
    list without the list being able to authenticate as one of them. `scopes` is the ceiling
    the key was minted with, not the authority it currently has: see `effective_scopes`.

    `key_id` is the revoke handle. It is deliberately not the hash: a settings page that has
    to name the hash to revoke a key is rendering a value that, for the older callers who
    passed the plaintext through `revoke`, is one hash away from the credential itself. An id
    is a name and nothing more, so it can be put in a URL. It defaults empty, and a record
    loaded from a row written before this field existed has no id: `revoke_handle` is what a
    caller reads to get a handle either way.

    `kind`, `created_by` and `metadata` are the product's own dimensions, none of which this
    package interprets. `metadata` round-trips through the store untouched, so a product does
    not grow a second table beside this one to hold two extra fields.
    """

    key_hash: str
    user_id: str
    tenant_id: str
    prefix: str
    scopes: tuple[str, ...] = ()
    name: str = ""
    created_at: str = ""
    expires_at: int = 0
    last_used_at: str = ""
    revoked_at: str = ""
    key_id: str = ""
    kind: str = KIND_USER
    created_by: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def revoke_handle(self) -> str:
        """The value to revoke this key by: its `key_id`, falling back to its hash.

        The fallback is what keeps a row written before `key_id` existed revocable by the same
        call as a new one. It is a fallback and not a migration: the row still has no id, so a
        listing that renders this value renders the hash for an old key and an id for a new
        one, and `revoke_by_id` accepts both.
        """
        return self.key_id or self.key_hash

    @property
    def is_revoked(self) -> bool:
        """Whether this key has been revoked."""
        return bool(self.revoked_at)

    def is_expired(self, *, now: datetime | None = None) -> bool:
        """Whether this key's expiry has passed. A zero `expires_at` never expires."""
        if not self.expires_at:
            return False
        return (now or _now()).timestamp() >= self.expires_at

    def is_usable(self, *, now: datetime | None = None) -> bool:
        """Whether this key may authenticate a request right now."""
        return not self.is_revoked and not self.is_expired(now=now)


@dataclass(frozen=True, slots=True)
class MintedApiKey:
    """The one moment a plaintext key exists outside the caller's own storage.

    `plaintext` is returned exactly once by `mint` and is never recoverable afterwards, so a
    route that mints a key must put it in that one response and nowhere else, least of all a
    log line.
    """

    plaintext: str
    record: ApiKeyRecord


class ApiKeyStore(ABC):
    """The `api-keys` table: hash `key_hash`, `user_id-created_at-index`, no TTL.

    No TTL, deliberately. A key's `expires_at` is checked on the read path, because a key
    that vanishes from the table is indistinguishable from one that never existed, and an
    expired key a person can still see and delete is the better operator experience.
    """

    @abstractmethod
    def get(self, key_hash: str) -> ApiKeyRecord | None:
        """The record, revoked and expired ones included. The caller checks `is_usable`."""

    @abstractmethod
    def put(self, record: ApiKeyRecord) -> None:
        """Write a new key."""

    @abstractmethod
    def list_for_user(self, user_id: str) -> list[ApiKeyRecord]:
        """Every key a user holds, for a settings page. Never carries a plaintext."""

    @abstractmethod
    def revoke(self, key_hash: str, *, revoked_at: str | None = None) -> ApiKeyRecord | None:
        """Mark a key revoked, returning it as it was, or `None` when it was already gone."""

    @abstractmethod
    def touch(self, key_hash: str, *, used_at: str | None = None) -> None:
        """Record that a key was just used, best effort. A failure must never refuse a request."""

    @abstractmethod
    def delete_all_for_user(self, user_id: str) -> int:
        """Delete every key a user holds, returning how many went. The account deletion purge."""

    def list_for_tenant(self, tenant_id: str) -> list[ApiKeyRecord]:
        """Every key issued inside one tenant, for a multi-tenant admin page.

        Concrete rather than abstract so a store written before this method existed keeps
        satisfying the protocol. The default answers empty rather than scanning, because a
        store with no tenant index cannot answer this without reading the whole table and a
        silent scan on a human-facing page is worse than an empty list.
        """
        del tenant_id
        return []

    def get_by_id(self, tenant_id: str, key_id: str) -> ApiKeyRecord | None:
        """The record one tenant's `key_id` names, or `None`.

        Tenant first, so a key id from one product's URL can never resolve a row in another
        tenant even if the id were guessed. The id is matched against `revoke_handle`, so a row
        written before `key_id` existed is reachable by its hash through the same call.

        Concrete rather than abstract so a store written before this method existed keeps
        satisfying the protocol. The default is built on `list_for_tenant`, which means a store
        with no tenant index answers `None` rather than scanning.
        """
        if not tenant_id or not key_id:
            return None
        for record in self.list_for_tenant(tenant_id):
            if constant_time_equals(record.revoke_handle, key_id):
                return record
        return None

    def revoke_by_id(self, tenant_id: str, key_id: str, *, revoked_at: str | None = None) -> ApiKeyRecord | None:
        """Revoke one key by its id, without ever holding the secret or its hash.

        The verb a settings page needs: a person revoking a key has an id from a list and no
        credential, and requiring the hash would mean rendering it. Returns the record as it
        was, or `None` when there was nothing live to revoke, which is also the answer for a
        key belonging to another tenant.
        """
        record = self.get_by_id(tenant_id, key_id)
        if record is None:
            return None
        return self.revoke(record.key_hash, revoked_at=revoked_at)

    def count_for_tenant(self, tenant_id: str) -> int:
        """How many keys one tenant holds, for a per-create cap check.

        Every key, revoked ones included. A product that caps only live keys subtracts them
        itself, because "how many rows exist" is what an index can count cheaply and "how many
        are still usable" is not: revocation is an attribute, not a key, so counting around it
        would mean reading the rows.

        Concrete rather than abstract, and built on `list_for_tenant` by default, so a store
        written before this method existed keeps satisfying the protocol and one with no tenant
        index answers zero rather than scanning. `DynamoApiKeyStore` overrides it with a
        counted query that never returns a row.
        """
        return len(self.list_for_tenant(tenant_id))

    def revoke_all_for_tenant(self, tenant_id: str, *, revoked_at: str | None = None) -> int:
        """Revoke every live key of one tenant, returning how many were revoked.

        The offboarding verb: a tenant that is suspended or deleted must stop authenticating
        at once, and revoking is a write rather than a delete for the same reason one key's
        revocation is, so the rows stay visible to an operator afterwards.

        Built on `list_for_tenant`, so a store that cannot list a tenant revokes nothing and
        says so by returning zero rather than appearing to have succeeded.
        """
        revoked = 0
        for record in self.list_for_tenant(tenant_id):
            if not record.is_revoked and self.revoke(record.key_hash, revoked_at=revoked_at) is not None:
                revoked += 1
        return revoked


class InMemoryApiKeyStore(ApiKeyStore):
    """Dict-backed `ApiKeyStore`, keyed as the table is."""

    def __init__(self) -> None:
        """Start with an empty backing dict."""
        self._items: dict[str, ApiKeyRecord] = {}

    def get(self, key_hash: str) -> ApiKeyRecord | None:
        """The record, revoked and expired ones included. The caller checks `is_usable`."""
        return self._items.get(key_hash)

    def put(self, record: ApiKeyRecord) -> None:
        """Write a new key."""
        self._items[record.key_hash] = record

    def list_for_user(self, user_id: str) -> list[ApiKeyRecord]:
        """Every key a user holds, oldest first, matching the index's sort order."""
        return sorted(
            (record for record in self._items.values() if record.user_id == user_id),
            key=lambda record: record.created_at,
        )

    def revoke(self, key_hash: str, *, revoked_at: str | None = None) -> ApiKeyRecord | None:
        """Mark a key revoked, returning it as it was, or `None` when it was already gone."""
        existing = self._items.get(key_hash)
        if existing is None or existing.is_revoked:
            return None
        self._items[key_hash] = dataclasses.replace(existing, revoked_at=revoked_at or now_iso())
        return existing

    def touch(self, key_hash: str, *, used_at: str | None = None) -> None:
        """Record that a key was just used, tolerating an absent row."""
        existing = self._items.get(key_hash)
        if existing is None:
            return
        self._items[key_hash] = dataclasses.replace(existing, last_used_at=used_at or now_iso())

    def delete_all_for_user(self, user_id: str) -> int:
        """Delete every key a user holds, returning how many went."""
        hashes = [key_hash for key_hash, record in self._items.items() if record.user_id == user_id]
        for key_hash in hashes:
            del self._items[key_hash]
        return len(hashes)

    def list_for_tenant(self, tenant_id: str) -> list[ApiKeyRecord]:
        """Every key of one tenant, oldest first, matching the index's sort order."""
        return sorted(
            (record for record in self._items.values() if record.tenant_id == tenant_id),
            key=lambda record: record.created_at,
        )

    def count_for_tenant(self, tenant_id: str) -> int:
        """How many keys one tenant holds, revoked ones included."""
        return sum(1 for record in self._items.values() if record.tenant_id == tenant_id)


FakeApiKeyStore = InMemoryApiKeyStore
"""The name a test reaches for, aliasing `InMemoryApiKeyStore`.

The storage module calls its doubles `InMemory*`, so the implementation keeps that name and
this alias exists for the `Fake*` spelling the test fixtures use.
"""


def _record_to_item(record: ApiKeyRecord) -> dict[str, Any]:
    """The DynamoDB item for a record. `scopes` goes down as a list, not a joined string.

    `metadata` goes down as a map for the reason a share token's capability does: DynamoDB
    stores one natively, so a product that later wants a projection or a filter on one of its
    fields can have it, which a JSON blob forecloses.
    """
    return {
        "key_hash": record.key_hash,
        "user_id": record.user_id,
        "tenant_id": record.tenant_id,
        "prefix": record.prefix,
        "scopes": list(record.scopes),
        "name": record.name,
        "created_at": record.created_at,
        "expires_at": record.expires_at,
        "last_used_at": record.last_used_at,
        "revoked_at": record.revoked_at,
        "key_id": record.key_id,
        "kind": record.kind,
        "created_by": record.created_by or "",
        "metadata": dict(record.metadata),
    }


def _record_from_item(item: Mapping[str, Any]) -> ApiKeyRecord:
    """Rebuild a record from a DynamoDB item, tolerating an absent optional attribute.

    A row written before `key_id`, `kind`, `created_by` and `metadata` existed loads unchanged:
    the id comes back empty and `revoke_handle` falls back to the hash, the kind defaults to
    `KIND_USER`, the creator is `None` rather than an empty string so "not recorded" is
    distinguishable from "recorded as nobody", and the metadata is an empty mapping.
    """
    raw_metadata = item.get("metadata")
    metadata = dict(raw_metadata) if isinstance(raw_metadata, Mapping) else {}
    created_by = str(item.get("created_by", "") or "")
    raw_scopes = item.get("scopes") or []
    scopes = tuple(str(scope) for scope in raw_scopes) if isinstance(raw_scopes, Sequence) else ()
    return ApiKeyRecord(
        key_hash=str(item["key_hash"]),
        user_id=str(item.get("user_id", "")),
        tenant_id=str(item.get("tenant_id", "")),
        prefix=str(item.get("prefix", "")),
        scopes=scopes,
        name=str(item.get("name", "")),
        created_at=str(item.get("created_at", "")),
        expires_at=int(item.get("expires_at", 0) or 0),
        last_used_at=str(item.get("last_used_at", "")),
        revoked_at=str(item.get("revoked_at", "")),
        key_id=str(item.get("key_id", "")),
        kind=str(item.get("kind", "") or KIND_USER),
        created_by=created_by or None,
        metadata=metadata,
    )


class DynamoApiKeyStore(ApiKeyStore):
    """`ApiKeyStore` over a `webbpulse.dynamodb.Repository`, with the `user_id-created_at-index` GSI."""

    def __init__(self, repository: Repository) -> None:
        """Bind this store to the repository holding its table."""
        self._repo = repository

    def get(self, key_hash: str) -> ApiKeyRecord | None:
        """The record, read consistently: a key minted a moment ago must authenticate now."""
        item = self._repo.get({"key_hash": key_hash}, consistent=True)
        return _record_from_item(item) if item is not None else None

    def put(self, record: ApiKeyRecord) -> None:
        """Write a new key."""
        self._repo.put(_record_to_item(record))

    def list_for_user(self, user_id: str) -> list[ApiKeyRecord]:
        """Every key a user holds, from the GSI, so the read may be slightly stale."""
        from boto3.dynamodb.conditions import Key as KeyCondition

        return [
            _record_from_item(item)
            for item in self._repo.iter_query(KeyCondition("user_id").eq(user_id), index_name=API_KEY_USER_INDEX)
        ]

    def revoke(self, key_hash: str, *, revoked_at: str | None = None) -> ApiKeyRecord | None:
        """Atomically mark a key revoked, returning it as it was, or `None` if already revoked."""
        from boto3.dynamodb.conditions import Attr

        from webbpulse.dynamodb import ConditionFailed

        try:
            old = self._repo.update(
                {"key_hash": key_hash},
                update_expression="SET revoked_at = :now",
                expression_values={":now": revoked_at or now_iso()},
                condition=(Attr("key_hash").exists() & (Attr("revoked_at").not_exists() | Attr("revoked_at").eq(""))),
                return_values="ALL_OLD",
            )
        except ConditionFailed:
            return None
        return _record_from_item(old) if old else None

    def touch(self, key_hash: str, *, used_at: str | None = None) -> None:
        """Stamp `last_used_at`, swallowing every failure.

        Best effort by design: this runs on the authorization path, and a write that fails
        must not turn a good key into a refused request. A conditional check keeps it from
        resurrecting a row that was deleted between the read and this write.

        The package's own `ReadOnlyTable` refusal is swallowed alongside the AWS error, so a
        domain holding this table read-only behaves locally as it does in AWS, where the same
        write comes back as an `AccessDeniedException`.
        """
        from boto3.dynamodb.conditions import Attr
        from botocore.exceptions import ClientError

        try:
            self._repo.update(
                {"key_hash": key_hash},
                update_expression="SET last_used_at = :now",
                expression_values={":now": used_at or now_iso()},
                condition=Attr("key_hash").exists(),
            )
        except (ClientError, ReadOnlyTable) as exc:
            _log.debug("Could not stamp last_used_at on an API key: %s", exc)

    def delete_all_for_user(self, user_id: str) -> int:
        """Delete every key a user holds, enumerating through the GSI and batching the deletes."""
        from boto3.dynamodb.conditions import Key as KeyCondition

        keys = [
            {"key_hash": str(item["key_hash"])}
            for item in self._repo.iter_query(
                KeyCondition("user_id").eq(user_id),
                index_name=API_KEY_USER_INDEX,
                projection="key_hash",
            )
        ]
        if not keys:
            return 0
        return self._repo.delete_many(keys)

    def list_for_tenant(self, tenant_id: str) -> list[ApiKeyRecord]:
        """Every key of one tenant, from `API_KEY_TENANT_INDEX`, so the read may be slightly stale.

        Staleness is acceptable here and not on `get`: this is the settings page, where a key
        minted a second ago appearing a second late is invisible, whereas a key that cannot
        authenticate immediately after minting is a bug its owner reports.
        """
        from boto3.dynamodb.conditions import Key as KeyCondition

        return [
            _record_from_item(item)
            for item in self._repo.iter_query(KeyCondition("tenant_id").eq(tenant_id), index_name=API_KEY_TENANT_INDEX)
        ]

    def count_for_tenant(self, tenant_id: str) -> int:
        """How many keys one tenant holds, as a counted query on `API_KEY_TENANT_INDEX`.

        `Select="COUNT"` rather than the base class's listing, because this runs on the create
        path of every key: DynamoDB counts the index entries server side and returns no items
        at all, so the call costs the read capacity of the keys it counted and nothing is
        deserialised. Never a scan.

        Paginated, because `Count` is per page and a tenant whose index entries spill past 1 MB
        would otherwise report only the first page's worth and let a cap be walked past.
        """
        from boto3.dynamodb.conditions import Key as KeyCondition

        if not tenant_id:
            return 0
        total = 0
        start_key: dict[str, Any] | None = None
        while True:
            kwargs: dict[str, Any] = {
                "KeyConditionExpression": KeyCondition("tenant_id").eq(tenant_id),
                "IndexName": API_KEY_TENANT_INDEX,
                "Select": "COUNT",
            }
            if start_key is not None:
                kwargs["ExclusiveStartKey"] = start_key
            response = self._repo.table.query(**kwargs)
            total += int(response.get("Count", 0))
            start_key = response.get("LastEvaluatedKey")
            if not start_key:
                return total


API_KEY_TABLE: Final = TableSpec(
    logical_name=API_KEYS_TABLE,
    attributes=(
        TableAttribute("key_hash", "S"),
        TableAttribute("user_id", "S"),
        TableAttribute("tenant_id", "S"),
        TableAttribute("created_at", "S"),
    ),
    hash_key="key_hash",
    global_secondary_indexes=(
        TableIndex(name=API_KEY_USER_INDEX, hash_key="user_id", range_key="created_at"),
        TableIndex(name=API_KEY_TENANT_INDEX, hash_key="tenant_id", range_key="created_at"),
    ),
)
"""The `api-keys` table spec, in the shape the platform identity module provisions it.

Billing is `PAY_PER_REQUEST` through `BILLING_MODE`, like every other identity table. No TTL:
the `ApiKeyStore` docstring says why an expired key stays visible rather than vanishing.
"""


def mint(
    *,
    user_id: str,
    tenant_id: str,
    scopes: Iterable[str],
    name: str = "",
    expires_at: datetime | int | None = None,
    store: ApiKeyStore | None = None,
    created_at: str | None = None,
    kind: str = KIND_USER,
    created_by: str | None = None,
    metadata: Mapping[str, Any] | None = None,
    key_id: str | None = None,
) -> MintedApiKey:
    """Mint a key, returning the plaintext once alongside the record that was stored.

    The plaintext is in the returned `MintedApiKey` and nowhere else: only its SHA-256 reaches
    the store, so nothing after this call can reproduce it.

    Args:
        user_id: The minting user. Becomes the key's `sub`, so a key acts as that person.
        tenant_id: The tenant the key acts inside. A key never spans tenants.
        scopes: The ceiling this key may ever exercise. Normalised, de-duplicated and sorted.
            Passing more than the minter holds does not grant more: `effective_scopes`
            intersects against live membership on every request.
        name: A label the owner recognises the key by in a list.
        expires_at: When the key stops working, as a datetime or a Unix timestamp. `None`
            mints a key that never expires, which is the right default only for a key whose
            owner is a service rather than a person.
        store: Where to write the record. `None` mints without storing, for a caller that
            writes through its own transaction.
        created_at: The creation stamp, defaulting to now. A seam for tests.
        kind: The product's own label for what sort of key this is, defaulting to `KIND_USER`.
            Never interpreted here.
        created_by: Who minted it, when that is someone other than `user_id`. A key that acts
            as a service has no person as its subject, and this is where the person who created
            it is recorded. `None` leaves it unrecorded rather than recording nobody.
        metadata: Product fields the store round-trips untouched.
        key_id: The revoke handle, defaulting to a fresh one. Pass one only to adopt an id a
            caller already allocated, such as one written in the same transaction.

    Returns:
        The plaintext and the stored record, together, once.
    """
    plaintext = new_key()
    expiry = int(expires_at.timestamp()) if isinstance(expires_at, datetime) else int(expires_at or 0)
    record = ApiKeyRecord(
        key_hash=hash_key(plaintext),
        user_id=user_id,
        tenant_id=tenant_id,
        prefix=display_prefix(plaintext),
        scopes=_normalise_scopes(scopes),
        name=name,
        created_at=created_at or now_iso(),
        expires_at=expiry,
        key_id=key_id if key_id is not None else new_key_id(),
        kind=kind,
        created_by=created_by,
        metadata=dict(metadata or {}),
    )
    if store is not None:
        store.put(record)
    return MintedApiKey(plaintext=plaintext, record=record)


def verify(
    plaintext: str,
    store: ApiKeyStore,
    *,
    now: datetime | None = None,
    touch: bool = True,
) -> ApiKeyRecord | None:
    """Resolve a presented plaintext to its usable record, or `None`.

    `None` for every refusal: wrong shape, unknown hash, revoked, expired. The caller cannot
    tell which, and must not, because distinguishing "no such key" from "revoked key" tells an
    attacker whether a guessed value ever existed.

    The stored hash is compared with `constant_time_equals` even though the lookup already
    matched on it, so the comparison never becomes a timing oracle if the store is later
    reimplemented over something that matches loosely.
    """
    if not is_api_key(plaintext):
        return None
    key_hash = hash_key(plaintext)
    record = store.get(key_hash)
    if record is None or not constant_time_equals(record.key_hash, key_hash):
        return None
    if not record.is_usable(now=now):
        return None
    if touch:
        store.touch(key_hash)
    return record


def verify_for_tenant(
    plaintext: str,
    store: ApiKeyStore,
    tenant_id: str,
    *,
    now: datetime | None = None,
    touch: bool = True,
) -> ApiKeyRecord | None:
    """Resolve a presented plaintext against one tenant, or `None`.

    `verify` plus the binding check a multi-tenant product must make: a key names exactly one
    tenant and may never act in another, so a key minted in tenant A reaching tenant B
    whenever its minter belongs to both is the cross-tenant reach a scoped credential exists
    to prevent.

    `None` for every refusal, tenant mismatch included, so a key cannot be walked across
    tenant ids to learn which ones exist. A caller that wants to log the difference compares
    `record.tenant_id` itself after a plain `verify`.

    An empty `tenant_id` refuses rather than matching everything, because a caller that could
    not resolve which tenant it is in must not be the one deciding the key may act. The key
    is touched only on a match, so a refused presentation leaves `last_used_at` alone.
    """
    if not tenant_id:
        return None
    record = verify(plaintext, store, now=now, touch=False)
    if record is None or not constant_time_equals(record.tenant_id, tenant_id):
        return None
    if touch:
        store.touch(record.key_hash)
    return record


def revoke(plaintext_or_hash: str, store: ApiKeyStore, *, revoked_at: str | None = None) -> ApiKeyRecord | None:
    """Revoke a key by either its plaintext or its stored hash.

    Takes both because the two callers differ: a person revoking from a settings page has only
    the hash the list rendered, and a service rotating its own key has only the plaintext.
    Returns the record as it was, or `None` when there was nothing live to revoke.
    """
    key_hash = hash_key(plaintext_or_hash) if is_api_key(plaintext_or_hash) else plaintext_or_hash
    return store.revoke(key_hash, revoked_at=revoked_at)


def revoke_by_id(
    tenant_id: str,
    key_id: str,
    store: ApiKeyStore,
    *,
    revoked_at: str | None = None,
) -> ApiKeyRecord | None:
    """Revoke a key by the tenant it belongs to and its id, holding no secret at all.

    The counterpart to `revoke` for the human path. `revoke` takes a plaintext or a hash,
    which is what a service rotating its own key and a page rendering the hash have; this takes
    the id a listing shows, so a settings page never has to put a value derived from the
    credential in a URL.

    Answers `None` for an unknown id, for a key in another tenant and for one already revoked
    alike, so a key id cannot be walked across tenants to learn which ones exist.
    """
    return store.revoke_by_id(tenant_id, key_id, revoked_at=revoked_at)


def effective_scopes(key_scopes: Iterable[str], live_scopes: Iterable[str]) -> tuple[str, ...]:
    """The scopes a key may actually exercise: its own set intersected with live membership.

    A key is a delegation of what its minter held at mint time, and membership changes after
    that. Without this intersection a key outlives the role it was minted under, which is how
    a removed admin keeps admin access through a key nobody remembers.

    Call it on every request, against freshly loaded membership, and authorize against the
    result rather than against the record's `scopes`.
    """
    live = {scope.strip() for scope in live_scopes if scope.strip()}
    return tuple(sorted({scope.strip() for scope in key_scopes if scope.strip()} & live))


def claims_for_key(record: ApiKeyRecord, *, scopes: Iterable[str] | None = None) -> AuthorizerClaims:
    """Build the same `AuthorizerClaims` shape the gateway produces, for a verified key.

    Returning the gateway's own shape is the point: a route guarded by `require_scopes` cannot
    tell a key from a signed-in person, so there is no second authorization path to keep in
    step with the first.

    `scope` is a space-separated string, the form RFC 6749 gives it and the form the gateway
    flattens it to, so `coerce_claims` splits it into `scopes` exactly as it does for a JWT.

    Args:
        record: The verified key.
        scopes: The scopes to put on the claims, normally the `effective_scopes` result.
            `None` uses the record's own set, which is only correct where the caller has
            already intersected it or where there is no live membership to intersect with.

    Returns:
        Claims carrying `sub`, the tenant, the scope string and `ACTOR_CLAIM`.
    """
    granted = _normalise_scopes(scopes if scopes is not None else record.scopes)
    return AuthorizerClaims(
        {
            "sub": record.user_id,
            TENANT_CLAIM: record.tenant_id,
            "scope": " ".join(granted),
            ACTOR_CLAIM: ACTOR_API_KEY,
        }
    )
