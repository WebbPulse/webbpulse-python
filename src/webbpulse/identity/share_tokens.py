"""Share tokens: a bearer credential whose whole authority is one stored capability.

The third credential kind, beside a session JWT and an API key. A share token opens a public
read-only link: holding it is the entire authorization, there is no account behind it, and it
grants exactly what its stored row says and nothing that widens.

Minted once, shown once, stored only as a SHA-256 hash with no clear-text prefix, exactly as
an API key is. A leaked table therefore authenticates as nobody, and a listing rendered on a
settings page cannot be replayed as a credential.

The payload is opaque to this package. A product decides what a token grants and reads it
back out of `capability`; nothing here interprets it, so this module is not an issue tracker's
share link, an album's share link or a report's share link, but all three.
"""

from __future__ import annotations

import dataclasses
import hashlib
import logging
import secrets
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

from webbpulse.dynamodb import now_iso
from webbpulse.identity.claims import AuthorizerClaims
from webbpulse.identity.storage import (
    IDENTITY_TTL_ATTRIBUTE,
    TableAttribute,
    TableIndex,
    TableSpec,
    constant_time_equals,
)

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import Request

    from webbpulse.dynamodb import Repository

__all__ = [
    "ACTOR_SHARE_TOKEN",
    "CAPABILITY_CLAIM",
    "SHARE_TOKENS_TABLE",
    "SHARE_TOKEN_BYTES",
    "SHARE_TOKEN_PREFIX",
    "SHARE_TOKEN_SUBJECT",
    "SHARE_TOKEN_TABLE",
    "SHARE_TOKEN_TARGET_INDEX",
    "SHARE_TOKEN_TENANT_INDEX",
    "DynamoShareTokenStore",
    "FakeShareTokenStore",
    "InMemoryShareTokenStore",
    "MintedShareToken",
    "ShareTarget",
    "ShareTokenRecord",
    "ShareTokenStore",
    "claims_for_share_token",
    "claims_or_credential",
    "hash_share_token",
    "is_share_token",
    "is_share_token_actor",
    "mint_share_token",
    "new_share_token",
    "revoke_share_token",
    "share_target_key",
    "share_token_capability",
    "share_token_credential",
    "verify_share_token",
]

_log = logging.getLogger(__name__)

SHARE_TOKENS_TABLE: Final = "share-tokens"
"""The logical table name, prefixed by the environment like every other identity table."""

SHARE_TOKEN_TENANT_INDEX: Final = "tenant_id-created_at-index"
"""The GSI listing one tenant's share tokens, newest last, for a settings page and for purge.

Partitioning by the token hash is what makes resolving a presented token one point read, and
it is also what leaves "every share in this tenant" unanswerable without this index.
"""

SHARE_TOKEN_TARGET_INDEX: Final = "tenant_id-target_key-index"
"""The GSI listing every share token pointing at one target inside one tenant.

Hash `tenant_id` and range `target_key`, which is what makes "every link onto this issue" and
"revoke everything pointing at this view" one query each rather than a tenant-wide read
filtered afterwards. The range key carries the type and the id together, so a caller holding
several visible targets fans out over exact keys and never fetches a row it may not see.

The name is a contract with `platform-modules/aws//modules/identity`, which provisions the
same index under the same name.
"""

SHARE_TOKEN_PREFIX: Final = "wps_"
"""The literal every plaintext share token starts with.

Distinct from the API key's `wpk_` because the two are never interchangeable: one opens an
anonymous read of a named resource and the other acts as a person inside a tenant, and a
prefix test is what routes a presented bearer value to the right verifier without parsing it.
"""

SHARE_TOKEN_BYTES: Final = 32
"""256 bits of CSPRNG entropy, matching an API key and `storage.new_token`.

The token is the only credential on a public route, with no account, no lockout and no second
factor standing behind it, so guessing has to be infeasible rather than merely impractical.
"""

SHARE_TOKEN_SUBJECT: Final = "share"
"""The `sub` a share token's claims carry, naming no person because there is none.

A fixed non-empty subject rather than an empty one, so a guard that refuses claims without a
subject does not accidentally accept an anonymous share as a signed-in caller.
"""

ACTOR_SHARE_TOKEN: Final = "share_token"
"""The `actor_kind` value marking a request authenticated by a share token."""

CAPABILITY_CLAIM: Final = "capability"
"""The claim carrying the stored payload, which only the product reads."""


def new_share_token() -> str:
    """A fresh plaintext share token: `SHARE_TOKEN_PREFIX` followed by 256 base64url bits."""
    return f"{SHARE_TOKEN_PREFIX}{secrets.token_urlsafe(SHARE_TOKEN_BYTES)}"


def hash_share_token(plaintext: str) -> str:
    """The stored form of a token: hex SHA-256 of its UTF-8 bytes, prefix included.

    SHA-256 and not a password hash, for the reason every token in this package uses it: the
    input is 256 bits from a CSPRNG, so there is no dictionary to slow down and a work factor
    would only cost the read path.
    """
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def is_share_token(candidate: str) -> bool:
    """Whether a presented value is shaped like one of this package's share tokens.

    A prefix test only. It decides which verifier a value is handed to, never whether the
    value is genuine.
    """
    return candidate.startswith(SHARE_TOKEN_PREFIX)


def _now() -> datetime:
    """The current UTC time, as one seam every expiry check in this module shares."""
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class ShareTarget:
    """The one resource a share token opens, as a type and an id.

    A first-class field rather than a convention inside `capability`, because it is the only
    part of the payload this package has to understand: it is what `SHARE_TOKEN_TARGET_INDEX`
    is keyed on, so "every link onto this issue" is a query rather than a filter. Everything
    else about what the token grants stays opaque in `capability`.

    The type is the product's own vocabulary, such as `issue`, `view` or `album`. Nothing here
    validates it, for the same reason nothing here interprets `capability`.
    """

    type: str
    id: str

    @property
    def key(self) -> str:
        """The stored `target_key`: the type and the id joined by a `#`.

        The tenant is not in it. The index hash key carries the tenant already, so repeating it
        here would only make the range key longer without bounding anything further.
        """
        return share_target_key(self.type, self.id)

    def __bool__(self) -> bool:
        """Whether this names a target at all, so an unset one is falsey."""
        return bool(self.type and self.id)


def share_target_key(target_type: str, target_id: str) -> str:
    """The `target_key` attribute for one target: `"<type>#<id>"`.

    A module-level function as well as a property, so a caller holding two loose strings can
    build the key without constructing a value type first.
    """
    return f"{target_type}#{target_id}"


def _coerce_target(target: ShareTarget | tuple[str, str] | None) -> ShareTarget:
    """One target from whichever spelling a caller had, or an empty one.

    A pair is accepted beside the value type because a product listing several targets usually
    has tuples in hand, and requiring a construction per element would be noise.
    """
    if target is None:
        return ShareTarget(type="", id="")
    if isinstance(target, ShareTarget):
        return target
    target_type, target_id = target
    return ShareTarget(type=str(target_type), id=str(target_id))


@dataclass(frozen=True, slots=True)
class ShareTokenRecord:
    """One stored share token. Holds the hash and never the plaintext.

    `capability` is whatever the product put there and is never interpreted here. Keep it
    small and closed: it is the whole of what the token grants, so a field this package would
    have to widen later, such as a filter applied after the fact, belongs in the row rather
    than in the request.

    `target_type` and `target_id` are the exception: the one part of the payload this package
    understands, because `SHARE_TOKEN_TARGET_INDEX` is keyed on them and revoking every link
    onto a deleted resource has to be a query. They are stored flat, and `target` reads them
    back as a `ShareTarget`. Both default empty, so a record minted before they existed is
    still a valid record and simply has no target to list by.
    """

    token_hash: str
    tenant_id: str
    capability: Mapping[str, Any] = field(default_factory=dict)
    target_type: str = ""
    target_id: str = ""
    name: str = ""
    created_by: str = ""
    created_at: str = ""
    expires_at: int = 0
    last_used_at: str = ""
    revoked_at: str = ""

    @property
    def target(self) -> ShareTarget:
        """The resource this token opens, as a value type. Empty when the row names none."""
        return ShareTarget(type=self.target_type, id=self.target_id)

    @property
    def target_key(self) -> str:
        """The stored `target_key`, or `""` when this row names no target.

        Empty rather than `"#"` for an unset target, because the attribute is what makes a row
        appear in the index and a row with no target must stay out of it entirely.
        """
        return self.target.key if self.target else ""

    @property
    def is_revoked(self) -> bool:
        """Whether this token has been revoked."""
        return bool(self.revoked_at)

    def is_expired(self, *, now: datetime | None = None) -> bool:
        """Whether this token's expiry has passed. A zero `expires_at` never expires.

        Checked here rather than trusted to the table's TTL sweep, because DynamoDB deletes an
        expired item on its own schedule and a share must stop resolving at its expiry rather
        than at its deletion.
        """
        if not self.expires_at:
            return False
        return (now or _now()).timestamp() >= self.expires_at

    def is_usable(self, *, now: datetime | None = None) -> bool:
        """Whether this token may authorize a read right now."""
        return not self.is_revoked and not self.is_expired(now=now)


@dataclass(frozen=True, slots=True)
class MintedShareToken:
    """The one moment a plaintext share token exists outside the caller's own storage.

    `plaintext` is returned exactly once by `mint_share_token` and is never recoverable, so
    the route that mints a share must put it in that one response and nowhere else. It is
    normally embedded in a URL, which means it will reach browser history and referrer
    headers: that is what the expiry and the revocation verb are for.
    """

    plaintext: str
    record: ShareTokenRecord


class ShareTokenStore(ABC):
    """The `share-tokens` table: hash `token_hash`, `tenant_id-created_at-index`, TTL on `expires_at`.

    A TTL, unlike the API key table. A share is a link a person hands out and forgets, so the
    table would otherwise grow without bound, and there is no owner for whom an expired share
    staying visible is worth anything. Expiry is still enforced on the read path, because the
    sweep is not prompt.
    """

    @abstractmethod
    def get(self, token_hash: str) -> ShareTokenRecord | None:
        """The record, revoked and expired ones included. The caller checks `is_usable`."""

    @abstractmethod
    def put(self, record: ShareTokenRecord) -> None:
        """Write a new share token."""

    @abstractmethod
    def list_for_tenant(self, tenant_id: str) -> list[ShareTokenRecord]:
        """Every share token issued inside one tenant. Never carries a plaintext."""

    @abstractmethod
    def revoke(self, token_hash: str, *, revoked_at: str | None = None) -> ShareTokenRecord | None:
        """Mark a token revoked, returning it as it was, or `None` when it was already gone."""

    @abstractmethod
    def touch(self, token_hash: str, *, used_at: str | None = None) -> None:
        """Record that a token was just used, best effort. A failure must never refuse a read."""

    @abstractmethod
    def delete_all_for_tenant(self, tenant_id: str) -> int:
        """Delete every share token of one tenant, returning how many went. The purge."""

    def list_for_target(self, tenant_id: str, target: ShareTarget | tuple[str, str]) -> list[ShareTokenRecord]:
        """Every share token of one tenant pointing at one target, oldest first.

        The listing a product needs to show "this issue is shared" beside the issue, and to
        revoke every link onto a resource it is about to delete. A tenant-wide read filtered
        afterwards would answer the same question, but it would also fetch rows for targets the
        caller may not see, which is exactly what a per-target query avoids.

        Concrete rather than abstract so a store written before this method existed keeps
        satisfying the protocol. The default answers empty rather than scanning, for the reason
        `ApiKeyStore.list_for_tenant` gives: a silent scan is worse than an empty list.

        Args:
            tenant_id: The tenant to look inside. An empty one answers empty rather than
                spanning tenants.
            target: The resource, as a `ShareTarget` or a `(type, id)` pair.

        Returns:
            The matching records, oldest first, revoked and expired ones included.
        """
        del tenant_id, target
        return []

    def revoke_all_for_target(
        self,
        tenant_id: str,
        target: ShareTarget | tuple[str, str],
        *,
        revoked_at: str | None = None,
    ) -> int:
        """Revoke every live share token onto one target, returning how many were revoked.

        The verb for a resource being deleted or made private: its links must stop resolving at
        once, and a link nobody remembered is exactly the one that would otherwise outlive it.

        Built on `list_for_target`, so a store that cannot list a target revokes nothing and
        says so by returning zero rather than appearing to have succeeded.
        """
        revoked = 0
        for record in self.list_for_target(tenant_id, target):
            if not record.is_revoked and self.revoke(record.token_hash, revoked_at=revoked_at) is not None:
                revoked += 1
        return revoked

    def revoke_all_for_tenant(self, tenant_id: str, *, revoked_at: str | None = None) -> int:
        """Revoke every live share token of one tenant, returning how many were revoked.

        Revoking rather than deleting, so a tenant that suspends its shares can see afterwards
        what was revoked and when. `delete_all_for_tenant` is the harder verb, for a tenant
        that is going away.
        """
        revoked = 0
        for record in self.list_for_tenant(tenant_id):
            if not record.is_revoked and self.revoke(record.token_hash, revoked_at=revoked_at) is not None:
                revoked += 1
        return revoked


class InMemoryShareTokenStore(ShareTokenStore):
    """Dict-backed `ShareTokenStore`, keyed as the table is."""

    def __init__(self) -> None:
        """Start with an empty backing dict."""
        self._items: dict[str, ShareTokenRecord] = {}

    def get(self, token_hash: str) -> ShareTokenRecord | None:
        """The record, revoked and expired ones included. The caller checks `is_usable`."""
        return self._items.get(token_hash)

    def put(self, record: ShareTokenRecord) -> None:
        """Write a new share token."""
        self._items[record.token_hash] = record

    def list_for_tenant(self, tenant_id: str) -> list[ShareTokenRecord]:
        """Every token of one tenant, oldest first, matching the index's sort order."""
        return sorted(
            (record for record in self._items.values() if record.tenant_id == tenant_id),
            key=lambda record: record.created_at,
        )

    def revoke(self, token_hash: str, *, revoked_at: str | None = None) -> ShareTokenRecord | None:
        """Mark a token revoked, returning it as it was, or `None` when it was already gone."""
        existing = self._items.get(token_hash)
        if existing is None or existing.is_revoked:
            return None
        self._items[token_hash] = dataclasses.replace(existing, revoked_at=revoked_at or now_iso())
        return existing

    def touch(self, token_hash: str, *, used_at: str | None = None) -> None:
        """Record that a token was just used, tolerating an absent row."""
        existing = self._items.get(token_hash)
        if existing is None:
            return
        self._items[token_hash] = dataclasses.replace(existing, last_used_at=used_at or now_iso())

    def delete_all_for_tenant(self, tenant_id: str) -> int:
        """Delete every share token of one tenant, returning how many went."""
        hashes = [token_hash for token_hash, record in self._items.items() if record.tenant_id == tenant_id]
        for token_hash in hashes:
            del self._items[token_hash]
        return len(hashes)

    def list_for_target(self, tenant_id: str, target: ShareTarget | tuple[str, str]) -> list[ShareTokenRecord]:
        """Every token of one tenant onto one target, oldest first, matching the index order."""
        wanted = _coerce_target(target)
        if not tenant_id or not wanted:
            return []
        return sorted(
            (
                record
                for record in self._items.values()
                if record.tenant_id == tenant_id and record.target_key == wanted.key
            ),
            key=lambda record: record.created_at,
        )


FakeShareTokenStore = InMemoryShareTokenStore
"""The name a test reaches for, aliasing `InMemoryShareTokenStore`."""


def _record_to_item(record: ShareTokenRecord) -> dict[str, Any]:
    """The DynamoDB item for a record. `capability` goes down as a map, not a JSON string.

    A map rather than a string because DynamoDB stores one natively and a product that wants
    a projection or a filter on one of its fields can then have it, which a blob forecloses.

    `target_key` is written only when the row names a target. A sparse attribute keeps a
    targetless row out of `SHARE_TOKEN_TARGET_INDEX` entirely, rather than collecting every
    such row under one degenerate key.
    """
    item: dict[str, Any] = {
        "token_hash": record.token_hash,
        "tenant_id": record.tenant_id,
        "capability": dict(record.capability),
        "target_type": record.target_type,
        "target_id": record.target_id,
        "name": record.name,
        "created_by": record.created_by,
        "created_at": record.created_at,
        "expires_at": record.expires_at,
        "last_used_at": record.last_used_at,
        "revoked_at": record.revoked_at,
    }
    if record.target_key:
        item["target_key"] = record.target_key
    return item


def _record_from_item(item: Mapping[str, Any]) -> ShareTokenRecord:
    """Rebuild a record from a DynamoDB item, tolerating an absent optional attribute.

    `target_key` is not read back: it is derived from `target_type` and `target_id`, so the
    stored copy exists only to key the index and a row written before it existed simply has
    no target.
    """
    raw_capability = item.get("capability")
    capability = dict(raw_capability) if isinstance(raw_capability, Mapping) else {}
    return ShareTokenRecord(
        token_hash=str(item["token_hash"]),
        tenant_id=str(item.get("tenant_id", "")),
        capability=capability,
        target_type=str(item.get("target_type", "")),
        target_id=str(item.get("target_id", "")),
        name=str(item.get("name", "")),
        created_by=str(item.get("created_by", "")),
        created_at=str(item.get("created_at", "")),
        expires_at=int(item.get("expires_at", 0) or 0),
        last_used_at=str(item.get("last_used_at", "")),
        revoked_at=str(item.get("revoked_at", "")),
    )


class DynamoShareTokenStore(ShareTokenStore):
    """`ShareTokenStore` over a `webbpulse.dynamodb.Repository`, with the tenant GSI."""

    def __init__(self, repository: Repository) -> None:
        """Bind this store to the repository holding its table."""
        self._repo = repository

    def get(self, token_hash: str) -> ShareTokenRecord | None:
        """The record, read consistently: a share minted a moment ago must open now."""
        item = self._repo.get({"token_hash": token_hash}, consistent=True)
        return _record_from_item(item) if item is not None else None

    def put(self, record: ShareTokenRecord) -> None:
        """Write a new share token."""
        self._repo.put(_record_to_item(record))

    def list_for_tenant(self, tenant_id: str) -> list[ShareTokenRecord]:
        """Every token of one tenant, from the GSI, so the read may be slightly stale."""
        from boto3.dynamodb.conditions import Key as KeyCondition

        return [
            _record_from_item(item)
            for item in self._repo.iter_query(
                KeyCondition("tenant_id").eq(tenant_id), index_name=SHARE_TOKEN_TENANT_INDEX
            )
        ]

    def revoke(self, token_hash: str, *, revoked_at: str | None = None) -> ShareTokenRecord | None:
        """Atomically mark a token revoked, returning it as it was, or `None` if already revoked."""
        from boto3.dynamodb.conditions import Attr

        from webbpulse.dynamodb import ConditionFailed

        try:
            old = self._repo.update(
                {"token_hash": token_hash},
                update_expression="SET revoked_at = :now",
                expression_values={":now": revoked_at or now_iso()},
                condition=(Attr("token_hash").exists() & (Attr("revoked_at").not_exists() | Attr("revoked_at").eq(""))),
                return_values="ALL_OLD",
            )
        except ConditionFailed:
            return None
        return _record_from_item(old) if old else None

    def touch(self, token_hash: str, *, used_at: str | None = None) -> None:
        """Stamp `last_used_at`, swallowing every failure.

        Best effort by design: this runs on the read path of a public page, and a write that
        fails must not turn a good share link into a refused request.
        """
        from boto3.dynamodb.conditions import Attr
        from botocore.exceptions import ClientError

        try:
            self._repo.update(
                {"token_hash": token_hash},
                update_expression="SET last_used_at = :now",
                expression_values={":now": used_at or now_iso()},
                condition=Attr("token_hash").exists(),
            )
        except ClientError as exc:
            _log.debug("Could not stamp last_used_at on a share token: %s", exc)

    def delete_all_for_tenant(self, tenant_id: str) -> int:
        """Delete every share token of one tenant, enumerating through the GSI."""
        from boto3.dynamodb.conditions import Key as KeyCondition

        keys = [
            {"token_hash": str(item["token_hash"])}
            for item in self._repo.iter_query(
                KeyCondition("tenant_id").eq(tenant_id),
                index_name=SHARE_TOKEN_TENANT_INDEX,
                projection="token_hash",
            )
        ]
        if not keys:
            return 0
        return self._repo.delete_many(keys)

    def list_for_target(self, tenant_id: str, target: ShareTarget | tuple[str, str]) -> list[ShareTokenRecord]:
        """Every token onto one target, oldest first, from `SHARE_TOKEN_TARGET_INDEX`.

        One query on the exact index key, never a tenant read with a filter: the range key is
        the whole target, so DynamoDB returns the rows for that one resource and nothing else
        is read or paid for. The read may be slightly stale, as any GSI read is.

        Sorted here rather than by the index. The range key is the target, which is what makes
        the query exact, and that leaves the order within one target the table's own rather
        than creation order. One target's links are few by construction, so sorting them in
        memory costs nothing and the ordering stays the same as every other listing's.
        """
        from boto3.dynamodb.conditions import Key as KeyCondition

        wanted = _coerce_target(target)
        if not tenant_id or not wanted:
            return []
        condition = KeyCondition("tenant_id").eq(tenant_id) & KeyCondition("target_key").eq(wanted.key)
        records = [
            _record_from_item(item) for item in self._repo.iter_query(condition, index_name=SHARE_TOKEN_TARGET_INDEX)
        ]
        return sorted(records, key=lambda record: record.created_at)


SHARE_TOKEN_TABLE: Final = TableSpec(
    logical_name=SHARE_TOKENS_TABLE,
    attributes=(
        TableAttribute("token_hash", "S"),
        TableAttribute("tenant_id", "S"),
        TableAttribute("created_at", "S"),
        TableAttribute("target_key", "S"),
    ),
    hash_key="token_hash",
    global_secondary_indexes=(
        TableIndex(name=SHARE_TOKEN_TENANT_INDEX, hash_key="tenant_id", range_key="created_at"),
        TableIndex(name=SHARE_TOKEN_TARGET_INDEX, hash_key="tenant_id", range_key="target_key"),
    ),
    ttl_attribute=IDENTITY_TTL_ATTRIBUTE,
)
"""The `share-tokens` table spec, in the shape the platform identity module provisions it.

Billing is `PAY_PER_REQUEST` through `BILLING_MODE`, like every other identity table. It does
carry a TTL, unlike `api-keys`: the `ShareTokenStore` docstring says why.
"""


def mint_share_token(
    *,
    tenant_id: str,
    capability: Mapping[str, Any] | None = None,
    target: ShareTarget | tuple[str, str] | None = None,
    name: str = "",
    created_by: str = "",
    expires_at: datetime | int | None = None,
    expires_in: timedelta | None = None,
    store: ShareTokenStore | None = None,
    created_at: str | None = None,
) -> MintedShareToken:
    """Mint a share token, returning the plaintext once alongside the record that was stored.

    The plaintext is in the returned `MintedShareToken` and nowhere else: only its SHA-256
    reaches the store.

    Args:
        tenant_id: The tenant the share belongs to, which is what makes it listable and
            revocable by its owner. It bounds the share's administration, not its audience:
            the token's reader is anonymous.
        capability: The payload naming exactly what this token opens. Opaque to this package
            and read back by the product out of `record.capability`. Keep it closed: whatever
            it does not name, the token does not grant.
        target: The one resource this token points at, as a `ShareTarget` or a `(type, id)`
            pair. The only part of the grant this package understands, because it is what
            `list_for_target` and `revoke_all_for_target` query on. `None` mints a token with
            no target, which resolves exactly as before and simply cannot be listed by one.
        name: A label the owner recognises the share by in a list.
        created_by: The user who minted it, for the listing and for an audit line.
        expires_at: When the share stops resolving, as a datetime or a Unix timestamp.
        expires_in: The same thing as a duration from now, which is the form a route usually
            has. Ignored when `expires_at` is given.
        store: Where to write the record. `None` mints without storing, for a caller writing
            through its own transaction.
        created_at: The creation stamp, defaulting to now. A seam for tests.

    Returns:
        The plaintext and the stored record, together, once.
    """
    plaintext = new_share_token()
    if expires_at is not None:
        expiry = int(expires_at.timestamp()) if isinstance(expires_at, datetime) else int(expires_at)
    elif expires_in is not None:
        expiry = int((_now() + expires_in).timestamp())
    else:
        expiry = 0
    wanted = _coerce_target(target)
    record = ShareTokenRecord(
        token_hash=hash_share_token(plaintext),
        tenant_id=tenant_id,
        capability=dict(capability or {}),
        target_type=wanted.type,
        target_id=wanted.id,
        name=name,
        created_by=created_by,
        created_at=created_at or now_iso(),
        expires_at=expiry,
    )
    if store is not None:
        store.put(record)
    return MintedShareToken(plaintext=plaintext, record=record)


def verify_share_token(
    plaintext: str,
    store: ShareTokenStore,
    *,
    now: datetime | None = None,
    touch: bool = True,
) -> ShareTokenRecord | None:
    """Resolve a presented plaintext to its usable record, or `None`.

    `None` for every refusal: wrong shape, unknown hash, revoked, expired. The caller cannot
    tell which, and must not, because the reader here is anonymous and distinguishing
    "no such share" from "revoked share" says whether a guessed value ever existed.

    The stored hash is compared with `constant_time_equals` even though the lookup already
    matched on it, so the comparison never becomes a timing oracle if the store is later
    reimplemented over something that matches loosely.
    """
    if not is_share_token(plaintext):
        return None
    token_hash = hash_share_token(plaintext)
    record = store.get(token_hash)
    if record is None or not constant_time_equals(record.token_hash, token_hash):
        return None
    if not record.is_usable(now=now):
        return None
    if touch:
        store.touch(token_hash)
    return record


def revoke_share_token(
    plaintext_or_hash: str,
    store: ShareTokenStore,
    *,
    revoked_at: str | None = None,
) -> ShareTokenRecord | None:
    """Revoke a share token by either its plaintext or its stored hash.

    Takes both because the two callers differ: a person revoking from a settings page has only
    the hash the list rendered, and a holder disabling a link they were sent has only the
    plaintext. Returns the record as it was, or `None` when there was nothing live to revoke.
    """
    token_hash = hash_share_token(plaintext_or_hash) if is_share_token(plaintext_or_hash) else plaintext_or_hash
    return store.revoke(token_hash, revoked_at=revoked_at)


def claims_for_share_token(record: ShareTokenRecord) -> AuthorizerClaims:
    """Build the gateway's own `AuthorizerClaims` shape for a verified share token.

    The same shape a JWT and an API key produce, so a route reached by all three has one
    claims object to read and no second authorization path to keep in step.

    The claims carry no `scope`. A share token's authority is its capability payload and not a
    scope set, so `require_scopes` refuses it outright, which is the right default: a route
    that means to admit a share says so by reading `share_token_capability` rather than by a
    scope the token happens to hold.

    Returns:
        Claims carrying the fixed subject, the tenant, the capability and `actor_kind`.
    """
    from webbpulse.identity.api_keys import ACTOR_CLAIM, TENANT_CLAIM

    return AuthorizerClaims(
        {
            "sub": SHARE_TOKEN_SUBJECT,
            TENANT_CLAIM: record.tenant_id,
            CAPABILITY_CLAIM: dict(record.capability),
            ACTOR_CLAIM: ACTOR_SHARE_TOKEN,
        }
    )


def share_token_capability(claims: Mapping[str, Any]) -> Mapping[str, Any]:
    """The capability payload on a share token's claims, or an empty mapping.

    Empty for a JWT and for an API key, so a route can read it unconditionally and get nothing
    where there is nothing, rather than branching on the actor first.
    """
    payload = claims.get(CAPABILITY_CLAIM)
    return dict(payload) if isinstance(payload, Mapping) else {}


def is_share_token_actor(claims: Mapping[str, Any]) -> bool:
    """Whether these claims came from a share token rather than a person or a key.

    For the route that must refuse an anonymous share outright, such as anything that writes:
    a share token is read-only by construction, and that is enforced by the routes it may
    reach rather than by the token.
    """
    from webbpulse.identity.api_keys import ACTOR_CLAIM

    return str(claims.get(ACTOR_CLAIM, "")) == ACTOR_SHARE_TOKEN


def share_token_credential(request: Request, *, path_param: str = "token") -> str:
    """The share token on this request, from the bearer header or the path, or `""`.

    Both, because a share link is a URL a person opens in a browser, which cannot set a
    header. The header is tried first so a machine caller presenting one is not overridden by
    a path segment that happens to be named the same.
    """
    from webbpulse.identity.scopes import bearer_credential

    presented = bearer_credential(request)
    if presented and is_share_token(presented):
        return presented
    from_path = str(request.path_params.get(path_param, "") or "").strip()
    return from_path if is_share_token(from_path) else ""


def _share_claims(request: Request, store: ShareTokenStore, path_param: str) -> AuthorizerClaims | None:
    """Claims for a presented share token, or `None` when there is no usable one.

    Swallows a verification failure into `None` rather than letting it escape, so a store
    outage on the share path leaves the stronger credential's own 401 as the answer instead
    of turning a refused request into a 500.
    """
    presented = share_token_credential(request, path_param=path_param)
    if not presented:
        return None
    try:
        record = verify_share_token(presented, store)
    except Exception as exc:
        _log.warning("Share token verification failed: %s", exc, exc_info=exc)
        return None
    if record is None:
        return None
    return claims_for_share_token(record)


def claims_or_credential(
    *,
    share_store: ShareTokenStore | None = None,
    share_path_param: str = "token",
    claims_dependency: Any | None = None,
    **kwargs: Any,
) -> Any:
    """Build the dependency resolving all three credential kinds into one claims object.

    A JWT the authorizer already verified, one of this package's API keys, or a share token,
    in that order. The order is what keeps the weakest credential from ever widening a
    request: a share token is consulted only where neither of the stronger two arrived, so
    adding this dependency cannot weaken a route that had an authorizer.

    Fails closed everywhere. Every path that cannot produce verified claims raises the same
    401 as `claims_or_api_key`, so a missing credential, an unknown key and a revoked share
    are indistinguishable to a caller.

    Args:
        share_store: Where share tokens are verified against. `None` disables the share path,
            leaving exactly `claims_or_api_key`.
        share_path_param: The path parameter a share token may arrive in, since a share link
            is a URL rather than a header.
        claims_dependency: The two-credential dependency to extend, defaulting to one built
            from `kwargs`. Pass one already built to reuse its store and `live_scopes`.
        kwargs: Forwarded to `claims_or_api_key` when `claims_dependency` is `None`, so
            `store`, `live_scopes` and `tenant` all work here as they do there.

    Returns:
        An `async def` dependency suitable for `Depends`.
    """
    from fastapi import HTTPException

    from webbpulse.identity.scopes import claims_or_api_key

    inner = claims_dependency if claims_dependency is not None else claims_or_api_key(**kwargs)

    async def dependency(request: Request) -> AuthorizerClaims:
        """Return the verified claims for this request from any of the three kinds, or raise a 401."""
        try:
            resolved = inner(request)
            if hasattr(resolved, "__await__"):
                resolved = await resolved
            claims: AuthorizerClaims = resolved
            return claims
        except HTTPException as refusal:
            if share_store is None:
                raise
            share = _share_claims(request, share_store, share_path_param)
            if share is None:
                raise refusal from None
            return share

    dependency.__name__ = "claims_or_credential"
    dependency.__doc__ = "The verified claims for this request, from a JWT, an API key or a share token."
    _bind_request()
    return dependency


def _bind_request() -> None:
    """Put `fastapi.Request` in this module's globals, as `scopes` does for its dependencies.

    FastAPI resolves a dependency's string annotations against its defining module's globals,
    so a name visible only under `TYPE_CHECKING` is not there when it builds the signature.
    """
    global Request
    if globals().get("Request") is None:
        from fastapi import Request as _Request

        globals()["Request"] = _Request


if not TYPE_CHECKING:
    Request = None
    """Bound by `_bind_request`, for the same reason `scopes` binds its own."""
