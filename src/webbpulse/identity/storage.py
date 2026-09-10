"""Storage interfaces for the identity flows, with DynamoDB and in-memory implementations.

M1 defines the interfaces and ships both implementations; M2 and later fill in the flows
that call them. Defining them now is what lets the flow milestones be written against a
seam that already exists rather than growing one per milestone.

## Per-entity tables, not single-table

Section 4.1 of `docs/identity-standard.md` settles this against the fashionable default, and
the reasoning is worth restating here because a reader arriving at this module will ask:

- The identity access patterns are point lookups on an exact key: this email, this
  credential id, this token hash. Every one is a `GetItem` or a one-key `Query` either way,
  so single-table's benefit, fetching heterogeneous related items in one query, never
  materialises.
- **TTL is a table-level setting.** Refresh tokens, challenges, states and verification
  tokens all want one; users and passkeys must never have one. Mixing an expiring entity
  and a permanent one in a single table means the permanent items carry a TTL attribute that
  must never be set, and one bug silently deletes accounts. Separate tables make that
  failure impossible rather than merely unlikely.
- Per-table IAM is what the domain split is built on. One identity table would have to be
  granted to both `identity` and `users`, weakening the boundary the split exists to draw.

## The key design, per table

Logical names; `webbpulse.dynamodb.table_name` prefixes each with the environment, so
`credentials` becomes `carmodpicker-production-credentials`.

| Table | Hash | Range | GSIs | TTL |
| --- | --- | --- | --- | --- |
| `users` | `id` | none | `email_lower-index`, `username_lower-index` | **never** |
| `credentials` | `user_id` | `credential_type` | none | **never** |
| `refresh_tokens` | `token_hash` | none | `family_id-generation-index` | `expires_at` |
| `identity_tokens` | `token_hash` | none | none | `expires_at` |

The three M1 stores are `credentials`, `refresh_tokens` and `identity_tokens`; `users` is
reached through the product's own repository behind `IdentityHooks.user_repository`, because
section 4.2 gives the `users` domain ownership of that record.

**`credentials` is hash `user_id` and range `credential_type`.** Separating the password
hash from the user record means a route that returns a user cannot accidentally serialise a
hash, which is a real class of bug rather than a hypothetical one, and it lets a second
password-like credential exist later without another column on `users`.

**`refresh_tokens` is keyed on the hash of the token, not on a token id.** That makes the
hot path, "is this presented token valid", a single `GetItem` on the primary key with no
index in the way. The GSI `family_id-generation-index` exists for the other operation,
revoking a whole family, and is never on the verification path.

Only the SHA-256 of the token is stored, so a read of the table cannot be turned into a
working session. The same holds for `identity_tokens`: the email carries the raw value and
the table holds its hash, so a database read cannot be turned into a working reset link.

**Every expiry is checked on read as well as by TTL.** DynamoDB deletes expired items on its
own schedule, typically within a couple of days, which `webbpulse.dynamodb.ttl_in` says in
its own docstring. TTL is storage reclamation. It is never an access control, and every
implementation here checks the deadline in code.

## Why an in-memory implementation ships in the package

Not for this package's own tests, which have moto. It ships because every consuming product
will otherwise write one, slightly differently, and a store whose expiry semantics differ
from the real one is a test suite that passes on behaviour production does not have. The
in-memory stores here check expiry the same way the DynamoDB ones do, hash the same way, and
apply the same conditional semantics, so a flow tested against `InMemory*` and run against
`Dynamo*` behaves identically or the difference is a bug in this file.

They are not thread-safe and are not intended to be. A test is single-threaded and a Lambda
handles one request per execution environment.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import secrets
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final, Literal, cast

from webbpulse.dynamodb import now_iso

if TYPE_CHECKING:  # pragma: no cover - typing only
    from webbpulse.dynamodb import Repository

__all__ = [
    "CREDENTIALS_TABLE",
    "IDENTITY_TOKENS_TABLE",
    "REFRESH_FAMILY_INDEX",
    "REFRESH_TOKENS_TABLE",
    "USERS_TABLE",
    "CredentialRecord",
    "CredentialStore",
    "DynamoCredentialStore",
    "DynamoIdentityTokenStore",
    "DynamoRefreshTokenStore",
    "IdentityStores",
    "IdentityTokenPurpose",
    "IdentityTokenRecord",
    "IdentityTokenStore",
    "InMemoryCredentialStore",
    "InMemoryIdentityTokenStore",
    "InMemoryRefreshTokenStore",
    "RefreshTokenRecord",
    "RefreshTokenStore",
    "constant_time_equals",
    "hash_token",
    "is_expired",
    "new_token",
]

#: Logical table names, as `webbpulse.dynamodb.table_name` expects them. Hyphenated to match
#: the estate's naming, which uses hyphens throughout and never em dashes or underscores in
#: a resource name.
USERS_TABLE: Final = "users"
CREDENTIALS_TABLE: Final = "credentials"
REFRESH_TOKENS_TABLE: Final = "refresh-tokens"
IDENTITY_TOKENS_TABLE: Final = "identity-tokens"

#: The one GSI on `refresh-tokens`, for revoking a family. Never on the verification path.
REFRESH_FAMILY_INDEX: Final = "family_id-generation-index"

#: The purposes an `identity_tokens` row can carry. One table for both, because the two
#: differ only in a TTL and a template, and two tables would double the Terraform for that.
type IdentityTokenPurpose = Literal["verify_email", "reset_password"]

#: Bits of entropy in a refresh token or a verification link. 256, per sections 2.6 and 4.2.
TOKEN_BYTES: Final = 32


def new_token() -> str:
    """A fresh 256-bit token, base64url without padding.

    `secrets.token_urlsafe` rather than `uuid4`: a UUID4 carries 122 bits, not 256, and six
    of its characters are fixed by the version and variant, which is a poor shape for a
    value whose only job is to be unguessable.
    """
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(token: str) -> str:
    """The stored form of a token: hex SHA-256 of its UTF-8 bytes.

    SHA-256 and not bcrypt, deliberately. bcrypt's cost exists to slow an offline attack on
    a **low-entropy** secret, which a password is. These tokens carry 256 bits from a CSPRNG,
    so there is nothing to brute-force and the cost would only be paid on the refresh path
    of every request that needs a new access token.

    Hex rather than base64url because this value is a DynamoDB partition key: hex is
    case-insensitive-safe and cannot collide with the base64url alphabet's `-` and `_` in a
    key expression somebody writes by hand in the console.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CredentialRecord:
    """One credential for one user. In M2 this is the bcrypt password hash.

    `secret` is the stored form and never the presented one: for a password that is the
    bcrypt hash, and nothing that reads this record ever holds a plaintext.
    """

    user_id: str
    credential_type: str
    secret: str
    created_at: str = ""
    updated_at: str = ""
    attributes: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RefreshTokenRecord:
    """One generation of one refresh family.

    A **family** is one login. Rotation writes a new record and marks this one consumed,
    recording `successor_hash` so a replay inside the grace window can be answered with the
    same successor the first call minted rather than revoking a correct session.
    """

    token_hash: str
    family_id: str
    user_id: str
    generation: int
    created_at: str
    expires_at: int
    consumed_at: str = ""
    successor_hash: str = ""
    revoked: bool = False
    device: str = ""
    ip_first_seen: str = ""

    @property
    def is_consumed(self) -> bool:
        return bool(self.consumed_at)


@dataclass(frozen=True, slots=True)
class IdentityTokenRecord:
    """A single-use, time-limited link: email verification or password reset."""

    token_hash: str
    purpose: IdentityTokenPurpose
    user_id: str
    created_at: str
    expires_at: int
    consumed_at: str = ""


# ---------------------------------------------------------------------------
# Interfaces
# ---------------------------------------------------------------------------


class CredentialStore(ABC):
    """The `credentials` table: hash `user_id`, range `credential_type`, no TTL ever."""

    @abstractmethod
    def get(self, user_id: str, credential_type: str) -> CredentialRecord | None:
        """The credential, or `None`.

        Must cost the same whether or not it finds one, as far as the store can control
        that. A lookup that is measurably slower when it succeeds is a timing oracle for
        whether an account has a password, which section 5.3 is about closing.
        """

    @abstractmethod
    def put(self, record: CredentialRecord) -> None:
        """Write or replace a credential."""

    @abstractmethod
    def delete(self, user_id: str, credential_type: str) -> None:
        """Remove a credential. Idempotent: removing an absent one is not an error."""


class RefreshTokenStore(ABC):
    """The `refresh-tokens` table: hash `token_hash`, GSI on the family, TTL `expires_at`."""

    @abstractmethod
    def get(self, token_hash: str) -> RefreshTokenRecord | None:
        """The record for a presented token, expired ones included.

        Expired records are returned rather than hidden, because the caller has to tell
        "expired" from "never existed" to decide between a plain 401 and a reuse
        investigation. `is_expired` is the caller's check, and every implementation here
        makes the same one available.
        """

    @abstractmethod
    def put(self, record: RefreshTokenRecord) -> None:
        """Write a new generation."""

    @abstractmethod
    def consume(
        self, token_hash: str, *, successor_hash: str, consumed_at: str | None = None
    ) -> RefreshTokenRecord | None:
        """Atomically mark this token consumed, returning the record **as it was before**.

        The check and the consume must be one operation. Read-then-write races: two
        concurrent refreshes both read an unconsumed record, both write, and both succeed,
        which is exactly the condition reuse detection exists to notice. On DynamoDB this is
        one `UpdateItem` with a `ConditionExpression` on `attribute_not_exists(consumed_at)`
        and `ReturnValues="ALL_OLD"`.

        Returns `None` when the condition failed, meaning the token was already consumed or
        does not exist. The caller then re-reads to tell those apart: a consumed record whose
        `consumed_at` is inside the grace window replays to `successor_hash`, and one outside
        it is reuse and revokes the family.
        """

    @abstractmethod
    def revoke_family(self, family_id: str) -> int:
        """Revoke every generation of a family. Returns how many were revoked.

        Queries `family_id-generation-index`, which is the only thing that index is for.
        Revoking rather than deleting: a revoked record still has to answer a later replay
        of the same token, and a deleted one answers "never existed", which loses the
        signal.
        """

    @abstractmethod
    def revoke_all_for_user(self, user_id: str) -> int:
        """Revoke every family for a user. What a password reset and "sign out everywhere" call."""


class IdentityTokenStore(ABC):
    """The `identity-tokens` table: hash `token_hash`, TTL `expires_at`, single use."""

    @abstractmethod
    def get(self, token_hash: str) -> IdentityTokenRecord | None:
        """The record, expired ones included, for the same reason `RefreshTokenStore` does."""

    @abstractmethod
    def put(self, record: IdentityTokenRecord) -> None:
        """Write a new link."""

    @abstractmethod
    def consume(
        self, token_hash: str, *, consumed_at: str | None = None
    ) -> IdentityTokenRecord | None:
        """Atomically mark a link used, returning it as it was, or `None` if already used."""

    @abstractmethod
    def revoke_for_user(self, user_id: str, purpose: IdentityTokenPurpose) -> int:
        """Invalidate outstanding links of a purpose for a user, as issuing a new one does."""


@dataclass(frozen=True, slots=True)
class IdentityStores:
    """The stores `build_identity_router` takes, in one object.

    A single argument rather than three, because M2 through M6 add more and a router
    signature that grows a parameter per milestone is one every consumer edits per
    milestone. Every field has a default of `None`, so M1's caller, which mounts only the
    discovery routes and touches no store, passes `IdentityStores()` or nothing at all.
    """

    credentials: CredentialStore | None = None
    refresh_tokens: RefreshTokenStore | None = None
    identity_tokens: IdentityTokenStore | None = None

    def require_credentials(self) -> CredentialStore:
        return _require(self.credentials, "credentials")

    def require_refresh_tokens(self) -> RefreshTokenStore:
        return _require(self.refresh_tokens, "refresh_tokens")

    def require_identity_tokens(self) -> IdentityTokenStore:
        return _require(self.identity_tokens, "identity_tokens")


def _require[StoreT](store: StoreT | None, name: str) -> StoreT:
    if store is None:
        raise ValueError(
            f"IdentityStores.{name} is not configured, and a flow needed it. Pass a "
            f"Dynamo{name.title().replace('_', '')}Store in production, or the InMemory "
            "equivalent in a test."
        )
    return store


# ---------------------------------------------------------------------------
# In-memory implementations
# ---------------------------------------------------------------------------


class InMemoryCredentialStore(CredentialStore):
    """Dict-backed `CredentialStore`, keyed as the table is."""

    def __init__(self) -> None:
        self._items: dict[tuple[str, str], CredentialRecord] = {}

    def get(self, user_id: str, credential_type: str) -> CredentialRecord | None:
        return self._items.get((user_id, credential_type))

    def put(self, record: CredentialRecord) -> None:
        now = now_iso()
        existing = self._items.get((record.user_id, record.credential_type))
        self._items[(record.user_id, record.credential_type)] = CredentialRecord(
            user_id=record.user_id,
            credential_type=record.credential_type,
            secret=record.secret,
            created_at=record.created_at or (existing.created_at if existing else now),
            updated_at=record.updated_at or now,
            attributes=dict(record.attributes),
        )

    def delete(self, user_id: str, credential_type: str) -> None:
        self._items.pop((user_id, credential_type), None)


class InMemoryRefreshTokenStore(RefreshTokenStore):
    """Dict-backed `RefreshTokenStore` with the same atomicity and expiry semantics.

    `consume` is atomic here for free, because a dict operation in a single-threaded test
    cannot interleave. What matters is that it has the same **return contract** as the
    DynamoDB one: the record as it was before the write, or `None` when the condition would
    have failed. A test that depends on that contract passes against both.
    """

    def __init__(self) -> None:
        self._items: dict[str, RefreshTokenRecord] = {}

    def get(self, token_hash: str) -> RefreshTokenRecord | None:
        return self._items.get(token_hash)

    def put(self, record: RefreshTokenRecord) -> None:
        self._items[record.token_hash] = record

    def consume(
        self, token_hash: str, *, successor_hash: str, consumed_at: str | None = None
    ) -> RefreshTokenRecord | None:
        existing = self._items.get(token_hash)
        if existing is None or existing.is_consumed:
            return None
        self._items[token_hash] = dataclasses.replace(
            existing,
            consumed_at=consumed_at or now_iso(),
            successor_hash=successor_hash,
        )
        return existing

    def revoke_family(self, family_id: str) -> int:
        count = 0
        for token_hash, record in list(self._items.items()):
            if record.family_id == family_id and not record.revoked:
                self._items[token_hash] = dataclasses.replace(record, revoked=True)
                count += 1
        return count

    def revoke_all_for_user(self, user_id: str) -> int:
        count = 0
        for token_hash, record in list(self._items.items()):
            if record.user_id == user_id and not record.revoked:
                self._items[token_hash] = dataclasses.replace(record, revoked=True)
                count += 1
        return count


class InMemoryIdentityTokenStore(IdentityTokenStore):
    """Dict-backed `IdentityTokenStore`."""

    def __init__(self) -> None:
        self._items: dict[str, IdentityTokenRecord] = {}

    def get(self, token_hash: str) -> IdentityTokenRecord | None:
        return self._items.get(token_hash)

    def put(self, record: IdentityTokenRecord) -> None:
        self._items[record.token_hash] = record

    def consume(
        self, token_hash: str, *, consumed_at: str | None = None
    ) -> IdentityTokenRecord | None:
        existing = self._items.get(token_hash)
        if existing is None or existing.consumed_at:
            return None
        self._items[token_hash] = dataclasses.replace(
            existing, consumed_at=consumed_at or now_iso()
        )
        return existing

    def revoke_for_user(self, user_id: str, purpose: IdentityTokenPurpose) -> int:
        count = 0
        marker = now_iso()
        for token_hash, record in list(self._items.items()):
            if record.user_id == user_id and record.purpose == purpose and not record.consumed_at:
                self._items[token_hash] = dataclasses.replace(record, consumed_at=marker)
                count += 1
        return count


# ---------------------------------------------------------------------------
# DynamoDB implementations
# ---------------------------------------------------------------------------
#
# These speak `webbpulse.dynamodb.Repository`'s own vocabulary rather than wrapping it in a
# friendlier one. That module's docstring is explicit that it "does not hide
# `KeyConditionExpression`" and that callers pass DynamoDB's own terms, so an
# `updates={...}` convenience layer here would be a second dialect of the same API for a
# reader to learn. The cost is visible `UpdateExpression` strings; the benefit is that
# anything true of a `Repository` elsewhere in the estate is true of these too.


class DynamoCredentialStore(CredentialStore):
    """`CredentialStore` over a `webbpulse.dynamodb.Repository`.

    Takes the repository rather than building one, so the caller owns the table name, the
    prefix and the region exactly as every other repository in a service does, and so this
    module needs no boto3 at import.
    """

    def __init__(self, repository: Repository) -> None:
        self._repo = repository

    def get(self, user_id: str, credential_type: str) -> CredentialRecord | None:
        item = self._repo.get({"user_id": user_id, "credential_type": credential_type})
        if item is None:
            return None
        return _credential_from_item(item)

    def put(self, record: CredentialRecord) -> None:
        now = now_iso()
        self._repo.put(
            {
                **dict(record.attributes),
                "user_id": record.user_id,
                "credential_type": record.credential_type,
                "secret": record.secret,
                "created_at": record.created_at or now,
                "updated_at": record.updated_at or now,
            }
        )

    def delete(self, user_id: str, credential_type: str) -> None:
        self._repo.delete({"user_id": user_id, "credential_type": credential_type})


class DynamoRefreshTokenStore(RefreshTokenStore):
    """`RefreshTokenStore` over a `webbpulse.dynamodb.Repository`.

    The one method worth reading is `consume`, which is a single `UpdateItem` with a
    condition and `ReturnValues="ALL_OLD"`. Anything else races: two tabs refreshing at once
    both read an unconsumed record, both write, both succeed, and the reuse detection that
    the whole session design rests on never fires.
    """

    def __init__(self, repository: Repository) -> None:
        self._repo = repository

    def get(self, token_hash: str) -> RefreshTokenRecord | None:
        # Consistent, because a rotation writes the successor and the very next request may
        # present it. An eventually consistent read can miss a token written moments ago and
        # answer "never existed", which the reuse path would read as an attack.
        item = self._repo.get({"token_hash": token_hash}, consistent=True)
        return _refresh_record_from_item(item) if item is not None else None

    def put(self, record: RefreshTokenRecord) -> None:
        self._repo.put(
            {
                "token_hash": record.token_hash,
                "family_id": record.family_id,
                "user_id": record.user_id,
                "generation": record.generation,
                "created_at": record.created_at,
                "expires_at": record.expires_at,
                "consumed_at": record.consumed_at,
                "successor_hash": record.successor_hash,
                "revoked": record.revoked,
                "device": record.device,
                "ip_first_seen": record.ip_first_seen,
            }
        )

    def consume(
        self, token_hash: str, *, successor_hash: str, consumed_at: str | None = None
    ) -> RefreshTokenRecord | None:
        from boto3.dynamodb.conditions import Attr
        from botocore.exceptions import ClientError

        try:
            old = self._repo.update(
                {"token_hash": token_hash},
                update_expression="SET consumed_at = :now, successor_hash = :successor",
                expression_values={
                    ":now": consumed_at or now_iso(),
                    ":successor": successor_hash,
                },
                # Both halves matter. `exists` refuses to create a row for a token that never
                # existed, which `UpdateItem` would otherwise do happily, turning a forged
                # token into a valid-looking consumed record. The `consumed_at` check is the
                # atomic part: it makes a second concurrent consume fail rather than
                # overwrite the first. `eq("")` is there because `put` writes the unconsumed
                # state as an empty string rather than omitting the attribute.
                condition=(
                    Attr("token_hash").exists()
                    & (Attr("consumed_at").not_exists() | Attr("consumed_at").eq(""))
                ),
                return_values="ALL_OLD",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return None
            raise
        return _refresh_record_from_item(old) if old else None

    def revoke_family(self, family_id: str) -> int:
        from boto3.dynamodb.conditions import Key

        return self._revoke(
            self._repo.iter_query(
                Key("family_id").eq(family_id),
                index_name=REFRESH_FAMILY_INDEX,
            )
        )

    def revoke_all_for_user(self, user_id: str) -> int:
        # No user GSI on this table by design: the hot path is the token hash, and an extra
        # index costs a write on every rotation to serve an operation that runs on a password
        # reset. Sign-out-everywhere revokes each family instead, which the caller knows.
        # Raising rather than silently scanning a production table.
        raise NotImplementedError(
            "revoke_all_for_user needs the caller's family ids: `refresh-tokens` carries no "
            "user index, because indexing the cold path would cost a write on every "
            "rotation of the hot one. Revoke each family with revoke_family instead. M2 "
            "adds the family list to the session service that owns it."
        )

    def _revoke(self, items: Iterable[Mapping[str, Any]]) -> int:
        count = 0
        for item in items:
            if item.get("revoked"):
                continue
            self._repo.update(
                {"token_hash": item["token_hash"]},
                update_expression="SET revoked = :true",
                expression_values={":true": True},
            )
            count += 1
        return count


class DynamoIdentityTokenStore(IdentityTokenStore):
    """`IdentityTokenStore` over a `webbpulse.dynamodb.Repository`."""

    def __init__(self, repository: Repository) -> None:
        self._repo = repository

    def get(self, token_hash: str) -> IdentityTokenRecord | None:
        item = self._repo.get({"token_hash": token_hash}, consistent=True)
        return _identity_token_from_item(item) if item is not None else None

    def put(self, record: IdentityTokenRecord) -> None:
        self._repo.put(
            {
                "token_hash": record.token_hash,
                "purpose": record.purpose,
                "user_id": record.user_id,
                "created_at": record.created_at,
                "expires_at": record.expires_at,
                "consumed_at": record.consumed_at,
            }
        )

    def consume(
        self, token_hash: str, *, consumed_at: str | None = None
    ) -> IdentityTokenRecord | None:
        from boto3.dynamodb.conditions import Attr
        from botocore.exceptions import ClientError

        try:
            old = self._repo.update(
                {"token_hash": token_hash},
                update_expression="SET consumed_at = :now",
                expression_values={":now": consumed_at or now_iso()},
                condition=(
                    Attr("token_hash").exists()
                    & (Attr("consumed_at").not_exists() | Attr("consumed_at").eq(""))
                ),
                return_values="ALL_OLD",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return None
            raise
        return _identity_token_from_item(old) if old else None

    def revoke_for_user(self, user_id: str, purpose: IdentityTokenPurpose) -> int:
        raise NotImplementedError(
            "revoke_for_user needs a user index on `identity-tokens`, which the table does "
            "not carry: the hot path is the token hash and outstanding links expire on "
            "their own within an hour or a day. M3 decides whether the index is worth it "
            "when it implements the reset flow."
        )


# ---------------------------------------------------------------------------
# Item mapping
# ---------------------------------------------------------------------------
#
# Every field is read defensively rather than by subscript. These tables are written by
# this module today, but a record written by an older version of it during a rolling deploy
# is a normal condition, not a corrupt one, and a `KeyError` on a missing `device` would
# turn that into a 500 on the refresh path.


def _credential_from_item(item: Mapping[str, Any]) -> CredentialRecord:
    reserved = {"user_id", "credential_type", "secret", "created_at", "updated_at"}
    return CredentialRecord(
        user_id=str(item["user_id"]),
        credential_type=str(item["credential_type"]),
        secret=str(item.get("secret", "")),
        created_at=str(item.get("created_at", "")),
        updated_at=str(item.get("updated_at", "")),
        attributes={key: value for key, value in item.items() if key not in reserved},
    )


def _refresh_record_from_item(item: Mapping[str, Any]) -> RefreshTokenRecord:
    return RefreshTokenRecord(
        token_hash=str(item["token_hash"]),
        family_id=str(item.get("family_id", "")),
        user_id=str(item.get("user_id", "")),
        generation=int(item.get("generation", 0)),
        created_at=str(item.get("created_at", "")),
        expires_at=int(item.get("expires_at", 0)),
        consumed_at=str(item.get("consumed_at", "")),
        successor_hash=str(item.get("successor_hash", "")),
        revoked=bool(item.get("revoked", False)),
        device=str(item.get("device", "")),
        ip_first_seen=str(item.get("ip_first_seen", "")),
    )


def _identity_token_from_item(item: Mapping[str, Any]) -> IdentityTokenRecord:
    purpose = str(item.get("purpose", ""))
    if purpose not in {"verify_email", "reset_password"}:
        raise ValueError(
            f"Unknown identity token purpose {purpose!r} on token "
            f"{str(item.get('token_hash', ''))[:8]}."
        )
    return IdentityTokenRecord(
        token_hash=str(item["token_hash"]),
        purpose=cast("IdentityTokenPurpose", purpose),
        user_id=str(item.get("user_id", "")),
        created_at=str(item.get("created_at", "")),
        expires_at=int(item.get("expires_at", 0)),
        consumed_at=str(item.get("consumed_at", "")),
    )


# ---------------------------------------------------------------------------
# Deadline and comparison helpers
# ---------------------------------------------------------------------------


def is_expired(expires_at: int, *, now: datetime | None = None) -> bool:
    """Whether an epoch-seconds deadline has passed.

    Every store's caller checks this rather than trusting the table's TTL, for the reason
    `webbpulse.dynamodb.ttl_in` gives in its own docstring: DynamoDB deletes on its own
    schedule, typically within a couple of days, so an expired refresh token stays readable
    long after it expired. TTL is storage reclamation and never an access control.
    """
    return int((now or _now()).timestamp()) >= expires_at


def constant_time_equals(left: str, right: str) -> bool:
    """`hmac.compare_digest` on two strings, for comparing a hash to a stored hash.

    Section 5.3: every comparison of a secret uses a constant-time compare. A `==` on a
    token hash is a timing oracle, and the fact that both sides are already hashes does not
    remove it, because the attacker controls one of them.
    """
    return hmac.compare_digest(left, right)
