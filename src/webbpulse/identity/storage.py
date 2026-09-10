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
| `totp_factors` | `user_id` | none | none | **never** |
| `recovery_codes` | `user_id` | `code_hash` | none | **never** |

The three M1 stores are `credentials`, `refresh_tokens` and `identity_tokens`; M4 adds
`totp_factors` and `recovery_codes`. `users` is reached through the product's own repository
behind `IdentityHooks.user_repository`, because section 4.2 gives the `users` domain
ownership of that record.

**The two M4 tables must never carry a TTL**, and the reason is the sharper version of the
general rule above. An expiring refresh token that vanishes early costs a user one extra
login. A TOTP factor or a recovery code that vanishes early costs them the account: the
second factor silently disappears, and if MFA is required for their role they cannot get in
at all. These rows are deleted explicitly, by a user disabling TOTP or regenerating a set,
and never on a schedule.

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
    from webbpulse.identity.oauth import OAuthLinkStore, OAuthStateStore

__all__ = [
    "CREDENTIALS_TABLE",
    "IDENTITY_TOKENS_TABLE",
    "RECOVERY_CODES_TABLE",
    "REFRESH_FAMILY_INDEX",
    "REFRESH_TOKENS_TABLE",
    "TOTP_FACTORS_TABLE",
    "USERS_TABLE",
    "CredentialRecord",
    "CredentialStore",
    "DynamoCredentialStore",
    "DynamoIdentityTokenStore",
    "DynamoRecoveryCodeStore",
    "DynamoRefreshTokenStore",
    "DynamoTotpFactorStore",
    "IdentityStores",
    "IdentityTokenPurpose",
    "IdentityTokenRecord",
    "IdentityTokenStore",
    "InMemoryCredentialStore",
    "InMemoryIdentityTokenStore",
    "InMemoryRecoveryCodeStore",
    "InMemoryRefreshTokenStore",
    "InMemoryTotpFactorStore",
    "RecoveryCodeRecord",
    "RecoveryCodeStore",
    "RefreshTokenRecord",
    "RefreshTokenStore",
    "TotpFactorRecord",
    "TotpFactorStore",
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
TOTP_FACTORS_TABLE: Final = "totp-factors"
RECOVERY_CODES_TABLE: Final = "recovery-codes"

#: The one GSI on `refresh-tokens`, for revoking a family. Never on the verification path.
REFRESH_FAMILY_INDEX: Final = "family_id-generation-index"

#: The purposes an `identity_tokens` row can carry. One table for all three, because they
#: differ only in a TTL and a template, and three tables would triple the Terraform for that.
#:
#: `mfa_ticket` is M4's, and it stores no token: the ticket itself is a signed JWT that is
#: never written down. What is written is a row keyed on the hash of its `jti`, so that
#: spending a ticket is the same atomic `consume` a reset link uses, and a replay loses the
#: race rather than being caught by a read. The TTL matches the ticket's own five minutes,
#: so the rows clear themselves.
type IdentityTokenPurpose = Literal["verify_email", "reset_password", "mfa_ticket"]

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
    #: When the family this record belongs to began, carried on every generation.
    #:
    #: The absolute cap in section 3.3 is a property of the family, not of the token, so a
    #: rotation has to know when the login happened. Copying it onto each generation keeps
    #: that a field read rather than a second lookup, and there is nothing to look up
    #: anyway once the first generation has been reclaimed by TTL.
    #:
    #: Empty on a record written before this field existed, which a rolling deploy produces.
    #: The session service falls back to `created_at`, which is wrong in the permissive
    #: direction for at most one rotation and never denies a correct session.
    family_started_at: str = ""

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


@dataclass(frozen=True, slots=True)
class TotpFactorRecord:
    """One user's TOTP factor: the sealed seed, its state, and the replay watermark.

    The seed is held as the three base64 strings `EnvelopeCipher` produces, never as
    plaintext and never as something that could be hashed instead. A TOTP seed is the input
    to an HMAC that both sides compute, so unlike a password it has to come back out.

    `activated_at` empty means enrolled but not confirmed. A factor in that state is not a
    factor: it does not gate login and it does not appear in `factors`, because the user has
    not yet proved their authenticator holds the same seed. Section 2.6 requires the first
    code before the factor counts, so that a user who scans a QR badly is not locked out of
    their own account by a factor they cannot satisfy.

    `last_used_step` is the highest time step ever accepted for this user. It is the whole
    of the replay defence and the reason `totp.verify_code` returns a step rather than a
    boolean. Zero means nothing has been accepted yet.
    """

    user_id: str
    secret_ciphertext: str
    secret_nonce: str
    wrapped_data_key: str
    created_at: str
    activated_at: str = ""
    last_used_step: int = 0

    @property
    def is_active(self) -> bool:
        """Whether this factor gates login. Enrolled but unconfirmed factors do not."""
        return bool(self.activated_at)


@dataclass(frozen=True, slots=True)
class RecoveryCodeRecord:
    """One recovery code, stored as its hash, spent at most once.

    Hashed rather than sealed, the opposite of the TOTP seed, and for the reason that
    decides every such choice: a recovery code is only ever **compared**, so the plaintext
    never needs to come back and storing it would be storing a password in the clear.

    `used_at` empty means unspent. Rows are marked rather than deleted so that
    `recovery.used` in section 5.7 has something to audit against and so a user can be shown
    how many codes remain without the count being a guess.
    """

    user_id: str
    code_hash: str
    created_at: str
    used_at: str = ""


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
    def revoke_all_for_user(self, user_id: str, *, except_family_id: str = "") -> int:
        """Revoke every family for a user. What a password reset and "sign out everywhere" call.

        `except_family_id` spares one family, which is what a password **change** wants: the
        change is made from a live session, and signing the user out of the tab they did it
        in is a bad experience with no security value, since that session has just re-proved
        the password. A **reset** passes nothing and revokes everything, because there the
        session doing the resetting is exactly the one that might be the attacker's.
        """


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


class TotpFactorStore(ABC):
    """The `totp-factors` table: hash `user_id`, no range, no TTL ever.

    One factor per user, so `user_id` alone is the key. A second authenticator is not a
    second row: the user re-enrols and replaces the seed, which is what every consumer app
    does and what keeps `factors` in the login challenge a straightforward derivation
    rather than a query.

    **No TTL.** Section 4.1's rule applies with force here: a TTL attribute on this table
    that some future code sets by accident silently removes a user's second factor, and the
    account quietly drops to one. The table must never carry one.
    """

    @abstractmethod
    def get(self, user_id: str) -> TotpFactorRecord | None:
        """The factor, active or merely enrolled. The caller checks `is_active`."""

    @abstractmethod
    def put(self, record: TotpFactorRecord) -> None:
        """Write or replace a factor. Re-enrolment overwrites, per the class docstring."""

    @abstractmethod
    def activate(self, user_id: str, *, step: int, activated_at: str | None = None) -> bool:
        """Confirm a pending factor with its first verified code.

        Returns `False` if there is no factor or it is already active, so that a replayed
        activation cannot reset `last_used_step` and reopen the window for a code that was
        already spent. Setting the step in the same write is what makes the confirming code
        itself unusable a second time.
        """

    @abstractmethod
    def record_use(self, user_id: str, *, step: int) -> bool:
        """Advance the replay watermark, refusing anything not strictly newer.

        Returns `False` when `step` is not greater than the stored value, which is the
        replay case. This must be one atomic conditional write: a read-then-write here
        loses exactly the race the watermark exists to close, since two requests carrying
        the same captured code would both read the old value and both accept.
        """

    @abstractmethod
    def delete(self, user_id: str) -> None:
        """Remove the factor entirely, for a user disabling TOTP."""


class RecoveryCodeStore(ABC):
    """The `recovery-codes` table: hash `user_id`, range `code_hash`, no TTL ever.

    The range key is the hash, so spending a code is a point write on the primary key with
    no index and no scan, and a whole set is one `Query` on the partition.
    """

    @abstractmethod
    def put_many(self, records: Iterable[RecoveryCodeRecord]) -> None:
        """Write a fresh set. Called only after `delete_for_user`, never to append."""

    @abstractmethod
    def list_for_user(self, user_id: str) -> list[RecoveryCodeRecord]:
        """Every code for a user, spent ones included, so remaining can be counted."""

    @abstractmethod
    def consume(self, user_id: str, code_hash: str, *, used_at: str | None = None) -> bool:
        """Atomically spend one code, returning `False` if unknown or already spent.

        Conditional for the same reason `IdentityTokenStore.consume` is: two requests
        presenting the same code concurrently must not both succeed, and only the database
        can settle that.
        """

    @abstractmethod
    def delete_for_user(self, user_id: str) -> int:
        """Remove every code for a user, for regeneration or for disabling MFA."""


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
    totp_factors: TotpFactorStore | None = None
    recovery_codes: RecoveryCodeStore | None = None
    oauth_states: OAuthStateStore | None = None
    oauth_links: OAuthLinkStore | None = None

    def require_credentials(self) -> CredentialStore:
        return _require(self.credentials, "credentials")

    def require_refresh_tokens(self) -> RefreshTokenStore:
        return _require(self.refresh_tokens, "refresh_tokens")

    def require_identity_tokens(self) -> IdentityTokenStore:
        return _require(self.identity_tokens, "identity_tokens")

    def require_totp_factors(self) -> TotpFactorStore:
        return _require(self.totp_factors, "totp_factors")

    def require_recovery_codes(self) -> RecoveryCodeStore:
        return _require(self.recovery_codes, "recovery_codes")

    def require_oauth_states(self) -> OAuthStateStore:
        return _require(self.oauth_states, "oauth_states")

    def require_oauth_links(self) -> OAuthLinkStore:
        return _require(self.oauth_links, "oauth_links")


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

    def revoke_all_for_user(self, user_id: str, *, except_family_id: str = "") -> int:
        count = 0
        for token_hash, record in list(self._items.items()):
            if record.family_id == except_family_id:
                continue
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


class InMemoryTotpFactorStore(TotpFactorStore):
    """Dict-backed `TotpFactorStore`, keyed as the table is."""

    def __init__(self) -> None:
        self._items: dict[str, TotpFactorRecord] = {}

    def get(self, user_id: str) -> TotpFactorRecord | None:
        return self._items.get(user_id)

    def put(self, record: TotpFactorRecord) -> None:
        self._items[record.user_id] = record

    def activate(self, user_id: str, *, step: int, activated_at: str | None = None) -> bool:
        existing = self._items.get(user_id)
        if existing is None or existing.is_active:
            return False
        self._items[user_id] = dataclasses.replace(
            existing, activated_at=activated_at or now_iso(), last_used_step=step
        )
        return True

    def record_use(self, user_id: str, *, step: int) -> bool:
        existing = self._items.get(user_id)
        if existing is None or step <= existing.last_used_step:
            return False
        self._items[user_id] = dataclasses.replace(existing, last_used_step=step)
        return True

    def delete(self, user_id: str) -> None:
        self._items.pop(user_id, None)


class InMemoryRecoveryCodeStore(RecoveryCodeStore):
    """Dict-backed `RecoveryCodeStore`, keyed by the table's composite key."""

    def __init__(self) -> None:
        self._items: dict[tuple[str, str], RecoveryCodeRecord] = {}

    def put_many(self, records: Iterable[RecoveryCodeRecord]) -> None:
        for record in records:
            self._items[(record.user_id, record.code_hash)] = record

    def list_for_user(self, user_id: str) -> list[RecoveryCodeRecord]:
        return [record for (owner, _), record in self._items.items() if owner == user_id]

    def consume(self, user_id: str, code_hash: str, *, used_at: str | None = None) -> bool:
        existing = self._items.get((user_id, code_hash))
        if existing is None or existing.used_at:
            return False
        self._items[(user_id, code_hash)] = dataclasses.replace(
            existing, used_at=used_at or now_iso()
        )
        return True

    def delete_for_user(self, user_id: str) -> int:
        keys = [key for key in self._items if key[0] == user_id]
        for key in keys:
            del self._items[key]
        return len(keys)


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
                "family_started_at": record.family_started_at,
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

    def revoke_all_for_user(self, user_id: str, *, except_family_id: str = "") -> int:
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


class DynamoTotpFactorStore(TotpFactorStore):
    """`TotpFactorStore` over a `webbpulse.dynamodb.Repository`.

    The two methods worth reading are `activate` and `record_use`, both single conditional
    `UpdateItem` calls. `record_use` in particular is the replay defence, and writing it as
    a read followed by a write would defeat it entirely: two requests carrying the same
    captured code would both read the old `last_used_step`, both find it lower, and both
    accept. The condition moves that decision into the database, where it is settled once.
    """

    def __init__(self, repository: Repository) -> None:
        self._repo = repository

    def get(self, user_id: str) -> TotpFactorRecord | None:
        # Consistent, because the read after enrolment's write decides whether a user can
        # confirm their factor, and an eventually consistent miss there reads as "you never
        # enrolled" to somebody holding a QR code they just scanned.
        item = self._repo.get({"user_id": user_id}, consistent=True)
        return _totp_factor_from_item(item) if item is not None else None

    def put(self, record: TotpFactorRecord) -> None:
        self._repo.put(
            {
                "user_id": record.user_id,
                "secret_ciphertext": record.secret_ciphertext,
                "secret_nonce": record.secret_nonce,
                "wrapped_data_key": record.wrapped_data_key,
                "created_at": record.created_at,
                "activated_at": record.activated_at,
                "last_used_step": record.last_used_step,
            }
        )

    def activate(self, user_id: str, *, step: int, activated_at: str | None = None) -> bool:
        from boto3.dynamodb.conditions import Attr
        from botocore.exceptions import ClientError

        try:
            self._repo.update(
                {"user_id": user_id},
                update_expression="SET activated_at = :at, last_used_step = :step",
                expression_values={":at": activated_at or now_iso(), ":step": step},
                condition=(
                    Attr("user_id").exists()
                    & (Attr("activated_at").not_exists() | Attr("activated_at").eq(""))
                ),
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return False
            raise
        return True

    def record_use(self, user_id: str, *, step: int) -> bool:
        from boto3.dynamodb.conditions import Attr
        from botocore.exceptions import ClientError

        try:
            self._repo.update(
                {"user_id": user_id},
                update_expression="SET last_used_step = :step",
                expression_values={":step": step},
                # Strictly greater. `not_exists` covers a factor written before this
                # attribute existed, which a rolling deploy can produce.
                condition=(
                    Attr("user_id").exists()
                    & (Attr("last_used_step").not_exists() | Attr("last_used_step").lt(step))
                ),
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return False
            raise
        return True

    def delete(self, user_id: str) -> None:
        self._repo.delete({"user_id": user_id})


class DynamoRecoveryCodeStore(RecoveryCodeStore):
    """`RecoveryCodeStore` over a `webbpulse.dynamodb.Repository`."""

    def __init__(self, repository: Repository) -> None:
        self._repo = repository

    def put_many(self, records: Iterable[RecoveryCodeRecord]) -> None:
        self._repo.put_many(
            [
                {
                    "user_id": record.user_id,
                    "code_hash": record.code_hash,
                    "created_at": record.created_at,
                    "used_at": record.used_at,
                }
                for record in records
            ]
        )

    def list_for_user(self, user_id: str) -> list[RecoveryCodeRecord]:
        from boto3.dynamodb.conditions import Key as KeyCondition

        return [
            _recovery_code_from_item(item)
            for item in self._repo.iter_query(KeyCondition("user_id").eq(user_id), consistent=True)
        ]

    def consume(self, user_id: str, code_hash: str, *, used_at: str | None = None) -> bool:
        from boto3.dynamodb.conditions import Attr
        from botocore.exceptions import ClientError

        try:
            self._repo.update(
                {"user_id": user_id, "code_hash": code_hash},
                update_expression="SET used_at = :now",
                expression_values={":now": used_at or now_iso()},
                condition=(
                    Attr("code_hash").exists()
                    & (Attr("used_at").not_exists() | Attr("used_at").eq(""))
                ),
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                # Unknown code and already-spent code are one answer on purpose. The caller
                # must not be able to tell them apart, and neither must anybody watching the
                # caller's response times.
                return False
            raise
        return True

    def delete_for_user(self, user_id: str) -> int:
        from boto3.dynamodb.conditions import Key as KeyCondition

        hashes = [
            str(item["code_hash"])
            for item in self._repo.iter_query(
                KeyCondition("user_id").eq(user_id), consistent=True, projection="code_hash"
            )
        ]
        for code_hash in hashes:
            self._repo.delete({"user_id": user_id, "code_hash": code_hash})
        return len(hashes)


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
        family_started_at=str(item.get("family_started_at", "")),
    )


def _identity_token_from_item(item: Mapping[str, Any]) -> IdentityTokenRecord:
    purpose = str(item.get("purpose", ""))
    if purpose not in {"verify_email", "reset_password", "mfa_ticket"}:
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


def _totp_factor_from_item(item: Mapping[str, Any]) -> TotpFactorRecord:
    return TotpFactorRecord(
        user_id=str(item["user_id"]),
        secret_ciphertext=str(item.get("secret_ciphertext", "")),
        secret_nonce=str(item.get("secret_nonce", "")),
        wrapped_data_key=str(item.get("wrapped_data_key", "")),
        created_at=str(item.get("created_at", "")),
        activated_at=str(item.get("activated_at", "")),
        last_used_step=int(item.get("last_used_step", 0)),
    )


def _recovery_code_from_item(item: Mapping[str, Any]) -> RecoveryCodeRecord:
    return RecoveryCodeRecord(
        user_id=str(item["user_id"]),
        code_hash=str(item["code_hash"]),
        created_at=str(item.get("created_at", "")),
        used_at=str(item.get("used_at", "")),
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
