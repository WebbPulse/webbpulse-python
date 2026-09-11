"""Storage interfaces for the identity flows, with DynamoDB and in-memory implementations.

Per-entity tables rather than single-table, because TTL is a table-level setting and the
expiring entities must never share a table with the permanent ones.
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

if TYPE_CHECKING:  # pragma: no cover
    from webbpulse.dynamodb import Repository
    from webbpulse.identity.oauth import OAuthLinkStore, OAuthStateStore

__all__ = [
    "CREDENTIALS_TABLE",
    "IDENTITY_TOKENS_TABLE",
    "PASSKEYS_TABLE",
    "PASSKEY_CREDENTIAL_INDEX",
    "RECOVERY_CODES_TABLE",
    "REFRESH_FAMILY_INDEX",
    "REFRESH_TOKENS_TABLE",
    "TOTP_FACTORS_TABLE",
    "USERS_TABLE",
    "WEBAUTHN_CHALLENGES_TABLE",
    "CredentialRecord",
    "CredentialStore",
    "DynamoCredentialStore",
    "DynamoIdentityTokenStore",
    "DynamoPasskeyStore",
    "DynamoRecoveryCodeStore",
    "DynamoRefreshTokenStore",
    "DynamoTotpFactorStore",
    "DynamoWebAuthnChallengeStore",
    "IdentityStores",
    "IdentityTokenPurpose",
    "IdentityTokenRecord",
    "IdentityTokenStore",
    "InMemoryCredentialStore",
    "InMemoryIdentityTokenStore",
    "InMemoryPasskeyStore",
    "InMemoryRecoveryCodeStore",
    "InMemoryRefreshTokenStore",
    "InMemoryTotpFactorStore",
    "InMemoryWebAuthnChallengeStore",
    "PasskeyRecord",
    "PasskeyStore",
    "RecoveryCodeRecord",
    "RecoveryCodeStore",
    "RefreshTokenRecord",
    "RefreshTokenStore",
    "TotpFactorRecord",
    "TotpFactorStore",
    "WebAuthnChallengeRecord",
    "WebAuthnChallengeStore",
    "constant_time_equals",
    "hash_token",
    "is_expired",
    "new_token",
]

USERS_TABLE: Final = "users"
CREDENTIALS_TABLE: Final = "credentials"
REFRESH_TOKENS_TABLE: Final = "refresh-tokens"
IDENTITY_TOKENS_TABLE: Final = "identity-tokens"
TOTP_FACTORS_TABLE: Final = "totp-factors"
RECOVERY_CODES_TABLE: Final = "recovery-codes"

PASSKEYS_TABLE: Final = "passkeys"
WEBAUTHN_CHALLENGES_TABLE: Final = "webauthn-challenges"

REFRESH_FAMILY_INDEX: Final = "family_id-generation-index"

PASSKEY_CREDENTIAL_INDEX: Final = "credential_id-index"

type IdentityTokenPurpose = Literal["verify_email", "reset_password", "mfa_ticket"]

type WebAuthnChallengePurpose = Literal["register", "login"]

TOKEN_BYTES: Final = 32


def new_token() -> str:
    """A fresh 256-bit token, base64url without padding.

    `secrets.token_urlsafe` rather than `uuid4`, whose 122 bits and fixed version and
    variant characters are a poor shape for a value that only has to be unguessable.
    """
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(token: str) -> str:
    """The stored form of a token: hex SHA-256 of its UTF-8 bytes.

    SHA-256 and not bcrypt: these tokens carry 256 bits from a CSPRNG, so there is
    nothing to brute-force. Hex because the value is a DynamoDB partition key.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _now() -> datetime:
    """The current UTC time, as one seam every expiry check shares."""
    return datetime.now(UTC)


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

    A family is one login. Rotation writes a new record and marks this one consumed,
    recording `successor_hash` so a replay inside the grace window gets that successor.
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
    family_started_at: str = ""

    @property
    def is_consumed(self) -> bool:
        """Whether this generation has been rotated away."""
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

    An empty `activated_at` means enrolled but not confirmed, and does not gate login.
    `last_used_step` is the highest step ever accepted, and is the whole replay defence.
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

    Hashed rather than sealed, because a recovery code is only ever compared. An empty
    `used_at` means unspent; rows are marked rather than deleted so they can be audited.
    """

    user_id: str
    code_hash: str
    created_at: str
    used_at: str = ""


@dataclass(frozen=True, slots=True)
class PasskeyRecord:
    """One WebAuthn credential: its public key, its signature counter, and its label.

    The stored half is public, so nothing here is hashed or encrypted. `sign_count`
    migrates as stored, since importing it as zero would disarm clone detection forever.
    """

    user_id: str
    credential_id: str
    public_key: str
    sign_count: int = 0
    name: str = ""
    created_at: str = ""
    last_used_at: str = ""
    transports: tuple[str, ...] = ()
    aaguid: str = ""
    backup_eligible: bool = False
    backup_state: bool = False
    user_verified: bool = False


@dataclass(frozen=True, slots=True)
class WebAuthnChallengeRecord:
    """One outstanding WebAuthn challenge, spent by the ceremony that follows it.

    A table rather than a signed token, because single use is a property of storage.
    `user_id` is empty for a passwordless login challenge.
    """

    challenge_id: str
    challenge: str
    purpose: WebAuthnChallengePurpose
    created_at: str
    expires_at: int
    user_id: str = ""


class CredentialStore(ABC):
    """The `credentials` table: hash `user_id`, range `credential_type`, no TTL ever."""

    @abstractmethod
    def get(self, user_id: str, credential_type: str) -> CredentialRecord | None:
        """The credential, or `None`.

        Must cost the same whether or not it finds one, so far as the store controls that: a
        lookup that is slower when it succeeds is a timing oracle for whether an account exists.
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
        "expired" from "never existed". `is_expired` is the caller's check.
        """

    @abstractmethod
    def put(self, record: RefreshTokenRecord) -> None:
        """Write a new generation."""

    @abstractmethod
    def consume(
        self, token_hash: str, *, successor_hash: str, consumed_at: str | None = None
    ) -> RefreshTokenRecord | None:
        """Atomically mark this token consumed, returning the record as it was before.

        The check and the consume must be one operation, or two concurrent refreshes both
        succeed. Returns `None` when the condition failed, meaning already consumed or absent.
        """

    @abstractmethod
    def revoke_family(self, family_id: str) -> int:
        """Revoke every generation of a family. Returns how many were revoked.

        Queries `family_id-generation-index`. Revoking rather than deleting, because a
        revoked record still has to answer a later replay of the same token.
        """

    @abstractmethod
    def revoke_all_for_user(self, user_id: str, *, except_family_id: str = "") -> int:
        """Revoke every family for a user, sparing `except_family_id`.

        A password change spares the session it was made from, which has just re-proved the
        password. A reset passes nothing, because that session might be the attacker's.
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

    One factor per user, so re-enrolment replaces the seed rather than adding a row. A TTL
    here would silently remove a user's second factor, so the table must never carry one.
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

        Returns `False` when there is no factor or it is already active, so a replayed
        activation cannot reset `last_used_step` and reopen a spent code's window.
        """

    @abstractmethod
    def record_use(self, user_id: str, *, step: int) -> bool:
        """Advance the replay watermark, refusing anything not strictly newer.

        Returns `False` when `step` is not greater than the stored value. Must be one atomic
        conditional write, or two requests carrying the same captured code both accept.
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

        Conditional because two requests presenting the same code concurrently must not both
        succeed, and only the database can settle that.
        """

    @abstractmethod
    def delete_for_user(self, user_id: str) -> int:
        """Remove every code for a user, for regeneration or for disabling MFA."""


class PasskeyStore(ABC):
    """The `passkeys` table: hash `user_id`, range `credential_id`, no TTL ever.

    The GSI settles the second access pattern, which wants the opposite key. No TTL: under
    `passkeys_passwordless` a passkey may be the only way a user signs in.
    """

    @abstractmethod
    def get(self, user_id: str, credential_id: str) -> PasskeyRecord | None:
        """One passkey by its primary key, for rename and delete."""

    @abstractmethod
    def find_by_credential_id(self, credential_id: str) -> PasskeyRecord | None:
        """The passkey with this credential id, whoever owns it, or `None`.

        The login path, and the only read that goes through the GSI. An unknown credential
        is an ordinary refusal rather than an error.
        """

    @abstractmethod
    def list_for_user(self, user_id: str) -> list[PasskeyRecord]:
        """Every passkey a user has, for the management list and for `exclude_credentials`."""

    @abstractmethod
    def put(self, record: PasskeyRecord) -> None:
        """Write a new passkey, refusing a credential id already registered to anyone.

        Conditional on the primary key not existing. The cross-account case is a separate
        check the caller makes, since this method can only condition on its own key.
        """

    @abstractmethod
    def record_use(
        self, user_id: str, credential_id: str, *, sign_count: int, used_at: str
    ) -> None:
        """Advance the signature counter and the last-used stamp after a good assertion.

        Unconditional, unlike `TotpFactorStore.record_use`: the challenge is the replay
        defence here, and the counter detects a clone after the fact.
        """

    @abstractmethod
    def delete(self, user_id: str, credential_id: str) -> bool:
        """Remove one passkey, returning `False` if it was not there.

        Scoped by `user_id` as well as by credential, so a caller cannot delete a passkey it
        does not own even if it learns another user's credential id.
        """

    @abstractmethod
    def rename(self, user_id: str, credential_id: str, *, name: str) -> bool:
        """Set the label on one passkey, returning `False` if it was not there."""


class WebAuthnChallengeStore(ABC):
    """The `webauthn-challenges` table: hash `challenge_id`, TTL `expires_at`, single use.

    The TTL is storage reclamation and never the access control: `consume` checks the
    deadline in code, because DynamoDB deletes on its own schedule.
    """

    @abstractmethod
    def put(self, record: WebAuthnChallengeRecord) -> None:
        """Write a freshly minted challenge."""

    @abstractmethod
    def consume(self, challenge_id: str) -> WebAuthnChallengeRecord | None:
        """Atomically spend a challenge, returning it, or `None` if unknown or already spent.

        Deletes rather than marks, because a spent challenge has nothing to audit and its
        only property is that it does not work twice. Expiry is checked here, not by the TTL.
        """


@dataclass(frozen=True, slots=True)
class IdentityStores:
    """The stores `build_identity_router` takes, in one object.

    One argument rather than one per milestone. Every field defaults to `None`, so a
    caller that mounts only the discovery routes passes nothing at all.
    """

    credentials: CredentialStore | None = None
    refresh_tokens: RefreshTokenStore | None = None
    identity_tokens: IdentityTokenStore | None = None
    totp_factors: TotpFactorStore | None = None
    recovery_codes: RecoveryCodeStore | None = None
    oauth_states: OAuthStateStore | None = None
    oauth_links: OAuthLinkStore | None = None
    passkeys: PasskeyStore | None = None
    webauthn_challenges: WebAuthnChallengeStore | None = None

    def require_credentials(self) -> CredentialStore:
        """The credential store, or a `ValueError` if it was not configured."""
        return _require(self.credentials, "credentials")

    def require_refresh_tokens(self) -> RefreshTokenStore:
        """The refresh token store, or a `ValueError` if it was not configured."""
        return _require(self.refresh_tokens, "refresh_tokens")

    def require_identity_tokens(self) -> IdentityTokenStore:
        """The identity token store, or a `ValueError` if it was not configured."""
        return _require(self.identity_tokens, "identity_tokens")

    def require_totp_factors(self) -> TotpFactorStore:
        """The TOTP factor store, or a `ValueError` if it was not configured."""
        return _require(self.totp_factors, "totp_factors")

    def require_recovery_codes(self) -> RecoveryCodeStore:
        """The recovery code store, or a `ValueError` if it was not configured."""
        return _require(self.recovery_codes, "recovery_codes")

    def require_oauth_states(self) -> OAuthStateStore:
        """The OAuth state store, or a `ValueError` if it was not configured."""
        return _require(self.oauth_states, "oauth_states")

    def require_oauth_links(self) -> OAuthLinkStore:
        """The OAuth link store, or a `ValueError` if it was not configured."""
        return _require(self.oauth_links, "oauth_links")

    def require_passkeys(self) -> PasskeyStore:
        """The passkey store, or a `ValueError` if it was not configured."""
        return _require(self.passkeys, "passkeys")

    def require_webauthn_challenges(self) -> WebAuthnChallengeStore:
        """The WebAuthn challenge store, or a `ValueError` if it was not configured."""
        return _require(self.webauthn_challenges, "webauthn_challenges")


def _require[StoreT](store: StoreT | None, name: str) -> StoreT:
    """The store, or a `ValueError` naming the one that was not configured."""
    if store is None:
        raise ValueError(
            f"IdentityStores.{name} is not configured, and a flow needed it. Pass a "
            f"Dynamo{name.title().replace('_', '')}Store in production, or the InMemory "
            "equivalent in a test."
        )
    return store


class InMemoryCredentialStore(CredentialStore):
    """Dict-backed `CredentialStore`, keyed as the table is."""

    def __init__(self) -> None:
        """Start with an empty backing dict."""
        self._items: dict[tuple[str, str], CredentialRecord] = {}

    def get(self, user_id: str, credential_type: str) -> CredentialRecord | None:
        """The credential, or `None`."""
        return self._items.get((user_id, credential_type))

    def put(self, record: CredentialRecord) -> None:
        """Write or replace a credential."""
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
        """Remove a credential. Idempotent: removing an absent one is not an error."""
        self._items.pop((user_id, credential_type), None)


class InMemoryRefreshTokenStore(RefreshTokenStore):
    """Dict-backed `RefreshTokenStore` with the same atomicity and expiry semantics.

    `consume` has the same return contract as the DynamoDB one: the record as it was
    before the write, or `None` when the condition would have failed.
    """

    def __init__(self) -> None:
        """Start with an empty backing dict."""
        self._items: dict[str, RefreshTokenRecord] = {}

    def get(self, token_hash: str) -> RefreshTokenRecord | None:
        """The record for a presented token, expired ones included."""
        return self._items.get(token_hash)

    def put(self, record: RefreshTokenRecord) -> None:
        """Write a new generation."""
        self._items[record.token_hash] = record

    def consume(
        self, token_hash: str, *, successor_hash: str, consumed_at: str | None = None
    ) -> RefreshTokenRecord | None:
        """Atomically mark this token consumed, returning the record **as it was before**."""
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
        """Revoke every generation of a family. Returns how many were revoked."""
        count = 0
        for token_hash, record in list(self._items.items()):
            if record.family_id == family_id and not record.revoked:
                self._items[token_hash] = dataclasses.replace(record, revoked=True)
                count += 1
        return count

    def revoke_all_for_user(self, user_id: str, *, except_family_id: str = "") -> int:
        """Revoke every family for a user. What a password reset and "sign out everywhere" call."""
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
        """Start with an empty backing dict."""
        self._items: dict[str, IdentityTokenRecord] = {}

    def get(self, token_hash: str) -> IdentityTokenRecord | None:
        """The record, expired ones included, for the same reason `RefreshTokenStore` does."""
        return self._items.get(token_hash)

    def put(self, record: IdentityTokenRecord) -> None:
        """Write a new link."""
        self._items[record.token_hash] = record

    def consume(
        self, token_hash: str, *, consumed_at: str | None = None
    ) -> IdentityTokenRecord | None:
        """Atomically mark a link used, returning it as it was, or `None` if already used."""
        existing = self._items.get(token_hash)
        if existing is None or existing.consumed_at:
            return None
        self._items[token_hash] = dataclasses.replace(
            existing, consumed_at=consumed_at or now_iso()
        )
        return existing

    def revoke_for_user(self, user_id: str, purpose: IdentityTokenPurpose) -> int:
        """Invalidate outstanding links of a purpose for a user, as issuing a new one does."""
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
        """Start with an empty backing dict."""
        self._items: dict[str, TotpFactorRecord] = {}

    def get(self, user_id: str) -> TotpFactorRecord | None:
        """The factor, active or merely enrolled. The caller checks `is_active`."""
        return self._items.get(user_id)

    def put(self, record: TotpFactorRecord) -> None:
        """Write or replace a factor. Re-enrolment overwrites, per the class docstring."""
        self._items[record.user_id] = record

    def activate(self, user_id: str, *, step: int, activated_at: str | None = None) -> bool:
        """Confirm a pending factor with its first verified code."""
        existing = self._items.get(user_id)
        if existing is None or existing.is_active:
            return False
        self._items[user_id] = dataclasses.replace(
            existing, activated_at=activated_at or now_iso(), last_used_step=step
        )
        return True

    def record_use(self, user_id: str, *, step: int) -> bool:
        """Advance the replay watermark, refusing anything not strictly newer."""
        existing = self._items.get(user_id)
        if existing is None or step <= existing.last_used_step:
            return False
        self._items[user_id] = dataclasses.replace(existing, last_used_step=step)
        return True

    def delete(self, user_id: str) -> None:
        """Remove the factor entirely, for a user disabling TOTP."""
        self._items.pop(user_id, None)


class InMemoryRecoveryCodeStore(RecoveryCodeStore):
    """Dict-backed `RecoveryCodeStore`, keyed by the table's composite key."""

    def __init__(self) -> None:
        """Start with an empty backing dict."""
        self._items: dict[tuple[str, str], RecoveryCodeRecord] = {}

    def put_many(self, records: Iterable[RecoveryCodeRecord]) -> None:
        """Write a fresh set. Called only after `delete_for_user`, never to append."""
        for record in records:
            self._items[(record.user_id, record.code_hash)] = record

    def list_for_user(self, user_id: str) -> list[RecoveryCodeRecord]:
        """Every code for a user, spent ones included, so remaining can be counted."""
        return [record for (owner, _), record in self._items.items() if owner == user_id]

    def consume(self, user_id: str, code_hash: str, *, used_at: str | None = None) -> bool:
        """Atomically spend one code, returning `False` if unknown or already spent."""
        existing = self._items.get((user_id, code_hash))
        if existing is None or existing.used_at:
            return False
        self._items[(user_id, code_hash)] = dataclasses.replace(
            existing, used_at=used_at or now_iso()
        )
        return True

    def delete_for_user(self, user_id: str) -> int:
        """Remove every code for a user, for regeneration or for disabling MFA."""
        keys = [key for key in self._items if key[0] == user_id]
        for key in keys:
            del self._items[key]
        return len(keys)


class InMemoryPasskeyStore(PasskeyStore):
    """Dict-backed `PasskeyStore`, keyed by the table's composite key.

    `find_by_credential_id` walks the values rather than keeping a second dict, which
    cannot drift out of step the way two mappings would.
    """

    def __init__(self) -> None:
        """Start with an empty backing dict."""
        self._items: dict[tuple[str, str], PasskeyRecord] = {}

    def get(self, user_id: str, credential_id: str) -> PasskeyRecord | None:
        """One passkey by its primary key, for rename and delete."""
        return self._items.get((user_id, credential_id))

    def find_by_credential_id(self, credential_id: str) -> PasskeyRecord | None:
        """The passkey with this credential id, whoever owns it, or `None`."""
        for (_, stored_id), record in self._items.items():
            if stored_id == credential_id:
                return record
        return None

    def list_for_user(self, user_id: str) -> list[PasskeyRecord]:
        """Every passkey a user has, for the management list and for `exclude_credentials`."""
        return [record for (owner, _), record in self._items.items() if owner == user_id]

    def put(self, record: PasskeyRecord) -> None:
        """Write a new passkey, refusing a credential id already registered to anyone."""
        key = (record.user_id, record.credential_id)
        if key in self._items:
            raise KeyError(f"passkey {record.credential_id[:12]} is already registered")
        self._items[key] = dataclasses.replace(record, created_at=record.created_at or now_iso())

    def record_use(
        self, user_id: str, credential_id: str, *, sign_count: int, used_at: str
    ) -> None:
        """Advance the signature counter and the last-used stamp after a good assertion."""
        existing = self._items.get((user_id, credential_id))
        if existing is None:
            return
        self._items[(user_id, credential_id)] = dataclasses.replace(
            existing, sign_count=sign_count, last_used_at=used_at
        )

    def delete(self, user_id: str, credential_id: str) -> bool:
        """Remove one passkey, returning `False` if it was not there."""
        return self._items.pop((user_id, credential_id), None) is not None

    def rename(self, user_id: str, credential_id: str, *, name: str) -> bool:
        """Set the label on one passkey, returning `False` if it was not there."""
        existing = self._items.get((user_id, credential_id))
        if existing is None:
            return False
        self._items[(user_id, credential_id)] = dataclasses.replace(existing, name=name)
        return True


class InMemoryWebAuthnChallengeStore(WebAuthnChallengeStore):
    """Dict-backed `WebAuthnChallengeStore`, deleting on consumption as the real one does."""

    def __init__(self) -> None:
        """Start with an empty backing dict."""
        self._items: dict[str, WebAuthnChallengeRecord] = {}

    def put(self, record: WebAuthnChallengeRecord) -> None:
        """Write a freshly minted challenge."""
        self._items[record.challenge_id] = record

    def consume(self, challenge_id: str) -> WebAuthnChallengeRecord | None:
        """Atomically spend a challenge, returning it, or `None` if unknown or already spent."""
        existing = self._items.pop(challenge_id, None)
        if existing is None or is_expired(existing.expires_at):
            return None
        return existing


class DynamoCredentialStore(CredentialStore):
    """`CredentialStore` over a `webbpulse.dynamodb.Repository`.

    Takes the repository rather than building one, so the caller owns the table name,
    prefix and region, and this module needs no boto3 at import.
    """

    def __init__(self, repository: Repository) -> None:
        """Bind this store to the repository holding its table."""
        self._repo = repository

    def get(self, user_id: str, credential_type: str) -> CredentialRecord | None:
        """The credential, or `None`."""
        item = self._repo.get({"user_id": user_id, "credential_type": credential_type})
        if item is None:
            return None
        return _credential_from_item(item)

    def put(self, record: CredentialRecord) -> None:
        """Write or replace a credential."""
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
        """Remove a credential. Idempotent: removing an absent one is not an error."""
        self._repo.delete({"user_id": user_id, "credential_type": credential_type})


class DynamoRefreshTokenStore(RefreshTokenStore):
    """`RefreshTokenStore` over a `webbpulse.dynamodb.Repository`.

    `consume` is a single `UpdateItem` with a condition and `ReturnValues="ALL_OLD"`.
    Anything else races, and the reuse detection never fires.
    """

    def __init__(self, repository: Repository) -> None:
        """Bind this store to the repository holding its table."""
        self._repo = repository

    def get(self, token_hash: str) -> RefreshTokenRecord | None:
        """The record for a presented token, expired ones included."""
        item = self._repo.get({"token_hash": token_hash}, consistent=True)
        return _refresh_record_from_item(item) if item is not None else None

    def put(self, record: RefreshTokenRecord) -> None:
        """Write a new generation."""
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
        """Atomically mark this token consumed, returning the record **as it was before**."""
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
        """Revoke every generation of a family. Returns how many were revoked."""
        from boto3.dynamodb.conditions import Key

        return self._revoke(
            self._repo.iter_query(
                Key("family_id").eq(family_id),
                index_name=REFRESH_FAMILY_INDEX,
            )
        )

    def revoke_all_for_user(self, user_id: str, *, except_family_id: str = "") -> int:
        """Revoke every family for a user. What a password reset and "sign out everywhere" call."""
        raise NotImplementedError(
            "revoke_all_for_user needs the caller's family ids: `refresh-tokens` carries no "
            "user index, because indexing the cold path would cost a write on every "
            "rotation of the hot one. Revoke each family with revoke_family instead. M2 "
            "adds the family list to the session service that owns it."
        )

    def _revoke(self, items: Iterable[Mapping[str, Any]]) -> int:
        """Mark each item revoked, skipping ones already revoked. Returns how many changed."""
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
        """Bind this store to the repository holding its table."""
        self._repo = repository

    def get(self, token_hash: str) -> IdentityTokenRecord | None:
        """The record, expired ones included, for the same reason `RefreshTokenStore` does."""
        item = self._repo.get({"token_hash": token_hash}, consistent=True)
        return _identity_token_from_item(item) if item is not None else None

    def put(self, record: IdentityTokenRecord) -> None:
        """Write a new link."""
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
        """Atomically mark a link used, returning it as it was, or `None` if already used."""
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
        """Invalidate outstanding links of a purpose for a user, as issuing a new one does."""
        raise NotImplementedError(
            "revoke_for_user needs a user index on `identity-tokens`, which the table does "
            "not carry: the hot path is the token hash and outstanding links expire on "
            "their own within an hour or a day. M3 decides whether the index is worth it "
            "when it implements the reset flow."
        )


class DynamoTotpFactorStore(TotpFactorStore):
    """`TotpFactorStore` over a `webbpulse.dynamodb.Repository`.

    `activate` and `record_use` are conditional writes, because the replay watermark
    only works if the comparison happens inside the database.
    """

    def __init__(self, repository: Repository) -> None:
        """Bind this store to the repository holding its table."""
        self._repo = repository

    def get(self, user_id: str) -> TotpFactorRecord | None:
        """The factor, active or merely enrolled. The caller checks `is_active`."""
        item = self._repo.get({"user_id": user_id}, consistent=True)
        return _totp_factor_from_item(item) if item is not None else None

    def put(self, record: TotpFactorRecord) -> None:
        """Write or replace a factor. Re-enrolment overwrites, per the class docstring."""
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
        """Confirm a pending factor with its first verified code."""
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
        """Advance the replay watermark, refusing anything not strictly newer."""
        from boto3.dynamodb.conditions import Attr
        from botocore.exceptions import ClientError

        try:
            self._repo.update(
                {"user_id": user_id},
                update_expression="SET last_used_step = :step",
                expression_values={":step": step},
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
        """Remove the factor entirely, for a user disabling TOTP."""
        self._repo.delete({"user_id": user_id})


class DynamoRecoveryCodeStore(RecoveryCodeStore):
    """`RecoveryCodeStore` over a `webbpulse.dynamodb.Repository`."""

    def __init__(self, repository: Repository) -> None:
        """Bind this store to the repository holding its table."""
        self._repo = repository

    def put_many(self, records: Iterable[RecoveryCodeRecord]) -> None:
        """Write a fresh set. Called only after `delete_for_user`, never to append."""
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
        """Every code for a user, spent ones included, so remaining can be counted."""
        from boto3.dynamodb.conditions import Key as KeyCondition

        return [
            _recovery_code_from_item(item)
            for item in self._repo.iter_query(KeyCondition("user_id").eq(user_id), consistent=True)
        ]

    def consume(self, user_id: str, code_hash: str, *, used_at: str | None = None) -> bool:
        """Atomically spend one code, returning `False` if unknown or already spent."""
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
                return False
            raise
        return True

    def delete_for_user(self, user_id: str) -> int:
        """Remove every code for a user, for regeneration or for disabling MFA."""
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


class DynamoPasskeyStore(PasskeyStore):
    """`PasskeyStore` over a `webbpulse.dynamodb.Repository`.

    `find_by_credential_id` is the one read that goes through `PASSKEY_CREDENTIAL_INDEX`.
    """

    def __init__(self, repository: Repository) -> None:
        """Bind this store to the repository holding its table."""
        self._repo = repository

    def get(self, user_id: str, credential_id: str) -> PasskeyRecord | None:
        """One passkey by its primary key, for rename and delete."""
        item = self._repo.get({"user_id": user_id, "credential_id": credential_id}, consistent=True)
        return _passkey_from_item(item) if item is not None else None

    def find_by_credential_id(self, credential_id: str) -> PasskeyRecord | None:
        """The passkey with this credential id, whoever owns it, or `None`."""
        from boto3.dynamodb.conditions import Key as KeyCondition

        page = self._repo.query(
            KeyCondition("credential_id").eq(credential_id),
            index_name=PASSKEY_CREDENTIAL_INDEX,
            limit=1,
        )
        return _passkey_from_item(page.items[0]) if page.items else None

    def list_for_user(self, user_id: str) -> list[PasskeyRecord]:
        """Every passkey a user has, for the management list and for `exclude_credentials`."""
        from boto3.dynamodb.conditions import Key as KeyCondition

        return [
            _passkey_from_item(item)
            for item in self._repo.iter_query(KeyCondition("user_id").eq(user_id), consistent=True)
        ]

    def put(self, record: PasskeyRecord) -> None:
        """Write a new passkey, refusing a credential id already registered to anyone."""
        from boto3.dynamodb.conditions import Attr
        from botocore.exceptions import ClientError

        try:
            self._repo.put(
                {
                    "user_id": record.user_id,
                    "credential_id": record.credential_id,
                    "public_key": record.public_key,
                    "sign_count": record.sign_count,
                    "name": record.name,
                    "created_at": record.created_at or now_iso(),
                    "last_used_at": record.last_used_at,
                    "transports": list(record.transports),
                    "aaguid": record.aaguid,
                    "backup_eligible": record.backup_eligible,
                    "backup_state": record.backup_state,
                    "user_verified": record.user_verified,
                },
                condition=Attr("credential_id").not_exists(),
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                raise KeyError(
                    f"passkey {record.credential_id[:12]} is already registered"
                ) from exc
            raise

    def record_use(
        self, user_id: str, credential_id: str, *, sign_count: int, used_at: str
    ) -> None:
        """Advance the signature counter and the last-used stamp after a good assertion."""
        self._repo.update(
            {"user_id": user_id, "credential_id": credential_id},
            update_expression="SET sign_count = :count, last_used_at = :at",
            expression_values={":count": sign_count, ":at": used_at},
        )

    def delete(self, user_id: str, credential_id: str) -> bool:
        """Remove one passkey, returning `False` if it was not there."""
        from boto3.dynamodb.conditions import Attr
        from botocore.exceptions import ClientError

        try:
            self._repo.delete(
                {"user_id": user_id, "credential_id": credential_id},
                condition=Attr("credential_id").exists(),
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return False
            raise
        return True

    def rename(self, user_id: str, credential_id: str, *, name: str) -> bool:
        """Set the label on one passkey, returning `False` if it was not there."""
        from boto3.dynamodb.conditions import Attr
        from botocore.exceptions import ClientError

        try:
            self._repo.update(
                {"user_id": user_id, "credential_id": credential_id},
                update_expression="SET #name = :name",
                expression_values={":name": name},
                expression_names={"#name": "name"},
                condition=Attr("credential_id").exists(),
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return False
            raise
        return True


class DynamoWebAuthnChallengeStore(WebAuthnChallengeStore):
    """`WebAuthnChallengeStore` over a `webbpulse.dynamodb.Repository`.

    `consume` deletes rather than marks, and checks expiry in code rather than trusting
    the table's TTL.
    """

    def __init__(self, repository: Repository) -> None:
        """Bind this store to the repository holding its table."""
        self._repo = repository

    def put(self, record: WebAuthnChallengeRecord) -> None:
        """Write a freshly minted challenge."""
        self._repo.put(
            {
                "challenge_id": record.challenge_id,
                "challenge": record.challenge,
                "purpose": record.purpose,
                "user_id": record.user_id,
                "created_at": record.created_at,
                "expires_at": record.expires_at,
            }
        )

    def consume(self, challenge_id: str) -> WebAuthnChallengeRecord | None:
        """Atomically spend a challenge, returning it, or `None` if unknown or already spent."""
        response = self._repo.table.delete_item(
            Key={"challenge_id": challenge_id}, ReturnValues="ALL_OLD"
        )
        attributes = response.get("Attributes")
        if not attributes:
            return None
        record = _webauthn_challenge_from_item(attributes)
        return None if is_expired(record.expires_at) else record


def _credential_from_item(item: Mapping[str, Any]) -> CredentialRecord:
    """Build a `CredentialRecord` from a DynamoDB item, keeping unreserved keys as attributes."""
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
    """Build a `RefreshTokenRecord` from a DynamoDB item."""
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
    """Build an `IdentityTokenRecord` from a DynamoDB item, rejecting an unknown purpose."""
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
    """Build a `TotpFactorRecord` from a DynamoDB item."""
    return TotpFactorRecord(
        user_id=str(item["user_id"]),
        secret_ciphertext=str(item.get("secret_ciphertext", "")),
        secret_nonce=str(item.get("secret_nonce", "")),
        wrapped_data_key=str(item.get("wrapped_data_key", "")),
        created_at=str(item.get("created_at", "")),
        activated_at=str(item.get("activated_at", "")),
        last_used_step=int(item.get("last_used_step", 0)),
    )


def _passkey_from_item(item: Mapping[str, Any]) -> PasskeyRecord:
    """Build a `PasskeyRecord` from a DynamoDB item."""
    raw_transports = item.get("transports")
    transports = (
        tuple(str(value) for value in raw_transports) if isinstance(raw_transports, list) else ()
    )
    return PasskeyRecord(
        user_id=str(item["user_id"]),
        credential_id=str(item["credential_id"]),
        public_key=str(item.get("public_key", "")),
        sign_count=int(item.get("sign_count", 0)),
        name=str(item.get("name", "")),
        created_at=str(item.get("created_at", "")),
        last_used_at=str(item.get("last_used_at", "")),
        transports=transports,
        aaguid=str(item.get("aaguid", "")),
        backup_eligible=bool(item.get("backup_eligible", False)),
        backup_state=bool(item.get("backup_state", False)),
        user_verified=bool(item.get("user_verified", False)),
    )


def _webauthn_challenge_from_item(item: Mapping[str, Any]) -> WebAuthnChallengeRecord:
    """Build a `WebAuthnChallengeRecord` from a DynamoDB item, rejecting an unknown purpose."""
    purpose = str(item.get("purpose", ""))
    if purpose not in {"register", "login"}:
        raise ValueError(
            f"Unknown WebAuthn challenge purpose {purpose!r} on challenge "
            f"{str(item.get('challenge_id', ''))[:8]}."
        )
    return WebAuthnChallengeRecord(
        challenge_id=str(item["challenge_id"]),
        challenge=str(item.get("challenge", "")),
        purpose=cast("WebAuthnChallengePurpose", purpose),
        user_id=str(item.get("user_id", "")),
        created_at=str(item.get("created_at", "")),
        expires_at=int(item.get("expires_at", 0)),
    )


def _recovery_code_from_item(item: Mapping[str, Any]) -> RecoveryCodeRecord:
    """Build a `RecoveryCodeRecord` from a DynamoDB item."""
    return RecoveryCodeRecord(
        user_id=str(item["user_id"]),
        code_hash=str(item["code_hash"]),
        created_at=str(item.get("created_at", "")),
        used_at=str(item.get("used_at", "")),
    )


def is_expired(expires_at: int, *, now: datetime | None = None) -> bool:
    """Whether an epoch-seconds deadline has passed.

    Every store's caller checks this rather than trusting the table's TTL, because
    DynamoDB deletes on its own schedule. TTL is storage reclamation, not access control.
    """
    return int((now or _now()).timestamp()) >= expires_at


def constant_time_equals(left: str, right: str) -> bool:
    """`hmac.compare_digest` on two strings, for comparing a hash to a stored hash.

    A `==` on a token hash is a timing oracle, and both sides already being hashes does
    not remove it, because the attacker controls one of them.
    """
    return hmac.compare_digest(left, right)
