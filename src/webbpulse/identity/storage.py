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
| `passkeys` | `user_id` | `credential_id` | `credential_id-index` | **never** |
| `webauthn_challenges` | `challenge_id` | none | none | `expires_at` |

The three M1 stores are `credentials`, `refresh_tokens` and `identity_tokens`; M4 adds
`totp_factors` and `recovery_codes`; M5 adds `passkeys` and `webauthn_challenges`. `users`
is reached through the product's own repository behind `IdentityHooks.user_repository`,
because section 4.2 gives the `users` domain ownership of that record.

**The two M4 tables and `passkeys` must never carry a TTL**, and the reason is the sharper
version of the general rule above. An expiring refresh token that vanishes early costs a
user one extra login. A TOTP factor, a recovery code or a passkey that vanishes early costs
them the account: the factor silently disappears, and if MFA is required for their role, or
if the passkey was their only credential under `passkeys_passwordless`, they cannot get in
at all. These rows are deleted explicitly, by a user disabling TOTP, regenerating a set or
removing a passkey, and never on a schedule.

`webauthn_challenges` is the counterpart and is the one M5 table that **does** expire. Its
rows live five minutes, are deleted the moment they are spent, and hold nothing whose loss
costs anybody anything: a challenge that vanishes early is a ceremony the user restarts.

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

#: Logical table names, as `webbpulse.dynamodb.table_name` expects them. Hyphenated to match
#: the estate's naming, which uses hyphens throughout and never em dashes or underscores in
#: a resource name.
USERS_TABLE: Final = "users"
CREDENTIALS_TABLE: Final = "credentials"
REFRESH_TOKENS_TABLE: Final = "refresh-tokens"
IDENTITY_TOKENS_TABLE: Final = "identity-tokens"
TOTP_FACTORS_TABLE: Final = "totp-factors"
RECOVERY_CODES_TABLE: Final = "recovery-codes"

#: M5's two. `passkeys` is hash `user_id`, range `credential_id`, and **never** a TTL, for
#: the reason `totp-factors` has none: a passkey that vanishes on a schedule is a second
#: factor, or with `passkeys_passwordless` the only factor, silently removed from an account.
#: `webauthn-challenges` is the opposite and is the one table in the identity set whose rows
#: are meant to disappear, hash `challenge_id` and TTL `expires_at`.
PASSKEYS_TABLE: Final = "passkeys"
WEBAUTHN_CHALLENGES_TABLE: Final = "webauthn-challenges"

#: The one GSI on `refresh-tokens`, for revoking a family. Never on the verification path.
REFRESH_FAMILY_INDEX: Final = "family_id-generation-index"

#: The one GSI on `passkeys`, hash `credential_id`, and it is on the **login** path rather
#: than off it, which is the opposite of `REFRESH_FAMILY_INDEX`.
#:
#: A passwordless assertion arrives carrying a credential id and nothing else: the whole
#: point of a discoverable credential is that the user never typed a username. So the lookup
#: "whose passkey is this" has to be answerable without a `user_id`, and the table's own
#: hash key is `user_id`. The alternative shape, hash `credential_id` with a GSI on
#: `user_id`, was rejected because listing a user's passkeys would then be the indexed read
#: and every management route would be eventually consistent: a passkey just registered
#: would be missing from the list the frontend renders immediately after registering it.
#:
#: The consequence is that the login path is eventually consistent, and it is bounded: a
#: passkey missing from the index for the second after it was written cannot be one the user
#: is signing in with, because it was written by a request that was already authenticated.
PASSKEY_CREDENTIAL_INDEX: Final = "credential_id-index"

#: The purposes an `identity_tokens` row can carry. One table for all three, because they
#: differ only in a TTL and a template, and three tables would triple the Terraform for that.
#:
#: `mfa_ticket` is M4's, and it stores no token: the ticket itself is a signed JWT that is
#: never written down. What is written is a row keyed on the hash of its `jti`, so that
#: spending a ticket is the same atomic `consume` a reset link uses, and a replay loses the
#: race rather than being caught by a read. The TTL matches the ticket's own five minutes,
#: so the rows clear themselves.
type IdentityTokenPurpose = Literal["verify_email", "reset_password", "mfa_ticket"]

#: What a `webauthn-challenges` row was minted for. Checked when the row is spent, so a
#: challenge issued for a registration cannot be presented to the login verify leg: the two
#: ceremonies verify different things, and letting one satisfy the other would mean an
#: attacker who can start a registration can answer a login.
type WebAuthnChallengePurpose = Literal["register", "login"]

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


@dataclass(frozen=True, slots=True)
class PasskeyRecord:
    """One WebAuthn credential: its public key, its signature counter, and its label.

    A third storage choice, alongside the sealed TOTP seed and the hashed recovery code, and
    the reason is the same rule applied a third time: store the weakest thing that supports
    the operation. A passkey's stored half is a **public** key. Nothing here is a secret, so
    it is neither hashed nor encrypted, and a read of this table proves nothing and
    authenticates nobody. The private half never left the authenticator.

    `credential_id` and `public_key` are base64url text without padding rather than raw
    bytes. DynamoDB has a binary type and it would work; text is chosen because these values
    travel to the browser as base64url in the WebAuthn JSON either way, because a `B`
    attribute reads back as a `Binary` wrapper that every mapping function would have to
    unwrap, and because an operator looking at a row in the console can compare the value to
    the one in a browser's network tab without decoding anything.

    `sign_count` is the authenticator's own monotonic counter, and it is the one field here
    whose value carries security meaning. It **migrates as stored**: a credential imported
    from another system keeps the counter that system last saw. Importing it as zero would
    disarm the clone detection for that credential permanently, because every subsequent
    assertion would be greater than zero and so would look correct forever. A genuine zero
    means the authenticator does not implement a counter, which is common, and section 6.1.3
    of the WebAuthn specification says both being zero is the signal to skip the check.

    `backup_eligible` and `backup_state` are recorded because a synced passkey and a
    device-bound one are different security propositions, and a product that wants to require
    a device-bound credential for something sensitive needs the row to say which it has.
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
    #: Whether the authenticator verified the user (PIN, biometric) at registration.
    #:
    #: Recorded at registration and **not** consulted at login: what counts for the `amr`
    #: of a passkey login is the `uv` flag on that assertion, because a credential that
    #: could do user verification is not the same as one that just did.
    user_verified: bool = False


@dataclass(frozen=True, slots=True)
class WebAuthnChallengeRecord:
    """One outstanding WebAuthn challenge, spent by the ceremony that follows it.

    ## Why this is a table and not a signed token

    A challenge exists to make one assertion unreplayable, which means the server has to be
    able to say "this one has been used". A stateless JWT cannot say that: it verifies
    exactly as well the second time as the first, so a captured options-plus-assertion pair
    replays for the whole of the token's lifetime. Section 2.6 requires the challenge to be
    single use, and single use is a property of storage.

    That is a deliberate reversal of CarModPicker's current implementation, which puts the
    challenge in a five-minute signed token. Migrating it here is the security half of M5.

    `user_id` is empty for a passwordless login challenge, which is not a defect: a
    discoverable credential means the browser has not yet said who is signing in, and the
    assertion names the credential that answers it. A **registration** challenge always
    carries the subject it was issued to, and the verify leg refuses one that does not match
    the caller, so a challenge minted for one account cannot be spent registering a passkey
    on another.
    """

    challenge_id: str
    challenge: str
    purpose: WebAuthnChallengePurpose
    created_at: str
    expires_at: int
    user_id: str = ""


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


class PasskeyStore(ABC):
    """The `passkeys` table: hash `user_id`, range `credential_id`, no TTL ever.

    Two access patterns, and they want opposite keys, which is what the GSI settles. See
    `PASSKEY_CREDENTIAL_INDEX` for why the table is keyed this way round rather than the
    other.

    **No TTL**, for the reason `TotpFactorStore` gives with even more force: with
    `passkeys_passwordless` on, a passkey may be the only way a user signs in, and a row
    that expires on a schedule is an account locked out by a table setting.
    """

    @abstractmethod
    def get(self, user_id: str, credential_id: str) -> PasskeyRecord | None:
        """One passkey by its primary key, for rename and delete."""

    @abstractmethod
    def find_by_credential_id(self, credential_id: str) -> PasskeyRecord | None:
        """The passkey with this credential id, whoever owns it, or `None`.

        The login path, and the only read that goes through the GSI. Returns `None` for an
        unknown credential rather than raising: an assertion naming a credential this
        product never registered is an ordinary refusal, not an error.
        """

    @abstractmethod
    def list_for_user(self, user_id: str) -> list[PasskeyRecord]:
        """Every passkey a user has, for the management list and for `exclude_credentials`."""

    @abstractmethod
    def put(self, record: PasskeyRecord) -> None:
        """Write a new passkey, refusing a credential id already registered to anyone.

        Conditional on the primary key not existing, which catches a re-registration of the
        same credential to the same account. The cross-account case is a different check and
        the caller does it: this method can only condition on its own key.
        """

    @abstractmethod
    def record_use(
        self, user_id: str, credential_id: str, *, sign_count: int, used_at: str
    ) -> None:
        """Advance the signature counter and the last-used stamp after a good assertion.

        Unconditional, unlike `TotpFactorStore.record_use`, and the difference is worth
        stating because the two look alike. A TOTP watermark is the **whole** replay
        defence, so the comparison has to happen inside the database. A WebAuthn counter is
        not: the challenge is, and it is single use in its own table. The counter detects a
        cloned authenticator after the fact, which is a signal to log and refuse rather than
        a race to win, and the comparison happens in the service before this is called.
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

    The TTL attribute is `expires_at`, matching `refresh-tokens` and `identity-tokens`, and
    like both of those it is storage reclamation and never the access control: `consume`
    checks the deadline in code, because DynamoDB deletes on its own schedule.
    """

    @abstractmethod
    def put(self, record: WebAuthnChallengeRecord) -> None:
        """Write a freshly minted challenge."""

    @abstractmethod
    def consume(self, challenge_id: str) -> WebAuthnChallengeRecord | None:
        """Atomically spend a challenge, returning it, or `None` if unknown or already spent.

        Delete rather than mark, which is the opposite of every other `consume` here. A
        spent link is kept and stamped so section 5.7 has something to audit and so a user
        can be told a link was already used; a spent challenge has nothing to audit, has a
        lifetime of thirty seconds of real use, and its only property is that it does not
        work twice. Deleting makes that property unconditional, and it means the table holds
        only live challenges rather than a five-minute backlog of dead ones.

        Expiry is checked here, not left to the TTL, so a challenge whose row DynamoDB has
        not got round to deleting is still refused.
        """


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
    passkeys: PasskeyStore | None = None
    webauthn_challenges: WebAuthnChallengeStore | None = None

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

    def require_passkeys(self) -> PasskeyStore:
        return _require(self.passkeys, "passkeys")

    def require_webauthn_challenges(self) -> WebAuthnChallengeStore:
        return _require(self.webauthn_challenges, "webauthn_challenges")


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


class InMemoryPasskeyStore(PasskeyStore):
    """Dict-backed `PasskeyStore`, keyed by the table's composite key.

    `find_by_credential_id` walks the values rather than keeping a second dict. A user has a
    handful of passkeys and a test has a handful of users, so the scan is free, and one
    mapping cannot drift out of step with another the way two would.
    """

    def __init__(self) -> None:
        self._items: dict[tuple[str, str], PasskeyRecord] = {}

    def get(self, user_id: str, credential_id: str) -> PasskeyRecord | None:
        return self._items.get((user_id, credential_id))

    def find_by_credential_id(self, credential_id: str) -> PasskeyRecord | None:
        for (_, stored_id), record in self._items.items():
            if stored_id == credential_id:
                return record
        return None

    def list_for_user(self, user_id: str) -> list[PasskeyRecord]:
        return [record for (owner, _), record in self._items.items() if owner == user_id]

    def put(self, record: PasskeyRecord) -> None:
        key = (record.user_id, record.credential_id)
        if key in self._items:
            raise KeyError(f"passkey {record.credential_id[:12]} is already registered")
        self._items[key] = dataclasses.replace(record, created_at=record.created_at or now_iso())

    def record_use(
        self, user_id: str, credential_id: str, *, sign_count: int, used_at: str
    ) -> None:
        existing = self._items.get((user_id, credential_id))
        if existing is None:
            return
        self._items[(user_id, credential_id)] = dataclasses.replace(
            existing, sign_count=sign_count, last_used_at=used_at
        )

    def delete(self, user_id: str, credential_id: str) -> bool:
        return self._items.pop((user_id, credential_id), None) is not None

    def rename(self, user_id: str, credential_id: str, *, name: str) -> bool:
        existing = self._items.get((user_id, credential_id))
        if existing is None:
            return False
        self._items[(user_id, credential_id)] = dataclasses.replace(existing, name=name)
        return True


class InMemoryWebAuthnChallengeStore(WebAuthnChallengeStore):
    """Dict-backed `WebAuthnChallengeStore`, deleting on consumption as the real one does."""

    def __init__(self) -> None:
        self._items: dict[str, WebAuthnChallengeRecord] = {}

    def put(self, record: WebAuthnChallengeRecord) -> None:
        self._items[record.challenge_id] = record

    def consume(self, challenge_id: str) -> WebAuthnChallengeRecord | None:
        existing = self._items.pop(challenge_id, None)
        if existing is None or is_expired(existing.expires_at):
            # An expired row is removed by the `pop` above and then refused, which is what
            # the DynamoDB one does too: the delete succeeds and the deadline check fails.
            return None
        return existing


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


class DynamoPasskeyStore(PasskeyStore):
    """`PasskeyStore` over a `webbpulse.dynamodb.Repository`.

    `find_by_credential_id` is the one method here that reads an index, and it is the only
    read in this module that **cannot** be consistent: DynamoDB does not offer consistent
    reads on a global secondary index at all. See `PASSKEY_CREDENTIAL_INDEX` for why that is
    the acceptable side of the trade.
    """

    def __init__(self, repository: Repository) -> None:
        self._repo = repository

    def get(self, user_id: str, credential_id: str) -> PasskeyRecord | None:
        item = self._repo.get({"user_id": user_id, "credential_id": credential_id}, consistent=True)
        return _passkey_from_item(item) if item is not None else None

    def find_by_credential_id(self, credential_id: str) -> PasskeyRecord | None:
        from boto3.dynamodb.conditions import Key as KeyCondition

        page = self._repo.query(
            KeyCondition("credential_id").eq(credential_id),
            index_name=PASSKEY_CREDENTIAL_INDEX,
            limit=1,
        )
        return _passkey_from_item(page.items[0]) if page.items else None

    def list_for_user(self, user_id: str) -> list[PasskeyRecord]:
        from boto3.dynamodb.conditions import Key as KeyCondition

        return [
            _passkey_from_item(item)
            for item in self._repo.iter_query(KeyCondition("user_id").eq(user_id), consistent=True)
        ]

    def put(self, record: PasskeyRecord) -> None:
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
        self._repo.update(
            {"user_id": user_id, "credential_id": credential_id},
            update_expression="SET sign_count = :count, last_used_at = :at",
            expression_values={":count": sign_count, ":at": used_at},
        )

    def delete(self, user_id: str, credential_id: str) -> bool:
        from boto3.dynamodb.conditions import Attr
        from botocore.exceptions import ClientError

        try:
            # Conditional, only so the absent case can be reported. `Repository.delete` is
            # an unconditional upsert-shaped no-op on a missing item and returns nothing, so
            # the condition is what turns "there was nothing there" into a `False` the route
            # can render as a 404 rather than a misleading 200.
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
        from boto3.dynamodb.conditions import Attr
        from botocore.exceptions import ClientError

        try:
            self._repo.update(
                {"user_id": user_id, "credential_id": credential_id},
                # `name` is a DynamoDB reserved word, which is exactly the case
                # `expression_names` exists for.
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

    `consume` is a conditional `DeleteItem` returning the old item, which is what makes a
    challenge single use against concurrent requests: two assertions racing the same
    challenge both issue the delete, exactly one finds the item there, and the loser gets
    `None` and is refused.
    """

    def __init__(self, repository: Repository) -> None:
        self._repo = repository

    def put(self, record: WebAuthnChallengeRecord) -> None:
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
        # `Repository.delete` cannot return the old item, so this reaches for the table
        # directly. It is the one place in this module that does, and the alternative was a
        # `ReturnValues` parameter on `Repository.delete` that no other caller wants.
        response = self._repo.table.delete_item(
            Key={"challenge_id": challenge_id}, ReturnValues="ALL_OLD"
        )
        attributes = response.get("Attributes")
        if not attributes:
            return None
        record = _webauthn_challenge_from_item(attributes)
        # Deleted either way: an expired challenge is spent by being refused, and leaving
        # the row would let a caller retry against it until TTL got round to it.
        return None if is_expired(record.expires_at) else record


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


def _passkey_from_item(item: Mapping[str, Any]) -> PasskeyRecord:
    raw_transports = item.get("transports")
    transports = (
        tuple(str(value) for value in raw_transports) if isinstance(raw_transports, list) else ()
    )
    return PasskeyRecord(
        user_id=str(item["user_id"]),
        credential_id=str(item["credential_id"]),
        public_key=str(item.get("public_key", "")),
        # `int()` rather than a subscript, because DynamoDB hands back a `Decimal` and a
        # `Decimal` compared against an `int` counter would work but would serialise into
        # JSON as `3.0`.
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
