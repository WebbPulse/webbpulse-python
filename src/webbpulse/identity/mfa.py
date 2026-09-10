"""The MFA service: TOTP enrolment and verification, recovery codes, and the ticket.

`totp.py` holds the arithmetic and `crypto.py` holds the envelope encryption. This module is
what a route calls: it owns the order of operations, the storage writes, and the decisions
about what a caller is allowed to learn from a failure.

## Two secrets, two opposite storage choices

A **TOTP seed** is sealed, not hashed. Verification recomputes the code from the seed, so the
plaintext has to come back, and a hash cannot give it back. `EnvelopeCipher` is what makes
that acceptable: the row holds ciphertext, and turning it into a seed needs a live
`kms:Decrypt` under an encryption context bound to the user, so a database dump is not a set
of working authenticators.

A **recovery code** is hashed, like a password, because it is only ever compared. It is
hashed with SHA-256 rather than bcrypt for the reason `storage.hash_token` gives: bcrypt's
cost exists to protect a low-entropy secret, and these carry 100 bits from a CSPRNG.

The two choices look inconsistent and are the same rule applied twice: store the weakest
thing that still supports the operation.

## What a caller is allowed to learn

Section 2.6 requires the second leg of login to be enumeration-resistant in the same way the
first is. So `verify_challenge` answers with one failure for every reason: wrong code,
replayed code, unknown user, no factor enrolled, factor enrolled but not activated, spent
recovery code, and a recovery code that never existed. A caller cannot use the second leg to
discover whether an account has TOTP enabled, which would otherwise be a way to find the
accounts worth attacking.

The one exception is the rate limit, which answers 429, and that is deliberate: it is a
signal about the caller, not about the account.

## Single use, and why the ticket is not stored

The ticket is a signed JWT and is never written down. What is written is a row in
`identity-tokens` keyed on the hash of its `jti`, and spending it is the same atomic
`consume` a password reset link uses. The row is created when the ticket is minted, so a
ticket that was never issued by this service has no row and cannot be spent even if an
attacker could forge one, and consuming is a conditional write so two requests racing the
same ticket produce exactly one success.

This is the reason `TokenService.mint_mfa_ticket` takes a `jti` rather than generating one:
the value has to be recorded, and generating it inside the signer would mean decoding the
token to find out what to record.

## Step-up is not a second flavour of login

This module verifies the factor; `flows.IdentityFlows.step_up` is what mints the token,
because minting is `_mint_access`'s job and there is one of those. Step-up issues a **new
access token** for a session that already exists, with `auth_time` reset to now and the
satisfied factor added to `amr`. It does not start a refresh family and does not touch the
cookie, because the session is not new: the user is proving freshness within it. Section
2.6's sensitive routes then assert on `amr` and on `auth_time`, never on a boolean, which is
what makes "was this re-authenticated recently" answerable at all.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final

from webbpulse.dynamodb import now_iso, ttl_in
from webbpulse.identity import totp
from webbpulse.identity.crypto import EnvelopeCipher, EnvelopeDecryptionFailed, SealedSecret
from webbpulse.identity.storage import (
    IdentityTokenRecord,
    RecoveryCodeRecord,
    TotpFactorRecord,
    hash_token,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Mapping, Sequence

    from webbpulse.identity.service import TokenService
    from webbpulse.identity.settings import IdentitySettings
    from webbpulse.identity.storage import IdentityStores

__all__ = [
    "AMR_MFA",
    "AMR_OTP",
    "AMR_PASSWORD",
    "AMR_RECOVERY",
    "RECOVERY_CODE_COUNT",
    "TOTP_FACTOR",
    "Enrolment",
    "MfaChallenge",
    "MfaRejected",
    "MfaService",
    "RecoveryCodeSet",
    "hash_recovery_code",
    "normalise_recovery_code",
]

_log = logging.getLogger(__name__)

#: RFC 8176 authentication method references. Section 3.2 fixes these values, and they are
#: the vocabulary sensitive routes assert on.
AMR_PASSWORD: Final = "pwd"
AMR_OTP: Final = "otp"
AMR_MFA: Final = "mfa"

#: Not an RFC 8176 value. RFC 8176 has no registered value for a recovery code, and
#: inventing one is better than reusing `otp`, which would make a recovery code
#: indistinguishable from a live authenticator in the audit trail and in any policy that
#: asserts on `amr`. A route that requires a real second factor can then refuse this.
AMR_RECOVERY: Final = "recovery"

#: The factor name in the login challenge and on the enrol routes.
TOTP_FACTOR: Final = "totp"

#: Codes issued per set. Ten is the common choice and is enough that a user who loses their
#: phone has spares without the list being long enough that nobody stores it.
RECOVERY_CODE_COUNT: Final = 10

#: Bytes per recovery code before encoding. 12 bytes is 96 bits, well beyond guessing, and
#: base32-encodes to a 20 character string that groups tidily into four blocks of five.
RECOVERY_CODE_BYTES: Final = 12

#: Characters per group in a displayed recovery code, for legibility only.
_RECOVERY_GROUP: Final = 5


def normalise_recovery_code(code: str) -> str:
    """Upper-case, strip the grouping separators, and drop whitespace.

    A user reads these off paper, so the hyphens that make them readable are stripped, and
    lower case is accepted. Base32's alphabet has no lower case and no digits 0, 1 or 8, so
    there is no ambiguity introduced by folding case.
    """
    return "".join(code.split()).replace("-", "").upper()


def hash_recovery_code(code: str) -> str:
    """The stored form of a recovery code: hex SHA-256 of its normalised text.

    Normalised first, so that the same code typed with or without hyphens hashes alike. A
    code compared against the stored hash without this step fails for a user who typed it
    exactly as it was printed.
    """
    return hashlib.sha256(normalise_recovery_code(code).encode("utf-8")).hexdigest()


def _generate_recovery_code() -> str:
    """One code, grouped with hyphens for reading off paper."""
    import base64

    raw = base64.b32encode(secrets.token_bytes(RECOVERY_CODE_BYTES)).decode("ascii").rstrip("=")
    return "-".join(raw[i : i + _RECOVERY_GROUP] for i in range(0, len(raw), _RECOVERY_GROUP))


class MfaRejected(Exception):
    """A factor was not satisfied. One type, one message, for every reason.

    Carries an `error_code` so a route can map it to the envelope, but the message is fixed:
    see the module docstring on what a caller is allowed to learn.
    """

    def __init__(
        self,
        message: str = "That code is not valid.",
        *,
        error_code: str = "INVALID_MFA_CODE",
        status_code: int = 401,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class MfaChallenge:
    """What the first leg of login returns instead of tokens.

    The field names are the wire names `@webbpulse/auth` reads, so that the frontend needs no
    change: `mfa_required`, `mfa_ticket` and `factors` in the JSON body.
    """

    ticket: str
    factors: list[str]

    def as_body(self) -> dict[str, Any]:
        """The JSON body, in the shape `AuthClient.runTokenCall` branches on."""
        return {"mfa_required": True, "mfa_ticket": self.ticket, "factors": list(self.factors)}


@dataclass(frozen=True, slots=True)
class Enrolment:
    """A pending TOTP enrolment: what the user needs to add the account to their app.

    The seed is returned in plaintext exactly once, here, because the user has to be able to
    type it in when a QR code cannot be scanned. It is never returned again: a second call to
    `begin_enrolment` issues a new seed rather than redisplaying the old one.
    """

    secret: str
    provisioning_uri: str


@dataclass(frozen=True, slots=True)
class RecoveryCodeSet:
    """A freshly generated set, in plaintext, returned exactly once."""

    codes: list[str] = field(default_factory=list)


class MfaService:
    """TOTP, recovery codes and the MFA ticket, over the stores and the token service.

    Construct one per request or hold one per execution environment; it keeps no per-user
    state. The `EnvelopeCipher` it builds is cheap and holds only a key id and a client.
    """

    def __init__(
        self,
        settings: IdentitySettings,
        stores: IdentityStores,
        tokens: TokenService,
        *,
        kms_client: Any = None,
    ) -> None:
        self._settings = settings
        self._stores = stores
        self._tokens = tokens
        self._kms = kms_client

    # ---- the cipher --------------------------------------------------------------

    @property
    def cipher(self) -> EnvelopeCipher:
        """The envelope cipher for TOTP seeds.

        Built on demand rather than in `__init__` so that a product with `totp_enabled`
        false, or one mounting only the discovery routes, never needs `data_key_arn` set.
        The error when it is missing names the setting, because the alternative is a
        `ValueError` from deep inside the cipher on the first enrolment in production.
        """
        if not self._settings.data_key_arn:
            raise ValueError(
                "IDENTITY_DATA_KEY_ARN is not set, and a TOTP seed cannot be sealed without "
                "it. Set it to a symmetric KMS key, distinct from the signing key."
            )
        if self._kms is None:
            raise ValueError(
                "MfaService needs a KMS client to seal a TOTP seed. Pass kms_client to "
                "build_identity_router."
            )
        return EnvelopeCipher(self._settings.data_key_arn, self._kms)

    # ---- factor state ------------------------------------------------------------

    def factors_for(self, user_id: str) -> list[str]:
        """The active factor names for a user, for the login challenge.

        Only **activated** factors count. An enrolment the user never confirmed is not a
        factor: including it would challenge a user with an authenticator that does not hold
        the seed, and there would be no way through.
        """
        if not self._settings.totp_enabled:
            return []
        factor = self._stores.require_totp_factors().get(user_id)
        return [TOTP_FACTOR] if factor is not None and factor.is_active else []

    def requires_mfa(self, user: Mapping[str, Any]) -> bool:
        """Whether this user must satisfy a factor, from enrolment or from their role.

        A user with an active factor is always challenged. A user whose role appears in
        `mfa_required_for_roles` is challenged too, but that case is settled by the caller:
        this service can only report that they have no factor to satisfy, and refusing the
        login outright is a product decision that belongs in `may_authenticate`.
        """
        user_id = str(user.get("id", ""))
        return bool(user_id) and bool(self.factors_for(user_id))

    # ---- the ticket --------------------------------------------------------------

    def issue_challenge(self, user_id: str, *, factors: Sequence[str]) -> MfaChallenge:
        """Mint a ticket for a login that got past the password and record it for single use.

        The row is written **before** the ticket is returned. If the write fails the caller
        gets an exception and no ticket, which is the safe direction: a ticket with no row
        cannot be spent, so the failure is a login the user retries rather than a ticket that
        works more than once.
        """
        jti = secrets.token_urlsafe(24)
        ticket = self._tokens.mint_mfa_ticket(user_id, factors=[AMR_PASSWORD], jti=jti)
        ttl_seconds = int(self._settings.mfa_ticket_ttl.total_seconds())
        self._stores.require_identity_tokens().put(
            IdentityTokenRecord(
                token_hash=hash_token(jti),
                purpose="mfa_ticket",
                user_id=user_id,
                created_at=now_iso(),
                expires_at=ttl_in(ttl_seconds),
            )
        )
        _log.info("mfa.challenge issued for %s", user_id)
        return MfaChallenge(ticket=ticket, factors=list(factors))

    def consume_ticket(self, ticket: str) -> str:
        """Verify a ticket, spend it, and return the user id it was issued for.

        Both halves are required and neither is sufficient. The signature check proves the
        ticket came from this issuer with the right `typ` and audience; the `consume` proves
        it has not been spent. A ticket that verifies but whose row is already consumed is a
        replay and is refused here.
        """
        from webbpulse.identity.service import InvalidToken

        try:
            claims = self._tokens.verify_mfa_ticket(ticket)
        except InvalidToken as exc:
            _log.info("mfa ticket rejected: %s", exc.reason)
            raise MfaRejected(
                "That sign-in attempt has expired. Start again.",
                error_code="MFA_TICKET_INVALID",
            ) from exc

        record = self._stores.require_identity_tokens().consume(hash_token(str(claims["jti"])))
        if record is None or record.purpose != "mfa_ticket":
            # Already spent, never issued, or a row of another purpose whose hash collided
            # with this jti, which cannot happen but is refused rather than assumed away.
            _log.warning("mfa ticket replay refused for %s", claims.get("sub"))
            raise MfaRejected(
                "That sign-in attempt has expired. Start again.",
                error_code="MFA_TICKET_INVALID",
            )
        return str(claims["sub"])

    # ---- TOTP enrolment ----------------------------------------------------------

    def begin_enrolment(self, user_id: str, *, account_name: str) -> Enrolment:
        """Generate and seal a seed, returning it in plaintext exactly once.

        The factor is written **inactive**. It does not gate login and does not appear in
        `factors_for` until `confirm_enrolment` sees a correct code, so a user who scans
        badly and walks away has changed nothing about their account.

        An existing **active** factor is refused rather than overwritten. Silently replacing
        a working authenticator with an unconfirmed one is how a user ends up with a factor
        they cannot satisfy, and the route for replacing one is to disable and re-enrol.
        """
        store = self._stores.require_totp_factors()
        existing = store.get(user_id)
        if existing is not None and existing.is_active:
            raise MfaRejected(
                "TOTP is already enabled for this account.",
                error_code="TOTP_ALREADY_ENABLED",
                status_code=409,
            )

        seed = totp.generate_seed()
        sealed = self.cipher.seal(seed.encode("ascii"), user_id=user_id)
        store.put(
            TotpFactorRecord(
                user_id=user_id,
                secret_ciphertext=sealed.ciphertext,
                secret_nonce=sealed.nonce,
                wrapped_data_key=sealed.wrapped_key,
                created_at=now_iso(),
            )
        )
        return Enrolment(
            secret=seed,
            provisioning_uri=totp.provisioning_uri(
                seed,
                account_name=account_name,
                issuer=self._settings.product_name or "WebbPulse",
            ),
        )

    def confirm_enrolment(self, user_id: str, code: str) -> RecoveryCodeSet:
        """Activate a pending factor with its first correct code, and issue recovery codes.

        Recovery codes are generated here rather than at enrolment because a set the user
        never activated is a set of live credentials for a factor that does not exist. Tying
        them to activation means the codes and the factor appear together.
        """
        store = self._stores.require_totp_factors()
        factor = store.get(user_id)
        if factor is None or factor.is_active:
            raise MfaRejected(
                "There is no pending TOTP enrolment for this account.",
                error_code="NO_PENDING_ENROLMENT",
                status_code=409,
            )

        seed = self._open_seed(factor, user_id)
        step = totp.verify_code(seed, code, last_used_step=factor.last_used_step)
        if step is None:
            raise MfaRejected()

        # Activation records the confirming step, so the code just used cannot be replayed
        # as a login code seconds later.
        if not store.activate(user_id, step=step):
            raise MfaRejected(
                "There is no pending TOTP enrolment for this account.",
                error_code="NO_PENDING_ENROLMENT",
                status_code=409,
            )
        _log.info("totp.enrolled for %s", user_id)
        return self.regenerate_recovery_codes(user_id)

    def disable_totp(self, user_id: str) -> None:
        """Remove the factor and every recovery code.

        Both, always. Leaving recovery codes behind after TOTP is disabled leaves a set of
        credentials that satisfy a factor the user believes is gone.

        **This verifies nothing, on purpose.** It is the mechanism; the policy of who may
        call it is `IdentityFlows.disable_totp`, which requires a current TOTP code or an
        unused recovery code first. Calling this directly disables the factor with no proof
        of possession at all, which is what the route did before 0.13.0 and what that
        release fixed. The same split applies to `regenerate_recovery_codes`.
        """
        self._stores.require_totp_factors().delete(user_id)
        self._stores.require_recovery_codes().delete_for_user(user_id)
        _log.info("totp.disabled for %s", user_id)

    # ---- verification ------------------------------------------------------------

    def verify_challenge(self, user_id: str, code: str) -> str:
        """Satisfy a factor with a TOTP code or a recovery code. Returns the `amr` value.

        A six digit numeric code is tried as TOTP, anything else as a recovery code. That is
        a shape test rather than a decision the caller makes, so one route accepts both and
        the caller cannot be made to reveal which kind it was by varying the response.

        Every failure raises the same `MfaRejected`.
        """
        presented = totp.normalise_code(code)
        if len(presented) == totp.CODE_DIGITS and presented.isdigit():
            self._verify_totp(user_id, presented)
            return AMR_OTP
        self._verify_recovery_code(user_id, code)
        return AMR_RECOVERY

    def _verify_totp(self, user_id: str, code: str) -> None:
        store = self._stores.require_totp_factors()
        factor = store.get(user_id)
        if factor is None or not factor.is_active:
            raise MfaRejected()

        seed = self._open_seed(factor, user_id)
        step = totp.verify_code(seed, code, last_used_step=factor.last_used_step)
        if step is None:
            _log.info("mfa.failure totp for %s", user_id)
            raise MfaRejected()

        # The watermark write is conditional, so a code presented twice concurrently is
        # accepted exactly once: whichever request loses the condition is a replay.
        if not store.record_use(user_id, step=step):
            _log.warning("mfa.failure totp replay for %s", user_id)
            raise MfaRejected()
        _log.info("mfa.success totp for %s", user_id)

    def _verify_recovery_code(self, user_id: str, code: str) -> None:
        store = self._stores.require_recovery_codes()
        if not store.consume(user_id, hash_recovery_code(code)):
            _log.info("mfa.failure recovery for %s", user_id)
            raise MfaRejected()
        _log.info("recovery.used for %s", user_id)

    def _open_seed(self, factor: TotpFactorRecord, user_id: str) -> str:
        """Decrypt a sealed seed, turning a cipher failure into a refusal.

        A decryption failure here is not a wrong code and is logged as the fault it is, but
        the caller still sees the ordinary refusal: a user cannot act on "the key policy
        changed" and an attacker should not learn that it did.
        """
        sealed = SealedSecret(
            ciphertext=factor.secret_ciphertext,
            nonce=factor.secret_nonce,
            wrapped_key=factor.wrapped_data_key,
        )
        try:
            return self.cipher.open(sealed, user_id=user_id).decode("ascii")
        except (EnvelopeDecryptionFailed, ValueError) as exc:
            _log.error("totp seed could not be decrypted for %s: %s", user_id, exc)
            raise MfaRejected() from exc

    # ---- recovery codes ----------------------------------------------------------

    def regenerate_recovery_codes(self, user_id: str) -> RecoveryCodeSet:
        """Replace every code with a fresh set, returned in plaintext exactly once.

        The old set is deleted first. Generating a new set while the old one still works
        would mean a user who regenerates because a printout was lost has not invalidated
        the printout, which is the entire reason they regenerated.
        """
        store = self._stores.require_recovery_codes()
        store.delete_for_user(user_id)
        codes = [_generate_recovery_code() for _ in range(RECOVERY_CODE_COUNT)]
        created = now_iso()
        store.put_many(
            RecoveryCodeRecord(
                user_id=user_id, code_hash=hash_recovery_code(code), created_at=created
            )
            for code in codes
        )
        _log.info("recovery.regenerated for %s", user_id)
        return RecoveryCodeSet(codes=codes)

    def remaining_recovery_codes(self, user_id: str) -> int:
        """How many codes are still unspent, for showing the user a count."""
        return sum(
            1
            for record in self._stores.require_recovery_codes().list_for_user(user_id)
            if not record.used_at
        )
