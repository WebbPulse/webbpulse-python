"""The MFA service: TOTP enrolment and verification, recovery codes, and the ticket.

`totp` holds the arithmetic and `crypto` the envelope encryption; this module owns the
order of operations, the storage writes, and what a caller may learn from a failure.
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

if TYPE_CHECKING:  # pragma: no cover
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

AMR_PASSWORD: Final = "pwd"
AMR_OTP: Final = "otp"
AMR_MFA: Final = "mfa"

AMR_RECOVERY: Final = "recovery"

TOTP_FACTOR: Final = "totp"

RECOVERY_CODE_COUNT: Final = 10

RECOVERY_CODE_BYTES: Final = 12

_RECOVERY_GROUP: Final = 5


def normalise_recovery_code(code: str) -> str:
    """Upper-case a recovery code and strip its grouping hyphens and whitespace.

    Base32's alphabet has no lower case, so folding case introduces no ambiguity.
    """
    return "".join(code.split()).replace("-", "").upper()


def hash_recovery_code(code: str) -> str:
    """Hash a recovery code for storage: hex SHA-256 of its normalised text.

    Normalised first, so the same code typed with or without hyphens hashes alike.
    """
    return hashlib.sha256(normalise_recovery_code(code).encode("utf-8")).hexdigest()


def _generate_recovery_code() -> str:
    """Generate one recovery code, grouped with hyphens for reading off paper."""
    import base64

    raw = base64.b32encode(secrets.token_bytes(RECOVERY_CODE_BYTES)).decode("ascii").rstrip("=")
    return "-".join(raw[i : i + _RECOVERY_GROUP] for i in range(0, len(raw), _RECOVERY_GROUP))


class MfaRejected(Exception):
    """A factor was not satisfied: one type and one message for every reason.

    The uniform message is what keeps the second leg of login enumeration-resistant.
    """

    def __init__(
        self,
        message: str = "That code is not valid.",
        *,
        error_code: str = "INVALID_MFA_CODE",
        status_code: int = 401,
    ) -> None:
        """Record the caller-safe message and the envelope code a route should render."""
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class MfaChallenge:
    """What the first leg of login returns instead of tokens.

    `as_body` uses the wire names `@webbpulse/auth` already reads.
    """

    ticket: str
    factors: list[str]

    def as_body(self) -> dict[str, Any]:
        """Render the JSON body in the shape `AuthClient.runTokenCall` branches on."""
        return {"mfa_required": True, "mfa_ticket": self.ticket, "factors": list(self.factors)}


@dataclass(frozen=True, slots=True)
class Enrolment:
    """A pending TOTP enrolment: what the user needs to add the account to their app.

    The seed is returned in plaintext exactly once, here, and never again.
    """

    secret: str
    provisioning_uri: str


@dataclass(frozen=True, slots=True)
class RecoveryCodeSet:
    """A freshly generated set, in plaintext, returned exactly once."""

    codes: list[str] = field(default_factory=list)


class MfaService:
    """TOTP, recovery codes and the MFA ticket, over the stores and the token service.

    Keeps no per-user state, so one may be held per execution environment.
    """

    def __init__(
        self,
        settings: IdentitySettings,
        stores: IdentityStores,
        tokens: TokenService,
        *,
        kms_client: Any = None,
    ) -> None:
        """Bind the service to its settings, stores, token service and KMS client."""
        self._settings = settings
        self._stores = stores
        self._tokens = tokens
        self._kms = kms_client

    @property
    def cipher(self) -> EnvelopeCipher:
        """Build the envelope cipher for TOTP seeds, on demand.

        Not built in `__init__`, so a product without TOTP never needs `data_key_arn` set.
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

    def factors_for(self, user_id: str) -> list[str]:
        """Return the active factor names for a user, for the login challenge.

        Only activated factors count: challenging on an unconfirmed enrolment would leave the
        user no way through.
        """
        if not self._settings.totp_enabled:
            return []
        factor = self._stores.require_totp_factors().get(user_id)
        return [TOTP_FACTOR] if factor is not None and factor.is_active else []

    def requires_mfa(self, user: Mapping[str, Any]) -> bool:
        """Report whether this user has an active factor to satisfy.

        The role-driven requirement is the caller's decision, in `may_authenticate`.
        """
        user_id = str(user.get("id", ""))
        return bool(user_id) and bool(self.factors_for(user_id))

    def issue_challenge(self, user_id: str, *, factors: Sequence[str]) -> MfaChallenge:
        """Mint a ticket for a login that got past the password and record it for single use.

        The row is written before the ticket is returned, so a failed write leaves a ticket
        that cannot be spent rather than one that works more than once.
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

        The signature proves the issuer and the atomic consume proves it has not been spent;
        a ticket that verifies over a consumed row is a replay and is refused.
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
            _log.warning("mfa ticket replay refused for %s", claims.get("sub"))
            raise MfaRejected(
                "That sign-in attempt has expired. Start again.",
                error_code="MFA_TICKET_INVALID",
            )
        return str(claims["sub"])

    def begin_enrolment(self, user_id: str, *, account_name: str) -> Enrolment:
        """Generate and seal a seed, returning it in plaintext exactly once.

        The factor is written inactive until `confirm_enrolment` sees a correct code, and an
        existing active factor is refused rather than overwritten.
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

        Codes are issued at activation, not at enrolment, so a set never exists for a factor
        the user did not confirm.
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

        if not store.activate(user_id, step=step):
            raise MfaRejected(
                "There is no pending TOTP enrolment for this account.",
                error_code="NO_PENDING_ENROLMENT",
                status_code=409,
            )
        _log.info("totp.enrolled for %s", user_id)
        return self.regenerate_recovery_codes(user_id)

    def disable_totp(self, user_id: str) -> None:
        """Remove the factor and every recovery code, always both together.

        This verifies nothing on purpose: proof of possession is `IdentityFlows.disable_totp`,
        so calling this directly disables the factor with no proof at all.
        """
        self._stores.require_totp_factors().delete(user_id)
        self._stores.require_recovery_codes().delete_for_user(user_id)
        _log.info("totp.disabled for %s", user_id)

    def verify_challenge(self, user_id: str, code: str) -> str:
        """Satisfy a factor with a TOTP code or a recovery code, returning the `amr` value.

        The kind is chosen from the code's shape, not by the caller, and every failure raises
        the same `MfaRejected`.
        """
        presented = totp.normalise_code(code)
        if len(presented) == totp.CODE_DIGITS and presented.isdigit():
            self._verify_totp(user_id, presented)
            return AMR_OTP
        self._verify_recovery_code(user_id, code)
        return AMR_RECOVERY

    def _verify_totp(self, user_id: str, code: str) -> None:
        """Check a TOTP code and burn its step, refusing a replay."""
        store = self._stores.require_totp_factors()
        factor = store.get(user_id)
        if factor is None or not factor.is_active:
            raise MfaRejected()

        seed = self._open_seed(factor, user_id)
        step = totp.verify_code(seed, code, last_used_step=factor.last_used_step)
        if step is None:
            _log.info("mfa.failure totp for %s", user_id)
            raise MfaRejected()

        if not store.record_use(user_id, step=step):
            _log.warning("mfa.failure totp replay for %s", user_id)
            raise MfaRejected()
        _log.info("mfa.success totp for %s", user_id)

    def _verify_recovery_code(self, user_id: str, code: str) -> None:
        """Spend one unused recovery code, refusing anything else."""
        store = self._stores.require_recovery_codes()
        if not store.consume(user_id, hash_recovery_code(code)):
            _log.info("mfa.failure recovery for %s", user_id)
            raise MfaRejected()
        _log.info("recovery.used for %s", user_id)

    def _open_seed(self, factor: TotpFactorRecord, user_id: str) -> str:
        """Decrypt a sealed seed, turning a cipher failure into the ordinary refusal.

        The fault is logged as itself, but the caller must not learn a decrypt failed.
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

    def regenerate_recovery_codes(self, user_id: str) -> RecoveryCodeSet:
        """Replace every code with a fresh set, returned in plaintext exactly once.

        The old set is deleted first, so regenerating actually invalidates a lost printout.
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
        """Count the codes still unspent, for showing the user a total."""
        return sum(
            1
            for record in self._stores.require_recovery_codes().list_for_user(user_id)
            if not record.used_at
        )
