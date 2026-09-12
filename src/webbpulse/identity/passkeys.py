"""The passkey service: WebAuthn registration, assertion, and credential management.

Owns the challenge lifecycle and what a caller may learn from a failure; token minting and
policy stay in `flows.IdentityFlows`. Challenges are single-use rows, not tokens.

`SUPPORTED_COSE_ALGS` is the COSE algorithm set registration offers and accepts, as the
identifiers the WebAuthn registry assigns: EdDSA (-8), ES256 (-7), RS256 (-257). It is named
rather than inherited because py_webauthn narrowed its own default from nine algorithms to
these three in 3.0.0, and a silent change in what an authenticator may register should not
ride on the resolved minor. Login is unaffected either way, since an assertion is verified
with the algorithm of the stored public key and consults no list.
"""

from __future__ import annotations

import base64
import json
import logging
import secrets
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final

from webbpulse.dynamodb import now_iso, ttl_in
from webbpulse.identity.storage import (
    PasskeyRecord,
    WebAuthnChallengePurpose,
    WebAuthnChallengeRecord,
)

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Mapping, Sequence

    from webbpulse.identity.settings import IdentitySettings
    from webbpulse.identity.storage import IdentityStores

__all__ = [
    "AMR_PASSKEY",
    "AMR_PIN",
    "CHALLENGE_BYTES",
    "CHALLENGE_TTL_SECONDS",
    "MAX_PASSKEY_NAME",
    "PASSKEY_REJECTED_MESSAGE",
    "SUPPORTED_COSE_ALGS",
    "AssertionResult",
    "PasskeyRejected",
    "PasskeyService",
    "RegistrationChallenge",
    "b64url_decode",
    "b64url_encode",
]

_log = logging.getLogger(__name__)

AMR_PASSKEY: Final = "swk"
AMR_PIN: Final = "pin"

CHALLENGE_BYTES: Final = 32

CHALLENGE_TTL_SECONDS: Final = 300

MAX_PASSKEY_NAME: Final = 64

PASSKEY_REJECTED_MESSAGE: Final = "That passkey could not be verified."

SUPPORTED_COSE_ALGS: Final = (-8, -7, -257)


def b64url_encode(raw: bytes) -> str:
    """Base64url without padding, which is how WebAuthn spells bytes on the wire."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    """Decode base64url, re-adding the padding the encoder stripped.

    Raises `ValueError` on anything that is not base64url.
    """
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"not valid base64url: {value[:12]}") from exc


class PasskeyRejected(Exception):
    """A passkey ceremony failed: one type and one message for every reason.

    Carries an `error_code` and a `status_code` so management routes can answer 404 and 409,
    while every login and verify refusal stays a 401 with `PASSKEY_REJECTED_MESSAGE`.
    """

    def __init__(
        self,
        message: str = PASSKEY_REJECTED_MESSAGE,
        *,
        error_code: str = "PASSKEY_REJECTED",
        status_code: int = 401,
    ) -> None:
        """Record the refusal message, its error code and the status to answer with."""
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class RegistrationChallenge:
    """The options object the browser passes to `navigator.credentials`, and its id.

    `options` is WebAuthn JSON exactly as py_webauthn renders it. `challenge_id` is only a
    lookup key for spending the challenge, not the challenge itself.
    """

    challenge_id: str
    options: dict[str, Any]


@dataclass(frozen=True, slots=True)
class AssertionResult:
    """A verified passkey assertion: who it was, and what it proved.

    `amr` is computed here because user verification is known only at this point.
    """

    user_id: str
    credential_id: str
    user_verified: bool
    amr: list[str] = field(default_factory=list)


class PasskeyService:
    """WebAuthn ceremonies over the passkey and challenge stores.

    Keeps no per-user state. Imports `webauthn` lazily inside methods so a product with
    passkeys disabled never has to install the extra.
    """

    def __init__(self, settings: IdentitySettings, stores: IdentityStores) -> None:
        """Hold the identity settings and stores the ceremonies read and write."""
        self._settings = settings
        self._stores = stores

    @property
    def rp_id(self) -> str:
        """The Relying Party ID every ceremony is bound to.

        Raises `ValueError` when unset, since only a product mounting passkey routes needs
        one and a settings-level requirement would burden every other deployment.
        """
        if not self._settings.rp_id:
            raise ValueError(
                "IDENTITY_RP_ID is not set, and a WebAuthn ceremony cannot be bound without "
                "it. Set it to the registrable domain, which is what the credential is "
                "hashed against and is immutable for that credential's life."
            )
        return self._settings.rp_id

    @property
    def origins(self) -> list[str]:
        """The origins an assertion may have come from.

        Required and never defaulted: an empty list would make the origin check vacuous, and
        that check is what makes a passkey phishing resistant.
        """
        origins = [origin.strip() for origin in self._settings.webauthn_origins if origin.strip()]
        if not origins:
            raise ValueError(
                "IDENTITY_WEBAUTHN_ORIGINS is empty, and the origin check is what makes a "
                "passkey phishing resistant. Set it to the exact origins the frontend is "
                "served from, scheme and port included, for example "
                '["https://carmodpicker.com"].'
            )
        return origins

    def begin_registration(
        self,
        user_id: str,
        *,
        user_name: str,
        display_name: str = "",
    ) -> RegistrationChallenge:
        """Mint a registration challenge for an authenticated user.

        `exclude_credentials` lists the account's existing passkeys so an authenticator
        declines a duplicate. The row is written before the options are returned.
        """
        from webauthn import generate_registration_options, options_to_json
        from webauthn.helpers.cose import COSEAlgorithmIdentifier
        from webauthn.helpers.structs import (
            AuthenticatorSelectionCriteria,
            PublicKeyCredentialDescriptor,
            ResidentKeyRequirement,
            UserVerificationRequirement,
        )

        challenge = secrets.token_bytes(CHALLENGE_BYTES)
        existing = self._stores.require_passkeys().list_for_user(user_id)
        exclude = [
            PublicKeyCredentialDescriptor(id=b64url_decode(record.credential_id))
            for record in existing
        ]

        options = generate_registration_options(
            rp_id=self.rp_id,
            rp_name=self._settings.rp_name or self._settings.product_name or self.rp_id,
            user_id=user_id.encode("utf-8"),
            user_name=user_name,
            user_display_name=display_name or user_name,
            challenge=challenge,
            exclude_credentials=exclude,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
            supported_pub_key_algs=[COSEAlgorithmIdentifier(alg) for alg in SUPPORTED_COSE_ALGS],
        )

        record = self._new_challenge("register", challenge, user_id=user_id)
        self._stores.require_webauthn_challenges().put(record)
        return RegistrationChallenge(
            challenge_id=record.challenge_id,
            options=dict(json.loads(options_to_json(options))),
        )

    def finish_registration(
        self,
        user_id: str,
        *,
        challenge_id: str,
        credential: Mapping[str, Any],
        name: str = "",
    ) -> PasskeyRecord:
        """Verify an attestation and store the new credential.

        The challenge is spent before the attestation is checked, and its recorded `user_id`
        must match the caller so a challenge cannot be answered against another account.
        """
        from webauthn import verify_registration_response
        from webauthn.helpers.cose import COSEAlgorithmIdentifier
        from webauthn.helpers.exceptions import WebAuthnException

        record = self._spend_challenge(challenge_id, expected_purpose="register")
        if record.user_id != user_id:
            _log.warning(
                "passkey.register challenge belonged to another subject",
                extra={"event": "passkey.register.mismatch", "user_id": user_id},
            )
            raise PasskeyRejected()

        try:
            verified = verify_registration_response(
                credential=dict(credential),
                expected_challenge=b64url_decode(record.challenge),
                expected_rp_id=self.rp_id,
                expected_origin=self.origins,
                supported_pub_key_algs=[
                    COSEAlgorithmIdentifier(alg) for alg in SUPPORTED_COSE_ALGS
                ],
            )
        except (WebAuthnException, ValueError, KeyError) as exc:
            _log.info(
                "passkey.register verification failed",
                extra={"event": "passkey.register.failure", "user_id": user_id},
            )
            raise PasskeyRejected() from exc

        credential_id = b64url_encode(verified.credential_id)
        store = self._stores.require_passkeys()
        owner = store.find_by_credential_id(credential_id)
        if owner is not None:
            raise PasskeyRejected(
                "That passkey is already registered.",
                error_code="PASSKEY_ALREADY_REGISTERED",
                status_code=409,
            )

        stored = PasskeyRecord(
            user_id=user_id,
            credential_id=credential_id,
            public_key=b64url_encode(verified.credential_public_key),
            sign_count=verified.sign_count,
            name=_clean_name(name) or "Passkey",
            created_at=now_iso(),
            transports=_transports_from(credential),
            aaguid=str(verified.aaguid or ""),
            backup_eligible=bool(verified.credential_backed_up),
            backup_state=bool(verified.credential_backed_up),
            user_verified=bool(verified.user_verified),
        )
        try:
            store.put(stored)
        except KeyError as exc:
            raise PasskeyRejected(
                "That passkey is already registered.",
                error_code="PASSKEY_ALREADY_REGISTERED",
                status_code=409,
            ) from exc

        _log.info(
            "passkey.registered",
            extra={"event": "passkey.registered", "user_id": user_id},
        )
        return stored

    def begin_login(self, *, user_id: str = "") -> RegistrationChallenge:
        """Mint a login challenge, optionally scoped to one user's credentials.

        The caller resolves the user and passes an empty string when there is none, so an
        unknown address produces the same shape as a genuine discoverable request.
        """
        from webauthn import generate_authentication_options, options_to_json
        from webauthn.helpers.structs import (
            PublicKeyCredentialDescriptor,
            UserVerificationRequirement,
        )

        challenge = secrets.token_bytes(CHALLENGE_BYTES)
        allow: list[PublicKeyCredentialDescriptor] = []
        if user_id:
            allow = [
                PublicKeyCredentialDescriptor(id=b64url_decode(record.credential_id))
                for record in self._stores.require_passkeys().list_for_user(user_id)
            ]

        options = generate_authentication_options(
            rp_id=self.rp_id,
            challenge=challenge,
            allow_credentials=allow or None,
            user_verification=UserVerificationRequirement.PREFERRED,
        )

        record = self._new_challenge("login", challenge)
        self._stores.require_webauthn_challenges().put(record)
        return RegistrationChallenge(
            challenge_id=record.challenge_id,
            options=dict(json.loads(options_to_json(options))),
        )

    def finish_login(
        self,
        *,
        challenge_id: str,
        credential: Mapping[str, Any],
    ) -> AssertionResult:
        """Verify an assertion and report who signed in, and with what.

        Mints nothing; `flows.IdentityFlows.login_with_passkey` turns this into a session.
        Spends the challenge first, and every failure is the same refusal.
        """
        from webauthn import verify_authentication_response
        from webauthn.helpers.exceptions import WebAuthnException

        record = self._spend_challenge(challenge_id, expected_purpose="login")

        raw_id = credential.get("id") if isinstance(credential, dict) else None
        if not isinstance(raw_id, str) or not raw_id:
            raise PasskeyRejected()
        try:
            credential_id = b64url_encode(b64url_decode(raw_id))
        except ValueError as exc:
            raise PasskeyRejected() from exc

        stored = self._stores.require_passkeys().find_by_credential_id(credential_id)
        if stored is None:
            _log.info(
                "passkey.login unknown credential",
                extra={"event": "passkey.login.unknown"},
            )
            raise PasskeyRejected()

        try:
            verified = verify_authentication_response(
                credential=dict(credential),
                expected_challenge=b64url_decode(record.challenge),
                expected_rp_id=self.rp_id,
                expected_origin=self.origins,
                credential_public_key=b64url_decode(stored.public_key),
                credential_current_sign_count=0,
            )
        except (WebAuthnException, ValueError, KeyError) as exc:
            _log.info(
                "passkey.login verification failed",
                extra={"event": "passkey.login.failure", "user_id": stored.user_id},
            )
            raise PasskeyRejected() from exc

        self._check_sign_count(stored, verified.new_sign_count)

        self._stores.require_passkeys().record_use(
            stored.user_id,
            stored.credential_id,
            sign_count=verified.new_sign_count,
            used_at=now_iso(),
        )
        amr = amr_for(bool(verified.user_verified))
        _log.info(
            "passkey.login succeeded",
            extra={
                "event": "passkey.login.success",
                "user_id": stored.user_id,
                "user_verified": bool(verified.user_verified),
            },
        )
        return AssertionResult(
            user_id=stored.user_id,
            credential_id=stored.credential_id,
            user_verified=bool(verified.user_verified),
            amr=amr,
        )

    def _check_sign_count(self, stored: PasskeyRecord, presented: int) -> None:
        """Refuse a signature counter that did not advance, logging it as a clone signal.

        Both counters at zero is the specification's documented exception for authenticators
        that keep no counter, and is not a regression.
        """
        if stored.sign_count == 0 and presented == 0:
            return
        if presented > stored.sign_count:
            return
        _log.error(
            "passkey.counter_regression",
            extra={
                "event": "passkey.counter_regression",
                "user_id": stored.user_id,
                "stored_sign_count": stored.sign_count,
                "presented_sign_count": presented,
            },
        )
        raise PasskeyRejected()

    def list_passkeys(self, user_id: str) -> list[PasskeyRecord]:
        """Every passkey a user has, in whatever order the store returns them."""
        return self._stores.require_passkeys().list_for_user(user_id)

    def rename_passkey(self, user_id: str, credential_id: str, *, name: str) -> PasskeyRecord:
        """Relabel one of the caller's own passkeys.

        Scoped to `user_id` and behind the authorizer, so it answers an honest 404.
        """
        cleaned = _clean_name(name)
        if not cleaned:
            raise PasskeyRejected(
                "A passkey needs a name.",
                error_code="PASSKEY_NAME_REQUIRED",
                status_code=422,
            )
        store = self._stores.require_passkeys()
        if not store.rename(user_id, credential_id, name=cleaned):
            raise PasskeyRejected(
                "No such passkey.", error_code="PASSKEY_NOT_FOUND", status_code=404
            )
        updated = store.get(user_id, credential_id)
        if updated is None:  # pragma: no cover
            raise PasskeyRejected(
                "No such passkey.", error_code="PASSKEY_NOT_FOUND", status_code=404
            )
        return updated

    def delete_passkey(self, user_id: str, credential_id: str, *, has_password: bool) -> None:
        """Remove one passkey, refusing to strand the user outside their own account.

        The refusal applies only to the last passkey when `has_password` is false, which the
        caller decides so this service needs no credential store.
        """
        store = self._stores.require_passkeys()
        existing = store.list_for_user(user_id)
        if not any(record.credential_id == credential_id for record in existing):
            raise PasskeyRejected(
                "No such passkey.", error_code="PASSKEY_NOT_FOUND", status_code=404
            )
        if len(existing) == 1 and not has_password:
            raise PasskeyRejected(
                "This is your only way to sign in. Set a password before removing it.",
                error_code="LAST_CREDENTIAL",
                status_code=409,
            )
        store.delete(user_id, credential_id)
        _log.info(
            "passkey.deleted",
            extra={"event": "passkey.deleted", "user_id": user_id},
        )

    def _new_challenge(
        self,
        purpose: WebAuthnChallengePurpose,
        challenge: bytes,
        *,
        user_id: str = "",
    ) -> WebAuthnChallengeRecord:
        """Build an unsaved challenge row with a fresh id and the standard TTL."""
        return WebAuthnChallengeRecord(
            challenge_id=secrets.token_urlsafe(CHALLENGE_BYTES),
            challenge=b64url_encode(challenge),
            purpose=purpose,
            user_id=user_id,
            created_at=now_iso(),
            expires_at=ttl_in(CHALLENGE_TTL_SECONDS),
        )

    def _spend_challenge(
        self, challenge_id: str, *, expected_purpose: WebAuthnChallengePurpose
    ) -> WebAuthnChallengeRecord:
        """Consume a challenge, refusing an unknown, expired, spent or mismatched one.

        The purpose check is what keeps the registration and login ceremonies apart.
        """
        if not challenge_id:
            raise PasskeyRejected()
        record = self._stores.require_webauthn_challenges().consume(challenge_id)
        if record is None or record.purpose != expected_purpose:
            _log.info(
                "passkey challenge refused",
                extra={"event": "passkey.challenge.refused", "purpose": expected_purpose},
            )
            raise PasskeyRejected(
                "That passkey attempt has expired. Start again.",
                error_code="PASSKEY_CHALLENGE_INVALID",
            )
        return record


def amr_for(user_verified: bool) -> list[str]:
    """The `amr` a passkey assertion earns, given whether the authenticator verified the user.

    Module level so `flows` can ask the same question when deciding on a second factor.
    """
    return [AMR_PASSKEY, AMR_PIN] if user_verified else [AMR_PASSKEY]


def _clean_name(name: str) -> str:
    """Trim a user-supplied label and cap its length. Empty stays empty."""
    return " ".join(name.split())[:MAX_PASSKEY_NAME]


def _transports_from(credential: Mapping[str, Any]) -> tuple[str, ...]:
    """The transports the browser reported, if it reported any.

    The field is optional, so a browser that omits it yields an empty tuple.
    """
    response = credential.get("response")
    if not isinstance(response, dict):
        return ()
    transports = response.get("transports")
    if not isinstance(transports, list):
        return ()
    return tuple(str(value) for value in transports if str(value))


def passkey_summary(record: PasskeyRecord) -> dict[str, Any]:
    """One passkey as the management routes render it, deliberately without the public key."""
    return {
        "credential_id": record.credential_id,
        "name": record.name,
        "created_at": record.created_at,
        "last_used_at": record.last_used_at,
        "transports": list(record.transports),
        "aaguid": record.aaguid,
        "backup_eligible": record.backup_eligible,
        "backup_state": record.backup_state,
        "user_verified": record.user_verified,
    }


def passkey_summaries(records: Sequence[PasskeyRecord]) -> list[dict[str, Any]]:
    """`passkey_summary` over a list, for the list route."""
    return [passkey_summary(record) for record in records]
