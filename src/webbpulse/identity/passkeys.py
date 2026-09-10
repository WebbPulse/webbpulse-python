"""The passkey service: WebAuthn registration, assertion, and credential management.

`storage.PasskeyStore` and `storage.WebAuthnChallengeStore` hold the rows; the `webauthn`
package (py_webauthn) does the cryptography. This module is what a route calls: it owns the
order of operations, the challenge lifecycle, and the decisions about what a caller is
allowed to learn from a failure.

It stands to M5 exactly as `mfa.py` stands to M4, and it deliberately mirrors that module's
shape: one service class, one refusal exception with a fixed message, and the flow-level
decisions (minting tokens, honouring `may_authenticate`) left to `flows.IdentityFlows`.

## The challenge is a row, not a token, and that is the point of M5

A WebAuthn challenge exists to make an assertion unreplayable. That is a claim about
**state**: the server has to be able to say "this challenge has already been answered". A
signed token cannot say it. It verifies exactly as well the second time as the first, so a
captured options-plus-assertion pair replays for the whole of the token's lifetime, and
lengthening or shortening that lifetime only moves the window.

CarModPicker's current implementation puts the challenge in a five minute JWT, and porting
it unchanged would have carried that hole into the shared package. So the challenges move
into `webauthn-challenges`: written when options are generated, deleted when consumed, and
refused when the deadline has passed regardless of whether DynamoDB's TTL has got round to
the row. The five minutes is unchanged, because it is a good number: long enough for a user
to find their security key, short enough that the outstanding set stays small.

## What a caller is allowed to learn

Section 5.4's enumeration rule reaches the passkey login leg too, and there it bites harder
than on the password leg, because `login/passkey/options` is called with no credential at
all for a discoverable flow. So:

- **Options are issued for any input, including an unknown email.** A request naming an
  address with no account gets a challenge and an empty `allowCredentials`, which is exactly
  what a discoverable-credential request looks like. Refusing, or answering with a different
  shape, would turn the options route into an account oracle that needs no password.
- **Every verify failure is one refusal.** Unknown credential, wrong signature, a deleted
  user, a counter regression, a product hook saying no: all `PasskeyRejected` with the same
  message. The exception is a counter regression, which is *logged* as the serious thing it
  is while still answering the ordinary refusal.

The management routes are different and answer honestly, because they are behind the
authorizer and act on the caller's own account: renaming a passkey that does not exist is a
404, and it discloses nothing the caller does not already own.

## Signature counters migrate as stored, never as zero

Section 6.1.3 of the WebAuthn specification treats a counter that fails to increase as
evidence of a cloned authenticator. The check is only as good as the stored starting point,
so a credential imported from another system keeps the counter that system last saw.
Importing at zero would disarm the check for that credential permanently: every subsequent
assertion would exceed zero and so would look correct forever.

Both being zero is different and is not a regression. Many authenticators, Apple's included,
do not implement a counter at all and send zero every time. The specification says to skip
the check in that case, and `_check_sign_count` does.

## `amr` for a passkey, and why a passkey with `uv` counts as two factors

A passkey login sets `amr` to `["swk"]` when the authenticator did not verify the user, and
to `["swk", "pin", "mfa"]` when it did. Both values are RFC 8176 registered: `swk` is "proof
of possession of a software-secured key" and `pin` is a PIN confirming presence.

The reasoning for treating a verified passkey as multi-factor: the assertion proves
possession of the private key, which never leaves the authenticator, and the `uv` flag
proves the authenticator separately checked something the user knows or is, before it would
sign. That is possession plus knowledge or inherence, established in one gesture, and it is
the reasoning every major platform applies to the same flag. A passkey **without** `uv`
proves possession only, so it is one factor and gets no `mfa`.

The practical consequence is deliberate: a user with TOTP enrolled who signs in with a
user-verified passkey is **not** challenged for a code, because they have already presented
two factors. The same user signing in with a passkey that reports no user verification
**is** challenged, and so is one signing in with a password. This is the one place where the
package decides an MFA policy on the user's behalf rather than asking the product, and it is
recorded in the M5 decisions and in the README because a product that disagrees needs to
know it is the package's choice and not an accident.

## Deleting the last passkey

Refused when the user has no password to fall back on, which is not a rule about passkeys so
much as about not stranding somebody outside their own account. "Has a password" is answered
by the `credentials` store, which is where the package's own password lives, so no new hook
is needed and `IdentityHooks` is unchanged by M5. A product whose users can sign in some
other way the package does not know about is not made worse off: it still has
`may_authenticate` and it can refuse the delete in front of the route.
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

if TYPE_CHECKING:  # pragma: no cover - typing only
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
    "AssertionResult",
    "PasskeyRejected",
    "PasskeyService",
    "RegistrationChallenge",
    "b64url_decode",
    "b64url_encode",
]

_log = logging.getLogger(__name__)

#: RFC 8176 `amr` values for a passkey. `swk` is "proof of possession of a software-secured
#: key", which is what a WebAuthn assertion is; `pin` is added when the authenticator's `uv`
#: flag says it verified the user itself. See the module docstring for why the pair counts
#: as multi-factor and a bare `swk` does not.
AMR_PASSKEY: Final = "swk"
AMR_PIN: Final = "pin"

#: Bytes of challenge entropy. 32, well beyond the 16 the WebAuthn specification requires as
#: a minimum, and the same figure `secrets.token_bytes` produces for every other secret here.
CHALLENGE_BYTES: Final = 32

#: How long an outstanding challenge lives. Five minutes, per the plan, and it is also the
#: TTL on the row so an abandoned ceremony clears itself.
CHALLENGE_TTL_SECONDS: Final = 300

#: The longest label a user may give a passkey. Long enough for "Tyler's YubiKey 5C NFC",
#: short enough that the field cannot be used to store a document in the table.
MAX_PASSKEY_NAME: Final = 64

#: The one message every passkey refusal carries, whatever went wrong. The counterpart of
#: `flows.INVALID_CREDENTIALS_MESSAGE` and `mfa.MfaRejected`'s default, and a constant for
#: the same reason: the control is that the strings are identical, and two literals drift.
PASSKEY_REJECTED_MESSAGE: Final = "That passkey could not be verified."


def b64url_encode(raw: bytes) -> str:
    """Base64url without padding, which is how WebAuthn spells bytes on the wire.

    Unpadded because that is what the WebAuthn JSON encoding uses and what the browser sends
    back, so a stored value can be compared to a presented one without normalising either.
    """
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    """The inverse, re-adding the padding the encoder stripped.

    Raises `ValueError` on anything that is not base64url, which every caller here turns
    into the ordinary refusal: a malformed credential id is an unusable one, and saying so
    precisely would tell a caller which of their guesses was well formed.
    """
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except (ValueError, TypeError) as exc:  # `binascii.Error` is a `ValueError`
        raise ValueError(f"not valid base64url: {value[:12]}") from exc


class PasskeyRejected(Exception):
    """A passkey ceremony failed. One type, one message, for every reason.

    Carries an `error_code` so a route can render it, and a `status_code` so the management
    routes can answer 404 and 409 where those are honest, while every login and verify
    refusal stays a 401 with `PASSKEY_REJECTED_MESSAGE`.
    """

    def __init__(
        self,
        message: str = PASSKEY_REJECTED_MESSAGE,
        *,
        error_code: str = "PASSKEY_REJECTED",
        status_code: int = 401,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class RegistrationChallenge:
    """The options object the browser passes to `navigator.credentials`, and its id.

    `options` is the WebAuthn JSON exactly as py_webauthn renders it, with no reshaping: the
    browser API is specified in terms of that document, and a helpfully renamed field is a
    field the browser does not understand.

    `challenge_id` is what the verify leg presents to spend the challenge. It is **not** the
    challenge: the challenge itself is inside `options` and is checked by py_webauthn against
    what the authenticator signed. The id is a lookup key with no security meaning of its
    own, which is why it can be handed to the browser in the clear.
    """

    challenge_id: str
    options: dict[str, Any]


@dataclass(frozen=True, slots=True)
class AssertionResult:
    """A verified passkey assertion: who it was, and what it proved.

    `amr` is computed here rather than by the flow, because whether the authenticator
    verified the user is a fact about this assertion and is known only at this point.
    """

    user_id: str
    credential_id: str
    user_verified: bool
    amr: list[str] = field(default_factory=list)


class PasskeyService:
    """WebAuthn ceremonies over the two M5 stores.

    Construct one per request or hold one per execution environment; it keeps no per-user
    state. Imports the `webauthn` package lazily, inside the methods that need it, so a
    product with `passkeys_enabled` false never has to install the extra.
    """

    def __init__(self, settings: IdentitySettings, stores: IdentityStores) -> None:
        self._settings = settings
        self._stores = stores

    # ---- configuration -------------------------------------------------------------

    @property
    def rp_id(self) -> str:
        """The Relying Party ID every ceremony is bound to.

        Checked here rather than in `IdentitySettings`, because `rp_id` is only required by
        a product that mounts the passkey routes and a settings-level requirement would make
        every JWKS-only deployment set one. The error names the variable, since the
        alternative is py_webauthn raising about an origin mismatch on the first real
        registration in production.
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
        """The origins an assertion may have come from. Section 5.5's other half.

        Required and never defaulted. An empty list would make py_webauthn's origin check
        vacuous, and the origin check is what stops a credential minted on the real site
        being replayed from an attacker's page.
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

    # ---- registration --------------------------------------------------------------

    def begin_registration(
        self,
        user_id: str,
        *,
        user_name: str,
        display_name: str = "",
    ) -> RegistrationChallenge:
        """Mint a registration challenge for an authenticated user.

        `exclude_credentials` lists the passkeys the account already has, so an authenticator
        that already holds one for this account declines rather than silently creating a
        second. That is a usability control rather than a security one: the duplicate would
        be refused by `finish_registration` anyway, but refusing it in the browser saves the
        user a failed ceremony they cannot interpret.

        The row is written **before** the options are returned, so a challenge the caller
        holds always has a row to spend. The other order would produce a ceremony that fails
        at the verify leg for a reason the user cannot act on.
        """
        from webauthn import generate_registration_options, options_to_json
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
                # `PREFERRED` on both, matching CarModPicker. Requiring a resident key would
                # refuse security keys with no room left, and requiring user verification
                # would refuse authenticators with no PIN or biometric. Both are recorded
                # per credential instead, so a product can require them where it matters
                # rather than at the door.
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
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

        The challenge is spent **before** the attestation is checked, on the same reasoning
        `complete_mfa` spends the MFA ticket first: a challenge is consumed by one attempt
        whatever the outcome, so a captured one cannot be ground against.

        The challenge's own `user_id` must match the caller. Without that check a challenge
        minted for one account could be answered while holding another account's access
        token, and the passkey would land on whichever account the token named.
        """
        from webauthn import verify_registration_response
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
            )
        except (WebAuthnException, ValueError, KeyError) as exc:
            # `ValueError` and `KeyError` as well as the library's own type: a body that is
            # not a credential at all reaches the parser before any WebAuthn check runs, and
            # a 500 there would be a client's malformed JSON reported as a server fault.
            _log.info(
                "passkey.register verification failed",
                extra={"event": "passkey.register.failure", "user_id": user_id},
            )
            raise PasskeyRejected() from exc

        credential_id = b64url_encode(verified.credential_id)
        store = self._stores.require_passkeys()
        owner = store.find_by_credential_id(credential_id)
        if owner is not None:
            # Registered already, to this account or another. One answer for both: telling a
            # caller that the credential belongs to somebody else would let a user with an
            # authenticator test which accounts it is enrolled on.
            raise PasskeyRejected(
                "That passkey is already registered.",
                error_code="PASSKEY_ALREADY_REGISTERED",
                status_code=409,
            )

        stored = PasskeyRecord(
            user_id=user_id,
            credential_id=credential_id,
            public_key=b64url_encode(verified.credential_public_key),
            # As reported by the authenticator, never forced to zero. See the module
            # docstring: a starting point of zero disarms the clone check permanently.
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
            # Lost a race with a concurrent registration of the same credential. The
            # conditional write is what settles it, and the loser gets the same 409 the
            # lookup above would have produced.
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

    # ---- login ---------------------------------------------------------------------

    def begin_login(self, *, user_id: str = "") -> RegistrationChallenge:
        """Mint a login challenge, optionally scoped to one user's credentials.

        Called with no `user_id` for the discoverable flow, which is the ordinary case: the
        browser picks the passkey and the assertion names it. Called with one when the
        frontend already knows who is signing in, which produces an `allowCredentials` list.

        **The caller resolves the user, and passes an empty string when there is none.** That
        keeps the enumeration decision in one place: an unknown address produces an empty
        list, which is byte-identical to a genuine discoverable request, so the route cannot
        answer differently for an address that has an account.
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

        # The row carries no `user_id` even when the options were scoped to one. The
        # assertion names the credential and the credential names its owner, so binding the
        # challenge to a user as well would add a second source of truth for who is signing
        # in, and the weaker one: it comes from an unauthenticated request body.
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

        Mints nothing. `flows.IdentityFlows.login_with_passkey` is what turns this into a
        session, because minting is `_mint_access`'s job and there is one of those, and
        because `may_authenticate` is a flow-level decision this module has no business
        making.

        The order is: spend the challenge, find the credential, verify the signature, check
        the counter, record the use. Every failure before the last step is the same refusal.
        """
        from webauthn import verify_authentication_response
        from webauthn.helpers.exceptions import WebAuthnException

        record = self._spend_challenge(challenge_id, expected_purpose="login")

        raw_id = credential.get("id") if isinstance(credential, dict) else None
        if not isinstance(raw_id, str) or not raw_id:
            raise PasskeyRejected()
        try:
            # Round-tripped rather than used as presented, so that a credential id spelled
            # with padding, or with the standard alphabet's `+` and `/`, still matches the
            # canonical form the table holds.
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
                # Zero, so py_webauthn's own counter check never fires and
                # `_check_sign_count` below is the one that decides. The signature, the
                # challenge, the origin and the RP ID are all still verified by the library;
                # only the counter comparison is taken back, and it is taken back so that a
                # regression is logged as the finding it is rather than disappearing into a
                # generic verification failure. See `_check_sign_count`.
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
        """Refuse a counter that did not advance, and log it as the finding it is.

        Section 6.1.3 of the WebAuthn specification: a counter that fails to increase is
        evidence that the credential has been cloned, because two copies of the same private
        key each keep their own count and the lower one eventually shows up.

        Both zero is the documented exception and is not a regression. Many authenticators,
        Apple's platform one included, keep no counter and send zero on every assertion.

        py_webauthn implements the identical rule, and `finish_login` deliberately passes it
        a stored count of zero so that this check is the one that decides. Two reasons: a
        regression must be **logged** as the finding it is rather than folded into a generic
        verification failure, and a control this important should not be a library's
        internal behaviour that an upgrade can quietly change.
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

    # ---- management ----------------------------------------------------------------

    def list_passkeys(self, user_id: str) -> list[PasskeyRecord]:
        """Every passkey a user has, newest label first is not promised: the store's order."""
        return self._stores.require_passkeys().list_for_user(user_id)

    def rename_passkey(self, user_id: str, credential_id: str, *, name: str) -> PasskeyRecord:
        """Relabel one of the caller's own passkeys.

        Answers honestly, unlike the login paths: this is behind the authorizer and scoped
        to `user_id`, so a 404 says only that the caller has no such passkey, which they
        already know.
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
        if updated is None:  # pragma: no cover - deleted between the write and the read
            raise PasskeyRejected(
                "No such passkey.", error_code="PASSKEY_NOT_FOUND", status_code=404
            )
        return updated

    def delete_passkey(self, user_id: str, credential_id: str, *, has_password: bool) -> None:
        """Remove one passkey, refusing to strand the user outside their own account.

        `has_password` is decided by the caller, which is `flows.IdentityFlows.delete_passkey`
        reading the `credentials` store. It is a parameter rather than a lookup here so that
        this service needs no credential store and so the rule is testable without one.

        The refusal applies only to the **last** passkey and only when there is no password:
        a user with two passkeys may delete either, and a user with a password may delete all
        of them. That is the narrowest rule that still makes the lockout impossible.
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

    # ---- the challenge lifecycle ---------------------------------------------------

    def _new_challenge(
        self,
        purpose: WebAuthnChallengePurpose,
        challenge: bytes,
        *,
        user_id: str = "",
    ) -> WebAuthnChallengeRecord:
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

        The purpose check is what keeps the two ceremonies apart. A registration challenge
        answered at the login verify leg would otherwise be a way for somebody who can start
        a registration to satisfy a login, and the two legs verify different things.
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
    """The `amr` a passkey assertion earns. See the module docstring for the reasoning.

    A module-level function rather than a method, so `flows` can ask the same question when
    it decides whether to challenge for a second factor, without either copy of the rule
    being able to drift from the other.
    """
    return [AMR_PASSKEY, AMR_PIN] if user_verified else [AMR_PASSKEY]


def _clean_name(name: str) -> str:
    """Trim a user-supplied label and cap its length. Empty stays empty."""
    return " ".join(name.split())[:MAX_PASSKEY_NAME]


def _transports_from(credential: Mapping[str, Any]) -> tuple[str, ...]:
    """The transports the browser reported, if it reported any.

    Recorded because a future `allowCredentials` can carry them, which is what lets a browser
    prompt for the right thing rather than offering every option. Read defensively: the field
    is optional, and a browser that omits it is not an error.
    """
    response = credential.get("response")
    if not isinstance(response, dict):
        return ()
    transports = response.get("transports")
    if not isinstance(transports, list):
        return ()
    return tuple(str(value) for value in transports if str(value))


def passkey_summary(record: PasskeyRecord) -> dict[str, Any]:
    """One passkey as the management routes render it.

    The public key is **not** in this document. It discloses nothing, being public, but a
    frontend has no use for it and a response body that carries key material invites somebody
    to start comparing it to something.
    """
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
