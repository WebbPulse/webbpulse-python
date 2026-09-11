"""The flows: register, login, change password, verification, reset, refresh, logout.

The service layer behind `router.py`, holding every decision about whether something is
allowed. Imports no web framework, so each path is reachable from a plain unit test.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final, NoReturn

from webbpulse.dynamodb import now_iso
from webbpulse.identity.hooks import AuthenticationRefused
from webbpulse.identity.lockout import (
    LockoutState,
    LoginAttemptStore,
    email_key,
    ip_key,
    lockout_state,
    new_attempt,
)
from webbpulse.identity.mfa import (
    AMR_MFA,
    AMR_PASSWORD,
    MfaChallenge,
    MfaRejected,
    MfaService,
    RecoveryCodeSet,
)
from webbpulse.identity.passwords import (
    check_password,
    equalise_password_timing,
    normalise_password,
)
from webbpulse.identity.sessions import SessionService

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Mapping, Sequence

    from webbpulse.identity.email import EmailMessage, EmailSender
    from webbpulse.identity.hooks import IdentityHooks
    from webbpulse.identity.passkeys import PasskeyService, RegistrationChallenge
    from webbpulse.identity.service import TokenService
    from webbpulse.identity.settings import IdentitySettings
    from webbpulse.identity.storage import IdentityStores, PasskeyRecord
    from webbpulse.identity.verification import LinkService

__all__ = [
    "INVALID_CREDENTIALS_MESSAGE",
    "PASSWORD_CREDENTIAL_TYPE",
    "AuthResult",
    "IdentityFlows",
    "LoginRejected",
    "MfaChallengeRequired",
    "RateLimited",
]

_log = logging.getLogger(__name__)

INVALID_CREDENTIALS_MESSAGE: Final = "Invalid email or password."

PASSWORD_CREDENTIAL_TYPE: Final = "password"

REGISTRATION_VIA: Final = "password"


class LoginRejected(Exception):
    """A login, registration or password change was refused.

    Carries the message the caller renders and an `error_code` the frontend branches on,
    matching `AuthenticationRefused` and `PasswordRejected`.
    """

    def __init__(
        self,
        message: str = INVALID_CREDENTIALS_MESSAGE,
        *,
        error_code: str = "INVALID_CREDENTIALS",
        status_code: int = 401,
    ) -> None:
        """Record the message, error code and status the router will render."""
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code


class RateLimited(LoginRejected):
    """Progressive lockout is in effect for this account. Section 5.1.

    Protects one account against guessing, unlike a `webbpulse.ratelimit` refusal, which
    protects the service. Answers 429 with `Retry-After`.
    """

    def __init__(self, retry_after: int) -> None:
        """Build the 429 refusal, carrying the seconds until the lockout decays."""
        super().__init__(
            "Too many failed attempts. Try again shortly.",
            error_code="TOO_MANY_ATTEMPTS",
            status_code=429,
        )
        self.retry_after = retry_after


class MfaChallengeRequired(Exception):
    """The password was correct and a second factor is enrolled.

    Raised rather than returned so a product that has not handled MFA gets a loud failure.
    Not a `LoginRejected`: nothing was refused, and it answers 200 carrying the challenge.
    """

    def __init__(self, challenge: MfaChallenge) -> None:
        """Carry the challenge the router renders as an `mfa_required` body."""
        super().__init__("Multi-factor authentication is required.")
        self.challenge = challenge


@dataclass(frozen=True, slots=True)
class AuthResult:
    """A successful authentication: the access token and the refresh cookie to set.

    `refresh_token` is the plaintext and exists only to be written into a `Set-Cookie`.
    Nothing stores it and nothing logs it.
    """

    access_token: str
    expires_in: int
    user: Mapping[str, Any]
    refresh_token: str
    family_id: str
    extra: Mapping[str, Any] = field(default_factory=dict)


class IdentityFlows:
    """The flow logic for one product.

    Built once per execution environment and holds no request state, so every method takes
    the request's IP and user agent explicitly. `now` is a parameter where time is behaviour.
    """

    def __init__(
        self,
        settings: IdentitySettings,
        hooks: IdentityHooks,
        stores: IdentityStores,
        tokens: TokenService,
        *,
        attempts: LoginAttemptStore | None = None,
        email_sender: EmailSender | None = None,
        kms_client: Any = None,
    ) -> None:
        """Wire the flows to their settings, hooks, stores and token service.

        The MFA, passkey and link services are built only when their stores and settings are
        present, so an unconfigured capability is absent rather than broken.
        """
        self._settings = settings
        self._hooks = hooks
        self._stores = stores
        self._tokens = tokens
        self._attempts = attempts
        self._email = email_sender
        self._sessions = SessionService(settings, stores.require_refresh_tokens())
        self._links: LinkService | None = None
        if email_sender is not None and stores.identity_tokens is not None:
            from webbpulse.identity.verification import LinkService

            self._links = LinkService(settings, stores.identity_tokens)

        self.mfa: MfaService | None = None
        if (
            settings.totp_enabled
            and stores.totp_factors is not None
            and stores.recovery_codes is not None
            and stores.identity_tokens is not None
        ):
            self.mfa = MfaService(settings, stores, tokens, kms_client=kms_client)

        self.passkeys: PasskeyService | None = None
        if (
            settings.passkeys_enabled
            and stores.passkeys is not None
            and stores.webauthn_challenges is not None
        ):
            from webbpulse.identity.passkeys import PasskeyService

            self.passkeys = PasskeyService(settings, stores)

    @property
    def sessions(self) -> SessionService:
        """The session service, for a caller that needs the family lifecycle directly."""
        return self._sessions

    @property
    def email_enabled(self) -> bool:
        """Whether the email flows can run: a sender and an `identity-tokens` store.

        The router asks this rather than re-deriving the condition, so the routes that mount
        and the flows that work are decided by one expression.
        """
        return self._links is not None and self._email is not None

    def register(
        self,
        *,
        email: str,
        password: str,
        ip: str = "",
        user_agent: str = "",
        attributes: Mapping[str, Any] | None = None,
    ) -> AuthResult | None:
        """Create an account and sign it in, or pretend to when the email is taken.

        Returns `None` when the address already exists, which the router renders as the same
        200 a real registration gets. Raises `LoginRejected` when registration is disabled.
        """
        if not self._settings.registration_enabled:
            raise LoginRejected(
                "Registration is not open.",
                error_code="REGISTRATION_DISABLED",
                status_code=403,
            )
        if not self._settings.passwords_enabled:
            raise LoginRejected(
                "Password registration is not available.",
                error_code="PASSWORDS_DISABLED",
                status_code=403,
            )

        normalised_email = _normalise_email(email)
        if not normalised_email:
            raise LoginRejected(
                "An email address is required.",
                error_code="EMAIL_REQUIRED",
                status_code=400,
            )

        checked = check_password(password, breach_check=self._settings.password_breach_check)

        existing = self._hooks.load_user_by_email(normalised_email)
        if existing is not None:
            equalise_password_timing(checked)
            self._send_registration_notice(existing, normalised_email)
            _log.info(
                "Registration attempted for an address that already has an account.",
                extra={
                    "event": "register.duplicate",
                    "ip": ip,
                    "user_agent": _device_class(user_agent),
                },
            )
            return None

        from webbpulse.security import hash_password

        secret = hash_password(checked)
        user = self._hooks.create_user(
            email=normalised_email,
            attributes=dict(attributes or {}) | {"email_verified": False},
        )
        user_id = _user_id(user)

        from webbpulse.identity.storage import CredentialRecord

        self._stores.require_credentials().put(
            CredentialRecord(
                user_id=user_id,
                credential_type=PASSWORD_CREDENTIAL_TYPE,
                secret=secret,
                created_at=now_iso(),
                updated_at=now_iso(),
            )
        )
        self._hooks.on_user_created(user, REGISTRATION_VIA)

        self._send_verification(user_id, normalised_email, best_effort=True)

        _log.info(
            "Account registered.",
            extra={"event": "register.success", "user_id": user_id, "ip": ip},
        )

        if self._settings.email_verification_required:
            raise LoginRejected(
                "Check your email to confirm your address before signing in.",
                error_code="EMAIL_VERIFICATION_REQUIRED",
                status_code=403,
            )

        return self._issue(user, ip=ip, user_agent=user_agent, extra={"user_id": user_id})

    def login(
        self,
        *,
        email: str,
        password: str,
        ip: str = "",
        user_agent: str = "",
        now: datetime | None = None,
    ) -> AuthResult:
        """Authenticate an email and password, or raise the one indistinguishable refusal.

        Checks lockout, loads the user, always verifies against a real or dummy hash, asks the
        product, then records the attempt. Every refusal raises the same `LoginRejected`.
        """
        moment = now or datetime.now(UTC)
        if not self._settings.passwords_enabled:
            raise LoginRejected(
                "Password sign-in is not available.",
                error_code="PASSWORDS_DISABLED",
                status_code=403,
            )

        normalised_email = _normalise_email(email)
        identity = email_key(normalised_email)

        state = self._lockout_state(identity, now=moment)
        if state.locked:
            self._record(identity, "locked", ip=ip, user_agent=user_agent)
            _log.warning(
                "Login refused by progressive lockout.",
                extra={"event": "login.locked", "ip": ip, "failures": state.failures},
            )
            raise RateLimited(state.retry_after_seconds(now=moment))

        user = self._hooks.load_user_by_email(normalised_email) if normalised_email else None
        presented = normalise_password(password)

        credential = None
        if user is not None:
            credential = self._stores.require_credentials().get(
                _user_id(user), PASSWORD_CREDENTIAL_TYPE
            )

        if user is None or credential is None or not credential.secret:
            equalise_password_timing(presented)
            self._fail(identity, ip=ip, user_agent=user_agent, reason="unknown_or_no_credential")

        from webbpulse.security import needs_rehash, verify_password

        if not verify_password(presented, credential.secret):
            self._fail(
                identity,
                ip=ip,
                user_agent=user_agent,
                user_id=_user_id(user),
                reason="wrong_password",
            )

        try:
            self._hooks.may_authenticate(user)
        except AuthenticationRefused as refused:
            self._fail(
                identity,
                ip=ip,
                user_agent=user_agent,
                user_id=_user_id(user),
                reason="refused_by_hook",
                message=refused.message,
                error_code=refused.error_code,
            )

        if needs_rehash(credential.secret):
            from webbpulse.identity.storage import CredentialRecord
            from webbpulse.security import hash_password

            self._stores.require_credentials().put(
                CredentialRecord(
                    user_id=_user_id(user),
                    credential_type=PASSWORD_CREDENTIAL_TYPE,
                    secret=hash_password(presented),
                    created_at=credential.created_at,
                    updated_at=now_iso(),
                    attributes=credential.attributes,
                )
            )

        self._record(identity, "success", user_id=_user_id(user), ip=ip, user_agent=user_agent)
        _log.info(
            "Login succeeded.",
            extra={
                "event": "login.success",
                "user_id": _user_id(user),
                "ip": ip,
                "user_agent": _device_class(user_agent),
            },
        )

        challenge = self._challenge_for(user)
        if challenge is not None:
            raise MfaChallengeRequired(challenge)

        return self._issue(user, ip=ip, user_agent=user_agent)

    def issue_for_oauth(
        self,
        user: Mapping[str, Any],
        *,
        provider: str,
        ip: str = "",
        user_agent: str = "",
    ) -> AuthResult:
        """Issue the same token pair a password login gets, for a completed OAuth callback.

        MFA is honoured exactly as it is for a password, and `may_authenticate` is consulted,
        so a second front door cannot reach a disabled account. `amr` records the provider.
        """
        from webbpulse.identity.oauth import AMR_OAUTH

        self._hooks.may_authenticate(user)

        challenge = self._challenge_for(user)
        if challenge is not None:
            raise MfaChallengeRequired(challenge)

        return self._issue(
            user,
            ip=ip,
            user_agent=user_agent,
            amr=[AMR_OAUTH, provider],
        )

    def _challenge_for(self, user: Mapping[str, Any]) -> MfaChallenge | None:
        """The challenge this user must answer, or `None` to issue tokens directly.

        Returns `None` when MFA is not configured at all, so a product that never wired the
        stores keeps its previous behaviour.
        """
        if self.mfa is None:
            return None
        user_id = _user_id(user)
        factors = self.mfa.factors_for(user_id)
        if not factors:
            return None
        return self.mfa.issue_challenge(user_id, factors=factors)

    def complete_mfa(
        self,
        *,
        ticket: str,
        code: str,
        ip: str = "",
        user_agent: str = "",
    ) -> AuthResult:
        """The second leg of login: spend a ticket, satisfy a factor, issue the session.

        The ticket is consumed before the code is checked, so a stolen ticket cannot be used
        to grind codes.
        """
        service = self._require_mfa()
        user_id = service.consume_ticket(ticket)

        user = self._hooks.load_user_by_id(user_id)
        if user is None:
            raise MfaRejected(
                "That sign-in attempt has expired. Start again.",
                error_code="MFA_TICKET_INVALID",
            )

        method = service.verify_challenge(user_id, code)
        _log.info(
            "MFA login completed.",
            extra={"event": "mfa.success", "user_id": user_id, "method": method},
        )
        return self._issue(user, ip=ip, user_agent=user_agent, amr=[AMR_PASSWORD, method])

    def step_up(
        self,
        *,
        user_id: str,
        session_id: str,
        code: str,
    ) -> AuthResult:
        """Re-authenticate inside an existing session, returning a fresher access token.

        No new refresh family and no cookie change: what changes is `auth_time` and `amr`.
        The result carries an empty `refresh_token` and the caller's existing `family_id`.
        """
        service = self._require_mfa()
        user = self._hooks.load_user_by_id(user_id)
        if user is None:
            raise MfaRejected()

        method = service.verify_challenge(user_id, code)
        access = self._mint_access(
            user,
            session_id=session_id,
            amr=[AMR_PASSWORD, method],
            auth_time=int(time.time()),
        )
        _log.info(
            "Step-up authentication succeeded.",
            extra={"event": "mfa.step_up", "user_id": user_id, "method": method},
        )
        return AuthResult(
            access_token=access,
            expires_in=int(self._settings.access_token_ttl.total_seconds()),
            user=user,
            refresh_token="",
            family_id=session_id,
        )

    def disable_totp(self, *, user_id: str, code: str) -> None:
        """Remove the factor and every recovery code, after proving possession of the factor.

        The code is checked before anything is deleted, so a stolen access token alone cannot
        turn off the control that bounds its value. A recovery code presented here is spent.
        """
        service = self._require_mfa()
        user = self._hooks.load_user_by_id(user_id)
        if user is None:
            raise MfaRejected()

        method = service.verify_challenge(user_id, code)
        service.disable_totp(user_id)
        _log.info(
            "TOTP disabled after re-authentication.",
            extra={"event": "totp.disabled", "user_id": user_id, "method": method},
        )

    def regenerate_recovery_codes(self, *, user_id: str, code: str) -> RecoveryCodeSet:
        """Replace every recovery code, after proving possession of the factor.

        Verification happens before the old set is deleted, so a refused attempt leaves the
        user's existing codes intact.
        """
        service = self._require_mfa()
        user = self._hooks.load_user_by_id(user_id)
        if user is None:
            raise MfaRejected()

        method = service.verify_challenge(user_id, code)
        codes = service.regenerate_recovery_codes(user_id)
        _log.info(
            "Recovery codes regenerated after re-authentication.",
            extra={"event": "recovery.regenerated", "user_id": user_id, "method": method},
        )
        return codes

    def _require_mfa(self) -> MfaService:
        """The MFA service, or a 503 saying it is not configured."""
        service = self.mfa
        if service is None:
            raise MfaRejected(
                "Multi-factor authentication is not available.",
                error_code="MFA_NOT_CONFIGURED",
                status_code=503,
            )
        return service

    def change_password(
        self,
        *,
        user_id: str,
        current_password: str,
        new_password: str,
        ip: str = "",
        keep_family_id: str = "",
    ) -> int:
        """Change a signed-in user's password and revoke their other sessions.

        Requires the current password, because a token proves the session and not the person.
        `keep_family_id` spares the caller's own family. Returns the number of records revoked.
        """
        credential = self._stores.require_credentials().get(user_id, PASSWORD_CREDENTIAL_TYPE)
        presented = normalise_password(current_password)

        from webbpulse.security import verify_password

        if credential is None or not credential.secret:
            equalise_password_timing(presented)
            raise LoginRejected(
                "Your current password is not correct.", error_code="INVALID_CREDENTIALS"
            )
        if not verify_password(presented, credential.secret):
            raise LoginRejected(
                "Your current password is not correct.", error_code="INVALID_CREDENTIALS"
            )

        checked = check_password(new_password, breach_check=self._settings.password_breach_check)

        from webbpulse.identity.storage import CredentialRecord
        from webbpulse.security import hash_password

        self._stores.require_credentials().put(
            CredentialRecord(
                user_id=user_id,
                credential_type=PASSWORD_CREDENTIAL_TYPE,
                secret=hash_password(checked),
                created_at=credential.created_at,
                updated_at=now_iso(),
                attributes=credential.attributes,
            )
        )

        revoked = self._revoke_families(user_id, keep_family_id=keep_family_id)
        _log.info(
            "Password changed.",
            extra={
                "event": "password.changed",
                "user_id": user_id,
                "ip": ip,
                "revoked_records": revoked,
            },
        )
        self._send_password_changed(user_id)
        return revoked

    def request_verification(self, email: str, *, ip: str = "") -> None:
        """Send a verification link to an address, on demand. Always succeeds.

        Returns `None` on every path, so an unknown address, an already verified one and one
        that gets a link are the same outcome from outside.
        """
        self._require_email()
        normalised = _normalise_email(email)
        if not normalised:
            return
        user = self._hooks.load_user_by_email(normalised)
        if user is None:
            _log.info(
                "Verification requested for an address with no account.",
                extra={"event": "email.verification_requested", "found": False, "ip": ip},
            )
            return
        if _is_verified(user):
            _log.info(
                "Verification requested for an address that is already verified.",
                extra={"event": "email.verification_requested", "found": True, "ip": ip},
            )
            return
        self._send_verification(_user_id(user), normalised, best_effort=False)

    def confirm_verification(self, token: str, *, ip: str = "") -> str:
        """Consume a verification link and mark the address verified. Returns the user id.

        Raises `ConfirmationFailed` for an unknown, expired, used or wrong-purpose token, all
        with the same message. The hook runs after the link is consumed.
        """
        links = self._require_links()
        from webbpulse.identity.verification import ConfirmationFailed

        try:
            record = links.confirm(token, "verify_email")
        except ConfirmationFailed as exc:
            links.log_refusal(exc, "verify_email")
            raise

        self._hooks.mark_email_verified(record.user_id)
        _log.info(
            "Email address verified.",
            extra={"event": "email.verified", "user_id": record.user_id, "ip": ip},
        )
        return record.user_id

    def request_password_reset(self, email: str, *, ip: str = "") -> None:
        """Send a reset link. Always succeeds, whatever the address is.

        Returns `None` on every path, so no caller can branch on whether the address exists.
        A link is issued whether or not the address is verified.
        """
        self._require_email()
        normalised = _normalise_email(email)
        if not normalised:
            return
        user = self._hooks.load_user_by_email(normalised)
        if user is None:
            _log.info(
                "Password reset requested for an address with no account.",
                extra={"event": "password.reset_requested", "found": False, "ip": ip},
            )
            return

        links = self._require_links()
        issued = links.issue(_user_id(user), "reset_password")
        from webbpulse.identity.email import render_password_reset
        from webbpulse.identity.verification import describe_expiry

        self._send(
            render_password_reset(
                self._settings,
                to=normalised,
                link=issued.url,
                expiry=describe_expiry(links.ttl_for("reset_password")),
            ),
            best_effort=False,
        )

    def confirm_password_reset(
        self,
        *,
        token: str,
        new_password: str,
        ip: str = "",
        family_ids: list[str] | None = None,
    ) -> str:
        """Consume a reset link, set a new password, and end every session. Returns the id.

        Nothing is kept, unlike `change_password`: a reset is the remedy for a compromise.
        The link is consumed before the policy is checked, which makes it genuinely single use.
        """
        links = self._require_links()
        from webbpulse.identity.verification import ConfirmationFailed

        try:
            record = links.confirm(token, "reset_password")
        except ConfirmationFailed as exc:
            links.log_refusal(exc, "reset_password")
            raise

        checked = check_password(new_password, breach_check=self._settings.password_breach_check)

        from webbpulse.identity.storage import CredentialRecord
        from webbpulse.security import hash_password

        credentials = self._stores.require_credentials()
        existing = credentials.get(record.user_id, PASSWORD_CREDENTIAL_TYPE)
        credentials.put(
            CredentialRecord(
                user_id=record.user_id,
                credential_type=PASSWORD_CREDENTIAL_TYPE,
                secret=hash_password(checked),
                created_at=existing.created_at if existing else now_iso(),
                updated_at=now_iso(),
                attributes=existing.attributes if existing else {},
            )
        )

        revoked = self._revoke_families(record.user_id, family_ids=family_ids)

        try:
            self._hooks.mark_email_verified(record.user_id)
        except Exception:
            _log.info(
                "Password reset did not mark the address verified.",
                extra={"event": "password.reset_completed", "user_id": record.user_id},
            )

        self._send_password_changed(record.user_id)
        _log.info(
            "Password reset completed.",
            extra={
                "event": "password.reset_completed",
                "user_id": record.user_id,
                "revoked_records": revoked,
                "ip": ip,
            },
        )
        return record.user_id

    def refresh(
        self,
        presented: str,
        *,
        ip: str = "",
        user_agent: str = "",
        now: datetime | None = None,
    ) -> AuthResult:
        """Rotate a refresh token and mint a new access token.

        Every refusal is the same 401, whatever the outcome. Re-reads the user and re-runs
        `may_authenticate` on each rotation, which is the only revocation the design has.
        """
        if not presented:
            raise LoginRejected("Your session has ended. Sign in again.", error_code="NO_SESSION")

        result = self._sessions.rotate(presented, ip=ip, now=now)
        if result.issued is None:
            _log.info(
                "Refresh refused.",
                extra={
                    "event": "session.refresh_failed",
                    "outcome": result.outcome,
                    "family_id": result.family_id,
                    "user_id": result.user_id,
                    "ip": ip,
                },
            )
            raise LoginRejected("Your session has ended. Sign in again.", error_code="NO_SESSION")

        user = self._hooks.load_user_by_id(result.issued.user_id)
        if user is None:
            self._sessions.revoke_family(result.issued.family_id)
            raise LoginRejected("Your session has ended. Sign in again.", error_code="NO_SESSION")

        try:
            self._hooks.may_authenticate(user)
        except AuthenticationRefused as refused:
            self._sessions.revoke_family(result.issued.family_id)
            _log.info(
                "Refresh refused by the product's may_authenticate hook; family revoked.",
                extra={
                    "event": "session.revoked",
                    "user_id": result.issued.user_id,
                    "family_id": result.issued.family_id,
                },
            )
            raise LoginRejected(refused.message, error_code=refused.error_code) from refused

        access = self._mint_access(user, session_id=result.issued.family_id)
        _log.info(
            "Session refreshed.",
            extra={
                "event": "session.refreshed",
                "user_id": result.issued.user_id,
                "family_id": result.issued.family_id,
                "generation": result.issued.generation,
                "replayed": result.outcome == "replayed",
                "ip": ip,
            },
        )
        return AuthResult(
            access_token=access,
            expires_in=int(self._settings.access_token_ttl.total_seconds()),
            user=user,
            refresh_token=result.issued.token,
            family_id=result.issued.family_id,
        )

    def logout(self, presented: str, *, ip: str = "") -> int:
        """Revoke the family the presented cookie belongs to. Always succeeds.

        Tolerant of an unknown, expired or already-revoked token, because the caller's intent
        is to end up signed out.
        """
        if not presented:
            return 0
        result = self._sessions.revoke_presented(presented)
        _log.info(
            "Logout.",
            extra={
                "event": "session.revoked",
                "user_id": result.user_id,
                "family_id": result.family_id,
                "revoked_records": result.revoked,
                "ip": ip,
            },
        )
        return result.revoked

    def logout_all(
        self,
        user_id: str,
        *,
        ip: str = "",
        family_ids: list[str] | None = None,
        presented: str = "",
    ) -> int:
        """Revoke every family for a user. The sign-out-everywhere button.

        See `SessionService.revoke_all_for_user` for why the family ids may have to come
        from the caller: `refresh-tokens` carries no user index by design. `presented` is a
        refresh token whose own family is resolved through the store and revoked too.
        """
        targets = list(family_ids) if family_ids is not None else None
        if presented:
            family = self._sessions.family_of(presented)
            if family:
                targets = (targets or []) + [family]
        revoked = self._revoke_families(user_id, family_ids=targets)
        _log.info(
            "Signed out of every session.",
            extra={
                "event": "session.logout_all",
                "user_id": user_id,
                "revoked_records": revoked,
                "ip": ip,
            },
        )
        return revoked

    def _require_email(self) -> None:
        """Raise a 503 unless a sender and an `identity-tokens` store are both present."""
        if not self.email_enabled:
            raise LoginRejected(
                "This service is not configured to send email, so this flow is not available.",
                error_code="EMAIL_NOT_CONFIGURED",
                status_code=503,
            )

    def _require_links(self) -> LinkService:
        """The link service, after checking email is configured."""
        self._require_email()
        assert self._links is not None
        return self._links

    def _send(self, message: EmailMessage, *, best_effort: bool) -> None:
        """Send one rendered message.

        `best_effort` separates the paths that tolerate a send failure from the paths that
        report one: a deliberate resend must not answer 200 having sent nothing.
        """
        from webbpulse.identity.email import EmailSendFailed

        assert self._email is not None
        try:
            self._email.send(message)
        except EmailSendFailed:
            if not best_effort:
                raise
            _log.warning(
                "Could not send an identity email; the flow continued.",
                extra={
                    "event": "email.send_failed",
                    "purpose": message.tags.get("purpose", "unknown"),
                },
            )

    def _send_verification(self, user_id: str, email: str, *, best_effort: bool) -> None:
        """Issue a verification link and mail it, when email is configured.

        Silently does nothing when it is not, and only on the `best_effort` path, so a product
        with no email sender still registers accounts.
        """
        if not self.email_enabled:
            if not best_effort:
                self._require_email()
            return
        links = self._require_links()
        issued = links.issue(user_id, "verify_email")
        from webbpulse.identity.email import render_verification
        from webbpulse.identity.verification import describe_expiry

        self._send(
            render_verification(
                self._settings,
                to=email,
                link=issued.url,
                expiry=describe_expiry(links.ttl_for("verify_email")),
            ),
            best_effort=best_effort,
        )

    def _send_registration_notice(self, user: Mapping[str, Any], email: str) -> None:
        """Section 5.4's notice to an address somebody tried to register again.

        Always best effort: a send failure must not turn the non-disclosure into a 500 that
        discloses by its own existence.
        """
        if not self.email_enabled:
            return
        from webbpulse.identity.email import render_registration_notice

        del user
        self._send(
            render_registration_notice(
                self._settings,
                to=email,
                link=self._require_links().page_for("reset_password"),
            ),
            best_effort=True,
        )

    def _send_password_changed(self, user_id: str) -> None:
        """Tell a user their password changed. Always best effort.

        A notification, not a control: the password is already changed, so failing the request
        would undo nothing. No address on the user record means no notice.
        """
        if not self.email_enabled:
            return
        try:
            user = self._hooks.load_user_by_id(user_id)
        except Exception:
            return
        address = str((user or {}).get("email", "")).strip()
        if not address:
            return
        from webbpulse.identity.email import render_password_changed

        self._send(
            render_password_changed(
                self._settings,
                to=address,
                link=self._require_links().page_for("reset_password"),
            ),
            best_effort=True,
        )

    def _require_passkeys(self) -> PasskeyService:
        """The passkey service, or a refusal naming the reason it is absent.

        A 501 rather than a 500: the tables are absent or `passkeys_enabled` is false, which
        is a configuration state and not a fault.
        """
        if self.passkeys is None:
            raise LoginRejected(
                "Passkeys are not available.",
                error_code="PASSKEYS_DISABLED",
                status_code=501,
            )
        return self.passkeys

    def begin_passkey_registration(self, *, user_id: str) -> RegistrationChallenge:
        """Options for enrolling a new passkey on an already-authenticated account.

        `may_authenticate` is consulted, so a disabled account cannot grow new credentials
        while a valid token is still in hand.
        """
        service = self._require_passkeys()
        user = self._hooks.load_user_by_id(user_id)
        if user is None:
            raise LoginRejected("No such account.", error_code="USER_NOT_FOUND", status_code=404)
        self._hooks.may_authenticate(user)
        email = str(user.get("email", "")).strip()
        return service.begin_registration(
            user_id,
            user_name=email or user_id,
            display_name=str(user.get("name", "")).strip() or email or user_id,
        )

    def finish_passkey_registration(
        self,
        *,
        user_id: str,
        challenge_id: str,
        credential: Mapping[str, Any],
        name: str = "",
    ) -> PasskeyRecord:
        """Verify the attestation and store the credential against the caller's account."""
        service = self._require_passkeys()
        record = service.finish_registration(
            user_id, challenge_id=challenge_id, credential=credential, name=name
        )
        _log.info(
            "Passkey registered.",
            extra={"event": "passkey.register.success", "user_id": user_id},
        )
        return record

    def begin_passkey_login(self, *, email: str = "") -> RegistrationChallenge:
        """Options for signing in with a passkey.

        Refused unless `passkeys_passwordless` is on. An unknown or absent address produces a
        discoverable-credential challenge, so this route is not an account oracle.
        """
        service = self._require_passkeys()
        if not self._settings.passkeys_passwordless:
            raise LoginRejected(
                "Passwordless sign-in is not available.",
                error_code="PASSKEY_LOGIN_DISABLED",
                status_code=403,
            )
        user_id = ""
        normalised = _normalise_email(email)
        if normalised:
            try:
                user = self._hooks.load_user_by_email(normalised)
            except Exception:  # pragma: no cover
                user = None
            if user is not None:
                user_id = _user_id(user)
        return service.begin_login(user_id=user_id)

    def login_with_passkey(
        self,
        *,
        challenge_id: str,
        credential: Mapping[str, Any],
        ip: str = "",
        user_agent: str = "",
    ) -> AuthResult:
        """The passwordless login leg: verify an assertion, issue the same token pair.

        Identical output to `login` but for `amr`. A user-verified passkey is not challenged
        for TOTP; one reporting no user verification still is. Lockout does not apply.
        """
        service = self._require_passkeys()
        if not self._settings.passkeys_passwordless:
            raise LoginRejected(
                "Passwordless sign-in is not available.",
                error_code="PASSKEY_LOGIN_DISABLED",
                status_code=403,
            )
        result = service.finish_login(challenge_id=challenge_id, credential=credential)

        user = self._hooks.load_user_by_id(result.user_id)
        if user is None:
            from webbpulse.identity.passkeys import PasskeyRejected

            raise PasskeyRejected()

        self._hooks.may_authenticate(user)

        if not result.user_verified and self.mfa is not None:
            challenge = self._challenge_for(user)
            if challenge is not None:
                raise MfaChallengeRequired(challenge)

        self._record(
            str(user.get("email", "")) or result.user_id,
            "success",
            user_id=result.user_id,
            ip=ip,
            user_agent=user_agent,
        )
        _log.info(
            "Passkey login succeeded.",
            extra={
                "event": "passkey.login.success",
                "user_id": result.user_id,
                "ip": ip,
                "user_agent": _device_class(user_agent),
                "user_verified": result.user_verified,
            },
        )
        return self._issue(user, ip=ip, user_agent=user_agent, amr=result.amr)

    def list_passkeys(self, *, user_id: str) -> list[PasskeyRecord]:
        """Every passkey on the caller's own account."""
        return self._require_passkeys().list_passkeys(user_id)

    def rename_passkey(self, *, user_id: str, credential_id: str, name: str) -> PasskeyRecord:
        """Relabel one of the caller's own passkeys."""
        return self._require_passkeys().rename_passkey(user_id, credential_id, name=name)

    def delete_passkey(self, *, user_id: str, credential_id: str) -> None:
        """Remove one of the caller's own passkeys, unless it is the only way in.

        "Has a password" is read from the `credentials` store, so M5 needed no new hook.
        """
        service = self._require_passkeys()
        credential = self._stores.require_credentials().get(user_id, PASSWORD_CREDENTIAL_TYPE)
        service.delete_passkey(
            user_id, credential_id, has_password=credential is not None and bool(credential.secret)
        )

    def _issue(
        self,
        user: Mapping[str, Any],
        *,
        ip: str,
        user_agent: str,
        extra: Mapping[str, Any] | None = None,
        amr: Sequence[str] = (AMR_PASSWORD,),
    ) -> AuthResult:
        """Start a family and mint the first access token for it."""
        user_id = _user_id(user)
        issued = self._sessions.start_family(user_id, device=_device_class(user_agent), ip=ip)
        access = self._mint_access(user, session_id=issued.family_id, amr=amr)
        return AuthResult(
            access_token=access,
            expires_in=int(self._settings.access_token_ttl.total_seconds()),
            user=user,
            refresh_token=issued.token,
            family_id=issued.family_id,
            extra=dict(extra or {}),
        )

    def _mint_access(
        self,
        user: Mapping[str, Any],
        *,
        session_id: str,
        amr: Sequence[str] = (AMR_PASSWORD,),
        auth_time: int | None = None,
    ) -> str:
        """The single place an access token is minted, and so the single place `amr` is set.

        `amr` and `auth_time` are applied after `claims_for`, so a product hook cannot
        overwrite them. `mfa` is added alongside the specific factor when more than one was used.
        """
        methods = list(dict.fromkeys(amr))
        if len(methods) > 1 and AMR_MFA not in methods:
            methods.append(AMR_MFA)
        claims = dict(self._hooks.claims_for(user))
        claims["amr"] = methods
        claims["auth_time"] = int(time.time()) if auth_time is None else auth_time
        return self._tokens.mint_access_token(
            _user_id(user),
            claims=claims,
            session_id=session_id,
        )

    def _revoke_families(
        self,
        user_id: str,
        *,
        keep_family_id: str = "",
        family_ids: list[str] | None = None,
    ) -> int:
        """Revoke a user's families, using `family_ids` when the caller supplied them."""
        if family_ids is not None:
            targets = [family for family in family_ids if family]
            return self._sessions.revoke_all_for_user(
                user_id, family_ids=targets, except_family_id=keep_family_id
            )
        return self._sessions.revoke_all_for_user(user_id, except_family_id=keep_family_id)

    def _lockout_state(self, identity: str, *, now: datetime) -> LockoutState:
        """The lockout state for an identity, or an empty one when attempts are unreadable."""
        if self._attempts is None:
            return LockoutState(failures=0)
        try:
            recent = self._attempts.recent(identity)
        except Exception:  # pragma: no cover
            _log.warning(
                "Could not read login attempts; proceeding without lockout.",
                extra={"event": "login.lockout_read_failed"},
            )
            return LockoutState(failures=0)
        return lockout_state(recent, now=now)

    def _record(
        self,
        identity: str,
        outcome: str,
        *,
        user_id: str = "",
        ip: str = "",
        user_agent: str = "",
    ) -> None:
        """Write one attempt row, best effort. Never raises.

        Written under both the email key and the IP key, which is what makes section 5.2's
        anomaly query a `Query` rather than a scan.
        """
        if self._attempts is None:
            return
        for key in (identity, ip_key(ip) if ip else ""):
            if not key:
                continue
            try:
                self._attempts.record(
                    new_attempt(
                        key,
                        outcome,  # type: ignore[arg-type]
                        user_id=user_id,
                        ip=ip,
                        user_agent=_device_class(user_agent),
                    )
                )
            except Exception:  # pragma: no cover
                _log.warning(
                    "Could not record a login attempt.",
                    extra={"event": "login.attempt_write_failed", "outcome": outcome},
                )

    def _fail(
        self,
        identity: str,
        *,
        ip: str,
        user_agent: str,
        user_id: str = "",
        reason: str,
        message: str = INVALID_CREDENTIALS_MESSAGE,
        error_code: str = "INVALID_CREDENTIALS",
    ) -> NoReturn:
        """Record a failed login and raise. Never returns.

        `NoReturn` so the type checker narrows after each call site. `reason` reaches the log
        and never the response.
        """
        self._record(identity, "failure", user_id=user_id, ip=ip, user_agent=user_agent)
        _log.info(
            "Login failed.",
            extra={
                "event": "login.failure",
                "reason": reason,
                "user_id": user_id,
                "ip": ip,
                "user_agent": _device_class(user_agent),
            },
        )
        raise LoginRejected(message, error_code=error_code)


def _normalise_email(email: str) -> str:
    """Lower case and strip. The form every lookup and every attempt key uses.

    Must be done identically at registration and at login, or an account becomes
    unreachable.
    """
    return email.strip().lower()


def _user_id(user: Mapping[str, Any]) -> str:
    """The immutable id from a product's user mapping.

    Section 3.3: `sub` is the immutable id, never the username or the email, because both
    change and a `sub` that changes breaks every row keyed on it.
    """
    value = user.get("id") or user.get("user_id") or ""
    if not value:
        raise LoginRejected(
            "The product's user record has no id, so no token can be minted for it.",
            error_code="USER_ID_MISSING",
            status_code=500,
        )
    return str(value)


def _is_verified(user: Mapping[str, Any]) -> bool:
    """Whether the product's user record already says this address is confirmed.

    Absent means not verified, which is the safe reading: the cost is a redundant link,
    where the other reading would strand a user who genuinely needs one.
    """
    return bool(user.get("email_verified", False))


def _device_class(user_agent: str) -> str:
    """A coarse device class, never a fingerprint. Section 4.2 and section 5.7.

    Enough to make an audit line readable, and deliberately not enough to identify a
    browser.
    """
    if not user_agent:
        return "unknown"
    lowered = user_agent.lower()
    if "bot" in lowered or "crawler" in lowered or "spider" in lowered:
        return "bot"
    if "mobile" in lowered or "android" in lowered or "iphone" in lowered:
        return "mobile"
    if "mozilla" in lowered or "safari" in lowered or "chrome" in lowered:
        return "desktop"
    return "other"
