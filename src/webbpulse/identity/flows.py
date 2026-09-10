"""The M2 flows: register, login, change password, refresh, logout, logout-all.

Section 2.1 splits routers from services and says the services hold "the flow logic, no
FastAPI imports". This module is that layer for M2. It imports no web framework, so every
decision below is reachable from a plain unit test with no client, no app and no transport,
which is what makes the negative paths cheap enough to write exhaustively.

`router.py` is the thin part: it parses a body, calls one method here, and renders the
result. Anything that decides *whether* something is allowed lives here.

## The rules that shape every method

**Enumeration resistance is structural, not a message.** Section 5.4 requires that a login
against an unknown address and a login with the wrong password be indistinguishable. Both
answer 401 with the identical body, and both spend one bcrypt verification, the real one
against the stored hash or the dummy one from `passwords.equalise_password_timing`. This is
why `login` has no early return for "no such user": the shape of the function is the
control.

**Register never says the email is taken.** It returns the same 200 either way. Section 5.4
specifies emailing the existing address instead, which is M3's job; this milestone gets the
non-disclosure right and records the missing email as a hook call the product can implement.

**Refusals from a hook are laundered into the same 401.** `may_authenticate` raising is the
product saying no: a disabled account, an unverified email. Its message is passed through
because a product writes it knowing what it discloses, but the login path still spends its
bcrypt round first, so a disabled account is not detectable by timing either.

**Every failure is recorded, and recording never fails the request.** Login attempts go to
the `login-attempts` table and to the structured log. A DynamoDB write that fails must not
turn a correct login into a 500, so the write is best-effort and the log line is not.
"""

from __future__ import annotations

import logging
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
from webbpulse.identity.passwords import (
    check_password,
    equalise_password_timing,
    normalise_password,
)
from webbpulse.identity.sessions import SessionService

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Mapping

    from webbpulse.identity.hooks import IdentityHooks
    from webbpulse.identity.service import TokenService
    from webbpulse.identity.settings import IdentitySettings
    from webbpulse.identity.storage import IdentityStores

__all__ = [
    "INVALID_CREDENTIALS_MESSAGE",
    "PASSWORD_CREDENTIAL_TYPE",
    "AuthResult",
    "IdentityFlows",
    "LoginRejected",
    "RateLimited",
]

_log = logging.getLogger(__name__)

#: The one message every failed login returns, whatever actually went wrong. Section 5.4.
#: A single constant rather than a literal at each `raise`, because the control is that the
#: strings are identical and two literals drift.
INVALID_CREDENTIALS_MESSAGE: Final = "Invalid email or password."

#: The `credential_type` range key for a bcrypt password in the `credentials` table.
PASSWORD_CREDENTIAL_TYPE: Final = "password"

#: What `on_user_created` is told about a registration through this flow.
REGISTRATION_VIA: Final = "password"


class LoginRejected(Exception):
    """A login, registration or password change was refused.

    Carries the message the caller renders and an `error_code` the frontend branches on,
    matching `AuthenticationRefused` and `PasswordRejected` so the router renders all three
    identically.
    """

    def __init__(
        self,
        message: str = INVALID_CREDENTIALS_MESSAGE,
        *,
        error_code: str = "INVALID_CREDENTIALS",
        status_code: int = 401,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code


class RateLimited(LoginRejected):
    """Progressive lockout is in effect for this account. Section 5.1.

    Distinct from a `webbpulse.ratelimit` refusal, which protects the service and is applied
    by a route dependency before this module is reached. This one protects one account
    against guessing and is decided here, because it depends on that account's own history.

    Answers 429 with `Retry-After`, and the message deliberately does not confirm that the
    account exists: a locked-out response for an address that has failed five times is
    itself weak evidence, which section 5.4 records as a residual leak of the same kind as
    the rate limit boundary.
    """

    def __init__(self, retry_after: int) -> None:
        super().__init__(
            "Too many failed attempts. Try again shortly.",
            error_code="TOO_MANY_ATTEMPTS",
            status_code=429,
        )
        self.retry_after = retry_after


@dataclass(frozen=True, slots=True)
class AuthResult:
    """A successful authentication: the access token and the refresh cookie to set.

    `refresh_token` is the plaintext, and it exists only to be written into a `Set-Cookie`.
    Nothing stores it, nothing logs it. The router is the only caller, and it puts the value
    straight into the cookie.
    """

    access_token: str
    expires_in: int
    user: Mapping[str, Any]
    refresh_token: str
    family_id: str
    #: Extra body fields a flow wants returned, such as `user_id` on a registration.
    extra: Mapping[str, Any] = field(default_factory=dict)


class IdentityFlows:
    """The M2 flow logic for one product.

    Built once per execution environment from settings, hooks, stores and a `TokenService`.
    Holds no request state, so it is safe to share, and every method takes the request's IP
    and user agent explicitly rather than reaching for a request object it cannot see.

    `now` is a parameter on the paths where time is part of the behaviour, so lockout decay
    and refresh expiry are testable without sleeping.
    """

    def __init__(
        self,
        settings: IdentitySettings,
        hooks: IdentityHooks,
        stores: IdentityStores,
        tokens: TokenService,
        *,
        attempts: LoginAttemptStore | None = None,
    ) -> None:
        self._settings = settings
        self._hooks = hooks
        self._stores = stores
        self._tokens = tokens
        self._attempts = attempts
        self._sessions = SessionService(settings, stores.require_refresh_tokens())

    @property
    def sessions(self) -> SessionService:
        """The session service, for a caller that needs the family lifecycle directly."""
        return self._sessions

    # ---- registration --------------------------------------------------------------

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

        Returns an `AuthResult` for a genuine new account. Returns **`None`** when the
        address already exists, which the router renders as the same 200 a real registration
        gets. That is section 5.4's requirement: the signup form must leak nothing, so the
        two cases have to be indistinguishable from outside.

        Returning `None` rather than raising is deliberate. An exception would tempt a
        caller into rendering something different, and the whole control is that it cannot.

        Password policy runs **before** the existence check, so a password that violates the
        policy is rejected for a taken address too. That is not a leak: the answer depends
        only on the password the caller just supplied, never on the address.

        Raises `LoginRejected` when registration is disabled, and `PasswordRejected` when the
        password fails section 5.6's policy.
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
            # Section 5.4: 200, and M3 emails the existing address to say somebody tried.
            # Spend a bcrypt round anyway, so the taken and free paths cost the same and the
            # non-disclosure holds against a clock as well as against a reader.
            equalise_password_timing(checked)
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

        _log.info(
            "Account registered.",
            extra={"event": "register.success", "user_id": user_id, "ip": ip},
        )

        if self._settings.email_verification_required:
            # The account exists but cannot sign in until M3's verification lands. Refusing
            # here rather than issuing a token is the honest reading of the setting: a
            # product that requires verification does not want an unverified session.
            raise LoginRejected(
                "Check your email to confirm your address before signing in.",
                error_code="EMAIL_VERIFICATION_REQUIRED",
                status_code=403,
            )

        return self._issue(user, ip=ip, user_agent=user_agent, extra={"user_id": user_id})

    # ---- login ---------------------------------------------------------------------

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

        The order of operations is the security control, so it is worth reading as a whole:

        1. **Lockout check** first, from the attempt history. A locked account never reaches
           bcrypt, which is what stops the lockout itself becoming a work amplifier.
        2. **Load the user**, which may be `None`.
        3. **Verify**, against the stored hash when there is one and against the dummy hash
           when there is not. There is no branch that skips this step.
        4. **Ask the product** whether this user may authenticate.
        5. **Record** the attempt, success or failure.

        Every refusal from steps 2, 3 and 4 raises the same `LoginRejected` with the same
        message, so no caller can render them differently even by accident.
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
        # `presented` is normalised the same way the stored hash was produced, or a password
        # containing a composed character stops verifying the day normalisation lands.
        presented = normalise_password(password)

        credential = None
        if user is not None:
            credential = self._stores.require_credentials().get(
                _user_id(user), PASSWORD_CREDENTIAL_TYPE
            )

        if user is None or credential is None or not credential.secret:
            # No early return above this line, deliberately. Section 5.3: both paths cost
            # one bcrypt verification, so "no such account" and "wrong password" have the
            # same timing shape as well as the same body.
            equalise_password_timing(presented)
            self._fail(identity, ip=ip, user_agent=user_agent, reason="unknown_or_no_credential")

        from webbpulse.security import needs_rehash, verify_password

        # `user` and `credential` are non-None here: `_fail` is `NoReturn`, so the branch
        # above cannot fall through.
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
            # The product said no: disabled, unverified, whatever its policy is. The bcrypt
            # round is already spent, so this refusal costs the same as a wrong password.
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
            # Section 5.6: upgrade the cost factor on login, which is the only moment the
            # plaintext is available to rehash with.
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
        return self._issue(user, ip=ip, user_agent=user_agent)

    # ---- change password -----------------------------------------------------------

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

        Requires the current password even though the caller already holds a valid access
        token. A token proves the session, not the person at the keyboard, and re-proving
        the password is what stops a stolen access token being upgraded into permanent
        control of the account.

        Revokes every family the caller can identify, because section 2.6 says a password
        change calls sign-out-everywhere: a change made in response to a suspected
        compromise is worthless if the attacker's session survives it.

        `keep_family_id` names the caller's own family, which is spared so that changing a
        password does not sign the user out of the tab they did it in. Passing nothing
        revokes everything including the caller's, which is the stricter behaviour and the
        right default for a reset rather than a change.

        Returns the number of refresh records revoked. Raises `LoginRejected` when the
        current password is wrong and `PasswordRejected` when the new one fails the policy.
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
        return revoked

    # ---- sessions ------------------------------------------------------------------

    def refresh(
        self,
        presented: str,
        *,
        ip: str = "",
        user_agent: str = "",
        now: datetime | None = None,
    ) -> AuthResult:
        """Rotate a refresh token and mint a new access token.

        Delegates the state machine to `SessionService.rotate` and turns its outcome into
        either an `AuthResult` or the one 401. Every refusal is the same 401 whatever the
        outcome was: the difference between an expired token and a detected reuse is an
        alarm for an operator, not information for whoever presented the token.

        Re-reads the user through `load_user_by_id` and re-runs `may_authenticate` on every
        rotation. That is the only revocation the design has: section 2.6 states plainly
        that a logout cannot invalidate an already-issued access token, so an account
        disabled mid-session stops being able to *renew*, and the ten-minute access token is
        the bound on how long the old one keeps working.
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
            # The family outlived the account. Revoke rather than leave a live family
            # pointing at a user that no longer exists.
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

        Tolerant of an unknown, expired or already-revoked token, because the caller's
        intent is to end up signed out and answering 401 to that is both unhelpful and a
        signal about whether the cookie they hold is live.
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

    def logout_all(self, user_id: str, *, ip: str = "", family_ids: list[str] | None = None) -> int:
        """Revoke every family for a user. The sign-out-everywhere button.

        See `SessionService.revoke_all_for_user` for why the family ids may have to come
        from the caller: `refresh-tokens` carries no user index by design.
        """
        revoked = self._revoke_families(user_id, family_ids=family_ids)
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

    # ---- internals -----------------------------------------------------------------

    def _issue(
        self,
        user: Mapping[str, Any],
        *,
        ip: str,
        user_agent: str,
        extra: Mapping[str, Any] | None = None,
    ) -> AuthResult:
        """Start a family and mint the first access token for it."""
        user_id = _user_id(user)
        issued = self._sessions.start_family(user_id, device=_device_class(user_agent), ip=ip)
        access = self._mint_access(user, session_id=issued.family_id)
        return AuthResult(
            access_token=access,
            expires_in=int(self._settings.access_token_ttl.total_seconds()),
            user=user,
            refresh_token=issued.token,
            family_id=issued.family_id,
            extra=dict(extra or {}),
        )

    def _mint_access(self, user: Mapping[str, Any], *, session_id: str) -> str:
        # `claims_for` supplies the product claims. `mint_access_token` drops any registered
        # claim a hook returns, so a hook cannot forge an issuer or extend a lifetime.
        return self._tokens.mint_access_token(
            _user_id(user),
            claims=self._hooks.claims_for(user),
            session_id=session_id,
        )

    def _revoke_families(
        self,
        user_id: str,
        *,
        keep_family_id: str = "",
        family_ids: list[str] | None = None,
    ) -> int:
        if family_ids is not None:
            targets = [family for family in family_ids if family]
            return self._sessions.revoke_all_for_user(
                user_id, family_ids=targets, except_family_id=keep_family_id
            )
        # No family list, so fall through to the store. Exact where the store can be, and
        # raising where it cannot be without scanning a production table. See
        # `SessionService.revoke_all_for_user`.
        return self._sessions.revoke_all_for_user(user_id, except_family_id=keep_family_id)

    def _lockout_state(self, identity: str, *, now: datetime) -> LockoutState:
        if self._attempts is None:
            # No attempt store configured, so there is no history to lock on. Permitting is
            # the right failure direction: lockout is a hardening measure, and a product
            # that has not wired the table should still be able to sign its users in.
            return LockoutState(failures=0)
        try:
            recent = self._attempts.recent(identity)
        except Exception:  # pragma: no cover - defensive, storage failures
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
        """Write one attempt row, best effort.

        Never raises. A failure to write the audit row must not turn a correct login into a
        500, and the structured log line has already carried the same event to CloudWatch,
        which section 5.7 requires precisely so the record survives a table problem.

        Written under both the email key and the IP key, which is what makes section 5.2's
        anomaly query possible: one email failing from many addresses, or many emails
        failing from one, are both a `Query` rather than a scan.
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
            except Exception:  # pragma: no cover - defensive, storage failures
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

        `NoReturn` rather than `None` so the type checker narrows after each call site: the
        code following `if user is None: self._fail(...)` genuinely has a non-None user, and
        saying so here is what keeps that from needing an assertion.

        `reason` reaches the log and never the response, which is the whole point: an
        operator can tell an unknown address from a wrong password, and the caller cannot.
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

    Email local parts are case sensitive by RFC, and every mail provider in practice ignores
    that. Matching case-insensitively is what users expect, and it must be done identically
    at registration and at login or an account becomes unreachable.
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


def _device_class(user_agent: str) -> str:
    """A coarse class, never a fingerprint. Section 4.2 and section 5.7.

    Enough to make an audit line readable and to notice that a session moved from a phone to
    a server, and deliberately not enough to identify a browser. A full user-agent string in
    a table with a thirty day TTL is tracking data with no purpose this design has.
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
