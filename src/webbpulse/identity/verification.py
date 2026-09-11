"""The single-use link primitive behind email verification and password reset.

One implementation for both flows, which differ only in purpose, TTL and template. Only
the token hash is stored, expiry is checked against the clock, and consumption is atomic.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final
from urllib.parse import quote, urlencode

from webbpulse.dynamodb import now_iso
from webbpulse.identity.storage import (
    IdentityTokenRecord,
    hash_token,
    is_expired,
    new_token,
)

if TYPE_CHECKING:  # pragma: no cover
    from webbpulse.identity.settings import IdentitySettings
    from webbpulse.identity.storage import IdentityTokenPurpose, IdentityTokenStore

__all__ = [
    "CONFIRMATION_FAILED_MESSAGE",
    "RESET_LINK_PATH",
    "VERIFY_LINK_PATH",
    "ConfirmationFailed",
    "IssuedLink",
    "LinkService",
    "describe_expiry",
]

_log = logging.getLogger(__name__)

CONFIRMATION_FAILED_MESSAGE: Final = "This link is no longer valid. Request a new one."

VERIFY_LINK_PATH: Final = "/verify-email"
RESET_LINK_PATH: Final = "/reset-password"

TOKEN_PARAM: Final = "token"


class ConfirmationFailed(Exception):
    """A presented link is unknown, expired, already used, or of the wrong purpose.

    One exception for all four, carrying one message. `reason` is for the log and is never
    rendered, since "already used" would confirm that a guessed value was a real token.
    """

    def __init__(self, reason: str) -> None:
        """Record the log-only reason behind the fixed caller-facing message."""
        super().__init__(CONFIRMATION_FAILED_MESSAGE)
        self.message = CONFIRMATION_FAILED_MESSAGE
        self.error_code = "INVALID_LINK"
        self.status_code = 400
        self.reason = reason


@dataclass(frozen=True, slots=True)
class IssuedLink:
    """A freshly minted link: the plaintext token and the URL to mail.

    `token` exists only to be mailed; the stored record holds its hash.
    """

    token: str
    url: str
    purpose: IdentityTokenPurpose
    user_id: str
    expires_at: int

    def expires_at_datetime(self) -> datetime:
        """The expiry as an aware UTC datetime."""
        return datetime.fromtimestamp(self.expires_at, tz=UTC)


class LinkService:
    """Issue and confirm the single-use links both email flows are built on.

    Holds no request state, so one instance per execution environment is correct.
    """

    def __init__(self, settings: IdentitySettings, store: IdentityTokenStore) -> None:
        """Bind the service to its settings and the `identity-tokens` store."""
        self._settings = settings
        self._store = store

    def issue(
        self,
        user_id: str,
        purpose: IdentityTokenPurpose,
        *,
        now: datetime | None = None,
    ) -> IssuedLink:
        """Mint a link for a user and write its hash.

        Does not revoke that user's outstanding links of the same purpose: `identity-tokens`
        carries no user index, and each outstanding link is still single use and short lived.
        """
        moment = now or datetime.now(UTC)
        ttl = self.ttl_for(purpose)
        token = new_token()
        expires_at = int((moment + ttl).timestamp())

        self._store.put(
            IdentityTokenRecord(
                token_hash=hash_token(token),
                purpose=purpose,
                user_id=user_id,
                created_at=now_iso(),
                expires_at=expires_at,
            )
        )
        _log.info(
            "Identity link issued.",
            extra={
                "event": (
                    "email.verification_sent"
                    if purpose == "verify_email"
                    else "password.reset_requested"
                ),
                "user_id": user_id,
                "purpose": purpose,
            },
        )
        return IssuedLink(
            token=token,
            url=self.link_for(purpose, token),
            purpose=purpose,
            user_id=user_id,
            expires_at=expires_at,
        )

    def ttl_for(self, purpose: IdentityTokenPurpose) -> timedelta:
        """The lifetime for a purpose: 24 hours to verify, 1 hour to reset.

        A reset link is the credential that changes a password, so its window is the window
        in which a compromised mailbox is a compromised account.
        """
        return (
            self._settings.email_verification_ttl
            if purpose == "verify_email"
            else self._settings.password_reset_ttl
        )

    def link_for(self, purpose: IdentityTokenPurpose, token: str) -> str:
        """Build the URL to mail, pointing at the frontend rather than at the API.

        A page rather than a state-changing `GET`, so a mail scanner prefetching the link
        cannot burn it, and so a reset can land on a form that collects the new password.
        """
        base = self._settings.frontend_base_url.rstrip("/")
        path = VERIFY_LINK_PATH if purpose == "verify_email" else RESET_LINK_PATH
        if not token:
            return f"{base}{path}"
        query = urlencode({TOKEN_PARAM: token}, quote_via=quote)
        return f"{base}{path}?{query}"

    def page_for(self, purpose: IdentityTokenPurpose) -> str:
        """Build the bare frontend page URL for a purpose, carrying no token.

        For notification emails: mailing a live reset token to somebody who did not ask for
        one would make every "your password changed" notice a working password reset.
        """
        return self.link_for(purpose, "")

    def confirm(
        self,
        presented: str,
        purpose: IdentityTokenPurpose,
        *,
        now: datetime | None = None,
    ) -> IdentityTokenRecord:
        """Consume a presented link and return its record, or raise `ConfirmationFailed`.

        The order is the control: look up by hash, check purpose and expiry before consuming
        so a misdirected link is not burned, consume atomically, then re-check on the
        consumed record. Every failure raises the same exception with the same message.
        """
        moment = now or datetime.now(UTC)
        if not presented:
            raise ConfirmationFailed("empty")

        token_hash = hash_token(presented)
        existing = self._store.get(token_hash)
        if existing is None:
            raise ConfirmationFailed("unknown")
        if existing.purpose != purpose:
            raise ConfirmationFailed("wrong_purpose")
        if existing.consumed_at:
            raise ConfirmationFailed("already_consumed")
        if is_expired(existing.expires_at, now=moment):
            raise ConfirmationFailed("expired")

        consumed = self._store.consume(token_hash, consumed_at=now_iso())
        if consumed is None:
            raise ConfirmationFailed("consumed_concurrently")
        if consumed.purpose != purpose:  # pragma: no cover
            raise ConfirmationFailed("wrong_purpose")
        if is_expired(consumed.expires_at, now=moment):  # pragma: no cover
            raise ConfirmationFailed("expired")

        _log.info(
            "Identity link confirmed.",
            extra={
                "event": "email.verified" if purpose == "verify_email" else "password.reset_used",
                "user_id": consumed.user_id,
                "purpose": purpose,
            },
        )
        return consumed

    def log_refusal(self, exc: ConfirmationFailed, purpose: IdentityTokenPurpose) -> None:
        """Log why a confirmation was refused, at the one place the reason is allowed out."""
        _log.info(
            "Identity link refused.",
            extra={"event": "email.link_refused", "purpose": purpose, "reason": exc.reason},
        )


def describe_expiry(ttl: timedelta) -> str:
    """Render a link's lifetime as a human phrase for the email body.

    Relative rather than absolute, so no timezone is implied, and hours are preferred right
    up to two days so a 24 hour window reads back as "24 hours".
    """
    seconds = int(ttl.total_seconds())
    if seconds >= 172800 and seconds % 86400 == 0:
        return f"{seconds // 86400} days"
    if seconds >= 3600:
        hours = seconds // 3600
        return "1 hour" if hours == 1 else f"{hours} hours"
    minutes = max(1, seconds // 60)
    return "1 minute" if minutes == 1 else f"{minutes} minutes"


def constant_time_token_compare(left: str, right: str) -> bool:
    """Compare two token hashes in constant time, via `secrets.compare_digest`.

    The lookup path is keyed by hash and has no comparison to make; this exists so a caller
    holding both hashes finds the right primitive rather than reaching for `==`.
    """
    return secrets.compare_digest(left, right)
