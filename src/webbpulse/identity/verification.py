"""The single-use link primitive behind email verification and password reset.

Section 2.6 of `docs/identity-standard.md` says the two flows are the same primitive: "a
single-use, time-limited, signed link". This module is that primitive, once, and the two
flows in `flows.py` differ only in a purpose, a TTL, a template and what confirming one
does.

Writing it once is the point. The two flows are close enough that a second implementation
would look correct and differ in exactly the place that matters: whether the token is
compared in constant time, whether expiry is checked in code as well as by the table's TTL,
whether consumption is atomic. Those three are the whole security of the mechanism.

## What is stored, and what is mailed

The token is 256 bits from a CSPRNG, base64url. **Only its SHA-256 is stored.** The email
carries the raw value and nothing else does, so a read of `identity-tokens` cannot be turned
into a working link. That is the same reasoning `refresh-tokens` uses, and the same
`hash_token` implements it.

The tokens are high-entropy random values, so the hash is a plain SHA-256 rather than
bcrypt. There is nothing to brute force in 256 bits, and bcrypt's cost would be paid on the
click path for no gain. M1 decision 2 recorded the identical argument for refresh tokens.

## Expiry is checked twice, and the table's TTL is not one of the checks

`webbpulse.dynamodb.ttl_in` says in its own docstring that DynamoDB deletes on its own
schedule, "typically within a couple of days". So an expired row stays readable long after
it expired, and a flow that trusted the TTL to remove it would honour a verification link a
day and a half after it lapsed. `consume` checks `expires_at` against the clock, every time,
and the TTL is storage reclamation only.

## Consumption is atomic, and a consumed link is refused

`IdentityTokenStore.consume` is one conditional `UpdateItem` returning the prior state, so
two clicks on the same link race and exactly one wins. That matters more for reset than for
verification: two concurrent resets both succeeding would let a slow attacker's window
overlap the owner's.

## Every refusal is the same refusal

`ConfirmationFailed` carries no reason the caller can see. Unknown, expired, already used
and wrong purpose are one message, because the difference between them is information about
somebody else's token: "already used" told to a caller holding a guessed token confirms the
guess was a real token. The reason reaches the log, where an operator can read it.

## Purpose is checked positively

A row carries `purpose`, and `confirm` asserts the purpose it wanted rather than accepting
whatever the row says. Without that, one table holding both purposes means a verification
link is a valid reset link: click the one that arrives on registration, present it to the
reset endpoint, and set a password on an account you do not own. That is the same
token-confusion class the standard's threat model names for JWTs, and the answer is the
same, which is that the verifier asserts the type rather than reading it.
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

if TYPE_CHECKING:  # pragma: no cover - typing only
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

#: The one message any failed confirmation returns. A constant rather than a literal at each
#: raise, for the reason `INVALID_CREDENTIALS_MESSAGE` is one: the control is that the
#: strings are identical, and two literals drift.
CONFIRMATION_FAILED_MESSAGE: Final = "This link is no longer valid. Request a new one."

#: Where a link points on the **frontend**, not on the API.
#:
#: The standard's route table has `GET /api/auth/verify-email/{token}` on the API, and this
#: package mails a frontend URL instead. See `LinkService.link_for` for why.
VERIFY_LINK_PATH: Final = "/verify-email"
RESET_LINK_PATH: Final = "/reset-password"

#: The query parameter the token arrives in on the frontend link.
TOKEN_PARAM: Final = "token"


class ConfirmationFailed(Exception):
    """A presented link is unknown, expired, already used, or of the wrong purpose.

    One exception for all four, carrying one message. `reason` is for the log and is never
    rendered: telling a caller that a token they presented was "already used" confirms that
    the value they hold was once a real token, which is exactly what a caller who guessed it
    wants to know.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(CONFIRMATION_FAILED_MESSAGE)
        self.message = CONFIRMATION_FAILED_MESSAGE
        self.error_code = "INVALID_LINK"
        self.status_code = 400
        self.reason = reason


@dataclass(frozen=True, slots=True)
class IssuedLink:
    """A freshly minted link: the plaintext token and the URL to mail.

    `token` exists only to be put in a URL and mailed. Nothing stores it, nothing logs it,
    and the record written to the table holds its hash.
    """

    token: str
    url: str
    purpose: IdentityTokenPurpose
    user_id: str
    expires_at: int

    def expires_at_datetime(self) -> datetime:
        return datetime.fromtimestamp(self.expires_at, tz=UTC)


class LinkService:
    """Issue and confirm the single-use links both email flows are built on.

    Holds no request state. Built once per execution environment from settings and the
    `identity-tokens` store, alongside `SessionService` and for the same reason.
    """

    def __init__(self, settings: IdentitySettings, store: IdentityTokenStore) -> None:
        self._settings = settings
        self._store = store

    # ---- issuing -------------------------------------------------------------------

    def issue(
        self,
        user_id: str,
        purpose: IdentityTokenPurpose,
        *,
        now: datetime | None = None,
    ) -> IssuedLink:
        """Mint a link for a user and write its hash.

        Does **not** revoke that user's outstanding links of the same purpose. See
        `M3 decisions` in the standard: `identity-tokens` carries no user index, adding one
        would cost a write on the click path to serve the issue path, and the exposure it
        would close is a link the user themselves asked for that expires in an hour anyway.
        A user who asks for three reset links can use whichever arrives first, and each is
        still single use.
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
            # No token, no hash, no address. Section 5.7: no event carries a token, hashed
            # or otherwise, and a hash in a log is a working lookup key into the table.
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
        """Section 4.3: 24 hours to verify, 1 hour to reset.

        The asymmetry is deliberate and worth stating. A verification link arrives when the
        user is at the keyboard and can wait a day for a mail client to sync. A reset link
        is the credential that changes a password, so its window is the window in which a
        compromised mailbox is a compromised account, and an hour is short enough that the
        mailbox has to be compromised now rather than at some point in the past day.
        """
        return (
            self._settings.email_verification_ttl
            if purpose == "verify_email"
            else self._settings.password_reset_ttl
        )

    def link_for(self, purpose: IdentityTokenPurpose, token: str) -> str:
        """The URL to mail, pointing at the **frontend** rather than at the API.

        The standard's section 2.3 route table lists `GET /api/auth/verify-email/{token}` on
        the API, and this mails `<frontend_base_url>/verify-email?token=...` instead. Both
        are consistent with the design and this is the better one, for three reasons:

        1. **A reset link has to land on a form.** There is no password in the link, so the
           API cannot complete a reset from a `GET`; something has to collect the new
           password. Mailing the frontend for reset and the API for verification would give
           the two flows different shapes for no reason.
        2. **A `GET` that changes state is prefetched.** Mail clients and link scanners
           follow links in mail to check them for malware, and a verification endpoint that
           consumes its token on `GET` is consumed by the scanner before the user clicks.
           Landing on a page that then `POST`s is what keeps a scanner from burning the
           link.
        3. **The frontend already owns the post-confirmation experience**: where to send the
           user next, what to show while it works, how to render a failure. An API redirect
           would put that routing in the package, where it cannot know it.

        The token goes in a query parameter rather than a path segment because a path
        segment is what a router logs as a route, and `urlencode` is what keeps a base64url
        `-` or `_` from needing thought.
        """
        base = self._settings.frontend_base_url.rstrip("/")
        path = VERIFY_LINK_PATH if purpose == "verify_email" else RESET_LINK_PATH
        if not token:
            return f"{base}{path}"
        query = urlencode({TOKEN_PARAM: token}, quote_via=quote)
        return f"{base}{path}?{query}"

    def page_for(self, purpose: IdentityTokenPurpose) -> str:
        """The bare frontend page for a purpose, carrying no token.

        For the two notification emails, which point a reader at "reset your password" as an
        action to start rather than a link to follow. Mailing a live reset token to somebody
        who did not ask for one would make every "your password changed" notice a working
        password reset, which is the opposite of what a security notice should be.
        """
        return self.link_for(purpose, "")

    # ---- confirming ----------------------------------------------------------------

    def confirm(
        self,
        presented: str,
        purpose: IdentityTokenPurpose,
        *,
        now: datetime | None = None,
    ) -> IdentityTokenRecord:
        """Consume a presented link and return its record, or raise `ConfirmationFailed`.

        The order is the security control:

        1. **Hash the presented value** and look up by hash. The plaintext is never
           compared to anything, because there is nothing stored to compare it to.
        2. **Read the record** to check the purpose and the expiry, before consuming. A
           consume-first order would burn a valid verification link that was presented to
           the reset endpoint by mistake.
        3. **Consume atomically.** The conditional write is what makes the link single use,
           and the read above is advisory: two clients that both pass step 2 race here and
           exactly one wins.
        4. **Re-check the purpose on the consumed record**, because step 2 read a row that
           step 3 re-read, and trusting the first read would make the check advisory too.

        Every failure raises the same exception with the same message.
        """
        moment = now or datetime.now(UTC)
        if not presented:
            raise ConfirmationFailed("empty")

        token_hash = hash_token(presented)
        existing = self._store.get(token_hash)
        if existing is None:
            raise ConfirmationFailed("unknown")
        if existing.purpose != purpose:
            # Token confusion: a verification link presented to the reset endpoint. Refused
            # without consuming, so the real link keeps working.
            raise ConfirmationFailed("wrong_purpose")
        if existing.consumed_at:
            raise ConfirmationFailed("already_consumed")
        if is_expired(existing.expires_at, now=moment):
            raise ConfirmationFailed("expired")

        consumed = self._store.consume(token_hash, consumed_at=now_iso())
        if consumed is None:
            # Lost the race with a concurrent click, or consumed between the read and here.
            raise ConfirmationFailed("consumed_concurrently")
        if consumed.purpose != purpose:  # pragma: no cover - defensive, checked above too
            raise ConfirmationFailed("wrong_purpose")
        if is_expired(consumed.expires_at, now=moment):  # pragma: no cover - checked above
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
    """A human phrase for a link's lifetime, for the email body.

    "24 hours" and "1 hour" rather than an absolute timestamp, because an absolute time in
    an email is in whichever timezone the sender picked and is wrong for most readers. A
    relative window is correct for everyone and needs no timezone at all.

    Hours are preferred right up to two days, so the standard's 24 hour verification window
    reads back as "24 hours" rather than as "1 day". They mean the same thing and the first
    is the one section 4.3 uses, which is what a support conversation will quote.
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
    """`secrets.compare_digest` on two token hashes.

    Not used on the lookup path, which is a dict or a `GetItem` keyed by the hash and so has
    no comparison to make constant time. It is here for a caller that has both hashes in
    hand, and it exists so that anybody adding such a path finds the right primitive rather
    than reaching for `==`.
    """
    return secrets.compare_digest(left, right)
