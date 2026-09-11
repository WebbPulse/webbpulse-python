"""Refresh families: issue, rotate, detect reuse, revoke. The heart of M2.

Section 2.6 of `docs/identity-standard.md` calls this "the flow that most repays care" and
specifies it exactly. This module is that specification made executable, kept out of the
router so the state machine can be tested without a request.

## A family is one login

It has a `family_id`, a user, a device class and a generation counter. Each refresh token is
256 bits from a CSPRNG and **only its SHA-256 hash is stored**, so a read of the table cannot
be turned into a working session. Rotation writes the successor and marks the presented
token consumed, recording `successor_hash` on it.

## The state machine, in full

`rotate` is a total function over six states. Naming them is the point: reuse detection is
more subtly stateful than it looks, and a flow written as a chain of `if` statements
inevitably collapses two of these into one.

| Presented token is | Outcome |
| --- | --- |
| current and unconsumed | rotated: successor minted, generation + 1 |
| consumed **inside** the grace window | replayed: the same successor is returned again |
| consumed **outside** the grace window | **reuse**: the whole family is revoked, 401 |
| revoked | 401, no further revocation to do |
| expired, or past the absolute cap | 401, family revoked |
| unknown | 401, nothing to revoke |

## The grace window, and the benign case it protects

Concurrent refresh is real and benign: two browser tabs both notice an expiring access token
and both refresh. A naive implementation punishes it, because the second call sees a consumed
token and revokes a correct session, logging the user out.

So a consumed token replayed within `refresh_reuse_grace` (10 seconds by default) returns the
**same successor** the first call minted, rather than revoking. The successor hash is stored
on the consumed record for exactly this purpose. Beyond the window a replay is theft.

The cost of the grace is honest and worth stating: an attacker who steals a cookie and
replays it within ten seconds of the victim's own refresh gets the same successor the victim
got, so both hold a live token until the next rotation. The window is a setting so a product
can set it to zero and take the stricter behaviour, and the threat model in section 5.9
already records that an attacker who refreshes before the victim wins that race regardless.

**The replay returns the successor hash, not the successor token.** A hash cannot be turned
back into a token, so a replay inside the grace window cannot re-mint the cookie value the
first call set. It mints a *new* refresh token, rotating the family again from the same
successor generation, which is what keeps both tabs holding a token that works. That is the
one place this implementation goes past what section 2.6 spells out, and the alternative,
storing the plaintext successor so it can be handed out twice, would defeat the entire reason
only hashes are stored.

## Why the consume is one conditional write

`RefreshTokenStore.consume` is a single `UpdateItem` with a `ConditionExpression` and
`ReturnValues="ALL_OLD"`. Read-then-write races: two concurrent refreshes both read an
unconsumed record, both write, both succeed, and the reuse detection the whole session design
rests on never fires. The condition is what makes exactly one of them win, and the loser's
`None` is what routes it into the grace-or-reuse branch.

## Absolute cap

A family carries `family_started_at`, and a rotation past `refresh_absolute_ttl` from it is
refused however active the session has been. That is what stops an attacker holding a working
family forever by refreshing it. The rolling `refresh_token_ttl` is the per-token deadline;
the absolute cap is the per-family one, and both are checked in code rather than trusted to
the table's TTL sweep.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final, Literal

from webbpulse.dynamodb import now_iso, ttl_at
from webbpulse.identity.storage import (
    RefreshTokenRecord,
    RefreshTokenStore,
    hash_token,
    is_expired,
    new_token,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from webbpulse.identity.settings import IdentitySettings

__all__ = [
    "IssuedRefresh",
    "RotationOutcome",
    "RotationResult",
    "SessionService",
]

_log = logging.getLogger(__name__)

#: Every way `rotate` can end. A closed set rather than a bool, because the router answers
#: three of these differently and a caller branching on `is None` cannot tell reuse from an
#: unknown token, which is the difference between paging somebody and not.
type RotationOutcome = Literal["rotated", "replayed", "reuse", "expired", "revoked", "unknown"]

#: The `device` value written when the caller supplies no user agent. A coarse class, never
#: a fingerprint: section 4.2 says so explicitly, and a fingerprint in this table would be
#: tracking data with a thirty day TTL and no purpose the design has.
UNKNOWN_DEVICE: Final = "unknown"


@dataclass(frozen=True, slots=True)
class IssuedRefresh:
    """A freshly minted refresh token and the family it belongs to.

    `token` is the **plaintext**, and it exists only long enough to reach `set_cookie`.
    Nothing stores it, nothing logs it, and the record written to the table carries only its
    hash.
    """

    token: str
    family_id: str
    user_id: str
    generation: int
    expires_at: int


@dataclass(frozen=True, slots=True)
class RotationResult:
    """What `rotate` decided, and the new token when there is one."""

    outcome: RotationOutcome
    issued: IssuedRefresh | None = None
    #: The family that was involved, when one was identifiable. Empty for an unknown token.
    family_id: str = ""
    user_id: str = ""
    #: How many records `revoke_family` marked, for the audit line. Zero when none was.
    revoked: int = 0

    @property
    def ok(self) -> bool:
        """Whether the caller should mint an access token and set a new cookie."""
        return self.issued is not None


class SessionService:
    """Issues, rotates and revokes refresh families for one product.

    Holds settings and a store, and no request state, so one instance per execution
    environment is correct and a test builds one per case cheaply.

    Every method takes an optional `now` so the state machine can be driven across the grace
    boundary and the absolute cap without sleeping. Production passes nothing.
    """

    def __init__(self, settings: IdentitySettings, store: RefreshTokenStore) -> None:
        self._settings = settings
        self._store = store

    # ---- issuing -------------------------------------------------------------------

    def start_family(
        self,
        user_id: str,
        *,
        device: str = "",
        ip: str = "",
        now: datetime | None = None,
    ) -> IssuedRefresh:
        """Begin a new family. One login, generation 1.

        `device` is a coarse user-agent class and `ip` is the address the first token was
        seen from. Both are for the audit trail: nothing in the rotation path compares them,
        deliberately, because binding a session to an IP breaks every mobile user who moves
        between networks and binding it to a user agent breaks every browser update.
        """
        moment = now or datetime.now(UTC)
        return self._mint(
            family_id=uuid.uuid4().hex,
            user_id=user_id,
            generation=1,
            device=device or UNKNOWN_DEVICE,
            ip=ip,
            family_started_at=moment,
            now=moment,
        )

    def _mint(
        self,
        *,
        family_id: str,
        user_id: str,
        generation: int,
        device: str,
        ip: str,
        family_started_at: datetime,
        now: datetime,
    ) -> IssuedRefresh:
        token = new_token()
        # The rolling window, capped by the absolute one. A token minted on day 89 of a
        # 90 day cap expires in one day, not thirty: without the `min` the last rotation
        # before the cap would issue a token outliving the family it belongs to.
        rolling = now + self._settings.refresh_token_ttl
        absolute = family_started_at + self._settings.refresh_absolute_ttl
        expires_at = ttl_at(min(rolling, absolute))

        self._store.put(
            RefreshTokenRecord(
                token_hash=hash_token(token),
                family_id=family_id,
                user_id=user_id,
                generation=generation,
                created_at=now_iso(),
                expires_at=expires_at,
                device=device,
                ip_first_seen=ip,
                # Carried on every generation so the cap survives without a second table.
                # A family whose first record has been reclaimed by TTL is a family past
                # its rolling window anyway, so there is nothing to read back from.
                family_started_at=_iso(family_started_at),
            )
        )
        return IssuedRefresh(
            token=token,
            family_id=family_id,
            user_id=user_id,
            generation=generation,
            expires_at=expires_at,
        )

    # ---- rotation ------------------------------------------------------------------

    def rotate(
        self,
        presented: str,
        *,
        ip: str = "",
        now: datetime | None = None,
    ) -> RotationResult:
        """Consume a presented refresh token and mint its successor, or refuse.

        The whole state machine, in the order the states have to be checked. The order is
        not arbitrary:

        1. **Unknown** first, because a forged token must not reach a conditional write that
           could create a row for it.
        2. **Revoked** before expired, because a revoked token in a family already killed by
           reuse detection should not be reported as an ordinary expiry.
        3. **Expired** and the **absolute cap** before the consume, because consuming an
           expired token would mark it used and lose the ability to tell a later replay of
           it from a fresh presentation.
        4. The **conditional consume**, which is the only atomic step and the one that
           decides between rotation and the grace-or-reuse branch.

        Never raises for an invalid token. Every refusal is a `RotationResult` the caller
        renders as one identical 401, because the difference between "expired" and "reuse"
        is a log line and an alarm, not something to tell whoever presented the token.
        """
        moment = now or datetime.now(UTC)
        token_hash = hash_token(presented)
        record = self._store.get(token_hash)

        if record is None:
            return RotationResult(outcome="unknown")

        if record.revoked:
            # Already dead. Nothing further to revoke, and re-revoking a family on every
            # replay of a token from it would turn one theft into an endless stream of
            # `session.reuse_detected` events for an operator to page on.
            return RotationResult(
                outcome="revoked", family_id=record.family_id, user_id=record.user_id
            )

        if is_expired(record.expires_at, now=moment) or self._past_absolute_cap(record, moment):
            # The family is finished either way, so it is revoked rather than left to the
            # TTL sweep: a sibling token from the same family may still be inside its own
            # rolling window, and leaving it live would let an expired session be resumed
            # from a token the user never rotated.
            revoked = self._store.revoke_family(record.family_id)
            return RotationResult(
                outcome="expired",
                family_id=record.family_id,
                user_id=record.user_id,
                revoked=revoked,
            )

        successor = self._mint(
            family_id=record.family_id,
            user_id=record.user_id,
            generation=record.generation + 1,
            device=record.device or UNKNOWN_DEVICE,
            ip=record.ip_first_seen or ip,
            family_started_at=self._family_started_at(record),
            now=moment,
        )

        previous = self._store.consume(
            token_hash,
            successor_hash=hash_token(successor.token),
            consumed_at=_iso(moment),
        )
        if previous is not None:
            return RotationResult(
                outcome="rotated",
                issued=successor,
                family_id=record.family_id,
                user_id=record.user_id,
            )

        # The condition failed, so somebody else consumed this token between the `get` above
        # and the write. Re-read to tell the benign concurrent case from theft. The successor
        # just minted is now an orphan: it is a valid row in a live family, which is
        # harmless (nobody holds its plaintext, and it expires on its own), and removing it
        # would need a delete that could race with the very rotation that won.
        return self._after_failed_consume(token_hash, moment)

    def _after_failed_consume(self, token_hash: str, moment: datetime) -> RotationResult:
        """The grace-or-reuse branch, entered only when the conditional consume lost."""
        current = self._store.get(token_hash)
        if current is None:
            # Deleted between the two reads. Nothing to identify, nothing to revoke.
            return RotationResult(outcome="unknown")

        if current.revoked:
            return RotationResult(
                outcome="revoked", family_id=current.family_id, user_id=current.user_id
            )

        consumed_at = _parse(current.consumed_at)
        grace = self._settings.refresh_reuse_grace
        within_grace = (
            consumed_at is not None
            and grace > timedelta(0)
            and moment - consumed_at <= grace
            and bool(current.successor_hash)
        )

        if not within_grace:
            # Reuse. The family is compromised: somebody holds a token that was already
            # spent, and the legitimate holder has moved on to the successor. Revoking the
            # whole family rather than the one token is the point, because a stolen sibling
            # would otherwise stay live.
            revoked = self._store.revoke_family(current.family_id)
            _log.warning(
                "Refresh token reuse detected; the family has been revoked.",
                extra={
                    "event": "session.reuse_detected",
                    "family_id": current.family_id,
                    "user_id": current.user_id,
                    "generation": current.generation,
                    "revoked_records": revoked,
                },
            )
            return RotationResult(
                outcome="reuse",
                family_id=current.family_id,
                user_id=current.user_id,
                revoked=revoked,
            )

        # Inside the grace window: two tabs refreshed at once and this is the loser. It gets
        # a working token rather than a logout, minted from the successor's generation.
        #
        # A new token rather than the successor itself, because only the successor's *hash*
        # is stored and a hash cannot be turned back into a token. Section 2.6 describes
        # returning "the same successor"; storing the plaintext to make that literal would
        # give up the property that a table read yields no working session, which is worth
        # far more than the extra row this costs.
        successor_record = self._store.get(current.successor_hash)
        if successor_record is None:
            # The successor is gone, so there is nothing to continue from. Treated as reuse
            # rather than as a rotation, because a missing successor is not a state a
            # correct client produces.
            revoked = self._store.revoke_family(current.family_id)
            return RotationResult(
                outcome="reuse",
                family_id=current.family_id,
                user_id=current.user_id,
                revoked=revoked,
            )

        issued = self._mint(
            family_id=current.family_id,
            user_id=current.user_id,
            generation=successor_record.generation,
            device=current.device or UNKNOWN_DEVICE,
            ip=current.ip_first_seen,
            family_started_at=self._family_started_at(current),
            now=moment,
        )
        _log.info(
            "Concurrent refresh inside the grace window; replaying rather than revoking.",
            extra={
                "event": "session.refreshed",
                "family_id": current.family_id,
                "user_id": current.user_id,
                "replayed": True,
            },
        )
        return RotationResult(
            outcome="replayed",
            issued=issued,
            family_id=current.family_id,
            user_id=current.user_id,
        )

    # ---- revocation ----------------------------------------------------------------

    def revoke_family(self, family_id: str) -> int:
        """Revoke every generation of one family. What logout calls.

        Logout revokes the family and not the single token, because revoking one token would
        leave a stolen sibling live, which is precisely the situation logout exists to end.
        """
        return self._store.revoke_family(family_id)

    def revoke_presented(self, presented: str) -> RotationResult:
        """Revoke the family a presented token belongs to, without rotating it.

        The logout path. Deliberately tolerant: a logout presenting an unknown, expired or
        already-revoked token still succeeds from the caller's point of view, because the
        user's intent is to end up signed out and answering 401 to that is unhelpful and
        tells an attacker whether the cookie they hold is live.
        """
        record = self._store.get(hash_token(presented))
        if record is None:
            return RotationResult(outcome="unknown")
        revoked = self._store.revoke_family(record.family_id)
        return RotationResult(
            outcome="revoked",
            family_id=record.family_id,
            user_id=record.user_id,
            revoked=revoked,
        )

    def family_of(self, presented: str) -> str:
        """The family id a presented refresh token belongs to, or `""` for an unknown one.

        Lets sign-out-everywhere name the caller's own family without rotating or revoking
        it first, since `refresh-tokens` is keyed by token hash rather than by user.
        """
        if not presented:
            return ""
        record = self._store.get(hash_token(presented))
        return record.family_id if record is not None else ""

    def revoke_all_for_user(
        self,
        user_id: str,
        *,
        family_ids: list[str] | None = None,
        except_family_id: str = "",
    ) -> int:
        """Revoke every family for a user. Sign out everywhere, and what a reset will call.

        `family_ids` exists because `refresh-tokens` carries no user index by design: the hot
        path is the token hash, and indexing the cold path would cost a write on every
        rotation to serve an operation that runs on a password change. M1 recorded that
        `DynamoRefreshTokenStore.revoke_all_for_user` raises rather than scanning a
        production table, and this is the resolution that decision deferred to M2.

        A caller that knows the families revokes them by id, which is the cheap path and the
        one the logout-all route takes with the family from the presented cookie plus
        whatever the product tracks. A caller that passes none falls through to the store,
        which is exact where the store can be (the in-memory one) and raises where it cannot
        be without a scan. Raising is the honest answer: silently revoking only the current
        family would report success for a sign-out that did not happen.
        """
        if family_ids is not None:
            return sum(
                self._store.revoke_family(family_id)
                for family_id in family_ids
                if family_id != except_family_id
            )
        return self._store.revoke_all_for_user(user_id, except_family_id=except_family_id)

    # ---- helpers -------------------------------------------------------------------

    def _family_started_at(self, record: RefreshTokenRecord) -> datetime:
        """When the family began, for the absolute cap.

        Falls back to `created_at` when the field is absent, which is what a record written
        by an earlier version of this module during a rolling deploy looks like. The fallback
        makes the cap measure from this generation rather than from the login, which is
        wrong in the permissive direction for at most one rotation and never denies a
        correct session.
        """
        parsed = _parse(record.family_started_at) or _parse(record.created_at)
        return parsed or datetime.now(UTC)

    def _past_absolute_cap(self, record: RefreshTokenRecord, moment: datetime) -> bool:
        started = self._family_started_at(record)
        return moment >= started + self._settings.refresh_absolute_ttl


def _iso(moment: datetime) -> str:
    """`now_iso`'s format for an explicit moment, so stored timestamps are one shape."""
    return moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse(value: str) -> datetime | None:
    """Parse a stored timestamp, or `None` for anything unreadable.

    Never raises. An unreadable `consumed_at` means the grace window cannot be established,
    and the caller treats that as outside the window, which fails toward revoking a family
    rather than toward admitting a replayed token.
    """
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
