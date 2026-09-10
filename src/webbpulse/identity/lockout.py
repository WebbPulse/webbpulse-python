"""Progressive lockout and the `login-attempts` record it is computed from.

Section 5.1 of `docs/identity-standard.md` separates two mechanisms that are constantly
confused, and this module implements the second of them:

- **Rate limiting protects the service.** It is `webbpulse.ratelimit`, it counts requests
  per IP and per email, and the router wires it as a dependency. Nothing here.
- **Lockout protects an account.** It counts *consecutive failed password attempts* for one
  account and makes the next attempt wait. That is this module.

## Progressive, not binary, and the reason matters

A hard lock is a denial-of-service tool handed to the attacker: anyone who knows an address
can lock its owner out by failing five times. So after `LOCKOUT_THRESHOLD` consecutive
failures the account gets a **delay** that doubles from one second to a fifteen-minute cap,
and any success clears it. The account is never unusable; it is only slow, and only for
whoever is guessing.

The delay is enforced by refusing the attempt while it is in force, not by sleeping. Sleeping
holds a Lambda execution environment open for up to fifteen minutes, which is a cost the
attacker chooses and we pay, and concurrency is the scarcest thing an identity function has.
Refusing costs nothing and delays the guesser exactly as much.

**Passkey and OAuth logins are not blocked by this**, per section 5.1: neither is subject to
the guessing attack the lock exists to stop, and blocking them turns a password attack into
a total account outage. M5 and M6 own those flows and neither will call `check_lockout`.

## The table, and why it is queried rather than counted on the user record

`login-attempts` is hash `identity_key` (`email#<lower>` or `ip#<addr>`), range `attempted_at`,
TTL `expires_at` at 30 days. The lockout state is derived by reading the most recent attempts
for an email and counting the failures since the last success.

The alternative, a `failed_login_count` counter on the user record, is what section 4.2 lists
as an added user attribute, and it is cheaper to read. It is not what this computes from, for
two reasons. A counter needs a write on the success path as well as the failure path, on the
hot path of every login, to reset itself. And the attempt rows have to be written anyway for
the audit trail in section 5.7 and the anomaly signal in section 5.2, so deriving from them
costs one query rather than one query plus a counter that can disagree with them.

## Every deadline is checked against the clock, never against the TTL

`webbpulse.dynamodb.ttl_in` says it in its own docstring: DynamoDB deletes expired items on
its own schedule, typically within a couple of days. An attempt row outside the lookback
window is therefore still readable, and the window is applied in code. TTL is storage
reclamation and is never an access control.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final, Literal

from webbpulse.dynamodb import now_iso, ttl_in

if TYPE_CHECKING:  # pragma: no cover - typing only
    from webbpulse.dynamodb import Repository

__all__ = [
    "ATTEMPT_TTL",
    "LOCKOUT_BASE_DELAY",
    "LOCKOUT_LOOKBACK",
    "LOCKOUT_MAX_DELAY",
    "LOCKOUT_THRESHOLD",
    "LOGIN_ATTEMPTS_TABLE",
    "AttemptOutcome",
    "DynamoLoginAttemptStore",
    "InMemoryLoginAttemptStore",
    "LockoutState",
    "LoginAttempt",
    "LoginAttemptStore",
    "email_key",
    "ip_key",
    "lockout_state",
    "new_attempt",
]

#: Logical table name, prefixed by `webbpulse.dynamodb.table_name`. Hyphenated to match the
#: estate's naming, as `refresh-tokens` and `identity-tokens` already are.
LOGIN_ATTEMPTS_TABLE: Final = "login-attempts"

#: Consecutive failures before any delay applies. Five, per section 5.1.
LOCKOUT_THRESHOLD: Final = 5

#: The delay after the threshold is first crossed. It doubles per additional failure.
LOCKOUT_BASE_DELAY: Final = timedelta(seconds=1)

#: The cap the doubling stops at. Fifteen minutes, per section 5.1.
LOCKOUT_MAX_DELAY: Final = timedelta(minutes=15)

#: How far back the failure count looks. Longer than the maximum delay by a wide margin, so
#: a patient attacker cannot wait out the window and start again at zero, and far shorter
#: than the row TTL, so the query is bounded.
LOCKOUT_LOOKBACK: Final = timedelta(hours=24)

#: How long an attempt row is kept. Thirty days, per section 4.3. The audit trail and the
#: credential-stuffing anomaly signal in section 5.2 are what want the long tail; the
#: lockout computation itself only ever looks back `LOCKOUT_LOOKBACK`.
ATTEMPT_TTL: Final = timedelta(days=30)

#: What an attempt row records. `locked` is a refusal that never reached a verification, so
#: it is deliberately distinct from `failure`: counting it as a failure would let a locked
#: account extend its own lockout every time the owner retried.
type AttemptOutcome = Literal["success", "failure", "locked"]


def email_key(email: str) -> str:
    """The `identity_key` for an email address. Lowercased, as the `users` GSI keys it."""
    return f"email#{email.strip().lower()}"


def ip_key(address: str) -> str:
    """The `identity_key` for a source address."""
    return f"ip#{address}"


@dataclass(frozen=True, slots=True)
class LoginAttempt:
    """One row of `login-attempts`.

    **No field here holds a credential.** Not the password, not its hash, not a token. That
    is section 5.7's rule for every audit event and it is enforced by there being nowhere to
    put one.
    """

    identity_key: str
    attempted_at: str
    outcome: AttemptOutcome
    user_id: str = ""
    ip: str = ""
    user_agent: str = ""
    expires_at: int = 0


@dataclass(frozen=True, slots=True)
class LockoutState:
    """The delay in force for an account, and the count it was derived from."""

    failures: int
    #: When the next attempt may be made. `None` when no delay is in force.
    retry_at: datetime | None = None

    @property
    def locked(self) -> bool:
        return self.retry_at is not None

    def retry_after_seconds(self, *, now: datetime | None = None) -> int:
        """Whole seconds until the next attempt is permitted, for a `Retry-After` header."""
        if self.retry_at is None:
            return 0
        delta = self.retry_at - (now or datetime.now(UTC))
        return max(int(delta.total_seconds() + 0.999), 0)


class LoginAttemptStore(ABC):
    """The `login-attempts` table: hash `identity_key`, range `attempted_at`, TTL 30 days."""

    @abstractmethod
    def record(self, attempt: LoginAttempt) -> None:
        """Append one attempt. Never overwrites: the range key is the timestamp."""

    @abstractmethod
    def recent(self, identity_key: str, *, limit: int = 50) -> list[LoginAttempt]:
        """The most recent attempts for a key, newest first.

        Bounded rather than unbounded, because the only question asked of them is how many
        failures precede the most recent success, and an account with fifty consecutive
        failures is already at the fifteen-minute cap. Reading further would cost pages of
        a hot query to refine a number that cannot change the answer.
        """


def lockout_state(
    attempts: list[LoginAttempt],
    *,
    now: datetime | None = None,
    threshold: int = LOCKOUT_THRESHOLD,
    base_delay: timedelta = LOCKOUT_BASE_DELAY,
    max_delay: timedelta = LOCKOUT_MAX_DELAY,
    lookback: timedelta = LOCKOUT_LOOKBACK,
) -> LockoutState:
    """The delay in force, from the recent attempts for one account, newest first.

    Counts consecutive `failure` outcomes back from the newest, stopping at the first
    `success`, which is what "cleared by any success" means. A `locked` outcome is skipped
    rather than counted: it is a refusal that never reached a password verification, and
    counting it would let a locked-out owner extend their own lockout by retrying.

    Attempts older than `lookback` are ignored, checked against the clock rather than
    trusting the table's TTL to have removed them.

    The delay doubles per failure past the threshold and stops at `max_delay`::

        5 failures -> 1s, 6 -> 2s, 7 -> 4s, ... 14 -> 512s, 15+ -> 900s (the cap)

    `retry_at` is measured from the **newest counted failure**, not from now, so the delay
    elapses in real time rather than restarting on each read.
    """
    moment = now or datetime.now(UTC)
    horizon = moment - lookback

    failures = 0
    newest_failure: datetime | None = None
    for attempt in attempts:
        parsed = _parse(attempt.attempted_at)
        if parsed is None or parsed < horizon:
            # Older than the window, or a timestamp this code cannot read. Both stop the
            # count: rows are newest first, so everything after this is older still.
            break
        if attempt.outcome == "success":
            break
        if attempt.outcome == "locked":
            continue
        failures += 1
        if newest_failure is None:
            newest_failure = parsed

    if failures < threshold or newest_failure is None:
        return LockoutState(failures=failures)

    # Doubling, capped. `2 ** (failures - threshold)` is 1 at the threshold itself, so the
    # first delay is exactly `base_delay`. The exponent is capped before the shift so a
    # thousand failures cannot produce an integer with a thousand bits.
    steps = min(failures - threshold, 32)
    delay = min(base_delay * (2**steps), max_delay)
    retry_at = newest_failure + delay
    if retry_at <= moment:
        # The delay has already elapsed. The failures still count toward the next one, which
        # is what makes the backoff progressive rather than resetting on every wait.
        return LockoutState(failures=failures)
    return LockoutState(failures=failures, retry_at=retry_at)


def _parse(value: str) -> datetime | None:
    """Parse a `now_iso` timestamp. `None` for anything unreadable rather than raising.

    A row written by an older version of this package, or by hand in the console, must not
    turn a login into a 500. An unreadable timestamp stops the count, which fails toward
    permitting the attempt rather than toward locking an account out on a parse bug.
    """
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


class InMemoryLoginAttemptStore(LoginAttemptStore):
    """List-backed `LoginAttemptStore` with the same ordering contract as the table."""

    def __init__(self) -> None:
        self._items: dict[str, list[tuple[int, LoginAttempt]]] = {}
        # A monotonic tie-break for rows sharing a one second timestamp. See `recent`.
        self._sequence = 0

    def record(self, attempt: LoginAttempt) -> None:
        self._sequence += 1
        self._items.setdefault(attempt.identity_key, []).append((self._sequence, attempt))

    def recent(self, identity_key: str, *, limit: int = 50) -> list[LoginAttempt]:
        rows = self._items.get(identity_key, [])
        # Newest first, matching `ScanIndexForward=False` on the real query.
        #
        # Sorted on `(timestamp, insertion order)` rather than on the timestamp alone.
        # `now_iso()` has one second resolution, so a failure and the retry that follows it
        # commonly share a timestamp, and sorting on that alone leaves their relative order
        # to `sorted`'s stability over an arbitrary insertion sequence. That matters here
        # rather than being a cosmetic detail: `lockout_state` counts consecutive failures
        # back from the newest row and stops at the first success, so a success ordered
        # behind the failure it followed would leave the count uncleared and lock an account
        # that had just signed in correctly.
        #
        # The real table has the same resolution and the same exposure. There the range key
        # is `attempted_at`, and DynamoDB orders equal range keys by nothing in particular,
        # so the sequence number here is modelling a weakness rather than papering over one.
        # It is recorded in the M2 notes as the reason `attempted_at` should gain
        # sub-second precision.
        ordered = sorted(rows, key=lambda row: (row[1].attempted_at, row[0]), reverse=True)
        return [attempt for _, attempt in ordered[:limit]]


class DynamoLoginAttemptStore(LoginAttemptStore):
    """`LoginAttemptStore` over a `webbpulse.dynamodb.Repository`.

    Takes the repository rather than building one, exactly as the stores in `storage` do, so
    the caller owns the table name, the prefix and the region.
    """

    def __init__(self, repository: Repository) -> None:
        self._repo = repository

    def record(self, attempt: LoginAttempt) -> None:
        item: dict[str, Any] = {
            "identity_key": attempt.identity_key,
            "attempted_at": attempt.attempted_at or now_iso(),
            "outcome": attempt.outcome,
            "user_id": attempt.user_id,
            "ip": attempt.ip,
            "user_agent": attempt.user_agent,
            "expires_at": attempt.expires_at or ttl_in(ATTEMPT_TTL.total_seconds()),
        }
        self._repo.put(item)

    def recent(self, identity_key: str, *, limit: int = 50) -> list[LoginAttempt]:
        from boto3.dynamodb.conditions import Key

        page = self._repo.query(
            Key("identity_key").eq(identity_key),
            # Newest first. The lockout question is about the tail of the history, and
            # scanning forward would read every attempt ever made to find it.
            ascending=False,
            limit=limit,
        )
        return [_attempt_from_item(item) for item in page.items]


def _outcome(value: str) -> AttemptOutcome:
    """Read an outcome defensively.

    An unrecognised value is read as a failure rather than rejected. A row written by a
    newer version of this package during a rolling deploy is a normal condition, and failing
    the login on it would be an outage caused by a deploy overlap.
    """
    if value == "success":
        return "success"
    if value == "locked":
        return "locked"
    return "failure"


def _attempt_from_item(item: Any) -> LoginAttempt:
    outcome = str(item.get("outcome", "failure"))
    return LoginAttempt(
        identity_key=str(item["identity_key"]),
        attempted_at=str(item.get("attempted_at", "")),
        outcome=_outcome(outcome),
        user_id=str(item.get("user_id", "")),
        ip=str(item.get("ip", "")),
        user_agent=str(item.get("user_agent", "")),
        expires_at=int(item.get("expires_at", 0)),
    )


def _stamp() -> str:
    """`now_iso()`'s shape with millisecond precision. See `new_attempt`."""
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def new_attempt(
    identity_key: str,
    outcome: AttemptOutcome,
    *,
    user_id: str = "",
    ip: str = "",
    user_agent: str = "",
) -> LoginAttempt:
    """One attempt row, stamped now and with the 30 day TTL already set.

    The timestamp carries **milliseconds**, unlike `now_iso()` elsewhere in the package.
    `attempted_at` is the range key this table is ordered by, and `lockout_state` counts
    consecutive failures back from the newest row and stops at the first success. At one
    second resolution a failure and the successful retry that followed it commonly share a
    timestamp, their order becomes arbitrary, and a success ordered behind its own preceding
    failure leaves the count uncleared, locking an account that just signed in correctly.
    Milliseconds make that collision rare enough not to matter, and the format still sorts
    lexicographically, which is what a range key needs.
    """
    return LoginAttempt(
        identity_key=identity_key,
        attempted_at=_stamp(),
        outcome=outcome,
        user_id=user_id,
        ip=ip,
        user_agent=user_agent,
        expires_at=ttl_in(ATTEMPT_TTL.total_seconds()),
    )
