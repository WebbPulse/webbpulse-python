"""Progressive lockout and the `login-attempts` record it is computed from.

Lockout protects one account by delaying the next attempt after consecutive password
failures; rate limiting, which protects the service, lives in `webbpulse.ratelimit`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final, Literal

from webbpulse.dynamodb import now_iso, ttl_in

if TYPE_CHECKING:  # pragma: no cover
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

LOGIN_ATTEMPTS_TABLE: Final = "login-attempts"

LOCKOUT_THRESHOLD: Final = 5

LOCKOUT_BASE_DELAY: Final = timedelta(seconds=1)

LOCKOUT_MAX_DELAY: Final = timedelta(minutes=15)

LOCKOUT_LOOKBACK: Final = timedelta(hours=24)

ATTEMPT_TTL: Final = timedelta(days=30)

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

    No field here holds a credential: not the password, not its hash, not a token.
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
    retry_at: datetime | None = None

    @property
    def locked(self) -> bool:
        """Whether a delay is currently in force."""
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
        """Return the most recent attempts for a key, newest first.

        Bounded: an account past `limit` consecutive failures is already at the delay cap,
        so reading further cannot change the answer.
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
    """Compute the delay in force from one account's recent attempts, newest first.

    Counts consecutive failures back from the newest, cleared by any success and skipping
    `locked` rows, and doubles the delay past the threshold up to `max_delay`. Attempts older
    than `lookback` are ignored, checked against the clock rather than the table's TTL.
    """
    moment = now or datetime.now(UTC)
    horizon = moment - lookback

    failures = 0
    newest_failure: datetime | None = None
    for attempt in attempts:
        parsed = _parse(attempt.attempted_at)
        if parsed is None or parsed < horizon:
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

    steps = min(failures - threshold, 32)
    delay = min(base_delay * (2**steps), max_delay)
    retry_at = newest_failure + delay
    if retry_at <= moment:
        return LockoutState(failures=failures)
    return LockoutState(failures=failures, retry_at=retry_at)


def _parse(value: str) -> datetime | None:
    """Parse a `now_iso` timestamp, returning `None` for anything unreadable.

    An unreadable row stops the count, failing toward permitting the attempt rather than
    locking an account out on a parse bug.
    """
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


class InMemoryLoginAttemptStore(LoginAttemptStore):
    """List-backed `LoginAttemptStore` with the same ordering contract as the table."""

    def __init__(self) -> None:
        """Start with no attempts and a monotonic tie-break sequence."""
        self._items: dict[str, list[tuple[int, LoginAttempt]]] = {}
        self._sequence = 0

    def record(self, attempt: LoginAttempt) -> None:
        """Append one attempt, tagged with its insertion order."""
        self._sequence += 1
        self._items.setdefault(attempt.identity_key, []).append((self._sequence, attempt))

    def recent(self, identity_key: str, *, limit: int = 50) -> list[LoginAttempt]:
        """Return the newest attempts first, tie-breaking equal timestamps on insertion order.

        A success sharing a timestamp with the failure before it must sort newer, or the
        failure count would not clear and a correct sign-in would stay locked out.
        """
        rows = self._items.get(identity_key, [])
        ordered = sorted(rows, key=lambda row: (row[1].attempted_at, row[0]), reverse=True)
        return [attempt for _, attempt in ordered[:limit]]


class DynamoLoginAttemptStore(LoginAttemptStore):
    """`LoginAttemptStore` over a `webbpulse.dynamodb.Repository`.

    Takes the repository rather than building one, so the caller owns the table name, the
    prefix and the region.
    """

    def __init__(self, repository: Repository) -> None:
        """Bind the store to a repository for the `login-attempts` table."""
        self._repo = repository

    def record(self, attempt: LoginAttempt) -> None:
        """Write one attempt row, filling in the timestamp and TTL when unset."""
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
        """Query one key's most recent attempts, newest first."""
        from boto3.dynamodb.conditions import Key

        page = self._repo.query(
            Key("identity_key").eq(identity_key),
            ascending=False,
            limit=limit,
        )
        return [_attempt_from_item(item) for item in page.items]


def _outcome(value: str) -> AttemptOutcome:
    """Read a stored outcome, treating anything unrecognised as a failure.

    A row written by a newer version during a rolling deploy must not fail the login.
    """
    if value == "success":
        return "success"
    if value == "locked":
        return "locked"
    return "failure"


def _attempt_from_item(item: Any) -> LoginAttempt:
    """Build a `LoginAttempt` from a stored item."""
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
    """Stamp the current time in `now_iso()`'s shape with millisecond precision."""
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def new_attempt(
    identity_key: str,
    outcome: AttemptOutcome,
    *,
    user_id: str = "",
    ip: str = "",
    user_agent: str = "",
) -> LoginAttempt:
    """Build one attempt row, stamped now and with the 30 day TTL already set.

    The range key carries milliseconds, unlike `now_iso()`: at one second resolution a
    success and the failure before it can share a timestamp and sort arbitrarily, which would
    leave the failure count uncleared for an account that just signed in correctly.
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
