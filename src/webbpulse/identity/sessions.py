"""Refresh families: issue, rotate, detect reuse, revoke.

A family is one login, identified by `family_id`, and only token hashes are stored. Reuse
of a spent token outside the grace window revokes the whole family.
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

if TYPE_CHECKING:  # pragma: no cover
    from webbpulse.identity.settings import IdentitySettings

__all__ = [
    "IssuedRefresh",
    "PresentedSession",
    "RotationOutcome",
    "RotationResult",
    "SessionService",
]

_log = logging.getLogger(__name__)

type RotationOutcome = Literal["rotated", "replayed", "reuse", "expired", "revoked", "unknown"]

UNKNOWN_DEVICE: Final = "unknown"


@dataclass(frozen=True, slots=True)
class IssuedRefresh:
    """A freshly minted refresh token and the family it belongs to.

    `token` is the plaintext and exists only long enough to reach `set_cookie`; the stored
    record carries only its hash. `device` is the label the family was started under, which every generation carries.
    `auth_time` is the family's last authentication in epoch seconds, for the access token
    minted alongside this generation.
    """

    token: str
    family_id: str
    user_id: str
    generation: int
    expires_at: int
    device: str = ""
    auth_time: int = 0


@dataclass(frozen=True, slots=True)
class PresentedSession:
    """A live refresh family, as `SessionService.peek` read it without touching it.

    `auth_time` is the family's last authentication in epoch seconds: the login, or a
    later step-up.
    """

    user_id: str
    family_id: str
    auth_time: int


@dataclass(frozen=True, slots=True)
class RotationResult:
    """What `rotate` decided, and the new token when there is one."""

    outcome: RotationOutcome
    issued: IssuedRefresh | None = None
    family_id: str = ""
    user_id: str = ""
    revoked: int = 0

    @property
    def ok(self) -> bool:
        """Whether the caller should mint an access token and set a new cookie."""
        return self.issued is not None


class SessionService:
    """Issues, rotates and revokes refresh families for one product.

    Holds no request state. Every method takes an optional `now` so the state machine can be
    driven across the grace boundary and the absolute cap without sleeping.
    """

    def __init__(self, settings: IdentitySettings, store: RefreshTokenStore) -> None:
        """Bind the service to its settings and refresh token store."""
        self._settings = settings
        self._store = store

    def start_family(
        self,
        user_id: str,
        *,
        device: str = "",
        ip: str = "",
        now: datetime | None = None,
        auth_time: int | None = None,
    ) -> IssuedRefresh:
        """Begin a new family for one login, at generation 1.

        `device` and `ip` are recorded for the audit trail only: nothing in the rotation path
        compares them, since binding a session to either breaks legitimate users. `auth_time`
        defaults to the moment the family starts, which is the login.
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
            auth_time=int(moment.timestamp()) if auth_time is None else auth_time,
        )

    def record_reauthentication(self, family_id: str, auth_time: int) -> int:
        """Carry a step-up's `auth_time` into the family, so the next refresh keeps it.

        Best effort and never raises: a store that cannot update a family, or one that
        fails, leaves refreshes carrying the login's `auth_time`, which only ever asks for
        another step-up sooner. Returns how many rows changed.
        """
        if not family_id:
            return 0
        try:
            return self._store.set_family_auth_time(family_id, auth_time)
        except NotImplementedError:
            _log.warning(
                "This store cannot record a step-up on a refresh family.",
                extra={"event": "session.reauth_unsupported", "family_id": family_id},
            )
        except Exception:
            _log.warning(
                "Could not record a step-up on a refresh family.",
                extra={"event": "session.reauth_write_failed", "family_id": family_id},
                exc_info=True,
            )
        return 0

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
        auth_time: int,
    ) -> IssuedRefresh:
        """Write one generation of a family and return its plaintext token.

        The rolling window is capped by the absolute one, so no token outlives its family.
        """
        token = new_token()
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
                family_started_at=_iso(family_started_at),
                auth_time=auth_time,
            )
        )
        return IssuedRefresh(
            token=token,
            family_id=family_id,
            user_id=user_id,
            generation=generation,
            expires_at=expires_at,
            device=device,
            auth_time=auth_time,
        )

    def rotate(
        self,
        presented: str,
        *,
        ip: str = "",
        now: datetime | None = None,
    ) -> RotationResult:
        """Consume a presented refresh token and mint its successor, or refuse.

        States are checked in order: unknown, revoked, expired or past the absolute cap, then
        the conditional consume that decides rotation from the grace-or-reuse branch. Never
        raises: every refusal is a result the caller renders as one identical 401.
        """
        moment = now or datetime.now(UTC)
        token_hash = hash_token(presented)
        record = self._store.get(token_hash)

        if record is None:
            return RotationResult(outcome="unknown")

        if record.revoked:
            return RotationResult(outcome="revoked", family_id=record.family_id, user_id=record.user_id)

        if is_expired(record.expires_at, now=moment) or self._past_absolute_cap(record, moment):
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
            auth_time=self._auth_time(record),
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

        return self._after_failed_consume(token_hash, moment)

    def _after_failed_consume(self, token_hash: str, moment: datetime) -> RotationResult:
        """Decide between a benign concurrent refresh and theft, after the consume lost.

        Entered only when the conditional consume failed, meaning another request spent this
        token first.
        """
        current = self._store.get(token_hash)
        if current is None:
            return RotationResult(outcome="unknown")

        if current.revoked:
            return RotationResult(outcome="revoked", family_id=current.family_id, user_id=current.user_id)

        consumed_at = _parse(current.consumed_at)
        grace = self._settings.refresh_reuse_grace
        within_grace = (
            consumed_at is not None
            and grace > timedelta(0)
            and moment - consumed_at <= grace
            and bool(current.successor_hash)
        )

        if not within_grace:
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

        successor_record = self._store.get(current.successor_hash)
        if successor_record is None:
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
            auth_time=max(self._auth_time(current), self._auth_time(successor_record)),
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

    def peek(self, presented: str, *, now: datetime | None = None) -> PresentedSession | None:
        """Read the live family a presented refresh token belongs to, writing nothing.

        For a browser request that must know who is signed in without spending the cookie,
        such as the OAuth authorization screen. Returns `None` for an unknown, revoked,
        expired, past-cap, consumed or rotated-out token. A spent token is refused rather
        than treated as reuse: this path never rotates, never revokes and never updates a
        row, so it cannot trip reuse detection or race a concurrent refresh.
        """
        if not presented:
            return None
        moment = now or datetime.now(UTC)
        record = self._store.get(hash_token(presented))
        if record is None or record.revoked:
            return None
        if record.is_consumed or record.successor_hash:
            return None
        if is_expired(record.expires_at, now=moment) or self._past_absolute_cap(record, moment):
            return None
        return PresentedSession(
            user_id=record.user_id,
            family_id=record.family_id,
            auth_time=self._auth_time(record),
        )

    def revoke_family(self, family_id: str) -> int:
        """Revoke every generation of one family, which is what logout calls.

        The family and not the single token, since revoking one token would leave a stolen
        sibling live.
        """
        return self._store.revoke_family(family_id)

    def revoke_presented(self, presented: str) -> RotationResult:
        """Revoke the family a presented token belongs to, without rotating it.

        Deliberately tolerant: an unknown, expired or already-revoked token still reports
        success, so a logout never tells an attacker whether their cookie is live.
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

    def revoke_device(self, user_id: str, device: str) -> int:
        """Revoke every family of one user started under one `device` label.

        What revoking an authorized OAuth client calls. A store that cannot enumerate a
        user's families reports nothing revoked rather than failing the call, exactly as
        `revoke_all_for_user` does.
        """
        try:
            return self._store.revoke_all_for_device(user_id, device)
        except NotImplementedError:
            _log.warning(
                "This store cannot enumerate a user's families, so no family was revoked by device.",
                extra={"event": "session.revoke_device_unsupported", "user_id": user_id, "device": device},
            )
            return 0

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
        """Revoke every family for a user: sign out everywhere.

        A caller that already knows the `family_ids` takes the cheap path and revokes each
        one directly. Passing none falls through to the store, which queries the user index on
        `refresh-tokens`. A store built against a table with no such index reports nothing
        revoked rather than failing the call, and those other sessions stay signed in.
        """
        if family_ids is not None:
            return sum(
                self._store.revoke_family(family_id) for family_id in family_ids if family_id != except_family_id
            )
        try:
            return self._store.revoke_all_for_user(user_id, except_family_id=except_family_id)
        except NotImplementedError:
            _log.warning(
                "This store cannot enumerate a user's families, so no other session was revoked.",
                extra={
                    "event": "session.revoke_all_unsupported",
                    "user_id": user_id,
                    "except_family_id": except_family_id,
                },
            )
            return 0

    def _family_started_at(self, record: RefreshTokenRecord) -> datetime:
        """Read when the family began, for the absolute cap.

        Falls back to `created_at` for a record written before the field existed, which is
        permissive for at most one rotation and never denies a correct session.
        """
        parsed = _parse(record.family_started_at) or _parse(record.created_at)
        return parsed or datetime.now(UTC)

    def _auth_time(self, record: RefreshTokenRecord) -> int:
        """The family's last authentication, carried from `record` and never bumped.

        Falls back to when the family began for a record written before `auth_time` existed,
        which is exactly the login for a family that never stepped up.
        """
        if record.auth_time > 0:
            return record.auth_time
        return int(self._family_started_at(record).timestamp())

    def _past_absolute_cap(self, record: RefreshTokenRecord, moment: datetime) -> bool:
        """Whether this family has outlived `refresh_absolute_ttl`."""
        started = self._family_started_at(record)
        return moment >= started + self._settings.refresh_absolute_ttl


def _iso(moment: datetime) -> str:
    """Format an explicit moment as `now_iso` does, so stored timestamps are one shape."""
    return moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse(value: str) -> datetime | None:
    """Parse a stored timestamp, returning `None` for anything unreadable.

    Never raises. An unreadable `consumed_at` reads as outside the grace window, failing
    toward revoking a family rather than admitting a replayed token.
    """
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
