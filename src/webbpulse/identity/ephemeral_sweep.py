"""Find the ephemeral e2e users an earlier run failed to delete.

A run creates its user on the reserved `e2e.invalid` domain with an `e2e-` local part and
deletes it at session end. When that delete fails the user outlives the run, and nothing
else ever names it. This module finds such users by that address alone, which is the one
marker every ephemeral user has carried since the routes shipped: registration validates
addresses with `EmailStr`, which refuses the `.invalid` domain, so no real account and no
durable e2e login can match it.

Candidates come from the product's hooks: an optional `list_ephemeral_users(created_before)`
hook where the product defines one, and otherwise a filtered scan of the package
`Repository` that `user_repository()` returns or wraps. A product whose users table is
reachable neither way gets `EphemeralSweepUnsupported`.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, Final

__all__ = [
    "EPHEMERAL_EMAIL_DOMAIN",
    "EPHEMERAL_EMAIL_PREFIX",
    "EPHEMERAL_SWEEP_DEFAULT_AGE",
    "EPHEMERAL_SWEEP_LIMIT",
    "EPHEMERAL_SWEEP_MINIMUM_AGE",
    "EphemeralSweepUnsupported",
    "created_at_of",
    "ephemeral_candidates",
    "is_ephemeral_email",
    "users_scan_source",
]

EPHEMERAL_EMAIL_DOMAIN: Final = "e2e.invalid"
"""The RFC 2606 reserved domain `webbpulse.e2e` creates every ephemeral user on."""

EPHEMERAL_EMAIL_PREFIX: Final = "e2e-"
"""The local part prefix `webbpulse.e2e.ephemeral_email` gives every ephemeral user."""

EPHEMERAL_SWEEP_DEFAULT_AGE: Final = timedelta(hours=3)
"""How old an ephemeral user must be before a sweep deletes it, when the caller names no age.

Long enough that no run still in progress loses its own user to another run's sweep."""

EPHEMERAL_SWEEP_MINIMUM_AGE: Final = timedelta(hours=1)
"""The floor on a requested age, so a caller cannot sweep users a live run is signed in as."""

EPHEMERAL_SWEEP_LIMIT: Final = 100
"""The most users one sweep deletes, so a single call stays well inside a Lambda timeout."""

_EPHEMERAL_EMAIL: Final = re.compile(
    rf"^{re.escape(EPHEMERAL_EMAIL_PREFIX)}[a-z0-9-]+@{re.escape(EPHEMERAL_EMAIL_DOMAIN)}$"
)

_WRAPPED_REPOSITORY_ATTRIBUTES: Final = ("repository", "_repository", "_repo", "shared")


class EphemeralSweepUnsupported(Exception):
    """The product's users table cannot be enumerated, so no sweep can run."""


def is_ephemeral_email(value: Any) -> bool:
    """Whether this address carries the ephemeral marker, `e2e-<run>@e2e.invalid`."""
    if not isinstance(value, str):
        return False
    return bool(_EPHEMERAL_EMAIL.match(value.strip().lower()))


def created_at_of(user: Mapping[str, Any]) -> datetime | None:
    """The row's `created_at` as an aware datetime, or `None` when it is missing or unreadable.

    Accepts an ISO 8601 string, a datetime, or epoch seconds. A naive value is read as UTC.
    """
    value = user.get("created_at")
    parsed: datetime | None = None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    elif isinstance(value, (int, float, Decimal)) and not isinstance(value, bool):
        try:
            parsed = datetime.fromtimestamp(float(value), tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if parsed is None:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def users_scan_source(user_repository: Any) -> Any | None:
    """The package `Repository` behind `user_repository()`, or `None` when there is none.

    The object itself when it can scan, otherwise the first wrapped repository that can,
    which covers the product repositories that hold a package `Repository` as an attribute.
    """
    if callable(getattr(user_repository, "iter_scan", None)):
        return user_repository
    for attribute in _WRAPPED_REPOSITORY_ATTRIBUTES:
        wrapped = getattr(user_repository, attribute, None)
        if wrapped is not None and callable(getattr(wrapped, "iter_scan", None)):
            return wrapped
    return None


def _email_of(user: Mapping[str, Any]) -> Any:
    """The row's address, from `email` or the lowercased index attribute."""
    return user.get("email") or user.get("email_lower")


def ephemeral_candidates(hooks: Any, *, created_before: datetime) -> Iterable[Mapping[str, Any]]:
    """Every ephemeral user row created before `created_before`, from the product's hooks.

    Every row is re-checked here whatever its source, so a product hook that returns too much
    cannot widen the sweep past the marker or the cutoff.

    Raises:
        EphemeralSweepUnsupported: When the hooks offer neither a listing hook nor a users
            table this module can scan.
    """
    listed = getattr(hooks, "list_ephemeral_users", None)
    if callable(listed):
        rows: Iterable[Mapping[str, Any]] = listed(created_before)
    else:
        try:
            repository = hooks.user_repository()
        except Exception as error:
            raise EphemeralSweepUnsupported("The product's hooks do not expose a users repository to sweep.") from error
        source = users_scan_source(repository)
        if source is None:
            raise EphemeralSweepUnsupported(
                "The product's users repository is not a package Repository, and its hooks "
                "define no list_ephemeral_users, so its ephemeral users cannot be enumerated."
            )
        from boto3.dynamodb.conditions import Attr

        marker = f"@{EPHEMERAL_EMAIL_DOMAIN}"
        rows = source.iter_scan(filter_expression=Attr("email").contains(marker) | Attr("email_lower").contains(marker))

    for row in rows:
        if not isinstance(row, Mapping):
            continue
        if not str(row.get("id", "") or "").strip():
            continue
        if not is_ephemeral_email(_email_of(row)):
            continue
        created_at = created_at_of(row)
        if created_at is None or created_at >= created_before:
            continue
        yield row
