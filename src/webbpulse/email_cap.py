"""Outbound email send caps on the shared `<prefix>-rate-limits` table.

`EmailSendCap.check` counts one send against up to three clock-aligned counters, per
recipient within a tenant, per tenant, and a global daily ceiling for the app, in one
conditional write: a single `UpdateItem` when one counter is on, one `TransactWriteItems`
when several are. A counter already at its limit fails the write, so nothing is counted and
the send is skipped. Every limit defaults to off, which makes `check` a no-op with no
DynamoDB call.

Mail comes in two categories with separate counters and separate limits. `transactional`
is identity mail a user cannot sign in without (verification, reset, MFA), and its limits
must be at least the `standard` ones, so a notification storm can never exhaust the
allowance a locked out user needs.

A capped send logs a structured WARNING with `event="email.capped"` and emits an
`EmailCapped` count. A DynamoDB failure fails open, logs `email_cap_failed_open=True` and
emits `EmailCapFailedOpen`. Nothing here raises into a request.
"""

from __future__ import annotations

import hashlib
import logging
import math
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from webbpulse.dynamodb import ConditionFailed, Repository, TransactionCanceled
from webbpulse.metrics import emit, metrics_enabled_from_env
from webbpulse.ratelimit import RATE_LIMIT_TABLE, TTL_ATTRIBUTE

__all__ = [
    "DAY_SECONDS",
    "EMAIL_CAPPED_METRIC",
    "EMAIL_CAP_FAILED_OPEN_METRIC",
    "EMAIL_METRICS_NAMESPACE",
    "CapScope",
    "EmailCapDecision",
    "EmailCapLimits",
    "EmailCapPolicy",
    "EmailCategory",
    "EmailSendCap",
    "recipient_hash",
]

_log = logging.getLogger(__name__)

DAY_SECONDS: Final = 86_400

EMAIL_METRICS_NAMESPACE: Final = "WebbPulse/Email"

EMAIL_CAPPED_METRIC: Final = "EmailCapped"

EMAIL_CAP_FAILED_OPEN_METRIC: Final = "EmailCapFailedOpen"

_TTL_GRACE_SECONDS: Final = 60

_COUNT_ATTRIBUTE: Final = "count"

type EmailCategory = Literal["standard", "transactional"]

type CapScope = Literal["recipient", "tenant", "daily"]


@dataclass(frozen=True, slots=True)
class EmailCapLimits:
    """The limits for one category of mail. `None` turns a counter off.

    `per_recipient` counts sends to one address within one tenant per window, `per_tenant`
    counts every send for one tenant per window, and `daily` counts every send in the
    category for the whole app per UTC day.
    """

    per_recipient: int | None = None
    per_recipient_window_seconds: int = DAY_SECONDS
    per_tenant: int | None = None
    per_tenant_window_seconds: int = DAY_SECONDS
    daily: int | None = None

    def __post_init__(self) -> None:
        """Refuse a limit or window below one, which would block every send."""
        for name in ("per_recipient", "per_tenant", "daily"):
            value = getattr(self, name)
            if value is not None and value < 1:
                raise ValueError(f"EmailCapLimits.{name} must be at least 1 or None, got {value}.")
        for name in ("per_recipient_window_seconds", "per_tenant_window_seconds"):
            value = getattr(self, name)
            if value < 1:
                raise ValueError(f"EmailCapLimits.{name} must be at least 1, got {value}.")

    @property
    def enabled(self) -> bool:
        """Whether any counter in this category is on."""
        return any(value is not None for value in (self.per_recipient, self.per_tenant, self.daily))


@dataclass(frozen=True, slots=True)
class EmailCapPolicy:
    """Limits for standard and transactional mail. The default caps nothing.

    Every transactional limit must be unset or at least its standard counterpart, and a
    transactional limit left unset is uncapped, so identity mail always has the larger
    allowance.
    """

    standard: EmailCapLimits = field(default_factory=EmailCapLimits)
    transactional: EmailCapLimits = field(default_factory=EmailCapLimits)

    def __post_init__(self) -> None:
        """Refuse a transactional limit lower than the standard one."""
        for name in ("per_recipient", "per_tenant", "daily"):
            standard = getattr(self.standard, name)
            transactional = getattr(self.transactional, name)
            if standard is not None and transactional is not None and transactional < standard:
                raise ValueError(
                    f"EmailCapPolicy.transactional.{name} ({transactional}) is below the standard "
                    f"limit ({standard}). Transactional mail needs the higher allowance, or None."
                )

    def limits_for(self, category: EmailCategory) -> EmailCapLimits:
        """The limits for one category."""
        return self.transactional if category == "transactional" else self.standard


@dataclass(frozen=True, slots=True)
class EmailCapDecision:
    """The outcome of one cap check.

    `allowed` is the answer. `exceeded` names the counters at their limit when a send is
    refused, `failed_open` is set when DynamoDB failed and the send was allowed anyway, and
    `counted` is False when no counter was on for the category.
    """

    allowed: bool
    category: EmailCategory
    exceeded: tuple[CapScope, ...] = ()
    failed_open: bool = False
    counted: bool = True


@dataclass(frozen=True, slots=True)
class _Counter:
    """One counter a send is checked against."""

    scope: CapScope
    key: str
    limit: int
    window_end: int


def recipient_hash(address: str) -> str:
    """A stable, non-reversible key for one address: SHA-256 of the trimmed lowercase form.

    The counter rows then hold no address, and `Alice@Example.com` counts with
    `alice@example.com`.
    """
    return hashlib.sha256(address.strip().lower().encode()).hexdigest()[:32]


class EmailSendCap(Repository):
    """Send caps over the `<prefix>-rate-limits` table, one conditional write per send.

    Rows share the table with `webbpulse.ratelimit` under keys starting `<namespace>#`, which
    defaults to `email`, and carry the same `expires_at` TTL.
    """

    logical_name = RATE_LIMIT_TABLE

    def __init__(
        self,
        policy: EmailCapPolicy | None = None,
        *,
        namespace: str = "email",
        metrics_namespace: str = EMAIL_METRICS_NAMESPACE,
        metrics_enabled: bool | None = None,
        **kwargs: Any,
    ) -> None:
        """Bind the cap to a policy and a key namespace.

        `metrics_enabled=None` gates the metrics on `metrics_enabled_from_env()` at emit time.
        The remaining keyword arguments are `Repository`'s.
        """
        super().__init__(**kwargs)
        self.policy = policy or EmailCapPolicy()
        self.namespace = namespace
        self.metrics_namespace = metrics_namespace
        self.metrics_enabled = metrics_enabled

    def check(
        self,
        recipient: str,
        *,
        tenant: str = "-",
        category: EmailCategory = "standard",
        purpose: str = "unknown",
        now: float | None = None,
    ) -> EmailCapDecision:
        """Count one send to `recipient` for `tenant` and decide whether it may go.

        `tenant` is whatever the app partitions by, such as a workspace id, and `purpose`
        only labels the log line. A refused send is not counted, and a DynamoDB failure
        allows the send with `failed_open` set.
        """
        current = time.time() if now is None else now
        counters = self._counters(recipient, tenant=tenant, category=category, now=current)
        if not counters:
            return EmailCapDecision(allowed=True, category=category, counted=False)

        try:
            exceeded = self._count(counters)
        except Exception as exc:
            return self._failed_open(category, exc)

        if not exceeded:
            return EmailCapDecision(allowed=True, category=category)

        self._report_capped(recipient, tenant=tenant, category=category, purpose=purpose, exceeded=exceeded)
        return EmailCapDecision(allowed=False, category=category, exceeded=exceeded)

    def _counters(self, recipient: str, *, tenant: str, category: EmailCategory, now: float) -> list[_Counter]:
        """The counters that are on for this category, keyed for the current windows."""
        limits = self.policy.limits_for(category)
        base = f"{self.namespace}#{category}"
        counters: list[_Counter] = []
        if limits.per_recipient is not None:
            start, end = _window(now, limits.per_recipient_window_seconds)
            key = f"{base}#rcpt#{tenant}#{recipient_hash(recipient)}#{start}"
            counters.append(_Counter("recipient", key, limits.per_recipient, end))
        if limits.per_tenant is not None:
            start, end = _window(now, limits.per_tenant_window_seconds)
            counters.append(_Counter("tenant", f"{base}#tenant#{tenant}#{start}", limits.per_tenant, end))
        if limits.daily is not None:
            start, end = _window(now, DAY_SECONDS)
            counters.append(_Counter("daily", f"{base}#daily#{start}", limits.daily, end))
        return counters

    def _update_arguments(self, counter: _Counter) -> dict[str, Any]:
        """The conditional increment for one counter, shared by both write paths."""
        return {
            "update_expression": "ADD #c :one SET #ttl = if_not_exists(#ttl, :ttl)",
            "expression_names": {"#c": _COUNT_ATTRIBUTE, "#ttl": TTL_ATTRIBUTE},
            "expression_values": {":one": 1, ":ttl": counter.window_end + _TTL_GRACE_SECONDS, ":limit": counter.limit},
            "condition": "attribute_not_exists(#c) OR #c < :limit",
        }

    def _count(self, counters: Sequence[_Counter]) -> tuple[CapScope, ...]:
        """Apply every increment in one write and return the scopes that were at their limit.

        Raises anything other than a failed condition, which the caller turns into a fail
        open.
        """
        if len(counters) == 1:
            counter = counters[0]
            try:
                self.update({"pk": counter.key}, **self._update_arguments(counter))
            except ConditionFailed:
                return (counter.scope,)
            return ()

        actions = [self.update_action({"pk": counter.key}, **self._update_arguments(counter)) for counter in counters]
        try:
            self.transact_write(actions)
        except TransactionCanceled as exc:
            if not exc.conditional_check_failed:
                raise
            return _failed_scopes(counters, exc.reasons)
        return ()

    def _emit(self, metric: str, dimensions: Mapping[str, str]) -> None:
        """Emit one count, logging and swallowing any failure."""
        try:
            enabled = metrics_enabled_from_env() if self.metrics_enabled is None else self.metrics_enabled
            emit(namespace=self.metrics_namespace, metrics={metric: 1}, dimensions=dimensions, enabled=enabled)
        except Exception as exc:
            _log.warning(
                "Failed to emit an email cap metric.",
                extra={"metric": metric, "error_type": type(exc).__name__},
            )

    def _report_capped(
        self,
        recipient: str,
        *,
        tenant: str,
        category: EmailCategory,
        purpose: str,
        exceeded: tuple[CapScope, ...],
    ) -> None:
        """Log the structured WARNING and emit `EmailCapped` for a refused send."""
        _log.warning(
            "Outbound email skipped: send cap reached.",
            extra={
                "event": "email.capped",
                "email_cap_namespace": self.namespace,
                "email_category": category,
                "email_cap_scopes": list(exceeded),
                "tenant": tenant,
                "recipient_hash": recipient_hash(recipient),
                "purpose": purpose,
            },
        )
        self._emit(
            EMAIL_CAPPED_METRIC,
            {"Namespace": self.namespace, "Category": category, "Scope": exceeded[0]},
        )

    def _failed_open(self, category: EmailCategory, exc: BaseException) -> EmailCapDecision:
        """Log the fail-open WARNING, emit its metric, and allow the send."""
        _log.warning(
            "Email cap check failed; allowing the send.",
            extra={
                "email_cap_failed_open": True,
                "email_cap_namespace": self.namespace,
                "email_category": category,
                "error_type": type(exc).__name__,
                "error_message": str(exc),
            },
        )
        self._emit(EMAIL_CAP_FAILED_OPEN_METRIC, {"Namespace": self.namespace, "Category": category})
        return EmailCapDecision(allowed=True, category=category, failed_open=True)


def _window(now: float, window_seconds: int) -> tuple[int, int]:
    """The clock-aligned window holding `now`, as start and end epoch seconds."""
    start = int(math.floor(now / window_seconds) * window_seconds)
    return start, start + window_seconds


def _failed_scopes(counters: Sequence[_Counter], reasons: Sequence[Mapping[str, Any]]) -> tuple[CapScope, ...]:
    """The scopes whose actions DynamoDB cancelled on a failed condition.

    Falls back to every scope when the reasons do not line up with the actions, since the
    send is refused either way.
    """
    if len(reasons) != len(counters):
        return tuple(counter.scope for counter in counters)
    return tuple(
        counter.scope
        for counter, reason in zip(counters, reasons, strict=True)
        if reason.get("Code") == "ConditionalCheckFailed"
    )
