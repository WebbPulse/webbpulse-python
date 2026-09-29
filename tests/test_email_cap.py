"""Tests for the outbound email send cap and the capped sender."""

from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import Any

import pytest

from webbpulse import email_cap
from webbpulse.email_cap import (
    DAY_SECONDS,
    EMAIL_CAP_FAILED_OPEN_METRIC,
    EMAIL_CAPPED_METRIC,
    EMAIL_METRICS_NAMESPACE,
    EmailCapLimits,
    EmailCapPolicy,
    EmailSendCap,
    recipient_hash,
)
from webbpulse.identity.email import (
    CappedEmailSender,
    EmailCapExceeded,
    EmailMessage,
    EmailSendFailed,
    RecordingEmailSender,
)

NOW = 1_000_000.0


def _cap(policy: EmailCapPolicy | None = None, **kwargs: Any) -> EmailSendCap:
    """A cap bound to the moto-backed `rate-limits` table."""
    return EmailSendCap(policy, prefix="", region_name="us-west-2", metrics_enabled=False, **kwargs)


def _message(to: str = "alice@example.com", purpose: str = "issue_updated") -> EmailMessage:
    """A rendered message tagged with `purpose`."""
    return EmailMessage(to=to, subject="Hi", text="Hi", html="<p>Hi</p>", tags={"purpose": purpose})


def _capture_emits(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Record every `emit` call the cap makes."""
    calls: list[dict[str, Any]] = []

    def fake_emit(**kwargs: Any) -> None:
        """Record one call."""
        calls.append(kwargs)

    monkeypatch.setattr(email_cap, "emit", fake_emit)
    return calls


def _explode(*args: Any, **kwargs: Any) -> Any:
    """Stand in for a DynamoDB call that fails."""
    raise RuntimeError("dynamodb is down")


def test_the_default_policy_caps_nothing_and_writes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """With every limit off, a check is allowed without touching DynamoDB."""
    cap = _cap()
    monkeypatch.setattr(cap, "update", _explode)
    monkeypatch.setattr(cap, "transact_write", _explode)

    decision = cap.check("alice@example.com", now=NOW)

    assert decision.allowed is True
    assert decision.counted is False
    assert decision.failed_open is False


def test_per_recipient_limit_refuses_the_send_after_the_limit(rate_limit_table: Any) -> None:
    """One counter on: the sends up to the limit go and the next is refused as `recipient`."""
    assert rate_limit_table is not None
    cap = _cap(EmailCapPolicy(standard=EmailCapLimits(per_recipient=2)))

    decisions = [cap.check("alice@example.com", tenant="ws1", now=NOW) for _ in range(3)]

    assert [d.allowed for d in decisions] == [True, True, False]
    assert decisions[2].exceeded == ("recipient",)


def test_a_refused_send_is_not_counted(rate_limit_table: Any) -> None:
    """The conditional write leaves the counter at the limit rather than past it."""
    assert rate_limit_table is not None
    cap = _cap(EmailCapPolicy(standard=EmailCapLimits(per_recipient=1)))
    for _ in range(3):
        cap.check("alice@example.com", tenant="ws1", now=NOW)

    start = int(NOW // DAY_SECONDS * DAY_SECONDS)
    item = cap.get({"pk": f"email#standard#rcpt#ws1#{recipient_hash('alice@example.com')}#{start}"})
    assert item is not None
    assert int(item["count"]) == 1
    assert int(item["expires_at"]) == start + DAY_SECONDS + 60


def test_the_recipient_key_holds_no_address_and_ignores_case(rate_limit_table: Any) -> None:
    """Addresses are hashed, trimmed and lowercased before they reach a key."""
    assert rate_limit_table is not None
    cap = _cap(EmailCapPolicy(standard=EmailCapLimits(per_recipient=1)))

    assert cap.check("Alice@Example.com", tenant="ws1", now=NOW).allowed is True
    assert cap.check(" alice@example.com ", tenant="ws1", now=NOW).allowed is False
    assert all("alice" not in item["pk"] for item in rate_limit_table.scan()["Items"])


def test_recipients_tenants_and_windows_are_independent(rate_limit_table: Any) -> None:
    """Another recipient, another tenant or the next window starts a fresh count."""
    assert rate_limit_table is not None
    cap = _cap(EmailCapPolicy(standard=EmailCapLimits(per_recipient=1, per_recipient_window_seconds=3600)))
    assert cap.check("alice@example.com", tenant="ws1", now=NOW).allowed is True

    assert cap.check("bob@example.com", tenant="ws1", now=NOW).allowed is True
    assert cap.check("alice@example.com", tenant="ws2", now=NOW).allowed is True
    assert cap.check("alice@example.com", tenant="ws1", now=NOW + 3600).allowed is True
    assert cap.check("alice@example.com", tenant="ws1", now=NOW).allowed is False


def test_several_counters_refuse_with_the_scope_that_tripped(rate_limit_table: Any) -> None:
    """With three counters on, the refusal names the one at its limit and counts nothing."""
    assert rate_limit_table is not None
    cap = _cap(EmailCapPolicy(standard=EmailCapLimits(per_recipient=10, per_tenant=10, daily=2)))

    first = cap.check("a@example.com", tenant="ws1", now=NOW)
    second = cap.check("b@example.com", tenant="ws2", now=NOW)
    third = cap.check("c@example.com", tenant="ws3", now=NOW)

    assert (first.allowed, second.allowed, third.allowed) == (True, True, False)
    assert third.exceeded == ("daily",)
    tenants = [item for item in rate_limit_table.scan()["Items"] if "#tenant#ws3#" in item["pk"]]
    assert tenants == [], "a cancelled transaction must not count the other counters"


def test_the_per_tenant_counter_spans_recipients(rate_limit_table: Any) -> None:
    """`per_tenant` counts every recipient in one tenant together."""
    assert rate_limit_table is not None
    cap = _cap(EmailCapPolicy(standard=EmailCapLimits(per_recipient=5, per_tenant=2)))

    results = [cap.check(f"user{i}@example.com", tenant="ws1", now=NOW) for i in range(3)]

    assert [r.allowed for r in results] == [True, True, False]
    assert results[2].exceeded == ("tenant",)


def test_transactional_mail_has_its_own_higher_allowance(rate_limit_table: Any) -> None:
    """Standard mail at its cap leaves transactional mail to the same address untouched."""
    assert rate_limit_table is not None
    cap = _cap(
        EmailCapPolicy(
            standard=EmailCapLimits(per_recipient=1, daily=1),
            transactional=EmailCapLimits(per_recipient=3),
        )
    )
    assert cap.check("alice@example.com", now=NOW).allowed is True
    assert cap.check("alice@example.com", now=NOW).allowed is False

    transactional = [cap.check("alice@example.com", category="transactional", now=NOW) for _ in range(4)]

    assert [d.allowed for d in transactional] == [True, True, True, False]


def test_a_transactional_limit_below_the_standard_one_is_refused() -> None:
    """The policy refuses a configuration that could lock users out first."""
    with pytest.raises(ValueError, match=r"transactional\.per_recipient"):
        EmailCapPolicy(standard=EmailCapLimits(per_recipient=5), transactional=EmailCapLimits(per_recipient=4))


@pytest.mark.parametrize("field", ["per_recipient", "per_tenant", "daily", "per_recipient_window_seconds"])
def test_a_limit_below_one_is_refused(field: str) -> None:
    """Zero would block every send, so it is a configuration error."""
    with pytest.raises(ValueError, match=field):
        EmailCapLimits(**{field: 0})


def test_a_capped_send_logs_and_emits(
    rate_limit_table: Any, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refusal logs `email.capped` without the address and emits `EmailCapped`."""
    assert rate_limit_table is not None
    calls = _capture_emits(monkeypatch)
    cap = _cap(EmailCapPolicy(standard=EmailCapLimits(per_recipient=1)))
    cap.check("alice@example.com", tenant="ws1", now=NOW)

    with caplog.at_level(logging.WARNING, logger="webbpulse.email_cap"):
        cap.check("alice@example.com", tenant="ws1", purpose="digest", now=NOW)

    record = next(r for r in caplog.records if getattr(r, "event", None) == "email.capped")
    assert record.__dict__["email_cap_scopes"] == ["recipient"]
    assert record.__dict__["tenant"] == "ws1"
    assert record.__dict__["purpose"] == "digest"
    assert record.__dict__["recipient_hash"] == recipient_hash("alice@example.com")
    assert "alice" not in record.getMessage()
    assert calls == [
        {
            "namespace": EMAIL_METRICS_NAMESPACE,
            "metrics": {EMAIL_CAPPED_METRIC: 1},
            "dimensions": {"Namespace": "email", "Category": "standard", "Scope": "recipient"},
            "enabled": False,
        }
    ]


@pytest.mark.parametrize(
    "limits",
    [EmailCapLimits(per_recipient=1), EmailCapLimits(per_recipient=1, daily=5)],
    ids=["update", "transaction"],
)
def test_a_dynamodb_failure_fails_open(
    limits: EmailCapLimits, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Either write path failing allows the send, logs the fail open, and emits its metric."""
    calls = _capture_emits(monkeypatch)
    cap = _cap(EmailCapPolicy(standard=limits))
    monkeypatch.setattr(cap, "update", _explode)
    monkeypatch.setattr(cap, "transact_write", _explode)

    with caplog.at_level(logging.WARNING, logger="webbpulse.email_cap"):
        decision = cap.check("alice@example.com", now=NOW)

    assert decision.allowed is True
    assert decision.failed_open is True
    assert any(getattr(r, "email_cap_failed_open", False) for r in caplog.records)
    assert [call["metrics"] for call in calls] == [{EMAIL_CAP_FAILED_OPEN_METRIC: 1}]


def test_a_missing_table_fails_open(dynamodb_resource: Any) -> None:
    """With no table at all, the send still goes."""
    assert dynamodb_resource is not None
    decision = _cap(EmailCapPolicy(standard=EmailCapLimits(daily=1))).check("alice@example.com", now=NOW)

    assert decision.failed_open is True


def test_a_failing_emitter_never_raises(rate_limit_table: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """A broken metrics path is logged and swallowed."""
    assert rate_limit_table is not None
    monkeypatch.setattr(email_cap, "emit", _explode)
    cap = _cap(EmailCapPolicy(standard=EmailCapLimits(per_recipient=1)))
    cap.check("alice@example.com", now=NOW)

    assert cap.check("alice@example.com", now=NOW).allowed is False


def test_the_capped_sender_skips_and_reports(rate_limit_table: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """`send_checked` reports a skipped send, and `send` returns an empty id without raising."""
    assert rate_limit_table is not None
    monkeypatch.setattr(email_cap, "time", SimpleNamespace(time=lambda: NOW))
    inner = RecordingEmailSender()
    sender = CappedEmailSender(inner, _cap(EmailCapPolicy(standard=EmailCapLimits(per_recipient=1))))

    first = sender.send_checked(_message(), tenant="ws1", now=NOW)
    second = sender.send_checked(_message(), tenant="ws1", now=NOW)

    assert (first.sent, first.message_id) == (True, "recorded-1")
    assert (second.sent, second.message_id) == (False, "")
    assert second.decision.exceeded == ("recipient",)
    assert sender.send(_message()) == "recorded-2", "send uses the default tenant, a fresh counter"
    assert sender.send(_message()) == ""
    assert len(inner.sent) == 2


def test_the_capped_sender_raises_only_when_opted_in(rate_limit_table: Any) -> None:
    """`raise_on_cap` turns a capped send into `EmailCapExceeded`, an `EmailSendFailed`."""
    assert rate_limit_table is not None
    sender = CappedEmailSender(
        RecordingEmailSender(),
        _cap(EmailCapPolicy(standard=EmailCapLimits(per_recipient=1))),
        raise_on_cap=True,
    )
    sender.send_checked(_message(), now=NOW)

    with pytest.raises(EmailSendFailed) as caught:
        sender.send_checked(_message(), now=NOW)

    assert isinstance(caught.value, EmailCapExceeded)
    assert caught.value.decision.exceeded == ("recipient",)


@pytest.mark.parametrize(
    ("purpose", "category"),
    [
        ("verify_email", "transactional"),
        ("reset_password", "transactional"),
        ("password_changed", "transactional"),
        ("registration_notice", "transactional"),
        ("mfa_code", "transactional"),
        ("issue_updated", "standard"),
    ],
)
def test_identity_purposes_classify_as_transactional(purpose: str, category: str) -> None:
    """Identity's own purpose tags and any `mfa` purpose are transactional."""
    sender = CappedEmailSender(RecordingEmailSender(), _cap())

    assert sender.category_of(_message(purpose=purpose)) == category


def test_identity_mail_keeps_flowing_when_standard_mail_is_capped(rate_limit_table: Any) -> None:
    """A reset link still goes out after notifications to the same address hit the cap."""
    assert rate_limit_table is not None
    inner = RecordingEmailSender()
    sender = CappedEmailSender(inner, _cap(EmailCapPolicy(standard=EmailCapLimits(per_recipient=1, daily=1))))
    sender.send_checked(_message(), now=NOW)
    assert sender.send_checked(_message(), now=NOW).sent is False

    reset = sender.send_checked(_message(purpose="reset_password"), now=NOW)

    assert reset.sent is True
    assert reset.decision.category == "transactional"
    assert [m.tags["purpose"] for m in inner.sent] == ["issue_updated", "reset_password"]


def test_the_transactional_override_wins_over_the_purpose(rate_limit_table: Any) -> None:
    """`transactional=False` counts identity mail as standard when the caller says so."""
    assert rate_limit_table is not None
    sender = CappedEmailSender(RecordingEmailSender(), _cap())

    result = sender.send_checked(_message(purpose="verify_email"), transactional=False, now=NOW)

    assert result.decision.category == "standard"
