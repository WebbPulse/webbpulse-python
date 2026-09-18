"""Tests for `webbpulse.events.webhooks`.

Pins the signature scheme against its own verifier in `webbpulse.http`, the retry policy's
shape and its jitter bounds, and what the dispatcher does with a delivered, a retryable and
a permanently refused endpoint.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

import pytest

from webbpulse.events.webhooks import (
    DEFAULT_REPLAY_WINDOW_SECONDS,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    RetryPolicy,
    WebhookDelivery,
    WebhookDispatcher,
    WebhookResponse,
    sign_payload,
    signature_headers,
    signed_message,
    within_replay_window,
)
from webbpulse.http import SignatureMismatch, verify_hmac_signature
from webbpulse.testing import FakeWebhookSender

SECRET = "whsec-test"

URL = "https://example.test/hooks/webbpulse"


def _dispatcher(
    sender: FakeWebhookSender,
    *,
    policy: RetryPolicy | None = None,
    dead_letter: Any = None,
) -> WebhookDispatcher:
    """A dispatcher that never really sleeps, so a retry test costs no wall clock."""
    return WebhookDispatcher(
        sender,
        SECRET,
        policy=policy if policy is not None else RetryPolicy(attempts=3, base_delay=0.0, jitter=0.0),
        dead_letter=dead_letter,
        sleep=lambda _seconds: None,
    )


def test_the_signature_covers_the_timestamp_and_the_body() -> None:
    """A signature over the body alone would verify forever; this one cannot."""
    assert signed_message(1700000000, b'{"a":1}') == b'1700000000.{"a":1}'

    first = sign_payload(SECRET, 1700000000, b"{}")
    second = sign_payload(SECRET, 1700000001, b"{}")
    assert first != second


def test_the_headers_carry_the_prefixed_digest_and_the_timestamp() -> None:
    """The wire shape is `sha256=<hex>` alongside the moment it was signed at."""
    headers = signature_headers(SECRET, b"{}", timestamp=1700000000)

    assert headers[TIMESTAMP_HEADER] == "1700000000"
    assert headers[SIGNATURE_HEADER] == f"sha256={sign_payload(SECRET, 1700000000, b'{}')}"


def test_a_sent_signature_verifies_through_the_receiving_helper() -> None:
    """The two halves of the scheme agree, which is the property that matters."""
    body = b'{"event":"post.created"}'
    headers = signature_headers(SECRET, body, timestamp=1700000000)

    assert verify_hmac_signature(
        signed_message(1700000000, body),
        headers[SIGNATURE_HEADER],
        SECRET,
    )


def test_a_tampered_body_does_not_verify() -> None:
    """Editing the body after signing is exactly what the receiver must catch."""
    headers = signature_headers(SECRET, b'{"amount":1}', timestamp=1700000000)

    with pytest.raises(SignatureMismatch):
        verify_hmac_signature(
            signed_message(1700000000, b'{"amount":9999}'),
            headers[SIGNATURE_HEADER],
            SECRET,
        )


def test_a_secret_may_be_bytes_or_text() -> None:
    """A secret read from Secrets Manager and one read from an env var sign the same."""
    assert sign_payload(SECRET, 1, b"{}") == sign_payload(SECRET.encode(), 1, b"{}")


@pytest.mark.parametrize("offset", [0, 10, -10, DEFAULT_REPLAY_WINDOW_SECONDS, -DEFAULT_REPLAY_WINDOW_SECONDS])
def test_the_replay_window_is_applied_in_both_directions(offset: int) -> None:
    """A receiver whose clock runs a little ahead must not reject every delivery."""
    assert within_replay_window(1700000000 + offset, now=1700000000)


@pytest.mark.parametrize("offset", [DEFAULT_REPLAY_WINDOW_SECONDS + 1, -DEFAULT_REPLAY_WINDOW_SECONDS - 1])
def test_a_delivery_outside_the_window_is_refused(offset: int) -> None:
    """Past the window a captured delivery stops being replayable."""
    assert not within_replay_window(1700000000 + offset, now=1700000000)


@pytest.mark.parametrize("status", [200, 201, 202, 204, 299])
def test_any_2xx_counts_as_delivered(status: int) -> None:
    """An endpoint that answers 204 accepted the delivery as much as one that answers 200."""
    assert WebhookResponse(status_code=status).delivered


@pytest.mark.parametrize("status", [408, 429, 500, 502, 503, 504])
def test_the_not_now_statuses_are_retryable(status: int) -> None:
    """These mean the endpoint is down or busy, not that the delivery was wrong."""
    assert WebhookResponse(status_code=status).retryable


@pytest.mark.parametrize("status", [400, 401, 403, 404, 410, 422])
def test_a_permanent_refusal_is_not_retried(status: int) -> None:
    """Retrying a 404 only spends the budget an endpoint that was merely down would use."""
    assert not WebhookResponse(status_code=status).retryable


def test_a_transport_failure_is_always_retryable() -> None:
    """A status of 0 is a connection failure or a timeout, both worth another attempt."""
    response = WebhookResponse(status_code=0, error="ConnectTimeout")

    assert response.retryable
    assert not response.delivered


def test_the_first_attempt_waits_and_the_rest_back_off() -> None:
    """Attempt 1 goes immediately; the gaps then double until the cap."""
    policy = RetryPolicy(attempts=5, base_delay=1.0, max_delay=8.0, jitter=0.0)

    assert policy.delay_before(1, rand=lambda: 0.0) == 0.0
    assert policy.delay_before(2, rand=lambda: 0.0) == 1.0
    assert policy.delay_before(3, rand=lambda: 0.0) == 2.0
    assert policy.delay_before(4, rand=lambda: 0.0) == 4.0
    assert policy.delay_before(5, rand=lambda: 0.0) == 8.0


def test_the_backoff_is_capped() -> None:
    """A long retry chain does not grow an unbounded gap."""
    policy = RetryPolicy(attempts=12, base_delay=1.0, max_delay=8.0, jitter=0.0)

    assert policy.delay_before(12, rand=lambda: 0.0) == 8.0


@pytest.mark.parametrize("draw", [0.0, 0.5, 1.0])
def test_the_jitter_only_ever_shortens_the_gap(draw: float) -> None:
    """The delay stays inside `[base * (1 - jitter), base]`, so it never exceeds the cap."""
    policy = RetryPolicy(attempts=3, base_delay=4.0, max_delay=30.0, jitter=0.25)

    delay = policy.delay_before(2, rand=lambda: draw)

    assert 3.0 <= delay <= 4.0


def test_a_delivered_webhook_is_posted_once() -> None:
    """A 200 on the first attempt ends the delivery, with no retry and no dead letter."""
    sender = FakeWebhookSender([200])
    dead_lettered: list[WebhookDelivery] = []

    delivery = _dispatcher(sender, dead_letter=dead_lettered.append).send(URL, {"id": "evt-1"}, event="post.created")

    assert delivery.delivered
    assert delivery.attempts == 1
    assert sender.attempts == 1
    assert dead_lettered == []


def test_a_retryable_failure_is_tried_again_until_it_lands() -> None:
    """The budget is spent on the endpoint that is merely down, which is the point."""
    sender = FakeWebhookSender([503, 503, 200])

    delivery = _dispatcher(sender).send(URL, {"id": "evt-1"})

    assert delivery.delivered
    assert delivery.attempts == 3
    assert [response.status_code for response in delivery.responses] == [503, 503, 200]


def test_the_attempts_are_bounded_by_the_policy() -> None:
    """An endpoint that never recovers does not retry forever."""
    sender = FakeWebhookSender(default=503)

    delivery = _dispatcher(sender, policy=RetryPolicy(attempts=4, base_delay=0.0, jitter=0.0)).send(
        URL, {"id": "evt-1"}
    )

    assert not delivery.delivered
    assert delivery.attempts == 4
    assert sender.attempts == 4


def test_a_permanent_refusal_stops_the_retries_early() -> None:
    """A 404 will answer the same way on every attempt, so the budget is not spent."""
    sender = FakeWebhookSender([404], default=200)

    delivery = _dispatcher(sender).send(URL, {"id": "evt-1"})

    assert not delivery.delivered
    assert delivery.attempts == 1
    assert sender.attempts == 1


def test_the_dead_letter_hook_runs_once_on_a_failed_delivery() -> None:
    """A product decides where an undeliverable event goes, and hears about it once."""
    sender = FakeWebhookSender(default=500)
    dead_lettered: list[WebhookDelivery] = []

    delivery = _dispatcher(sender, dead_letter=dead_lettered.append).send(URL, {"id": "evt-1"}, event="post.created")

    assert len(dead_lettered) == 1
    assert dead_lettered[0] is delivery
    assert dead_lettered[0].event == "post.created"
    assert dead_lettered[0].last_response is not None
    assert dead_lettered[0].last_response.status_code == 500


def test_a_raising_dead_letter_hook_does_not_mask_the_delivery() -> None:
    """The hook failing must not turn a reported failure into an exception the caller sees."""

    def explode(_delivery: WebhookDelivery) -> None:
        """A dead-letter hook that is itself broken."""
        raise RuntimeError("the dead letter queue is unreachable")

    delivery = _dispatcher(FakeWebhookSender(default=500), dead_letter=explode).send(URL, {"id": "evt-1"})

    assert not delivery.delivered


def test_the_body_is_canonical_so_the_signature_is_reproducible() -> None:
    """A receiver verifies the bytes it was sent, so key order must not vary."""
    sender = FakeWebhookSender([200])

    _dispatcher(sender).send(URL, {"b": 2, "a": 1})

    assert sender.last_call is not None
    assert sender.last_call["body"] == b'{"a":1,"b":2}'


def test_the_posted_headers_carry_a_signature_the_receiver_accepts() -> None:
    """The dispatcher's own output is what `verify_hmac_signature` is handed in production."""
    sender = FakeWebhookSender([200])

    _dispatcher(sender).send(URL, {"id": "evt-1"}, event="post.created")

    call = sender.last_call
    assert call is not None
    headers = call["headers"]
    assert headers["Content-Type"] == "application/json"
    assert headers["X-Webhook-Event"] == "post.created"

    timestamp = int(headers[TIMESTAMP_HEADER])
    assert verify_hmac_signature(
        signed_message(timestamp, call["body"]),
        headers[SIGNATURE_HEADER],
        SECRET,
    )


def test_the_signature_is_computed_once_across_retries() -> None:
    """The timestamp a receiver checks is when the event was signed, not when it last retried."""
    sender = FakeWebhookSender([503, 503, 200])

    _dispatcher(sender).send(URL, {"id": "evt-1"})

    signatures = {call["headers"][SIGNATURE_HEADER] for call in sender.calls}
    timestamps = {call["headers"][TIMESTAMP_HEADER] for call in sender.calls}
    assert len(signatures) == 1
    assert len(timestamps) == 1


def test_a_bytes_payload_is_sent_and_signed_untouched() -> None:
    """A caller that already serialised its own body keeps those exact bytes."""
    sender = FakeWebhookSender([200])
    raw = b'{"already":"serialised"}'

    _dispatcher(sender).send(URL, raw)

    call = sender.last_call
    assert call is not None
    assert call["body"] == raw
    timestamp = int(call["headers"][TIMESTAMP_HEADER])
    expected = hmac.new(SECRET.encode(), signed_message(timestamp, raw), hashlib.sha256).hexdigest()
    assert call["headers"][SIGNATURE_HEADER] == f"sha256={expected}"


def test_a_per_call_secret_overrides_the_dispatcher_one() -> None:
    """A product with a per-endpoint secret can keep one dispatcher."""
    sender = FakeWebhookSender([200])

    _dispatcher(sender).send(URL, {"id": "evt-1"}, secret="whsec-other", timestamp=1700000000)

    call = sender.last_call
    assert call is not None
    assert call["headers"][SIGNATURE_HEADER] == f"sha256={sign_payload('whsec-other', 1700000000, call['body'])}"


def test_caller_headers_win_over_the_defaults() -> None:
    """A product that must send its own content type or tracing header can."""
    sender = FakeWebhookSender([200])

    _dispatcher(sender).send(URL, {"id": "evt-1"}, headers={"Content-Type": "application/vnd.webbpulse+json"})

    call = sender.last_call
    assert call is not None
    assert call["headers"]["Content-Type"] == "application/vnd.webbpulse+json"


def test_a_delivery_with_no_attempts_reports_no_last_response() -> None:
    """The zero-attempt policy is degenerate but must not raise on inspection."""
    delivery = WebhookDelivery(url=URL, event="x", delivered=False, attempts=0)

    assert delivery.last_response is None
