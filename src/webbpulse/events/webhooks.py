"""Outbound signed webhooks: the signature scheme, the retry policy, and the dispatcher.

The receiving side of this scheme, and GitHub's, is `webbpulse.http.verify_hmac_signature`.
A delivery is signed over the timestamp and the body together, never the body alone, so a
captured request cannot be replayed outside the window: `X-Webhook-Signature` carries
`sha256=<hex>` of `"<timestamp>.<body>"` and `X-Webhook-Timestamp` carries the timestamp the
signature was computed over.

`WebhookSender` is the transport seam. `HttpxWebhookSender` ships and `FakeWebhookSender` in
`webbpulse.testing` is the double. `WebhookDispatcher` owns the retries: a bounded number of
attempts with jittered exponential backoff, and a dead-letter hook that is called once when
every attempt has failed, so a product decides where an undeliverable event goes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import random
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final, Protocol

__all__ = [
    "DEFAULT_REPLAY_WINDOW_SECONDS",
    "DEFAULT_SIGNATURE_PREFIX",
    "SIGNATURE_HEADER",
    "TIMESTAMP_HEADER",
    "DeadLetter",
    "HttpxWebhookSender",
    "RetryPolicy",
    "UrllibWebhookSender",
    "WebhookDelivery",
    "WebhookDispatcher",
    "WebhookResponse",
    "WebhookSender",
    "sign_payload",
    "signature_headers",
    "signed_message",
    "within_replay_window",
]

_log = logging.getLogger(__name__)

SIGNATURE_HEADER: Final = "X-Webhook-Signature"

TIMESTAMP_HEADER: Final = "X-Webhook-Timestamp"

DEFAULT_SIGNATURE_PREFIX: Final = "sha256="

DEFAULT_REPLAY_WINDOW_SECONDS: Final = 300

_RETRYABLE_STATUSES: Final = frozenset({408, 409, 425, 429, 500, 502, 503, 504})


def signed_message(timestamp: int, body: bytes) -> bytes:
    """The bytes the signature covers: the timestamp, a dot, then the body.

    Binding the timestamp into the signature is what makes the replay window enforceable. A
    signature over the body alone would verify forever, so a captured delivery could be
    replayed at any time.
    """
    return f"{timestamp}.".encode() + body


def sign_payload(secret: str | bytes, timestamp: int, body: bytes) -> str:
    """The hex HMAC-SHA256 of `signed_message`, without the scheme prefix."""
    key = secret.encode() if isinstance(secret, str) else secret
    return hmac.new(key, signed_message(timestamp, body), hashlib.sha256).hexdigest()


def signature_headers(secret: str | bytes, body: bytes, *, timestamp: int | None = None) -> dict[str, str]:
    """The two headers a signed delivery carries, `timestamp` defaulting to now."""
    moment = int(time.time()) if timestamp is None else timestamp
    return {
        SIGNATURE_HEADER: f"{DEFAULT_SIGNATURE_PREFIX}{sign_payload(secret, moment, body)}",
        TIMESTAMP_HEADER: str(moment),
    }


def within_replay_window(
    timestamp: int,
    *,
    window_seconds: int = DEFAULT_REPLAY_WINDOW_SECONDS,
    now: int | None = None,
) -> bool:
    """Whether `timestamp` is close enough to now to be accepted.

    The window is applied in both directions, so a receiver whose clock runs a little ahead
    of the sender's does not reject every delivery.
    """
    moment = int(time.time()) if now is None else now
    return abs(moment - timestamp) <= window_seconds


@dataclass(frozen=True, slots=True)
class WebhookResponse:
    """What one delivery attempt came back with.

    `status_code` is 0 when the attempt raised before any response arrived, which is a
    connection failure or a timeout, and `error` then names it.
    """

    status_code: int
    body: str = ""
    error: str | None = None

    @property
    def delivered(self) -> bool:
        """Whether the endpoint accepted the delivery, which is any 2xx."""
        return 200 <= self.status_code < 300

    @property
    def retryable(self) -> bool:
        """Whether another attempt could plausibly succeed.

        A transport failure is always retryable. A 4xx is not, other than the handful that
        mean "not now": a 400 or a 404 will answer the same way on every attempt, and
        retrying it only spends the budget an endpoint that is merely down would have used.
        """
        if self.delivered:
            return False
        if self.status_code == 0:
            return True
        return self.status_code in _RETRYABLE_STATUSES


class WebhookSender(Protocol):
    """The one call the dispatcher makes against an endpoint.

    A Protocol, so `HttpxWebhookSender`, `UrllibWebhookSender` and a test double satisfy it
    without inheritance. An implementation returns a `WebhookResponse` rather than raising:
    the dispatcher decides what a failure means.
    """

    def post(self, url: str, *, body: bytes, headers: Mapping[str, str], timeout: float) -> WebhookResponse:
        """Post `body` to `url` and report what came back."""
        ...


class HttpxWebhookSender:
    """`WebhookSender` over `httpx`, built once and reused.

    Follows no redirect: a 3xx from a webhook endpoint is a misconfiguration, and chasing it
    would post a signed body to a URL the product never registered.
    """

    def __init__(self, *, client: Any = None) -> None:
        """Hold an already-built client when one is supplied, else build on first use."""
        self._client = client

    def _require(self, timeout: float) -> Any:
        """Build the `httpx` client on first use, and return it thereafter."""
        if self._client is None:
            import httpx

            self._client = httpx.Client(timeout=timeout, follow_redirects=False)
        return self._client

    def post(self, url: str, *, body: bytes, headers: Mapping[str, str], timeout: float) -> WebhookResponse:
        """Post the signed body, turning a transport failure into a status of 0."""
        try:
            response = self._require(timeout).post(url, content=body, headers=dict(headers), timeout=timeout)
        except Exception as exc:
            return WebhookResponse(status_code=0, error=type(exc).__name__)
        return WebhookResponse(status_code=int(response.status_code), body=_short_body(response))


class UrllibWebhookSender:
    """`WebhookSender` over `urllib.request`, for a service that does not install `httpx`.

    Every outcome is a `WebhookResponse`: an `HTTPError` carries the endpoint's own status,
    and anything else is a transport failure reported as 0.
    """

    def post(self, url: str, *, body: bytes, headers: Mapping[str, str], timeout: float) -> WebhookResponse:
        """Post the signed body through the standard library."""
        import urllib.error
        import urllib.request

        request = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return WebhookResponse(
                    status_code=int(response.status),
                    body=response.read(2048).decode("utf-8", "replace"),
                )
        except urllib.error.HTTPError as exc:
            return WebhookResponse(
                status_code=int(exc.code),
                body=exc.read(2048).decode("utf-8", "replace"),
                error=str(exc.reason),
            )
        except Exception as exc:
            return WebhookResponse(status_code=0, error=type(exc).__name__)


def _short_body(response: Any) -> str:
    """At most 2KiB of a response body, for the log and the dead letter, never the whole thing."""
    try:
        return str(response.text)[:2048]
    except Exception:
        return ""


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """How many times a delivery is attempted and how long the gaps are.

    The delay before attempt `n` is `base_delay * 2 ** (n - 1)`, capped at `max_delay`, then
    multiplied by a random factor in `[1 - jitter, 1]`. The jitter is what stops a hundred
    endpoints that all failed on the same outage from retrying in lockstep and arriving as
    one thundering herd on recovery.
    """

    attempts: int = 3
    base_delay: float = 0.5
    max_delay: float = 30.0
    jitter: float = 0.25
    timeout: float = 10.0

    def delay_before(self, attempt: int, *, rand: Callable[[], float] = random.random) -> float:
        """The seconds to wait before `attempt`, which is 1-based; attempt 1 waits none."""
        if attempt <= 1:
            return 0.0
        raw = min(self.base_delay * (2 ** (attempt - 2)), self.max_delay)
        return float(raw * (1.0 - self.jitter * rand()))


@dataclass(frozen=True, slots=True)
class WebhookDelivery:
    """What became of one webhook after every attempt it was given."""

    url: str
    event: str
    delivered: bool
    attempts: int
    responses: tuple[WebhookResponse, ...] = field(default=())

    @property
    def last_response(self) -> WebhookResponse | None:
        """The final attempt's response, or `None` when none was ever made."""
        return self.responses[-1] if self.responses else None


type DeadLetter = Callable[[WebhookDelivery], None]
"""Called once with the finished delivery when every attempt has failed."""


class WebhookDispatcher:
    """Signs, sends and retries one webhook at a time.

    The secret signs every delivery this dispatcher makes, so a product with a per-endpoint
    secret builds one dispatcher per endpoint or passes `secret` per call. `dead_letter` is
    called once, after the last attempt, and only when the delivery never succeeded; it is
    called inside a try, because a failing dead-letter hook must not mask the delivery
    failure it was told about.
    """

    __slots__ = ("_dead_letter", "_policy", "_secret", "_sender", "_sleep")

    def __init__(
        self,
        sender: WebhookSender,
        secret: str | bytes,
        *,
        policy: RetryPolicy | None = None,
        dead_letter: DeadLetter | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """Hold the transport, the signing secret, the retry policy and the dead-letter hook."""
        self._sender = sender
        self._secret = secret
        self._policy = policy if policy is not None else RetryPolicy()
        self._dead_letter = dead_letter
        self._sleep = sleep

    def send(
        self,
        url: str,
        payload: Mapping[str, Any] | bytes,
        *,
        event: str = "",
        headers: Mapping[str, str] | None = None,
        secret: str | bytes | None = None,
        timestamp: int | None = None,
    ) -> WebhookDelivery:
        """Deliver `payload` to `url`, retrying under the policy, and report the outcome.

        A mapping is serialised compactly with sorted keys, which is what makes the signature
        reproducible: a receiver verifies the bytes it was sent, so the producer must not let
        key order vary between the signing and the sending. The signature is computed once
        and reused across attempts, so the timestamp a receiver checks is when the event was
        signed rather than when the last retry happened; that is the point of the window.
        """
        body = payload if isinstance(payload, bytes) else _canonical_body(payload)
        signing_secret = secret if secret is not None else self._secret
        request_headers = {
            "Content-Type": "application/json",
            **signature_headers(signing_secret, body, timestamp=timestamp),
            **(dict(headers) if headers else {}),
        }
        if event:
            request_headers.setdefault("X-Webhook-Event", event)

        responses: list[WebhookResponse] = []
        for attempt in range(1, self._policy.attempts + 1):
            pause = self._policy.delay_before(attempt)
            if pause > 0:
                self._sleep(pause)
            response = self._sender.post(url, body=body, headers=request_headers, timeout=self._policy.timeout)
            responses.append(response)
            if response.delivered:
                return self._finish(url, event, True, attempt, responses)
            if not response.retryable:
                break

        return self._finish(url, event, False, len(responses), responses)

    def _finish(
        self,
        url: str,
        event: str,
        delivered: bool,
        attempts: int,
        responses: list[WebhookResponse],
    ) -> WebhookDelivery:
        """Log the outcome, run the dead-letter hook on a failure, and return the delivery."""
        delivery = WebhookDelivery(
            url=url,
            event=event,
            delivered=delivered,
            attempts=attempts,
            responses=tuple(responses),
        )
        last = delivery.last_response
        _log.log(
            logging.INFO if delivered else logging.WARNING,
            "Delivered a webhook." if delivered else "A webhook was not delivered.",
            extra={
                "event": "webhook.delivered" if delivered else "webhook.failed",
                "webhook_event": event,
                "attempts": attempts,
                "status": last.status_code if last is not None else 0,
            },
        )
        if not delivered and self._dead_letter is not None:
            try:
                self._dead_letter(delivery)
            except Exception:
                _log.exception(
                    "The webhook dead-letter hook raised.",
                    extra={"event": "webhook.dead_letter_failed", "webhook_event": event},
                )
        return delivery


def _canonical_body(payload: Mapping[str, Any]) -> bytes:
    """The bytes a mapping is signed and sent as: compact, sorted keys, UTF-8."""
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
