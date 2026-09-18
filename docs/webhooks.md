# Outbound webhooks

Signed, retried deliveries to an endpoint a customer registered, in
`webbpulse.events.webhooks`. The receiving half is `webbpulse.http.verify_hmac_signature`,
in [http.md](http.md). Back to the [README](../README.md).

## The signature scheme

A delivery is signed over the timestamp and the body together, never the body alone:

| Header | Carries |
| --- | --- |
| `X-Webhook-Signature` | `sha256=<hex>` of `"<timestamp>.<body>"` under the shared secret |
| `X-Webhook-Timestamp` | The unix seconds the signature was computed at |
| `X-Webhook-Event` | The event name, when one was given |

Binding the timestamp into the signature is what makes the replay window enforceable. A
signature over the body alone would verify forever, so a captured delivery could be replayed
at any time.

## Sending

```python
from webbpulse.events.webhooks import HttpxWebhookSender, RetryPolicy, WebhookDispatcher

dispatcher = WebhookDispatcher(
    HttpxWebhookSender(),
    endpoint.secret,
    policy=RetryPolicy(attempts=5),
    dead_letter=lambda delivery: enqueue(settings.dlq_url, {"url": delivery.url}),
)

delivery = dispatcher.send(endpoint.url, {"id": event.id, "type": "post.created"}, event="post.created")
```

A mapping is serialised compactly with sorted keys, which is what makes the signature
reproducible: a receiver verifies the bytes it was sent, so key order must not vary between
the signing and the sending. Pass `bytes` to send a body you already serialised. The
signature is computed once and reused across attempts, so the timestamp a receiver checks is
when the event was signed rather than when the last retry happened.

`send` returns a `WebhookDelivery` and does not raise: `delivered`, `attempts` and the per
attempt `responses` are there to log or to persist.

## The retry policy

| Field | Default | What it does |
| --- | --- | --- |
| `attempts` | `3` | How many times a delivery is tried at most. |
| `base_delay` | `0.5` | The gap before attempt 2, doubling thereafter. |
| `max_delay` | `30.0` | The cap the doubling stops at. |
| `jitter` | `0.25` | The fraction of the gap randomly shaved off. |
| `timeout` | `10.0` | Seconds allowed per attempt. |

The delay before attempt `n` is `base_delay * 2 ** (n - 2)`, capped at `max_delay`, then
multiplied by a random factor in `[1 - jitter, 1]`. The jitter is what stops a hundred
endpoints that all failed on the same outage from retrying in lockstep and arriving as one
thundering herd on recovery.

A 2xx is delivered. A transport failure, reported as status 0, is always retried, and so are
408, 409, 425, 429 and the 5xx family. Every other 4xx stops the retries immediately: a 400
or a 404 will answer the same way on every attempt, and retrying it only spends the budget an
endpoint that was merely down would have used.

`dead_letter` is called once, after the last attempt, and only when the delivery never
succeeded, so a product decides where an undeliverable event goes. It is called inside a try:
a failing dead-letter hook must not mask the delivery failure it was told about.

## The transports

`HttpxWebhookSender` needs the `oauth` extra, which is what brings `httpx` in.
`UrllibWebhookSender` is the standard-library fallback for a service that installs neither.
Both follow no redirect: a 3xx from a webhook endpoint is a misconfiguration, and chasing it
would post a signed body to a URL the product never registered.

`WebhookSender` is a Protocol, so a product with its own HTTP client satisfies it by having
the one `post` method.

## Receiving

The other side of this scheme, and of GitHub's, is `verify_hmac_signature`. Check the
timestamp first, then the signature over the same bytes the sender signed:

```python
from webbpulse.events.webhooks import signed_message, within_replay_window
from webbpulse.http import SignatureMismatch, verify_hmac_signature

timestamp = int(request.headers["X-Webhook-Timestamp"])
if not within_replay_window(timestamp):
    raise HTTPException(status_code=401, detail=unauthenticated())

try:
    verify_hmac_signature(signed_message(timestamp, body), request.headers["X-Webhook-Signature"], secret)
except SignatureMismatch:
    raise HTTPException(status_code=401, detail=unauthenticated()) from None
```

The window is applied in both directions, so a receiver whose clock runs a little ahead of
the sender's does not reject every delivery.

## Testing

`webbpulse.testing.FakeWebhookSender` satisfies `WebhookSender` structurally and scripts its
responses, so a retry test is deterministic with no sleeping and no socket.

```python
from webbpulse.testing import FakeWebhookSender

sender = FakeWebhookSender([503, 503, 200])
delivery = WebhookDispatcher(sender, "secret", sleep=lambda _: None).send(url, {"id": "1"})

assert delivery.delivered
assert sender.attempts == 3
```

`responses` is consumed one per attempt and `default` answers the rest, an `int` standing in
for a response with that status. Every call is recorded on `calls` with the url, the body and
the headers, so a test can re-derive the signature the dispatcher produced. Pass
`sleep=lambda _: None` to the dispatcher so the backoff costs no wall clock.
