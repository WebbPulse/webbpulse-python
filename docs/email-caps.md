# Outbound email send caps

`webbpulse.email_cap` caps outbound mail on the shared `<prefix>-rate-limits` table, and
`webbpulse.identity.CappedEmailSender` puts any `EmailSender` behind it. Every limit is off
by default, so nothing changes until a product configures one.

```python
from webbpulse.email_cap import EmailCapLimits, EmailCapPolicy, EmailSendCap
from webbpulse.identity import CappedEmailSender, SesV2EmailSender

cap = EmailSendCap(
    EmailCapPolicy(
        standard=EmailCapLimits(per_recipient=20, per_tenant=200, daily=5_000),
        transactional=EmailCapLimits(per_recipient=50, daily=20_000),
    )
)
sender = CappedEmailSender(SesV2EmailSender.from_settings(settings, ses), cap)

result = sender.send_checked(message, tenant=workspace_id)
if not result.sent:
    ...  # skipped: result.decision.exceeded names the counters at their limit
```

## The counters

| Counter | Key | Window |
| --- | --- | --- |
| `per_recipient` | `<namespace>#<category>#rcpt#<tenant>#<recipient hash>#<window start>` | `per_recipient_window_seconds`, default one day |
| `per_tenant` | `<namespace>#<category>#tenant#<tenant>#<window start>` | `per_tenant_window_seconds`, default one day |
| `daily` | `<namespace>#<category>#daily#<UTC day start>` | One UTC day, for the whole app |

Windows are clock aligned and each row carries the `expires_at` TTL the rate limiter uses,
so the table needs no change. `namespace` defaults to `email`. The recipient part is the
first 32 hex characters of the SHA-256 of the trimmed, lowercased address, so no address is
stored and case does not split a count. `tenant` is whatever the app partitions by, such as
a workspace id, and defaults to `-`.

**One conditional write per send.** One counter on is a single `UpdateItem`; two or three are
one `TransactWriteItems`. Each increment is conditioned on `count < limit`, so a counter at
its limit cancels the write, nothing is counted, and the send is skipped. A transaction
costs two write units per item, which is the price of never counting a refused send.

## Categories

Mail is `standard` or `transactional`, with separate counters and separate limits.
`CappedEmailSender` classifies a message as transactional when its `purpose` tag is in
`TRANSACTIONAL_PURPOSES` (`verify_email`, `reset_password`, `password_changed`,
`registration_notice`) or starts with `mfa`. `send_checked(..., transactional=...)`
overrides that.

`EmailCapPolicy` refuses a transactional limit below its standard counterpart, and a
transactional limit left as `None` is uncapped. A notification storm can therefore never use
up the allowance a user needs to verify, reset or finish MFA.

## When a send is capped

- The send is skipped, never raised: `send_checked` returns `EmailSendResult(sent=False,
  message_id="", decision=...)`, and `send` returns an empty message id.
- A WARNING is logged with `event="email.capped"`, `email_category`, `email_cap_scopes`,
  `tenant`, `recipient_hash` and `purpose`. It never includes the address.
- `EmailCapped` is emitted to `WebbPulse/Email` with the dimensions `Namespace`, `Category`
  and `Scope`.

Pass `raise_on_cap=True` to raise `EmailCapExceeded` instead. It subclasses
`EmailSendFailed`, so identity's reported paths answer 503 `EMAIL_UNAVAILABLE` and its
best-effort paths log and carry on. Without it, a capped identity send on a reported path
still answers success, which is why identity mail gets the higher allowance.

## Failing open

Any DynamoDB error other than a failed condition allows the send, logs a WARNING with
`email_cap_failed_open=True`, and emits `EmailCapFailedOpen` with `Namespace` and
`Category`. The metrics follow `metrics_enabled`, which defaults to
`metrics_enabled_from_env()`, and a failing emitter is logged and swallowed.

## Terraform

Nothing new. IAM authorises each item in a `TransactWriteItems` by its own action, so an
update inside the transaction needs only the `dynamodb:UpdateItem` on the rate limits table
that the rate limiter already has.
