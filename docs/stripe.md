# Stripe billing gateway

`webbpulse.integrations.stripe.StripeGateway` makes the subscription billing calls both
CarModPicker and Standupless need, over one `stripe.StripeClient`. Settings, the client and
the low-level webhook receiver are in the README's [Stripe](../README.md#stripe) section.
Install the `stripe` extra (`webbpulse[stripe]`); the module itself imports `stripe` only
when a gateway or client is built, so settings and errors load without it.

## The gateway

```python
from webbpulse.integrations.stripe import StripeGateway, load_stripe_settings

gateway = StripeGateway(load_stripe_settings())
```

| Method | Does |
| --- | --- |
| `find_price_id(lookup_key)` | The active price with that lookup key, or None |
| `find_customer_ids(owner_key, owner_id)` | Every customer tagged `metadata[owner_key] = owner_id`, oldest first |
| `ensure_customer(*, owner_key, owner_id, email=None, name=None, metadata=None, customer_id=None)` | The owner's one customer id, created at most once (below) |
| `create_checkout_session(*, customer_id, price_id, reference_id, success_url, cancel_url, quantity=1, metadata=None)` | A subscription Checkout URL; `reference_id` is the `client_reference_id`, `metadata` lands on the session and the subscription |
| `create_portal_session(*, customer_id, return_url)` | A billing portal URL |
| `retrieve_subscription(subscription_id)` | The subscription as a plain dict |
| `set_quantity(subscription_id, item_id, quantity)` | A prorated seat change |
| `cancel_subscriptions(customer_id)` | Cancels every live subscription at once, without a final invoice or proration |
| `cancel_owner_subscriptions(owner_key, owner_id)` | The same for every customer the owner holds, for account delete |
| `verify_webhook(payload, signature_header)` | Verifies a delivery and parses a `StripeEvent` |

`owner_key` is the metadata key naming the owner (`user_id`, `workspace_id`) and must
match `[A-Za-z0-9_]{1,40}`; `owner_id` must match `[A-Za-z0-9_.:-]{1,200}`. Anything else
raises `ValueError` before a call, since both go into a search query. Stripe failures
surface as `stripe.StripeError`. `BillingGateway` is the Protocol both the gateway and
`webbpulse.testing.FakeStripeGateway` satisfy, so a route depends on the Protocol.

## One customer per owner

Two concurrent checkouts for an owner with no stored customer used to both call
`customers.create`, leaving two customers and a stranded subscription. `ensure_customer`
closes that in three layers:

1. A metadata search answers an existing customer, the oldest of any legacy duplicates.
2. The create sends the idempotency key `webbpulse-customer-v1-<owner_key>-<owner_id>`.
   Stripe answers every request with that key, for 24 hours, with the first response, so
   racers that both missed in search get the same customer. A 409 while the first request
   is in flight is retried with backoff.
3. After 24 hours the key expires, but search (about a minute behind) has indexed the
   customer by then, so layer 1 answers it.

When Stripe refuses the key because an earlier create sent other parameters, such as a
changed email, the gateway searches again and raises `StripeCustomerConflict` only if
nothing is found. Store the answered id with a conditional write where the table allows
it; since every racer answers the same id, a plain write is also safe.

## Cancel on account delete

`cancel_owner_subscriptions("user_id", user_id)` needs only the owner id, so a delete
consumer can run it after the user row is gone. It skips `canceled` and
`incomplete_expired` subscriptions, cancels each under the key
`webbpulse-cancel-v1-<subscription id>`, and treats a subscription that ended meanwhile as
done, so a redelivered delete message is harmless. Run it before deleting anything the
retry would need, and let a Stripe error fail the message so the queue retries it.

## Webhook events

`verify_webhook(payload, signature_header)` takes the raw body bytes and the
`Stripe-Signature` header, checks them against `STRIPE_WEBHOOK_SECRET`, and answers a
frozen `StripeEvent`:

| Field | Holds |
| --- | --- |
| `id`, `type`, `created`, `livemode`, `api_version` | The event envelope |
| `data_object` | `data.object` as a plain dict, left out of the repr |
| `subscription_id` | The subscription, from a subscription, a Checkout session or an invoice's `parent.subscription_details` |
| `customer_id` | The customer id, expanded or not |
| `reference_id` | A Checkout session's `client_reference_id` |

A missing secret raises `StripeNotConfigured`; a missing, wrong or stale signature, or a
body that is not an event, raises `StripeSignatureError`. Neither the body, the header nor
the secret is logged. `claim_webhook_event(event, store)` takes a `StripeEvent` as well as
a `stripe.Event`.

## Testing

`webbpulse.testing.FakeStripeGateway(prices=..., webhook_secret=...)` keeps customers,
subscriptions, Checkout and portal sessions in memory, creates one customer per owner under
a lock, and counts creates in `customer_creates`. `add_subscription(customer_id, ...)`
seeds a subscription. Its `verify_webhook` checks a header made by `sign_stripe_payload`
with the same tolerance and errors as the real gateway.

## Adopting

- Replace the product's own gateway class with `StripeGateway` and type the dependency
  as `BillingGateway`.
- Call `ensure_customer(owner_key=..., owner_id=..., customer_id=<stored id>)` instead of
  a create, and store the answer.
- Pass the owner as `reference_id` and as `metadata` on Checkout, so every subscription
  event names it.
- Receive through `verify_webhook` and `claim_webhook_event`.
- Call `cancel_owner_subscriptions` in the account or workspace delete path, which needs
  the Stripe settings in that function's environment.
