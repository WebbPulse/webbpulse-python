"""Stripe configuration, a client built from it, a billing gateway, and verified, claimed webhook events.

`StripeSettings` is the one configuration shape every product reads from its `app` secret,
and `load_stripe_settings` resolves it from the environment and that secret. `stripe_client`
builds a `stripe.StripeClient` from those settings. `StripeGateway` is the subscription
billing seam both products call: price lookup, idempotent customer create, Checkout and
billing portal sessions, seat quantity, cancel on account delete, and webhook verify plus
parse into a `StripeEvent`. `BillingGateway` is its protocol, and
`webbpulse.testing.FakeStripeGateway` the in-memory double. `verify_webhook_event` checks a
delivery's `Stripe-Signature` header against the raw request body and answers the
`stripe.Event`, and `claim_webhook_event` claims the event id once, so a redelivered event
does its work once. Nothing here knows any product's prices or plans.

The `stripe` package is imported lazily, so the settings, the errors and `StripeEvent` load
without the `stripe` extra; building a client needs it. Every failure raised here is a
`StripeIntegrationError`, and Stripe's own `stripe.StripeError` passes through the gateway
untouched. The API key, the webhook signing secret, the signature header and the raw body
stay out of reprs, exception messages and log lines.
"""

from __future__ import annotations

import logging
import os
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final, Protocol

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, field_validator

if TYPE_CHECKING:  # pragma: no cover
    import stripe
    from stripe.params import CustomerCreateParams

__all__ = [
    "CUSTOMER_IDEMPOTENCY_PREFIX",
    "DEFAULT_EVENT_CLAIM_TTL_SECONDS",
    "DEFAULT_WEBHOOK_TOLERANCE_SECONDS",
    "ENDED_SUBSCRIPTION_STATUSES",
    "EVENT_CLAIM_PREFIX",
    "SETTINGS_KEYS",
    "BillingGateway",
    "EventClaimStore",
    "StripeCustomerConflict",
    "StripeEvent",
    "StripeGateway",
    "StripeIntegrationError",
    "StripeNotConfigured",
    "StripeSettings",
    "StripeSignatureError",
    "customer_idempotency_key",
    "customer_search_query",
    "claim_webhook_event",
    "event_claim_key",
    "load_stripe_settings",
    "stripe_client",
    "verify_webhook_event",
]

SETTINGS_KEYS: Final = (
    "STRIPE_API_KEY",
    "STRIPE_WEBHOOK_SECRET",
    "STRIPE_API_VERSION",
)
"""Every key `StripeSettings` reads, as it is spelled in the `app` secret."""

_REQUIRED_KEYS: Final = ("STRIPE_API_KEY",)

_API_KEY_PREFIXES: Final = ("sk_", "rk_")

_WEBHOOK_SECRET_PREFIX: Final = "whsec_"

DEFAULT_WEBHOOK_TOLERANCE_SECONDS: Final = 300
"""How old a signed delivery may be before it is refused, matching Stripe's own default."""

DEFAULT_EVENT_CLAIM_TTL_SECONDS: Final = 7 * 24 * 60 * 60
"""How long an event id stays claimed: past the three days Stripe keeps retrying a delivery."""

EVENT_CLAIM_PREFIX: Final = "stripe:event:"
"""The prefix of every idempotency key `claim_webhook_event` claims."""


CUSTOMER_IDEMPOTENCY_PREFIX: Final = "webbpulse-customer-v1"
"""The prefix of the deterministic Stripe idempotency key `StripeGateway.ensure_customer` sends."""

ENDED_SUBSCRIPTION_STATUSES: Final = frozenset({"canceled", "incomplete_expired"})
"""The subscription statuses that bill nothing more, so cancel on delete skips them."""

_OWNER_KEY: Final = re.compile(r"^[A-Za-z0-9_]{1,40}$")

_OWNER_ID: Final = re.compile(r"^[A-Za-z0-9_.:-]{1,200}$")

_CONFLICT_ATTEMPTS: Final = 4

_CONFLICT_BACKOFF_SECONDS: Final = 0.5

_log = logging.getLogger(__name__)


class StripeIntegrationError(Exception):
    """Stripe is not configured, or a webhook delivery cannot be trusted."""


class StripeNotConfigured(StripeIntegrationError):
    """The environment and the `app` secret lack a usable Stripe configuration."""


class StripeSignatureError(StripeIntegrationError):
    """A webhook delivery's signature is missing, malformed, wrong or too old, or its body is not an event."""


class StripeCustomerConflict(StripeIntegrationError):
    """Stripe refused the owner's idempotent customer create and no customer could be found for it."""


class EventClaimStore(Protocol):
    """The one-shot claim `claim_webhook_event` needs.

    `webbpulse.dynamodb.IdempotencyStore` and `webbpulse.testing.FakeIdempotencyStore` both
    satisfy it, so this module never imports the `dynamodb` extra.
    """

    def claim(self, key: str, ttl_seconds: float) -> bool:
        """Claim `key` for `ttl_seconds`, answering whether this caller won."""
        ...


class StripeSettings(BaseModel):
    """The standard Stripe configuration, keyed as the `app` secret spells it.

    `api_key` is a secret key (`sk_`) or, preferably, a restricted key (`rk_`) and is
    required. `webhook_secret` is the endpoint's signing secret (`whsec_`), needed only by a
    product that receives webhooks. `api_version` pins the Stripe API version the client
    sends; left unset, the client sends the version the installed `stripe` package was
    generated against, which is what its types describe. Secret values are `SecretStr`, so
    they print masked, and validation errors never echo an input.
    """

    model_config = ConfigDict(frozen=True, populate_by_name=True, hide_input_in_errors=True, extra="ignore")

    api_key: SecretStr = Field(alias="STRIPE_API_KEY")
    webhook_secret: SecretStr | None = Field(default=None, alias="STRIPE_WEBHOOK_SECRET")
    api_version: str | None = Field(default=None, alias="STRIPE_API_VERSION", min_length=1)

    @field_validator("api_key", mode="before")
    @classmethod
    def _strip_api_key(cls, value: object) -> object:
        """Trim whitespace around a string key before it is checked."""
        return value.strip() if isinstance(value, str) else value

    @field_validator("api_key")
    @classmethod
    def _check_api_key(cls, value: SecretStr) -> SecretStr:
        """Refuse anything that is not a secret or restricted key; a publishable key is never enough."""
        if not value.get_secret_value().startswith(_API_KEY_PREFIXES):
            raise ValueError("STRIPE_API_KEY is not a secret (sk_) or restricted (rk_) key")
        return value

    @field_validator("webhook_secret", mode="before")
    @classmethod
    def _strip_webhook_secret(cls, value: object) -> object:
        """Trim whitespace around a string secret before it is checked."""
        return value.strip() if isinstance(value, str) else value

    @field_validator("webhook_secret")
    @classmethod
    def _check_webhook_secret(cls, value: SecretStr | None) -> SecretStr | None:
        """Refuse a signing secret that is not a `whsec_` value."""
        if value is not None and not value.get_secret_value().startswith(_WEBHOOK_SECRET_PREFIX):
            raise ValueError("STRIPE_WEBHOOK_SECRET is not a webhook signing secret (whsec_)")
        return value

    @field_validator("api_version", mode="before")
    @classmethod
    def _strip_api_version(cls, value: object) -> object:
        """Trim whitespace around a string version."""
        return value.strip() if isinstance(value, str) else value


def _present(values: Mapping[str, Any]) -> dict[str, str]:
    """The standard keys that carry a non-empty value, matched without regard to case."""
    by_upper = {str(name).upper(): value for name, value in values.items()}
    found: dict[str, str] = {}
    for key in SETTINGS_KEYS:
        value = by_upper.get(key)
        if value is not None and str(value).strip():
            found[key] = str(value)
    return found


def load_stripe_settings(
    secret_arn: str | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    client: Any = None,
    region_name: str | None = None,
) -> StripeSettings:
    """Resolve `StripeSettings` from the environment, then the `app` secret.

    Each key resolves on its own: a non-empty environment variable wins over the secret key
    of the same name, so a local run can override a deployed value. The secret is read
    through `webbpulse.security.app_secrets`, defaulting to `APP_SECRETS_ARN`; with no ARN
    only the environment is read. Raises `StripeNotConfigured` naming the missing or invalid
    keys, never their values.
    """
    from webbpulse.security import app_secrets

    merged = _present(app_secrets(secret_arn, client=client, region_name=region_name))
    merged.update(_present(os.environ if environ is None else environ))
    missing = [key for key in _REQUIRED_KEYS if key not in merged]
    if missing:
        raise StripeNotConfigured(f"the Stripe configuration is missing {', '.join(missing)}")
    try:
        return StripeSettings.model_validate(merged)
    except ValidationError as exc:
        names = sorted({str(error["loc"][0]) for error in exc.errors() if error["loc"]})
        raise StripeNotConfigured(f"the Stripe configuration has invalid {', '.join(names)}") from None


def stripe_client(settings: StripeSettings, *, http_client: stripe.HTTPClient | None = None) -> stripe.StripeClient:
    """Build a `stripe.StripeClient` from the standard settings.

    `http_client` replaces the transport the client sends through, so a test can answer
    requests without the network; left unset, Stripe's default client is used. It needs
    the `stripe` extra.
    """
    import stripe

    return stripe.StripeClient(
        settings.api_key.get_secret_value(),
        stripe_version=settings.api_version,
        http_client=http_client,
    )


def verify_webhook_event(
    payload: bytes,
    signature_header: str | None,
    settings: StripeSettings,
    *,
    tolerance: int = DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
    client: stripe.StripeClient | None = None,
) -> stripe.Event:
    """Check a webhook delivery's signature and answer the event it carries.

    `payload` must be the raw request body exactly as received, never a parsed and
    re-serialised copy, and `signature_header` the `Stripe-Signature` header. A delivery
    signed more than `tolerance` seconds ago is refused. `client` is the client the event
    is bound to, built from `settings` when not given.

    Raises:
        StripeNotConfigured: When `settings` carries no webhook signing secret.
        StripeSignatureError: When the header is missing, malformed, does not match, or is
            too old, or when the body is not a JSON event.
        TypeError: When `payload` is not bytes.
        ValueError: When `tolerance` is not positive.
    """
    if not isinstance(payload, bytes | bytearray):
        raise TypeError("payload must be the raw request body as bytes")
    if tolerance <= 0:
        raise ValueError(f"tolerance must be positive, got {tolerance}")
    if settings.webhook_secret is None:
        raise StripeNotConfigured("the Stripe configuration is missing STRIPE_WEBHOOK_SECRET")
    if not signature_header:
        raise StripeSignatureError("the webhook delivery carries no Stripe-Signature header")
    import stripe

    bound = client if client is not None else stripe_client(settings)
    try:
        return bound.construct_event(
            bytes(payload),
            signature_header,
            settings.webhook_secret.get_secret_value(),
            tolerance,
        )
    except stripe.SignatureVerificationError:
        raise StripeSignatureError("the webhook signature did not verify") from None
    except ValueError:
        raise StripeSignatureError("the webhook body is not a Stripe event") from None


class _Identified(Protocol):
    """Anything carrying a Stripe event id: a `stripe.Event` or a `StripeEvent`."""

    @property
    def id(self) -> str:
        """The event id, such as `evt_...`."""
        ...


def event_claim_key(event_id: str) -> str:
    """The idempotency key a Stripe event id is claimed under."""
    if not event_id:
        raise ValueError("a Stripe event needs an id to be claimed")
    return f"{EVENT_CLAIM_PREFIX}{event_id}"


def claim_webhook_event(
    event: _Identified,
    store: EventClaimStore,
    *,
    ttl_seconds: float = DEFAULT_EVENT_CLAIM_TTL_SECONDS,
) -> bool:
    """Claim a verified event by its id, answering False when it was already claimed.

    Stripe delivers an event at least once and retries until it sees a 2xx, so a receiver
    claims each event before acting and acknowledges a duplicate without acting again. A
    receiver whose work then fails should `release` the key so Stripe's retry can win.
    """
    return store.claim(event_claim_key(event.id), ttl_seconds)


def _object_id(value: Any) -> str | None:
    """The id of a Stripe reference that may be an id string or an expanded object."""
    if isinstance(value, Mapping):
        found = value.get("id")
        return str(found) if found else None
    return str(value) if value else None


@dataclass(frozen=True)
class StripeEvent:
    """A verified webhook event, parsed into plain values.

    `data_object` is the event's `data.object` as a plain dict. `subscription_id`,
    `customer_id` and `reference_id` read the references the billing events carry, across
    the old and new API shapes, so a receiver need not dig through the object itself.
    """

    id: str
    type: str
    data_object: dict[str, Any] = field(repr=False)
    created: int | None = None
    livemode: bool = False
    api_version: str | None = None

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> StripeEvent:
        """Parse an event from its JSON object, raising `StripeSignatureError` when it is not one."""
        event_id = payload.get("id")
        event_type = payload.get("type")
        data = payload.get("data")
        data_object = data.get("object") if isinstance(data, Mapping) else None
        if not isinstance(event_id, str) or not event_id or not isinstance(event_type, str) or not event_type:
            raise StripeSignatureError("the webhook body is not a Stripe event")
        if not isinstance(data_object, Mapping):
            raise StripeSignatureError("the webhook body is not a Stripe event")
        created = payload.get("created")
        api_version = payload.get("api_version")
        return cls(
            id=event_id,
            type=event_type,
            data_object=dict(data_object),
            created=created if isinstance(created, int) else None,
            livemode=bool(payload.get("livemode")),
            api_version=api_version if isinstance(api_version, str) else None,
        )

    @classmethod
    def from_stripe(cls, event: stripe.Event) -> StripeEvent:
        """Parse a `stripe.Event` the SDK already constructed."""
        return cls.from_payload(event.to_dict())

    @property
    def subscription_id(self) -> str | None:
        """The subscription the event concerns: the object itself, a Checkout's, or an invoice's."""
        obj = self.data_object
        if obj.get("object") == "subscription":
            return _object_id(obj.get("id"))
        direct = _object_id(obj.get("subscription"))
        if direct:
            return direct
        parent = obj.get("parent")
        details = parent.get("subscription_details") if isinstance(parent, Mapping) else None
        return _object_id(details.get("subscription")) if isinstance(details, Mapping) else None

    @property
    def customer_id(self) -> str | None:
        """The customer the event's object belongs to, or the customer itself."""
        obj = self.data_object
        if obj.get("object") == "customer":
            return _object_id(obj.get("id"))
        return _object_id(obj.get("customer"))

    @property
    def reference_id(self) -> str | None:
        """A Checkout Session's `client_reference_id`, the owner the session was started for."""
        value = self.data_object.get("client_reference_id")
        return str(value) if value else None


def _check_owner(owner_key: str, owner_id: str) -> None:
    """Refuse an owner key or id that could not be a metadata key or break a search query."""
    if not _OWNER_KEY.fullmatch(owner_key):
        raise ValueError("owner_key must be 1 to 40 letters, digits or underscores")
    if not _OWNER_ID.fullmatch(owner_id):
        raise ValueError("owner_id must be 1 to 200 letters, digits, '_', '.', ':' or '-'")


def customer_idempotency_key(owner_key: str, owner_id: str) -> str:
    """The deterministic Stripe idempotency key the owner's customer is created under."""
    _check_owner(owner_key, owner_id)
    return f"{CUSTOMER_IDEMPOTENCY_PREFIX}-{owner_key}-{owner_id}"


def customer_search_query(owner_key: str, owner_id: str) -> str:
    """The Stripe search query that finds the owner's customers by metadata."""
    _check_owner(owner_key, owner_id)
    return f"metadata['{owner_key}']:'{owner_id}'"


class BillingGateway(Protocol):
    """What subscription billing needs from Stripe, satisfied by `StripeGateway` and `FakeStripeGateway`."""

    def find_price_id(self, lookup_key: str) -> str | None:
        """The id of the active price carrying `lookup_key`, or None."""
        ...

    def find_customer_ids(self, owner_key: str, owner_id: str) -> list[str]:
        """The owner's customer ids by metadata, oldest first."""
        ...

    def ensure_customer(
        self,
        *,
        owner_key: str,
        owner_id: str,
        email: str | None = None,
        name: str | None = None,
        metadata: Mapping[str, str] | None = None,
        customer_id: str | None = None,
    ) -> str:
        """The owner's one customer id, creating it at most once."""
        ...

    def create_checkout_session(
        self,
        *,
        customer_id: str,
        price_id: str,
        reference_id: str,
        success_url: str,
        cancel_url: str,
        quantity: int = 1,
        metadata: Mapping[str, str] | None = None,
    ) -> str:
        """Create a subscription Checkout Session and return its URL."""
        ...

    def create_portal_session(self, *, customer_id: str, return_url: str) -> str:
        """Create a billing portal session and return its URL."""
        ...

    def retrieve_subscription(self, subscription_id: str) -> dict[str, Any]:
        """The subscription as a plain dict."""
        ...

    def set_quantity(self, subscription_id: str, item_id: str, quantity: int) -> dict[str, Any]:
        """Set a subscription item's quantity, prorated, and return the subscription."""
        ...

    def cancel_subscriptions(self, customer_id: str) -> list[str]:
        """Cancel every live subscription of a customer at once, answering the ids cancelled."""
        ...

    def cancel_owner_subscriptions(self, owner_key: str, owner_id: str) -> list[str]:
        """Cancel every live subscription of every customer the owner holds."""
        ...

    def verify_webhook(self, payload: bytes, signature_header: str | None) -> StripeEvent:
        """Verify a delivery against the signing secret and parse its event."""
        ...


class StripeGateway:
    """The subscription billing calls both products make, over one `stripe.StripeClient`.

    Build it from `StripeSettings`; `client` replaces the client built from them, so a test
    can send through a fake transport. Every Stripe failure surfaces as `stripe.StripeError`
    except where a method says otherwise. Nothing here logs a key, the signing secret, a
    signature header or a request body.
    """

    def __init__(
        self,
        settings: StripeSettings,
        *,
        client: stripe.StripeClient | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """Hold the settings and a client built from them unless one is given."""
        self.settings = settings
        self.client = client if client is not None else stripe_client(settings)
        self._sleep = sleep

    def __repr__(self) -> str:
        """Name the class only, since the settings carry the keys."""
        return "StripeGateway()"

    def find_price_id(self, lookup_key: str) -> str | None:
        """The id of the active price carrying `lookup_key`, or None."""
        prices = self.client.v1.prices.list(params={"lookup_keys": [lookup_key], "active": True, "limit": 1})
        return prices.data[0].id if prices.data else None

    def find_customer_ids(self, owner_key: str, owner_id: str) -> list[str]:
        """The ids of every customer whose metadata names the owner, oldest first.

        Stripe search is eventually consistent, usually within a minute, so a customer
        created moments ago may be missing; `ensure_customer` covers that window with its
        idempotency key.
        """
        found = self.client.v1.customers.search(
            params={"query": customer_search_query(owner_key, owner_id), "limit": 100}
        )
        customers = sorted(found.auto_paging_iter(), key=lambda customer: (customer.created, customer.id))
        return [customer.id for customer in customers]

    def ensure_customer(
        self,
        *,
        owner_key: str,
        owner_id: str,
        email: str | None = None,
        name: str | None = None,
        metadata: Mapping[str, str] | None = None,
        customer_id: str | None = None,
    ) -> str:
        """The owner's one Stripe customer id, creating it at most once however many callers race.

        `owner_key` is the metadata key naming the owner, such as `user_id` or
        `workspace_id`, and `owner_id` its value. `customer_id` is the id the caller already
        stored, answered as is.

        The race: two concurrent checkouts for an owner with no stored customer both used to
        call `customers.create`, so Stripe made two customers and the later stored id won,
        stranding the other with its subscription. Three layers close it:

        1. A search by `metadata['<owner_key>']:'<owner_id>'` answers an existing customer,
           the oldest when legacy duplicates exist, so a lost or never-stored id is found
           again rather than replaced.
        2. The create carries the deterministic idempotency key
           `webbpulse-customer-v1-<owner_key>-<owner_id>`. Stripe answers every request with
           that key, for 24 hours, with the response of the first one, so concurrent callers
           that both missed in search get the same customer back. A 409 while the first
           request is still in flight is retried with backoff until it resolves to that
           response.
        3. Past 24 hours the key has expired, but by then search has long indexed the
           customer, so step 1 answers it. Search lags by about a minute and the key lasts a
           day, so the two windows overlap.

        A caller should still store the id with a conditional write, such as
        `attribute_not_exists(stripe_customer_id)`, but since every racer answers the same id
        an unconditional write is also safe. When Stripe refuses the key because an earlier
        create used different parameters, such as a changed email, the owner's customer is
        looked up again; `StripeCustomerConflict` is raised only when none is found.
        """
        import stripe

        if customer_id:
            return customer_id
        existing = self.find_customer_ids(owner_key, owner_id)
        if existing:
            return existing[0]
        params: CustomerCreateParams = {"metadata": {**(metadata or {}), owner_key: owner_id}}
        if email:
            params["email"] = email
        if name:
            params["name"] = name
        key = customer_idempotency_key(owner_key, owner_id)
        for attempt in range(_CONFLICT_ATTEMPTS):
            try:
                created = self.client.v1.customers.create(params=params, options={"idempotency_key": key})
            except stripe.IdempotencyError:
                break
            except stripe.StripeError as error:
                if error.http_status != 409 or attempt == _CONFLICT_ATTEMPTS - 1:
                    raise
                self._sleep(_CONFLICT_BACKOFF_SECONDS * 2**attempt)
                continue
            _log.info(
                "Ensured the Stripe customer for an owner.",
                extra={"owner_key": owner_key, "owner_id": owner_id, "customer_id": created.id},
            )
            return created.id
        existing = self.find_customer_ids(owner_key, owner_id)
        if existing:
            return existing[0]
        raise StripeCustomerConflict(f"Stripe refused the idempotent customer create for {owner_key}")

    def create_checkout_session(
        self,
        *,
        customer_id: str,
        price_id: str,
        reference_id: str,
        success_url: str,
        cancel_url: str,
        quantity: int = 1,
        metadata: Mapping[str, str] | None = None,
    ) -> str:
        """Create a subscription mode Checkout Session and return its URL.

        `reference_id` becomes the session's `client_reference_id`, and `metadata` is set on
        both the session and the subscription it creates, so every later subscription event
        names the owner. Raises `stripe.StripeError` when the session comes back without a URL.
        """
        import stripe

        if quantity < 1:
            raise ValueError("quantity must be at least 1")
        tags = dict(metadata or {})
        session = self.client.v1.checkout.sessions.create(
            params={
                "mode": "subscription",
                "customer": customer_id,
                "client_reference_id": reference_id,
                "line_items": [{"price": price_id, "quantity": quantity}],
                "success_url": success_url,
                "cancel_url": cancel_url,
                "metadata": tags,
                "subscription_data": {"metadata": tags},
            }
        )
        if not session.url:
            raise stripe.StripeError("Checkout Session has no URL")
        return session.url

    def create_portal_session(self, *, customer_id: str, return_url: str) -> str:
        """Create a billing portal session and return its URL."""
        session = self.client.v1.billing_portal.sessions.create(
            params={"customer": customer_id, "return_url": return_url}
        )
        return session.url

    def retrieve_subscription(self, subscription_id: str) -> dict[str, Any]:
        """The subscription with this id, as a plain dict."""
        return self.client.v1.subscriptions.retrieve(subscription_id).to_dict()

    def set_quantity(self, subscription_id: str, item_id: str, quantity: int) -> dict[str, Any]:
        """Set a subscription item's seat quantity, prorated, and return the subscription."""
        if quantity < 1:
            raise ValueError("quantity must be at least 1")
        updated = self.client.v1.subscriptions.update(
            subscription_id,
            params={"items": [{"id": item_id, "quantity": quantity}], "proration_behavior": "create_prorations"},
        )
        return updated.to_dict()

    def cancel_subscriptions(self, customer_id: str) -> list[str]:
        """Cancel every live subscription of a customer immediately, answering the ids cancelled.

        This is the account delete step: billing stops at once, without proration or a final
        invoice. A subscription already `canceled` or `incomplete_expired` is skipped, and
        one that ends between the listing and the cancel is treated as done, so a replay of
        the delete cascade is a no-op. Each cancel carries the idempotency key
        `webbpulse-cancel-v1-<subscription id>`.
        """
        import stripe

        listing = self.client.v1.subscriptions.list(params={"customer": customer_id, "status": "all", "limit": 100})
        cancelled: list[str] = []
        for subscription in listing.auto_paging_iter():
            if subscription.status in ENDED_SUBSCRIPTION_STATUSES:
                continue
            try:
                self.client.v1.subscriptions.cancel(
                    subscription.id,
                    params={"invoice_now": False, "prorate": False},
                    options={"idempotency_key": f"webbpulse-cancel-v1-{subscription.id}"},
                )
            except stripe.InvalidRequestError:
                current = self.client.v1.subscriptions.retrieve(subscription.id)
                if current.status not in ENDED_SUBSCRIPTION_STATUSES:
                    raise
                continue
            cancelled.append(subscription.id)
        if cancelled:
            _log.info(
                "Cancelled a Stripe customer's subscriptions.",
                extra={"customer_id": customer_id, "subscriptions": len(cancelled)},
            )
        return cancelled

    def cancel_owner_subscriptions(self, owner_key: str, owner_id: str) -> list[str]:
        """Cancel every live subscription of every customer whose metadata names the owner.

        For a delete cascade that runs after the owner's row is gone and so has no stored
        customer id. Duplicate customers from before `ensure_customer` are covered too.
        """
        cancelled: list[str] = []
        for customer_id in self.find_customer_ids(owner_key, owner_id):
            cancelled.extend(self.cancel_subscriptions(customer_id))
        return cancelled

    def verify_webhook(
        self, payload: bytes, signature_header: str | None, *, tolerance: int = DEFAULT_WEBHOOK_TOLERANCE_SECONDS
    ) -> StripeEvent:
        """Verify a delivery with the configured signing secret and parse it into a `StripeEvent`.

        `payload` is the raw request body and `signature_header` the `Stripe-Signature`
        header. Raises what `verify_webhook_event` raises.
        """
        return StripeEvent.from_stripe(
            verify_webhook_event(payload, signature_header, self.settings, tolerance=tolerance, client=self.client)
        )
