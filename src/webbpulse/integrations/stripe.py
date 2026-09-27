"""Stripe configuration, a client built from it, and verified, claimed webhook events.

`StripeSettings` is the one configuration shape every product reads from its `app` secret,
and `load_stripe_settings` resolves it from the environment and that secret. `stripe_client`
builds a `stripe.StripeClient` from those settings, which is what a product calls Checkout,
subscriptions and the billing portal through. `verify_webhook_event` checks a delivery's
`Stripe-Signature` header against the raw request body and answers the `stripe.Event`, and
`claim_webhook_event` claims the event id once, so a redelivered event does its work once.
Nothing here routes events or knows any product's prices or plans.

Every failure raised here is a `StripeIntegrationError`. The API key and the webhook signing
secret stay out of reprs, exception messages and log lines.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any, Final, Protocol

import stripe
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, field_validator

__all__ = [
    "DEFAULT_EVENT_CLAIM_TTL_SECONDS",
    "DEFAULT_WEBHOOK_TOLERANCE_SECONDS",
    "EVENT_CLAIM_PREFIX",
    "SETTINGS_KEYS",
    "EventClaimStore",
    "StripeIntegrationError",
    "StripeNotConfigured",
    "StripeSettings",
    "StripeSignatureError",
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


class StripeIntegrationError(Exception):
    """Stripe is not configured, or a webhook delivery cannot be trusted."""


class StripeNotConfigured(StripeIntegrationError):
    """The environment and the `app` secret lack a usable Stripe configuration."""


class StripeSignatureError(StripeIntegrationError):
    """A webhook delivery's signature is missing, malformed, wrong or too old, or its body is not an event."""


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
    requests without the network; left unset, Stripe's default client is used.
    """
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


def event_claim_key(event_id: str) -> str:
    """The idempotency key a Stripe event id is claimed under."""
    if not event_id:
        raise ValueError("a Stripe event needs an id to be claimed")
    return f"{EVENT_CLAIM_PREFIX}{event_id}"


def claim_webhook_event(
    event: stripe.Event,
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
