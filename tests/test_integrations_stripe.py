"""`webbpulse.integrations.stripe`: settings, the client, webhook verification and event claims."""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from typing import Any, ClassVar

import pytest
import stripe

from webbpulse.integrations.stripe import (
    DEFAULT_EVENT_CLAIM_TTL_SECONDS,
    EVENT_CLAIM_PREFIX,
    SETTINGS_KEYS,
    StripeIntegrationError,
    StripeNotConfigured,
    StripeSettings,
    StripeSignatureError,
    claim_webhook_event,
    event_claim_key,
    load_stripe_settings,
    stripe_client,
    verify_webhook_event,
)
from webbpulse.testing import FakeIdempotencyStore, sign_stripe_payload

API_KEY = "rk_test_restricted-key-value"

WEBHOOK_SECRET = "whsec_webhook-secret-value"

EVENT_ID = "evt_1TestEvent"


class FakeSecrets:
    """A Secrets Manager stand-in answering one JSON secret."""

    def __init__(self, payload: dict[str, Any]) -> None:
        """Hold the secret's JSON object."""
        self.payload = payload

    def get_secret_value(self, SecretId: str) -> dict[str, Any]:
        """Answer the payload as a secret string."""
        return {"SecretString": json.dumps(self.payload)}


class FakeHttpClient(stripe.HTTPClient):
    """A Stripe transport that records each request and answers one canned JSON body."""

    name: ClassVar[str] = "fake"

    def __init__(self, body: dict[str, Any]) -> None:
        """Hold the body every request is answered with."""
        super().__init__()
        self.body = body
        self.requests: list[tuple[str, str, dict[str, str]]] = []

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str] | None,
        post_data: Any = None,
        *,
        _usage: list[str] | None = None,
    ) -> tuple[str, int, Mapping[str, str]]:
        """Record the request and answer the canned body with a 200."""
        self.requests.append((method, url, dict(headers or {})))
        return json.dumps(self.body), 200, {}

    def close(self) -> None:
        """Nothing to close."""


def _app_secret() -> dict[str, Any]:
    """An `app` secret carrying the Stripe keys beside an unrelated one."""
    return {
        "SECRET_KEY": "unrelated",
        "STRIPE_API_KEY": API_KEY,
        "STRIPE_WEBHOOK_SECRET": WEBHOOK_SECRET,
    }


def _settings(**overrides: str) -> StripeSettings:
    """Settings carrying the test key and signing secret, with any key replaced."""
    values: dict[str, str] = {"STRIPE_API_KEY": API_KEY, "STRIPE_WEBHOOK_SECRET": WEBHOOK_SECRET}
    values.update(overrides)
    return StripeSettings.model_validate(values)


def _event_body(event_id: str = EVENT_ID) -> bytes:
    """A raw `checkout.session.completed` delivery body."""
    return json.dumps(
        {
            "id": event_id,
            "object": "event",
            "type": "checkout.session.completed",
            "api_version": "2026-08-27.basil",
            "created": 1_800_000_000,
            "livemode": False,
            "data": {"object": {"id": "cs_test_1", "object": "checkout.session"}},
        }
    ).encode()


def test_settings_keys_name_every_field() -> None:
    """`SETTINGS_KEYS` spells every alias the settings read."""
    aliases = {field.alias for field in StripeSettings.model_fields.values()}
    assert aliases == set(SETTINGS_KEYS)


def test_settings_load_from_the_app_secret() -> None:
    """The keys load from the secret, and the version is left to the SDK."""
    settings = load_stripe_settings("arn:secret", environ={}, client=FakeSecrets(_app_secret()))
    assert settings.api_key.get_secret_value() == API_KEY
    assert settings.webhook_secret is not None
    assert settings.webhook_secret.get_secret_value() == WEBHOOK_SECRET
    assert settings.api_version is None


def test_settings_repr_masks_every_secret() -> None:
    """No secret value appears in the settings repr or str."""
    settings = load_stripe_settings("arn:secret", environ={}, client=FakeSecrets(_app_secret()))
    rendered = repr(settings) + str(settings)
    assert API_KEY not in rendered
    assert WEBHOOK_SECRET not in rendered


def test_settings_environment_wins_per_key() -> None:
    """A non-empty environment value overrides the secret for its key alone, in any case."""
    environ = {"stripe_api_key": "sk_test_local", "STRIPE_WEBHOOK_SECRET": "", "STRIPE_API_VERSION": "2026-08-27.basil"}
    settings = load_stripe_settings("arn:secret", environ=environ, client=FakeSecrets(_app_secret()))
    assert settings.api_key.get_secret_value() == "sk_test_local"
    assert settings.webhook_secret is not None
    assert settings.webhook_secret.get_secret_value() == WEBHOOK_SECRET
    assert settings.api_version == "2026-08-27.basil"


def test_settings_without_an_arn_read_only_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no ARN the environment alone configures Stripe, and the signing secret is optional."""
    monkeypatch.delenv("APP_SECRETS_ARN", raising=False)
    settings = load_stripe_settings(environ={"STRIPE_API_KEY": API_KEY})
    assert settings.api_key.get_secret_value() == API_KEY
    assert settings.webhook_secret is None


def test_settings_missing_api_key() -> None:
    """A missing API key raises `StripeNotConfigured` naming it."""
    payload = _app_secret()
    del payload["STRIPE_API_KEY"]
    with pytest.raises(StripeNotConfigured, match="STRIPE_API_KEY") as caught:
        load_stripe_settings("arn:secret", environ={}, client=FakeSecrets(payload))
    assert isinstance(caught.value, StripeIntegrationError)


def test_settings_invalid_values_name_the_key_not_the_value() -> None:
    """A publishable key and a malformed signing secret are refused without echoing either."""
    environ = {"STRIPE_API_KEY": "pk_test_publishable-value", "STRIPE_WEBHOOK_SECRET": "not-a-signing-secret"}
    with pytest.raises(StripeNotConfigured) as caught:
        load_stripe_settings(environ=environ, secret_arn="")
    message = str(caught.value)
    assert "STRIPE_API_KEY" in message
    assert "STRIPE_WEBHOOK_SECRET" in message
    assert "pk_test_publishable-value" not in message
    assert "not-a-signing-secret" not in message
    assert caught.value.__cause__ is None


def test_client_sends_through_the_injected_transport_with_the_key() -> None:
    """The client authenticates with the settings key and sends through the given transport."""
    http = FakeHttpClient({"id": "cus_1", "object": "customer"})
    client = stripe_client(_settings(), http_client=http)
    customer = client.v1.customers.retrieve("cus_1")
    assert customer.id == "cus_1"
    [(method, url, headers)] = http.requests
    assert method == "get"
    assert url.endswith("/v1/customers/cus_1")
    assert headers["Authorization"] == f"Bearer {API_KEY}"
    assert headers["Stripe-Version"] == stripe.api_version


def test_client_pins_the_configured_api_version() -> None:
    """A configured API version is the one the client sends."""
    http = FakeHttpClient({"id": "cus_1", "object": "customer"})
    client = stripe_client(_settings(STRIPE_API_VERSION="2026-08-27.basil"), http_client=http)
    client.v1.customers.retrieve("cus_1")
    assert http.requests[0][2]["Stripe-Version"] == "2026-08-27.basil"


def test_verify_answers_the_signed_event() -> None:
    """A correctly signed, fresh delivery answers its event."""
    body = _event_body()
    event = verify_webhook_event(body, sign_stripe_payload(body, WEBHOOK_SECRET), _settings())
    assert isinstance(event, stripe.Event)
    assert event.id == EVENT_ID
    assert event.type == "checkout.session.completed"


def test_verify_accepts_an_injected_client() -> None:
    """The event binds to a client the caller already holds."""
    body = _event_body()
    client = stripe_client(_settings(), http_client=FakeHttpClient({}))
    event = verify_webhook_event(body, sign_stripe_payload(body, WEBHOOK_SECRET), _settings(), client=client)
    assert event.id == EVENT_ID


def _bad_header(case: str) -> str | None:
    """A `Stripe-Signature` header that must not verify against `_event_body()`, by case."""
    headers: dict[str, str | None] = {
        "wrong-secret": sign_stripe_payload(_event_body(), "whsec_some-other-secret"),
        "other-body": sign_stripe_payload(_event_body("evt_other"), WEBHOOK_SECRET),
        "malformed": "t=abc,v1=def",
        "garbage": "garbage",
        "empty": "",
        "missing": None,
    }
    return headers[case]


@pytest.mark.parametrize("case", ["wrong-secret", "other-body", "malformed", "garbage", "empty", "missing"])
def test_verify_refuses_a_bad_signature(case: str) -> None:
    """A wrong, mismatched, malformed or missing signature raises `StripeSignatureError`."""
    with pytest.raises(StripeSignatureError) as caught:
        verify_webhook_event(_event_body(), _bad_header(case), _settings())
    assert isinstance(caught.value, StripeIntegrationError)
    assert WEBHOOK_SECRET not in str(caught.value)
    assert caught.value.__cause__ is None


def test_verify_refuses_an_expired_signature() -> None:
    """A delivery signed longer ago than the tolerance is refused."""
    body = _event_body()
    header = sign_stripe_payload(body, WEBHOOK_SECRET, timestamp=int(time.time()) - 301)
    with pytest.raises(StripeSignatureError):
        verify_webhook_event(body, header, _settings())
    assert verify_webhook_event(body, header, _settings(), tolerance=600).id == EVENT_ID


def test_verify_refuses_a_signed_body_that_is_not_json() -> None:
    """A correctly signed body that is not an event is refused as untrustworthy."""
    body = b"not json"
    with pytest.raises(StripeSignatureError, match="not a Stripe event"):
        verify_webhook_event(body, sign_stripe_payload(body, WEBHOOK_SECRET), _settings())


def test_verify_without_a_signing_secret_is_not_configured() -> None:
    """Settings without a webhook secret raise `StripeNotConfigured`, before the header is read."""
    settings = StripeSettings.model_validate({"STRIPE_API_KEY": API_KEY})
    with pytest.raises(StripeNotConfigured, match="STRIPE_WEBHOOK_SECRET"):
        verify_webhook_event(_event_body(), "t=1,v1=abc", settings)


def test_verify_takes_raw_bytes_only() -> None:
    """A decoded body is refused, since only the raw bytes carry the signature."""
    body = _event_body()
    header = sign_stripe_payload(body, WEBHOOK_SECRET)
    with pytest.raises(TypeError):
        verify_webhook_event(body.decode(), header, _settings())  # type: ignore[arg-type]


def test_verify_refuses_a_disabled_tolerance() -> None:
    """A zero tolerance would switch the age check off, so it is refused."""
    body = _event_body()
    with pytest.raises(ValueError, match="tolerance"):
        verify_webhook_event(body, sign_stripe_payload(body, WEBHOOK_SECRET), _settings(), tolerance=0)


def test_claim_wins_once_per_event() -> None:
    """The first claim of an event wins, a redelivery loses, and another event wins."""
    store = FakeIdempotencyStore()
    body = _event_body()
    event = verify_webhook_event(body, sign_stripe_payload(body, WEBHOOK_SECRET), _settings())
    assert claim_webhook_event(event, store) is True
    assert claim_webhook_event(event, store) is False
    other_body = _event_body("evt_other")
    other = verify_webhook_event(other_body, sign_stripe_payload(other_body, WEBHOOK_SECRET), _settings())
    assert claim_webhook_event(other, store) is True
    assert store.claims == [f"stripe:event:{EVENT_ID}", f"stripe:event:{EVENT_ID}", "stripe:event:evt_other"]


def test_claim_expires_and_can_be_released() -> None:
    """A claim lapses after its TTL, and a released claim lets the retry win."""
    now = [0.0]
    store = FakeIdempotencyStore(now=lambda: now[0])
    body = _event_body()
    event = verify_webhook_event(body, sign_stripe_payload(body, WEBHOOK_SECRET), _settings())
    assert claim_webhook_event(event, store, ttl_seconds=60) is True
    now[0] = 61.0
    assert claim_webhook_event(event, store) is True
    store.release(event_claim_key(event.id))
    assert claim_webhook_event(event, store) is True
    assert DEFAULT_EVENT_CLAIM_TTL_SECONDS > 3 * 24 * 60 * 60


def test_event_claim_key_refuses_an_empty_id() -> None:
    """An event with no id cannot be claimed."""
    assert event_claim_key("evt_1") == f"{EVENT_CLAIM_PREFIX}evt_1"
    with pytest.raises(ValueError):
        event_claim_key("")


def test_signed_header_has_stripes_shape() -> None:
    """The test signer answers `t=<timestamp>,v1=<hex>` at the given time."""
    header = sign_stripe_payload(b"{}", WEBHOOK_SECRET, timestamp=1_800_000_000)
    stamp, signature = header.split(",")
    assert stamp == "t=1800000000"
    assert signature.startswith("v1=")
    assert len(signature) == 3 + 64
