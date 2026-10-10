"""`webbpulse.integrations.stripe.StripeGateway`, `StripeEvent` and `webbpulse.testing.FakeStripeGateway`."""

from __future__ import annotations

import json
import logging
import subprocess  # nosec B404
import sys
import threading
import time
from collections.abc import Mapping
from typing import Any, ClassVar
from urllib.parse import parse_qsl, urlsplit

import pytest
import stripe

from webbpulse.integrations.stripe import (
    CUSTOMER_IDEMPOTENCY_PREFIX,
    BillingGateway,
    StripeCustomerConflict,
    StripeEvent,
    StripeGateway,
    StripeIntegrationError,
    StripeNotConfigured,
    StripeSettings,
    StripeSignatureError,
    claim_webhook_event,
    customer_idempotency_key,
    customer_search_query,
)
from webbpulse.testing import FakeIdempotencyStore, FakeStripeGateway, sign_stripe_payload

API_KEY = "rk_" + "test_" + "gateway-key-value"

WEBHOOK_SECRET = "whsec_" + "gateway-signing-value"

OWNER = "0b9a7c1e-2f4d-4c8e-9a1b-3d5e7f9a1b2c"


def _error(status: int, kind: str, message: str) -> tuple[int, dict[str, Any]]:
    """A Stripe error response."""
    return status, {"error": {"type": kind, "message": message}}


class FakeStripeApi(stripe.HTTPClient):
    """A Stripe transport that keeps customers and subscriptions and honours idempotency keys.

    `searchable` False models search lag: the search answers nothing however many customers
    exist. `search_barrier` holds each search until every racer has searched. `failures`
    queues error responses per `(method, path)` ahead of the normal answer.
    """

    name: ClassVar[str] = "fake-api"

    def __init__(self) -> None:
        """Start with one price and nothing else."""
        super().__init__()
        self.lock = threading.Lock()
        self.customers: dict[str, dict[str, Any]] = {}
        self.subscriptions: dict[str, dict[str, Any]] = {}
        self.prices = {"premium_monthly": "price_premium"}
        self.idempotent: dict[str, tuple[str, int]] = {}
        self.requests: list[tuple[str, str, dict[str, str], dict[str, str]]] = []
        self.failures: dict[tuple[str, str], list[tuple[int, dict[str, Any]]]] = {}
        self.searchable = True
        self.search_barrier: threading.Barrier | None = None
        self.sequence = 0

    def _next(self, prefix: str) -> str:
        """A fresh object id."""
        self.sequence += 1
        return f"{prefix}_{self.sequence}"

    def add_customer(self, owner: str, *, created: int) -> str:
        """Seed a customer whose metadata names `owner`."""
        customer_id = self._next("cus")
        self.customers[customer_id] = {
            "id": customer_id,
            "object": "customer",
            "created": created,
            "metadata": {"user_id": owner},
        }
        return customer_id

    def add_subscription(self, customer_id: str, status: str = "active") -> str:
        """Seed a subscription for `customer_id`."""
        subscription_id = self._next("sub")
        self.subscriptions[subscription_id] = {
            "id": subscription_id,
            "object": "subscription",
            "customer": customer_id,
            "status": status,
            "items": {"object": "list", "data": [{"id": self._next("si"), "object": "subscription_item"}]},
        }
        return subscription_id

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str] | None,
        post_data: Any = None,
        *,
        _usage: list[str] | None = None,
    ) -> tuple[str, int, Mapping[str, str]]:
        """Answer one request the way Stripe would."""
        parts = urlsplit(url)
        fields = dict(parse_qsl(parts.query)) | dict(parse_qsl(post_data or ""))
        sent = dict(headers or {})
        path = parts.path
        if path == "/v1/customers/search" and self.search_barrier is not None:
            self.search_barrier.wait(timeout=5)
        with self.lock:
            self.requests.append((method, path, sent, fields))
            queued = self.failures.get((method, path))
            if queued:
                status, body = queued.pop(0)
                return json.dumps(body), status, {}
            key = sent.get("Idempotency-Key")
            if key and key in self.idempotent:
                body_text, status = self.idempotent[key]
                return body_text, status, {}
            status, payload = self._answer(method, path, fields)
            body_text = json.dumps(payload)
            if key and method == "post":
                self.idempotent[key] = (body_text, status)
            return body_text, status, {}

    def _answer(self, method: str, path: str, fields: dict[str, str]) -> tuple[int, dict[str, Any]]:
        """The status and body for one request, under the lock."""
        if path == "/v1/prices":
            price = self.prices.get(fields.get("lookup_keys[0]", ""))
            data = [{"id": price, "object": "price"}] if price else []
            return 200, {"object": "list", "data": data, "has_more": False, "url": path}
        if path == "/v1/customers/search":
            found: list[dict[str, Any]] = []
            if self.searchable:
                query = fields["query"]
                found = [
                    customer
                    for customer in self.customers.values()
                    if any(f"metadata['{k}']:'{v}'" == query for k, v in customer["metadata"].items())
                ]
            return 200, {"object": "search_result", "data": found, "has_more": False, "next_page": None, "url": path}
        if path == "/v1/customers" and method == "post":
            customer_id = self._next("cus")
            metadata = {name[9:-1]: value for name, value in fields.items() if name.startswith("metadata[")}
            customer = {
                "id": customer_id,
                "object": "customer",
                "created": 1_800_000_000 + self.sequence,
                "email": fields.get("email"),
                "metadata": metadata,
            }
            self.customers[customer_id] = customer
            return 200, customer
        if path == "/v1/checkout/sessions":
            session_id = self._next("cs")
            return 200, {"id": session_id, "object": "checkout.session", "url": f"https://checkout.test/{session_id}"}
        if path == "/v1/billing_portal/sessions":
            return 200, {"id": "bps_1", "object": "billing_portal.session", "url": "https://portal.test/bps_1"}
        if path == "/v1/subscriptions" and method == "get":
            data = [sub for sub in self.subscriptions.values() if sub["customer"] == fields.get("customer")]
            return 200, {"object": "list", "data": data, "has_more": False, "url": path}
        if path.startswith("/v1/subscriptions/"):
            subscription = self.subscriptions.get(path.rsplit("/", 1)[1])
            if subscription is None:
                return _error(404, "invalid_request_error", "No such subscription")
            if method == "delete":
                if subscription["status"] == "canceled":
                    return _error(400, "invalid_request_error", "already canceled")
                subscription["status"] = "canceled"
            if method == "post" and "items[0][quantity]" in fields:
                subscription["items"]["data"][0]["quantity"] = int(fields["items[0][quantity]"])
            return 200, subscription
        return _error(404, "invalid_request_error", f"unrouted {method} {path}")

    def close(self) -> None:
        """Nothing to close."""


def _settings(**overrides: str) -> StripeSettings:
    """Settings carrying the test key and signing secret."""
    values = {"STRIPE_API_KEY": API_KEY, "STRIPE_WEBHOOK_SECRET": WEBHOOK_SECRET} | overrides
    return StripeSettings.model_validate(values)


def _gateway(api: FakeStripeApi, sleeps: list[float] | None = None) -> StripeGateway:
    """A gateway sending through `api`, with network retries off and sleeps recorded."""
    client = stripe.StripeClient(API_KEY, http_client=api, max_network_retries=0)
    recorded = sleeps if sleeps is not None else []
    return StripeGateway(_settings(), client=client, sleep=recorded.append)


def _calls(api: FakeStripeApi, method: str, path: str) -> list[tuple[dict[str, str], dict[str, str]]]:
    """The headers and fields of every request to `method path`."""
    return [(headers, fields) for m, p, headers, fields in api.requests if m == method and p == path]


def test_find_price_id() -> None:
    """A known lookup key answers its price, an unknown one None."""
    gateway = _gateway(FakeStripeApi())
    assert gateway.find_price_id("premium_monthly") == "price_premium"
    assert gateway.find_price_id("missing") is None


def test_ensure_customer_answers_a_stored_id_without_calling_stripe() -> None:
    """A caller's stored customer id is answered as is."""
    api = FakeStripeApi()
    assert _gateway(api).ensure_customer(owner_key="user_id", owner_id=OWNER, customer_id="cus_stored") == "cus_stored"
    assert api.requests == []


def test_ensure_customer_finds_the_oldest_existing_customer() -> None:
    """A customer already tagged with the owner is reused, the oldest of legacy duplicates."""
    api = FakeStripeApi()
    newer = api.add_customer(OWNER, created=200)
    older = api.add_customer(OWNER, created=100)
    assert newer != older
    assert _gateway(api).ensure_customer(owner_key="user_id", owner_id=OWNER) == older
    [(_, fields)] = _calls(api, "get", "/v1/customers/search")
    assert fields["query"] == f"metadata['user_id']:'{OWNER}'"
    assert _calls(api, "post", "/v1/customers") == []


def test_ensure_customer_creates_under_the_deterministic_key() -> None:
    """A new owner's customer is created once, tagged, under the owner's idempotency key."""
    api = FakeStripeApi()
    customer_id = _gateway(api).ensure_customer(
        owner_key="user_id", owner_id=OWNER, email="person@example.test", metadata={"plan": "premium"}
    )
    [(headers, fields)] = _calls(api, "post", "/v1/customers")
    assert headers["Idempotency-Key"] == f"{CUSTOMER_IDEMPOTENCY_PREFIX}-user_id-{OWNER}"
    assert fields["metadata[user_id]"] == OWNER
    assert fields["metadata[plan]"] == "premium"
    assert fields["email"] == "person@example.test"
    assert api.customers[customer_id]["metadata"]["user_id"] == OWNER


def test_concurrent_ensure_customer_creates_one_customer() -> None:
    """Two racers that both miss in search still get one customer, the CAR-11 race."""
    api = FakeStripeApi()
    api.searchable = False
    api.search_barrier = threading.Barrier(2)
    gateway = _gateway(api)
    answers: list[str] = []

    def checkout() -> None:
        """One concurrent checkout's customer step."""
        answers.append(gateway.ensure_customer(owner_key="user_id", owner_id=OWNER, email="person@example.test"))

    threads = [threading.Thread(target=checkout) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert len(answers) == 2
    assert answers[0] == answers[1]
    assert len(api.customers) == 1
    assert len(_calls(api, "post", "/v1/customers")) == 2


def test_ensure_customer_retries_an_in_flight_conflict() -> None:
    """A 409 while the first request with the key is in flight is retried with backoff."""
    api = FakeStripeApi()
    api.failures[("post", "/v1/customers")] = [
        _error(409, "idempotency_error", "in progress"),
        _error(409, "idempotency_error", "in progress"),
    ]
    sleeps: list[float] = []
    customer_id = _gateway(api, sleeps).ensure_customer(owner_key="user_id", owner_id=OWNER)
    assert customer_id in api.customers
    assert sleeps == [0.5, 1.0]


def test_ensure_customer_gives_up_after_repeated_conflicts() -> None:
    """A conflict that never resolves surfaces as the Stripe error."""
    api = FakeStripeApi()
    api.failures[("post", "/v1/customers")] = [_error(409, "idempotency_error", "in progress")] * 4
    with pytest.raises(stripe.StripeError) as caught:
        _gateway(api).ensure_customer(owner_key="user_id", owner_id=OWNER)
    assert caught.value.http_status == 409


def test_ensure_customer_falls_back_to_search_on_a_parameter_mismatch() -> None:
    """A key reused with other parameters looks the customer up instead of creating another."""
    api = FakeStripeApi()
    existing = api.add_customer(OWNER, created=100)
    api.searchable = False
    api.failures[("post", "/v1/customers")] = [_error(400, "idempotency_error", "different parameters")]
    original_answer = api._answer

    def answer_after_lag(method: str, path: str, fields: dict[str, str]) -> tuple[int, dict[str, Any]]:
        """Let search see the customer once the create has been refused."""
        if path == "/v1/customers/search" and _calls(api, "post", "/v1/customers"):
            api.searchable = True
        return original_answer(method, path, fields)

    api._answer = answer_after_lag  # type: ignore[method-assign]
    assert _gateway(api).ensure_customer(owner_key="user_id", owner_id=OWNER, email="new@example.test") == existing


def test_ensure_customer_conflict_without_a_customer() -> None:
    """A refused key with no customer to find raises `StripeCustomerConflict`."""
    api = FakeStripeApi()
    api.failures[("post", "/v1/customers")] = [_error(400, "idempotency_error", "different parameters")]
    with pytest.raises(StripeCustomerConflict) as caught:
        _gateway(api).ensure_customer(owner_key="user_id", owner_id=OWNER)
    assert isinstance(caught.value, StripeIntegrationError)


@pytest.mark.parametrize(
    ("owner_key", "owner_id"),
    [("user id", OWNER), ("user_id", "x' OR metadata['a']:'b"), ("", OWNER), ("user_id", ""), ("k" * 41, OWNER)],
)
def test_owner_values_that_could_break_a_query_are_refused(owner_key: str, owner_id: str) -> None:
    """An owner key or id outside the safe alphabet is refused before any call."""
    api = FakeStripeApi()
    with pytest.raises(ValueError):
        _gateway(api).ensure_customer(owner_key=owner_key, owner_id=owner_id)
    with pytest.raises(ValueError):
        customer_idempotency_key(owner_key, owner_id)
    with pytest.raises(ValueError):
        customer_search_query(owner_key, owner_id)
    assert api.requests == []


def test_checkout_session_tags_the_session_and_subscription() -> None:
    """The session carries the reference, the quantity and the metadata on both objects."""
    api = FakeStripeApi()
    url = _gateway(api).create_checkout_session(
        customer_id="cus_1",
        price_id="price_premium",
        reference_id="ws_1",
        success_url="https://app.test/ok",
        cancel_url="https://app.test/cancel",
        quantity=3,
        metadata={"workspace_id": "ws_1"},
    )
    assert url.startswith("https://checkout.test/")
    [(_, fields)] = _calls(api, "post", "/v1/checkout/sessions")
    assert fields["mode"] == "subscription"
    assert fields["client_reference_id"] == "ws_1"
    assert fields["line_items[0][quantity]"] == "3"
    assert fields["metadata[workspace_id]"] == "ws_1"
    assert fields["subscription_data[metadata][workspace_id]"] == "ws_1"


def test_checkout_session_refuses_no_seats_and_a_missing_url() -> None:
    """A zero quantity is refused, and a session without a URL is a Stripe error."""
    api = FakeStripeApi()
    gateway = _gateway(api)
    arguments: dict[str, Any] = {
        "customer_id": "cus_1",
        "price_id": "price_premium",
        "reference_id": "u",
        "success_url": "https://app.test/ok",
        "cancel_url": "https://app.test/cancel",
    }
    with pytest.raises(ValueError):
        gateway.create_checkout_session(**arguments, quantity=0)
    api.failures[("post", "/v1/checkout/sessions")] = [(200, {"id": "cs_x", "object": "checkout.session", "url": None})]
    with pytest.raises(stripe.StripeError, match="no URL"):
        gateway.create_checkout_session(**arguments)


def test_portal_session_and_quantity() -> None:
    """The portal answers its URL, and a seat change updates the item."""
    api = FakeStripeApi()
    subscription_id = api.add_subscription("cus_1")
    gateway = _gateway(api)
    portal = gateway.create_portal_session(customer_id="cus_1", return_url="https://app.test/")
    assert portal == "https://portal.test/bps_1"
    item_id = gateway.retrieve_subscription(subscription_id)["items"]["data"][0]["id"]
    updated = gateway.set_quantity(subscription_id, item_id, 4)
    assert updated["items"]["data"][0]["quantity"] == 4
    [(_, fields)] = _calls(api, "post", f"/v1/subscriptions/{subscription_id}")
    assert fields["proration_behavior"] == "create_prorations"


def test_cancel_subscriptions_cancels_live_ones_once() -> None:
    """Live subscriptions are cancelled at once under a key, ended ones skipped, and a replay does nothing."""
    api = FakeStripeApi()
    live = api.add_subscription("cus_1")
    past_due = api.add_subscription("cus_1", status="past_due")
    api.add_subscription("cus_1", status="canceled")
    api.add_subscription("cus_1", status="incomplete_expired")
    api.add_subscription("cus_other")
    gateway = _gateway(api)
    assert gateway.cancel_subscriptions("cus_1") == [live, past_due]
    deletes = _calls(api, "delete", f"/v1/subscriptions/{live}")
    assert deletes[0][0]["Idempotency-Key"] == f"webbpulse-cancel-v1-{live}"
    assert deletes[0][1] == {"invoice_now": "false", "prorate": "false"}
    assert gateway.cancel_subscriptions("cus_1") == []


def test_cancel_treats_a_subscription_that_ended_meanwhile_as_done() -> None:
    """A cancel refused because the subscription just ended is not an error."""
    api = FakeStripeApi()
    live = api.add_subscription("cus_1")
    api.failures[("delete", f"/v1/subscriptions/{live}")] = [_error(400, "invalid_request_error", "gone")]
    api.subscriptions[live]["status"] = "active"
    original_answer = api._answer

    def end_on_retrieve(method: str, path: str, fields: dict[str, str]) -> tuple[int, dict[str, Any]]:
        """Show the subscription as cancelled once the cancel was refused."""
        if method == "get" and path == f"/v1/subscriptions/{live}":
            api.subscriptions[live]["status"] = "canceled"
        return original_answer(method, path, fields)

    api._answer = end_on_retrieve  # type: ignore[method-assign]
    assert _gateway(api).cancel_subscriptions("cus_1") == []


def test_cancel_reraises_a_refusal_for_a_live_subscription() -> None:
    """A refused cancel of a subscription that is still live surfaces."""
    api = FakeStripeApi()
    live = api.add_subscription("cus_1")
    api.failures[("delete", f"/v1/subscriptions/{live}")] = [_error(400, "invalid_request_error", "nope")]
    with pytest.raises(stripe.InvalidRequestError):
        _gateway(api).cancel_subscriptions("cus_1")


def test_cancel_owner_subscriptions_covers_duplicate_customers() -> None:
    """Deleting an owner cancels the subscriptions of every customer tagged with it, the CAR-10 fix."""
    api = FakeStripeApi()
    first = api.add_customer(OWNER, created=100)
    second = api.add_customer(OWNER, created=200)
    stranger = api.add_customer("someone-else", created=50)
    one = api.add_subscription(first)
    two = api.add_subscription(second)
    kept = api.add_subscription(stranger)
    assert _gateway(api).cancel_owner_subscriptions("user_id", OWNER) == [one, two]
    assert api.subscriptions[kept]["status"] == "active"


def _event_body(obj: dict[str, Any], event_type: str = "checkout.session.completed") -> bytes:
    """A raw delivery body around `obj`."""
    return json.dumps(
        {
            "id": "evt_gateway",
            "object": "event",
            "type": event_type,
            "created": 1_800_000_000,
            "livemode": False,
            "api_version": "2026-08-27.basil",
            "data": {"object": obj},
        }
    ).encode()


def test_verify_webhook_parses_a_checkout_event() -> None:
    """A signed Checkout event parses with its subscription, customer and reference."""
    body = _event_body(
        {
            "id": "cs_1",
            "object": "checkout.session",
            "subscription": "sub_1",
            "customer": "cus_1",
            "client_reference_id": OWNER,
        }
    )
    event = _gateway(FakeStripeApi()).verify_webhook(body, sign_stripe_payload(body, WEBHOOK_SECRET))
    assert isinstance(event, StripeEvent)
    assert (event.id, event.type, event.created, event.livemode) == (
        "evt_gateway",
        "checkout.session.completed",
        1_800_000_000,
        False,
    )
    assert event.api_version == "2026-08-27.basil"
    assert (event.subscription_id, event.customer_id, event.reference_id) == ("sub_1", "cus_1", OWNER)
    assert "client_reference_id" not in repr(event)


def test_event_references_across_object_shapes() -> None:
    """Subscription, new invoice and customer objects all answer their references."""
    subscription = StripeEvent.from_payload(
        json.loads(_event_body({"id": "sub_2", "object": "subscription", "customer": {"id": "cus_2"}}))
    )
    assert (subscription.subscription_id, subscription.customer_id) == ("sub_2", "cus_2")
    invoice = StripeEvent.from_payload(
        json.loads(
            _event_body(
                {
                    "id": "in_1",
                    "object": "invoice",
                    "customer": "cus_3",
                    "parent": {"subscription_details": {"subscription": "sub_3"}},
                },
                "invoice.payment_failed",
            )
        )
    )
    assert (invoice.subscription_id, invoice.customer_id, invoice.reference_id) == ("sub_3", "cus_3", None)
    customer = StripeEvent.from_payload(json.loads(_event_body({"id": "cus_4", "object": "customer"})))
    assert (customer.customer_id, customer.subscription_id) == ("cus_4", None)


@pytest.mark.parametrize("payload", [{}, {"id": "evt", "type": "x"}, {"id": "evt", "type": "x", "data": {"object": 1}}])
def test_event_parse_refuses_a_non_event(payload: dict[str, Any]) -> None:
    """A body without an id, a type and a data object is not an event."""
    with pytest.raises(StripeSignatureError):
        StripeEvent.from_payload(payload)


def test_verify_webhook_refuses_and_logs_no_secret(caplog: pytest.LogCaptureFixture) -> None:
    """A bad signature raises, and neither the secret, the header nor the body reaches a log line."""
    body = _event_body({"id": "cs_1", "object": "checkout.session"})
    header = sign_stripe_payload(body, "whsec_" + "another-value")
    caplog.set_level(logging.DEBUG)
    with pytest.raises(StripeSignatureError) as caught:
        _gateway(FakeStripeApi()).verify_webhook(body, header)
    logged = " ".join(str(record.__dict__) for record in caplog.records) + str(caught.value)
    assert WEBHOOK_SECRET not in logged
    assert header not in logged
    assert body.decode() not in logged


def test_verify_webhook_without_a_signing_secret() -> None:
    """A gateway whose settings lack a signing secret is not configured to receive."""
    settings = StripeSettings.model_validate({"STRIPE_API_KEY": API_KEY})
    gateway = StripeGateway(settings, client=stripe.StripeClient(API_KEY, http_client=FakeStripeApi()))
    with pytest.raises(StripeNotConfigured):
        gateway.verify_webhook(b"{}", "t=1,v1=00")


def test_parsed_events_claim_once() -> None:
    """A `StripeEvent` claims through `claim_webhook_event` like a `stripe.Event`."""
    body = _event_body({"id": "cs_1", "object": "checkout.session"})
    event = _gateway(FakeStripeApi()).verify_webhook(body, sign_stripe_payload(body, WEBHOOK_SECRET))
    store = FakeIdempotencyStore()
    assert claim_webhook_event(event, store) is True
    assert claim_webhook_event(event, store) is False


def test_gateway_repr_hides_the_settings() -> None:
    """Neither key appears in the gateway's repr."""
    rendered = repr(_gateway(FakeStripeApi())) + repr(FakeStripeGateway(webhook_secret=WEBHOOK_SECRET))
    assert API_KEY not in rendered
    assert WEBHOOK_SECRET not in rendered


def test_importing_the_module_does_not_import_stripe() -> None:
    """The settings and errors load without importing the `stripe` package."""
    source = (
        "import sys; import webbpulse.integrations.stripe as module; "
        "module.StripeEvent; print(sorted(m for m in sys.modules if m.split('.')[0] == 'stripe'))"
    )
    result = subprocess.run([sys.executable, "-c", source], capture_output=True, text=True, check=True)  # nosec B603
    assert result.stdout.strip() == "[]"


def test_fake_gateway_satisfies_the_protocol() -> None:
    """Both gateways type as `BillingGateway`."""
    gateways: list[BillingGateway] = [FakeStripeGateway(), _gateway(FakeStripeApi())]
    assert len(gateways) == 2


def test_fake_gateway_creates_one_customer_under_a_race() -> None:
    """The fake answers one customer per owner however many threads race it."""
    fake = FakeStripeGateway()
    answers: list[str] = []
    threads = [
        threading.Thread(target=lambda: answers.append(fake.ensure_customer(owner_key="user_id", owner_id=OWNER)))
        for _ in range(8)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert len(set(answers)) == 1
    assert fake.customer_creates == 1
    assert fake.ensure_customer(owner_key="user_id", owner_id=OWNER, customer_id="cus_kept") == "cus_kept"


def test_fake_gateway_billing_flow() -> None:
    """Checkout, portal, quantity and cancel on delete behave as the real gateway does."""
    fake = FakeStripeGateway(prices={"standard_monthly": "price_std"})
    customer_id = fake.ensure_customer(owner_key="workspace_id", owner_id="ws_1", name="Acme")
    assert fake.find_price_id("standard_monthly") == "price_std"
    assert fake.find_price_id("missing") is None
    url = fake.create_checkout_session(
        customer_id=customer_id,
        price_id="price_std",
        reference_id="ws_1",
        success_url="https://app.test/ok",
        cancel_url="https://app.test/cancel",
        quantity=2,
        metadata={"workspace_id": "ws_1"},
    )
    assert url.startswith("https://checkout.stripe.test/")
    assert fake.checkout_sessions[0]["quantity"] == 2
    assert fake.create_portal_session(customer_id=customer_id, return_url="https://app.test/").startswith("https://")
    subscription = fake.add_subscription(customer_id, quantity=2, lookup_key="standard_monthly")
    item_id = subscription["items"]["data"][0]["id"]
    assert fake.set_quantity(subscription["id"], item_id, 5)["items"]["data"][0]["quantity"] == 5
    fake.add_subscription(customer_id, status="canceled")
    assert fake.cancel_owner_subscriptions("workspace_id", "ws_1") == [subscription["id"]]
    assert fake.retrieve_subscription(subscription["id"])["status"] == "canceled"
    assert fake.cancel_subscriptions(customer_id) == []


def test_fake_gateway_verifies_like_stripe() -> None:
    """The fake accepts a `sign_stripe_payload` header and refuses wrong, stale and absent ones."""
    fake = FakeStripeGateway(webhook_secret=WEBHOOK_SECRET)
    body = _event_body({"id": "sub_9", "object": "subscription", "customer": "cus_9"}, "customer.subscription.updated")
    event = fake.verify_webhook(body, sign_stripe_payload(body, WEBHOOK_SECRET))
    assert (event.type, event.subscription_id) == ("customer.subscription.updated", "sub_9")
    for header in (
        sign_stripe_payload(body, "whsec_" + "another-value"),
        sign_stripe_payload(body, WEBHOOK_SECRET, timestamp=int(time.time()) - 301),
        "garbage",
        None,
    ):
        with pytest.raises(StripeSignatureError):
            fake.verify_webhook(body, header)
    with pytest.raises(StripeSignatureError):
        fake.verify_webhook(b"[]", sign_stripe_payload(b"[]", WEBHOOK_SECRET))
    with pytest.raises(StripeNotConfigured):
        FakeStripeGateway().verify_webhook(body, sign_stripe_payload(body, WEBHOOK_SECRET))
