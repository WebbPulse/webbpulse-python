"""Tests for the pacing policy and the gate header injection.

The pacing rules are the part of this package that had to be got right before anything else
was worth running: a sweep that does not pace itself answers 429 to most of its probes, and
a suite that banks a 429 as a pass reports the limiter's health as the route's.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from webbpulse.e2e.client import (
    RETRY_CAP_SECONDS,
    E2EClient,
    Pacer,
    RateLimitExhausted,
    retry_delay,
)


class Clock:
    """A monotonic clock a test drives by hand, with a sleeper that advances it."""

    def __init__(self) -> None:
        """Start at zero with nothing slept."""
        self.now = 0.0
        self.slept: list[float] = []

    def __call__(self) -> float:
        """The current time."""
        return self.now

    def sleep(self, seconds: float) -> None:
        """Record a sleep and advance the clock by it."""
        self.slept.append(seconds)
        self.now += seconds


def responder(statuses: list[int], headers: dict[str, str] | None = None) -> Callable[[httpx.Request], httpx.Response]:
    """A MockTransport handler answering each call with the next status in the list."""
    remaining = list(statuses)

    def handle(request: httpx.Request) -> httpx.Response:
        """Answer one request, repeating the final status once the list runs out."""
        status = remaining.pop(0) if len(remaining) > 1 else remaining[0]
        return httpx.Response(status, headers=headers or {}, json={"ok": status == 200})

    return handle


def client_for(
    handler: Callable[[httpx.Request], httpx.Response],
    clock: Clock,
    **kwargs: object,
) -> E2EClient:
    """An `E2EClient` over a MockTransport, driven by the supplied clock."""
    return E2EClient(
        base_url="https://api.example.invalid",
        transport=httpx.MockTransport(handler),
        sleeper=clock.sleep,
        clock=clock,
        **kwargs,  # type: ignore[arg-type]
    )


class TestRetryDelay:
    """Tests for how long a 429 is waited out."""

    def test_retry_after_is_honoured(self) -> None:
        """A `Retry-After` the limiter sets is used instead of the backoff curve."""
        assert retry_delay({"retry-after": "60"}, 0) == 60.0

    def test_retry_after_is_capped(self) -> None:
        """An hour-window rejection is capped, so the suite fails rather than blocking."""
        assert retry_delay({"retry-after": "3600"}, 0) == float(RETRY_CAP_SECONDS)

    def test_missing_retry_after_falls_back_to_backoff(self) -> None:
        """Without the header the delay is bounded exponential backoff."""
        assert retry_delay({}, 0) == 1.0
        assert retry_delay({}, 3) == 8.0

    def test_backoff_is_capped_too(self) -> None:
        """The backoff curve is capped at the same ceiling."""
        assert retry_delay({}, 20) == float(RETRY_CAP_SECONDS)

    def test_an_unparseable_header_falls_back(self) -> None:
        """A `Retry-After` that is not a number is ignored rather than crashing the sweep."""
        assert retry_delay({"retry-after": "soon"}, 1) == 2.0


class TestPacer:
    """Tests for the per-minute budget the pacer keeps calls under."""

    def test_the_first_call_never_waits(self) -> None:
        """Nothing has been spent at the start of a window, so the first call goes straight out."""
        clock = Clock()
        pacer = Pacer(per_minute=10, sleeper=clock.sleep, clock=clock)
        pacer.before_call()
        assert clock.slept == []

    def test_a_zero_budget_never_waits(self) -> None:
        """Zero means the target is not rate limited, so no call is ever held back."""
        clock = Clock()
        pacer = Pacer(per_minute=0, sleeper=clock.sleep, clock=clock)
        for _ in range(50):
            pacer.before_call()
            pacer.after_call({})
        assert clock.slept == []
        assert pacer.slept_seconds == 0

    def test_it_waits_out_the_window_once_the_budget_is_spent(self) -> None:
        """With the budget spent, the next call waits for the rest of the minute."""
        clock = Clock()
        pacer = Pacer(per_minute=3, sleeper=clock.sleep, clock=clock)
        for _ in range(3):
            pacer.before_call()
            pacer.after_call({})
        pacer.before_call()
        assert clock.slept and clock.slept[0] > 0

    def test_the_advertised_remaining_count_tightens_the_budget(self) -> None:
        """A low `X-RateLimit-Remaining-Minute` paces sooner than the local count would.

        The limiter is in-memory per execution environment, so the advertised remaining is
        the only honest read on how much budget this instance has left.
        """
        clock = Clock()
        pacer = Pacer(per_minute=100, sleeper=clock.sleep, clock=clock)
        pacer.before_call()
        pacer.after_call({"x-ratelimit-remaining-minute": "1"})
        pacer.before_call()
        assert clock.slept and clock.slept[0] > 0

    def test_a_new_window_resets_the_count(self) -> None:
        """Once the minute has elapsed the budget starts again with no wait."""
        clock = Clock()
        pacer = Pacer(per_minute=2, sleeper=clock.sleep, clock=clock)
        pacer.before_call()
        pacer.after_call({})
        clock.now += 61
        pacer.before_call()
        assert clock.slept == []

    def test_waiting_out_a_429_resets_the_window(self) -> None:
        """After a 429 is slept off, the next call has a fresh budget."""
        clock = Clock()
        pacer = Pacer(per_minute=2, sleeper=clock.sleep, clock=clock)
        waited = pacer.wait_out_429({"retry-after": "30"}, 0)
        assert waited == 30.0
        pacer.before_call()
        assert clock.slept == [30.0]


class TestClientPacing:
    """Tests for the client's own retry behaviour around a 429."""

    def test_a_429_is_retried_and_the_answer_is_returned(self) -> None:
        """A 429 that clears on retry yields the real answer, and the throttle is recorded."""
        clock = Clock()
        client = client_for(responder([429, 200], {"retry-after": "5"}), clock)
        response = client.get("/api/parts")
        assert response.status_code == 200
        assert clock.slept == [5.0]
        assert client.records[-1].throttled == 1

    def test_retry_after_paces_the_retry(self) -> None:
        """The retry waits the advertised interval rather than a fixed guess."""
        clock = Clock()
        client = client_for(responder([429, 429, 200], {"retry-after": "12"}), clock)
        client.get("/api/parts")
        assert clock.slept == [12.0, 12.0]

    def test_exhausting_the_cap_raises(self) -> None:
        """Every attempt answering 429 raises rather than banking the 429 as a pass.

        The softer bar of "not 200 and not 5xx" is what let twenty probes report PASS on a
        limiter rejection, which is evidence about the limiter and none about the routes.
        """
        clock = Clock()
        client = client_for(responder([429], {"retry-after": "1"}), clock)
        with pytest.raises(RateLimitExhausted, match="429 on all"):
            client.get("/api/parts")

    def test_retries_can_be_turned_off(self) -> None:
        """A caller that wants to see the 429 itself gets it without a retry or a raise."""
        clock = Clock()
        client = client_for(responder([429]), clock)
        response = client.get("/api/parts", retry_on_429=False)
        assert response.status_code == 429
        assert clock.slept == []


class TestGateHeaderAndRequestIds:
    """Tests for the header injection and the request id capture."""

    def test_the_gate_header_is_sent_on_every_request(self) -> None:
        """Staging's `x-origin-verify` is injected without the caller passing it."""
        seen: list[httpx.Headers] = []

        def handle(request: httpx.Request) -> httpx.Response:
            """Record the request headers and answer 200."""
            seen.append(request.headers)
            return httpx.Response(200, json={})

        clock = Clock()
        client = client_for(handle, clock, gate_headers={"x-origin-verify": "secret-value"})
        client.get("/api/parts")
        assert seen[0]["x-origin-verify"] == "secret-value"

    def test_the_gate_header_can_be_withheld(self) -> None:
        """The JWKS probe sends no gate header, since the authorizer's own fetch carries none."""
        seen: list[httpx.Headers] = []

        def handle(request: httpx.Request) -> httpx.Response:
            """Record the request headers and answer 200."""
            seen.append(request.headers)
            return httpx.Response(200, json={})

        clock = Clock()
        client = client_for(handle, clock, gate_headers={"x-origin-verify": "secret-value"})
        client.get("/api/parts", send_gate_header=False)
        assert "x-origin-verify" not in seen[0]

    def test_a_token_becomes_a_bearer_header(self) -> None:
        """`with_token` produces a client sending the bearer header."""
        seen: list[httpx.Headers] = []

        def handle(request: httpx.Request) -> httpx.Response:
            """Record the request headers and answer 200."""
            seen.append(request.headers)
            return httpx.Response(200, json={})

        clock = Clock()
        client = client_for(handle, clock)
        client.with_token("tok").get("/api/me")
        assert seen[0]["authorization"] == "Bearer tok"

    def test_a_clone_shares_the_pacer(self) -> None:
        """An authenticated clone spends the same budget, since the limiter keys on source IP."""
        clock = Clock()
        client = client_for(responder([200]), clock)
        assert client.with_token("tok").pacer is client.pacer

    def test_the_gateway_request_id_is_captured(self) -> None:
        """The id the access log keys on is preferred over the other edge ids."""
        clock = Clock()
        client = client_for(
            responder([200], {"apigw-requestid": "gw-1", "x-request-id": "app-1"}),
            clock,
        )
        client.get("/api/parts")
        assert client.records[-1].request_id == "gw-1"

    def test_the_application_request_id_is_the_fallback(self) -> None:
        """Without a gateway id, the middleware's own id is recorded."""
        clock = Clock()
        client = client_for(responder([200], {"x-request-id": "app-1"}), clock)
        client.get("/api/parts")
        assert client.records[-1].request_id == "app-1"

    def test_a_status_never_raises(self) -> None:
        """A 500 is returned rather than raised, so a finding stays a finding."""
        clock = Clock()
        client = client_for(responder([500]), clock)
        assert client.get("/api/parts").status_code == 500


class TestVerbs:
    """Tests that every verb goes through `request`, so pacing and recording apply."""

    @pytest.mark.parametrize("verb", ["get", "post", "put", "patch", "delete", "options"])
    def test_each_verb_sends_its_own_method(self, verb: str) -> None:
        """`put` and `patch` join the four that were already there."""
        seen: list[str] = []

        def handle(request: httpx.Request) -> httpx.Response:
            """Record the method and answer 200."""
            seen.append(request.method)
            return httpx.Response(200, json={})

        clock = Clock()
        client = client_for(handle, clock)
        getattr(client, verb)("/api/parts")
        assert seen == [verb.upper()]

    @pytest.mark.parametrize("verb", ["put", "patch"])
    def test_the_new_verbs_are_recorded(self, verb: str) -> None:
        """A recorded request is what the hygiene group and the failure reports read."""
        clock = Clock()
        client = client_for(responder([200], {"apigw-requestid": "gw-1"}), clock)
        getattr(client, verb)("/api/parts/abc")
        record = client.records[-1]
        assert record.method == verb.upper()
        assert record.path == "/api/parts/abc"
        assert record.request_id == "gw-1"

    @pytest.mark.parametrize("verb", ["put", "patch"])
    def test_the_new_verbs_retry_a_429(self, verb: str) -> None:
        """Going through `request` means the limiter policy applies to them too."""
        clock = Clock()
        client = client_for(responder([429, 200], {"retry-after": "5"}), clock)
        response = getattr(client, verb)("/api/parts/abc")
        assert response.status_code == 200
        assert clock.slept == [5.0]

    @pytest.mark.parametrize("verb", ["put", "patch"])
    def test_the_new_verbs_carry_the_gate_header(self, verb: str) -> None:
        """Staging's header is injected on every verb, not only the four that had methods."""
        seen: list[httpx.Headers] = []

        def handle(request: httpx.Request) -> httpx.Response:
            """Record the headers and answer 200."""
            seen.append(request.headers)
            return httpx.Response(200, json={})

        clock = Clock()
        client = client_for(handle, clock, gate_headers={"x-origin-verify": "secret-value"})
        getattr(client, verb)("/api/parts/abc", json={"name": "x"})
        assert seen[0]["x-origin-verify"] == "secret-value"
