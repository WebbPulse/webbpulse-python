"""Tests for the shared suite's own helpers, chiefly the minted-token probe target.

The probe is the one place the suite picks a request out of the deployed configuration
rather than being handed one, so picking a method the app does not serve is a plugin bug
that reads exactly like a broken authorizer.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import pytest
from _pytest.outcomes import Skipped

from webbpulse.e2e.access_log import AccessLogEntry
from webbpulse.e2e.browser import BrowserFailure
from webbpulse.e2e.client import E2EClient, RateLimitExhausted
from webbpulse.e2e.gateway import ABSENT_ID, Operation, Route
from webbpulse.e2e.journeys import ExpectText
from webbpulse.e2e.suite import (
    SETTLE_POLL_MS,
    SETTLE_TIMEOUT_MS,
    STEP_POLL_MS,
    ProbeTarget,
    RouteProbe,
    _expect_text,
    _first_identity_probe,
    _settle,
    probe_every_route,
    route_probes,
)
from webbpulse.e2e.suite import TestRouteCut as RouteCutGroup
from webbpulse.http import ROUTE_KEY_HEADER

GATE_ID = "gate123"
IDENTITY_ID = "jwt456"
GATE_IDS = frozenset({GATE_ID})


def route(key: str, authorizer: str = "", auth_type: str = "NONE") -> Route:
    """One live route with a route key and an optional authorizer."""
    return Route(key, target="integrations/abc", authorizer_id=authorizer, authorization_type=auth_type)


def gated(key: str) -> Route:
    """A route behind the staging access gate alone, which is what staging deploys."""
    return route(key, authorizer=GATE_ID, auth_type="CUSTOM")


def identity_protected(key: str) -> Route:
    """A route behind the identity JWT authorizer, which is what production deploys."""
    return route(key, authorizer=IDENTITY_ID, auth_type="JWT")


def operation(method: str, path: str, requires_auth: bool = True) -> Operation:
    """One declared OpenAPI operation, reduced to what the probe reads."""
    return Operation(
        method=method,
        path=path,
        operation_id=f"{method.lower()}_{path}",
        requires_auth=requires_auth,
        expected_statuses=(200, 401),
    )


class TestIdentityProbeFromRoutes:
    """Tests for the structural path, where a route carries a non-gate authorizer."""

    def test_an_identity_route_is_probed_directly(self) -> None:
        """A route behind the JWT authorizer needs no help from the OpenAPI document."""
        routes = [gated("GET /health"), identity_protected("GET /api/me")]
        probe = _first_identity_probe(routes, GATE_IDS, [])
        assert probe == ProbeTarget(method="GET", path="/api/me", route_key="GET /api/me")

    def test_a_gate_only_route_is_not_an_identity_route(self) -> None:
        """The gate admits any caller with the origin-verify header, so it proves nothing."""
        with pytest.raises(Skipped) as caught:
            _first_identity_probe([gated("GET /api/me")], GATE_IDS, [])
        assert "no live route requires an identity token" in str(caught.value)

    def test_a_proxy_route_is_never_probed(self) -> None:
        """A catch-all key has no concrete path a probe could aim at."""
        with pytest.raises(Skipped):
            _first_identity_probe([identity_protected("ANY /{proxy+}")], GATE_IDS, [])


class TestIdentityProbeFromOperations:
    """Tests for the fallback, where the gate is the only authorizer on the API."""

    def test_the_carmodpicker_shape_probes_the_method_the_app_serves(self) -> None:
        """`ANY /api/admin/db-ops` with only POST declared must be probed with POST.

        This is the bug the CarModPicker staging run found. Turning the `ANY` key into a GET
        reaches a router that defines only POST, so FastAPI answers 404 before any auth
        dependency runs and the probe expecting 401 fails on a healthy app.
        """
        routes = [gated("ANY /api/admin/db-ops"), gated("GET /health")]
        operations = [operation("POST", "/api/admin/db-ops")]
        probe = _first_identity_probe(routes, GATE_IDS, operations)
        assert probe.method == "POST"
        assert probe.path == "/api/admin/db-ops"
        assert probe.route_key == "ANY /api/admin/db-ops"

    def test_a_get_operation_is_preferred_over_another_method(self) -> None:
        """A GET carries no body and changes nothing, so it is the safest probe."""
        routes = [gated("ANY /api/admin/db-ops"), gated("ANY /api/me")]
        operations = [operation("POST", "/api/admin/db-ops"), operation("GET", "/api/me")]
        probe = _first_identity_probe(routes, GATE_IDS, operations)
        assert probe.method == "GET"
        assert probe.path == "/api/me"

    def test_the_logout_path_is_never_probed(self) -> None:
        """`POST /api/auth/logout` ends the run's own session if it is probed."""
        routes = [gated("ANY /api/auth/logout")]
        operations = [operation("POST", "/api/auth/logout")]
        with pytest.raises(Skipped) as caught:
            _first_identity_probe(routes, GATE_IDS, operations)
        assert "no live route requires an identity token" in str(caught.value)

    def test_logout_loses_to_any_other_protected_operation(self) -> None:
        """Even alongside a candidate it ranks behind, logout is not a candidate at all."""
        routes = [gated("ANY /api/auth/logout"), gated("ANY /api/builds/{build_id}")]
        operations = [operation("POST", "/api/auth/logout"), operation("DELETE", "/api/builds/{build_id}")]
        probe = _first_identity_probe(routes, GATE_IDS, operations)
        assert probe.path.startswith("/api/builds/")

    def test_a_safe_method_outranks_a_parameterised_mutation(self) -> None:
        """A GET changes nothing at all, so it is tried before a DELETE on an absent id."""
        routes = [gated("ANY /api/builds/{build_id}"), gated("ANY /api/me")]
        operations = [operation("DELETE", "/api/builds/{build_id}"), operation("GET", "/api/me")]
        probe = _first_identity_probe(routes, GATE_IDS, operations)
        assert probe.method == "GET"

    def test_a_bare_mutation_is_never_a_probe_target(self) -> None:
        """An accepted admin token would run it for real, so the suite skips rather than risk it."""
        routes = [gated("ANY /api/admin/db-ops"), gated("ANY /api/admin/db-ops/{proxy+}")]
        operations = [operation("POST", "/api/admin/db-ops/cars/delete-all"), operation("POST", "/api/admin/db-ops")]
        with pytest.raises(Skipped):
            _first_identity_probe(routes, GATE_IDS, operations)

    def test_an_operation_behind_a_proxy_route_is_probed_at_its_own_path(self) -> None:
        """The route key may be a catch-all; the probe still sends the operation's concrete path."""
        routes = [gated("ANY /api/users"), gated("ANY /api/users/{proxy+}")]
        operations = [operation("GET", "/api/users/me")]
        probe = _first_identity_probe(routes, GATE_IDS, operations)
        assert probe.method == "GET"
        assert probe.path == "/api/users/me"
        assert probe.route_key == "ANY /api/users/{proxy+}"

    def test_a_public_operation_is_not_a_probe_target(self) -> None:
        """An operation declaring no security requirement answers 200 to any token."""
        routes = [gated("ANY /api/public")]
        operations = [operation("GET", "/api/public", requires_auth=False)]
        with pytest.raises(Skipped):
            _first_identity_probe(routes, GATE_IDS, operations)

    def test_an_operation_with_no_live_route_is_skipped(self) -> None:
        """A declared operation the gateway does not route cannot be probed."""
        routes = [gated("GET /health")]
        operations = [operation("GET", "/api/me")]
        with pytest.raises(Skipped):
            _first_identity_probe(routes, GATE_IDS, operations)

    def test_path_variables_are_filled_with_the_absent_marker(self) -> None:
        """A probe must be a lookup that misses, so no handler writes anything."""
        routes = [gated("GET /api/builds/{build_id}")]
        operations = [operation("GET", "/api/builds/{build_id}")]
        probe = _first_identity_probe(routes, GATE_IDS, operations)
        assert "{" not in probe.path
        assert probe.path.startswith("/api/builds/")

    def test_a_mutation_with_a_path_parameter_is_allowed(self) -> None:
        """It points at an absent id, so it reaches the auth dependency and writes nothing."""
        routes = [gated("ANY /api/builds/{build_id}")]
        operations = [operation("DELETE", "/api/builds/{build_id}")]
        probe = _first_identity_probe(routes, GATE_IDS, operations)
        assert probe.method == "DELETE"

    def test_the_structural_path_wins_over_the_fallback(self) -> None:
        """A real identity authorizer is better evidence than a declared requirement."""
        routes = [identity_protected("GET /api/me"), gated("ANY /api/admin/db-ops")]
        operations = [operation("POST", "/api/admin/db-ops")]
        probe = _first_identity_probe(routes, GATE_IDS, operations)
        assert probe.route_key == "GET /api/me"


class TestProbeTarget:
    """Tests for the record the probe hands back."""

    def test_it_names_the_route_key_for_the_failure_message(self) -> None:
        """A rejected token must report which route key answered, not just the path."""
        target: Any = ProbeTarget(method="POST", path="/api/admin/db-ops", route_key="ANY /api/admin/db-ops")
        assert target.route_key == "ANY /api/admin/db-ops"


def probe_client(handler: Any) -> E2EClient:
    """An unpaced `E2EClient` over a MockTransport, for the probe sweep."""
    return E2EClient(
        base_url="https://api.example.invalid",
        transport=httpx.MockTransport(handler),
        per_minute=0,
    )


def answering(status: int = 404, headers: dict[str, str] | None = None) -> Any:
    """A handler answering every probe the same way, recording the paths it saw."""
    seen: list[tuple[str, str]] = []

    def handle(request: httpx.Request) -> httpx.Response:
        """Record one probe and answer it."""
        seen.append((request.method, request.url.path))
        return httpx.Response(status, headers=headers or {}, json={})

    handle.seen = seen  # type: ignore[attr-defined]
    return handle


class TestProbeEveryRoute:
    """Tests for probing the whole route table before any access log is read.

    The sweep is what makes the group fast: 147 routes each waiting out their own roughly
    half-minute delivery lag took 3393 s of a 60 minute run, and probing first means the
    group pays that lag once, if at all.
    """

    def test_every_live_route_is_probed_once(self) -> None:
        """One probe per route, so the whole table is in flight before any log is read."""
        handler = answering()
        routes = [route("GET /api/parts"), route("POST /api/build-lists")]
        probes = probe_every_route(routes, [r.route_key for r in routes], probe_client(handler))
        assert len(probes) == 2
        assert handler.seen == [("GET", "/api/parts"), ("POST", "/api/build-lists")]

    def test_an_any_key_is_probed_with_get(self) -> None:
        """The same rule the per-route case used, now applied once up front."""
        handler = answering()
        routes = [route("ANY /api/admin/db-ops")]
        probe_every_route(routes, [r.route_key for r in routes], probe_client(handler))
        assert handler.seen == [("GET", "/api/admin/db-ops")]

    def test_path_variables_are_filled_with_the_absent_marker(self) -> None:
        """A probe is a lookup that misses, so no handler writes anything."""
        handler = answering()
        routes = [route("GET /api/parts/{part_id}")]
        probe_every_route(routes, [r.route_key for r in routes], probe_client(handler))
        assert handler.seen == [("GET", f"/api/parts/{ABSENT_ID}")]

    def test_a_shadowed_route_is_not_probed_and_carries_its_reason(self) -> None:
        """Asserting the shadowing key would be asserting the wrong thing, so the case skips."""
        handler = answering()
        routes = [route("GET /api/{proxy+}"), route("GET /api/{part_id}")]
        keys = [item.route_key for item in routes]
        probes = probe_every_route(routes, keys, probe_client(handler))
        shadowed = probes["GET /api/{proxy+}"]
        assert shadowed.request_id == ""
        assert "shadows GET /api/{proxy+}" in shadowed.skip_reason
        assert handler.seen == [("GET", f"/api/{ABSENT_ID}")]

    def test_the_request_id_and_status_are_recorded(self) -> None:
        """The per-route case takes its id from here rather than probing again."""
        handler = answering(200, {"apigw-requestid": "gw-1"})
        routes = [route("GET /api/parts")]
        probes = probe_every_route(routes, [r.route_key for r in routes], probe_client(handler))
        assert probes["GET /api/parts"].request_id == "gw-1"
        assert probes["GET /api/parts"].status == 200

    def test_the_served_route_key_header_is_recorded(self) -> None:
        """The app's own report of which key served it, which is the primary proof."""
        handler = answering(404, {ROUTE_KEY_HEADER: "GET /api/parts"})
        routes = [route("GET /api/parts")]
        probes = probe_every_route(routes, [r.route_key for r in routes], probe_client(handler))
        assert probes["GET /api/parts"].served_route_key == "GET /api/parts"

    def test_a_gateway_answer_carries_no_served_route_key(self) -> None:
        """A request the gateway answered never reached the function, so the log is the proof."""
        handler = answering(401)
        routes = [route("GET /api/me")]
        probes = probe_every_route(routes, [r.route_key for r in routes], probe_client(handler))
        assert probes["GET /api/me"].served_route_key == ""

    def test_a_probe_that_raises_is_kept_against_its_own_route(self) -> None:
        """One route's exhausted budget costs one case, not the rest of the sweep."""

        def handle(request: httpx.Request) -> httpx.Response:
            """Answer the first route 429 forever and the rest 200."""
            if request.url.path == "/api/parts":
                return httpx.Response(429, headers={"retry-after": "0"}, json={})
            return httpx.Response(200, json={})

        routes = [route("GET /api/parts"), route("GET /api/build-lists")]
        probes = probe_every_route(routes, [r.route_key for r in routes], probe_client(handle))
        assert isinstance(probes["GET /api/parts"].error, RateLimitExhausted)
        assert probes["GET /api/build-lists"].error is None
        assert probes["GET /api/build-lists"].status == 200


class FakeLookup:
    """An `AccessLogLookup` stand-in returning a scripted entry and counting the asks."""

    def __init__(self, entry: AccessLogEntry | None = None) -> None:
        """Hold the entry every `find` returns, or None for a miss."""
        self.entry = entry
        self.asked: list[str] = []
        self.windows: list[int] = []

    def open_window(self, first_probe_ms: int) -> None:
        """Record the window the probe sweep opened."""
        self.windows.append(first_probe_ms)

    def find(self, request_id: str, *, start_time_ms: int | None = None) -> AccessLogEntry | None:
        """Record the ask and hand back the scripted entry."""
        self.asked.append(request_id)
        return self.entry


def entry_for(route_key: str, *, integration_error: str = "") -> AccessLogEntry:
    """One parsed access log entry naming a route key."""
    return AccessLogEntry(
        request_id="gw-1",
        route_key=route_key,
        path="/api/parts",
        method="GET",
        status=200,
        integration_status=200,
        integration_error=integration_error,
        raw={},
    )


class TestRouteCutProofs:
    """Tests for the two proofs the route cut case reads, cheapest first.

    The app's own `X-WebbPulse-Route-Key` proves the cut the moment the probe answers. The
    access log is the fallback for a request the gateway answered before the function ran,
    and it is the one that costs a delivery lag.
    """

    def probe(self, **overrides: Any) -> dict[str, RouteProbe]:
        """One route's probe, keyed the way the fixture returns it."""
        fields: dict[str, Any] = {
            "route_key": "GET /api/parts",
            "method": "GET",
            "path": "/api/parts",
            "request_id": "gw-1",
            "status": 200,
        }
        fields.update(overrides)
        return {fields["route_key"]: RouteProbe(**fields)}

    def case(self, probes: dict[str, RouteProbe], lookup: FakeLookup) -> None:
        """Run the route cut case against one probe and one lookup."""
        RouteCutGroup().test_access_log_names_this_route_key(route("GET /api/parts"), lookup, probes)  # type: ignore[arg-type]

    def test_the_response_header_alone_proves_the_cut(self) -> None:
        """A probe that reached the function needs no access log at all."""
        lookup = FakeLookup()
        self.case(self.probe(served_route_key="GET /api/parts"), lookup)
        assert lookup.asked == []

    def test_the_wrong_header_fails_without_reading_the_log(self) -> None:
        """A key the app did not expect is a failure the moment the probe answers."""
        lookup = FakeLookup()
        with pytest.raises(AssertionError, match="ANY /api/"):
            self.case(self.probe(served_route_key="ANY /api/{proxy+}"), lookup)
        assert lookup.asked == []

    def test_a_gateway_answer_falls_back_to_the_access_log(self) -> None:
        """No header means the gateway answered first, and the log is then the only proof."""
        lookup = FakeLookup(entry_for("GET /api/parts"))
        self.case(self.probe(status=401), lookup)
        assert lookup.asked == ["gw-1"]

    def test_the_fallback_still_catches_a_wrong_key(self) -> None:
        """The access log assertion is unchanged, only reached less often."""
        lookup = FakeLookup(entry_for("ANY /api/{proxy+}"))
        with pytest.raises(AssertionError, match="according to the access log"):
            self.case(self.probe(status=401), lookup)

    def test_an_undelivered_entry_is_still_a_skip(self) -> None:
        """A miss inside the budget is a miss, not a routing verdict."""
        with pytest.raises(Skipped, match="no access log entry arrived"):
            self.case(self.probe(status=401), FakeLookup())

    def test_a_shadowed_route_skips_with_the_sweep_reason(self) -> None:
        """The reason the sweep recorded is the message the case skips with."""
        probes = self.probe(request_id="", skip_reason="/api/parts resolves to no route")
        with pytest.raises(Skipped, match="resolves to no route"):
            self.case(probes, FakeLookup())

    def test_a_probe_that_raised_fails_its_own_case(self) -> None:
        """An exhausted budget fails the route rather than quietly skipping it."""
        probes = self.probe(request_id="", error=RateLimitExhausted("429 on all 4 attempts"))
        with pytest.raises(RateLimitExhausted):
            self.case(probes, FakeLookup())

    def test_a_five_hundred_fails_before_either_proof(self) -> None:
        """A cut cannot be verified against a gateway that is erroring."""
        with pytest.raises(AssertionError, match="erroring"):
            self.case(self.probe(status=502, served_route_key=""), FakeLookup())

    def test_an_integration_error_still_fails_on_the_fallback(self) -> None:
        """The log's integration error is the other thing only the log can say."""
        lookup = FakeLookup(entry_for("GET /api/parts", integration_error="Internal Server Error"))
        with pytest.raises(AssertionError, match="logged an integration error"):
            self.case(self.probe(status=401), lookup)


class TestRouteProbesFixture:
    """Tests for the session fixture that probes first and opens the delivery window."""

    def test_it_probes_every_route_and_opens_the_window(self) -> None:
        """One sweep, and the window the later lookups scan starts at the first probe."""
        handler = answering(200, {"apigw-requestid": "gw-1"})
        routes = [route("GET /api/parts"), route("GET /api/build-lists")]
        lookup = FakeLookup()
        before = int(time.time() * 1000)
        probes = route_probes.__wrapped__(  # type: ignore[attr-defined]
            routes,
            [item.route_key for item in routes],
            probe_client(handler),
            lookup,
        )
        assert len(handler.seen) == 2
        assert len(probes) == 2
        assert lookup.windows and lookup.windows[0] >= before

    def test_the_window_is_opened_before_the_first_probe_is_sent(self) -> None:
        """An entry delivered for the very first probe must fall inside the window."""
        seen_windows: list[int] = []

        def handle(request: httpx.Request) -> httpx.Response:
            """Record what the lookup was told when the first probe went out."""
            seen_windows.append(len(lookup.windows))
            return httpx.Response(200, json={})

        lookup = FakeLookup()
        routes = [route("GET /api/parts")]
        route_probes.__wrapped__(  # type: ignore[attr-defined]
            routes,
            [item.route_key for item in routes],
            probe_client(handle),
            lookup,
        )
        assert seen_windows == [1]


class FakePage:
    """A page whose text and URL change on a virtual clock driven by `wait_for_timeout`.

    Real waits would make these cases slow and flaky for no gain: what is worth asserting is
    that the helpers keep polling past the first tick, so the clock only has to advance when
    the code under test asks it to.
    """

    def __init__(self, *, texts: Any = None, urls: Any = None, url: str = "https://app.invalid/") -> None:
        """Record the scripted timelines and start the clock at zero."""
        self.elapsed = 0
        self._texts = texts or []
        self._urls = urls or []
        self._url = url
        self.goto_calls: list[str] = []
        self.reads = 0

    def wait_for_timeout(self, milliseconds: int) -> None:
        """Advance the virtual clock, which is what moves both timelines along."""
        self.elapsed += milliseconds

    def wait_for_selector(self, selector: str, **kwargs: Any) -> None:
        """Succeed immediately, since these cases are about what happens after that."""

    def goto(self, path: str, **kwargs: Any) -> None:
        """Record the visit and apply the first scripted URL."""
        self.goto_calls.append(path)
        self._advance_url()

    def _scripted(self, timeline: Any, fallback: Any) -> Any:
        """The last scripted value whose time has come, or the fallback."""
        current = fallback
        for at, value in timeline:
            if self.elapsed >= at:
                current = value
        return current

    def _advance_url(self) -> None:
        """Move the URL to whatever the timeline says for the current time."""
        self._url = self._scripted(self._urls, self._url)

    @property
    def url(self) -> str:
        """The current URL, taken from the timeline at the current virtual time."""
        self._advance_url()
        return self._url

    def locator(self, selector: str) -> Any:
        """A locator whose `inner_text` reads the scripted text at the current time."""
        page = self

        class _Locator:
            def inner_text(self) -> str:
                page.reads += 1
                return str(page._scripted(page._texts, ""))

        return _Locator()


class FakeEnvironment:
    """The two fields the wait helpers read off `e2e_env`."""

    def __init__(self, browser_timeout_ms: int = 15000) -> None:
        """Record the browser timeout and a fixed run id."""
        self.browser_timeout_ms = browser_timeout_ms
        self.run_id = "run1"


class TestExpectTextPolls:
    """`_expect_text` must poll to the deadline rather than reading once.

    Reading once the moment the element became visible failed a correct app: a heading read
    part way through a lazy-chunk transition, or a profile field read milliseconds after a
    submit click, holds the old text for a tick and then settles.
    """

    def test_text_that_settles_after_the_first_read_passes(self) -> None:
        """A heading that lands at 237 ms must not fail a correct app."""
        page = FakePage(texts=[(0, "Loading"), (250, "My Garage")])
        _expect_text(page, ExpectText("h1", "My Garage"), FakeEnvironment(), 15000, "journey step 1")
        assert page.reads > 1

    def test_a_field_that_settles_late_still_passes(self) -> None:
        """A profile field read 16 ms after a submit click settles within the deadline."""
        page = FakePage(texts=[(0, ""), (1000, "new-name")])
        _expect_text(page, ExpectText("#name", "new-name"), FakeEnvironment(), 15000, "journey step 2")

    def test_text_that_never_arrives_fails_with_the_last_text_seen(self) -> None:
        """The failure names what the element actually read, not the first empty value."""
        page = FakePage(texts=[(0, "Loading"), (500, "Something else")])
        with pytest.raises(BrowserFailure) as caught:
            _expect_text(page, ExpectText("h1", "My Garage"), FakeEnvironment(1000), 1000, "journey step 3")
        assert "Something else" in str(caught.value)
        assert "My Garage" in str(caught.value)

    def test_it_gives_up_at_the_browser_timeout(self) -> None:
        """Polling is bounded by the timeout it was handed, not unbounded."""
        page = FakePage(texts=[(0, "never")])
        with pytest.raises(BrowserFailure):
            _expect_text(page, ExpectText("h1", "wanted"), FakeEnvironment(1000), 1000, "journey step 4")
        assert page.elapsed <= 1000 + STEP_POLL_MS

    def test_the_run_id_is_expanded_before_matching(self) -> None:
        """`{run_id}` in an expected text still expands, as it did before."""
        page = FakePage(texts=[(0, "e2e-run1-build")])
        _expect_text(page, ExpectText("h1", "e2e-{run_id}-build"), FakeEnvironment(), 15000, "journey step 5")


class TestSettleWaitsForARealRedirect:
    """`_settle` must not call the first unchanged 400 ms tick a settled URL.

    Measured route guard redirects land between 750 and 980 ms, so returning early reported
    the protected path as final and the guard cases read a phantom security failure.
    """

    def test_a_redirect_at_980ms_is_seen(self) -> None:
        """The slowest measured real redirect must be observed, not missed."""
        page = FakePage(urls=[(0, "https://app.invalid/garage"), (980, "https://app.invalid/login")])
        assert _settle(page, "/garage", FakeEnvironment()) == "/login"

    def test_a_redirect_at_750ms_is_seen(self) -> None:
        """The fastest measured real redirect is past the old single 400 ms tick too."""
        page = FakePage(urls=[(0, "https://app.invalid/garage"), (750, "https://app.invalid/login")])
        assert _settle(page, "/garage", FakeEnvironment()) == "/login"

    def test_a_route_that_never_redirects_is_reported_as_it_stands(self) -> None:
        """A guard that genuinely does not fire is still reported as the protected path."""
        page = FakePage(urls=[(0, "https://app.invalid/garage")])
        assert _settle(page, "/garage", FakeEnvironment()) == "/garage"

    def test_it_polls_to_a_real_deadline(self) -> None:
        """A page that never moves is watched for seconds, not for one tick."""
        page = FakePage(urls=[(0, "https://app.invalid/garage")])
        _settle(page, "/garage", FakeEnvironment())
        assert page.elapsed >= SETTLE_TIMEOUT_MS

    def test_reaching_the_expected_path_returns_at_once(self) -> None:
        """A passing guard case does not spend the rest of the deadline proving it again."""
        page = FakePage(urls=[(0, "https://app.invalid/garage"), (500, "https://app.invalid/login")])
        assert _settle(page, "/garage", FakeEnvironment(), expected="/login") == "/login"
        assert page.elapsed < SETTLE_TIMEOUT_MS

    def test_the_deadline_never_exceeds_the_browser_timeout(self) -> None:
        """A product with a short browser timeout is not made to wait past it."""
        page = FakePage(urls=[(0, "https://app.invalid/garage")])
        _settle(page, "/garage", FakeEnvironment(browser_timeout_ms=1000))
        assert page.elapsed <= 1000 + SETTLE_POLL_MS

    def test_a_redirect_loop_is_still_named_as_one(self) -> None:
        """The loop refusal survives, because a timeout says nothing about which guard is wrong."""
        flapping = [(index * 300, f"https://app.invalid/{'a' if index % 2 else 'b'}") for index in range(1, 12)]
        page = FakePage(urls=flapping)
        with pytest.raises(BrowserFailure) as caught:
            _settle(page, "/garage", FakeEnvironment())
        assert "redirect loop" in str(caught.value)
