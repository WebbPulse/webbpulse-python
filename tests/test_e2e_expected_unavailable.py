"""Tests for the routes a product declares as deliberately answering 503.

The declaration weakens the 5xx bar for exactly the routes it names, so the property that
matters most is that it cannot outlive its own reason: a declared route that answers anything
other than the 503 it declared, a 200 included, must fail as stale rather than pass.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx
import pytest

from webbpulse.e2e.access_log import AccessLogEntry
from webbpulse.e2e.client import E2EClient
from webbpulse.e2e.gateway import Operation, Route
from webbpulse.e2e.suite import RouteProbe
from webbpulse.e2e.suite import TestReachability as ReachabilityGroup
from webbpulse.e2e.suite import TestRouteCut as RouteCutGroup
from webbpulse.e2e.unavailable import (
    ExpectedUnavailable,
    normalise_expected_unavailable,
    response_error_code,
)

WEBHOOK_PATH = "/api/github/webhook"

NOT_CONFIGURED = "NOT_CONFIGURED"

DECLARED = {("POST", WEBHOOK_PATH): f"{NOT_CONFIGURED}: the GitHub App does not exist yet"}


def declared() -> Mapping[tuple[str, str], ExpectedUnavailable]:
    """The parsed declaration the cases below are run against."""
    return normalise_expected_unavailable(DECLARED)


def operation(method: str = "POST", path: str = WEBHOOK_PATH) -> Operation:
    """One declared OpenAPI operation, reduced to what the reachability probe reads."""
    return Operation(
        method=method,
        path=path,
        operation_id=f"{method.lower()}_{path}",
        requires_auth=False,
        expected_statuses=(200, 202),
    )


def answering(status: int, body: Any) -> E2EClient:
    """An unpaced client answering every request with one status and one body."""

    def handle(request: httpx.Request) -> httpx.Response:
        """Answer the probe."""
        return httpx.Response(status, json=body)

    return E2EClient(
        base_url="https://api.example.invalid",
        transport=httpx.MockTransport(handle),
        per_minute=0,
    )


def envelope(error_code: str) -> dict[str, Any]:
    """The shared error envelope `webbpulse.http.error_body` writes, carrying one code."""
    return {
        "success": False,
        "status": 503,
        "message": "the GitHub App is not configured",
        "request_id": "req-1",
        "error_code": error_code,
    }


def reach(client: E2EClient, expected: Mapping[tuple[str, str], ExpectedUnavailable]) -> None:
    """Run the anonymous reachability case against one client and one declaration."""
    ReachabilityGroup().test_anonymous_call_is_answered_by_the_api(operation(), client, expected)


class TestParsingTheDeclaration:
    """A declaration that does not parse must fail loudly rather than read as no declaration."""

    def test_a_well_formed_entry_parses_into_a_code_and_a_reason(self) -> None:
        """The value is split on the first colon, with both halves stripped."""
        parsed = declared()[("POST", WEBHOOK_PATH)]
        assert parsed.error_code == NOT_CONFIGURED
        assert parsed.reason == "the GitHub App does not exist yet"

    def test_a_reason_carrying_a_colon_keeps_it(self) -> None:
        """Only the first colon separates, so a reason may punctuate freely."""
        parsed = normalise_expected_unavailable({("GET", "/x"): "NOT_CONFIGURED: waiting on: the app"})
        assert parsed[("GET", "/x")].reason == "waiting on: the app"

    def test_a_lowercase_method_is_normalised(self) -> None:
        """Keyed exactly like the coverage allowlist, which normalises the same way."""
        parsed = normalise_expected_unavailable({("post", "/x"): "NOT_CONFIGURED: waiting"})
        assert ("POST", "/x") in parsed

    def test_no_declaration_is_an_empty_mapping(self) -> None:
        """The hook is optional, so None and an empty mapping mean the same thing."""
        assert normalise_expected_unavailable(None) == {}
        assert normalise_expected_unavailable({}) == {}

    def test_a_value_with_no_colon_fails_naming_the_entry(self) -> None:
        """A bare reason would silently excuse every 503 code the route could answer."""
        with pytest.raises(ValueError, match="POST /api/github/webhook is 'the app is missing'"):
            normalise_expected_unavailable({("POST", WEBHOOK_PATH): "the app is missing"})

    def test_a_value_with_no_code_fails(self) -> None:
        """A colon with nothing before it names no code to compare the body against."""
        with pytest.raises(ValueError, match="names no error code"):
            normalise_expected_unavailable({("POST", WEBHOOK_PATH): ": the app is missing"})

    def test_a_lowercase_code_fails(self) -> None:
        """The code is compared byte for byte, so it must be spelled as the app emits it."""
        with pytest.raises(ValueError, match="is not uppercase"):
            normalise_expected_unavailable({("POST", WEBHOOK_PATH): "not_configured: missing"})

    def test_a_value_with_no_reason_fails(self) -> None:
        """An exception with no reason cannot be reviewed or retired."""
        with pytest.raises(ValueError, match="with no reason after the colon"):
            normalise_expected_unavailable({("POST", WEBHOOK_PATH): "NOT_CONFIGURED:   "})


class TestReadingTheErrorCode:
    """The code is read from the field the shared error envelope writes."""

    def test_the_envelope_code_is_read(self) -> None:
        """`error_body` writes `error_code`, which is the field compared."""
        assert response_error_code(httpx.Response(503, json=envelope(NOT_CONFIGURED))) == NOT_CONFIGURED

    def test_a_body_with_no_code_reads_as_empty(self) -> None:
        """An envelope that omits the code never matches a declared one."""
        assert response_error_code(httpx.Response(503, json={"message": "Service Unavailable"})) == ""

    def test_a_non_json_body_reads_as_empty(self) -> None:
        """A gateway or proxy answering HTML is not a declared 503."""
        assert response_error_code(httpx.Response(503, text="<html>503</html>")) == ""

    def test_a_json_list_body_reads_as_empty(self) -> None:
        """Valid JSON that is not an object carries no envelope."""
        assert response_error_code(httpx.Response(503, json=[NOT_CONFIGURED])) == ""


class TestReachabilityAgainstADeclaredRoute:
    """The reachability group's bar for a route the product declared as unavailable."""

    def test_the_declared_503_passes(self) -> None:
        """A 503 carrying the declared code is what the entry excuses."""
        reach(answering(503, envelope(NOT_CONFIGURED)), declared())

    def test_a_two_hundred_fails_as_stale(self) -> None:
        """The integration is configured now, so the entry must be removed."""
        with pytest.raises(AssertionError, match="The entry is stale"):
            reach(answering(200, {"ok": True}), declared())

    def test_a_503_with_another_code_fails_as_stale(self) -> None:
        """A different code is a different outage, which the entry never excused."""
        with pytest.raises(AssertionError, match="503 carrying error_code 'DEPENDENCY_DOWN'"):
            reach(answering(503, envelope("DEPENDENCY_DOWN")), declared())

    def test_a_503_with_no_code_fails_as_stale(self) -> None:
        """A bare 503 could be the gateway or the load balancer, not the app answering."""
        with pytest.raises(AssertionError, match="503 carrying no error_code"):
            reach(answering(503, {"message": "Service Unavailable"}), declared())

    def test_a_five_hundred_on_a_declared_route_fails(self) -> None:
        """Only the declared 503 is excused, never every 5xx on that route."""
        with pytest.raises(AssertionError, match="but it answered 500"):
            reach(answering(500, envelope(NOT_CONFIGURED)), declared())


class TestReachabilityAgainstAnUndeclaredRoute:
    """A route nobody declared behaves exactly as it did before the hook existed."""

    def test_an_undeclared_503_still_fails(self) -> None:
        """The 5xx bar is unchanged for every route the product did not name."""
        with pytest.raises(AssertionError, match="answered 503"):
            reach(answering(503, envelope(NOT_CONFIGURED)), {})

    def test_an_undeclared_declared_status_still_passes(self) -> None:
        """A healthy route is judged against its own spec, as before."""
        reach(answering(200, {"ok": True}), {})

    def test_another_routes_declaration_does_not_excuse_this_one(self) -> None:
        """The mapping is keyed by route, so an entry excuses that route and no other."""
        elsewhere = normalise_expected_unavailable({("POST", "/api/other"): "NOT_CONFIGURED: elsewhere"})
        with pytest.raises(AssertionError, match="answered 503"):
            reach(answering(503, envelope(NOT_CONFIGURED)), elsewhere)


class FakeLookup:
    """An `AccessLogLookup` stand-in returning a scripted entry and counting the asks."""

    def __init__(self, entry: AccessLogEntry | None = None) -> None:
        """Hold the entry every `find` returns, or None for a miss."""
        self.entry = entry
        self.asked: list[str] = []

    def open_window(self, first_probe_ms: int) -> None:
        """Accept the window the probe sweep would have opened."""

    def find(self, request_id: str, *, start_time_ms: int | None = None) -> AccessLogEntry | None:
        """Record the ask and hand back the scripted entry."""
        self.asked.append(request_id)
        return self.entry


class TestRouteCutAgainstADeclaredRoute:
    """The route cut probe applies the same bar, from the code it captured on the probe."""

    def live_route(self) -> Route:
        """The live route the declared operation is served by."""
        return Route(f"POST {WEBHOOK_PATH}", target="integrations/abc", authorizer_id="", authorization_type="NONE")

    def probe(self, status: int, error_code: str) -> dict[str, RouteProbe]:
        """One route's probe, keyed the way the fixture returns it."""
        key = f"POST {WEBHOOK_PATH}"
        return {
            key: RouteProbe(
                route_key=key,
                method="POST",
                path=WEBHOOK_PATH,
                request_id="gw-1",
                served_route_key=key,
                status=status,
                error_code=error_code,
            )
        }

    def case(
        self,
        status: int,
        error_code: str,
        expected: Mapping[tuple[str, str], ExpectedUnavailable],
    ) -> None:
        """Run the route cut case against one probe and one declaration."""
        RouteCutGroup().test_access_log_names_this_route_key(
            self.live_route(),
            FakeLookup(),  # type: ignore[arg-type]
            self.probe(status, error_code),
            expected,
        )

    def test_the_declared_503_proves_the_cut(self) -> None:
        """The route is cut correctly and answering the 503 it was declared to answer."""
        self.case(503, NOT_CONFIGURED, declared())

    def test_a_two_hundred_fails_as_stale(self) -> None:
        """The route works now, so the entry that excused its 503 must go."""
        with pytest.raises(AssertionError, match="The entry is stale"):
            self.case(200, "", declared())

    def test_a_503_with_another_code_fails_as_stale(self) -> None:
        """A different code on the same route is a different failure."""
        with pytest.raises(AssertionError, match="503 carrying error_code 'DEPENDENCY_DOWN'"):
            self.case(503, "DEPENDENCY_DOWN", declared())

    def test_an_undeclared_503_still_fails_on_the_erroring_gateway_bar(self) -> None:
        """A route nobody declared keeps the message it always had."""
        with pytest.raises(AssertionError, match="erroring"):
            self.case(503, NOT_CONFIGURED, {})
