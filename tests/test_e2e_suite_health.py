"""Tests for the whole-run access log sweep and the coverage group's own guards.

The sweep exists to catch what a per-case assertion cannot see: a request answered by
something other than the function it was meant to reach. Its most important property is
that it cannot pass vacuously, because an empty sweep is exactly what a wrong log group
produces and a green group would then mean the sweep never ran.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import pytest

from webbpulse.e2e import environment_for_collection, suite
from webbpulse.e2e.access_log import AccessLogEntry
from webbpulse.e2e.client import RequestRecord
from webbpulse.e2e.coverage import measure_coverage

Health = suite.TestAccessLogHealth
Coverage = suite.TestRouteCoverage

ENVIRON = {
    "E2E_ENVIRONMENT": "staging",
    "E2E_API_BASE_URL": "https://api.example.test",
    "E2E_WEB_BASE_URL": "https://example.test",
    "E2E_AWS_REGION": "us-west-2",
    "E2E_API_ID": "abc123",
    "E2E_ACCESS_LOG_GROUP": "/aws/apigateway/example",
    "E2E_RUN_ID": "run-1",
    "E2E_READ_ONLY": "1",
}


def entry(
    *,
    status: int = 200,
    integration_status: int = 200,
    route_key: str = "GET /api/issues",
    method: str = "GET",
    raw: Mapping[str, Any] | None = None,
) -> AccessLogEntry:
    """One access log entry, healthy unless a test says otherwise."""
    return AccessLogEntry(
        request_id="req-1",
        route_key=route_key,
        path="/api/issues",
        method=method,
        status=status,
        integration_status=integration_status,
        integration_error="",
        raw={"integrationErrorMessage": "-"} if raw is None else raw,
    )


def record(request_id: str = "req-1") -> RequestRecord:
    """One recorded request."""
    return RequestRecord(method="GET", path="/api/issues", status=200, request_id=request_id)


class TestTheSweepCannotPassVacuously:
    """An empty sweep is a failure, because the checks below it would all pass on nothing."""

    def test_an_empty_sweep_against_real_requests_fails(self) -> None:
        """Requests were made and none were correlated, so the sweep proves nothing."""
        with pytest.raises(AssertionError, match="none of this run's 1 requests"):
            Health().test_the_access_log_carries_this_runs_requests([record()], [])

    def test_a_run_with_no_request_ids_skips(self) -> None:
        """Nothing to correlate is a skip rather than a failure: no evidence either way."""
        with pytest.raises(BaseException, match="no request ids"):
            Health().test_the_access_log_carries_this_runs_requests([record(request_id="")], [])

    def test_a_correlated_sweep_passes(self) -> None:
        """One correlated entry is enough to prove the sweep read this run."""
        Health().test_the_access_log_carries_this_runs_requests([record()], [entry()])


class TestTheFourFailingShapes:
    """Each shape the sweep looks for fails, and a healthy run passes all four."""

    def test_a_server_error_fails(self) -> None:
        """A 5xx anywhere in the run is reported."""
        with pytest.raises(AssertionError, match="answered 5xx"):
            Health().test_no_request_was_answered_with_a_server_error([entry(status=502)])

    def test_a_rejection_from_a_healthy_integration_fails(self) -> None:
        """A 401 whose integration answered 200 is the authorizer, not the product."""
        with pytest.raises(AssertionError, match="although the integration answered 200"):
            Health().test_no_rejection_came_from_a_healthy_integration([entry(status=401)])

    def test_a_genuine_product_rejection_passes(self) -> None:
        """A 401 the function itself returned is the product refusing, and is not flagged."""
        Health().test_no_rejection_came_from_a_healthy_integration([entry(status=401, integration_status=401)])

    def test_an_unmatched_route_fails(self) -> None:
        """An empty route key means the gateway answered instead of a function."""
        with pytest.raises(AssertionError, match="matched no declared route key"):
            Health().test_every_request_matched_a_declared_route([entry(route_key="")])

    def test_an_unmatched_preflight_passes(self) -> None:
        """OPTIONS is answered by the CORS configuration rather than by a route."""
        Health().test_every_request_matched_a_declared_route([entry(route_key="", method="OPTIONS")])

    def test_an_integration_error_message_fails(self) -> None:
        """A real error message is reported."""
        with pytest.raises(AssertionError, match="reported an error"):
            Health().test_no_integration_reported_an_error([entry(raw={"integrationErrorMessage": "Lambda timed out"})])

    def test_the_unset_placeholder_is_not_an_error(self) -> None:
        """The gateway renders an unset variable as `-`, which is not an error message."""
        Health().test_no_integration_reported_an_error(
            [entry(raw={"integrationErrorMessage": "-", "errorMessage": "-"})]
        )

    def test_a_healthy_run_passes_every_shape(self) -> None:
        """Nothing in a clean run trips any of the four."""
        entries = [entry()]
        health = Health()
        health.test_no_request_was_answered_with_a_server_error(entries)
        health.test_no_rejection_came_from_a_healthy_integration(entries)
        health.test_every_request_matched_a_declared_route(entries)
        health.test_no_integration_reported_an_error(entries)


class TestCoverageGuards:
    """The coverage group refuses to report a broken suite as a coverage gap."""

    def test_a_run_that_recorded_nothing_fails(self) -> None:
        """No requests at all is a broken suite, not a hundred uncovered routes."""
        with pytest.raises(AssertionError, match="recorded no requests at all"):
            Coverage().test_the_run_recorded_requests_to_correlate([])

    def test_an_uncovered_route_names_itself(self) -> None:
        """The failure names the route that was never exercised."""
        coverage = measure_coverage([("POST", "/api/issues")], [])
        with pytest.raises(AssertionError, match="POST /api/issues"):
            Coverage().test_every_served_route_was_exercised_or_is_allowlisted(coverage)

    def test_a_stale_allowlist_entry_fails(self) -> None:
        """An entry naming a route that is gone is reported rather than ignored."""
        coverage = measure_coverage([], [], {("GET", "/api/gone"): "was never built"})
        with pytest.raises(AssertionError, match="does not serve"):
            Coverage().test_the_coverage_allowlist_is_not_stale(coverage)

    def test_an_entry_with_no_reason_fails(self) -> None:
        """An exception with no reason cannot be reviewed, so it is refused."""
        with pytest.raises(AssertionError, match="carry no reason"):
            Coverage().test_every_allowlist_entry_carries_a_reason({("GET", "/api/x"): "  "})

    def test_a_reasoned_entry_passes(self) -> None:
        """A reason is all the check asks for."""
        Coverage().test_every_allowlist_entry_carries_a_reason({("GET", "/api/x"): "needs a real upload"})


class TestEnvironmentForCollection:
    """Collection degrades to None on an unconfigured shell and still raises on a wrong one."""

    def test_an_unset_environment_returns_none(self) -> None:
        """No `E2E_ENVIRONMENT` means there is nothing to collect against, not an error."""
        assert environment_for_collection({}) is None

    def test_a_configured_environment_is_returned(self) -> None:
        """A complete environment is parsed as usual."""
        env = environment_for_collection(dict(ENVIRON))
        assert env is not None
        assert env.environment == "staging"

    def test_a_partial_environment_still_raises(self) -> None:
        """A half-wired run is a mistake to fail on, not one to skip past."""
        partial = dict(ENVIRON)
        del partial["E2E_API_ID"]
        with pytest.raises(Exception, match="E2E_API_ID"):
            environment_for_collection(partial)


class TestUncoveredRoutesFixture:
    """The allowlist hook is normalised so a product may spell methods either way."""

    def test_methods_are_uppercased(self) -> None:
        """A lowercase method in the allowlist still matches an uppercase served route."""
        declared: Mapping[tuple[str, str], str] = {("post", "/api/x"): "reason"}
        normalised = {(m.upper(), p): r for (m, p), r in declared.items()}
        coverage = measure_coverage([("POST", "/api/x")], [], normalised)
        assert coverage.uncovered == ()

    def test_no_declaration_means_no_allowlist(self) -> None:
        """A product that declares nothing gets an empty mapping, not a failure."""
        entries: Sequence[tuple[str, str]] = []
        assert measure_coverage([], entries, None).allowed == ()
