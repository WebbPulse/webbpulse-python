"""Tests for the shared suite's own helpers, chiefly the minted-token probe target.

The probe is the one place the suite picks a request out of the deployed configuration
rather than being handed one, so picking a method the app does not serve is a plugin bug
that reads exactly like a broken authorizer.
"""

from __future__ import annotations

from typing import Any

import pytest
from _pytest.outcomes import Skipped

from webbpulse.e2e.gateway import Operation, Route
from webbpulse.e2e.suite import ProbeTarget, _first_identity_probe

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
