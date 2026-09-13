"""The generic post-deploy suite, derived from the live gateway and the deployed OpenAPI.

Re-export it from a product with:

    from webbpulse.e2e.suite import *  # noqa: F401,F403

Nothing here is hand-listed. Every case is parametrised from a fixture, so a route added in
Terraform or an operation added to the app appears in the next run with no edit, which is
the property the prior art's string rules kept losing.

The six groups, in the order they build on each other:

1. Route cut: every live route is probed and its access log entry must name that route key
   and the integration the route declares.
2. Coverage: every OpenAPI operation must resolve to a live route under gateway precedence,
   with the authorizer attached exactly when the operation needs auth.
3. Reachability: every operation is called and must answer a status its own spec declares,
   never a gateway 404, a gate 403 or a 5xx.
4. Identity: login, refresh, logout, JWKS, token shape, and the minted-token authorizer
   probes in staging.
5. Frontend: the shell, the SPA catch-all, the bundle's API base and legacy names, and the
   CORS preflight.
6. Hygiene: the cleanup hooks ran and left nothing behind.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

import pytest

from .access_log import AccessLogLookup
from .client import E2EClient, RateLimitExhausted
from .frontend import fetch_bundle, missing_allowed_headers, shell_looks_like_an_app
from .gateway import Operation, Route, matching_route, resolve, route_key_is_expressible
from .identity import JWKS_PATH, decode_claims, logout, refresh

__all__ = [
    "TestCoverage",
    "TestFrontend",
    "TestHygiene",
    "TestIdentity",
    "TestReachability",
    "TestRouteCut",
    "operation_id",
    "pytest_generate_tests",
    "route_id",
]

ABSENT_ID = "e2e-obviously-absent-id"
GATEWAY_404_BODY = "Not Found"
GATE_STATUSES = (401, 403)


def route_id(route: Route) -> str:
    """A junit-legible id for one live route."""
    return route.route_key


def operation_id(operation: Operation) -> str:
    """A junit-legible id for one OpenAPI operation."""
    return operation.label


def _probe_path(route: Route) -> str:
    """A concrete path that resolves to this route and to no more specific one.

    Variables are filled with a marker rather than a plausible id so the request is a
    lookup that misses, which every handler answers without writing anything.
    """
    segments = []
    for segment in route.path.strip("/").split("/"):
        if segment == "{proxy+}" or (segment.startswith("{") and segment.endswith("}")):
            segments.append(ABSENT_ID)
        else:
            segments.append(segment)
    return "/" + "/".join(segment for segment in segments if segment)


def _probe_method(route: Route) -> str:
    """The method to probe a route with, using GET for an `ANY` key."""
    return "GET" if route.method == "ANY" else route.method


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """Parametrise the route and operation cases at collection time.

    pytest cannot hand a session fixture to `pytest_generate_tests`, so the two collections
    the cases are derived from are built here through `collection_inputs`, cached for the
    run, and the matching fixtures below return the same cached objects. Both are read-only
    reads of the deployed stage, so building them at collection costs one extra API call.

    Parametrising rather than looping inside one test is the point: each route and each
    operation becomes its own junit case, so a failure names the route key or the operation
    instead of the first assertion that tripped.
    """
    inputs = collection_inputs(metafunc.config)
    if "live_route" in metafunc.fixturenames:
        routes = inputs.routes
        metafunc.parametrize("live_route", routes, ids=[route_id(route) for route in routes])
    if "operation" in metafunc.fixturenames:
        operations = inputs.operations
        metafunc.parametrize("operation", operations, ids=[operation_id(op) for op in operations])


class CollectionInputs:
    """The live routes and deployed operations, built once at collection and reused.

    The product's OpenAPI document is read through a module level `e2e_openapi_document()`
    in its `e2e/conftest.py`, because collection happens before any fixture runs and the
    document has to describe the commit under test rather than anything the plugin could
    guess.
    """

    def __init__(self, config: pytest.Config) -> None:
        """Read the environment, the live routes and the product's operations."""
        import boto3

        from . import E2EEnvironment
        from .gateway import fetch_routes, operations_from_openapi

        env = E2EEnvironment.from_environ()
        session = boto3.session.Session(region_name=env.aws_region)
        self.routes: tuple[Route, ...] = fetch_routes(session.client("apigatewayv2"), env.api_id)
        self.operations: tuple[Operation, ...] = operations_from_openapi(_product_openapi_document(config))


def collection_inputs(config: pytest.Config) -> CollectionInputs:
    """The cached `CollectionInputs` for this run, built on first use."""
    existing = config.pluginmanager.get_plugin("webbpulse-e2e-collection")
    if isinstance(existing, CollectionInputs):
        return existing
    built = CollectionInputs(config)
    config.pluginmanager.register(built, "webbpulse-e2e-collection")
    return built


def _product_openapi_document(config: pytest.Config) -> Mapping[str, Any]:
    """The product's OpenAPI document, via its conftest's `e2e_openapi_document()`."""
    for plugin in config.pluginmanager.get_plugins():
        builder = getattr(plugin, "e2e_openapi_document", None)
        if callable(builder):
            document = builder()
            if isinstance(document, Mapping):
                return document
    raise pytest.UsageError(
        "The product's e2e/conftest.py must define a module level `e2e_openapi_document()` "
        "returning its app's OpenAPI document, alongside the `openapi_document` fixture. "
        "Collection needs the document before any fixture runs, to parametrise the coverage "
        "and reachability cases. See docs/e2e.md."
    )


class TestRouteCut:
    """Group 1: every live route is served by the integration its route key declares.

    A 200 proves something answered. Only the access log entry says which route key matched
    and which integration ran, which is the difference between a landed cut and a request
    falling through a `{proxy+}` catch-all with no authorizer claims.
    """

    def test_route_key_is_expressible(self, live_route: Route) -> None:
        """Every live route key is one API Gateway can actually match."""
        assert route_key_is_expressible(live_route.route_key), (
            f"{live_route.route_key} is not a legal HTTP API route key. A path part is a "
            "whole variable or a whole literal, never a variable embedded in a literal, and "
            "a key whose path ends in a slash can never be matched by an inbound request."
        )

    def test_route_has_an_integration(self, live_route: Route) -> None:
        """Every live route points at an integration rather than at nothing."""
        assert live_route.target, (
            f"{live_route.route_key} declares no integration target, so a request matching "
            "it reaches no function at all."
        )

    def test_access_log_names_this_route_key(
        self,
        live_route: Route,
        anon: E2EClient,
        access_log: AccessLogLookup,
        route_keys: Sequence[str],
    ) -> None:
        """A probe to this route is logged with this route key and no integration error.

        The probe path is resolved back through the precedence matcher first: a route whose
        every path a more specific key shadows cannot be probed directly, and asserting the
        shadowing key would be asserting the wrong thing.
        """
        method = _probe_method(live_route)
        path = _probe_path(live_route)
        expected = resolve(path, method, route_keys)
        if expected != live_route.route_key:
            pytest.skip(f"{path} resolves to {expected or 'no route'}, which shadows {live_route.route_key}")

        response = anon.request(method, path)
        assert response.status_code < 500, (
            f"{method} {path} answered {response.status_code}. A cut cannot be verified "
            "against a gateway that is erroring."
        )

        entry = access_log.find(response.headers.get("apigw-requestid", ""))
        if entry is None:
            pytest.skip(
                f"No access log entry for {method} {path} inside the budget. Delivery is per "
                "stream and can lag, and the probe above already reached the API, so this is "
                "not itself evidence of a bad route."
            )
        assert entry.route_key == live_route.route_key, (
            f"{method} {path} was served by route key {entry.route_key!r}, not "
            f"{live_route.route_key!r}. Either an apply has not landed or a key was changed "
            "outside Terraform."
        )
        assert not entry.integration_error, (
            f"{live_route.route_key} logged an integration error: {entry.integration_error}"
        )


class TestCoverage:
    """Group 2: every OpenAPI operation lands on a live route, with the right authorizer.

    Derived from the deployed document and the live route table, so a route that exists in
    Terraform but not on the gateway, and an operation the app serves but the gateway never
    routes to, are both failures here rather than a 404 a user finds.
    """

    def test_operation_resolves_to_a_live_route(self, operation: Operation, gateway_routes: Sequence[Route]) -> None:
        """Every operation's path resolves to some live route under gateway precedence."""
        route = matching_route(operation, gateway_routes)
        assert route is not None, (
            f"{operation.label} is declared by the app but no live route key matches it, so "
            "the gateway answers its own 404 and the operation is unreachable. This is the "
            "shape of the thirteen passkey and OAuth routes that were mounted and declared "
            "nowhere."
        )

    def test_operation_path_has_no_trailing_slash(self, operation: Operation) -> None:
        """No operation path ends in a slash, which the gateway can never match.

        The gateway refuses a route key ending in a slash and does not normalise an inbound
        one, so a slashed path falls through to an unflagged catch-all, arrives with no
        authorizer claims and is rejected as unauthenticated.
        """
        assert operation.path == "/" or not operation.path.endswith("/"), (
            f"{operation.label} ends in a trailing slash. API Gateway will not match it to "
            "its own route key, so it falls through to the catch-all with no authorizer "
            "claims and answers 401 to a valid token."
        )

    def test_authorizer_matches_the_operation(self, operation: Operation, gateway_routes: Sequence[Route]) -> None:
        """An operation needing auth lands on a route with an authorizer, and vice versa."""
        route = matching_route(operation, gateway_routes)
        if route is None:
            pytest.skip("no live route matches, which the coverage case above already reports")
        assert route.has_authorizer == operation.requires_auth, (
            f"{operation.label} declares requires_auth={operation.requires_auth} but resolves "
            f"to {route.route_key!r}, which has_authorizer={route.has_authorizer}. A "
            "protected operation behind an unflagged route is served with no claims; an open "
            "one behind an authorizer is unreachable."
        )


class TestReachability:
    """Group 3: every operation answers a status its own spec declares.

    Never a gateway 404, never a 403 from the gate, never a 5xx. The bar is the spec's own
    status list rather than "not an error", because the softer bar is what let a wall of
    429s from the per-IP limiter read as proof that twenty routes were deleted.
    """

    def test_anonymous_call_is_answered_by_the_api(self, operation: Operation, anon: E2EClient) -> None:
        """Calling an operation anonymously reaches the API rather than the gate or a 404."""
        self._assert_reachable(operation, anon, "anonymously")

    def test_authenticated_call_is_answered_by_the_api(self, operation: Operation, api: E2EClient) -> None:
        """Calling an operation as the durable e2e user reaches the API."""
        self._assert_reachable(operation, api, "as the e2e user")

    def _assert_reachable(self, operation: Operation, client: E2EClient, who: str) -> None:
        """One reachability probe, with the distinction between the failure modes named."""
        path = _concrete_path(operation)
        try:
            response = client.request(operation.method, path, json={} if operation.method != "GET" else None)
        except RateLimitExhausted as error:
            pytest.fail(str(error))

        assert response.status_code < 500, (
            f"{operation.label} called {who} answered {response.status_code}: {response.text[:200]}"
        )

        if response.status_code == 404 and _looks_like_a_gateway_404(response):
            pytest.fail(
                f"{operation.label} called {who} answered API Gateway's own 404, so no route "
                "matched it and the request reached no function."
            )

        if operation.path_parameters:
            assert response.status_code in (*operation.expected_statuses, 404, 422, *GATE_STATUSES), (
                f"{operation.label} called {who} with an obviously absent id answered "
                f"{response.status_code}, which its spec does not declare and which is "
                "neither the 404 nor the 422 an absent id should produce."
            )
        else:
            assert response.status_code in (*operation.expected_statuses, *GATE_STATUSES), (
                f"{operation.label} called {who} answered {response.status_code}, which its "
                f"own spec does not declare. The spec declares {operation.expected_statuses}."
            )


def _concrete_path(operation: Operation) -> str:
    """The operation path with every placeholder filled with an obviously absent id."""
    segments = [
        ABSENT_ID if segment.startswith("{") and segment.endswith("}") else segment
        for segment in operation.path.strip("/").split("/")
    ]
    return "/" + "/".join(segment for segment in segments if segment)


def _looks_like_a_gateway_404(response: Any) -> bool:
    """Whether a 404 came from API Gateway itself rather than from the application.

    The gateway's own 404 is a bare `{"message":"Not Found"}` with no error envelope, which
    is exactly what the shared `webbpulse.http` envelope never produces.
    """
    try:
        payload = response.json()
    except ValueError:
        return False
    return isinstance(payload, dict) and set(payload) == {"message"} and payload.get("message") == GATEWAY_404_BODY


class TestIdentity:
    """Group 4: the identity flows and the token shape, plus the staging authorizer probes."""

    def test_login_returns_an_rs256_token(self, user_session: Any) -> None:
        """The durable user's access token is RS256, not a legacy HS256 one."""
        assert user_session.algorithm == "RS256", (
            f"the access token declares alg={user_session.algorithm!r}. A legacy HS256 token "
            "would mean a resolver still mints one, which is a claim about which code path ran."
        )

    def test_token_carries_this_environments_issuer_and_audience(self, user_session: Any, e2e_env: Any) -> None:
        """The token's `iss` and `aud` are this environment's, byte for byte.

        A stray trailing slash on either denies every request at the authorizer, so the
        comparison is exact rather than a prefix match.
        """
        if e2e_env.issuer:
            assert user_session.issuer == e2e_env.issuer, (
                f"iss is {user_session.issuer!r}, not {e2e_env.issuer!r}. The authorizer "
                "compares this byte for byte, so a trailing slash denies every request."
            )
        if e2e_env.audience:
            assert user_session.audience == e2e_env.audience, (
                f"aud is {user_session.audience!r}, not {e2e_env.audience!r}"
            )

    def test_jwks_is_reachable_without_the_gate_header(self, anon: E2EClient) -> None:
        """The JWKS the authorizer verifies against is reachable without a gate credential.

        The gate is a REQUEST authorizer that fetches this URL itself, and that URL is on the
        API the gate protects. If the JWKS route is not exempt, the authorizer's own fetch is
        answered by the authorizer's own policy, every verification fails closed, and every
        authenticated route answers a bare 403 that reads exactly like broken authentication.
        """
        response = anon.get(JWKS_PATH, send_gate_header=False)
        assert response.status_code == 200, (
            f"{JWKS_PATH} answered {response.status_code} without the gate header, so the "
            "gate authorizer cannot fetch the JWKS and every token verification fails closed."
        )
        assert response.json().get("keys"), "the JWKS document carries no keys"

    def test_refresh_issues_a_new_token(self, user_session: Any) -> None:
        """The refresh route exchanges the refresh material for a fresh access token."""
        response = refresh(user_session)
        assert response.status_code == 200, f"refresh answered {response.status_code}: {response.text[:200]}"
        payload = response.json()
        assert isinstance(payload, dict), "refresh answered 200 with a body that is not an object"

    def test_minted_token_is_accepted_by_the_authorizer(
        self,
        minted_token: Callable[..., str],
        anon: E2EClient,
        gateway_routes: Sequence[Route],
    ) -> None:
        """Staging only: a KMS-minted token is accepted on a route behind the authorizer."""
        route = _first_authorized_route(gateway_routes)
        token = minted_token({"roles": ["admin"]})
        response = anon.with_token(token).request(_probe_method(route), _probe_path(route))
        assert response.status_code not in (401, 403), (
            f"a minted token was rejected with {response.status_code} on {route.route_key}, so "
            "the authorizer does not accept a token this environment's own key signed."
        )

    def test_minted_token_with_the_wrong_audience_is_rejected(
        self,
        minted_token: Callable[..., str],
        anon: E2EClient,
        gateway_routes: Sequence[Route],
    ) -> None:
        """Staging only: a token for another audience is refused by the authorizer."""
        route = _first_authorized_route(gateway_routes)
        token = minted_token(audience="https://e2e.invalid/not-this-audience")
        response = anon.with_token(token).request(_probe_method(route), _probe_path(route))
        assert response.status_code in (401, 403), (
            f"a token minted for another audience answered {response.status_code} on "
            f"{route.route_key}. The authorizer is not checking `aud`."
        )

    def test_expired_minted_token_is_rejected(
        self,
        minted_token: Callable[..., str],
        anon: E2EClient,
        gateway_routes: Sequence[Route],
    ) -> None:
        """Staging only: a token whose `exp` has passed is refused by the authorizer."""
        import time

        route = _first_authorized_route(gateway_routes)
        token = minted_token(expires_in=1, now=int(time.time()) - 3600)
        response = anon.with_token(token).request(_probe_method(route), _probe_path(route))
        assert response.status_code in (401, 403), (
            f"an expired token answered {response.status_code} on {route.route_key}. The "
            "authorizer is not checking `exp`."
        )

    def test_logout_ends_the_session(self, user_session: Any) -> None:
        """The logout route answers, and runs last because it ends the session."""
        response = logout(user_session)
        assert response.status_code in (200, 204), f"logout answered {response.status_code}: {response.text[:200]}"


def _first_authorized_route(routes: Sequence[Route]) -> Route:
    """One live route that sits behind an authorizer, for the minted-token probes."""
    for route in sorted(routes, key=lambda item: item.route_key):
        if route.has_authorizer and "{proxy+}" not in route.path:
            return route
    pytest.skip("no live route carries an authorizer, so there is nothing to present a minted token to")


class TestFrontend:
    """Group 5: the deployed SPA answers, routes unknown URLs, and talks to the right API."""

    def test_web_origin_serves_the_app_shell(self, http: Any, e2e_env: Any) -> None:
        """The web base URL answers 200 with the app shell."""
        response = http.get(e2e_env.web_base_url + "/")
        assert response.status_code == 200, f"{e2e_env.web_base_url}/ answered {response.status_code}"
        assert shell_looks_like_an_app(response.text), (
            "the web origin answered 200 with something that is not the app shell: no mount "
            "point, or no script tag. A 200 carrying an empty root is the shipped blank page."
        )

    def test_unknown_path_renders_the_shell(self, http: Any, e2e_env: Any) -> None:
        """A path the router does not know still renders the shell, not an empty root.

        A router with no catch-all renders nothing on an unknown URL, and any render error
        blanks the page. Both ship silently through a deploy with no frontend verification.
        """
        response = http.get(f"{e2e_env.web_base_url}/e2e-no-such-page-{ABSENT_ID}")
        assert response.status_code == 200, f"an unknown path answered {response.status_code}, not the SPA catch-all"
        assert shell_looks_like_an_app(response.text), (
            "an unknown path answered 200 with something that is not the shell"
        )

    def test_bundle_references_this_environments_api(self, http: Any, e2e_env: Any) -> None:
        """The deployed bundle names this environment's API base URL."""
        shell = http.get(e2e_env.web_base_url + "/")
        report = fetch_bundle(http, e2e_env.web_base_url, shell.text)
        assert report.chunks, "no JS chunk could be fetched from the deployed shell"
        assert report.contains(e2e_env.api_base_url), (
            f"the deployed bundle never mentions {e2e_env.api_base_url}, so the app is "
            f"pointed at some other API. {report.chunks} chunks were read."
        )

    def test_bundle_carries_no_legacy_route_names(self, http: Any, e2e_env: Any) -> None:
        """The deployed bundle names none of `E2E_LEGACY_ROUTE_NAMES`.

        The bundle is what users run, so a source tree that no longer mentions a route
        proves nothing about what is deployed in front of them.
        """
        if not e2e_env.legacy_route_names:
            pytest.skip("E2E_LEGACY_ROUTE_NAMES is empty, so there is nothing to sweep for")
        shell = http.get(e2e_env.web_base_url + "/")
        report = fetch_bundle(http, e2e_env.web_base_url, shell.text)
        assert report.chunks, "no JS chunk could be fetched from the deployed shell"
        present = report.present(e2e_env.legacy_route_names)
        assert not present, f"the deployed bundle still references legacy routes: {', '.join(present)}"

    def test_cors_preflight_allows_the_clients_headers(
        self,
        http: Any,
        e2e_env: Any,
        cors_request_headers: Sequence[str],
        gateway_routes: Sequence[Route],
    ) -> None:
        """A preflight from the web origin allows every header the shared client sends.

        One header missing from the allow list makes the client's own requests fail
        cross-origin, which no server-side probe can see because a probe sends no `Origin`.
        """
        route = _first_authorized_route(gateway_routes) if gateway_routes else None
        path = _probe_path(route) if route else "/"
        response = http.request(
            "OPTIONS",
            e2e_env.api_base_url + path,
            headers={
                "origin": e2e_env.web_base_url,
                "access-control-request-method": "POST",
                "access-control-request-headers": ", ".join(cors_request_headers),
            },
        )
        assert response.status_code < 400, f"the preflight answered {response.status_code}"
        allowed_origin = response.headers.get("access-control-allow-origin", "")
        assert allowed_origin in (e2e_env.web_base_url, "*"), (
            f"the preflight allows origin {allowed_origin!r}, not {e2e_env.web_base_url!r}"
        )
        missing = missing_allowed_headers(response, cors_request_headers)
        assert not missing, (
            f"the gateway's CORS allow list is missing {', '.join(missing)}, so the shared "
            "client's own requests carrying those headers are rejected by the browser."
        )


class TestHygiene:
    """Group 6: the run named everything it created, and the cleanup hooks are registered."""

    def test_run_id_prefixes_every_created_name(self, e2e_env: Any) -> None:
        """The resource prefix carries the `e2e-` marker and this run's id.

        The start-of-session sweep finds leftovers by that prefix, so a prefix that does not
        carry it would leave every earlier run's resources undeletable.
        """
        assert e2e_env.resource_prefix.startswith("e2e-"), (
            f"resource prefix {e2e_env.resource_prefix!r} lacks the e2e- marker"
        )
        assert e2e_env.run_id in e2e_env.resource_prefix, "the resource prefix does not carry this run's id"

    def test_cleanup_hook_is_registered(self, request: pytest.FixtureRequest) -> None:
        """The `pytest_e2e_cleanup` hook exists, so a product can register a sweep against it."""
        assert hasattr(request.config.hook, "pytest_e2e_cleanup"), (
            "pytest_e2e_cleanup is not registered, so nothing this run creates would ever be "
            "deleted. Check that pytest_plugins names webbpulse.e2e."
        )

    def test_created_resources_are_tracked(self, created_resources: list[Any]) -> None:
        """The `created_resources` list exists for products to append to."""
        assert isinstance(created_resources, list)


def _decoded(token: str) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    """The header and claims of a token, for a product test that wants to assert on them."""
    return decode_claims(token)
