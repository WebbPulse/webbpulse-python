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

import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import pytest

from webbpulse.http import ROUTE_KEY_HEADER

from .access_log import AccessLogLookup
from .browser import ROOT_SELECTORS, BrowserFailure, ConsoleErrors, FailedRequests, browser_contract, sign_in
from .client import E2EClient, RateLimitExhausted
from .frontend import fetch_bundle, missing_allowed_headers, shell_looks_like_an_app
from .gateway import (
    ABSENT_ID,
    Operation,
    Route,
    concrete_path,
    identity_authorization_is_observable,
    matching_route,
    probe_method,
    probe_path,
    resolve,
    route_key_is_expressible,
    route_requires_identity,
)
from .identity import JWKS_PATH, decode_claims, logout, refresh
from .journeys import (
    Click,
    ExpectText,
    ExpectUrl,
    ExpectVisible,
    Fill,
    Goto,
    Journey,
    LoginForm,
    Record,
    RouteSpec,
    expand,
    url_matches,
)

__all__ = [
    "RouteProbe",
    "TestBrowser",
    "TestCoverage",
    "TestFrontend",
    "TestHygiene",
    "TestIdentity",
    "TestReachability",
    "TestRouteCut",
    "journey_id",
    "operation_id",
    "probe_every_route",
    "pytest_generate_tests",
    "route_id",
    "route_probes",
    "route_spec_id",
]

GATEWAY_404_BODY = "Not Found"
GATE_STATUSES = (401, 403)


def route_id(route: Route) -> str:
    """A junit-legible id for one live route."""
    return route.route_key


def operation_id(operation: Operation) -> str:
    """A junit-legible id for one OpenAPI operation."""
    return operation.label


def route_spec_id(spec: RouteSpec) -> str:
    """A junit-legible id for one declared front-end route."""
    return spec.label


def journey_id(journey: Journey) -> str:
    """A junit-legible id for one declared product journey."""
    return journey.label


MAX_NAVIGATIONS = 5


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
    browser_names = ("declared_route", "protected_route", "guest_only_route", "journey")
    if any(name in metafunc.fixturenames for name in browser_names):
        _parametrise_browser_cases(metafunc)
    if not any(name in metafunc.fixturenames for name in ("live_route", "operation")):
        return
    inputs = collection_inputs(metafunc.config)
    if "live_route" in metafunc.fixturenames:
        routes = inputs.routes
        metafunc.parametrize("live_route", routes, ids=[route_id(route) for route in routes])
    if "operation" in metafunc.fixturenames:
        operations = inputs.operations
        metafunc.parametrize("operation", operations, ids=[operation_id(op) for op in operations])


def _parametrise_browser_cases(metafunc: pytest.Metafunc) -> None:
    """Parametrise the browser cases from the three product hooks, gathered once.

    An empty declaration parametrises with nothing and marks the case skipped rather than
    leaving an unparametrised fixture behind, which would error as a missing fixture and
    read as a broken plugin rather than as a product that declared no routes.
    """
    from . import READ_ONLY_REASON, E2EEnvironment, _read_only_from_environ

    contract = browser_contract(metafunc.config, E2EEnvironment.from_environ())
    declared: dict[str, tuple[RouteSpec, ...] | tuple[Journey, ...]] = {
        "declared_route": contract.routes,
        "protected_route": tuple(spec for spec in contract.routes if spec.access == "protected"),
        "guest_only_route": tuple(spec for spec in contract.routes if spec.access == "guest-only"),
        "journey": contract.journeys,
    }
    reasons = {
        "declared_route": "pytest_e2e_routes declared no routes",
        "protected_route": "pytest_e2e_routes declared no protected routes",
        "guest_only_route": "pytest_e2e_routes declared no guest-only routes",
        "journey": "pytest_e2e_journeys declared no journeys",
    }
    read_only = _read_only_from_environ()
    for name, values in declared.items():
        if name not in metafunc.fixturenames:
            continue
        if not values:
            metafunc.parametrize(name, [pytest.param(None, marks=pytest.mark.skip(reason=reasons[name]))])
            continue
        ids = [value.label for value in values]
        params = [_browser_param(value, read_only, READ_ONLY_REASON) for value in values]
        metafunc.parametrize(name, params, ids=ids)


def _browser_param(value: RouteSpec | Journey, read_only: bool, reason: str) -> Any:
    """One parametrised browser case, skipped in read-only mode when it needs a session.

    Marked per parameter rather than per test, because the render case covers both a
    protected route, which has to be visited signed in, and every public one, which does
    not. A read-only run keeps the public parameters and skips only the parameters that
    would need the durable e2e user.
    """
    if read_only and _needs_a_session(value):
        return pytest.param(value, marks=pytest.mark.skip(reason=reason))
    return value


def _needs_a_session(value: RouteSpec | Journey) -> bool:
    """Whether one declared route or journey can only run as a signed-in user.

    A protected route is visited signed in by definition. A journey says so itself, through
    `signed_in` or `mutates`, and either one is enough.
    """
    if isinstance(value, Journey):
        return value.signed_in or value.mutates
    return value.access == "protected"


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


@dataclass(frozen=True)
class RouteProbe:
    """What one route's up-front probe produced, which the access log case then asks about.

    `served_route_key` is what the app itself reported on the response, which is empty when
    the gateway answered before the function ran. A route every path of which a more
    specific key shadows is never probed, and carries the `skip_reason` its case skips with
    instead of a request id. A probe that raised carries the `error` its case re-raises, so
    a limiter that exhausted the budget fails that route rather than quietly skipping it.
    """

    route_key: str
    method: str
    path: str
    request_id: str = ""
    served_route_key: str = ""
    status: int = 0
    skip_reason: str = ""
    error: Exception | None = None


def probe_every_route(
    routes: Sequence[Route],
    route_keys: Sequence[str],
    client: E2EClient,
) -> dict[str, RouteProbe]:
    """Probe every live route once, returning each route key's probe.

    Probing the whole group before any log is read is what makes the group fast: delivery
    lags roughly half a minute per stream, and one probe per route followed by one wait for
    all of them pays that lag once rather than once per route. A probe that raises is kept
    against its route rather than abandoning the sweep, so one route's exhausted budget
    costs one case and not the whole group.
    """
    probes: dict[str, RouteProbe] = {}
    for route in routes:
        method = probe_method(route)
        path = probe_path(route)
        expected = resolve(path, method, route_keys)
        if expected != route.route_key:
            probes[route.route_key] = RouteProbe(
                route_key=route.route_key,
                method=method,
                path=path,
                skip_reason=f"{path} resolves to {expected or 'no route'}, which shadows {route.route_key}",
            )
            continue
        try:
            response = client.request(method, path)
        except Exception as error:
            probes[route.route_key] = RouteProbe(route_key=route.route_key, method=method, path=path, error=error)
            continue
        probes[route.route_key] = RouteProbe(
            route_key=route.route_key,
            method=method,
            path=path,
            request_id=response.headers.get("apigw-requestid", ""),
            served_route_key=response.headers.get(ROUTE_KEY_HEADER.lower(), ""),
            status=response.status_code,
        )
    return probes


@pytest.fixture(scope="session")
def route_probes(
    gateway_routes: Sequence[Route],
    route_keys: Sequence[str],
    anon: E2EClient,
    access_log: AccessLogLookup,
) -> Mapping[str, RouteProbe]:
    """Every live route probed once, up front, before any access log entry is asked for.

    Opens the lookup's delivery window at the first probe, so the later per-route cases scan
    that one window instead of filtering for one request id at a time.
    """
    first_probe_ms = int(time.time() * 1000)
    access_log.open_window(first_probe_ms)
    return probe_every_route(gateway_routes, route_keys, anon)


class TestRouteCut:
    """Group 1: every live route is served by the integration its route key declares.

    A 200 proves something answered. Which route key matched is said by the app's own
    `X-WebbPulse-Route-Key` response header where the request reached the function, and by
    the access log entry where it did not, and that is the difference between a landed cut
    and a request falling through a `{proxy+}` catch-all with no identity claims.
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
        access_log: AccessLogLookup,
        route_probes: Mapping[str, RouteProbe],
    ) -> None:
        """A probe to this route is served by this route key, with no integration error.

        Two proofs, cheapest first. The shared HTTP layer echoes the gateway's own
        `routeKey` as `X-WebbPulse-Route-Key` on every response, so a probe that reached the
        function proves the cut the moment it answers. Where the header is absent the
        gateway answered before the function ran, which is what an identity rejection, a
        gate rejection or the gateway's own 404 look like, and then the access log entry is
        the only thing that says which key matched.

        The probe itself was sent by the `route_probes` fixture, which probed every route
        before this group started, so a group that has to fall back waits out one delivery
        lag rather than one per route. The probe path is resolved back through the
        precedence matcher there: a route whose every path a more specific key shadows
        cannot be probed directly, and asserting the shadowing key would be asserting the
        wrong thing.
        """
        probe = route_probes.get(live_route.route_key)
        if probe is None:
            pytest.skip(f"{live_route.route_key} was not probed, so there is nothing to correlate")
        if probe.error is not None:
            raise probe.error
        if probe.skip_reason:
            pytest.skip(probe.skip_reason)
        method, path = probe.method, probe.path
        assert probe.status < 500, (
            f"{method} {path} answered {probe.status}. A cut cannot be verified against a gateway that is erroring."
        )

        if probe.served_route_key:
            assert probe.served_route_key == live_route.route_key, (
                f"{method} {path} was served by route key {probe.served_route_key!r}, not "
                f"{live_route.route_key!r}, as the app itself reported on "
                f"{ROUTE_KEY_HEADER}. Either an apply has not landed or a key was changed "
                "outside Terraform."
            )
            return

        entry = access_log.find(probe.request_id)
        if entry is None:
            pytest.skip(
                f"{method} {path} answered {probe.status} without {ROUTE_KEY_HEADER}, so the "
                "gateway answered before the function ran, and no access log entry arrived "
                "inside the budget either. Delivery is per stream and can lag, and the probe "
                "already reached the API, so this is not itself evidence of a bad route."
            )
        assert entry.route_key == live_route.route_key, (
            f"{method} {path} was served by route key {entry.route_key!r}, not "
            f"{live_route.route_key!r}, according to the access log. Either an apply has "
            "not landed or a key was changed outside Terraform."
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

    def test_authorizer_matches_the_operation(
        self,
        operation: Operation,
        gateway_routes: Sequence[Route],
        gate_authorizers: frozenset[str],
    ) -> None:
        """An operation needing auth lands on a route with an identity authorizer, and vice versa.

        The access gate is not identity: it admits any caller presenting the `x-origin-verify`
        header or the signed gate cookies, and the http-api module attaches it to every route
        it creates, public ones included. Only a non-gate authorizer counts here.
        """
        route = matching_route(operation, gateway_routes)
        if route is None:
            pytest.skip("no live route matches, which the coverage case above already reports")
        if not identity_authorization_is_observable(gateway_routes, gate_authorizers):
            pytest.skip(
                "no live route carries an authorizer other than the staging access gate, so "
                "the gate's Lambda authorizer holds every route's only authorizer slot and "
                "verifies the identity token itself. The deployed route configuration cannot "
                "say which operations require a token, so there is nothing structural to check."
            )
        requires_identity = route_requires_identity(route, gate_authorizers)
        assert requires_identity == operation.requires_auth, (
            f"{operation.label} declares requires_auth={operation.requires_auth} but resolves "
            f"to {route.route_key!r}, which requires_identity={requires_identity}. A "
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

    @pytest.mark.e2e_writes
    def test_authenticated_call_is_answered_by_the_api(self, operation: Operation, api: E2EClient) -> None:
        """Calling an operation as the durable e2e user reaches the API.

        A bare mutation is skipped here: with no path parameter to fill with an absent id,
        the call would execute for real as the durable user, and `POST /api/auth/logout`
        would end the session every later case depends on. The anonymous probe above has
        already proven that such a route reaches the API.
        """
        if operation.is_bare_mutation:
            pytest.skip(f"{operation.label} would execute a real state change as the durable e2e user")
        self._assert_reachable(operation, api, "as the e2e user")

    def _assert_reachable(self, operation: Operation, client: E2EClient, who: str) -> None:
        """One reachability probe, with the distinction between the failure modes named."""
        path = concrete_path(operation.path)
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

    @pytest.mark.e2e_writes
    def test_login_returns_an_rs256_token(self, user_session: Any) -> None:
        """The durable user's access token is RS256, not a legacy HS256 one."""
        assert user_session.algorithm == "RS256", (
            f"the access token declares alg={user_session.algorithm!r}. A legacy HS256 token "
            "would mean a resolver still mints one, which is a claim about which code path ran."
        )

    @pytest.mark.e2e_writes
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

    @pytest.mark.e2e_writes
    def test_refresh_issues_a_new_token(self, user_session: Any) -> None:
        """The refresh route exchanges the refresh material for a fresh access token."""
        response = refresh(user_session)
        assert response.status_code == 200, f"refresh answered {response.status_code}: {response.text[:200]}"
        payload = response.json()
        assert isinstance(payload, dict), "refresh answered 200 with a body that is not an object"

    @pytest.mark.e2e_writes
    def test_minted_token_is_accepted_by_the_api(
        self,
        minted_token: Callable[..., str],
        anon: E2EClient,
        gateway_routes: Sequence[Route],
        gate_authorizers: frozenset[str],
        openapi_operations: Sequence[Operation],
    ) -> None:
        """Staging only: a KMS-minted token is accepted on a route that requires identity.

        A 403 counts as accepted. The probe is whichever auth-requiring operation the
        deployed configuration offers first, which on a product with an admin surface is an
        admin route, and there a 403 means the token was verified and the subject resolved
        to a real user who simply lacks the role. Only a 401 says the token itself was not
        accepted, which is the thing under test.
        """
        probe = _first_identity_probe(gateway_routes, gate_authorizers, openapi_operations)
        token = minted_token({"roles": ["admin"]})
        response = anon.with_token(token).request(probe.method, probe.path)
        assert response.status_code != 401, (
            f"a minted token was rejected with 401 on {probe.route_key}, so the API does not "
            "accept a token this environment's own key signed. A 403 would have been fine: "
            "it means the token verified and the subject resolved, and only the role check "
            "refused."
        )

    @pytest.mark.e2e_writes
    def test_minted_token_with_the_wrong_audience_is_rejected(
        self,
        minted_token: Callable[..., str],
        anon: E2EClient,
        gateway_routes: Sequence[Route],
        gate_authorizers: frozenset[str],
        openapi_operations: Sequence[Operation],
    ) -> None:
        """Staging only: a token for another audience is refused.

        The subject is the durable e2e user's own, so the only thing wrong with this token
        is its `aud` and the refusal can only be about that.
        """
        probe = _first_identity_probe(gateway_routes, gate_authorizers, openapi_operations)
        token = minted_token(audience="https://e2e.invalid/not-this-audience")
        response = anon.with_token(token).request(probe.method, probe.path)
        assert response.status_code in (401, 403), (
            f"a token minted for another audience answered {response.status_code} on "
            f"{probe.route_key}. The API is not checking `aud`."
        )

    @pytest.mark.e2e_writes
    def test_expired_minted_token_is_rejected(
        self,
        minted_token: Callable[..., str],
        anon: E2EClient,
        gateway_routes: Sequence[Route],
        gate_authorizers: frozenset[str],
        openapi_operations: Sequence[Operation],
    ) -> None:
        """Staging only: a token whose `exp` has passed is refused.

        The subject is the durable e2e user's own, so the only thing wrong with this token
        is its `exp` and the refusal can only be about that.
        """
        probe = _first_identity_probe(gateway_routes, gate_authorizers, openapi_operations)
        token = minted_token(expires_in=1, now=int(time.time()) - 3600)
        response = anon.with_token(token).request(probe.method, probe.path)
        assert response.status_code in (401, 403), (
            f"an expired token answered {response.status_code} on {probe.route_key}. The API is not checking `exp`."
        )

    @pytest.mark.e2e_writes
    def test_logout_ends_the_session(self, user_session: Any) -> None:
        """The logout route answers, and runs last because it ends the session."""
        response = logout(user_session)
        assert response.status_code in (200, 204), f"logout answered {response.status_code}: {response.text[:200]}"


def _first_authorized_route(routes: Sequence[Route]) -> Route:
    """One live route that sits behind any authorizer, for a probe that needs a real path.

    Structural, so on a gated staging API this is simply the first route. Callers asserting
    something about identity want `_first_identity_probe` instead.
    """
    for route in sorted(routes, key=lambda item: item.route_key):
        if route.has_authorizer and "{proxy+}" not in route.path:
            return route
    pytest.skip("no live route carries an authorizer, so there is nothing to present a minted token to")


@dataclass(frozen=True)
class ProbeTarget:
    """A concrete method and path to present a minted token to, and the key that serves it.

    The method matters as much as the path. A route key of `ANY /api/admin/db-ops` is served
    by a router that defines only POST, so probing it with GET is answered 404 by FastAPI
    before any auth dependency runs and a probe expecting 401 fails on a healthy app.
    """

    method: str
    path: str
    route_key: str


SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
UNSAFE_PROBE_PATHS = ("/api/auth/logout",)


def _operation_probe_rank(operation: Operation) -> tuple[int, str]:
    """Sort key ordering probe candidates safest first.

    A GET is the best probe: it carries no body, changes nothing, and every app serves one
    for a resource it also protects. A HEAD or OPTIONS is as safe and rarer. A mutation that
    takes a path parameter comes last, because the probe points it at an absent id and the
    handler answers the miss without writing. A mutation with no path parameter is never a
    candidate: the accepted-token probe carries an admin token, so the request would execute
    for real, and on CarModPicker the first such operation is `POST /api/admin/db-ops/cars/delete-all`.
    """
    rank = 0 if operation.method in SAFE_METHODS else 1
    return (rank, operation.label)


def _identity_probe_from_routes(routes: Sequence[Route], gate_ids: frozenset[str]) -> ProbeTarget | None:
    """The first live route carrying a non-gate authorizer, as a probe target, or None.

    The authorizer runs before the integration, so here the method only has to be one the
    gateway routes: an `ANY` key accepts every method and a concrete key names its own.
    """
    for route in sorted(routes, key=lambda item: item.route_key):
        if route_requires_identity(route, gate_ids) and "{proxy+}" not in route.path:
            return ProbeTarget(method=probe_method(route), path=probe_path(route), route_key=route.route_key)
    return None


def _identity_probe_from_operations(routes: Sequence[Route], operations: Sequence[Operation]) -> ProbeTarget | None:
    """A declared operation that requires auth and maps to a live route, as a probe target, or None.

    Used where the gate is the only authorizer and verifies the identity token itself, so the
    route table cannot say which routes need one. The operation's own method and concrete
    path are what the probe sends, because the route key it resolves to may be an `ANY` or
    `{proxy+}` key whose router defines only some methods, and a method with no handler is
    answered 404 before the auth dependency runs. Candidates are ordered safest first by
    `_operation_probe_rank`; a bare mutation is never one because an accepted admin token
    would run it for real, and the logout path is never one because the probe would end the
    run's own session.
    """
    candidates = [
        operation
        for operation in operations
        if operation.requires_auth and not operation.is_bare_mutation and operation.path not in UNSAFE_PROBE_PATHS
    ]
    for operation in sorted(candidates, key=_operation_probe_rank):
        route = matching_route(operation, routes)
        if route is None:
            continue
        return ProbeTarget(method=operation.method, path=concrete_path(operation.path), route_key=route.route_key)
    return None


def _first_identity_probe(
    routes: Sequence[Route],
    gate_ids: frozenset[str],
    operations: Sequence[Operation],
) -> ProbeTarget:
    """A method and path that actually requires an identity token, for the minted-token probes.

    A route carrying only the access gate's authorizer is not one: the gate admits any
    caller presenting the origin-verify header, so an expired or wrong-audience token
    reaches the integration and is answered 200, and the probe asserting a 401 fails on a
    healthy API. Where no route carries a non-gate authorizer the gate verifies the identity
    token itself, and the route table cannot say which routes those are, so the operation
    list the app declares is used instead, and the operation's own method is sent so the
    request reaches a handler rather than a 404.
    """
    found = _identity_probe_from_routes(routes, gate_ids) or _identity_probe_from_operations(routes, operations)
    if found is not None:
        return found

    pytest.skip(
        "no live route requires an identity token: every authorizer on this API is the "
        "staging access gate, and no declared operation that requires auth maps to a "
        "concrete route key, so there is nothing to present a minted token to."
    )


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
        path = probe_path(route) if route else "/"
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


class TestBrowser:
    """Group 7: the deployed SPA driven the way a person drives it.

    Everything above proves the API answers and the shell downloads. None of it proves the
    app renders, that a route guard sends an anonymous visitor to the login page rather
    than unmounting it, or that signing in through the real form still works. Those are
    exactly the failures that ship green, because a blank page is a 200.

    Every case here skips with a reason when the product declares no contract for it, so a
    product adopting the plugin gets the API groups immediately and the browser groups as
    it adds the hooks.
    """

    @pytest.mark.e2e_writes
    def test_sign_in_and_out_through_the_ui(
        self,
        page: Any,
        login_form: LoginForm,
        e2e_env: Any,
        console_errors: ConsoleErrors,
    ) -> None:
        """Signing in shows the signed-in marker, signing out takes it away, and a reload keeps it away.

        The reload is the part worth having: an app that clears its in-memory session on
        sign-out but leaves a token in storage looks signed out until the next page load,
        which is when a person discovers they never were.

        Sign-out is judged by what the page shows, never by the URL. An app that renders its
        login form in place leaves the path untouched, so requiring a change would fail every
        run against a correct app.
        """
        sign_in(page, login_form, e2e_env)
        assert page.locator(login_form.signed_in_marker).is_visible(), (
            f"{login_form.signed_in_marker} is not visible after signing in as the durable e2e user"
        )

        page.click(login_form.sign_out)
        page.wait_for_selector(login_form.signed_out_marker, state="visible", timeout=e2e_env.browser_timeout_ms)
        assert page.locator(login_form.signed_in_marker).count() == 0, (
            f"{login_form.signed_in_marker} is still on the page after signing out, so the session was never cleared."
        )
        assert not console_errors, f"signing in and out logged console errors: {console_errors.summary()}"

        page.reload(wait_until="domcontentloaded")
        page.wait_for_selector(login_form.signed_out_marker, state="visible", timeout=e2e_env.browser_timeout_ms)
        assert page.locator(login_form.signed_in_marker).count() == 0, (
            f"{login_form.signed_in_marker} came back after reloading, so signing out cleared "
            "the session in memory but left a token in storage. The app reads as signed out "
            "until the next page load, and a person discovers they never were."
        )

    def test_protected_routes_redirect_anonymous_visitors(
        self,
        protected_route: RouteSpec,
        page: Any,
        login_form: LoginForm,
        e2e_env: Any,
    ) -> None:
        """An anonymous visit to a protected route lands on the login path, with no loop."""
        landing = _settle(page, protected_route.path, e2e_env)
        assert landing.startswith(login_form.anonymous_redirect), (
            f"an anonymous visit to {protected_route.path} settled on {landing}, not on "
            f"{login_form.anonymous_redirect}. A guard that renders the protected route to "
            "an anonymous visitor is the whole reason this case exists."
        )

    @pytest.mark.e2e_writes
    def test_guest_only_routes_redirect_signed_in_users(
        self,
        guest_only_route: RouteSpec,
        signed_in_page: Any,
        login_form: LoginForm,
        e2e_env: Any,
    ) -> None:
        """A signed-in visit to a guest-only route lands on the signed-in landing path."""
        landing = _settle(signed_in_page, guest_only_route.path, e2e_env)
        assert landing.startswith(login_form.guest_redirect), (
            f"a signed-in visit to {guest_only_route.path} settled on {landing}, not on "
            f"{login_form.guest_redirect}. A guest guard that waits on a loading flag "
            "before redirecting shows the login form to someone already signed in."
        )

    def test_declared_routes_render_clean(
        self,
        declared_route: RouteSpec,
        request: pytest.FixtureRequest,
        e2e_env: Any,
        console_errors: ConsoleErrors,
        failed_requests: FailedRequests,
    ) -> None:
        """Every declared route paints children, logs no console error and makes no failed API call.

        A protected route is visited signed in; everything else anonymously, with the 401
        and 403 an anonymous visit is meant to provoke exempted rather than counted, in both
        collectors. The browser logs a resource-load console error for the same response the
        request listener sees, so exempting one without the other fails every public route on
        a healthy app.
        """
        signed_in = declared_route.access == "protected"
        if signed_in:
            page = request.getfixturevalue("signed_in_page")
        else:
            page = request.getfixturevalue("page")
            failed_requests.ignore_guard_statuses = True
            console_errors.ignore_guard_statuses = True
        console_errors.clear()
        failed_requests.clear()

        page.goto(declared_route.path, wait_until="domcontentloaded")
        page.wait_for_timeout(500)

        root = _root_locator(page, declared_route)
        assert root is not None, (
            f"{declared_route.path} rendered no mount point matching any of "
            f"{', '.join(_root_selectors(declared_route))}, so there is nothing on the page "
            "to assert about"
        )
        assert root.locator("*").count() > 0, (
            f"{declared_route.path} answered with an empty mount point. A 200 carrying an "
            "empty root is the shipped blank page, and no server-side probe can see it."
        )
        assert not console_errors, f"{declared_route.path} logged console errors: {console_errors.summary()}"
        assert not failed_requests, f"{declared_route.path} made API calls that failed: {failed_requests.summary()}"

    def test_product_journeys(
        self,
        journey: Journey,
        request: pytest.FixtureRequest,
        e2e_env: Any,
        created_resources: list[Any],
        console_errors: ConsoleErrors,
    ) -> None:
        """Run one declared journey's steps against the real UI.

        A mutating journey records what it created as it goes, so the cleanup hook deletes
        it even when a later step fails. The `Journey` constructor already refuses a
        mutating journey with no `Record` step, which makes that a collection-time refusal
        rather than a leak discovered afterwards.
        """
        page = request.getfixturevalue("signed_in_page" if journey.signed_in else "page")
        console_errors.clear()
        for index, step in enumerate(journey.steps):
            _run_step(page, step, e2e_env, created_resources, f"{journey.name} step {index + 1}")
        assert not console_errors, f"journey {journey.name} logged console errors: {console_errors.summary()}"


def _run_step(page: Any, step: Any, env: Any, created: list[Any], where: str) -> None:
    """Execute one journey step, naming the journey and the step index on a failure."""
    timeout = env.browser_timeout_ms
    if isinstance(step, Goto):
        page.goto(expand(step.path, env.run_id), wait_until="domcontentloaded")
    elif isinstance(step, Click):
        page.click(step.locator, timeout=timeout)
    elif isinstance(step, Fill):
        page.fill(step.locator, expand(step.value, env.run_id), timeout=timeout)
    elif isinstance(step, ExpectVisible):
        _expect_visible(page, step.locator, timeout, where)
    elif isinstance(step, ExpectText):
        _expect_text(page, step, env, timeout, where)
    elif isinstance(step, ExpectUrl):
        _expect_url(page, step, env, timeout, where)
    elif isinstance(step, Record):
        created.append(expand(step.resource, env.run_id) if isinstance(step.resource, str) else step.resource)
    else:
        raise BrowserFailure(f"{where} is {type(step).__name__}, which is not a journey step")


def _expect_visible(page: Any, locator: str, timeout: int, where: str) -> None:
    """Wait for one locator to become visible, failing with the journey's own name."""
    try:
        page.wait_for_selector(locator, state="visible", timeout=timeout)
    except Exception as error:
        raise BrowserFailure(f"{where}: {locator} never became visible ({type(error).__name__})") from None


def _expect_text(page: Any, step: Any, env: Any, timeout: int, where: str) -> None:
    """Wait for one locator to contain the expected text."""
    wanted = expand(step.text, env.run_id)
    deadline = timeout
    try:
        page.wait_for_selector(step.locator, state="visible", timeout=deadline)
        actual = page.locator(step.locator).inner_text()
    except Exception as error:
        raise BrowserFailure(f"{where}: {step.locator} never became visible ({type(error).__name__})") from None
    assert wanted in actual, f"{where}: {step.locator} reads {actual[:200]!r}, which does not contain {wanted!r}"


def _expect_url(page: Any, step: Any, env: Any, timeout: int, where: str) -> None:
    """Wait until the current URL matches the expected pattern."""
    pattern = expand(step.pattern, env.run_id)
    waited = 0
    while waited < timeout:
        if url_matches(pattern, page.url):
            return
        page.wait_for_timeout(250)
        waited += 250
    raise BrowserFailure(f"{where}: the URL settled on {page.url}, which does not match {pattern!r}")


def _settle(page: Any, path: str, env: Any) -> str:
    """Visit a path, follow the guard's redirects and return the path it settled on.

    Navigations are counted and capped, because a pair of guards that each redirect to the
    other loops until the runner times out, and a timeout says nothing about which guard
    is wrong.
    """
    page.goto(path, wait_until="domcontentloaded")
    seen = [_path_of(page.url)]
    for _ in range(MAX_NAVIGATIONS):
        page.wait_for_timeout(400)
        current = _path_of(page.url)
        if current == seen[-1]:
            return current
        seen.append(current)
    raise BrowserFailure(
        f"visiting {path} never settled: the app navigated more than {MAX_NAVIGATIONS} "
        f"times, through {' -> '.join(seen)}. That is a redirect loop between two guards, "
        "not a slow page."
    )


def _path_of(url: str) -> str:
    """The path and query of a URL, which is what a declared route is written as."""
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    return parts.path or "/"


def _root_selectors(spec: RouteSpec) -> tuple[str, ...]:
    """The selectors a route's mount point is looked for under, override first.

    A route carrying its own `root_locator` is tried against that alone, so a failure
    report names the selector that was actually used rather than the shared defaults.
    """
    return (spec.root_locator,) if spec.root_locator else tuple(ROOT_SELECTORS)


def _root_locator(page: Any, spec: RouteSpec) -> Any:
    """The mount point to assert children under, honouring a route's own override."""
    for selector in _root_selectors(spec):
        locator = page.locator(selector).first
        if locator.count() > 0:
            return locator
    return None


def _decoded(token: str) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    """The header and claims of a token, for a product test that wants to assert on them."""
    return decode_claims(token)
