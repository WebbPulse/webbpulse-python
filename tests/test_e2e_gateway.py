"""Tests for the route precedence matcher and the OpenAPI operation mapping.

The matcher is the one piece of this package that has to agree with API Gateway rather than
with itself, and the cases below are the ones the prior art's string rules kept getting
wrong: a literal promoted over a variable, a method-specific key promoted over `ANY`, and a
trailing slash that matches nothing at all.
"""

from __future__ import annotations

from typing import Any

import pytest

from webbpulse.e2e.gateway import (
    Authorizer,
    Operation,
    Route,
    fetch_authorizers,
    fetch_routes,
    gate_authorizer_ids,
    identity_authorization_is_observable,
    matching_route,
    operations_from_openapi,
    resolve,
    route_key_is_expressible,
    route_requires_identity,
)


def route(key: str, *, target: str = "integrations/abc", authorizer: str = "", auth_type: str = "NONE") -> Route:
    """One live route record, with the fields the assertions read."""
    return Route(route_key=key, target=target, authorizer_id=authorizer, authorization_type=auth_type)


class FakeApiGateway:
    """A stand-in for the `apigatewayv2` client, since moto's backend needs an extra dependency.

    Pages deliberately, so `fetch_routes` is exercised against a multi-page response rather
    than only the single-page case a real small API would produce.
    """

    def __init__(self, pages: list[dict[str, Any]]) -> None:
        """Hold the pages `get_routes` will hand back in order."""
        self.pages = pages
        self.calls: list[dict[str, Any]] = []

    def get_routes(self, **kwargs: Any) -> dict[str, Any]:
        """Return the page matching the supplied NextToken, recording the call."""
        self.calls.append(kwargs)
        index = int(kwargs.get("NextToken", "0"))
        return self.pages[index]

    def get_authorizers(self, **kwargs: Any) -> dict[str, Any]:
        """Return the page matching the supplied NextToken, recording the call."""
        self.calls.append(kwargs)
        index = int(kwargs.get("NextToken", "0"))
        return self.pages[index]


class TestPrecedence:
    """Tests for `resolve`, the gateway's own matching order."""

    def test_a_literal_segment_beats_a_variable(self) -> None:
        """An explicit literal key wins over a `{var}` key that would also match."""
        keys = ["GET /api/users/{user_id}", "GET /api/users/me"]
        assert resolve("/api/users/me", "GET", keys) == "GET /api/users/me"

    def test_a_variable_beats_a_greedy_proxy(self) -> None:
        """A `{var}` key wins over a `{proxy+}` catch-all at the same depth."""
        keys = ["ANY /api/users/{proxy+}", "GET /api/users/{user_id}"]
        assert resolve("/api/users/42", "GET", keys) == "GET /api/users/{user_id}"

    def test_a_method_specific_key_beats_any(self) -> None:
        """A key naming the method wins over the `ANY` key for the same path."""
        keys = ["ANY /api/parts", "GET /api/parts"]
        assert resolve("/api/parts", "GET", keys) == "GET /api/parts"

    def test_any_serves_a_method_with_no_explicit_key(self) -> None:
        """`ANY` still serves a method no explicit key claims."""
        keys = ["ANY /api/parts", "GET /api/parts"]
        assert resolve("/api/parts", "DELETE", keys) == "ANY /api/parts"

    def test_a_longer_literal_prefix_wins(self) -> None:
        """The more specific of two matching literal prefixes is the one that serves."""
        keys = ["ANY /api/{proxy+}", "ANY /api/admin/{proxy+}"]
        assert resolve("/api/admin/stats", "GET", keys) == "ANY /api/admin/{proxy+}"

    def test_a_trailing_slash_matches_nothing(self) -> None:
        """A slashed path matches no unslashed key, which is the incident, not a normalisation.

        The gateway neither normalises an inbound slash nor accepts a key carrying one, so
        the request falls through to whatever catch-all exists and arrives with no
        authorizer claims.
        """
        keys = ["POST /api/build-lists"]
        assert resolve("/api/build-lists/", "POST", keys) == ""

    def test_a_trailing_slash_falls_through_to_a_catch_all(self) -> None:
        """With a catch-all present, the slashed path lands on it rather than on its own key."""
        keys = ["POST /api/build-lists", "ANY /api/{proxy+}"]
        assert resolve("/api/build-lists/", "POST", keys) == "ANY /api/{proxy+}"

    def test_an_unmatched_path_resolves_to_nothing(self) -> None:
        """A path no key claims resolves to the empty string, which is the gateway's 404."""
        assert resolve("/api/nothing", "GET", ["GET /api/parts"]) == ""

    def test_a_proxy_needs_at_least_one_segment(self) -> None:
        """`{proxy+}` is greedy but not empty, so the bare prefix does not match it."""
        assert resolve("/api/users", "GET", ["ANY /api/users/{proxy+}"]) == ""


class TestRouteKeyLegality:
    """Tests for `route_key_is_expressible`."""

    @pytest.mark.parametrize(
        "key",
        ["GET /api/parts", "ANY /api/users/{user_id}", "ANY /api/{proxy+}", "GET /"],
    )
    def test_legal_keys(self, key: str) -> None:
        """A key whose every path part is a whole literal or a whole variable is legal."""
        assert route_key_is_expressible(key)

    @pytest.mark.parametrize(
        "key",
        [
            "GET /sitemap-{name}.xml",
            "GET /api/build-lists/",
            "GET /api/{}/x",
            "GET api/parts",
        ],
    )
    def test_illegal_keys(self, key: str) -> None:
        """A variable embedded in a literal, or a trailing slash, is refused by the gateway.

        `GET /sitemap-{name}.xml` is the one that failed an apply after a green plan.
        """
        assert not route_key_is_expressible(key)


class TestOperationsFromOpenapi:
    """Tests for reading a deployed OpenAPI document into `Operation` records."""

    def test_reads_method_path_and_statuses(self) -> None:
        """Each operation carries its method, path and the statuses its own spec declares."""
        document = {
            "paths": {
                "/api/parts": {
                    "get": {"operationId": "list_parts", "responses": {"200": {}, "422": {}}},
                    "post": {"operationId": "create_part", "responses": {"201": {}}},
                }
            }
        }
        operations = operations_from_openapi(document)
        assert [op.label for op in operations] == ["GET /api/parts", "POST /api/parts"]
        assert operations[0].expected_statuses == (200, 422)
        assert operations[1].expected_statuses == (201,)

    def test_security_on_the_operation_marks_it_as_needing_auth(self) -> None:
        """An operation declaring a security requirement requires auth."""
        document = {"paths": {"/api/me": {"get": {"security": [{"bearer": []}], "responses": {"200": {}}}}}}
        assert operations_from_openapi(document)[0].requires_auth

    def test_document_level_security_applies_to_every_operation(self) -> None:
        """A document-level security requirement is inherited where an operation has none."""
        document = {
            "security": [{"bearer": []}],
            "paths": {"/api/me": {"get": {"responses": {"200": {}}}}},
        }
        assert operations_from_openapi(document)[0].requires_auth

    def test_an_operation_can_opt_out_of_document_security(self) -> None:
        """An empty `security` list on an operation overrides the document's."""
        document = {
            "security": [{"bearer": []}],
            "paths": {"/api/health": {"get": {"security": [], "responses": {"200": {}}}}},
        }
        assert not operations_from_openapi(document)[0].requires_auth

    def test_non_operation_keys_are_ignored(self) -> None:
        """`parameters` and `summary` siblings are not mistaken for operations."""
        document = {"paths": {"/api/parts": {"parameters": [], "summary": "x", "get": {"responses": {"200": {}}}}}}
        assert len(operations_from_openapi(document)) == 1

    def test_path_parameters_are_listed_in_order(self) -> None:
        """`path_parameters` names every placeholder the path carries."""
        document: dict[str, Any] = {"paths": {"/api/a/{x}/b/{y}": {"get": {"responses": {"200": {}}}}}}
        assert operations_from_openapi(document)[0].path_parameters == ("x", "y")


class TestMatchingRoute:
    """Tests for mapping one operation onto the live route that would serve it."""

    def test_an_operation_maps_to_its_own_explicit_key(self) -> None:
        """An operation with an explicit key maps to that key rather than to a catch-all."""
        operation = Operation("GET", "/api/parts", "list_parts", False, (200,))
        routes = [route("GET /api/parts"), route("ANY /api/{proxy+}")]
        matched = matching_route(operation, routes)
        assert matched is not None
        assert matched.route_key == "GET /api/parts"

    def test_a_path_parameter_maps_to_the_variable_key(self) -> None:
        """A templated path maps to the `{var}` key, with the placeholder filled in."""
        operation = Operation("GET", "/api/users/{user_id}", "read_user", False, (200,))
        routes = [route("GET /api/users/{user_id}")]
        matched = matching_route(operation, routes)
        assert matched is not None
        assert matched.route_key == "GET /api/users/{user_id}"

    def test_a_trailing_slash_operation_maps_to_the_catch_all(self) -> None:
        """A slashed operation path lands on the unflagged catch-all, not on its own key.

        This is exactly the failure that answered 401 to a valid token: the catch-all has no
        authorizer, so the request arrives with no claims.
        """
        operation = Operation("POST", "/api/build-lists/", "create", True, (201,))
        routes = [
            route("POST /api/build-lists", authorizer="auth1", auth_type="CUSTOM"),
            route("ANY /api/{proxy+}"),
        ]
        matched = matching_route(operation, routes)
        assert matched is not None
        assert matched.route_key == "ANY /api/{proxy+}"
        assert not matched.has_authorizer

    def test_an_operation_with_no_route_maps_to_none(self) -> None:
        """An operation the gateway routes nowhere maps to None, which is the unreachable case."""
        operation = Operation("GET", "/api/auth/passkeys", "passkeys", True, (200,))
        assert matching_route(operation, [route("GET /api/parts")]) is None


class TestAuthorizerExpectation:
    """Tests for `Route.has_authorizer`, which the coverage assertions compare against."""

    def test_an_authorizer_id_means_the_route_is_protected(self) -> None:
        """A route carrying an authorizer id runs one before its integration."""
        assert route("GET /api/me", authorizer="abc123", auth_type="CUSTOM").has_authorizer

    def test_a_jwt_authorization_type_means_protected(self) -> None:
        """A JWT authorization type counts even where the id is reported empty."""
        assert route("GET /api/me", auth_type="JWT").has_authorizer

    def test_no_authorizer_and_none_type_means_open(self) -> None:
        """A route with neither is open, which a protected operation must not land on."""
        assert not route("GET /api/health").has_authorizer


class TestFetchRoutes:
    """Tests for reading the live route list, paging included."""

    def test_pages_until_the_token_runs_out(self) -> None:
        """Every page is read, because a partial list would weaken every derived assertion."""
        client = FakeApiGateway(
            [
                {
                    "Items": [{"RouteKey": "GET /b", "Target": "integrations/1"}],
                    "NextToken": "1",
                },
                {
                    "Items": [
                        {
                            "RouteKey": "GET /a",
                            "Target": "integrations/2",
                            "AuthorizerId": "auth1",
                            "AuthorizationType": "CUSTOM",
                        }
                    ]
                },
            ]
        )
        routes = fetch_routes(client, "api123")
        assert [r.route_key for r in routes] == ["GET /a", "GET /b"]
        assert routes[0].has_authorizer
        assert len(client.calls) == 2
        assert client.calls[0]["ApiId"] == "api123"

    def test_an_empty_api_yields_no_routes(self) -> None:
        """An API with no routes yields an empty tuple for the fixture to refuse on."""
        assert fetch_routes(FakeApiGateway([{"Items": []}]), "api123") == ()


class TestBareMutation:
    """`Operation.is_bare_mutation` names the calls an authenticated probe must not make."""

    def test_a_parameterless_post_is_a_bare_mutation(self) -> None:
        """Logout has no id to point at an absent record, so a real call would sign out."""
        operation = Operation("POST", "/api/auth/logout", "logout", True, (200,))
        assert operation.is_bare_mutation

    def test_a_parameterised_delete_is_not(self) -> None:
        """A templated path is filled with an absent id, so the call cannot land."""
        operation = Operation("DELETE", "/api/build-lists/{build_list_id}", "delete", True, (204,))
        assert not operation.is_bare_mutation

    def test_a_get_is_never_a_bare_mutation(self) -> None:
        """Reads change nothing, whatever their path."""
        operation = Operation("GET", "/api/users/me", "me", True, (200,))
        assert not operation.is_bare_mutation


GATE_ID = "p5vo7t"
IDENTITY_ID = "jwt123"

GATE = Authorizer(authorizer_id=GATE_ID, name="webbpulse-staging-access-gate-origin-verify", kind="REQUEST")
IDENTITY = Authorizer(authorizer_id=IDENTITY_ID, name="webbpulse-production-identity-jwt", kind="JWT")


def gated(key: str) -> Route:
    """A route behind the staging access gate alone, which is what staging deploys."""
    return route(key, authorizer=GATE_ID, auth_type="CUSTOM")


def identity_protected(key: str) -> Route:
    """A route behind the identity JWT authorizer, which is what production deploys."""
    return route(key, authorizer=IDENTITY_ID, auth_type="JWT")


def public(key: str) -> Route:
    """A route carrying no authorizer at all."""
    return route(key, auth_type="NONE")


class TestGateRecognition:
    """The access gate is told apart from an identity authorizer by the API's own configuration.

    `modules/staging-access-gate` always names its authorizer
    `<prefix>-access-gate-origin-verify` and always declares it REQUEST, so the pair
    identifies the gate with no new environment variable. Type alone would not: a product
    may protect a route with a Lambda authorizer of its own.
    """

    def test_the_gate_authorizer_is_recognised(self) -> None:
        """A REQUEST authorizer with the module's naming is the gate."""
        assert GATE.is_gate

    def test_a_jwt_authorizer_is_not_the_gate(self) -> None:
        """The identity JWT authorizer is never the gate."""
        assert not IDENTITY.is_gate

    def test_a_products_own_request_authorizer_is_not_the_gate(self) -> None:
        """A REQUEST authorizer that is not named for the gate is left alone."""
        other = Authorizer(authorizer_id="own", name="carmodpicker-staging-custom-auth", kind="REQUEST")
        assert not other.is_gate

    def test_a_jwt_authorizer_named_like_the_gate_is_not_the_gate(self) -> None:
        """Name alone does not make a gate; the type has to be REQUEST too."""
        impostor = Authorizer(authorizer_id="x", name="webbpulse-staging-access-gate-origin-verify", kind="JWT")
        assert not impostor.is_gate

    def test_gate_ids_are_collected(self) -> None:
        """Only the gate authorizers' ids come back."""
        assert gate_authorizer_ids([GATE, IDENTITY]) == frozenset({GATE_ID})

    def test_production_has_no_gate_ids(self) -> None:
        """An API with only an identity authorizer yields no gate ids."""
        assert gate_authorizer_ids([IDENTITY]) == frozenset()


class TestGatedStagingApi:
    """The Portfolio and CarModPicker staging shape: one REQUEST gate authorizer on every route.

    Both staging APIs carry exactly one authorizer, the gate, attached as CUSTOM to every
    route the http-api module creates including deliberately public ones. `identity_jwt` is
    null there, so the gate's own Lambda verifies the identity token and no route carries a
    separate identity authorizer.
    """

    def test_the_gate_is_not_identity_authorization(self) -> None:
        """A public route behind the gate does not count as requiring identity."""
        gate_ids = gate_authorizer_ids([GATE])
        assert not route_requires_identity(gated("GET /health"), gate_ids)

    def test_every_gated_route_reads_the_same_way(self) -> None:
        """A protected route and a public one are indistinguishable when only the gate is on."""
        gate_ids = gate_authorizer_ids([GATE])
        routes = [gated("GET /health"), gated("POST /api/auth/login"), gated("ANY /api/v1/admin")]
        assert not any(route_requires_identity(item, gate_ids) for item in routes)

    def test_identity_authorization_is_not_observable(self) -> None:
        """With only the gate deployed, the route table cannot say which routes need a token."""
        gate_ids = gate_authorizer_ids([GATE])
        routes = [gated("GET /health"), gated("ANY /api/v1/admin")]
        assert not identity_authorization_is_observable(routes, gate_ids)

    def test_an_explicitly_open_route_is_still_not_identity(self) -> None:
        """The two NONE routes Portfolio staging carries stay unprotected."""
        gate_ids = gate_authorizer_ids([GATE])
        assert not route_requires_identity(public("GET /api/auth/.well-known/jwks.json"), gate_ids)


class TestProductionApi:
    """The production shape: a JWT identity authorizer on the routes that need one, no gate."""

    def test_a_jwt_route_requires_identity(self) -> None:
        """A route behind the identity JWT authorizer requires identity."""
        gate_ids = gate_authorizer_ids([IDENTITY])
        assert route_requires_identity(identity_protected("ANY /api/v1/admin"), gate_ids)

    def test_an_unflagged_route_does_not(self) -> None:
        """A NONE route requires no identity."""
        gate_ids = gate_authorizer_ids([IDENTITY])
        assert not route_requires_identity(public("GET /health"), gate_ids)

    def test_identity_authorization_is_observable(self) -> None:
        """With a real identity authorizer attached, the structural check means something."""
        gate_ids = gate_authorizer_ids([IDENTITY])
        routes = [public("GET /health"), identity_protected("ANY /api/v1/admin")]
        assert identity_authorization_is_observable(routes, gate_ids)

    def test_identity_is_observable_alongside_the_gate(self) -> None:
        """A gated API that also attaches an identity authorizer is still checkable."""
        gate_ids = gate_authorizer_ids([GATE, IDENTITY])
        routes = [gated("GET /health"), identity_protected("ANY /api/v1/admin")]
        assert identity_authorization_is_observable(routes, gate_ids)
        assert not route_requires_identity(routes[0], gate_ids)
        assert route_requires_identity(routes[1], gate_ids)


class TestFetchAuthorizers:
    """`get-authorizers` is paged by hand, since botocore ships no paginator for it."""

    def test_every_page_is_read(self) -> None:
        """An authorizer on the second page is not lost."""
        client = FakeApiGateway(
            [
                {
                    "Items": [
                        {"AuthorizerId": GATE_ID, "Name": GATE.name, "AuthorizerType": "REQUEST"},
                    ],
                    "NextToken": "1",
                },
                {
                    "Items": [
                        {"AuthorizerId": IDENTITY_ID, "Name": IDENTITY.name, "AuthorizerType": "JWT"},
                    ]
                },
            ]
        )
        authorizers = fetch_authorizers(client, "api-1")
        assert len(authorizers) == 2
        assert gate_authorizer_ids(authorizers) == frozenset({GATE_ID})

    def test_an_api_with_no_authorizers_is_empty(self) -> None:
        """An API declaring no authorizer yields no gate ids rather than raising."""
        client = FakeApiGateway([{"Items": []}])
        assert fetch_authorizers(client, "api-1") == ()
        assert gate_authorizer_ids(fetch_authorizers(client, "api-1")) == frozenset()
