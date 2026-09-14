"""Tests for the `local` environment kind: a stack built from source, with no AWS at all.

A local run drives one composed FastAPI app, DynamoDB Local and a vite preview server on a
CI runner. It has no API Gateway, no CloudWatch access log, no access gate and no KMS key,
so the contract is that nothing on that path reads an `E2E_*` variable it cannot have and
nothing on it constructs an AWS client. The last of those is asserted by monkeypatching
boto3 to raise, because a fixture that quietly builds a session is exactly the regression
that would make the check fail on a runner with no credentials.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from webbpulse.e2e import (
    LOCAL_ACCESS_LOG_REASON,
    LOCAL_GATEWAY_REASON,
    E2EEnvironment,
    MissingEnvironment,
    access_log,
    gate_headers,
    gateway_authorizers,
)
from webbpulse.e2e.gateway import (
    LOCAL_AUTHORIZER_ID,
    LOCAL_TARGET,
    Route,
    operations_from_openapi,
    routes_from_openapi,
)

pytest_plugins = ["pytester"]

LOCAL = {
    "E2E_ENVIRONMENT": "local",
    "E2E_API_BASE_URL": "http://127.0.0.1:8000",
    "E2E_WEB_BASE_URL": "http://127.0.0.1:4173",
    "E2E_AWS_REGION": "us-west-2",
    "E2E_RUN_ID": "1234567890-1",
    "E2E_USER_EMAIL": "e2e@example.invalid",
    "E2E_USER_PASSWORD": "not-a-real-password",
    "E2E_BROWSER": "chromium",
    "E2E_HEADLESS": "true",
    "E2E_READ_ONLY": "false",
}

DOCUMENT: Mapping[str, Any] = {
    "paths": {
        "/api/health": {"get": {"operationId": "health", "responses": {"200": {}}}},
        "/api/items": {
            "get": {"operationId": "list_items", "responses": {"200": {}}},
            "post": {
                "operationId": "create_item",
                "security": [{"bearer": []}],
                "responses": {"201": {}},
            },
        },
        "/api/items/{item_id}": {
            "delete": {
                "operationId": "delete_item",
                "security": [{"bearer": []}],
                "responses": {"204": {}, "404": {}},
            }
        },
    }
}


class ExplodingBoto3:
    """A boto3 stand-in that raises on any use, so a hidden AWS call is a loud failure."""

    class session:
        """The `boto3.session` namespace, whose `Session` refuses to be constructed."""

        @staticmethod
        def Session(**kwargs: Any) -> Any:
            """Refuse, naming the contract that was broken."""
            raise AssertionError(f"a boto3 session was constructed on the local path with {sorted(kwargs)}")

    @staticmethod
    def client(*args: Any, **kwargs: Any) -> Any:
        """Refuse, naming the contract that was broken."""
        raise AssertionError(f"a boto3 client was constructed on the local path: {args}")


class Recorder:
    """A `pytest.FixtureRequest` stand-in recording which fixtures were pulled lazily."""

    def __init__(self, **values: Any) -> None:
        """Hold the fixtures this request can hand out, and what was asked for."""
        self.values = values
        self.asked: list[str] = []

    def getfixturevalue(self, name: str) -> Any:
        """Record the fixture asked for and hand it back, or fail when there is none."""
        self.asked.append(name)
        if name not in self.values:
            raise AssertionError(f"the local path asked for the {name} fixture, which it must not need")
        return self.values[name]


class TestEnvironmentParsing:
    """Tests for reading a local environment out of the variables the workflow sets."""

    def test_the_workflow_contract_parses(self) -> None:
        """Exactly what `e2e-local.yml` exports, and nothing more, is enough."""
        env = E2EEnvironment.from_environ(LOCAL)
        assert env.is_local
        assert env.api_base_url == "http://127.0.0.1:8000"
        assert env.web_base_url == "http://127.0.0.1:4173"
        assert env.run_id == "1234567890-1"

    def test_the_gateway_variables_are_not_required(self) -> None:
        """A local stack has no API Gateway and no access log, so neither is named."""
        env = E2EEnvironment.from_environ(LOCAL)
        assert env.api_id == ""
        assert env.access_log_group == ""

    def test_they_are_still_required_everywhere_else(self) -> None:
        """The conditional must not weaken the staging and production parse."""
        with pytest.raises(MissingEnvironment) as error:
            E2EEnvironment.from_environ({**LOCAL, "E2E_ENVIRONMENT": "staging"})
        assert "E2E_API_ID" in str(error.value)
        assert "E2E_ACCESS_LOG_GROUP" in str(error.value)

    def test_a_missing_base_url_is_still_refused(self) -> None:
        """Dropping two names from the required set must not drop the rest of them."""
        incomplete = {key: value for key, value in LOCAL.items() if key != "E2E_API_BASE_URL"}
        with pytest.raises(MissingEnvironment, match="E2E_API_BASE_URL"):
            E2EEnvironment.from_environ(incomplete)

    def test_the_user_is_still_required(self) -> None:
        """The product seeds a durable local user, so the run signs in as somebody."""
        incomplete = {key: value for key, value in LOCAL.items() if key != "E2E_USER_PASSWORD"}
        with pytest.raises(MissingEnvironment, match="E2E_USER_PASSWORD"):
            E2EEnvironment.from_environ(incomplete)

    def test_it_signs_in(self) -> None:
        """`E2E_READ_ONLY` is false, so the local run has a session like staging does."""
        assert E2EEnvironment.from_environ(LOCAL).signs_in

    def test_read_only_is_still_governed_by_its_own_variable(self) -> None:
        """Local says nothing about read-only; the flag alone does."""
        env = E2EEnvironment.from_environ({**LOCAL, "E2E_READ_ONLY": "true"})
        assert env.read_only
        assert not env.signs_in

    def test_it_is_not_rate_limited(self) -> None:
        """One runner is one source IP bucket, so the limiter paces nothing worth pacing."""
        assert not E2EEnvironment.from_environ(LOCAL).rate_limited

    def test_minting_is_disabled_even_if_the_flag_is_set(self) -> None:
        """There is no KMS key locally, so the flag cannot turn minting on by accident."""
        env = E2EEnvironment.from_environ({**LOCAL, "E2E_MINT_ENABLED": "true"})
        assert not env.mint_enabled

    def test_enabling_minting_locally_asks_for_no_kms_variables(self) -> None:
        """Minting off means the KMS names are not required, so the parse still succeeds."""
        assert E2EEnvironment.from_environ({**LOCAL, "E2E_MINT_ENABLED": "true"}).kms_key_id == ""

    def test_it_has_no_web_gate(self) -> None:
        """The staging gate cookies have nothing to sign for on a local stack."""
        env = E2EEnvironment.from_environ(LOCAL)
        assert not env.has_web_gate
        assert env.gate_ssm_parameter == ""

    def test_staging_and_production_are_not_local(self) -> None:
        """`is_local` keys on the environment name alone, so nothing else claims it."""
        complete = {**LOCAL, "E2E_API_ID": "abc123", "E2E_ACCESS_LOG_GROUP": "/aws/apigateway/example"}
        assert not E2EEnvironment.from_environ({**complete, "E2E_ENVIRONMENT": "staging"}).is_local
        assert not E2EEnvironment.from_environ({**complete, "E2E_ENVIRONMENT": "production"}).is_local


class TestRouteSynthesis:
    """Tests for the route table a local run derives from the product's OpenAPI document."""

    def test_one_route_per_declared_operation(self) -> None:
        """Every operation gets a key, so the parametrised cases keep their shape."""
        routes = routes_from_openapi(DOCUMENT)
        assert [route.route_key for route in routes] == [
            "DELETE /api/items/{item_id}",
            "GET /api/health",
            "GET /api/items",
            "POST /api/items",
        ]

    def test_every_route_declares_an_integration_target(self) -> None:
        """The route cut case asserts a target, and in process is still a target."""
        assert all(route.target == LOCAL_TARGET for route in routes_from_openapi(DOCUMENT))

    def test_a_protected_operation_gets_an_authorizer(self) -> None:
        """The authorizer flag comes from the operation's own declared security."""
        by_key = {route.route_key: route for route in routes_from_openapi(DOCUMENT)}
        assert by_key["POST /api/items"].authorizer_id == LOCAL_AUTHORIZER_ID
        assert by_key["POST /api/items"].has_authorizer

    def test_a_public_operation_gets_none(self) -> None:
        """An operation declaring no security must not look protected."""
        by_key = {route.route_key: route for route in routes_from_openapi(DOCUMENT)}
        assert by_key["GET /api/health"].authorizer_id == ""
        assert not by_key["GET /api/health"].has_authorizer

    def test_every_operation_resolves_to_one_of_them(self) -> None:
        """This is what makes the degraded coverage group pass: the document against itself."""
        from webbpulse.e2e.gateway import matching_route

        routes = routes_from_openapi(DOCUMENT)
        for operation in operations_from_openapi(DOCUMENT):
            assert matching_route(operation, routes) is not None, operation.label

    def test_every_synthesized_key_is_expressible(self) -> None:
        """A synthesized table must not trip the route cut group's own legality rule."""
        from webbpulse.e2e.gateway import route_key_is_expressible

        assert all(route_key_is_expressible(route.route_key) for route in routes_from_openapi(DOCUMENT))

    def test_an_empty_document_synthesizes_nothing(self) -> None:
        """No operations means no routes, which the operations fixture reports separately."""
        assert routes_from_openapi({"paths": {}}) == ()

    def test_the_synthesized_routes_are_plain_routes(self) -> None:
        """Everything downstream takes `Route`, so nothing has to learn a local shape."""
        assert all(isinstance(route, Route) for route in routes_from_openapi(DOCUMENT))


class TestFixturesMakeNoAwsCall:
    """Tests that the local path builds no AWS client, asserted against an exploding boto3."""

    def test_gate_headers_yields_an_empty_mapping(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """No gate locally, and no SSM read to find that out."""
        monkeypatch.setitem(__import__("sys").modules, "boto3", ExplodingBoto3)
        request = Recorder()
        headers = gate_headers.__wrapped__(E2EEnvironment.from_environ(LOCAL), request)  # type: ignore[attr-defined]
        assert headers == {}
        assert request.asked == []

    def test_gate_headers_still_fails_an_ungated_staging_run(self) -> None:
        """The local exemption must not swallow the staging misconfiguration it guards."""
        staging = {**LOCAL, "E2E_ENVIRONMENT": "staging", "E2E_API_ID": "a", "E2E_ACCESS_LOG_GROUP": "/g"}
        with pytest.raises(BaseException, match="E2E_GATE_SSM_PARAMETER"):
            gate_headers.__wrapped__(E2EEnvironment.from_environ(staging), Recorder())  # type: ignore[attr-defined]

    def test_gateway_authorizers_is_empty(self) -> None:
        """A local stack has no authorizers, and asks for no client to say so."""
        request = Recorder()
        assert gateway_authorizers.__wrapped__(E2EEnvironment.from_environ(LOCAL), request) == ()  # type: ignore[attr-defined]
        assert request.asked == []

    def test_the_access_log_skips_rather_than_building_a_logs_client(self) -> None:
        """Every case needing it is skipped already; this is the backstop for a product case."""
        with pytest.raises(BaseException, match="gateway only"):
            access_log.__wrapped__(E2EEnvironment.from_environ(LOCAL), Recorder())  # type: ignore[attr-defined]

    def test_the_access_log_reason_says_it_runs_post_deploy(self) -> None:
        """A silent skip reads as a pass, so the reason has to say which run covers it."""
        assert "post deploy" in LOCAL_ACCESS_LOG_REASON

    def test_collection_inputs_imports_no_boto3(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The one place that used to call `apigatewayv2 get-routes` at collection time."""
        import sys

        from webbpulse.e2e.suite import CollectionInputs

        monkeypatch.setitem(sys.modules, "boto3", ExplodingBoto3)
        for name, value in LOCAL.items():
            monkeypatch.setenv(name, value)

        class Conftest:
            """A stand-in for the product conftest's module level document builder."""

            @staticmethod
            def e2e_openapi_document() -> Mapping[str, Any]:
                """The document a local backend serves, read in process."""
                return DOCUMENT

        class Manager:
            """A plugin manager stand-in holding just the one plugin collection reads."""

            @staticmethod
            def get_plugins() -> tuple[Any, ...]:
                """The registered plugins, which is only the conftest here."""
                return (Conftest,)

        class Config:
            """A `pytest.Config` stand-in exposing only the plugin manager."""

            pluginmanager = Manager

        inputs = CollectionInputs(Config)  # type: ignore[arg-type]
        assert len(inputs.routes) == 4
        assert len(inputs.operations) == 4


LOCAL_CONFTEST = """
import os

for _name, _value in {environment}.items():
    os.environ[_name] = _value

for _name in ("E2E_API_ID", "E2E_ACCESS_LOG_GROUP", "E2E_GATE_SSM_PARAMETER", "E2E_MINT_ENABLED"):
    if _name not in {environment}:
        os.environ.pop(_name, None)

pytest_plugins = ["webbpulse.e2e"]
"""

GROUP_CASES = """
class TestRouteCut:
    def test_route_key_is_expressible(self):
        assert True

    def test_access_log_names_this_route_key(self):
        assert True


class TestCoverage:
    def test_operation_resolves_to_a_live_route(self):
        assert True

    def test_authorizer_matches_the_operation(self):
        assert True


class TestReachability:
    def test_anonymous_call_is_answered_by_the_api(self):
        assert True


class TestFrontend:
    def test_web_origin_serves_the_app_shell(self):
        assert True


class TestHygiene:
    def test_cleanup_hook_is_registered(self):
        assert True


def test_a_product_case_of_its_own():
    assert True
"""


def _outcomes(result: pytest.RunResult) -> dict[str, str]:
    """Each case's name mapped to its outcome, read out of a verbose run."""
    outcomes: dict[str, str] = {}
    for line in result.outlines:
        for outcome in ("PASSED", "SKIPPED", "FAILED"):
            if f" {outcome}" not in line or "::" not in line:
                continue
            outcomes[line.split("::")[-1].split(" ")[0]] = outcome
            break
    return outcomes


class TestGroupSkipping:
    """Tests for which groups a local run runs, skips and degrades, through a real session."""

    def _run(self, pytester: pytest.Pytester, environment: Mapping[str, str]) -> pytest.RunResult:
        """Run one pytester session with the given environment block applied."""
        pytester.makeconftest(LOCAL_CONFTEST.replace("{environment}", repr(dict(environment))))
        pytester.makepyfile(test_cases=GROUP_CASES)
        return pytester.runpytest_inprocess("-p", "no:cacheprovider", "-v")

    def test_the_route_cut_group_is_skipped_whole(self, pytester: pytest.Pytester) -> None:
        """Nothing local forwards a request context or writes an access log entry."""
        outcomes = _outcomes(self._run(pytester, LOCAL))
        assert outcomes["test_route_key_is_expressible"] == "SKIPPED"
        assert outcomes["test_access_log_names_this_route_key"] == "SKIPPED"

    def test_coverage_runs_degraded(self, pytester: pytest.Pytester) -> None:
        """Route resolution runs against the synthesized table; the authorizer case does not."""
        outcomes = _outcomes(self._run(pytester, LOCAL))
        assert outcomes["test_operation_resolves_to_a_live_route"] == "PASSED"
        assert outcomes["test_authorizer_matches_the_operation"] == "SKIPPED"

    def test_the_value_carrying_groups_run(self, pytester: pytest.Pytester) -> None:
        """Reachability, frontend and hygiene are the point of a local run."""
        outcomes = _outcomes(self._run(pytester, LOCAL))
        assert outcomes["test_anonymous_call_is_answered_by_the_api"] == "PASSED"
        assert outcomes["test_web_origin_serves_the_app_shell"] == "PASSED"
        assert outcomes["test_cleanup_hook_is_registered"] == "PASSED"

    def test_a_product_case_is_never_touched(self, pytester: pytest.Pytester) -> None:
        """The skip matches the plugin's own group names, so a product case is unaffected."""
        assert _outcomes(self._run(pytester, LOCAL))["test_a_product_case_of_its_own"] == "PASSED"

    def test_the_skip_reasons_say_they_run_post_deploy(self, pytester: pytest.Pytester) -> None:
        """A skip that does not say which run covers it reads as a pass."""
        pytester.makeconftest(LOCAL_CONFTEST.replace("{environment}", repr(dict(LOCAL))))
        pytester.makepyfile(test_cases=GROUP_CASES)
        result = pytester.runpytest_inprocess("-p", "no:cacheprovider", "-rs")
        result.stdout.fnmatch_lines([f"*{LOCAL_GATEWAY_REASON}*"])

    def test_nothing_is_skipped_on_staging(self, pytester: pytest.Pytester) -> None:
        """The branch keys on the environment name, so staging keeps every group."""
        staging = {
            **LOCAL,
            "E2E_ENVIRONMENT": "staging",
            "E2E_API_ID": "abc123",
            "E2E_ACCESS_LOG_GROUP": "/aws/apigateway/example",
        }
        outcomes = _outcomes(self._run(pytester, staging))
        assert set(outcomes.values()) == {"PASSED"}
