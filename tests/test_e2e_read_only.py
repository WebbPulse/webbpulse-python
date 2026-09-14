"""Tests for the anonymous read-only mode a production run uses.

Production has no durable e2e user, so after a production deploy only an anonymous smoke
runs. The mode is enforced in one place, a collection hook keyed on the `e2e_writes` marker,
so a product cannot ship a mutating case that runs in production by forgetting a
conditional. These run a real pytest session through `pytester`, because what is worth
asserting is what a whole session does rather than what one function returns.
"""

from __future__ import annotations

import pytest

from webbpulse.e2e import READ_ONLY_REASON, WRITES_MARKER

pytest_plugins = ["pytester"]

READ_ONLY_ENVIRONMENT = """
import os

for _name, _value in {
    "E2E_ENVIRONMENT": "production",
    "E2E_API_BASE_URL": "https://api.example.invalid",
    "E2E_WEB_BASE_URL": "https://www.example.invalid",
    "E2E_AWS_REGION": "us-west-2",
    "E2E_API_ID": "prod123",
    "E2E_ACCESS_LOG_GROUP": "/aws/apigateway/example",
    "E2E_RUN_ID": "run1",
    "E2E_READ_ONLY": "true",
}.items():
    os.environ[_name] = _value

for _name in ("E2E_USER_EMAIL", "E2E_USER_PASSWORD"):
    os.environ.pop(_name, None)
"""

SIGNED_IN_ENVIRONMENT = """
import os

for _name, _value in {
    "E2E_ENVIRONMENT": "staging",
    "E2E_API_BASE_URL": "https://api.staging.example.invalid",
    "E2E_WEB_BASE_URL": "https://www.staging.example.invalid",
    "E2E_AWS_REGION": "us-west-2",
    "E2E_API_ID": "abc123",
    "E2E_ACCESS_LOG_GROUP": "/aws/apigateway/example",
    "E2E_USER_EMAIL": "e2e@example.invalid",
    "E2E_USER_PASSWORD": "unused",
    "E2E_RUN_ID": "run1",
}.items():
    os.environ[_name] = _value

os.environ.pop("E2E_READ_ONLY", None)
"""

MARKED_CASES = """
import pytest


@pytest.mark.e2e_writes
def test_it_writes():
    assert True


def test_it_only_reads():
    assert True
"""

ROUTE_CONFTEST = """
pytest_plugins = ["webbpulse.e2e"]

{environment}

from webbpulse.e2e import Goto, Journey, Record, RouteSpec


def pytest_e2e_routes(env):
    'Two public routes and one protected.'
    return [
        RouteSpec(path="/", access="public"),
        RouteSpec(path="/about", access="public"),
        RouteSpec(path="/garage", access="protected"),
    ]


def pytest_e2e_journeys(env):
    'One anonymous read-only journey, one signed in, one mutating.'
    return [
        Journey(name="browse", steps=[Goto("/")], signed_in=False),
        Journey(name="dashboard", steps=[Goto("/garage")], signed_in=True),
        Journey(
            name="create",
            steps=[Goto("/new"), Record("e2e-thing")],
            signed_in=False,
            mutates=True,
        ),
    ]
"""

ROUTE_CASES = """
from webbpulse.e2e.suite import pytest_generate_tests  # noqa: F401


def test_routes(declared_route):
    assert declared_route is not None


def test_journeys(journey):
    assert journey.name
"""

CLEANUP_CONFTEST = """
pytest_plugins = ["webbpulse.e2e"]

{environment}

import pathlib


def pytest_e2e_cleanup(env, phase, created):
    'Record that the hook ran, so the test can assert it did not.'
    pathlib.Path("cleanup.log").open("a").write(phase + "\\n")
    return []
"""

CLEANUP_CASES = """
def test_anything():
    assert True
"""


def conftest_for(template: str, environment: str) -> str:
    """One pytester conftest with the chosen environment block spliced in."""
    return template.replace("{environment}", environment)


def _outcomes_by_id(result: pytest.RunResult) -> dict[str, str]:
    """Each parametrised case's id mapped to its outcome, from a verbose run's output."""
    outcomes: dict[str, str] = {}
    for line in result.outlines:
        for outcome in ("PASSED", "SKIPPED", "FAILED"):
            if f" {outcome}" not in line or "::" not in line:
                continue
            node = line.split("::")[-1].split(" ")[0]
            outcomes[node] = outcome
            break
    return outcomes


class TestTheMarker:
    """Tests for the `e2e_writes` marker and the single collection hook that acts on it."""

    def test_the_marker_name_is_the_documented_one(self) -> None:
        """Products mark their own mutating cases with it, so the name is part of the contract."""
        assert WRITES_MARKER == "e2e_writes"

    def test_a_marked_case_is_skipped_in_read_only_mode(self, pytester: pytest.Pytester) -> None:
        """This is the whole mechanism: one marker, one hook, every mutating case skipped."""
        pytester.makeconftest(f'pytest_plugins = ["webbpulse.e2e"]\n{READ_ONLY_ENVIRONMENT}')
        pytester.makepyfile(test_cases=MARKED_CASES)
        result = pytester.runpytest_inprocess("-p", "no:cacheprovider")
        result.assert_outcomes(passed=1, skipped=1)

    def test_the_skip_reason_names_the_mode(self, pytester: pytest.Pytester) -> None:
        """A skipped production case must say why, not read as a mystery."""
        pytester.makeconftest(f'pytest_plugins = ["webbpulse.e2e"]\n{READ_ONLY_ENVIRONMENT}')
        pytester.makepyfile(test_cases=MARKED_CASES)
        result = pytester.runpytest_inprocess("-p", "no:cacheprovider", "-rs")
        result.stdout.fnmatch_lines(["*E2E_READ_ONLY*"])

    def test_a_marked_case_runs_when_the_flag_is_unset(self, pytester: pytest.Pytester) -> None:
        """Staging runs the full suite, so the marker must be inert there."""
        pytester.makeconftest(f'pytest_plugins = ["webbpulse.e2e"]\n{SIGNED_IN_ENVIRONMENT}')
        pytester.makepyfile(test_cases=MARKED_CASES)
        result = pytester.runpytest_inprocess("-p", "no:cacheprovider")
        result.assert_outcomes(passed=2)

    def test_the_marker_is_registered_so_strict_markers_accepts_it(self, pytester: pytest.Pytester) -> None:
        """The suite runs under `--strict-markers`, which refuses an unregistered marker."""
        pytester.makeconftest(f'pytest_plugins = ["webbpulse.e2e"]\n{SIGNED_IN_ENVIRONMENT}')
        pytester.makepyfile(test_cases=MARKED_CASES)
        result = pytester.runpytest_inprocess("-p", "no:cacheprovider", "--strict-markers")
        result.assert_outcomes(passed=2)

    def test_the_reason_is_one_shared_string(self) -> None:
        """Every skip in the mode reads the same, from one constant."""
        assert "E2E_READ_ONLY" in READ_ONLY_REASON
        assert "read-only" in READ_ONLY_REASON


class TestParametrisedCases:
    """Tests for the browser cases, which are skipped per parameter rather than per test."""

    def test_read_only_keeps_the_anonymous_cases_and_skips_the_rest(self, pytester: pytest.Pytester) -> None:
        """Exactly the public routes and the anonymous non-mutating journey survive.

        Asserted by parameter id rather than by count, because a count agrees with the wrong
        three parameters as readily as with the right ones.
        """
        pytester.makeconftest(conftest_for(ROUTE_CONFTEST, READ_ONLY_ENVIRONMENT))
        pytester.makepyfile(test_cases=ROUTE_CASES)
        result = pytester.runpytest_inprocess("-p", "no:cacheprovider", "-v")
        assert _outcomes_by_id(result) == {
            "test_routes[public:/]": "PASSED",
            "test_routes[public:/about]": "PASSED",
            "test_routes[protected:/garage]": "SKIPPED",
            "test_journeys[browse]": "PASSED",
            "test_journeys[dashboard]": "SKIPPED",
            "test_journeys[create]": "SKIPPED",
        }

    def test_every_parameter_runs_when_the_flag_is_unset(self, pytester: pytest.Pytester) -> None:
        """Staging keeps every route and every journey."""
        pytester.makeconftest(conftest_for(ROUTE_CONFTEST, SIGNED_IN_ENVIRONMENT))
        pytester.makepyfile(test_cases=ROUTE_CASES)
        result = pytester.runpytest_inprocess("-p", "no:cacheprovider")
        result.assert_outcomes(passed=6)

    def test_a_mutating_journey_is_skipped_even_when_anonymous(self, pytester: pytest.Pytester) -> None:
        """`mutates=True` is enough on its own; a journey need not be signed in to write."""
        pytester.makeconftest(conftest_for(ROUTE_CONFTEST, READ_ONLY_ENVIRONMENT))
        pytester.makepyfile(test_cases=ROUTE_CASES)
        result = pytester.runpytest_inprocess("-p", "no:cacheprovider", "-v")
        assert _outcomes_by_id(result)["test_journeys[create]"] == "SKIPPED"


class TestCleanup:
    """Tests for the cleanup hook, which a read-only run must not invoke."""

    def test_the_cleanup_hook_is_not_invoked_in_read_only_mode(self, pytester: pytest.Pytester) -> None:
        """The start sweep deletes resources, which is what a read-only run must never do."""
        pytester.makeconftest(conftest_for(CLEANUP_CONFTEST, READ_ONLY_ENVIRONMENT))
        pytester.makepyfile(test_cases=CLEANUP_CASES)
        pytester.runpytest_inprocess("-p", "no:cacheprovider")
        assert not (pytester.path / "cleanup.log").exists()

    def test_the_cleanup_hook_runs_both_phases_otherwise(self, pytester: pytest.Pytester) -> None:
        """Staging still sweeps at the start and deletes what it created at the end."""
        pytester.makeconftest(conftest_for(CLEANUP_CONFTEST, SIGNED_IN_ENVIRONMENT))
        pytester.makepyfile(test_cases=CLEANUP_CASES)
        pytester.runpytest_inprocess("-p", "no:cacheprovider")
        phases = (pytester.path / "cleanup.log").read_text().split()
        assert phases == ["start", "end"]


class TestUserSessionBackstop:
    """Tests for the fixture that can only skip in read-only mode, never sign in."""

    def test_an_unmarked_case_needing_a_session_skips_rather_than_signing_in(self, pytester: pytest.Pytester) -> None:
        """A product case that forgot the marker must not attempt a login with no credential."""
        pytester.makeconftest(f'pytest_plugins = ["webbpulse.e2e"]\n{READ_ONLY_ENVIRONMENT}')
        pytester.makepyfile(
            test_cases="""
def test_forgot_the_marker(user_session):
    assert user_session is not None
"""
        )
        result = pytester.runpytest_inprocess("-p", "no:cacheprovider")
        result.assert_outcomes(skipped=1)
