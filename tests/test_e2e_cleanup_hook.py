"""Tests for the `pytest_e2e_cleanup` hook, run through a real pytest session.

The ordering is the whole contract: the sweep runs once before any test, so a previous run
that died mid-way does not leave its resources colliding with this one, and once after them
all with what this run created. Both are checked in-process through `pytester` rather than by
calling the fixture by hand, because the ordering is pytest's to enforce and not the
plugin's to assert about itself.
"""

from __future__ import annotations

import pytest

pytest_plugins = ["pytester"]

E2E_NAMES = (
    "E2E_ENVIRONMENT",
    "E2E_API_BASE_URL",
    "E2E_WEB_BASE_URL",
    "E2E_AWS_REGION",
    "E2E_API_ID",
    "E2E_ACCESS_LOG_GROUP",
    "E2E_USER_EMAIL",
    "E2E_USER_PASSWORD",
    "E2E_RUN_ID",
)


@pytest.fixture(autouse=True)
def _isolate_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear every `E2E_*` variable around each test.

    The inner sessions run in this process and set the variables in their own conftest, so
    without this a value one test set would still be there for the next, and the refusal
    test would find a fully configured environment.
    """
    for name in E2E_NAMES:
        monkeypatch.delenv(name, raising=False)


ENVIRONMENT = """
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
"""


def conftest_with(hook_body: str) -> str:
    """A product conftest enabling the plugin and implementing the cleanup hook."""
    return f'''
pytest_plugins = ["webbpulse.e2e"]

{ENVIRONMENT}

CALLS = []


def pytest_e2e_cleanup(env, phase, created):
    """The product's own cleanup, recording what it was handed."""
{hook_body}
'''


RECORDER = """
    CALLS.append((phase, env.resource_prefix, tuple(created)))
    with open(env.api_id + ".log", "a") as handle:
        handle.write(f"{phase}:{','.join(str(item) for item in created)}\\n")
    return ""
"""


class TestOrdering:
    """Tests for when the hook is called and with what."""

    def test_the_hook_runs_at_the_start_and_the_end(self, pytester: pytest.Pytester) -> None:
        """One sweep before any test and one after them all, in that order."""
        pytester.makeconftest(conftest_with(RECORDER))
        pytester.makepyfile(
            test_one="""
            def test_records_a_resource(created_resources, e2e_env):
                created_resources.append("bucket-1")
                with open(e2e_env.api_id + ".log", "a") as handle:
                    handle.write("test\\n")
            """
        )
        result = pytester.runpytest_inprocess("-p", "no:cacheprovider")
        result.assert_outcomes(passed=1)
        phases = (pytester.path / "abc123.log").read_text().splitlines()
        assert phases == ["start:", "test", "end:bucket-1"]

    def test_the_start_sweep_is_handed_nothing(self, pytester: pytest.Pytester) -> None:
        """Nothing has been created yet, so the start pass sweeps by prefix and age alone."""
        pytester.makeconftest(conftest_with(RECORDER))
        pytester.makepyfile(test_one="def test_nothing(e2e_env): pass")
        result = pytester.runpytest_inprocess("-p", "no:cacheprovider")
        result.assert_outcomes(passed=1)
        assert (pytester.path / "abc123.log").read_text().splitlines() == ["start:", "end:"]

    def test_the_hook_is_handed_the_run_prefix(self, pytester: pytest.Pytester) -> None:
        """The prefix carries the run id, so a concurrent run's resources are not swept."""
        pytester.makeconftest(
            conftest_with(
                """
    with open("prefix.log", "a") as handle:
        handle.write(env.resource_prefix + "\\n")
    return ""
"""
            )
        )
        pytester.makepyfile(test_one="def test_nothing(e2e_env): pass")
        pytester.runpytest_inprocess("-p", "no:cacheprovider")
        assert (pytester.path / "prefix.log").read_text().splitlines() == ["e2e-run1-", "e2e-run1-"]


class TestFailureHandling:
    """Tests for what a leftover or a raising hook does to the run."""

    def test_a_reported_leftover_warns_and_does_not_fail(self, pytester: pytest.Pytester) -> None:
        """A leftover is worth knowing about and never worth losing a green run over."""
        pytester.makeconftest(conftest_with('    return "3 buckets left" if phase == "end" else ""\n'))
        pytester.makepyfile(test_one="def test_nothing(e2e_env): pass")
        result = pytester.runpytest_inprocess("-p", "no:cacheprovider", "-W", "default")
        result.assert_outcomes(passed=1)
        result.stdout.fnmatch_lines(["*3 buckets left*"])

    def test_a_raising_hook_does_not_fail_the_run(self, pytester: pytest.Pytester) -> None:
        """A cleanup that throws is reported, not propagated over the tests' own result."""
        pytester.makeconftest(conftest_with('    raise RuntimeError("delete refused")\n'))
        pytester.makepyfile(test_one="def test_nothing(e2e_env): pass")
        result = pytester.runpytest_inprocess("-p", "no:cacheprovider", "-W", "default")
        result.assert_outcomes(passed=1)
        result.stdout.fnmatch_lines(["*delete refused*"])

    def test_no_registered_hook_is_not_an_error(self, pytester: pytest.Pytester) -> None:
        """A product with nothing to clean up implements nothing and still runs."""
        pytester.makeconftest(f'pytest_plugins = ["webbpulse.e2e"]\n{ENVIRONMENT}')
        pytester.makepyfile(test_one="def test_nothing(e2e_env): pass")
        result = pytester.runpytest_inprocess("-p", "no:cacheprovider")
        result.assert_outcomes(passed=1)


class TestEnvironmentRefusal:
    """Tests for the plugin refusing to run against an unconfigured environment."""

    def test_an_unset_environment_fails_the_test_rather_than_erroring_obscurely(
        self, pytester: pytest.Pytester
    ) -> None:
        """With nothing set, the run fails naming the variables instead of on a connection error."""
        pytester.makeconftest('pytest_plugins = ["webbpulse.e2e"]')
        pytester.makepyfile(test_one="def test_nothing(e2e_env): pass")
        result = pytester.runpytest_inprocess("-p", "no:cacheprovider")
        result.assert_outcomes(errors=1)
        result.stdout.fnmatch_lines(["*E2E_API_BASE_URL*"])


class TestSuiteReExport:
    """Tests for what `from webbpulse.e2e.suite import *` actually brings across."""

    def test_the_parametrisation_hook_is_exported(self) -> None:
        """`pytest_generate_tests` must cross the star import, or every case collapses.

        A product's `test_shared.py` is one star import. `__all__` governs what that brings
        over, so a hook left out of it is simply absent from the module pytest collects: the
        route and operation cases silently lose their parametrisation and then error on a
        missing `live_route` fixture, which reads as a broken plugin rather than a missing
        export.
        """
        from webbpulse.e2e import suite

        assert "pytest_generate_tests" in suite.__all__

    def test_a_star_import_lands_the_hook_and_the_groups(self) -> None:
        """The re-export a product writes yields the hook and all six groups."""
        namespace: dict[str, object] = {}
        exec("from webbpulse.e2e.suite import *", namespace)
        assert callable(namespace["pytest_generate_tests"])
        groups = (
            "TestRouteCut",
            "TestCoverage",
            "TestReachability",
            "TestIdentity",
            "TestFrontend",
            "TestHygiene",
        )
        for group in groups:
            assert group in namespace

    def test_every_name_in_all_actually_exists(self) -> None:
        """An `__all__` entry with no attribute behind it makes the star import raise."""
        from webbpulse.e2e import suite

        for name in suite.__all__:
            assert hasattr(suite, name), name
