"""Tests for the browser layer: the collectors, the artifact naming and the parametrisation.

The parametrisation cases run a real pytest session through `pytester` with fake hooks,
because what is worth asserting is that a product's declarations become one junit case
each and that an absent declaration skips with a reason rather than erroring on a missing
fixture. Nothing here launches a browser; the cases that would need one skip when
chromium is not installed, which is the ordinary state of this package's own CI.
"""

from __future__ import annotations

import pytest

from webbpulse.e2e.browser import (
    DEFAULT_ARTIFACTS_DIR,
    ROOT_SELECTORS,
    ConsoleErrors,
    FailedRequests,
    artifact_name,
    browser_is_available,
)

pytest_plugins = ["pytester"]

API = "https://api.staging.example.invalid"

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
    "E2E_BROWSER",
    "E2E_HEADLESS",
    "E2E_BROWSER_ARTIFACTS_DIR",
    "E2E_GATE_SIGNING_KEY_SSM_PARAMETER",
    "E2E_GATE_KEY_PAIR_ID",
    "E2E_GATE_COOKIE_DOMAIN",
)

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


@pytest.fixture(autouse=True)
def _isolate_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear every `E2E_*` variable around each test, since inner sessions set them."""
    for name in E2E_NAMES:
        monkeypatch.delenv(name, raising=False)


class TestConsoleErrors:
    """Tests for the console and page error collector."""

    def test_it_starts_empty_and_reads_falsy(self) -> None:
        """A page with nothing wrong must not fail the render case."""
        assert not ConsoleErrors()

    def test_a_recorded_message_makes_it_truthy(self) -> None:
        """One console error is enough to fail a route's render case."""
        errors = ConsoleErrors()
        errors.record("pageerror: TypeError")
        assert errors

    def test_clearing_forgets_everything(self) -> None:
        """The render case clears between navigations so one route's noise is its own."""
        errors = ConsoleErrors()
        errors.record("a")
        errors.clear()
        assert not errors

    def test_the_summary_is_capped(self) -> None:
        """A failure message quotes the first few rather than a page of them."""
        errors = ConsoleErrors()
        for index in range(20):
            errors.record(f"error-{index}")
        assert errors.summary(limit=3) == "error-0; error-1; error-2"


class TestFailedRequests:
    """Tests for the failed API call collector."""

    def test_a_successful_response_is_not_recorded(self) -> None:
        """Only 400 and above are failures."""
        failures = FailedRequests(api_base_url=API)
        failures.record(f"{API}/api/builds", 200)
        assert not failures

    def test_a_server_error_is_recorded(self) -> None:
        """A 500 behind a rendered page is invisible to a server-side probe."""
        failures = FailedRequests(api_base_url=API)
        failures.record(f"{API}/api/builds", 500)
        assert failures

    def test_a_call_to_another_origin_is_ignored(self) -> None:
        """An analytics or font host answering 404 is not this product's failure."""
        failures = FailedRequests(api_base_url=API)
        failures.record("https://cdn.example.invalid/font.woff2", 404)
        assert not failures

    @pytest.mark.parametrize("status", [401, 403])
    def test_guard_statuses_are_exempt_when_asked(self, status: int) -> None:
        """An anonymous visit provokes these on purpose, so counting them asserts nothing."""
        failures = FailedRequests(api_base_url=API, ignore_guard_statuses=True)
        failures.record(f"{API}/api/me", status)
        assert not failures

    @pytest.mark.parametrize("status", [401, 403])
    def test_guard_statuses_count_by_default(self, status: int) -> None:
        """A signed-in visit answering 401 is a real failure and must not be swallowed."""
        failures = FailedRequests(api_base_url=API)
        failures.record(f"{API}/api/me", status)
        assert failures

    def test_a_500_is_recorded_even_when_guards_are_exempt(self) -> None:
        """The exemption is for the two guard statuses alone, not for everything."""
        failures = FailedRequests(api_base_url=API, ignore_guard_statuses=True)
        failures.record(f"{API}/api/me", 500)
        assert failures

    def test_the_summary_names_the_status_and_the_url(self) -> None:
        """A failure message that says which call failed and how."""
        failures = FailedRequests(api_base_url=API)
        failures.record(f"{API}/api/builds", 502)
        assert failures.summary() == f"502 {API}/api/builds"


class TestArtifactNaming:
    """Tests for turning a node id into a filename."""

    def test_a_node_id_becomes_a_safe_stem(self) -> None:
        """Colons, slashes and brackets all appear in a node id and none survive."""
        stem = artifact_name("e2e/test_shared.py::TestBrowser::test_x[protected:/garage]")
        assert "/" not in stem
        assert ":" not in stem
        assert "[" not in stem

    def test_the_stem_stays_short_enough_for_a_filesystem(self) -> None:
        """A parametrised id can run past the 255 byte limit on its own."""
        assert len(artifact_name("a" * 400)) <= 120

    def test_an_unnameable_id_still_yields_a_name(self) -> None:
        """A file must be written even when the id reduces to nothing."""
        assert artifact_name("///") == "unnamed"

    def test_the_default_directory_is_the_documented_one(self) -> None:
        """`e2e.yml` uploads this path by name, so it is part of the contract."""
        assert DEFAULT_ARTIFACTS_DIR == "e2e-browser-artifacts"


class TestBrowserAvailability:
    """Tests for the check that decides whether the browser group can run."""

    def test_an_unknown_browser_name_is_reported(self) -> None:
        """A typo in `E2E_BROWSER` past the environment check still answers a reason."""
        assert browser_is_available("netscape")

    def test_the_answer_is_a_string(self) -> None:
        """Empty means available; anything else is the reason it is not."""
        assert isinstance(browser_is_available("chromium"), str)

    def test_the_root_selectors_start_at_the_conventional_mount_points(self) -> None:
        """`#root` and `#app` are what the shell check already looks for."""
        assert ROOT_SELECTORS[:2] == ("#root", "#app")


HOOK_CONFTEST = f'''
pytest_plugins = ["webbpulse.e2e"]

{ENVIRONMENT}

from webbpulse.e2e import Goto, Journey, LoginForm, Record, RouteSpec


def pytest_e2e_login_form(env):
    """The fake product's login locators."""
    return LoginForm(path="/login")


def pytest_e2e_routes(env):
    """Two public routes, one protected and one guest-only."""
    return [
        RouteSpec(path="/", access="public"),
        RouteSpec(path="/about", access="public"),
        RouteSpec(path="/garage", access="protected"),
        RouteSpec(path="/login", access="guest-only"),
    ]


def pytest_e2e_journeys(env):
    """One read-only journey and one that records what it creates."""
    return [
        Journey(name="browse", steps=[Goto("/")], signed_in=False),
        Journey(
            name="create",
            steps=[Goto("/new"), Record("e2e-{{run_id}}-thing")],
            mutates=True,
        ),
    ]
'''

CASES = """
from webbpulse.e2e.suite import pytest_generate_tests  # noqa: F401


def test_routes(declared_route):
    assert declared_route is not None


def test_protected(protected_route):
    assert protected_route.access == "protected"


def test_guest_only(guest_only_route):
    assert guest_only_route.access == "guest-only"


def test_journeys(journey):
    assert journey.name
"""


class TestParametrisation:
    """Tests for `pytest_generate_tests` turning the hook results into junit cases."""

    def test_each_declaration_becomes_its_own_case(self, pytester: pytest.Pytester) -> None:
        """Four routes, one protected, one guest-only and two journeys, each its own case."""
        pytester.makeconftest(HOOK_CONFTEST)
        pytester.makepyfile(test_cases=CASES)
        result = pytester.runpytest_inprocess("-p", "no:cacheprovider")
        result.assert_outcomes(passed=8)

    def test_the_case_ids_name_the_route_and_the_journey(self, pytester: pytest.Pytester) -> None:
        """A failure has to say which route or journey, not which assertion tripped."""
        pytester.makeconftest(HOOK_CONFTEST)
        pytester.makepyfile(test_cases=CASES)
        result = pytester.runpytest_inprocess("-p", "no:cacheprovider", "--collect-only", "-q")
        result.stdout.fnmatch_lines(["*protected:/garage*"])
        result.stdout.fnmatch_lines(["*test_journeys[[]create[]]*"])

    def test_the_hooks_are_called_once_for_the_whole_session(self, pytester: pytest.Pytester) -> None:
        """Four fixtures and several cases, but the product's hooks run once each."""
        pytester.makeconftest(
            HOOK_CONFTEST.replace(
                'def pytest_e2e_routes(env):\n    """Two public routes, one protected and one guest-only."""',
                'def pytest_e2e_routes(env):\n    """Two public routes, one protected and one guest-only."""\n'
                '    with open("routes.log", "a") as handle:\n        handle.write("called\\n")',
            )
        )
        pytester.makepyfile(test_cases=CASES)
        pytester.runpytest_inprocess("-p", "no:cacheprovider")
        assert (pytester.path / "routes.log").read_text().count("called") == 1

    def test_no_declaration_skips_with_a_reason(self, pytester: pytest.Pytester) -> None:
        """A product with no browser hooks gets skips naming the hook, not fixture errors."""
        pytester.makeconftest(f'pytest_plugins = ["webbpulse.e2e"]\n{ENVIRONMENT}')
        pytester.makepyfile(test_cases=CASES)
        result = pytester.runpytest_inprocess("-p", "no:cacheprovider", "-rs")
        result.assert_outcomes(skipped=4)
        result.stdout.fnmatch_lines(["*pytest_e2e_routes declared no routes*"])

    def test_declaring_only_public_routes_skips_the_guard_cases(self, pytester: pytest.Pytester) -> None:
        """The route cases run; the protected and guest-only ones skip with their own reason."""
        pytester.makeconftest(
            f'''
pytest_plugins = ["webbpulse.e2e"]

{ENVIRONMENT}

from webbpulse.e2e import RouteSpec


def pytest_e2e_routes(env):
    """One public route and nothing else."""
    return [RouteSpec(path="/", access="public")]
'''
        )
        pytester.makepyfile(test_cases=CASES)
        result = pytester.runpytest_inprocess("-p", "no:cacheprovider", "-rs")
        result.assert_outcomes(passed=1, skipped=3)
        result.stdout.fnmatch_lines(["*declared no protected routes*"])


class TestMutatingJourneyRefusal:
    """Tests for a mutating journey with no `Record` step failing at collection."""

    def test_the_session_fails_before_any_case_runs(self, pytester: pytest.Pytester) -> None:
        """A journey that would leak must never get as far as touching the stage."""
        pytester.makeconftest(
            f'''
pytest_plugins = ["webbpulse.e2e"]

{ENVIRONMENT}

from webbpulse.e2e import Goto, Journey


def pytest_e2e_journeys(env):
    """A journey that mutates and records nothing, which the constructor refuses."""
    return [Journey(name="leaky", steps=[Goto("/new")], mutates=True)]
'''
        )
        pytester.makepyfile(test_cases=CASES)
        result = pytester.runpytest_inprocess("-p", "no:cacheprovider")
        assert result.ret != 0
        result.stdout.fnmatch_lines(["*no Record step*"])

    def test_the_message_says_which_journey(self, pytester: pytest.Pytester) -> None:
        """A product with a dozen journeys needs the one that is wrong named."""
        pytester.makeconftest(
            f'''
pytest_plugins = ["webbpulse.e2e"]

{ENVIRONMENT}

from webbpulse.e2e import Goto, Journey


def pytest_e2e_journeys(env):
    """A named journey that mutates and records nothing."""
    return [Journey(name="create-a-build", steps=[Goto("/new")], mutates=True)]
'''
        )
        pytester.makepyfile(test_cases=CASES)
        result = pytester.runpytest_inprocess("-p", "no:cacheprovider")
        result.stdout.fnmatch_lines(["*create-a-build*"])


class TestSuiteExports:
    """Tests for what the star import a product writes brings across."""

    def test_the_browser_group_is_exported(self) -> None:
        """`TestBrowser` reaches the product's `test_shared.py` through `__all__`."""
        from webbpulse.e2e import suite

        assert "TestBrowser" in suite.__all__
        assert hasattr(suite, "TestBrowser")

    def test_a_star_import_lands_the_browser_group(self) -> None:
        """The one line a product writes yields the group as well as the hook."""
        namespace: dict[str, object] = {}
        exec("from webbpulse.e2e.suite import *", namespace)
        assert "TestBrowser" in namespace

    def test_the_declaration_types_are_importable_from_the_plugin(self) -> None:
        """A conftest imports these by name, so they are part of the package surface."""
        from webbpulse import e2e

        for name in ("LoginForm", "RouteSpec", "Journey", "Goto", "Click", "Fill", "Record"):
            assert name in e2e.__all__
            assert hasattr(e2e, name)
