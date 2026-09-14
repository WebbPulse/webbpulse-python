"""Tests for the browser layer: the collectors, the artifact naming and the parametrisation.

The parametrisation cases run a real pytest session through `pytester` with fake hooks,
because what is worth asserting is that a product's declarations become one junit case
each and that an absent declaration skips with a reason rather than erroring on a missing
fixture. Nothing here launches a browser; the cases that would need one skip when
chromium is not installed, which is the ordinary state of this package's own CI.
"""

from __future__ import annotations

from typing import ClassVar

import pytest

from webbpulse.e2e.browser import (
    DEFAULT_ARTIFACTS_DIR,
    ROOT_SELECTORS,
    TRACE_REDACTION_MARKER,
    ConsoleErrors,
    FailedRequests,
    artifact_name,
    browser_is_available,
    is_session_probe,
    message_location_url,
    redact_zip,
    resource_load_status,
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


CHROMIUM_401 = "Failed to load resource: the server responded with a status of 401 ()"
WEBKIT_403 = "Failed to load resource: the server responded with a status of 403 (Forbidden)"
FIREFOX_401 = f"Failed to load resource: the server responded with a status 401 for {API}/api/auth/refresh"


class TestResourceLoadStatus:
    """Tests for reading the status out of each engine's resource-load message."""

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            (CHROMIUM_401, 401),
            (WEBKIT_403, 403),
            (FIREFOX_401, 401),
            ("HTTP load failed with status 403. See the console for details.", 403),
            ("Failed to load resource: the server responded with a status of 500 ()", 500),
        ],
    )
    def test_a_resource_load_message_yields_its_status(self, text: str, expected: int) -> None:
        """Chromium, WebKit and Firefox each phrase it differently and all three must parse."""
        assert resource_load_status(text) == expected

    @pytest.mark.parametrize(
        "text",
        [
            "TypeError: Cannot read properties of undefined (reading 'map')",
            "Warning: Each child in a list should have a unique key prop.",
            "Uncaught (in promise) Error: 401",
        ],
    )
    def test_an_ordinary_error_yields_no_status(self, text: str) -> None:
        """A render error that merely mentions a number is not a resource-load error."""
        assert resource_load_status(text) is None


class TestConsoleGuardExemption:
    """Tests for the console collector agreeing with `FailedRequests` about one HTTP event.

    The shared `@webbpulse/api-client` calls `POST /api/auth/refresh` on load, and
    anonymously that correctly answers 401, which the browser also logs as a console error.
    """

    def test_a_guard_resource_error_is_ignored_when_asked(self) -> None:
        """The 401 an anonymous visit provokes must not fail every public route."""
        errors = ConsoleErrors(api_base_url=API, ignore_guard_statuses=True)
        errors.record(f"console.error: {CHROMIUM_401}", f"{API}/api/auth/refresh")
        assert not errors

    @pytest.mark.parametrize("status", [401, 403])
    def test_both_guard_statuses_are_ignored(self, status: int) -> None:
        """The exemption covers the same status set `FailedRequests` exempts."""
        errors = ConsoleErrors(api_base_url=API, ignore_guard_statuses=True)
        text = f"Failed to load resource: the server responded with a status of {status} ()"
        errors.record(f"console.error: {text}", f"{API}/api/auth/refresh")
        assert not errors

    def test_the_firefox_shape_is_ignored_from_its_text_alone(self) -> None:
        """Firefox names the URL in the text rather than in a location, and still matches."""
        errors = ConsoleErrors(api_base_url=API, ignore_guard_statuses=True)
        errors.record(f"console.error: {FIREFOX_401}")
        assert not errors

    def test_the_webkit_shape_is_ignored(self) -> None:
        """WebKit spells the reason phrase out and the status still parses."""
        errors = ConsoleErrors(api_base_url=API, ignore_guard_statuses=True)
        errors.record(f"console.error: {WEBKIT_403}", f"{API}/api/auth/refresh")
        assert not errors

    def test_a_guard_status_counts_when_signed_in(self) -> None:
        """A protected route is visited signed in, where a 401 is a real failure.

        Asserted on a product path rather than on the refresh path, because the cold-load
        session probe is exempt on its own terms whoever is visiting.
        """
        errors = ConsoleErrors(api_base_url=API)
        errors.record(f"console.error: {CHROMIUM_401}", f"{API}/api/builds")
        assert errors

    def test_a_server_error_still_fails_while_guards_are_exempt(self) -> None:
        """The exemption is for the two guard statuses alone, exactly as on `FailedRequests`."""
        errors = ConsoleErrors(api_base_url=API, ignore_guard_statuses=True)
        text = "Failed to load resource: the server responded with a status of 500 ()"
        errors.record(f"console.error: {text}", f"{API}/api/builds")
        assert errors

    def test_a_404_still_fails_while_guards_are_exempt(self) -> None:
        """A missing endpoint is a real bug an anonymous visit has no licence to provoke."""
        errors = ConsoleErrors(api_base_url=API, ignore_guard_statuses=True)
        text = "Failed to load resource: the server responded with a status of 404 ()"
        errors.record(f"console.error: {text}", f"{API}/api/gone")
        assert errors

    def test_a_render_error_still_fails_while_guards_are_exempt(self) -> None:
        """The whole point of the collector is the uncaught exception behind a blank page."""
        errors = ConsoleErrors(api_base_url=API, ignore_guard_statuses=True)
        errors.record("console.error: TypeError: Cannot read properties of undefined")
        assert errors

    def test_a_page_error_still_fails_while_guards_are_exempt(self) -> None:
        """An uncaught page error carries no status and is never a guard response."""
        errors = ConsoleErrors(api_base_url=API, ignore_guard_statuses=True)
        errors.record("pageerror: Error: render crashed")
        assert errors

    def test_a_guard_status_on_another_origin_still_fails(self) -> None:
        """The exemption is scoped to this product's API, the way `FailedRequests` is."""
        errors = ConsoleErrors(api_base_url=API, ignore_guard_statuses=True)
        errors.record(f"console.error: {CHROMIUM_401}", "https://cdn.example.invalid/private.json")
        assert errors

    def test_the_summary_still_names_what_was_kept(self) -> None:
        """A failure message must quote the errors that survived the exemption."""
        errors = ConsoleErrors(api_base_url=API, ignore_guard_statuses=True)
        errors.record(f"console.error: {CHROMIUM_401}", f"{API}/api/auth/refresh")
        errors.record("console.error: TypeError: boom")
        assert errors.summary() == "console.error: TypeError: boom"


class TestMessageLocationUrl:
    """Tests for reading the URL off a Playwright console message."""

    def test_a_mapping_location_yields_its_url(self) -> None:
        """The sync API hands `location` over as a mapping."""

        class Message:
            location: ClassVar[dict[str, object]] = {"url": f"{API}/api/auth/refresh", "lineNumber": 0}

        assert message_location_url(Message()) == f"{API}/api/auth/refresh"

    def test_an_object_location_yields_its_url(self) -> None:
        """A driver build that hands an object over must read the same."""

        class Location:
            url = f"{API}/api/auth/refresh"

        class Message:
            location = Location()

        assert message_location_url(Message()) == f"{API}/api/auth/refresh"

    def test_a_message_with_no_location_yields_none(self) -> None:
        """A message reported without one must not raise."""

        class Message:
            pass

        assert message_location_url(Message()) is None

    def test_an_empty_url_yields_none(self) -> None:
        """An empty string is no URL, and must not be scoped against the API base."""

        class Message:
            location: ClassVar[dict[str, object]] = {"url": ""}

        assert message_location_url(Message()) is None


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


REFRESH = f"{API}/api/auth/refresh"

PROBE_ERROR = "console.error: Failed to load resource: the server responded with a status of 401 ()"


class TestSessionProbeExemption:
    """The shared auth client's cold-load `POST /api/auth/refresh` probe is always exempt.

    `@webbpulse/auth` asks on every cold load whether a refresh cookie exists, and with no
    session the API correctly answers 401 `NO_SESSION`. Counting that one exchange failed the
    sign-in journey and every product journey that starts from a cold load, because those
    cases are signed in and so do not set the guard-status flag.
    """

    def test_the_probe_is_not_a_failed_request_when_signed_in(self) -> None:
        """The exemption does not depend on `ignore_guard_statuses`."""
        requests = FailedRequests(api_base_url=API)
        requests.record(REFRESH, 401)
        assert not requests

    def test_the_probe_is_not_a_console_error_when_signed_in(self) -> None:
        """The console listener's copy of the same event is exempt on the same terms."""
        errors = ConsoleErrors(api_base_url=API)
        errors.record(PROBE_ERROR, REFRESH)
        assert not errors

    def test_the_probe_is_recognised_from_the_message_text_alone(self) -> None:
        """A browser that reports the URL only inside the text is still matched."""
        errors = ConsoleErrors(api_base_url=API)
        text = f"Failed to load resource: the server responded with a status of 401 for {REFRESH}"
        errors.record(f"console.error: {text}")
        assert not errors

    def test_a_query_string_on_the_probe_is_still_the_probe(self) -> None:
        """Matching is on the path, so a cache-busting query does not defeat it."""
        requests = FailedRequests(api_base_url=API)
        requests.record(f"{REFRESH}?t=1", 401)
        assert not requests

    @pytest.mark.parametrize("status", [403, 500, 404])
    def test_only_a_401_on_that_path_is_exempt(self, status: int) -> None:
        """A different status from the same path is a real failure and still counts."""
        requests = FailedRequests(api_base_url=API)
        requests.record(REFRESH, status)
        assert requests

    def test_a_401_on_another_path_still_counts(self) -> None:
        """Nothing but the refresh path gains the exemption."""
        requests = FailedRequests(api_base_url=API)
        requests.record(f"{API}/api/builds", 401)
        assert requests

    def test_the_probe_path_on_another_origin_still_counts(self) -> None:
        """The path is only exempt under this product's own API base."""
        assert not is_session_probe("https://other.example.invalid/api/auth/refresh", 401, API)

    def test_the_guard_semantics_are_unchanged_for_everything_else(self) -> None:
        """An anonymous case still exempts guard statuses on other paths, as before."""
        requests = FailedRequests(api_base_url=API, ignore_guard_statuses=True)
        requests.record(f"{API}/api/builds", 401)
        assert not requests

    def test_a_render_error_is_never_exempted_by_the_probe_rule(self) -> None:
        """An uncaught page error carries no status, so it can never match."""
        errors = ConsoleErrors(api_base_url=API)
        errors.record("pageerror: TypeError: undefined is not a function")
        assert errors


class TestReportOnlyCspViolations:
    """A CSP violation the browser only reported is not the app under test's failure.

    CMP staging run 34805419305 failed `public:/` on the AdSense iframe reporting its own
    `frame-ancestors` policy against `www.google.com`. The app can neither cause it nor fix
    it, and the browser took no action, so it must not fail a render case.
    """

    ADSENSE = (
        "Framing 'https://www.google.com/' violates the following report-only Content "
        "Security Policy directive: \"frame-ancestors 'self'\". The violation has been "
        "logged, but no further action has been taken."
    )

    def test_the_adsense_report_only_violation_is_exempt(self) -> None:
        """The exact message the staging run failed on must not be recorded."""
        errors = ConsoleErrors(api_base_url=API)
        errors.record(self.ADSENSE)
        assert not errors

    def test_the_exemption_is_unconditional(self) -> None:
        """A signed-in journey's page reports the same third-party frame the same way."""
        errors = ConsoleErrors(api_base_url=API, ignore_guard_statuses=False)
        errors.record(self.ADSENSE)
        assert not errors

    def test_the_match_is_case_insensitive(self) -> None:
        """Browsers differ on the casing of the directive name they quote."""
        errors = ConsoleErrors(api_base_url=API)
        errors.record("Refused to frame: violates the following REPORT-ONLY CONTENT SECURITY POLICY directive")
        assert not errors

    def test_an_enforced_violation_still_counts(self) -> None:
        """An enforced policy blocked something, which is a real defect in the app's own page."""
        errors = ConsoleErrors(api_base_url=API)
        errors.record(
            "Refused to load the script 'https://cdn.invalid/x.js' because it violates the "
            "following Content Security Policy directive: \"script-src 'self'\"."
        )
        assert errors

    def test_an_unrelated_console_error_still_counts(self) -> None:
        """Nothing but a report-only CSP message gains this exemption."""
        errors = ConsoleErrors(api_base_url=API)
        errors.record("pageerror: TypeError: undefined is not a function")
        assert errors

    def test_the_predicate_is_callable_on_its_own(self) -> None:
        """The exemption is a named method, so a product can ask the same question."""
        errors = ConsoleErrors()
        assert errors.is_report_only_csp_violation(self.ADSENSE)
        assert not errors.is_report_only_csp_violation("Content Security Policy directive")


class TestTraceRedaction:
    """The durable e2e user's password never reaches a trace zip in the artifacts directory.

    Playwright records a `fill` step's parameters verbatim, and so does every other typing
    path it offers, so the trace is scrubbed before it is written where CI collects it.
    """

    @staticmethod
    def _zip_with_the_secret(path: object, secret: str) -> None:
        """Build a small zip carrying the secret in two separate entries."""
        import zipfile

        with zipfile.ZipFile(str(path), "w") as writer:
            writer.writestr(
                "trace.trace",
                '{"method":"fill","params":{"selector":"#pw","value":"' + secret + '"}}\n{"type":"log"}\n',
            )
            writer.writestr("trace.network", '{"body":"password=' + secret + '"}')
            writer.writestr("resources/page.html", f"<input value='{secret}'>")

    def test_every_entry_is_scrubbed(self, tmp_path: object) -> None:
        """The secret is gone from all three entries, and the count names how many changed."""
        import zipfile

        secret = "a-very-secret-password"
        source = tmp_path / "raw.zip"  # type: ignore[operator]
        destination = tmp_path / "out" / "trace.zip"  # type: ignore[operator]
        self._zip_with_the_secret(source, secret)

        changed = redact_zip(source, destination, secret)

        assert changed == 3
        with zipfile.ZipFile(str(destination)) as reader:
            names = reader.namelist()
            assert names == ["trace.trace", "trace.network", "resources/page.html"]
            for name in names:
                assert secret.encode() not in reader.read(name)
                assert TRACE_REDACTION_MARKER in reader.read(name)

    def test_the_trace_entry_stays_valid_jsonl(self, tmp_path: object) -> None:
        """Replacing bytes inside a JSON string leaves the trace parseable, so it still opens."""
        import json
        import zipfile

        secret = "a-very-secret-password"
        source = tmp_path / "raw.zip"  # type: ignore[operator]
        destination = tmp_path / "trace.zip"  # type: ignore[operator]
        self._zip_with_the_secret(source, secret)

        redact_zip(source, destination, secret)

        with zipfile.ZipFile(str(destination)) as reader:
            lines = [line for line in reader.read("trace.trace").decode().splitlines() if line.strip()]
            parsed = [json.loads(line) for line in lines]
        assert parsed[0]["params"]["value"] == TRACE_REDACTION_MARKER.decode()

    def test_an_untouched_entry_is_copied_through(self, tmp_path: object) -> None:
        """An entry that never held the secret is preserved exactly."""
        import zipfile

        source = tmp_path / "raw.zip"  # type: ignore[operator]
        destination = tmp_path / "trace.zip"  # type: ignore[operator]
        with zipfile.ZipFile(str(source), "w") as writer:
            writer.writestr("trace.trace", "no secret here")

        assert redact_zip(source, destination, "a-very-secret-password") == 0
        with zipfile.ZipFile(str(destination)) as reader:
            assert reader.read("trace.trace") == b"no secret here"
