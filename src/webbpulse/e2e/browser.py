"""Playwright fixtures for driving the deployed SPA the way a person does.

The API groups prove the gateway routes and the identity flows; none of them proves the
app renders. A bundle that joined the wrong API base, a route guard that unmounts on a
loading flag, a router with no catch-all: all three answer 200 to an httpx probe and show a
person a blank page. These fixtures open the real browser against the deployed origin,
carrying the staging gate cookies so the CloudFront function admits the request.

Everything is the synchronous Playwright API, because the suite around it is synchronous
and a mixed event loop under pytest costs more than it buys. A failing test leaves a
`trace.zip` and a screenshot under `E2E_BROWSER_ARTIFACTS_DIR`, named after the node id, which
is the difference between a red CI job and a reproducible one.

Importing this module does not import Playwright; the fixtures do, and skip with a clear
reason when it or its browser binary is absent.
"""

from __future__ import annotations

import os
import re
from collections.abc import Generator, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import pytest

from .gate import GateCookies
from .journeys import Journey, LoginForm, RouteSpec

__all__ = [
    "DEFAULT_ARTIFACTS_DIR",
    "ROOT_SELECTORS",
    "TRACE_REDACTION_MARKER",
    "BrowserFailure",
    "ConsoleErrors",
    "FailedRequests",
    "artifact_name",
    "browser_is_available",
    "is_session_probe",
    "message_location_url",
    "redact_zip",
    "resource_load_status",
]

DEFAULT_ARTIFACTS_DIR = "e2e-browser-artifacts"
ROOT_SELECTORS = ("#root", "#app", "main", "body")
GUARD_STATUSES = (401, 403)
SESSION_PROBE_PATH = "/api/auth/refresh"
SESSION_PROBE_STATUS = 401
REPORT_ONLY_CSP = "report-only content security policy"
TRACE_REDACTION_MARKER = b"[redacted]"
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
_RESOURCE_LOAD_PREFIX = re.compile(r"\b(?:Failed to load resource|HTTP load failed|NS_ERROR_|was loaded over)\b")
_RESOURCE_LOAD_STATUS = re.compile(r"\bstatus(?: of|:)? (\d{3})\b")
_URL_IN_TEXT = re.compile(r"https?://[^\s'\"()<>]+")


def resource_load_status(text: str) -> int | None:
    """The HTTP status a browser's resource-load console error names, or None.

    Chromium and WebKit both log `Failed to load resource: the server responded with a
    status of 401 ()`, WebKit also logs `HTTP load failed with status 403`, and Firefox
    phrases the same event as `... with a status 401 for <url>`. The message must read as a
    resource-load report and then name a three digit status, so a render error that merely
    mentions a number is never mistaken for one.
    """
    if not _RESOURCE_LOAD_PREFIX.search(text):
        return None
    found = _RESOURCE_LOAD_STATUS.search(text)
    return int(found.group(1)) if found else None


def is_session_probe(url: str, status: int, api_base_url: str) -> bool:
    """Whether one response is the shared auth client's cold-load session probe.

    `@webbpulse/auth` sends `POST /api/auth/refresh` on every cold load to find out whether
    a refresh cookie already exists, and before any sign in the API correctly answers 401
    `NO_SESSION`. That one exchange is a healthy app answering correctly, so it is exempt in
    both collectors whether or not the case is signed in: a signed-in journey that starts
    from a cold load makes the same probe before its sign in, and counting it fails every
    such journey.

    The match is deliberately narrow, on the URL path under this product's API base and that
    one status. A 500 from the same path, a 401 from any other path, and the same path on
    another origin all still count.
    """
    if status != SESSION_PROBE_STATUS or not api_base_url:
        return False
    if not url.startswith(api_base_url):
        return False
    from urllib.parse import urlsplit

    return urlsplit(url).path == SESSION_PROBE_PATH


class BrowserFailure(AssertionError):
    """A browser case failed in a way worth naming apart from a plain assertion."""


def artifact_name(node_id: str) -> str:
    """A filesystem-safe stem for one test's trace and screenshot, from its node id."""
    return _UNSAFE.sub("-", node_id).strip("-")[:120] or "unnamed"


def browser_is_available(browser_name: str) -> str:
    """Empty when the named browser can be launched, or the reason it cannot.

    Answered from Playwright's own driver registry rather than by starting a driver, so
    the package's own unit tests can ask the question cheaply and a machine with no
    browser binary skips the browser group with a reason rather than erroring inside a
    session fixture.
    """
    if browser_name not in ("chromium", "firefox", "webkit"):
        return f"playwright has no browser named {browser_name!r}"
    try:
        from playwright._impl._driver import compute_driver_executable  # noqa: F401
        from playwright._repo_version import version  # noqa: F401
    except ImportError:
        return "playwright is not installed, so no browser case can run"
    if not _installed_browser_paths(browser_name):
        return f"the {browser_name} binary is not installed. Run `python -m playwright install {browser_name}`"
    return ""


def _installed_browser_paths(browser_name: str) -> list[str]:
    """Every downloaded build directory for one engine, from Playwright's own cache.

    Reads the cache directory rather than asking a running driver, because asking costs a
    node process and answers with a path that exists only after a download.
    """
    root = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "").strip()
    if root in ("", "0"):
        root = os.path.join(os.path.expanduser("~"), ".cache", "ms-playwright")
    if not os.path.isdir(root):
        return []
    return [os.path.join(root, entry) for entry in os.listdir(root) if entry.split("-")[0].startswith(browser_name)]


@dataclass
class ConsoleErrors:
    """Every console error and uncaught page error one page produced.

    A React render error is an uncaught exception and a blank page; the API suite cannot
    see either, and the browser suite only sees them if something is listening.

    `ignore_guard_statuses` mirrors the flag of the same name on `FailedRequests`, and is
    set by the same cases for the same reason. The two collectors see one HTTP event twice:
    the response listener sees the 401 an anonymous visit is meant to provoke, and the
    console listener sees the resource-load error the browser logs for it. Ignoring the
    first while counting the second fails every public route on a healthy app, so the
    exemption covers both, on the same status set and the same anonymous versus signed-in
    rule.

    The shared auth client's cold-load session probe is exempt separately and
    unconditionally, through `is_session_probe`, because it is correct on a signed-in
    journey's first load too. A report-only CSP violation is exempt the same way, through
    `is_report_only_csp_violation`. Every other console error still counts.
    """

    api_base_url: str = ""
    ignore_guard_statuses: bool = False
    messages: list[str] = field(default_factory=list)

    def record(self, message: str, url: str | None = None) -> None:
        """Record one console error or page error, honouring every exemption."""
        if self.is_session_probe_error(message, url):
            return
        if self.is_report_only_csp_violation(message):
            return
        if self.is_ignored_guard_error(message, url):
            return
        self.messages.append(message)

    def is_report_only_csp_violation(self, message: str) -> bool:
        """Whether a console message reports a CSP violation the browser did not act on.

        Unconditional, because a report-only policy is usually a third-party frame's own,
        such as the AdSense iframe reporting `frame-ancestors` against `www.google.com`, and
        the app under test can neither cause it nor fix it. An enforced violation names no
        report-only directive and still counts.
        """
        return REPORT_ONLY_CSP in message.casefold()

    def is_session_probe_error(self, message: str, url: str | None = None) -> bool:
        """Whether a console message is the resource-load error the session probe made.

        Unconditional, because the probe is correct behaviour on a cold load whoever is
        visiting. The console listener may only ever see the message text and a location,
        so the URL is taken from either and judged on its path plus the status the message
        names.
        """
        status = resource_load_status(message)
        if status is None:
            return False
        target = url if url else _url_in(message)
        if target is None:
            return False
        return is_session_probe(target, status, self.api_base_url)

    def is_ignored_guard_error(self, message: str, url: str | None = None) -> bool:
        """Whether a console message is the resource-load error an exempt failed request made.

        The message must name a guard status in a resource-load error, and the URL it carries
        must be one `FailedRequests` would have scoped to this product's API. A console
        message that carries no URL at all is judged on the text alone, because a browser
        that reports the status without a location still reports the same event.
        """
        if not self.ignore_guard_statuses:
            return False
        status = resource_load_status(message)
        if status is None or status not in GUARD_STATUSES:
            return False
        target = url if url else _url_in(message)
        if target is None:
            return True
        return bool(self.api_base_url) and target.startswith(self.api_base_url)

    def clear(self) -> None:
        """Forget everything recorded so far, between navigations in one test."""
        self.messages.clear()

    def __bool__(self) -> bool:
        """Whether anything was recorded."""
        return bool(self.messages)

    def summary(self, limit: int = 5) -> str:
        """The first few recorded messages, for a failure message."""
        return "; ".join(self.messages[:limit])


@dataclass
class FailedRequests:
    """Every response the page received from the API with a status of 400 or above.

    `ignore_guard_statuses` is set while a case visits a route anonymously on purpose, so
    the 401 and 403 the app is meant to provoke are not counted as failures. The shared auth
    client's cold-load session probe is exempt whatever that flag says, through
    `is_session_probe`.
    """

    api_base_url: str
    ignore_guard_statuses: bool = False
    entries: list[tuple[str, int]] = field(default_factory=list)

    def record(self, url: str, status: int) -> None:
        """Record one API response, honouring both exemptions."""
        if not url.startswith(self.api_base_url):
            return
        if status < 400:
            return
        if is_session_probe(url, status, self.api_base_url):
            return
        if self.ignore_guard_statuses and status in GUARD_STATUSES:
            return
        self.entries.append((url, status))

    def clear(self) -> None:
        """Forget everything recorded so far."""
        self.entries.clear()

    def __bool__(self) -> bool:
        """Whether anything was recorded."""
        return bool(self.entries)

    def summary(self, limit: int = 5) -> str:
        """The first few recorded failures, for a failure message."""
        return "; ".join(f"{status} {url}" for url, status in self.entries[:limit])


@pytest.fixture(scope="session")
def browser_artifacts_dir(e2e_env: Any) -> Any:
    """The directory traces and screenshots are written to, created on first use."""
    import pathlib

    path = pathlib.Path(e2e_env.browser_artifacts_dir or DEFAULT_ARTIFACTS_DIR)
    path.mkdir(parents=True, exist_ok=True)
    return path


@pytest.fixture(scope="session")
def playwright(e2e_env: Any) -> Iterator[Any]:
    """The Playwright driver for the run, skipping when it or its browser is absent."""
    reason = browser_is_available(e2e_env.browser_name)
    if reason:
        pytest.skip(reason)
    from playwright.sync_api import sync_playwright

    with sync_playwright() as driver:
        yield driver


@pytest.fixture(scope="session")
def browser(playwright: Any, e2e_env: Any) -> Iterator[Any]:
    """One browser for the run, headless unless `E2E_HEADLESS` says otherwise."""
    engine = getattr(playwright, e2e_env.browser_name)
    instance = engine.launch(headless=e2e_env.headless)
    try:
        yield instance
    finally:
        instance.close()


@pytest.fixture
def context(
    request: pytest.FixtureRequest,
    browser: Any,
    e2e_env: Any,
    gate_cookies: GateCookies | None,
    browser_artifacts_dir: Any,
) -> Iterator[Any]:
    """A fresh browser context per test, gate cookies attached and tracing on.

    A fresh context per test rather than a shared one is the point: the guard cases need a
    genuinely anonymous visitor, and a context that carried a previous test's session
    would assert the opposite of what it reads as asserting.

    On failure the trace and a full-page screenshot are written under the artifacts
    directory, named after the node id. On success the trace is discarded, because a
    passing run's traces are a hundred megabytes of nothing anyone reads.
    """
    instance = browser.new_context(base_url=e2e_env.web_base_url, ignore_https_errors=False)
    if gate_cookies is not None:
        instance.add_cookies(gate_cookies.as_playwright_cookies())
    instance.tracing.start(screenshots=True, snapshots=True, sources=False)
    stem = artifact_name(request.node.nodeid)
    try:
        yield instance
    finally:
        failed = _test_failed(request)
        try:
            if failed:
                _stop_tracing_redacted(
                    instance,
                    browser_artifacts_dir / f"{stem}-trace.zip",
                    e2e_env.user_password,
                )
                _screenshot_open_pages(instance, browser_artifacts_dir, stem)
            else:
                instance.tracing.stop()
        finally:
            instance.close()


def _stop_tracing_redacted(instance: Any, destination: Any, secret: str) -> None:
    """Stop tracing and write the trace out with the password replaced everywhere.

    Playwright records a `fill` step's parameters, and every other typing path it offers
    records the value just as verbatim, so there is no way to type a password that keeps it
    out of the recording. The trace is therefore written to a temporary file first, scrubbed,
    and only then moved into the artifacts directory, so a secret never exists at the path
    CI collects.
    """
    import pathlib
    import tempfile

    target = pathlib.Path(destination)
    if not secret:
        instance.tracing.stop(path=str(target))
        return

    with tempfile.TemporaryDirectory() as staging:
        raw = pathlib.Path(staging) / "trace.zip"
        instance.tracing.stop(path=str(raw))
        redact_zip(raw, target, secret)


def redact_zip(source: Any, destination: Any, secret: str, marker: bytes = TRACE_REDACTION_MARKER) -> int:
    """Copy one zip to `destination`, replacing every occurrence of `secret` in every entry.

    Entries are rewritten byte for byte rather than parsed, because the password reaches a
    trace through several shapes at once: the `fill` call parameters and its log line in
    `trace.trace`, a `__playwright_value_` attribute in the DOM snapshot beside it, a request
    body in `trace.network`, and any resource entry that quoted it. Replacing the bytes
    catches all of them, and because the secret only ever appears inside a JSON string or a
    resource body, the result stays valid JSONL and `playwright show-trace` still opens it.

    Returns the number of entries that were changed, so a caller can assert on it.
    """
    import pathlib
    import zipfile

    needle = secret.encode()
    changed = 0
    source_path = pathlib.Path(source)
    destination_path = pathlib.Path(destination)
    destination_path.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(source_path) as reader, zipfile.ZipFile(destination_path, "w", zipfile.ZIP_DEFLATED) as writer:
        for info in reader.infolist():
            data = reader.read(info.filename)
            if needle and needle in data:
                data = data.replace(needle, marker)
                changed += 1
            writer.writestr(_copied_info(info), data)
    return changed


def _copied_info(info: Any) -> Any:
    """A `ZipInfo` carrying the original entry's name, timestamp and mode, for the new zip.

    The size is deliberately left to be recomputed, because redaction changes it.
    """
    import zipfile

    copied = zipfile.ZipInfo(info.filename, date_time=info.date_time)
    copied.compress_type = zipfile.ZIP_DEFLATED
    copied.external_attr = info.external_attr
    copied.internal_attr = info.internal_attr
    copied.create_system = info.create_system
    return copied


def _screenshot_open_pages(instance: Any, directory: Any, stem: str) -> None:
    """Save a full-page screenshot of every open page, ignoring one that will not paint."""
    for index, page in enumerate(instance.pages):
        suffix = "" if index == 0 else f"-{index}"
        try:
            page.screenshot(path=str(directory / f"{stem}{suffix}.png"), full_page=True)
        except Exception:
            continue


def _test_failed(request: pytest.FixtureRequest) -> bool:
    """Whether the test that used this fixture failed, via the report hook's stash."""
    report = getattr(request.node, "_webbpulse_e2e_failed", None)
    return bool(report)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item, call: pytest.CallInfo[None]
) -> Generator[None, pytest.TestReport, pytest.TestReport]:
    """Stash on the item whether any phase failed, so the context fixture can see it.

    A fixture's teardown runs before the test's own report is available anywhere it could
    read it, so the flag is set here as each phase's report is made.
    """
    report = yield
    if report.failed:
        item._webbpulse_e2e_failed = True  # type: ignore[attr-defined]
    return report


@pytest.fixture
def page(context: Any, console_errors: Any, failed_requests: Any) -> Iterator[Any]:
    """A page in the test's own context, with the listeners already attached."""
    opened = context.new_page()
    _attach_listeners(opened, console_errors, failed_requests)
    try:
        yield opened
    finally:
        opened.close()


def _attach_listeners(page: Any, console_errors: ConsoleErrors, failed_requests: FailedRequests) -> None:
    """Wire the console, page error and response listeners onto one page."""
    page.on("console", lambda message: _record_console(console_errors, message))
    page.on("pageerror", lambda error: console_errors.record(f"pageerror: {error}"))
    page.on("response", lambda response: failed_requests.record(response.url, response.status))


def _record_console(console_errors: ConsoleErrors, message: Any) -> None:
    """Hand one console error to the collector, with the URL the message carries.

    A resource-load error names the failing URL in `location`, which is where the collector
    can scope it to this product's API rather than to a font host that happens to 401.
    """
    if getattr(message, "type", None) != "error":
        return
    text = str(getattr(message, "text", ""))
    console_errors.record(f"console.error: {text}", message_location_url(message))


def message_location_url(message: Any) -> str | None:
    """The URL a Playwright console message's `location` names, or None when it carries none.

    `location` is a mapping in the sync API and absent on messages a browser reports without
    one, so both shapes and neither are tolerated.
    """
    location = getattr(message, "location", None)
    if isinstance(location, Mapping):
        url = location.get("url")
        return str(url) if url else None
    url = getattr(location, "url", None)
    return str(url) if url else None


def _url_in(text: str) -> str | None:
    """The first absolute http URL a console message's text names, or None."""
    found = _URL_IN_TEXT.search(text)
    return found.group(0) if found else None


@pytest.fixture
def console_errors(e2e_env: Any) -> ConsoleErrors:
    """Collector for console errors and uncaught page errors on the test's page."""
    return ConsoleErrors(api_base_url=e2e_env.api_base_url)


@pytest.fixture
def failed_requests(e2e_env: Any) -> FailedRequests:
    """Collector for API responses of 400 or above on the test's page."""
    return FailedRequests(api_base_url=e2e_env.api_base_url)


@pytest.fixture(scope="session")
def login_form(request: pytest.FixtureRequest, e2e_env: Any) -> LoginForm:
    """The product's `LoginForm`, skipping the case when it declares none."""
    form = browser_contract(request.config, e2e_env).login_form
    if form is None:
        pytest.skip(
            "no pytest_e2e_login_form hook is implemented, so the shared suite does not "
            "know how to sign in through this product's UI"
        )
    return form


@pytest.fixture
def signed_in_page(page: Any, login_form: LoginForm, e2e_env: Any) -> Any:
    """A page that has signed in as the durable e2e user through the real UI.

    The real form rather than an injected token, because the thing worth proving is that
    the deployed login page still works, and an injected session proves only that the app
    reads a session it was handed.
    """
    sign_in(page, login_form, e2e_env)
    return page


def sign_in(page: Any, form: LoginForm, env: Any) -> None:
    """Fill and submit the login form, then wait for the signed-in marker.

    The password reaches `Locator.fill` and nowhere else. A timeout here is reported as
    the sign-in failing, with no value from the form in the message.
    """
    page.goto(form.path, wait_until="domcontentloaded")
    page.fill(form.email, env.user_email)
    page.fill(form.password, env.user_password)
    page.click(form.submit)
    try:
        page.wait_for_selector(form.signed_in_marker, state="visible", timeout=env.browser_timeout_ms)
    except Exception as error:
        raise BrowserFailure(
            f"signing in as the durable e2e user through {form.path} never showed "
            f"{form.signed_in_marker}, so the deployed login page does not complete a "
            f"sign-in ({type(error).__name__})"
        ) from None


@dataclass(frozen=True)
class BrowserContract:
    """What the product declared through the three browser hooks, gathered once."""

    login_form: LoginForm | None = None
    routes: tuple[RouteSpec, ...] = ()
    journeys: tuple[Journey, ...] = ()


def browser_contract(config: pytest.Config, env: Any) -> BrowserContract:
    """The product's browser declarations, called once per session and cached on the config.

    The parametrisation hook runs at collection, before any fixture, and the fixtures want
    the same objects, so the hooks are called exactly once and both read the cache.
    """
    cached = getattr(config, "_webbpulse_e2e_browser_contract", None)
    if isinstance(cached, BrowserContract):
        return cached
    hook = config.hook
    built = BrowserContract(
        login_form=_one(hook, "pytest_e2e_login_form", env),
        routes=tuple(_many(hook, "pytest_e2e_routes", env)),
        journeys=tuple(_many(hook, "pytest_e2e_journeys", env)),
    )
    config._webbpulse_e2e_browser_contract = built  # type: ignore[attr-defined]
    return built


def _one(hook: Any, name: str, env: Any) -> Any:
    """Call a firstresult hook by name, tolerating a product that implements none."""
    caller = getattr(hook, name, None)
    if caller is None:
        return None
    return caller(env=env)


def _many(hook: Any, name: str, env: Any) -> Sequence[Any]:
    """Call a firstresult hook expected to return a sequence, or an empty one."""
    result = _one(hook, name, env)
    return tuple(result) if result else ()
