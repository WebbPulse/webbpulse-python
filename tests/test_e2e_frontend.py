"""Tests for the SPA shell, bundle and CORS preflight checks against fixture HTML.

Every case here stands for something that shipped silently: a shell that rendered an empty
root, a bundle joined against the wrong API base, and a preflight whose allow list had gone
stale against the headers the shared client sends.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from webbpulse.e2e.frontend import (
    BundleReport,
    allowed_headers,
    cors_preflight,
    fetch_bundle,
    missing_allowed_headers,
    script_sources,
    shell_looks_like_an_app,
)

SHELL = """<!doctype html>
<html lang="en">
  <head>
    <title>Example</title>
    <link rel="modulepreload" href="/assets/vendor-abc123.js" />
    <link rel="stylesheet" href="/assets/index-abc123.css" />
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/assets/index-abc123.js"></script>
  </body>
</html>
"""

EMPTY_SHELL = """<!doctype html>
<html><body><div id="root"></div></body></html>
"""

ERROR_PAGE = """<!doctype html>
<html><body><h1>404 Not Found</h1></body></html>
"""


def transport(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.Client:
    """An httpx client answering through a MockTransport."""
    return httpx.Client(transport=httpx.MockTransport(handler))


class TestShell:
    """Tests for telling the SPA shell from an error page or a blank deploy."""

    def test_a_real_shell_passes(self) -> None:
        """A mount point plus a script is the shell."""
        assert shell_looks_like_an_app(SHELL)

    def test_a_mount_point_with_no_script_fails(self) -> None:
        """A 200 whose body is an empty root and no script is the shipped-blank-page failure."""
        assert not shell_looks_like_an_app(EMPTY_SHELL)

    def test_an_error_page_fails(self) -> None:
        """An origin error page has no mount point, so a catch-all serving one is caught."""
        assert not shell_looks_like_an_app(ERROR_PAGE)

    def test_an_empty_body_fails(self) -> None:
        """An empty 200 passes nothing, rather than passing for want of a marker to fail on."""
        assert not shell_looks_like_an_app("")
        assert not shell_looks_like_an_app("   \n  ")

    def test_an_app_div_is_also_a_mount_point(self) -> None:
        """Some builds mount on `#app` rather than `#root`."""
        assert shell_looks_like_an_app('<div id="app"></div><script src="/a.js"></script>')


class TestScriptSources:
    """Tests for finding every chunk the shell references."""

    def test_it_finds_the_entry_script_and_the_preload(self) -> None:
        """A code-split build can put the API client in any chunk, so preloads count too."""
        assert script_sources(SHELL) == ("/assets/index-abc123.js", "/assets/vendor-abc123.js")

    def test_stylesheets_are_not_scripts(self) -> None:
        """A CSS preload is not a chunk to search for an API base URL."""
        assert "/assets/index-abc123.css" not in script_sources(SHELL)

    def test_a_query_string_still_counts(self) -> None:
        """A cache-busted chunk is still a chunk."""
        assert script_sources('<script src="/main.js?v=2"></script>') == ("/main.js?v=2",)

    def test_duplicates_are_collapsed(self) -> None:
        """A chunk named twice is fetched once."""
        html = '<script src="/a.js"></script><link rel="modulepreload" href="/a.js" />'
        assert script_sources(html) == ("/a.js",)

    def test_a_shell_with_no_scripts_yields_nothing(self) -> None:
        """Nothing to fetch is an empty tuple, not a crash."""
        assert script_sources(EMPTY_SHELL) == ()


class TestFetchBundle:
    """Tests for fetching and concatenating the chunks."""

    def test_every_chunk_is_fetched_and_concatenated(self) -> None:
        """Both the entry chunk and the preloaded vendor chunk are read."""
        bodies = {
            "/assets/index-abc123.js": 'const base="https://api.staging.example.invalid";',
            "/assets/vendor-abc123.js": "export const x=1;",
        }

        def handle(request: httpx.Request) -> httpx.Response:
            """Answer each chunk with its body."""
            return httpx.Response(200, text=bodies[request.url.path])

        report = fetch_bundle(transport(handle), "https://www.staging.example.invalid", SHELL)
        assert report.chunks == 2
        assert report.contains("https://api.staging.example.invalid")

    def test_a_relative_source_is_joined_against_the_web_origin(self) -> None:
        """A relative chunk path resolves against the deployed origin, not against the API."""
        seen: list[str] = []

        def handle(request: httpx.Request) -> httpx.Response:
            """Record the URL and answer empty."""
            seen.append(str(request.url))
            return httpx.Response(200, text="")

        fetch_bundle(transport(handle), "https://www.staging.example.invalid", '<script src="assets/a.js"></script>')
        assert seen == ["https://www.staging.example.invalid/assets/a.js"]

    def test_a_missing_chunk_is_skipped_rather_than_raised_on(self) -> None:
        """A 404 chunk must not hide which strings the chunks that did load carry."""

        def handle(request: httpx.Request) -> httpx.Response:
            """Answer the entry chunk and 404 the vendor chunk."""
            if request.url.path.endswith("vendor-abc123.js"):
                return httpx.Response(404)
            return httpx.Response(200, text="const a=1;")

        report = fetch_bundle(transport(handle), "https://www.staging.example.invalid", SHELL)
        assert report.chunks == 1
        assert report.fetched == ["https://www.staging.example.invalid/assets/index-abc123.js"]

    def test_a_trailing_slash_on_the_origin_does_not_double(self) -> None:
        """The origin is normalised, so the chunk URL carries exactly one slash."""
        seen: list[str] = []

        def handle(request: httpx.Request) -> httpx.Response:
            """Record the URL and answer empty."""
            seen.append(str(request.url))
            return httpx.Response(200, text="")

        fetch_bundle(transport(handle), "https://www.staging.example.invalid/", '<script src="/a.js"></script>')
        assert seen == ["https://www.staging.example.invalid/a.js"]


class TestBundleReport:
    """Tests for what a fetched bundle is asked about."""

    def test_missing_names_the_strings_the_bundle_lacks(self) -> None:
        """A bundle built against the wrong API base lacks the expected origin."""
        report = BundleReport(text='fetch("https://api.production.example.invalid/api/parts")')
        assert report.missing(["https://api.staging.example.invalid"]) == ("https://api.staging.example.invalid",)

    def test_missing_is_empty_when_everything_is_present(self) -> None:
        """A correctly built bundle is missing nothing."""
        report = BundleReport(text="https://api.staging.example.invalid")
        assert report.missing(["https://api.staging.example.invalid"]) == ()

    def test_present_names_the_legacy_strings_that_should_be_gone(self) -> None:
        """A legacy route name still in the bundle is the failure, so `present` is the check."""
        report = BundleReport(text='post("/api/auth/token")')
        assert report.present(["/api/auth/token", "/api/auth/2fa"]) == ("/api/auth/token",)


class TestCorsPreflight:
    """Tests for the preflight and its allow list."""

    def test_the_preflight_carries_the_origin_and_the_requested_headers(self) -> None:
        """The preflight asks about exactly the headers the shared client sends."""
        seen: list[httpx.Request] = []

        def handle(request: httpx.Request) -> httpx.Response:
            """Record the preflight and allow everything asked for."""
            seen.append(request)
            return httpx.Response(204, headers={"access-control-allow-headers": "authorization, content-type"})

        cors_preflight(
            transport(handle),
            "https://api.staging.example.invalid",
            "/api/parts",
            origin="https://www.staging.example.invalid",
            request_headers=("authorization", "content-type"),
        )
        assert seen[0].method == "OPTIONS"
        assert seen[0].headers["origin"] == "https://www.staging.example.invalid"
        assert seen[0].headers["access-control-request-headers"] == "authorization, content-type"
        assert seen[0].headers["access-control-request-method"] == "POST"

    def test_allowed_headers_are_lowercased(self) -> None:
        """Header names are case insensitive, so the comparison is done in one case."""
        response = httpx.Response(204, headers={"access-control-allow-headers": "Authorization, Content-Type"})
        assert allowed_headers(response) == frozenset({"authorization", "content-type"})

    def test_a_missing_header_is_reported(self) -> None:
        """A retry header the client sends and the gateway does not allow is the finding."""
        response = httpx.Response(204, headers={"access-control-allow-headers": "authorization, content-type"})
        missing = missing_allowed_headers(response, ["authorization", "content-type", "x-retry-attempt"])
        assert missing == ("x-retry-attempt",)

    def test_a_wildcard_allows_everything(self) -> None:
        """A wildcard allow list is not a finding, however long the wanted list is."""
        response = httpx.Response(204, headers={"access-control-allow-headers": "*"})
        assert missing_allowed_headers(response, ["authorization", "x-anything"]) == ()

    def test_no_allow_header_at_all_reports_every_wanted_header(self) -> None:
        """A preflight the gateway does not answer leaves every client header unallowed."""
        assert missing_allowed_headers(httpx.Response(204), ["authorization"]) == ("authorization",)

    @pytest.mark.parametrize("raw", ["authorization,content-type", " authorization ,  content-type "])
    def test_whitespace_in_the_allow_list_is_tolerated(self, raw: str) -> None:
        """The allow list is parsed the way a browser parses it, whitespace and all."""
        response = httpx.Response(204, headers={"access-control-allow-headers": raw})
        assert missing_allowed_headers(response, ["authorization", "content-type"]) == ()
