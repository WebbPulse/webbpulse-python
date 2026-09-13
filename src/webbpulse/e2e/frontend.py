"""Checks against the deployed SPA: the shell, the catch-all, the bundle and CORS.

Every check here exists because something shipped silently. A router with no catch-all
rendered an empty root on any unknown URL; a bundle joined the wrong API base and the UI
rendered as signed out; a retry header missing from the gateway's CORS allow list made the
client's own retries fail cross-origin. None of it is visible to a server-side probe of the
API, and all of it is one fetch away from being caught.

The bundle is fetched over HTTPS from the deployed web origin, and every script the shell
references is read, not only the entry chunk, since a code-split build can put the API
client anywhere.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

__all__ = [
    "SHELL_MARKERS",
    "BundleReport",
    "cors_preflight",
    "fetch_bundle",
    "script_sources",
    "shell_looks_like_an_app",
]

SHELL_MARKERS = ('<div id="root"', "<div id='root'", '<div id="app"', "<div id='app'")

_SCRIPT_SRC = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)
_MODULE_PRELOAD = re.compile(
    r"""<link[^>]+rel=["'](?:modulepreload|preload)["'][^>]+href=["']([^"']+\.js)["']""",
    re.IGNORECASE,
)


def shell_looks_like_an_app(html: str) -> bool:
    """Whether a response body is the SPA shell rather than an error page or a redirect.

    A mount point plus at least one script is the bar. A 200 whose body is an empty root
    with no script is exactly the shipped-blank-page failure, so an empty body passes
    nothing.
    """
    if not html.strip():
        return False
    has_mount = any(marker in html for marker in SHELL_MARKERS)
    return has_mount and bool(script_sources(html))


def script_sources(html: str) -> tuple[str, ...]:
    """Every JS asset the shell references, from `<script src>` and module preloads."""
    found = [*_SCRIPT_SRC.findall(html), *_MODULE_PRELOAD.findall(html)]
    seen: dict[str, None] = {}
    for source in found:
        if source.endswith(".js") or ".js?" in source:
            seen.setdefault(source, None)
    return tuple(seen)


@dataclass
class BundleReport:
    """What the deployed bundle contains, and which of the expected strings it is missing."""

    chunks: int = 0
    text: str = ""
    fetched: list[str] = field(default_factory=list)

    def contains(self, needle: str) -> bool:
        """Whether the concatenated bundle mentions a string."""
        return needle in self.text

    def missing(self, needles: Iterable[str]) -> tuple[str, ...]:
        """Those of `needles` the bundle does not mention."""
        return tuple(needle for needle in needles if needle not in self.text)

    def present(self, needles: Iterable[str]) -> tuple[str, ...]:
        """Those of `needles` the bundle does mention, which is the failure for legacy names."""
        return tuple(needle for needle in needles if needle in self.text)


def fetch_bundle(client: httpx.Client, web_base_url: str, shell_html: str) -> BundleReport:
    """Fetch every JS chunk the shell references and concatenate them.

    A chunk that does not answer 200 is skipped rather than raised on: a missing chunk is
    already a finding the shell check reports, and failing here would hide which strings the
    chunks that did load carry.
    """
    report = BundleReport()
    base = web_base_url if web_base_url.endswith("/") else web_base_url + "/"
    for source in script_sources(shell_html):
        url = urljoin(base, source)
        response = client.get(url)
        if response.status_code != 200:
            continue
        report.text += response.text
        report.chunks += 1
        report.fetched.append(url)
    return report


def cors_preflight(
    client: httpx.Client,
    api_base_url: str,
    path: str,
    *,
    origin: str,
    method: str = "POST",
    request_headers: Sequence[str],
) -> httpx.Response:
    """Send one CORS preflight from the web origin to the API.

    The header list comes from the product conftest, read off `@webbpulse/api-client` by
    name, because the allow list only has to cover the headers the shared client actually
    sends and a hand-kept copy of that list is what went stale.
    """
    url = api_base_url.rstrip("/") + path
    return client.request(
        "OPTIONS",
        url,
        headers={
            "origin": origin,
            "access-control-request-method": method,
            "access-control-request-headers": ", ".join(request_headers),
        },
    )


def allowed_headers(response: httpx.Response) -> frozenset[str]:
    """The lowercased header names a preflight response allows."""
    raw = response.headers.get("access-control-allow-headers", "")
    if raw.strip() == "*":
        return frozenset({"*"})
    return frozenset(name.strip().lower() for name in raw.split(",") if name.strip())


def missing_allowed_headers(response: httpx.Response, wanted: Iterable[str]) -> tuple[str, ...]:
    """Those of `wanted` a preflight response does not allow, wildcard honoured."""
    allowed: Mapping[str, None] | frozenset[str] = allowed_headers(response)
    if "*" in allowed:
        return ()
    return tuple(name for name in wanted if name.lower() not in allowed)
