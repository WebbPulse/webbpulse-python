"""The hook specifications products implement for cleanup and for the browser suite.

Separate from the plugin module so `pytest_addhooks` can register it without importing the
fixtures, which pluggy would then try to collect twice.

Every browser hook is optional. A product that implements none of them gets the browser
group skipped with a reason naming the hook it would need, rather than a failure, because
a product with no declared UI contract has nothing for the shared suite to assert about.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import pytest

__all__ = [
    "pytest_e2e_cleanup",
    "pytest_e2e_journeys",
    "pytest_e2e_login_form",
    "pytest_e2e_routes",
    "pytest_e2e_uncovered_routes",
]


@pytest.hookspec
def pytest_e2e_cleanup(env: Any, phase: str, created: Sequence[Any]) -> Any:
    """Delete resources this suite owns, at the start and the end of the session.

    Called twice per session. `phase` is `"start"`, where `created` is empty and the
    implementation should delete anything owned by the e2e user whose name carries the
    `e2e-` prefix and is older than an hour, or `"end"`, where `created` holds everything
    this run appended to the `created_resources` fixture.

    Return a falsy value when the sweep was clean, or a short description of what could not
    be deleted. A returned description is surfaced as a warning; it never fails the suite,
    since a leftover must not cost the result of the tests that already ran.
    """


@pytest.hookspec(firstresult=True)
def pytest_e2e_login_form(env: Any) -> Any:
    """Return the product's `LoginForm`, or None to skip every browser sign-in case.

    The locators are Playwright locator strings; the convention is `data-testid` values
    named `login-email`, `login-password`, `login-submit` and `sign-out`, with
    `signed_in_marker` naming an element that is visible only when authenticated.
    """


@pytest.hookspec(firstresult=True)
def pytest_e2e_routes(env: Any) -> Any:
    """Return the product's `Sequence[RouteSpec]`, or None to skip the route cases.

    Each spec declares a path and whether it is `"public"`, `"protected"` or
    `"guest-only"`. The guard cases assert where a visitor who may not see a route lands,
    and the render case asserts every declared route paints without a console error.
    """


@pytest.hookspec(firstresult=True)
def pytest_e2e_journeys(env: Any) -> Any:
    """Return the product's `Sequence[Journey]`, or None to skip the journey cases.

    A journey is a short list of steps against the real UI. One that sets `mutates=True`
    must carry at least one `Record` step, so whatever it creates reaches
    `created_resources` and the product's own `pytest_e2e_cleanup` deletes it. Browser
    journeys may mutate in both environments, which is exactly why the recording is
    mandatory.
    """


@pytest.hookspec(firstresult=True)
def pytest_e2e_uncovered_routes(env: Any) -> Any:
    """Return the routes this product knowingly leaves unexercised, or None for none.

    A mapping of `(method, path)` to the reason that pair is not worth covering, where the
    path is the route as the OpenAPI document spells it, template braces and all. The
    coverage case asserts that every served route was either exercised by this run or named
    here, so a route added without a test fails rather than passing unnoticed, and a reason
    that stops being true fails as a stale entry rather than silently excusing a gap.

    Only the allowlist is the product's: the matching, the staleness check and the empty
    reason check are the plugin's, so a product supplies the exceptions and nothing else.
    """
