"""The hook specification products implement to clean up after an e2e run.

Separate from the plugin module so `pytest_addhooks` can register it without importing the
fixtures, which pluggy would then try to collect twice.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import pytest

__all__ = ["pytest_e2e_cleanup"]


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
