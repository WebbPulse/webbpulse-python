"""Shared test configuration.

Loads the package's own fixtures as a pytest plugin and holds every moto test to
DynamoDB's primary key rule.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from webbpulse.testing import CheckedKey

pytest_plugins = ["webbpulse.testing"]


@pytest.fixture(autouse=True)
def _primary_keys_only(primary_keys_only: list[CheckedKey]) -> list[CheckedKey]:
    """Refuse any key that is not exactly its table's primary key, as DynamoDB does."""
    return primary_keys_only
