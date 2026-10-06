"""Shared test configuration.

Loads the package's own fixtures as a pytest plugin and holds every moto test to
DynamoDB's primary key rule. The OS keyring is replaced by keyring's null backend, so no
test can read or write a real credential store.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from webbpulse.testing import CheckedKey

pytest_plugins = ["webbpulse.testing"]

os.environ["PYTHON_KEYRING_BACKEND"] = "keyring.backends.null.Keyring"


@pytest.fixture(autouse=True)
def _primary_keys_only(primary_keys_only: list[CheckedKey]) -> list[CheckedKey]:
    """Refuse any key that is not exactly its table's primary key, as DynamoDB does."""
    return primary_keys_only


@pytest.fixture(autouse=True, scope="session")
def _cache_home(tmp_path_factory: pytest.TempPathFactory) -> None:
    """Keep device login lock files out of the real user cache directory."""
    os.environ["XDG_CACHE_HOME"] = str(tmp_path_factory.mktemp("cache"))
