"""Shared test configuration.

The package's own fixtures are loaded as a plugin, which is also how a consuming service
enables them, so the fixtures are exercised the way they are documented.
"""

from __future__ import annotations

pytest_plugins = ["webbpulse.testing"]
