"""Single source of truth for the package version.

`pyproject.toml` reads `__version__` from this file via hatchling, so a release is a
one-line edit here plus the matching `v<version>` tag.
"""

__version__ = "0.27.0"
