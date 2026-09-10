"""Single source of truth for the package version.

`pyproject.toml` reads `__version__` from this file via hatchling's `[tool.hatch.version]`,
so a release is a one-line edit here plus the matching `v<version>` tag. Deriving the
version from the git tag instead would make an sdist built outside a checkout unversioned,
and CodeArtifact rejects that.
"""

__version__ = "0.10.0"
