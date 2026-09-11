"""Domain discovery for the per-domain pytest matrix.

A service's test suite grows with its domains, and running it as one pytest invocation
makes CI slower every time a domain is added. The reusable `python-ci.yml` workflow instead
runs one job per domain, in parallel, so wall clock time tracks the *largest* domain rather
than the sum of all of them. This module is what tells that workflow which jobs to create.

The convention is declarative and lives in the service's own `pyproject.toml`, so adding a
domain to CI is adding a line rather than editing a workflow::

    [tool.webbpulse.ci]
    test-root = "tests"

    [tool.webbpulse.ci.domains]
    identity = ["tests/auth", "tests/dependencies"]
    catalog = ["tests/api/endpoints/test_parts.py", "tests/api/endpoints/test_categories.py"]

Each key is a domain name and each value is the list of paths that domain owns, relative to
the directory holding `pyproject.toml`. A path may be a directory or a single test file,
because a suite that is not yet split by directory still has to be splittable: requiring the
files to move first would make adopting this a refactor rather than a configuration change.

Everything under `test-root` that no domain claims belongs to the `shared` job, which this
module computes as a *deselection* rather than a list. `shared` runs the whole test root
with `--ignore` for every claimed path, so a new test file is covered by CI the moment it is
written. The failure mode of forgetting to claim a file is that it runs in `shared`, which
is slower but never silent, and that is the right direction for the mistake to fall.

Two commands, both of which write to stdout and are meant to be consumed by a workflow:

`python -m webbpulse.ci domains`
    A JSON array of domain names, for `fromJson` in a matrix `strategy`.

`python -m webbpulse.ci pytest-args --domain <name>`
    The pytest path arguments for one job. For a domain, its claimed paths. For the reserved
    name `shared`, the test root followed by `--ignore=` for every claimed path.

Nothing here imports pytest, FastAPI or boto3. The workflow calls it in a bare interpreter
before dependencies are installed, so the only import is the standard library.
"""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "SHARED_DOMAIN",
    "CiConfig",
    "load_config",
    "main",
    "pytest_args_for",
]

#: The reserved job name for everything no domain claims. Not usable as a domain name,
#: because the two would produce the same job and the matrix would collide.
SHARED_DOMAIN = "shared"

#: Where the convention lives. A nested table rather than a top-level `[webbpulse]` so it
#: cannot collide with a tool that claims the same name, per PEP 518's `[tool.*]` rule.
_CONFIG_PATH = ("tool", "webbpulse", "ci")


@dataclass(frozen=True)
class CiConfig:
    """A service's parsed `[tool.webbpulse.ci]` table.

    `domains` maps a domain name to the paths it owns. `test_root` is the directory the
    `shared` job sweeps. Both are relative to the directory holding `pyproject.toml`, which
    is the workflow's `working-directory`, so the strings can be passed to pytest unchanged.
    """

    test_root: str
    domains: dict[str, tuple[str, ...]]

    @property
    def domain_names(self) -> tuple[str, ...]:
        """Domain names in sorted order, so the matrix is stable across runs.

        A matrix whose order changed between runs would renumber the jobs in the GitHub UI
        and make a required status check's name unstable, so this is sorted rather than
        left in the order the TOML happened to declare.
        """
        return tuple(sorted(self.domains))

    @property
    def claimed_paths(self) -> tuple[str, ...]:
        """Every path claimed by any domain, sorted and de-duplicated."""
        seen: set[str] = set()
        for paths in self.domains.values():
            seen.update(paths)
        return tuple(sorted(seen))


def load_config(project_dir: Path | str = ".") -> CiConfig:
    """Read `[tool.webbpulse.ci]` from `project_dir/pyproject.toml`.

    A missing file, a missing table or an empty `domains` table all produce a config with no
    domains rather than an error. That is deliberate: a repository that has not adopted the
    convention still calls this command through the shared workflow, and it should get an
    empty matrix and a `shared` job carrying its whole suite, which is exactly the behaviour
    it had before the split existed.

    Raises `ValueError` only for a table that is present but malformed, because that is a
    typo in the service's configuration and failing loudly is what surfaces it.
    """
    root = Path(project_dir)
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        return CiConfig(test_root="tests", domains={})

    with pyproject.open("rb") as handle:
        document = tomllib.load(handle)

    table: object = document
    for key in _CONFIG_PATH:
        if not isinstance(table, dict):
            return CiConfig(test_root="tests", domains={})
        table = table.get(key, {})
    if not isinstance(table, dict):
        raise ValueError("[tool.webbpulse.ci] must be a table")

    test_root = table.get("test-root", "tests")
    if not isinstance(test_root, str):
        raise ValueError("[tool.webbpulse.ci] test-root must be a string")

    raw_domains = table.get("domains", {})
    if not isinstance(raw_domains, dict):
        raise ValueError("[tool.webbpulse.ci.domains] must be a table")

    domains: dict[str, tuple[str, ...]] = {}
    for name, paths in raw_domains.items():
        if name == SHARED_DOMAIN:
            raise ValueError(
                f"{SHARED_DOMAIN!r} is reserved for the job carrying everything no domain "
                "claims, so it cannot also be a domain name"
            )
        if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths):
            raise ValueError(f"domain {name!r} must map to a list of path strings")
        if not paths:
            raise ValueError(
                f"domain {name!r} claims no paths, so its job would run nothing; remove the "
                "entry or give it paths"
            )
        domains[name] = tuple(paths)

    return CiConfig(test_root=test_root, domains=domains)


def pytest_args_for(config: CiConfig, domain: str) -> tuple[str, ...]:
    """The pytest path arguments for one matrix job.

    For a domain, the paths it claims. For `shared`, the test root with an `--ignore` for
    every claimed path, so the two kinds of job together run each test exactly once: a file
    claimed by a domain is ignored by `shared`, and a file claimed by nobody is swept up by
    `shared` without anyone having to remember to list it.
    """
    if domain == SHARED_DOMAIN:
        return (config.test_root, *(f"--ignore={path}" for path in config.claimed_paths))
    try:
        return config.domains[domain]
    except KeyError:
        known = ", ".join((*config.domain_names, SHARED_DOMAIN)) or SHARED_DOMAIN
        raise KeyError(f"unknown domain {domain!r}; declared domains are: {known}") from None


def _shell_quote(value: str) -> str:
    """Quote one argument for the `run:` line that consumes this output.

    The workflow interpolates the result into a shell command, and a path containing a space
    would otherwise split into two arguments and make pytest collect a directory that does
    not exist. Single quotes because no other character is special inside them.
    """
    return "'" + value.replace("'", "'\\''") + "'"


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for `python -m webbpulse.ci`."""
    parser = argparse.ArgumentParser(
        prog="python -m webbpulse.ci",
        description="Domain discovery for the WebbPulse per-domain pytest matrix.",
    )
    parser.add_argument(
        "--project-dir",
        default=".",
        help="Directory holding pyproject.toml. Defaults to the working directory.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    domains_parser = subcommands.add_parser(
        "domains",
        help="Print the declared domain names as a JSON array, for a workflow matrix.",
    )
    domains_parser.add_argument(
        "--include-shared",
        action="store_true",
        help=(
            f"Append {SHARED_DOMAIN!r} to the array. The workflow runs that job separately "
            "so it can carry different coverage settings, so this is off by default."
        ),
    )

    args_parser = subcommands.add_parser(
        "pytest-args",
        help="Print the pytest path arguments for one domain, shell quoted.",
    )
    args_parser.add_argument(
        "--domain",
        required=True,
        help=f"Domain name, or {SHARED_DOMAIN!r} for everything no domain claims.",
    )

    args = parser.parse_args(argv)

    try:
        config = load_config(args.project_dir)
    except (ValueError, tomllib.TOMLDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if args.command == "domains":
        names = list(config.domain_names)
        if args.include_shared:
            names.append(SHARED_DOMAIN)
        print(json.dumps(names))
        return 0

    try:
        print(" ".join(_shell_quote(arg) for arg in pytest_args_for(config, args.domain)))
    except KeyError as error:
        print(f"error: {error.args[0]}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess
    raise SystemExit(main())
