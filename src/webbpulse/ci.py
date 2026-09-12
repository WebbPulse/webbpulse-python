"""Domain discovery for the per-domain pytest matrix.

Reads `[tool.webbpulse.ci]` from a service's `pyproject.toml` and prints either the
declared domain names or the pytest path arguments for one matrix job.
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

SHARED_DOMAIN = "shared"

_CONFIG_PATH = ("tool", "webbpulse", "ci")


@dataclass(frozen=True)
class CiConfig:
    """A service's parsed `[tool.webbpulse.ci]` table.

    `domains` maps a domain name to the paths it owns and `test_root` is the directory the
    `shared` job sweeps, both relative to the directory holding `pyproject.toml`.
    """

    test_root: str
    domains: dict[str, tuple[str, ...]]

    @property
    def domain_names(self) -> tuple[str, ...]:
        """Domain names in sorted order, so the matrix is stable across runs."""
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

    A missing file, table or `domains` entry yields a config with no domains; a table that
    is present but malformed raises `ValueError`.
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
                f"domain {name!r} claims no paths, so its job would run nothing; remove the entry or give it paths"
            )
        domains[name] = tuple(paths)

    return CiConfig(test_root=test_root, domains=domains)


def pytest_args_for(config: CiConfig, domain: str) -> tuple[str, ...]:
    """The pytest path arguments for one matrix job.

    A domain gets the paths it claims; `shared` gets the test root with an `--ignore` for
    every claimed path, so the jobs together run each test exactly once.
    """
    if domain == SHARED_DOMAIN:
        return (config.test_root, *(f"--ignore={path}" for path in config.claimed_paths))
    try:
        return config.domains[domain]
    except KeyError:
        known = ", ".join((*config.domain_names, SHARED_DOMAIN)) or SHARED_DOMAIN
        raise KeyError(f"unknown domain {domain!r}; declared domains are: {known}") from None


def _shell_quote(value: str) -> str:
    """Single quote one argument for the `run:` shell line that consumes this output."""
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


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
