"""The configuration tarball a plan-only run is started from."""

from __future__ import annotations

import io
import os
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

SKIPPED_DIRECTORIES = frozenset({".git", ".terraform"})
"""Directories left out at any depth when there is no `.terraformignore`, as HCP Terraform does."""

IGNORE_FILE = ".terraformignore"

MAX_UPLOAD_BYTES = 250 * 1024 * 1024
"""The largest configuration version the control plane accepts."""


class ArchiveError(Exception):
    """The directory cannot be packaged for the workspace."""


@dataclass(frozen=True)
class _Rule:
    """One `.terraformignore` line."""

    pattern: re.Pattern[str]
    negated: bool
    directory_only: bool


def _glob_to_regex(glob: str) -> str:
    """A regex for a gitignore-style glob, where `**` crosses directories and `*` does not."""
    out: list[str] = []
    index = 0
    while index < len(glob):
        if glob.startswith("**/", index):
            out.append("(?:.*/)?")
            index += 3
        elif glob.startswith("/**", index) and index + 3 == len(glob):
            out.append("(?:/.*)?")
            index += 3
        elif glob.startswith("**", index):
            out.append(".*")
            index += 2
        elif glob[index] == "*":
            out.append("[^/]*")
            index += 1
        elif glob[index] == "?":
            out.append("[^/]")
            index += 1
        else:
            out.append(re.escape(glob[index]))
            index += 1
    return "".join(out)


def parse_ignore(text: str) -> list[_Rule]:
    """The rules in a `.terraformignore`, with gitignore's anchoring, negation and directory rules."""
    rules: list[_Rule] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        negated = line.startswith("!")
        if negated:
            line = line[1:]
        directory_only = line.endswith("/")
        line = line.rstrip("/")
        if not line:
            continue
        anchored = "/" in line
        body = _glob_to_regex(line.lstrip("/"))
        prefix = "" if anchored else "(?:.*/)?"
        rules.append(_Rule(re.compile(f"^{prefix}{body}$"), negated, directory_only))
    return rules


def _ignored(rules: list[_Rule], relative: str, is_directory: bool) -> bool:
    """Whether the last rule matching `relative` excludes it."""
    ignored = False
    for rule in rules:
        if rule.directory_only and not is_directory:
            continue
        if rule.pattern.match(relative):
            ignored = not rule.negated
    return ignored


def upload_root(directory: Path, working_directory: str) -> Path:
    """The directory to tar so that `working_directory` inside it is `directory`.

    A workspace with a working directory plans from that path inside the tarball, so the
    tarball has to start that many levels above `directory`, the way HCP Terraform uploads
    from the repository root. `directory` must end with the working directory's segments.

    Raises:
        ArchiveError: `directory` is not the workspace's working directory.
    """
    resolved = directory.resolve()
    if not resolved.is_dir():
        raise ArchiveError(f"{directory} is not a directory")
    parts = PurePosixPath(working_directory.strip().strip("/")).parts if working_directory.strip() else ()
    if not parts:
        return resolved
    if tuple(resolved.parts[-len(parts) :]) != parts or len(resolved.parts) <= len(parts):
        raise ArchiveError(
            f"the workspace plans from '{'/'.join(parts)}', so run wp-tf from that directory of the repository"
        )
    return resolved.parents[len(parts) - 1]


def build_tarball(directory: Path, working_directory: str = "") -> bytes:
    """A gzipped tar of the configuration, rooted where the workspace expects it.

    A `.terraformignore` at the upload root filters it the way HCP Terraform does, and
    `.git` and `.terraform` directories are always skipped. Symlinks are stored as links
    and never followed.

    Raises:
        ArchiveError: `directory` cannot be packaged, or the tarball is over the size limit.
    """
    root = upload_root(directory, working_directory)
    ignore_file = root / IGNORE_FILE
    rules = parse_ignore(ignore_file.read_text(encoding="utf-8")) if ignore_file.is_file() else []
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for current, dirnames, filenames in os.walk(root):
            base = Path(current)
            kept: list[str] = []
            for name in sorted(dirnames):
                path = base / name
                relative = path.relative_to(root).as_posix()
                if name in SKIPPED_DIRECTORIES or _ignored(rules, relative, True):
                    continue
                if path.is_symlink():
                    archive.add(path, arcname=relative, recursive=False)
                else:
                    kept.append(name)
            dirnames[:] = kept
            for name in sorted(filenames):
                path = base / name
                relative = path.relative_to(root).as_posix()
                if not _ignored(rules, relative, False):
                    archive.add(path, arcname=relative, recursive=False)
            if buffer.tell() > MAX_UPLOAD_BYTES:
                break
    data = buffer.getvalue()
    if len(data) > MAX_UPLOAD_BYTES:
        raise ArchiveError(
            f"the configuration under {root} is over {MAX_UPLOAD_BYTES // (1024 * 1024)} MB; "
            f"list what the plan does not need in {root / IGNORE_FILE}"
        )
    return data


__all__ = [
    "IGNORE_FILE",
    "MAX_UPLOAD_BYTES",
    "SKIPPED_DIRECTORIES",
    "ArchiveError",
    "build_tarball",
    "parse_ignore",
    "upload_root",
]
