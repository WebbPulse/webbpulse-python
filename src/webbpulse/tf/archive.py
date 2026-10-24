"""The configuration tarball a plan-only run is started from."""

from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import tarfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any, Literal

SKIPPED_DIRECTORIES = frozenset({".git"})
"""Directories always left out, at any depth, whatever `.terraformignore` says."""

SKIPPED_FILES = re.compile(r"^(?:.*\.tfstate|.*\.tfstate\.backup|\.terraform\.tfstate\.lock\.info)$")
"""Local state files, always left out: a remote run has its own state, and these hold secrets."""

IGNORE_FILE = ".terraformignore"

DEFAULT_IGNORE = ".git/\n.terraform/\n!.terraform/modules/\n"
"""go-slug's default exclusions, applied before any `.terraformignore` rule."""

MAX_UPLOAD_BYTES = 250_000_000
"""The largest configuration version the control plane accepts."""

GIT_TIMEOUT_SECONDS = 60
"""How long a `git` call may take before the bundle is built without gitignore rules."""

IgnoreSource = Literal["terraformignore", "gitignore", "defaults"]
"""Which rules filtered a bundle beyond the defaults."""


class ArchiveError(Exception):
    """The directory cannot be packaged for the workspace."""


def format_size(size_bytes: int) -> str:
    """A byte count in the unit people read it in."""
    if size_bytes >= 1_000_000:
        return f"{size_bytes / 1_000_000:.1f} MB"
    if size_bytes >= 1_000:
        return f"{size_bytes / 1_000:.1f} KB"
    return f"{size_bytes} bytes"


class _CappedBuffer(io.BytesIO):
    """An in-memory buffer that refuses to grow past `MAX_UPLOAD_BYTES`."""

    def __init__(self, root: Path) -> None:
        """Remember the root to name in the refusal."""
        super().__init__()
        self.root = root

    def write(self, data: Any, /) -> int:
        """Write, or raise once the archive would pass the limit."""
        if self.tell() + len(data) > MAX_UPLOAD_BYTES:
            raise ArchiveError(
                f"the configuration under {self.root} is over the {format_size(MAX_UPLOAD_BYTES)} limit; "
                f"list what the plan does not need in {self.root / IGNORE_FILE}"
            )
        return super().write(data)


@dataclass(frozen=True)
class _Rule:
    """One `.terraformignore` line, compiled the way go-slug reads it."""

    pattern: re.Pattern[str]
    negated: bool
    directory_only: bool
    segments: tuple[str, ...]


@dataclass(frozen=True)
class ConfigBundle:
    """A built configuration tarball and what it was filtered by."""

    data: bytes
    root: Path
    files: int
    ignore_source: IgnoreSource
    gitignored: int = 0

    @property
    def size(self) -> int:
        """The tarball's length in bytes, which is what is uploaded."""
        return len(self.data)

    def describe(self) -> str:
        """One line naming the size, the file count and the rules that filtered it."""
        filtered = {
            "terraformignore": f"filtered by {IGNORE_FILE}",
            "gitignore": f"left out {self.gitignored} gitignored path{'' if self.gitignored == 1 else 's'}",
            "defaults": f"no {IGNORE_FILE} and not in a git work tree, so only the defaults apply",
        }[self.ignore_source]
        return f"{format_size(self.size)}, {self.files} file{'' if self.files == 1 else 's'}; {filtered}"


def _glob_to_regex(glob: str) -> str:
    """A regex for a go-slug glob, where `**` crosses directories and `*` and `?` do not."""
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
        elif glob[index] == "\\" and index + 1 < len(glob):
            out.append(re.escape(glob[index + 1]))
            index += 2
        elif glob[index] == "[" and (end := glob.find("]", index + 2)) != -1:
            body = glob[index + 1 : end].replace("\\", "\\\\")
            if body.startswith("!"):
                body = "^" + body[1:]
            out.append(f"[{body}]")
            index = end + 1
        else:
            out.append(re.escape(glob[index]))
            index += 1
    return "".join(out)


@lru_cache(maxsize=256)
def _segment(glob: str) -> re.Pattern[str]:
    """The regex one path segment of a glob compiles to."""
    return re.compile(_glob_to_regex(glob))


def parse_ignore(text: str) -> list[_Rule]:
    """The rules in a `.terraformignore`, read the way HCP Terraform's go-slug reads them.

    Blank lines and `#` comments are skipped and `!` negates. A leading `/` anchors a
    pattern to the upload root, and any other pattern matches at any depth, even one
    with a slash in the middle. A trailing `/` matches only directories and what is in
    them. A pattern that matches a directory also matches everything under it.
    """
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
        anchored = line.startswith("/")
        line = line.lstrip("/")
        if not line:
            continue
        glob = line if anchored else f"**/{line}"
        rules.append(_Rule(re.compile(f"^{_glob_to_regex(glob)}$"), negated, directory_only, tuple(glob.split("/"))))
    return rules


def _rule_matches(rule: _Rule, relative: str, is_directory: bool) -> bool:
    """Whether `rule` matches the path or one of the directories it sits in."""
    if rule.pattern.match(relative) and (is_directory or not rule.directory_only):
        return True
    parent = relative
    while "/" in parent:
        parent = parent.rsplit("/", 1)[0]
        if rule.pattern.match(parent):
            return True
    return False


def _decision(rules: list[_Rule], relative: str, is_directory: bool) -> tuple[bool, int]:
    """Whether the last rule matching `relative` excludes it, and that rule's index."""
    ignored, deciding = False, -1
    for index, rule in enumerate(rules):
        if _rule_matches(rule, relative, is_directory):
            ignored, deciding = not rule.negated, index
    return ignored, deciding


def _could_match_below(segments: tuple[str, ...], parts: tuple[str, ...]) -> bool:
    """Whether a glob's segments could match some path strictly inside the directory `parts`."""
    if not parts:
        return bool(segments)
    if not segments:
        return False
    head = segments[0]
    if head == "**":
        return _could_match_below(segments[1:], parts) or _could_match_below(segments, parts[1:])
    return _segment(head).fullmatch(parts[0]) is not None and _could_match_below(segments[1:], parts[1:])


def _prunable(rules: list[_Rule], relative: str, deciding: int) -> bool:
    """Whether no later negation could bring back anything under an excluded directory."""
    parts = tuple(relative.split("/"))
    return not any(rule.negated and _could_match_below(rule.segments, parts) for rule in rules[deciding + 1 :])


def git_ignored_paths(root: Path) -> frozenset[str] | None:
    """The untracked paths under `root` that git ignores, relative to it, or `None` without git.

    An ignored directory is one entry, not its contents. `None` means git is not
    installed, `root` is not inside a work tree, or git failed, so the caller goes on
    without gitignore rules.
    """
    git = shutil.which("git")
    if git is None:
        return None
    try:
        inside = subprocess.run(
            [git, "-C", str(root), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
        if inside.returncode != 0 or inside.stdout.strip() != "true":
            return None
        listed = subprocess.run(
            [git, "-C", str(root), "ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--directory"],
            capture_output=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if listed.returncode != 0:
        return None
    entries = (entry.decode("utf-8", "surrogateescape").rstrip("/") for entry in listed.stdout.split(b"\0"))
    return frozenset(entry for entry in entries if entry)


def _gitignored(ignored: frozenset[str], relative: str) -> bool:
    """Whether `relative` or a directory it sits in is in the gitignored set."""
    if relative in ignored:
        return True
    parent = relative
    while "/" in parent:
        parent = parent.rsplit("/", 1)[0]
        if parent in ignored:
            return True
    return False


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


def build_bundle(directory: Path, working_directory: str = "") -> ConfigBundle:
    """A gzipped tar of the configuration, rooted where the workspace expects it.

    go-slug's defaults always apply first: `.git/` and `.terraform/` are left out,
    `.terraform/modules/` is kept. A `.terraformignore` at the upload root then filters
    it the way HCP Terraform does. Without one, inside a git work tree, every path git
    ignores is left out as well; with no git it falls back to the defaults alone. `.git`
    and local `*.tfstate` files are always skipped, `.tfvars` files are configuration and
    are uploaded, and symlinks are stored as links and never followed.

    Raises:
        ArchiveError: `directory` cannot be packaged, or the tarball is over the size limit.
    """
    root = upload_root(directory, working_directory)
    ignore_file = root / IGNORE_FILE
    rules = parse_ignore(DEFAULT_IGNORE)
    gitignored: frozenset[str] = frozenset()
    source: IgnoreSource = "defaults"
    if ignore_file.is_file():
        rules += parse_ignore(ignore_file.read_text(encoding="utf-8"))
        source = "terraformignore"
    elif (found := git_ignored_paths(root)) is not None:
        gitignored, source = found, "gitignore"
    buffer = _CappedBuffer(root)
    files = 0
    left_out: set[str] = set()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for current, dirnames, filenames in os.walk(root):
            base = Path(current)
            kept: list[str] = []
            for name in sorted(dirnames):
                path = base / name
                relative = path.relative_to(root).as_posix()
                if name in SKIPPED_DIRECTORIES:
                    continue
                if _gitignored(gitignored, relative):
                    left_out.add(relative)
                    continue
                excluded, deciding = _decision(rules, relative, True)
                if excluded and _prunable(rules, relative, deciding):
                    continue
                if path.is_symlink():
                    if not excluded:
                        archive.add(path, arcname=relative, recursive=False)
                        files += 1
                else:
                    kept.append(name)
            dirnames[:] = kept
            for name in sorted(filenames):
                path = base / name
                relative = path.relative_to(root).as_posix()
                if SKIPPED_FILES.match(name):
                    continue
                if _gitignored(gitignored, relative):
                    left_out.add(relative)
                    continue
                if not _decision(rules, relative, False)[0]:
                    archive.add(path, arcname=relative, recursive=False)
                    files += 1
    return ConfigBundle(buffer.getvalue(), root, files, source, len(left_out))


def build_tarball(directory: Path, working_directory: str = "") -> bytes:
    """The bytes of `build_bundle`, for callers that only need the tarball.

    Raises:
        ArchiveError: `directory` cannot be packaged, or the tarball is over the size limit.
    """
    return build_bundle(directory, working_directory).data


__all__ = [
    "DEFAULT_IGNORE",
    "IGNORE_FILE",
    "MAX_UPLOAD_BYTES",
    "SKIPPED_DIRECTORIES",
    "SKIPPED_FILES",
    "ArchiveError",
    "ConfigBundle",
    "build_bundle",
    "build_tarball",
    "format_size",
    "git_ignored_paths",
    "parse_ignore",
    "upload_root",
]
