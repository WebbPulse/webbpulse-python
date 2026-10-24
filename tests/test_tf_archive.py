"""Tests for `webbpulse.tf.archive`."""

from __future__ import annotations

import io
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

from webbpulse.tf.archive import (
    ArchiveError,
    build_bundle,
    build_tarball,
    format_size,
    git_ignored_paths,
    parse_ignore,
    upload_root,
)

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def _names(data: bytes) -> list[str]:
    """The member names in a gzipped tarball."""
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        return archive.getnames()


def _tree(root: Path) -> Path:
    """A repository with a configuration under infra/prod."""
    config = root / "repo" / "infra" / "prod"
    config.mkdir(parents=True)
    (config / "main.tf").write_text('resource "terraform_data" "x" {}\n')
    (config / ".terraform").mkdir()
    (config / ".terraform" / "plugin").write_text("big")
    (root / "repo" / ".git").mkdir()
    (root / "repo" / ".git" / "HEAD").write_text("ref")
    (root / "repo" / "modules").mkdir()
    (root / "repo" / "modules" / "m.tf").write_text("")
    return config


def test_no_working_directory_tars_the_directory(tmp_path: Path) -> None:
    """Without a working directory the tarball is rooted at the directory itself."""
    config = _tree(tmp_path)
    assert _names(build_tarball(config)) == ["main.tf"]


def test_working_directory_roots_at_the_repository(tmp_path: Path) -> None:
    """A working directory makes the tarball start that many levels up, skipping .git and .terraform."""
    config = _tree(tmp_path)
    names = _names(build_tarball(config, "infra/prod"))
    assert "infra/prod/main.tf" in names
    assert "modules/m.tf" in names
    assert not any(".git" in name or ".terraform" in name for name in names)


def test_mismatched_working_directory_is_refused(tmp_path: Path) -> None:
    """A directory that is not the workspace's working directory is refused."""
    config = _tree(tmp_path)
    with pytest.raises(ArchiveError, match="infra/staging"):
        upload_root(config, "infra/staging")


def test_missing_directory_is_refused(tmp_path: Path) -> None:
    """A path that is not a directory is refused."""
    with pytest.raises(ArchiveError):
        build_tarball(tmp_path / "absent")


def test_symlinked_directory_is_not_followed(tmp_path: Path) -> None:
    """A symlinked directory is stored as a link, not walked."""
    config = _tree(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.tf").write_text("")
    (config / "link").symlink_to(outside, target_is_directory=True)
    names = _names(build_tarball(config))
    assert "link" in names
    assert "link/secret.tf" not in names


def test_terraformignore_filters_the_upload(tmp_path: Path) -> None:
    """`.terraformignore` at the upload root excludes, anchors and negates like gitignore."""
    config = _tree(tmp_path)
    repo = tmp_path / "repo"
    (repo / "node_modules" / "pkg").mkdir(parents=True)
    (repo / "node_modules" / "pkg" / "index.js").write_text("")
    (repo / "infra" / "prod" / "notes.log").write_text("")
    (repo / "infra" / "prod" / "keep.log").write_text("")
    (repo / "docs").mkdir()
    (repo / "docs" / "a.md").write_text("")
    (repo / ".terraformignore").write_text("# comment\nnode_modules/\n*.log\n!keep.log\n/docs\n")
    names = _names(build_tarball(config, "infra/prod"))
    assert "infra/prod/main.tf" in names
    assert "infra/prod/keep.log" in names
    assert "infra/prod/notes.log" not in names
    assert not any(name.startswith(("node_modules", "docs")) for name in names)


def test_double_star_patterns() -> None:
    """`**` crosses directories and a slash anchors to the root."""
    rules = parse_ignore("a/**/b\n/top.txt\n")
    assert rules[0].pattern.match("a/b")
    assert rules[0].pattern.match("a/x/y/b")
    assert rules[1].pattern.match("top.txt")
    assert not rules[1].pattern.match("sub/top.txt")


def test_oversized_upload_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A tarball over the limit is refused before any upload, pointing at .terraformignore."""
    config = _tree(tmp_path)
    monkeypatch.setattr("webbpulse.tf.archive.MAX_UPLOAD_BYTES", 10)
    with pytest.raises(ArchiveError, match=r"\.terraformignore"):
        build_tarball(config)


def test_local_state_is_never_uploaded(tmp_path: Path) -> None:
    """Local state files are skipped even without a .terraformignore; tfvars are configuration."""
    config = _tree(tmp_path)
    for name in ("terraform.tfstate", "terraform.tfstate.backup", "old.tfstate", "prod.auto.tfvars"):
        (config / name).write_text("{}")
    names = _names(build_tarball(config))
    assert "prod.auto.tfvars" in names
    assert not any("tfstate" in name for name in names)


def _git_repo(root: Path) -> Path:
    """A git work tree at `root` with a configuration and an ignored virtualenv under backend."""
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / ".gitignore").write_text(".venv/\n*.secret\n")
    (root / "terraform").mkdir()
    (root / "terraform" / "main.tf").write_text("")
    (root / "terraform" / "untracked.tf").write_text("")
    (root / "terraform" / "local.secret").write_text("")
    venv = root / "backend" / ".venv" / "lib"
    venv.mkdir(parents=True)
    (venv / "big.so").write_bytes(b"x" * 1024)
    (root / "backend" / "app.py").write_text("")
    return root


@needs_git
def test_gitignored_paths_are_left_out_without_a_terraformignore(tmp_path: Path) -> None:
    """Inside a git work tree with no .terraformignore, what git ignores is not uploaded."""
    repo = _git_repo(tmp_path / "repo")
    bundle = build_bundle(repo)
    names = _names(bundle.data)
    assert "terraform/main.tf" in names
    assert "terraform/untracked.tf" in names
    assert "backend/app.py" in names
    assert not any(".venv" in name or name.endswith(".secret") for name in names)
    assert bundle.ignore_source == "gitignore"
    assert bundle.gitignored == 2
    assert "2 gitignored paths" in bundle.describe()


@needs_git
def test_a_subdirectory_of_a_work_tree_uses_the_repository_gitignore(tmp_path: Path) -> None:
    """Uploading from a subdirectory still reads the ignore rules of the repository around it."""
    repo = _git_repo(tmp_path / "repo")
    names = _names(build_tarball(repo / "terraform"))
    assert sorted(names) == ["main.tf", "untracked.tf"]


@needs_git
def test_a_terraformignore_replaces_the_gitignore_rules(tmp_path: Path) -> None:
    """With a .terraformignore present, only it and the defaults filter the upload, as on HCP."""
    repo = _git_repo(tmp_path / "repo")
    (repo / ".terraformignore").write_text("backend/\n")
    bundle = build_bundle(repo)
    names = _names(bundle.data)
    assert "terraform/local.secret" in names
    assert not any(name.startswith("backend") for name in names)
    assert bundle.ignore_source == "terraformignore"


def test_without_git_only_the_defaults_apply(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No git on the path falls back cleanly to the defaults."""
    monkeypatch.setattr("webbpulse.tf.archive.shutil.which", lambda name: None)
    config = tmp_path / "config"
    config.mkdir()
    (config / "main.tf").write_text("")
    assert git_ignored_paths(config) is None
    bundle = build_bundle(config)
    assert _names(bundle.data) == ["main.tf"]
    assert bundle.ignore_source == "defaults"


@needs_git
def test_outside_a_work_tree_git_reports_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A directory outside any work tree yields no gitignore rules rather than an error."""
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    config = tmp_path / "plain"
    config.mkdir()
    assert git_ignored_paths(config) is None


def test_default_rules_keep_terraform_modules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`.terraform/` is left out except `.terraform/modules/`, go-slug's defaults."""
    monkeypatch.setattr("webbpulse.tf.archive.shutil.which", lambda name: None)
    config = tmp_path / "config"
    (config / ".terraform" / "modules" / "vpc").mkdir(parents=True)
    (config / ".terraform" / "modules" / "vpc" / "main.tf").write_text("")
    (config / ".terraform" / "providers" / "aws").mkdir(parents=True)
    (config / ".terraform" / "providers" / "aws" / "provider").write_text("")
    (config / "main.tf").write_text("")
    names = _names(build_tarball(config))
    assert sorted(names) == [".terraform/modules/vpc/main.tf", "main.tf"]


def test_a_negation_reaches_inside_an_excluded_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A later `!` rule brings back a file under a directory an earlier rule left out."""
    monkeypatch.setattr("webbpulse.tf.archive.shutil.which", lambda name: None)
    config = tmp_path / "config"
    (config / "node_modules" / "pkg").mkdir(parents=True)
    (config / "node_modules" / "pkg" / "index.js").write_text("")
    (config / "node_modules" / "keep.js").write_text("")
    (config / ".terraformignore").write_text("node_modules/\n!node_modules/keep.js\n")
    names = _names(build_tarball(config))
    assert "node_modules/keep.js" in names
    assert "node_modules/pkg/index.js" not in names


def test_unanchored_patterns_match_at_any_depth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without a leading slash a pattern matches at any depth, slash in the middle or not, as in go-slug."""
    monkeypatch.setattr("webbpulse.tf.archive.shutil.which", lambda name: None)
    config = tmp_path / "config"
    for relative in ("a/b/one.tf", "x/y/a/b/two.tf", "c/d/three.tf", "x/c/d/four.tf", "main.tf"):
        (config / relative).parent.mkdir(parents=True, exist_ok=True)
        (config / relative).write_text("")
    (config / ".terraformignore").write_text("a/b\n/c/d\n")
    names = _names(build_tarball(config))
    assert "a/b/one.tf" not in names
    assert "x/y/a/b/two.tf" not in names
    assert "c/d/three.tf" not in names
    assert "x/c/d/four.tf" in names
    assert "main.tf" in names


def test_sizes_read_in_people_units() -> None:
    """Byte counts print in bytes, KB or MB."""
    assert format_size(512) == "512 bytes"
    assert format_size(4_200) == "4.2 KB"
    assert format_size(85_000_000) == "85.0 MB"
