"""Tests for `webbpulse.tf.archive`."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from webbpulse.tf.archive import ArchiveError, build_tarball, parse_ignore, upload_root


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
