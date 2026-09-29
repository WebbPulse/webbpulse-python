"""Tests for `webbpulse.tf.credentials`."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from webbpulse.tf.credentials import CredentialsError, resolve_token, terraform_token_env_names

HOST = "staging.terraform.webbpulse.com"


def _write_credentials(home: Path, host: str, token: str) -> None:
    """Write a credentials file the way `terraform login` does."""
    directory = home / ".terraform.d"
    directory.mkdir()
    (directory / "credentials.tfrc.json").write_text(json.dumps({"credentials": {host: {"token": token}}}))


def test_env_names_follow_terraform() -> None:
    """Dots become underscores and hyphens get both spellings."""
    assert terraform_token_env_names("a.b.com") == ("TF_TOKEN_a_b_com",)
    assert terraform_token_env_names("my-host.com") == ("TF_TOKEN_my-host_com", "TF_TOKEN_my__host_com")


def test_explicit_env_wins(tmp_path: Path) -> None:
    """`WP_TF_TOKEN` beats the Terraform sources."""
    _write_credentials(tmp_path, HOST, "wpk_file")
    env = {"WP_TF_TOKEN": "wpk_explicit", "TF_TOKEN_staging_terraform_webbpulse_com": "wpk_tf"}
    assert resolve_token(HOST, env, tmp_path) == "wpk_explicit"


def test_terraform_env_beats_file(tmp_path: Path) -> None:
    """`TF_TOKEN_<host>` beats the credentials file, as in Terraform."""
    _write_credentials(tmp_path, HOST, "wpk_file")
    assert resolve_token(HOST, {"TF_TOKEN_staging_terraform_webbpulse_com": "wpk_tf"}, tmp_path) == "wpk_tf"


def test_credentials_file_is_read(tmp_path: Path) -> None:
    """The key `terraform login` stored is used."""
    _write_credentials(tmp_path, HOST, "wpk_file")
    assert resolve_token(HOST, {}, tmp_path) == "wpk_file"


def test_missing_token_says_to_log_in(tmp_path: Path) -> None:
    """No source at all names `terraform login` and never echoes anything secret."""
    _write_credentials(tmp_path, "other.example.com", "wpk_other")
    with pytest.raises(CredentialsError, match="terraform login"):
        resolve_token(HOST, {}, tmp_path)


def test_bad_json_is_an_error(tmp_path: Path) -> None:
    """A corrupt credentials file is reported without its contents."""
    (tmp_path / ".terraform.d").mkdir()
    (tmp_path / ".terraform.d" / "credentials.tfrc.json").write_text("{wpk_secret")
    with pytest.raises(CredentialsError) as caught:
        resolve_token(HOST, {}, tmp_path)
    assert "wpk_secret" not in str(caught.value)


def test_a_login_session_beats_the_file(tmp_path: Path) -> None:
    """A `wp-tf login` session is used ahead of the key `terraform login` stored."""
    _write_credentials(tmp_path, HOST, "wpk_file")
    assert resolve_token(HOST, {}, tmp_path, session_token=lambda: "session-token") == "session-token"


def test_the_environment_beats_a_login_session(tmp_path: Path) -> None:
    """An explicit key wins, and the session is not even consulted."""
    called: list[bool] = []

    def session() -> str:
        called.append(True)
        return "session-token"

    assert resolve_token(HOST, {"WP_TF_TOKEN": "wpk_explicit"}, tmp_path, session_token=session) == "wpk_explicit"
    assert called == []


def test_no_session_falls_through_to_the_file(tmp_path: Path) -> None:
    """Without a stored login the file is still read, and the error names both logins."""
    _write_credentials(tmp_path, HOST, "wpk_file")
    assert resolve_token(HOST, {}, tmp_path, session_token=lambda: None) == "wpk_file"
    with pytest.raises(CredentialsError, match="wp-tf login"):
        resolve_token(HOST, {}, tmp_path / "empty", session_token=lambda: None)
