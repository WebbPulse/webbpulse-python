"""Where `wp-tf` finds its API key: the same places Terraform CLI looks for a host's token."""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping
from pathlib import Path

TOKEN_ENV = "WP_TF_TOKEN"
"""An explicit key, checked before Terraform's own sources."""


class CredentialsError(Exception):
    """No usable token for the host, or a credentials file that could not be read."""


def terraform_token_env_names(host: str) -> tuple[str, ...]:
    """The `TF_TOKEN_*` names Terraform CLI accepts for `host`, in the order it tries them.

    Dots become underscores, and a hyphen may be kept or written as a double underscore.
    """
    dotted = host.lower().replace(".", "_")
    names = [f"TF_TOKEN_{dotted}"]
    if "-" in dotted:
        names.append(f"TF_TOKEN_{dotted.replace('-', '__')}")
    return tuple(names)


def credentials_file(environ: Mapping[str, str], home: Path | None = None) -> Path:
    """The `credentials.tfrc.json` `terraform login` writes to on this platform."""
    if os.name == "nt" and environ.get("APPDATA"):
        return Path(environ["APPDATA"]) / "terraform.d" / "credentials.tfrc.json"
    return (home or Path.home()) / ".terraform.d" / "credentials.tfrc.json"


def _file_token(path: Path, host: str) -> str | None:
    """The token stored for `host` in a credentials file, or None when the file or entry is absent."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise CredentialsError(f"could not read {path}: {exc.strerror}") from exc
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise CredentialsError(f"{path} is not valid JSON") from exc
    entries = document.get("credentials") if isinstance(document, dict) else None
    entry = entries.get(host) if isinstance(entries, dict) else None
    token = entry.get("token") if isinstance(entry, dict) else None
    return token if isinstance(token, str) and token else None


def resolve_token(
    host: str,
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
    *,
    session_token: Callable[[], str | None] | None = None,
) -> str:
    """The key for `host`: `WP_TF_TOKEN`, `TF_TOKEN_<host>`, a `wp-tf login` session, `credentials.tfrc.json`.

    `session_token` answers the stored device login's current access token, or `None` when
    there is none; it is only called when no key is set in the environment.

    Raises:
        CredentialsError: None of them holds a token.
    """
    env = os.environ if environ is None else environ
    explicit = env.get(TOKEN_ENV, "").strip()
    if explicit:
        return explicit
    for name in terraform_token_env_names(host):
        value = env.get(name, "").strip()
        if value:
            return value
    if session_token is not None:
        session = session_token()
        if session:
            return session
    path = credentials_file(env, home)
    token = _file_token(path, host)
    if token:
        return token
    raise CredentialsError(f"no token for {host}; run `wp-tf login`, `terraform login {host}` or set {TOKEN_ENV}")


__all__ = [
    "TOKEN_ENV",
    "CredentialsError",
    "credentials_file",
    "resolve_token",
    "terraform_token_env_names",
]
