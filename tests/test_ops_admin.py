"""Tests for the `webbpulse-admin` operator CLI in `webbpulse.ops.admin`.

Every test runs against moto with a throwaway named profile; nothing reaches a real account.
"""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import boto3
import pytest
from moto import mock_aws
from pytest import MonkeyPatch

from webbpulse.identity.users import USERS_TABLE_SPEC, DynamoUsersRepository, User
from webbpulse.ops.admin import (
    EXIT_OK,
    EXIT_TABLE_MISSING,
    EXIT_USAGE,
    EXIT_USER_MISSING,
    GRANTED_AT,
    GRANTED_BY,
    REVOKED_AT,
    REVOKED_BY,
    AdminStore,
    UsageError,
    _SessionRepository,
    main,
    mask_email,
    resolve_table_name,
)

REGION = "us-west-2"
PREFIX = "carmodpicker-staging"
TABLE = f"{PREFIX}-users"
PROFILE = "admin-cli-test"
EMAIL = "Tyler@Gmail.com"


@pytest.fixture(autouse=True)
def _aws(monkeypatch: MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """Point the SDK at a throwaway profile with fake keys, and strip every ambient credential."""
    for name in (
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)
    credentials = tmp_path / "credentials"
    credentials.write_text(f"[{PROFILE}]\naws_access_key_id = testing\naws_secret_access_key = testing\n")
    config = tmp_path / "config"
    config.write_text(f"[profile {PROFILE}]\nregion = {REGION}\n")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(credentials))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))
    with mock_aws():
        yield


def dynamodb() -> Any:
    """Return a moto DynamoDB client on the test profile."""
    return boto3.Session(profile_name=PROFILE).client("dynamodb")


def make_table() -> None:
    """Create the users table as the identity package specifies it."""
    dynamodb().create_table(**USERS_TABLE_SPEC.create_table_request(PREFIX))


def put_user(user_id: str, email: str, **extra: Any) -> None:
    """Write one users row the way the identity repository stores it."""
    table = boto3.Session(profile_name=PROFILE).resource("dynamodb").Table(TABLE)
    table.put_item(Item={"id": user_id, "email": email, "email_lower": email.lower(), "is_admin": False, **extra})


def row(user_id: str) -> dict[str, Any]:
    """Read one users row back."""
    table = boto3.Session(profile_name=PROFILE).resource("dynamodb").Table(TABLE)
    return dict(table.get_item(Key={"id": user_id})["Item"])


def run(*argv: str) -> tuple[int, str, str]:
    """Run the CLI with the test profile and prefix, returning the exit code, stdout and stderr."""
    stdout, stderr = io.StringIO(), io.StringIO()
    code = main(["--profile", PROFILE, "--prefix", PREFIX, *argv], stdout=stdout, stderr=stderr)
    return code, stdout.getvalue(), stderr.getvalue()


@pytest.fixture
def table() -> None:
    """A users table holding one ordinary user."""
    make_table()
    put_user("u-1", EMAIL)


@pytest.mark.parametrize(
    ("raw", "masked"),
    [
        ("tyler@gmail.com", "t***@g***.com"),
        ("A.B@mail.example.co.uk", "A***@m***.uk"),
        ("no-at-sign", "***"),
        ("x@localhost", "***"),
        ("", "***"),
    ],
)
def test_mask_email(raw: str, masked: str) -> None:
    """Masking keeps one local and one domain character and the TLD, or masks whole."""
    assert mask_email(raw) == masked


def test_table_name_resolves_from_prefix_or_override() -> None:
    """The prefix builds `<prefix>-users`, an explicit name wins, and neither is refused."""
    assert resolve_table_name(PREFIX, None) == TABLE
    assert resolve_table_name(PREFIX, "custom") == "custom"
    with pytest.raises(UsageError):
        resolve_table_name(None, None)


@pytest.mark.usefixtures("table")
def test_grant_by_email_sets_flag_and_audit_attributes() -> None:
    """A grant flips `is_admin`, records the caller ARN and time, and prints a masked audit line."""
    code, out, err = run("grant", "--email", "tyler@gmail.com")
    assert code == EXIT_OK
    stored = row("u-1")
    assert stored["is_admin"] is True
    assert stored[GRANTED_BY].startswith("arn:aws:")
    assert stored[GRANTED_AT]
    audit = json.loads(out)
    assert audit["event"] == "identity.admin_granted"
    assert audit["changed"] is True
    assert audit["dry_run"] is False
    assert audit["email"] == "T***@G***.com"
    assert audit["actor_arn"] == stored[GRANTED_BY]
    assert audit["table"] == TABLE
    assert "tyler" not in (out + err).lower()


@pytest.mark.usefixtures("table")
def test_grant_is_idempotent() -> None:
    """A second grant writes nothing and keeps the first grant's audit attributes."""
    assert run("grant", "--user-id", "u-1")[0] == EXIT_OK
    first = row("u-1")
    code, out, err = run("grant", "--user-id", "u-1")
    assert code == EXIT_OK
    assert json.loads(out)["changed"] is False
    assert "nothing written" in err
    assert row("u-1") == first


@pytest.mark.usefixtures("table")
def test_revoke_is_symmetric() -> None:
    """A revoke clears the flag, swaps the grant attributes for revoke ones, and repeats as a no-op."""
    run("grant", "--user-id", "u-1")
    code, out, _ = run("revoke", "--email", EMAIL)
    assert code == EXIT_OK
    stored = row("u-1")
    assert stored["is_admin"] is False
    assert GRANTED_BY not in stored
    assert GRANTED_AT not in stored
    assert stored[REVOKED_BY].startswith("arn:aws:")
    assert stored[REVOKED_AT]
    assert json.loads(out)["event"] == "identity.admin_revoked"
    code, out, _ = run("revoke", "--user-id", "u-1")
    assert code == EXIT_OK
    assert json.loads(out)["changed"] is False


@pytest.mark.usefixtures("table")
def test_grant_after_revoke_clears_revoke_attributes() -> None:
    """Granting again removes the revoke attributes so the row shows only the latest change."""
    run("grant", "--user-id", "u-1")
    run("revoke", "--user-id", "u-1")
    run("grant", "--user-id", "u-1")
    stored = row("u-1")
    assert stored["is_admin"] is True
    assert REVOKED_BY not in stored
    assert GRANTED_BY in stored


@pytest.mark.usefixtures("table")
def test_dry_run_writes_nothing() -> None:
    """`--dry-run` reports the change it would make and leaves the row untouched."""
    before = row("u-1")
    code, out, err = run("grant", "--user-id", "u-1", "--dry-run")
    assert code == EXIT_OK
    audit = json.loads(out)
    assert audit["changed"] is True
    assert audit["dry_run"] is True
    assert "dry run" in err
    assert row("u-1") == before


@pytest.mark.usefixtures("table")
def test_missing_user_exits_three_without_echoing_the_address() -> None:
    """An unknown address or id exits 3 and never prints the address given."""
    code, out, err = run("grant", "--email", "nobody@example.com")
    assert code == EXIT_USER_MISSING
    assert out == ""
    assert "nobody" not in err
    assert run("revoke", "--user-id", "u-404")[0] == EXIT_USER_MISSING


def test_missing_table_exits_four() -> None:
    """A prefix with no users table exits 4."""
    code, _, err = run("list")
    assert code == EXIT_TABLE_MISSING
    assert TABLE in err


@pytest.mark.usefixtures("table")
def test_list_prints_admins_masked() -> None:
    """`list` prints each admin's id and masked address, and nobody else."""
    put_user("u-2", "alice@example.org", is_admin=True)
    put_user("u-3", "bob@example.net", is_admin=True)
    code, out, err = run("list")
    assert code == EXIT_OK
    assert out.splitlines() == ["u-2\ta***@e***.org", "u-3\tb***@e***.net"]
    assert "2 admin(s)" in err
    assert "alice" not in out and "bob" not in out


@pytest.mark.usefixtures("table")
def test_profile_is_required() -> None:
    """Without `--profile` the tool refuses before touching AWS, even with a region set."""
    stderr = io.StringIO()
    code = main(["--prefix", PREFIX, "--region", REGION, "list"], stdout=io.StringIO(), stderr=stderr)
    assert code == EXIT_USAGE
    assert "--profile" in stderr.getvalue()


@pytest.mark.usefixtures("table")
def test_target_options_work_after_the_subcommand() -> None:
    """Target options given after the action are honoured like `webbpulse-config`'s."""
    stdout = io.StringIO()
    code = main(
        ["grant", "--user-id", "u-1", "--profile", PROFILE, "--table-name", TABLE],
        stdout=stdout,
        stderr=io.StringIO(),
    )
    assert code == EXIT_OK
    assert row("u-1")["is_admin"] is True


def test_email_and_user_id_are_mutually_exclusive() -> None:
    """Passing both selectors is an argparse usage error."""
    with pytest.raises(SystemExit) as exc:
        run("grant", "--email", EMAIL, "--user-id", "u-1")
    assert exc.value.code == EXIT_USAGE


@pytest.mark.usefixtures("table")
def test_lost_race_reads_back_as_no_op() -> None:
    """A user already granted by someone else between the read and the write is a no-op, not an error."""
    session = boto3.Session(profile_name=PROFILE)
    users: DynamoUsersRepository[User] = DynamoUsersRepository(
        repository=_SessionRepository(session.resource("dynamodb").Table(TABLE))
    )
    store = AdminStore(users, actor_arn="arn:aws:sts::1:assumed-role/x/y")
    stale = store.find(user_id="u-1")
    put_user("u-1", EMAIL, is_admin=True)
    change = store.grant(stale)
    assert change.changed is False
