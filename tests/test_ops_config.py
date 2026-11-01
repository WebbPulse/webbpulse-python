"""Tests for the `webbpulse-config` operator CLI in `webbpulse.ops.config`.

Every test runs against moto; nothing reaches a real account.
"""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws
from pytest import MonkeyPatch

from webbpulse.ops import config as ops
from webbpulse.ops.config import (
    CONFIG_PARAMETER_DESCRIPTION,
    EXIT_CONFLICT,
    EXIT_KEY_ABSENT,
    EXIT_MISSING,
    EXIT_NOT_OBJECT,
    EXIT_OK,
    EXIT_USAGE,
    PENDING_STAGE,
    ConcurrentChangeError,
    ConfigStore,
    ConfigToolError,
    SecretStore,
    UsageError,
    main,
    parse_config_value,
    resolve_target,
)

REGION = "us-west-2"
PREFIX = "carmodpicker-staging"
SECRET_ID = f"{PREFIX}/app"
PARAMETER = f"/{PREFIX}/config"


@pytest.fixture(autouse=True)
def _aws(monkeypatch: MonkeyPatch) -> Iterator[None]:
    """Give moto fake credentials and keep any operator profile out of the test process."""
    for name in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setattr(ops, "RETRY_BASE_DELAY_SECONDS", 0)
    with mock_aws():
        yield


class PipedStdin(io.StringIO):
    """Stdin that is not a terminal, as when a value is piped in."""

    def isatty(self) -> bool:
        """Report a pipe."""
        return False


class TerminalStdin(io.StringIO):
    """Stdin that claims to be a terminal, so the hidden prompt path runs."""

    def isatty(self) -> bool:
        """Report a terminal."""
        return True


def secrets_client() -> Any:
    """Return a moto Secrets Manager client in the test region."""
    return boto3.client("secretsmanager", region_name=REGION)


def ssm_client() -> Any:
    """Return a moto SSM client in the test region."""
    return boto3.client("ssm", region_name=REGION)


def make_secret(value: str = '{"SECRET_KEY":"old","OTHER":"keep"}') -> None:
    """Create the app secret with a starting value."""
    secrets_client().create_secret(Name=SECRET_ID, SecretString=value)


def make_parameter(value: str = '{"EXISTING":"keep"}') -> None:
    """Create the config parameter with a starting value."""
    ssm_client().put_parameter(Name=PARAMETER, Value=value, Type="String")


def stored_secret() -> dict[str, Any]:
    """Read the AWSCURRENT value back directly, bypassing the tool."""
    response = secrets_client().get_secret_value(SecretId=SECRET_ID, VersionStage="AWSCURRENT")
    return cast(dict[str, Any], json.loads(response["SecretString"]))


def version_stages() -> dict[str, list[str]]:
    """Return the labels on every version of the secret."""
    return cast(dict[str, list[str]], secrets_client().describe_secret(SecretId=SECRET_ID)["VersionIdsToStages"])


def stored_parameter() -> dict[str, Any]:
    """Read the parameter back directly, bypassing the tool."""
    return cast(dict[str, Any], json.loads(ssm_client().get_parameter(Name=PARAMETER)["Parameter"]["Value"]))


def run(*argv: str, stdin: io.StringIO | None = None, prompt: Any = None) -> tuple[int, str, str]:
    """Run the CLI with the test target and return the exit code, stdout and stderr."""
    out, err = io.StringIO(), io.StringIO()
    kwargs: dict[str, Any] = {"stdin": stdin or PipedStdin(""), "stdout": out, "stderr": err}
    if prompt is not None:
        kwargs["prompt"] = prompt
    code = main(["--prefix", PREFIX, "--region", REGION, *argv], **kwargs)
    return code, out.getvalue(), err.getvalue()


def test_resolve_target_uses_the_prefix_and_lets_overrides_win() -> None:
    """The prefix names both resources; an explicit id replaces only its own resource."""
    assert resolve_target(PREFIX) == ops.Target(SECRET_ID, PARAMETER)
    assert resolve_target(f"/{PREFIX}/") == ops.Target(SECRET_ID, PARAMETER)
    assert resolve_target(PREFIX, secret_id="webbpulse-staging/app") == ops.Target("webbpulse-staging/app", PARAMETER)
    assert resolve_target(None, parameter_name="/x/config") == ops.Target(None, "/x/config")


def test_parse_config_value_prefers_json_and_falls_back_to_a_string() -> None:
    """Lists, numbers and booleans parse; anything else stays a string unless forced."""
    assert parse_config_value('["a@b.c"]') == ["a@b.c"]
    assert parse_config_value("5") == 5
    assert parse_config_value("true") is True
    assert parse_config_value("hello world") == "hello world"
    assert parse_config_value("5", force_string=True) == "5"


def test_secret_set_from_stdin_merges_and_keeps_other_keys() -> None:
    """A piped value lands under its key, one trailing newline is dropped, other keys stay."""
    make_secret()
    code, out, err = run("secret", "set", "NEW_KEY", stdin=PipedStdin("s3cr3t-value\n"))
    assert code == EXIT_OK
    assert out == ""
    assert "s3cr3t-value" not in err
    assert stored_secret() == {"SECRET_KEY": "old", "OTHER": "keep", "NEW_KEY": "s3cr3t-value"}


def test_secret_set_overwrites_only_the_named_key() -> None:
    """Setting an existing key replaces its value and leaves every other key alone."""
    make_secret()
    code, _, _ = run("secret", "set", "SECRET_KEY", stdin=PipedStdin("rotated"))
    assert code == EXIT_OK
    assert stored_secret() == {"SECRET_KEY": "rotated", "OTHER": "keep"}


def test_secret_set_from_a_terminal_uses_a_confirmed_hidden_prompt() -> None:
    """On a terminal the value comes from the prompt, asked twice, never from stdin."""
    make_secret()
    prompts: list[str] = []

    def prompt(text: str) -> str:
        prompts.append(text)
        return "typed-value"

    code, _, _ = run("secret", "set", "TYPED", stdin=TerminalStdin("ignored"), prompt=prompt)
    assert code == EXIT_OK
    assert len(prompts) == 2
    assert stored_secret()["TYPED"] == "typed-value"


def test_secret_set_refuses_a_mismatched_confirmation() -> None:
    """Two different answers write nothing."""
    make_secret()
    answers = iter(["one", "two"])
    code, _, err = run("secret", "set", "TYPED", stdin=TerminalStdin(), prompt=lambda _: next(answers))
    assert code == EXIT_USAGE
    assert "did not match" in err
    assert "TYPED" not in stored_secret()


def test_secret_set_refuses_an_empty_value_and_an_empty_key() -> None:
    """An empty value and an empty key are both refused before any write."""
    make_secret()
    assert run("secret", "set", "EMPTY", stdin=PipedStdin("\n"))[0] == EXIT_USAGE
    assert run("secret", "set", "", stdin=PipedStdin("v"))[0] == EXIT_USAGE
    assert stored_secret() == {"SECRET_KEY": "old", "OTHER": "keep"}


def test_secret_set_warns_on_a_key_that_is_not_upper_snake() -> None:
    """A lower-case key is written but warned about."""
    make_secret()
    code, _, err = run("secret", "set", "lower_key", stdin=PipedStdin("v"))
    assert code == EXIT_OK
    assert "not UPPER_SNAKE" in err
    assert stored_secret()["lower_key"] == "v"


def test_secret_set_with_the_same_value_writes_no_new_version() -> None:
    """An unchanged value leaves the version history alone."""
    make_secret()
    before = secrets_client().describe_secret(SecretId=SECRET_ID)["VersionIdsToStages"]
    code, _, err = run("secret", "set", "SECRET_KEY", stdin=PipedStdin("old"))
    assert code == EXIT_OK
    assert "nothing written" in err
    assert secrets_client().describe_secret(SecretId=SECRET_ID)["VersionIdsToStages"] == before


def test_secret_set_on_a_secret_without_a_value_starts_an_object() -> None:
    """A secret terraform created with no version yet is treated as an empty object."""
    secrets_client().create_secret(Name=SECRET_ID)
    code, _, _ = run("secret", "set", "FIRST", stdin=PipedStdin("v"))
    assert code == EXIT_OK
    assert stored_secret() == {"FIRST": "v"}


def test_secret_unset_removes_one_key_and_keeps_the_rest() -> None:
    """Unset drops only the named key; unsetting an absent key writes nothing and succeeds."""
    make_secret()
    assert run("secret", "unset", "SECRET_KEY")[0] == EXIT_OK
    assert stored_secret() == {"OTHER": "keep"}
    code, _, err = run("secret", "unset", "SECRET_KEY")
    assert code == EXIT_OK
    assert "nothing written" in err


def test_secret_keys_lists_names_only() -> None:
    """Keys print one per line, sorted, and no value appears anywhere in the output."""
    make_secret('{"B_KEY":"value-b","A_KEY":"value-a"}')
    code, out, err = run("secret", "keys")
    assert code == EXIT_OK
    assert out == "A_KEY\nB_KEY\n"
    assert "value-" not in out + err


def test_secret_commands_report_a_missing_secret() -> None:
    """A secret that does not exist exits with the missing code and points at terraform."""
    code, out, err = run("secret", "keys")
    assert code == EXIT_MISSING
    assert out == ""
    assert "apply terraform first" in err
    assert run("secret", "set", "K", stdin=PipedStdin("v"))[0] == EXIT_MISSING


def test_secret_that_is_not_a_json_object_is_refused() -> None:
    """A list or plain text secret is never merged into."""
    make_secret('["not", "an", "object"]')
    code, _, err = run("secret", "set", "K", stdin=PipedStdin("v"))
    assert code == EXIT_NOT_OBJECT
    assert "not an object" in err
    assert json.loads(secrets_client().get_secret_value(SecretId=SECRET_ID)["SecretString"]) == ["not", "an", "object"]


def test_secret_id_override_targets_a_non_standard_name() -> None:
    """--secret-id replaces <prefix>/app and needs no prefix."""
    secrets_client().create_secret(Name="webbpulse-staging/app", SecretString="{}")
    out, err = io.StringIO(), io.StringIO()
    code = main(
        ["secret", "set", "K", "--secret-id", "webbpulse-staging/app", "--region", REGION],
        stdin=PipedStdin("v"),
        stdout=out,
        stderr=err,
    )
    assert code == EXIT_OK
    response = secrets_client().get_secret_value(SecretId="webbpulse-staging/app", VersionStage="AWSCURRENT")
    assert json.loads(response["SecretString"]) == {"K": "v"}


def test_a_command_with_no_target_is_a_usage_error() -> None:
    """Without --prefix or an override there is nothing to act on."""
    err = io.StringIO()
    assert main(["secret", "keys", "--region", REGION], stdout=io.StringIO(), stderr=err) == EXIT_USAGE
    assert "--prefix" in err.getvalue()


class RacingSecrets:
    """A Secrets Manager client that lets another writer land just before the tool moves AWSCURRENT."""

    def __init__(self, inner: Any, *, races: int) -> None:
        """Wrap a real client and arrange `races` concurrent writes."""
        self._inner = inner
        self._races = races

    def update_secret_version_stage(self, **kwargs: Any) -> Any:
        """Land a race before the swap, which then finds AWSCURRENT on another version."""
        if kwargs["VersionStage"] == "AWSCURRENT" and self._races > 0:
            self._races -= 1
            response = self._inner.get_secret_value(SecretId=SECRET_ID, VersionStage="AWSCURRENT")
            current = json.loads(response["SecretString"])
            current[f"RACER_{self._races}"] = "theirs"
            self._inner.put_secret_value(SecretId=SECRET_ID, SecretString=json.dumps(current))
        return self._inner.update_secret_version_stage(**kwargs)

    def __getattr__(self, name: str) -> Any:
        """Pass every other call straight through."""
        return getattr(self._inner, name)


class StaleReads:
    """A Secrets Manager client whose reads answer from a snapshot taken before a later write.

    Metadata stays stale for the client's whole life and the first `stale_reads` reads of AWSCURRENT
    stay stale too, whatever the version they name now holds.
    """

    def __init__(self, inner: Any, *, stale_reads: int) -> None:
        """Wrap a real client and snapshot what it reads right now."""
        self._inner = inner
        self._stale_reads = stale_reads
        self._described = inner.describe_secret(SecretId=SECRET_ID)
        self._read: Any = None
        self._miss: ClientError | None = None
        try:
            self._read = inner.get_secret_value(SecretId=SECRET_ID, VersionStage="AWSCURRENT")
        except ClientError as exc:
            self._miss = exc

    def describe_secret(self, **kwargs: Any) -> Any:
        """Answer from the snapshot."""
        return self._described

    def get_secret_value(self, **kwargs: Any) -> Any:
        """Answer a read of AWSCURRENT from the snapshot until the stale reads run out."""
        if "VersionStage" in kwargs and self._stale_reads > 0:
            self._stale_reads -= 1
            if self._miss is not None:
                raise self._miss
            return self._read
        return self._inner.get_secret_value(**kwargs)

    def __getattr__(self, name: str) -> Any:
        """Pass every other call straight through."""
        return getattr(self._inner, name)


class RefusedSwap:
    """A Secrets Manager client whose identity may put a version but may not move AWSCURRENT."""

    def __init__(self, inner: Any) -> None:
        """Wrap a real client."""
        self._inner = inner

    def update_secret_version_stage(self, **kwargs: Any) -> Any:
        """Refuse the swap and let the pending label cleanup through."""
        if kwargs["VersionStage"] == "AWSCURRENT":
            error: Any = {"Error": {"Code": "AccessDeniedException", "Message": "not authorized"}}
            raise ClientError(error, "UpdateSecretVersionStage")
        return self._inner.update_secret_version_stage(**kwargs)

    def __getattr__(self, name: str) -> Any:
        """Pass every other call straight through."""
        return getattr(self._inner, name)


def test_a_set_after_a_stale_read_keeps_the_key_written_just_before_it() -> None:
    """A set that reads the version before the previous set is refused, re-reads and keeps both keys."""
    make_secret()
    stale = StaleReads(secrets_client(), stale_reads=1)
    assert SecretStore(secrets_client(), SECRET_ID).set("FIRST", "one").changed
    result = SecretStore(cast(Any, stale), SECRET_ID).set("SECOND", "two")
    assert result.changed
    assert stored_secret() == {"SECRET_KEY": "old", "OTHER": "keep", "FIRST": "one", "SECOND": "two"}
    assert "AWSCURRENT" in version_stages()[cast(str, result.version)]


def test_a_read_that_stays_stale_fails_loudly_and_keeps_the_newer_key() -> None:
    """However long the staleness lasts, the set raises rather than overwrite the newer version."""
    make_secret()
    stale = StaleReads(secrets_client(), stale_reads=100)
    assert SecretStore(secrets_client(), SECRET_ID).set("FIRST", "one").changed
    with pytest.raises(ConcurrentChangeError):
        SecretStore(cast(Any, stale), SECRET_ID).set("SECOND", "two")
    assert stored_secret() == {"SECRET_KEY": "old", "OTHER": "keep", "FIRST": "one"}


def test_a_first_write_after_a_stale_empty_read_keeps_the_key_written_just_before_it() -> None:
    """A read that still sees no value cannot replace a first version it never saw."""
    secrets_client().create_secret(Name=SECRET_ID)
    stale = StaleReads(secrets_client(), stale_reads=1)
    assert SecretStore(secrets_client(), SECRET_ID).set("FIRST", "one").changed
    assert SecretStore(cast(Any, stale), SECRET_ID).set("SECOND", "two").changed
    assert stored_secret() == {"FIRST": "one", "SECOND": "two"}


def test_two_sets_in_a_row_keep_both_keys_and_leave_no_pending_label() -> None:
    """Each set moves AWSCURRENT to its own version, AWSPREVIOUS follows, and the pending label goes."""
    make_secret()
    store = SecretStore(secrets_client(), SECRET_ID)
    first = store.set("FIRST", "one")
    second = store.set("SECOND", "two")
    assert stored_secret() == {"SECRET_KEY": "old", "OTHER": "keep", "FIRST": "one", "SECOND": "two"}
    stages = version_stages()
    assert "AWSCURRENT" in stages[cast(str, second.version)]
    assert "AWSPREVIOUS" in stages[cast(str, first.version)]
    assert not any(PENDING_STAGE in labels for labels in stages.values())


def test_a_refused_swap_fails_loudly_and_leaves_the_current_value_alone() -> None:
    """An identity that cannot move AWSCURRENT gets an error naming it, and readers keep the old value."""
    make_secret()
    store = SecretStore(cast(Any, RefusedSwap(secrets_client())), SECRET_ID)
    with pytest.raises(ConfigToolError, match=r"AccessDeniedException.*not confirmed as current"):
        store.set("MINE", "ours")
    assert stored_secret() == {"SECRET_KEY": "old", "OTHER": "keep"}
    assert not any(PENDING_STAGE in labels for labels in version_stages().values())


def test_a_concurrent_change_is_retried_and_both_writes_survive() -> None:
    """When another writer lands mid-merge, the tool re-reads and keeps their key and its own."""
    make_secret()
    store = SecretStore(cast(Any, RacingSecrets(secrets_client(), races=1)), SECRET_ID)
    result = store.set("MINE", "ours")
    assert result.changed
    assert stored_secret() == {"SECRET_KEY": "old", "OTHER": "keep", "RACER_0": "theirs", "MINE": "ours"}


def test_set_many_writes_every_key_in_one_version() -> None:
    """Several keys land in a single new version and every other key survives."""
    make_secret()
    store = SecretStore(secrets_client(), SECRET_ID)
    before = store.current_version()
    result = store.set_many({"GITHUB_APP_ID": "1", "GITHUB_PRIVATE_KEY": "pem"})
    assert result.changed
    assert result.version != before
    versions = secrets_client().list_secret_version_ids(SecretId=SECRET_ID)["Versions"]
    assert len(versions) == 2
    assert stored_secret() == {"SECRET_KEY": "old", "OTHER": "keep", "GITHUB_APP_ID": "1", "GITHUB_PRIVATE_KEY": "pem"}


def test_set_many_refuses_empty_and_invalid_keys() -> None:
    """An empty map or a malformed key name fails before anything is written."""
    make_secret()
    store = SecretStore(secrets_client(), SECRET_ID)
    with pytest.raises(UsageError):
        store.set_many({})
    with pytest.raises(UsageError):
        store.set_many({" PADDED": "x"})
    assert stored_secret() == {"SECRET_KEY": "old", "OTHER": "keep"}


def test_a_value_that_keeps_changing_fails_without_writing() -> None:
    """After the retries run out the tool gives up and its own key is never written."""
    make_secret()
    store = SecretStore(cast(Any, RacingSecrets(secrets_client(), races=10)), SECRET_ID, retries=2)
    with pytest.raises(ConcurrentChangeError):
        store.set("MINE", "ours")
    assert "MINE" not in stored_secret()


def test_the_cli_exits_with_the_conflict_code(monkeypatch: MonkeyPatch) -> None:
    """The concurrent change failure reaches the shell as its own exit code."""
    make_secret()

    class Session:
        """A session whose Secrets Manager client always races."""

        region_name = REGION

        def client(self, name: str) -> Any:
            """Return the racing client."""
            return RacingSecrets(secrets_client(), races=100)

    monkeypatch.setattr(ops, "_session", lambda profile, region: Session())
    code, _, err = run("secret", "set", "MINE", stdin=PipedStdin("ours"))
    assert code == EXIT_CONFLICT
    assert "nothing written" in err
    assert "MINE" not in stored_secret()


def test_aws_default_region_resolves_a_region(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    """The variable the region error names is one boto3 reads."""
    make_secret()
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "absent"))
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    out = io.StringIO()
    code = main(["--prefix", PREFIX, "secret", "keys"], stdout=out, stderr=io.StringIO())
    assert code == EXIT_OK
    assert out.getvalue() == "OTHER\nSECRET_KEY\n"


def test_aws_region_alone_resolves_nothing_and_the_error_names_what_works(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """boto3 ignores AWS_REGION, so the error offers only what resolves a region and says so."""
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "absent"))
    monkeypatch.setenv("AWS_REGION", REGION)
    err = io.StringIO()
    code = main(["--prefix", PREFIX, "secret", "keys"], stdout=io.StringIO(), stderr=err)
    assert code == EXIT_USAGE
    assert "--region" in err.getvalue()
    assert "AWS_DEFAULT_REGION" in err.getvalue()
    assert "does not read AWS_REGION" in err.getvalue()


def test_config_set_parses_json_and_keeps_other_keys() -> None:
    """A JSON list is stored as a list, a bare word as a string, and existing keys stay."""
    make_parameter()
    assert run("config", "set", "ALLOWED_EMAILS", '["a@b.c"]')[0] == EXIT_OK
    assert run("config", "set", "FROM_NAME", "WebbPulse")[0] == EXIT_OK
    assert run("config", "set", "PORT", "5", "--string")[0] == EXIT_OK
    assert stored_parameter() == {
        "EXISTING": "keep",
        "ALLOWED_EMAILS": ["a@b.c"],
        "FROM_NAME": "WebbPulse",
        "PORT": "5",
    }


def test_config_get_prints_one_key_or_the_whole_object() -> None:
    """A string prints raw, anything else as JSON, and no key prints the object."""
    make_parameter('{"NAME":"x","LIST":[1,2]}')
    assert run("config", "get", "NAME")[1] == "x\n"
    assert run("config", "get", "LIST")[1] == "[1, 2]\n"
    assert json.loads(run("config", "get")[1]) == {"NAME": "x", "LIST": [1, 2]}
    code, out, _ = run("config", "get", "ABSENT")
    assert (code, out) == (EXIT_KEY_ABSENT, "")


def test_config_unset_removes_one_key() -> None:
    """Unset drops only the named key."""
    make_parameter('{"A":1,"B":2}')
    assert run("config", "unset", "A")[0] == EXIT_OK
    assert stored_parameter() == {"B": 2}


def test_config_get_and_unset_report_a_missing_parameter() -> None:
    """Get and unset on a parameter that does not exist exit with the missing code and create nothing."""
    code, _, err = run("config", "get")
    assert code == EXIT_MISSING
    assert "apply terraform first" in err
    code, _, err = run("config", "unset", "A")
    assert code == EXIT_MISSING
    assert "apply terraform first" in err
    assert ssm_client().describe_parameters()["Parameters"] == []


def test_config_set_creates_a_missing_parameter_the_way_operator_config_imports_it() -> None:
    """A missing parameter is created as a Standard String holding just the key, with the module's description."""
    code, _, err = run("config", "set", "ses_verified_recipients", '["a@b.c"]')
    assert code == EXIT_OK
    assert f"created parameter {PARAMETER} ({REGION}) holding ses_verified_recipients (version 1)" in err
    assert stored_parameter() == {"ses_verified_recipients": ["a@b.c"]}
    described = ssm_client().describe_parameters()["Parameters"]
    assert len(described) == 1
    assert described[0]["Name"] == PARAMETER
    assert described[0]["Type"] == "String"
    assert described[0]["Tier"] == "Standard"
    assert described[0]["Description"] == CONFIG_PARAMETER_DESCRIPTION


def test_config_set_on_an_existing_parameter_merges_without_recreating_it() -> None:
    """An existing parameter takes the normal merge path: a new version, the other keys and its metadata kept."""
    ssm_client().put_parameter(Name=PARAMETER, Value='{"EXISTING":"keep"}', Type="String", Description="theirs")
    code, _, err = run("config", "set", "A", "1")
    assert code == EXIT_OK
    assert "created" not in err
    assert f"set A in parameter {PARAMETER} ({REGION}) (version 2)" in err
    assert stored_parameter() == {"EXISTING": "keep", "A": 1}
    assert ssm_client().describe_parameters()["Parameters"][0]["Description"] == "theirs"


class RacingCreate:
    """An SSM client where another operator creates the parameter just before the tool's create."""

    def __init__(self, inner: Any) -> None:
        """Wrap a real client."""
        self._inner = inner

    def put_parameter(self, **kwargs: Any) -> Any:
        """Land the other operator's create first whenever the tool creates without overwrite."""
        if kwargs.get("Overwrite") is False:
            self._inner.put_parameter(Name=PARAMETER, Value='{"THEIRS":"kept"}', Type="String")
        return self._inner.put_parameter(**kwargs)

    def __getattr__(self, name: str) -> Any:
        """Pass every other call straight through."""
        return getattr(self._inner, name)


def test_config_set_falls_back_to_a_merge_when_a_create_races() -> None:
    """When another writer creates the parameter first, the tool merges its key into theirs."""
    store = ConfigStore(cast(Any, RacingCreate(ssm_client())), PARAMETER)
    result = store.set("MINE", "ours")
    assert result.changed
    assert not result.created
    assert result.version == "2"
    assert stored_parameter() == {"THEIRS": "kept", "MINE": "ours"}


def test_config_that_is_not_a_json_object_is_refused() -> None:
    """A parameter holding plain text is never merged into."""
    make_parameter("plain text")
    code, _, err = run("config", "set", "A", "1")
    assert code == EXIT_NOT_OBJECT
    assert "valid JSON" in err
    assert ssm_client().get_parameter(Name=PARAMETER)["Parameter"]["Value"] == "plain text"


def test_options_are_accepted_after_the_subcommand() -> None:
    """Target options work before or after the subcommand."""
    make_parameter()
    out = io.StringIO()
    code = main(["config", "get", "EXISTING", "--prefix", PREFIX, "--region", REGION], stdout=out, stderr=io.StringIO())
    assert code == EXIT_OK
    assert out.getvalue() == "keep\n"
