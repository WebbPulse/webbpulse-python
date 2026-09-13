"""Tests for the application secrets wrapper in `webbpulse.security`.

One JSON secret per service per environment, flattened to a string map, exported to the
environment and validated onto a settings model. Nothing here reads a real secret: every
test either mocks Secrets Manager with moto or injects a stub client.
"""

from __future__ import annotations

import json
from typing import Any

import boto3
import pytest
from moto import mock_aws
from pydantic import ValidationError
from pytest import MonkeyPatch

from webbpulse.config import BaseServiceSettings, SecretNotJsonObjectError
from webbpulse.security import (
    app_secrets,
    apply_app_secrets,
    flatten_secret,
    load_app_secrets,
    reset_secret_cache,
)

ARN_ENV = "APP_SECRETS_ARN"


@pytest.fixture(autouse=True)
def _clear_secret_cache(monkeypatch: MonkeyPatch) -> Any:
    """The secret caches are process wide, so they must not leak between tests."""
    monkeypatch.delenv(ARN_ENV, raising=False)
    reset_secret_cache()
    yield
    reset_secret_cache()


class StubSecrets:
    """A Secrets Manager client that answers one payload and counts the calls."""

    def __init__(self, payload: Any, *, binary: bool = False) -> None:
        self.payload = payload
        self.binary = binary
        self.calls: list[str] = []

    def get_secret_value(self, *, SecretId: str) -> dict[str, Any]:
        """Answer the held payload in the shape the real API returns."""
        self.calls.append(SecretId)
        if self.binary:
            return {"SecretBinary": b"\x00"}
        raw = self.payload if isinstance(self.payload, str) else json.dumps(self.payload)
        return {"SecretString": raw}


class Settings(BaseServiceSettings):
    """A settings model with fields of several types, to prove validation happens."""

    secret_key: str = "unset"
    max_items: int = 1
    debug_mode: bool = False


def test_flatten_secret_keeps_strings_and_encodes_everything_else() -> None:
    """A string passes through; anything else is JSON encoded so it survives an env var."""
    assert flatten_secret(
        {"A": "plain", "B": 5, "C": True, "D": ["x", "y"], "E": {"k": 1}},
    ) == {"A": "plain", "B": "5", "C": "true", "D": '["x", "y"]', "E": '{"k": 1}'}


def test_flatten_secret_drops_nulls() -> None:
    """A `null` is how a secret says a key is absent, so it must not become the text None."""
    assert flatten_secret({"A": "v", "B": None}) == {"A": "v"}


def test_app_secrets_is_empty_without_an_arn() -> None:
    """No ARN is the normal local and test path, not an error."""
    assert app_secrets() == {}


def test_an_empty_arn_argument_is_also_empty() -> None:
    """An explicitly empty ARN short circuits the same way an unset variable does."""
    assert app_secrets("") == {}


def test_app_secrets_reads_the_arn_from_the_environment(monkeypatch: MonkeyPatch) -> None:
    """With no argument the wrapper reads `APP_SECRETS_ARN`, which is how Lambda passes it."""
    with mock_aws():
        client = boto3.client("secretsmanager", region_name="us-west-2")
        arn = client.create_secret(Name="svc/app", SecretString='{"SECRET_KEY": "s3cret"}')["ARN"]
        monkeypatch.setenv(ARN_ENV, arn)
        monkeypatch.setenv("AWS_DEFAULT_REGION", "us-west-2")
        assert app_secrets() == {"SECRET_KEY": "s3cret"}


def test_app_secrets_flattens_what_it_reads() -> None:
    """The map handed back is strings all the way down, ready for the environment."""
    stub = StubSecrets({"SECRET_KEY": "k", "MAX_ITEMS": 12, "DEBUG_MODE": False})
    assert app_secrets("arn:stub", client=stub) == {
        "SECRET_KEY": "k",
        "MAX_ITEMS": "12",
        "DEBUG_MODE": "false",
    }


def test_a_real_read_is_cached_per_arn(monkeypatch: MonkeyPatch) -> None:
    """A Lambda reads its secret once per process, not once per request."""
    with mock_aws():
        client = boto3.client("secretsmanager", region_name="us-west-2")
        arn = client.create_secret(Name="svc/app", SecretString='{"A": "1"}')["ARN"]
        monkeypatch.setenv("AWS_DEFAULT_REGION", "us-west-2")

        assert app_secrets(arn) == {"A": "1"}
        client.put_secret_value(SecretId=arn, SecretString='{"A": "2"}')
        assert app_secrets(arn) == {"A": "1"}, "the cached value must be reused"

        reset_secret_cache()
        assert app_secrets(arn) == {"A": "2"}


def test_an_injected_client_never_touches_the_shared_cache() -> None:
    """A stub must not seed the cache a later real call would read, nor read one."""
    stub = StubSecrets({"A": "from-stub"})
    assert app_secrets("arn:shared", client=stub) == {"A": "from-stub"}
    assert app_secrets("arn:shared", client=stub) == {"A": "from-stub"}
    assert stub.calls == ["arn:shared", "arn:shared"], "each injected read must hit the client"


def test_a_secret_that_is_not_json_is_refused() -> None:
    """A secret written as plain text is a configuration error worth failing loudly on."""
    with pytest.raises(SecretNotJsonObjectError, match="not valid JSON"):
        app_secrets("arn:bad", client=StubSecrets("not json at all"))


def test_a_secret_that_is_not_an_object_is_refused() -> None:
    """The contract is one JSON object of keys, so a list is not a secret document."""
    with pytest.raises(SecretNotJsonObjectError, match="expected a JSON object"):
        app_secrets("arn:list", client=StubSecrets(["a", "b"]))


def test_a_binary_secret_is_refused() -> None:
    """Binary secret data holds no key map, so it cannot be flattened."""
    with pytest.raises(SecretNotJsonObjectError, match="binary"):
        app_secrets("arn:bin", client=StubSecrets(None, binary=True))


def test_a_failed_read_is_logged_with_the_arn_and_reraised(caplog: pytest.LogCaptureFixture) -> None:
    """A read that fails names the ARN in the log, since that is what makes it diagnosable."""

    class Exploding:
        """A client whose read always fails."""

        def get_secret_value(self, *, SecretId: str) -> dict[str, Any]:
            """Fail the way a denied or missing secret does."""
            raise RuntimeError("AccessDeniedException")

    with caplog.at_level("ERROR", logger="webbpulse.security"), pytest.raises(RuntimeError):
        app_secrets("arn:denied", client=Exploding())
    assert "arn:denied" in caplog.text


def test_no_secret_value_is_ever_logged(caplog: pytest.LogCaptureFixture) -> None:
    """Key names are logged so a missing one is diagnosable; values never are."""
    with caplog.at_level("INFO", logger="webbpulse.security"):
        app_secrets("arn:quiet", client=StubSecrets({"SECRET_KEY": "do-not-log-me"}))
    assert "SECRET_KEY" in caplog.text
    assert "do-not-log-me" not in caplog.text


def test_load_app_secrets_exports_every_key(monkeypatch: MonkeyPatch) -> None:
    """A consumer reading straight from the environment gets the whole secret there."""
    monkeypatch.delenv("SECRET_KEY", raising=False)
    applied = load_app_secrets("arn:x", client=StubSecrets({"SECRET_KEY": "k", "MAX_ITEMS": 3}))
    import os

    assert applied == {"SECRET_KEY": "k", "MAX_ITEMS": "3"}
    assert os.environ["SECRET_KEY"] == "k"
    assert os.environ["MAX_ITEMS"] == "3"
    monkeypatch.delenv("SECRET_KEY")
    monkeypatch.delenv("MAX_ITEMS")


def test_override_false_leaves_a_local_value_alone(monkeypatch: MonkeyPatch) -> None:
    """A value set for a local run wins over the deployed secret when override is off."""
    monkeypatch.setenv("SECRET_KEY", "local")
    load_app_secrets("arn:x", client=StubSecrets({"SECRET_KEY": "deployed"}), override=False)
    import os

    assert os.environ["SECRET_KEY"] == "local"


def test_override_true_replaces_an_existing_value(monkeypatch: MonkeyPatch) -> None:
    """By default the secret is the authority, since that is what deployment relies on."""
    monkeypatch.setenv("SECRET_KEY", "local")
    load_app_secrets("arn:x", client=StubSecrets({"SECRET_KEY": "deployed"}))
    import os

    assert os.environ["SECRET_KEY"] == "deployed"


def test_apply_app_secrets_validates_each_value_onto_its_field(monkeypatch: MonkeyPatch) -> None:
    """Each matching value is parsed to the field's own type, not left a string."""
    for name in ("SECRET_KEY", "MAX_ITEMS", "DEBUG_MODE"):
        monkeypatch.delenv(name, raising=False)
    settings = Settings()
    apply_app_secrets(
        settings,
        "arn:x",
        client=StubSecrets({"SECRET_KEY": "k", "MAX_ITEMS": 42, "DEBUG_MODE": "true"}),
    )
    assert settings.secret_key == "k"
    assert settings.max_items == 42
    assert settings.debug_mode is True


def test_apply_app_secrets_matches_field_names_case_insensitively(monkeypatch: MonkeyPatch) -> None:
    """pydantic-settings resolves environment variables either way, so this must too."""
    monkeypatch.delenv("secret_key", raising=False)
    settings = Settings()
    apply_app_secrets(settings, "arn:x", client=StubSecrets({"secret_key": "lower"}))
    assert settings.secret_key == "lower"


def test_a_key_with_no_field_reaches_the_environment_only(monkeypatch: MonkeyPatch) -> None:
    """A secret may carry values for other consumers, which must not fail the model."""
    monkeypatch.delenv("OTHER_CONSUMER", raising=False)
    settings = Settings()
    applied = apply_app_secrets(settings, "arn:x", client=StubSecrets({"OTHER_CONSUMER": "v"}))
    import os

    assert applied == {"OTHER_CONSUMER": "v"}
    assert os.environ["OTHER_CONSUMER"] == "v"
    assert not hasattr(settings, "other_consumer")


def test_a_malformed_value_fails_at_apply_not_at_first_use(monkeypatch: MonkeyPatch) -> None:
    """A secret whose value does not fit its field is a startup failure, not a later one."""
    monkeypatch.delenv("MAX_ITEMS", raising=False)
    with pytest.raises(ValidationError, match=r"valid integer"):
        apply_app_secrets(Settings(), "arn:x", client=StubSecrets({"MAX_ITEMS": "not-a-number"}))


def test_reset_clears_both_caches(monkeypatch: MonkeyPatch) -> None:
    """The flat map here is derived from the shared parse, so one reset clears both."""
    from webbpulse.config import load_json_secret

    with mock_aws():
        client = boto3.client("secretsmanager", region_name="us-west-2")
        arn = client.create_secret(Name="svc/app", SecretString='{"A": "1"}')["ARN"]
        monkeypatch.setenv("AWS_DEFAULT_REGION", "us-west-2")

        assert app_secrets(arn) == {"A": "1"}
        assert load_json_secret(arn) == {"A": "1"}
        client.put_secret_value(SecretId=arn, SecretString='{"A": "2"}')

        reset_secret_cache()
        assert load_json_secret(arn) == {"A": "2"}, "the shared parse cache must be cleared too"
        assert app_secrets(arn) == {"A": "2"}
