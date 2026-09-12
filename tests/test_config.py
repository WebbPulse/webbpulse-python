"""Tests for `webbpulse.config`."""

from __future__ import annotations

import json
from typing import Any

import boto3
import pytest
from moto import mock_aws
from pytest import MonkeyPatch

from webbpulse.config import (
    BaseServiceSettings,
    SecretNotJsonObjectError,
    load_json_secret,
    reset_secret_cache,
)


@pytest.fixture(autouse=True)
def _clear_secret_cache() -> Any:
    """The secret cache is process wide, so it must not leak between tests."""
    reset_secret_cache()
    yield
    reset_secret_cache()


class ServiceSettings(BaseServiceSettings):
    """A subclass, because that is how the base is meant to be used."""

    table_prefix: str = "webbpulse-test"


def test_defaults_are_safe_for_local_use() -> None:
    """Unconfigured settings default to the local, non-production values."""
    settings = ServiceSettings()
    assert settings.environment == "local"
    assert settings.log_level == "INFO"
    assert settings.app_secrets_arn == ""
    assert settings.cors_allow_origins == []
    assert settings.is_production is False


def test_environment_is_read_from_the_environment(monkeypatch: MonkeyPatch) -> None:
    """ENVIRONMENT=production sets `environment` and flips `is_production`."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    settings = ServiceSettings()
    assert settings.environment == "production"
    assert settings.is_production is True


def test_staging_is_not_production(monkeypatch: MonkeyPatch) -> None:
    """Guarding on `is_production` must not accidentally include staging."""
    monkeypatch.setenv("ENVIRONMENT", "staging")
    assert ServiceSettings().is_production is False


def test_an_unknown_environment_is_rejected(monkeypatch: MonkeyPatch) -> None:
    """An environment name outside the allowed set raises."""
    monkeypatch.setenv("ENVIRONMENT", "prod")
    with pytest.raises(ValueError, match="environment"):
        ServiceSettings()


@pytest.mark.parametrize("given,expected", [("debug", "DEBUG"), ("Warning", "WARNING")])
def test_log_level_is_normalised(monkeypatch: MonkeyPatch, given: str, expected: str) -> None:
    """A log level of any case is upper cased."""
    monkeypatch.setenv("LOG_LEVEL", given)
    assert ServiceSettings().log_level == expected


def test_an_invalid_log_level_is_rejected(monkeypatch: MonkeyPatch) -> None:
    """A typo here would otherwise silently fall back and lose every log line below it."""
    monkeypatch.setenv("LOG_LEVEL", "VERBOSE")
    with pytest.raises(ValueError, match="log_level"):
        ServiceSettings()


def test_cors_origins_accept_a_comma_separated_string(monkeypatch: MonkeyPatch) -> None:
    """Terraform passes a plain string in an environment variable, not a JSON list."""
    monkeypatch.setenv("CORS_ALLOW_ORIGINS", "https://a.example, https://b.example")
    assert ServiceSettings().cors_allow_origins == ["https://a.example", "https://b.example"]


def test_cors_origins_accept_a_json_list(monkeypatch: MonkeyPatch) -> None:
    """A JSON list in CORS_ALLOW_ORIGINS parses into a list of origins."""
    monkeypatch.setenv("CORS_ALLOW_ORIGINS", '["https://a.example"]')
    assert ServiceSettings().cors_allow_origins == ["https://a.example"]


def test_cors_origins_empty_string_is_no_origins(monkeypatch: MonkeyPatch) -> None:
    """A blank CORS_ALLOW_ORIGINS means no allowed origins, not one empty origin."""
    monkeypatch.setenv("CORS_ALLOW_ORIGINS", "  ")
    assert ServiceSettings().cors_allow_origins == []


def test_load_json_secret_returns_the_parsed_object() -> None:
    """`load_json_secret` returns the secret string parsed as a JSON object."""
    with mock_aws():
        client = boto3.client("secretsmanager", region_name="us-west-2")
        arn = client.create_secret(Name="webbpulse-test/app", SecretString=json.dumps({"SECRET_KEY": "s3cret"}))["ARN"]
        assert load_json_secret(arn, "us-west-2") == {"SECRET_KEY": "s3cret"}


def test_load_json_secret_is_cached_per_arn() -> None:
    """On Lambda this cache is what keeps a warm invoke from calling Secrets Manager."""
    with mock_aws():
        client = boto3.client("secretsmanager", region_name="us-west-2")
        arn = client.create_secret(Name="cached/app", SecretString='{"a": "1"}')["ARN"]

        assert load_json_secret(arn, "us-west-2") == {"a": "1"}
        client.put_secret_value(SecretId=arn, SecretString='{"a": "2"}')
        assert load_json_secret(arn, "us-west-2") == {"a": "1"}, "the cached value must be reused"

        reset_secret_cache()
        assert load_json_secret(arn, "us-west-2") == {"a": "2"}


def test_a_non_json_secret_raises() -> None:
    """A secret whose string is not JSON raises `SecretNotJsonObjectError`."""
    with mock_aws():
        client = boto3.client("secretsmanager", region_name="us-west-2")
        arn = client.create_secret(Name="plain/app", SecretString="not json")["ARN"]
        with pytest.raises(SecretNotJsonObjectError, match="not valid JSON"):
            load_json_secret(arn, "us-west-2")


def test_a_json_array_secret_raises() -> None:
    """A JSON array parses but cannot be merged into settings, so it must fail loudly."""
    with mock_aws():
        client = boto3.client("secretsmanager", region_name="us-west-2")
        arn = client.create_secret(Name="array/app", SecretString="[1, 2]")["ARN"]
        with pytest.raises(SecretNotJsonObjectError, match="expected a JSON object"):
            load_json_secret(arn, "us-west-2")


def test_load_secrets_is_empty_without_an_arn(monkeypatch: MonkeyPatch) -> None:
    """Local development and tests configure from the environment, which is not an error."""
    monkeypatch.delenv("APP_SECRETS_ARN", raising=False)
    assert ServiceSettings().load_secrets() == {}


def test_load_secrets_reads_the_configured_arn(monkeypatch: MonkeyPatch) -> None:
    """`load_secrets` reads the secret named by APP_SECRETS_ARN."""
    with mock_aws():
        client = boto3.client("secretsmanager", region_name="us-west-2")
        arn = client.create_secret(Name="wired/app", SecretString='{"K": "V"}')["ARN"]
        monkeypatch.setenv("APP_SECRETS_ARN", arn)
        monkeypatch.setenv("AWS_DEFAULT_REGION", "us-west-2")
        assert ServiceSettings().load_secrets() == {"K": "V"}


def test_importing_the_module_calls_no_aws(monkeypatch: MonkeyPatch) -> None:
    """Importing the module and constructing settings must make no boto3 client."""
    import boto3 as boto3_module

    def explode(*args: Any, **kwargs: Any) -> Any:
        """Fail if boto3 builds a client during import or construction."""
        raise AssertionError("boto3.client must not be called during import or construction.")

    monkeypatch.setattr(boto3_module, "client", explode)
    ServiceSettings()
