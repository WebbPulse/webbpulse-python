"""Settings base and the Secrets Manager JSON secret loader.

Two things live here, and they are deliberately separate.

`BaseServiceSettings` is the pydantic-settings base every service subclasses. It carries
only the fields that are genuinely common to every WebbPulse service: which environment
this is, what to log at, what the service is called, and where its shared secret lives.
Anything domain specific belongs in the subclass.

`load_json_secret` reads one Secrets Manager secret whose value is a JSON object and
returns it as a dict. It is cached per ARN for the life of the process, which on Lambda
means once per execution environment rather than once per invoke.

**Nothing in this module reads AWS at import time.** `load_json_secret` is a function, not
a module-level call, and the boto3 client it uses is created on first use. Importing this
module inside a Lambda handler must not cost a network round trip, because an import that
calls Secrets Manager turns every cold start into a synchronous dependency on another
service and fails the whole function when that service is slow.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

if TYPE_CHECKING:  # pragma: no cover - typing only
    from mypy_boto3_secretsmanager.client import SecretsManagerClient

__all__ = [
    "BaseServiceSettings",
    "Environment",
    "SecretNotJsonObjectError",
    "load_json_secret",
    "reset_secret_cache",
]

Environment = Literal["local", "test", "staging", "production"]

# The environment variable holding the ARN of the one JSON secret per service per
# environment. The name matches what the Portfolio and CarModPicker Terraform already sets.
APP_SECRETS_ARN_ENV = "APP_SECRETS_ARN"

_LOG_LEVELS = frozenset({"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"})


class SecretNotJsonObjectError(ValueError):
    """Raised when a secret's value is not a JSON object.

    A secret holding a bare string or a JSON array cannot be merged into settings, and
    failing loudly here beats a confusing `AttributeError` three frames later.
    """


class BaseServiceSettings(BaseSettings):
    """Base settings for a WebbPulse service.

    Subclass it and add the service's own fields::

        class Settings(BaseServiceSettings):
            table_prefix: str = "webbpulse-staging"
            google_client_id: str = ""

    Reading settings is the subclass's job, not this module's: instantiate the subclass
    behind an `lru_cache` in the service so construction happens on first use rather than
    at import.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        # Environment variables are conventionally upper case; pydantic-settings matches
        # case insensitively by default, and this keeps that explicit.
        case_sensitive=False,
    )

    environment: Environment = Field(
        default="local",
        description="Which deployment this is. Drives defaults elsewhere, never behaviour here.",
    )
    service_name: str = Field(
        default="webbpulse",
        description="Logical service name. Becomes the OpenTelemetry service.name.",
    )
    log_level: str = Field(
        default="INFO",
        description="Root log level, one of the standard logging level names.",
    )
    app_secrets_arn: str = Field(
        default="",
        description=(
            "ARN of the single Secrets Manager JSON secret for this service and "
            "environment. Empty locally, where secrets come from the environment."
        ),
    )
    cors_allow_origins: list[str] = Field(
        default_factory=list,
        description="Exact origins allowed by CORS. Never '*' when credentials are sent.",
    )
    cors_allow_credentials: bool = Field(
        default=True,
        description="Whether CORS permits cookies. Both apps authenticate by cookie.",
    )

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalise_log_level(cls, value: object) -> object:
        """Accept `info` and `INFO` alike, and reject a level that logging cannot use."""
        if not isinstance(value, str):
            return value
        upper = value.strip().upper()
        if upper not in _LOG_LEVELS:
            raise ValueError(f"log_level must be one of {sorted(_LOG_LEVELS)}, got {value!r}")
        return upper

    @field_validator("cors_allow_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        """Allow a comma separated string, which is how a Terraform env var arrives."""
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return []
            # A JSON list is handled by pydantic itself; only split the bare form.
            if stripped.startswith("["):
                return value
            return [part.strip() for part in stripped.split(",") if part.strip()]
        return value

    @property
    def is_production(self) -> bool:
        """True in production only. Staging is not production."""
        return self.environment == "production"

    def load_secrets(self) -> dict[str, Any]:
        """Load this service's JSON secret, or return `{}` when no ARN is configured.

        Local development and tests set no ARN and read their configuration from the
        environment, so an empty result is the normal path there rather than an error.
        """
        arn = self.app_secrets_arn or os.environ.get(APP_SECRETS_ARN_ENV, "")
        if not arn:
            return {}
        return load_json_secret(arn)


@lru_cache(maxsize=1)
def _secrets_client(region_name: str | None) -> SecretsManagerClient:
    """Create the Secrets Manager client once per process.

    Separate from `load_json_secret` so the cache on that function keys on the ARN alone
    and this one keys on the region, and so tests can clear either independently.
    """
    import boto3  # Imported lazily: the base install has no boto3.

    client: SecretsManagerClient = boto3.client("secretsmanager", region_name=region_name)
    return client


@lru_cache(maxsize=8)
def load_json_secret(arn: str, region_name: str | None = None) -> dict[str, Any]:
    """Fetch one Secrets Manager secret and parse its value as a JSON object.

    Cached per `(arn, region_name)` for the life of the process. On Lambda that is once per
    execution environment, so a warm invoke never calls Secrets Manager. The cache holds
    decrypted secret material in memory, which is the same exposure as an environment
    variable and considerably better than fetching on every request.

    Raises `SecretNotJsonObjectError` if the secret is not a JSON object, and lets
    botocore's own `ClientError` propagate for a missing secret or a denied read. Both are
    unrecoverable at startup and should fail the invoke rather than be swallowed.
    """
    response = _secrets_client(region_name).get_secret_value(SecretId=arn)
    raw = response.get("SecretString")
    if raw is None:
        # A binary secret is a configuration mistake for an application secret.
        raise SecretNotJsonObjectError(f"Secret {arn} holds binary data, not a JSON object.")

    try:
        parsed: object = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SecretNotJsonObjectError(f"Secret {arn} is not valid JSON: {exc}") from exc

    if not isinstance(parsed, dict):
        raise SecretNotJsonObjectError(
            f"Secret {arn} parsed as {type(parsed).__name__}, expected a JSON object."
        )
    return parsed


def reset_secret_cache() -> None:
    """Clear the secret and client caches. For tests, and for a credential rotation test."""
    load_json_secret.cache_clear()
    _secrets_client.cache_clear()
