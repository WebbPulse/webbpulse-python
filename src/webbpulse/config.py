"""Settings base and the Secrets Manager JSON secret loader.

`BaseServiceSettings` is the pydantic-settings base every service subclasses, and
`load_json_secret` reads one JSON secret, cached per ARN. Neither reads AWS at import time.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

if TYPE_CHECKING:  # pragma: no cover
    from mypy_boto3_secretsmanager.client import SecretsManagerClient

__all__ = [
    "BaseServiceSettings",
    "Environment",
    "SecretNotJsonObjectError",
    "load_json_secret",
    "reset_secret_cache",
    "split_csv",
]

Environment = Literal["local", "test", "staging", "production"]

APP_SECRETS_ARN_ENV = "APP_SECRETS_ARN"

_LOG_LEVELS = frozenset({"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"})


class SecretNotJsonObjectError(ValueError):
    """Raised when a secret's value is not a JSON object and so cannot become settings."""


def split_csv(value: str) -> list[str]:
    """Split a comma separated environment value into a list, dropping empty entries."""
    return [part.strip() for part in value.split(",") if part.strip()]


class _CsvOrJsonEnvSource(PydanticBaseSettingsSource):
    """Wrap a settings source so list fields accept CSV as well as JSON.

    Only the decoding of a complex value is overridden; everything else is delegated to the
    wrapped source.
    """

    def __init__(self, wrapped: PydanticBaseSettingsSource) -> None:
        """Wrap `wrapped`, capturing its real JSON decoder before any rebinding."""
        self._wrapped = wrapped
        self._decode_json = wrapped.decode_complex_value
        super().__init__(wrapped.settings_cls)

    def decode_complex_value(self, field_name: str, field: Any, value: Any) -> Any:
        """Decode a complex value, treating a non-JSON-looking string as CSV."""
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return []
            if not stripped.startswith(("[", "{", '"')):
                return split_csv(stripped)
        return self._decode_json(field_name, field, value)

    def get_field_value(self, field: Any, field_name: str) -> tuple[Any, str, bool]:
        """Delegate field lookup to the wrapped source."""
        return self._wrapped.get_field_value(field, field_name)

    def __call__(self) -> dict[str, Any]:
        """Run the wrapped source with this decoder installed on it for the call."""
        self._wrapped.decode_complex_value = self.decode_complex_value  # type: ignore[method-assign]
        try:
            return self._wrapped()
        finally:
            self._wrapped.decode_complex_value = self._decode_json  # type: ignore[method-assign]


class BaseServiceSettings(BaseSettings):
    """Base settings for a WebbPulse service.

    Subclass it, add the service's own fields, and instantiate the subclass behind an
    `lru_cache` so construction happens on first use rather than at import.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
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

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Parse list-valued environment and dotenv variables as CSV as well as JSON.

        The source decodes complex values before any validator runs, so the CSV form has to
        be handled at the source layer.
        """
        return (
            init_settings,
            _CsvOrJsonEnvSource(env_settings),
            _CsvOrJsonEnvSource(dotenv_settings),
            file_secret_settings,
        )

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
    """Create the Secrets Manager client once per process, keyed on region."""
    import boto3

    client: SecretsManagerClient = boto3.client("secretsmanager", region_name=region_name)
    return client


@lru_cache(maxsize=8)
def load_json_secret(arn: str, region_name: str | None = None) -> dict[str, Any]:
    """Fetch one Secrets Manager secret and parse its value as a JSON object.

    Cached per `(arn, region_name)` for the life of the process. Raises
    `SecretNotJsonObjectError` when the value is not a JSON object.
    """
    response = _secrets_client(region_name).get_secret_value(SecretId=arn)
    raw = response.get("SecretString")
    if raw is None:
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
