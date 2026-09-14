# Configuration and settings

Settings, secret loading, and the CI domain-matrix helper. Back to the [README](../README.md).

## `webbpulse.config`

`BaseServiceSettings` is the pydantic-settings base a service subclasses. It carries only
what is genuinely common: `environment`, `service_name`, `log_level`, `app_secrets_arn`,
and the two CORS fields. Anything domain-specific belongs in the subclass.

```python
from functools import lru_cache
from webbpulse.config import BaseServiceSettings


class Settings(BaseServiceSettings):
    table_prefix: str = "webbpulse-staging"
    google_client_id: str = ""


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
```

Construct settings behind a cache in the service, not at import, so a missing environment
variable fails a request rather than the whole cold start.

`environment` drives two properties. `is_production` is true for production only, never
staging. `rate_limiting_enabled` is false for the environments in
`RATE_LIMIT_FREE_ENVIRONMENTS`, which are `staging` and `local`, and true everywhere else, by
the `rate_limits_apply` convention. Staging sits behind the access gate and hosts the full e2e
suite, so nothing in it throttles; a local stack is one developer or one CI runner sharing a
single source IP bucket, so the limiter would pace a run it protects nothing from. Wire every
limiter through that property rather than a product variable, and the e2e client stops pacing
itself against either for the same reason.

List-valued environment variables accept both JSON and the bare comma-separated form, so
`CORS_ALLOW_ORIGINS=https://a.example,https://b.example` works. That needed a custom
settings source: pydantic-settings calls `json.loads` on a complex field *inside* the
source, before any `mode="before"` validator can see it.

`load_json_secret(arn)` reads one Secrets Manager secret whose value is a JSON object and
returns it as a dict, cached per ARN for the life of the process. On Lambda that is once
per execution environment, so a warm invoke never calls Secrets Manager. It is a function,
never a module-level call: an import that reaches Secrets Manager turns every cold start
into a synchronous dependency on another service.

```python
secrets = get_settings().load_secrets()  # {} locally, where no ARN is set
```

A secret that is not a JSON object raises `SecretNotJsonObjectError`. A missing secret or a
denied read lets botocore's `ClientError` propagate, because both are unrecoverable.
