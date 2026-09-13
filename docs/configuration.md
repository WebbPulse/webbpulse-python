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

## `webbpulse.ci`

Domain discovery for the per-domain pytest matrix in the organisation's reusable
`python-ci.yml`. A service's test suite grows with its domains, and running it as one pytest
invocation makes CI slower every time a domain is added. The reusable workflow runs one job
per domain instead, so wall clock time tracks the largest domain rather than the sum of all
of them, and this module is what tells that workflow which jobs to create.

The convention is declarative and lives in the service's own `pyproject.toml`, so adding a
domain to CI is adding a line rather than editing a workflow:

```toml
[tool.webbpulse.ci]
# The directory the `shared` job sweeps. Defaults to "tests".
test-root = "tests"

[tool.webbpulse.ci.domains]
identity = ["tests/auth", "tests/dependencies"]
catalog = ["tests/api/endpoints/test_parts.py", "tests/api/endpoints/test_categories.py"]
vehicles = ["tests/api/endpoints/test_car_generations.py"]
```

Every path is relative to the directory holding `pyproject.toml`, which is the workflow's
`working-directory`, so the strings reach pytest unchanged. A value may name a directory or
a single test file: a suite that is not yet split by directory still has to be splittable,
and requiring the files to move first would make adopting this a refactor rather than a
configuration change.

Everything under `test-root` that no domain claims runs in a job called `shared`, which the
module computes as a deselection rather than a list. `shared` runs the whole test root with
an `--ignore` for every claimed path, so the two kinds of job together run each test exactly
once and a new test file is covered by CI the moment it is written. The failure mode of
forgetting to claim a file is that it runs in `shared`, which is slower but never silent.

`shared` is reserved and cannot also be a domain name, because the two would produce one
colliding matrix job. A domain that claims no paths is rejected for the same reason: its job
would run pytest with no path arguments and collect the entire suite.

Two commands, both of which write to stdout:

| Command | Output |
| --- | --- |
| `python -m webbpulse.ci domains` | A JSON array of domain names, for `fromJson` in a matrix `strategy`. `--include-shared` appends `shared`. |
| `python -m webbpulse.ci pytest-args --domain <name>` | That job's pytest path arguments, shell quoted. For `shared`, the test root plus an `--ignore` per claimed path. |

`--project-dir` points both at the directory holding `pyproject.toml`, and defaults to the
working directory.

A repository with no `[tool.webbpulse.ci]` table gets an empty array and a `shared` job
carrying its whole suite, which is exactly the behaviour it had before the split existed.
That is what lets the shared workflow call this unconditionally.

The module imports only the standard library. The workflow calls it in a bare interpreter
before the service's dependencies are installed, so it must not need an extra, and
`tests/test_ci.py` asserts that in a subprocess rather than trusting the reading.
