# webbpulse

Shared infrastructure code for WebbPulse FastAPI services on AWS Lambda.

Every WebbPulse backend had grown its own copy of the same eight concerns: settings and
secret loading, JSON logging, tracing, the FastAPI app factory, rate limiting, the DynamoDB
access layer, the Lambda entrypoint, and the test fixtures. They had drifted, and the
drift was where the bugs lived. This package is one implementation of each, typed and
tested, so a service imports them instead of maintaining them.

Nothing here runs an AWS call at import time. Every module is importable on its own, and
the optional dependencies sit behind extras, so a service installs only the surface it
uses.

## Install

From the WebbPulse CodeArtifact repository:

```bash
aws codeartifact login --tool pip \
  --domain webbpulse --domain-owner 432410731887 \
  --repository python --region us-west-2

pip install "webbpulse[fastapi,dynamodb,otel]"
```

For local work on the package itself:

```bash
python3.13 -m venv .venv
.venv/bin/pip install -e ".[dynamodb,fastapi,otel,testing]" mypy ruff pytest-cov \
  "boto3-stubs[dynamodb,secretsmanager]" botocore-stubs
.venv/bin/ruff check . && .venv/bin/ruff format --check .
.venv/bin/mypy
.venv/bin/pytest
```

### Extras

The base install carries only `pydantic` and `pydantic-settings`, which every consumer
needs. Everything else is opt-in.

| Extra | Pulls in | Needed by |
| --- | --- | --- |
| `dynamodb` | `boto3`, `botocore` | `webbpulse.dynamodb`, `webbpulse.ratelimit`, and secret loading in `webbpulse.config` |
| `fastapi` | `fastapi`, `starlette`, `uvicorn` | `webbpulse.http`, `webbpulse.lambda_entry`, the `webbpulse.ratelimit` dependency |
| `otel` | the OpenTelemetry SDK, the OTLP HTTP exporter, the FastAPI and botocore instrumentations | `webbpulse.otel` |
| `testing` | `moto`, `pytest`, `httpx2` | `webbpulse.testing` |

A typical service installs `webbpulse[fastapi,dynamodb,otel]` at runtime and adds
`testing` in its dev dependencies. `webbpulse.otel` and `webbpulse.http` degrade to no-ops
rather than failing to import when their extra is absent, so a service can adopt them one
at a time.

## Modules

### `webbpulse.config`

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

### `webbpulse.logging`

`configure_logging(level=..., service=..., environment=...)` installs a JSON formatter on
the root logger, writing to stdout. One object per line, with a top-level `level` and an
RFC 3339 `timestamp`:

```json
{"timestamp":"2026-09-07T18:20:31.114Z","level":"ERROR","message":"...","logger":"app.api","trace_id":"...","span_id":"..."}
```

Those two keys are the ones that matter. With a function's log format set to JSON, Lambda
filters events by an application-supplied `level` key and needs a valid RFC 3339
`timestamp` beside it; AWS documents that an unparseable timestamp makes Lambda assign the
event level INFO and stamp its own time, which silently defeats both `application_log_level`
filtering and the `{ $.level = "ERROR" }` metric filter behind the `api-alarms` module.

There is no double wrapping. AWS documents that Lambda "doesn't double-encode any logs that
are already JSON encoded", so a function can set `log_format = "JSON"` and use this
formatter at the same time. Avoid `print()`, which Lambda captures as plain text whatever
the format setting.

Trace and span ids are merged in whenever a span is recording, so a log line and a trace
join on the same value. Anything passed as `extra={...}` becomes a top-level key, which is
what lets a CloudWatch metric filter or an Insights query select on it. `configure_logging`
is idempotent, replaces Lambda's own root handler rather than adding to it, and reattaches
uvicorn's loggers so access lines are JSON too.

### `webbpulse.otel`

OpenTelemetry is the only instrumentation in this package. Sentry is gone, and there is no
collector in the request path.

```python
from webbpulse.otel import configure_tracing

configure_tracing("webbpulse-staging-posts", environment="staging")
```

Traces go straight to the CloudWatch X-Ray OTLP endpoint,
`https://xray.<region>.amazonaws.com/v1/traces`. Three things about that endpoint are easy
to get wrong, and all three look identical from outside: traces simply never appear.

1. **It authenticates with SigV4.** A plain OTLP exporter posts unsigned and gets a 403.
   The signing comes from the ADOT Python distribution, `aws-opentelemetry-distro` 0.10.0
   or later with `botocore` present, selected by `OTEL_PYTHON_DISTRO=aws_distro` and
   `OTEL_PYTHON_CONFIGURATOR=aws_configurator` and activated by launching under
   `opentelemetry-instrument`. `configure_tracing` warns loudly when the endpoint is an
   X-Ray one and that distro is missing, rather than exporting into a 403 forever.
2. **Transaction Search must be enabled on the account.** It is a one-time per-account
   setting that an application cannot make for itself.
3. **The execution role needs X-Ray write access.** AWS prescribes the
   `AWSXrayWriteOnlyPolicy` managed policy.

The endpoint takes OTLP over HTTP only, so `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` must be
`http/protobuf`; there is no gRPC listener. Note the host is per-signal: logs go to
`logs.<region>.amazonaws.com/v1/logs` and metrics to `monitoring.<region>.amazonaws.com/v1/metrics`.
This package sends traces only, and CloudWatch handles logs.

`instrument_fastapi(app)` attaches the FastAPI instrumentation, excluding the health route
by default because the Web Adapter polls it on every cold start. Botocore is instrumented
too, so DynamoDB and Secrets Manager calls become spans. All of it is a no-op when the
`otel` extra is absent or when `WEBBPULSE_OTEL_DISABLED` or `OTEL_SDK_DISABLED` is set, so
tests and local runs cost nothing.

On sampling: exporting straight to the endpoint leaves the SDK at `parentbased_always_on`,
which AWS documents as up to twenty times the ingestion of their recommended 0.05 ratio.
This module does not override whatever the environment says, so set
`OTEL_TRACES_SAMPLER=parentbased_traceidratio` with a ratio below 1.0 once volume justifies
it.

### `webbpulse.http`

`create_app` builds one domain's FastAPI application, adding, in the order a request
traverses them: CORS, the request id middleware, the structured error handlers, and a
`GET /health` route.

```python
from webbpulse.http import create_app

app = create_app([posts_router], service_name="posts", version="1.4.0", settings=settings)
```

CORS origins come from `settings` or an explicit list. When credentials are allowed the
origin list must be exact and never `"*"`: the CORS specification forbids that pair, and it
is the browser that rejects the response, which makes a server misconfiguration look like a
client bug.

Errors all render in one envelope, so a validation failure and an unhandled exception have
the same shape and neither leaks a stack trace to the caller:

```json
{"success": false, "status": 422, "message": "...", "request_id": "..."}
```

Validation errors return only the location and the reason, never the offending input, which
can be a password or a token.

`RequestIdMiddleware` honours an inbound `X-Request-ID`, mints a UUID4 otherwise, bounds the
length so a hostile header cannot inflate every downstream log line, echoes it on the
response, and sets it on the active span. Read it in a route with `Depends(request_id)`.

`client_ip(request)` is the piece that most needed sharing. It reads the source IP that API
Gateway itself observed, from the `x-amzn-request-context` header the Web Adapter injects,
handling both payload shapes: `requestContext.http.sourceIp` for an HTTP API (format 2.0)
and `requestContext.identity.sourceIp` for a REST API (format 1.0). It never reads
`X-Forwarded-For`. Behind API Gateway the leftmost hop of that header is whatever the client
sent, so limiting on it lets a caller mint a fresh identity per request by varying one
header, which is worse than not limiting at all because it looks like it works. The
per-app version this replaces read `request.scope["aws.event"]`, which Mangum populated and
the Web Adapter does not, so on migration it silently stopped matching and fell through to
the spoofable header with nothing failing.

`health_router` is liveness only and never touches DynamoDB, deliberately. The Web Adapter
polls this path as its readiness check on every cold start, so a health route that queries a
table adds that query to every cold start and makes the function fail to start when the
table is briefly unavailable. Readiness checks that do touch dependencies belong on a path
the adapter does not poll.

`mount_all` is the second composition root:

```python
app = mount_all({"/api/v1/posts": posts_app, "/api/v1/skills": skills_app})
```

Production runs one entrypoint per domain, each importing only its own routers, which keeps
cold starts cheap and one domain's dependencies invisible to another. Local development,
the test suite and a plain `docker run` want the whole surface on one port, and this builds
it from the very same app objects rather than from a second wiring that can drift. Each
mount path must be the prefix API Gateway routes to that domain's function, so a path that
works locally works in production.

### `webbpulse.ratelimit`

Per-identity fixed window counting on one `<prefix>-rate-limits` table, partition key `pk`,
with a TTL. One `UpdateItem` per request and no read before the write:

```python
from fastapi import Depends
from webbpulse.ratelimit import rate_limit

@router.post(
    "/login",
    dependencies=[Depends(rate_limit(limit=10, window_seconds=900, namespace="login"))],
)
async def login(...): ...
```

Per route, which is the point: a login route and a read route want very different ceilings,
and a global middleware cannot express that without a table of path patterns. `namespace`
keeps limits that share the table independent.

The window comes from the clock, `floor(now / window) * window`, so the item key carries the
window start and a new window is a new item rather than a mutation. Counting is a single
atomic `ADD count :one` with a conditional `SET` of the TTL, so two concurrent requests in
different execution environments cannot both read 9 and write 10. A rejected request still
counts, which stops a caller holding the counter at exactly the limit. The honest trade of a
fixed window is the boundary: a caller can send `limit` requests at the end of one window and
`limit` more at the start of the next. A sliding log fixes that and costs a read plus an
unbounded item; for protecting a login route the fixed window is the right guarantee at one
write per request.

**It fails open.** Every boto3 error is caught, logged at WARNING with
`rate_limit_failed_open=True`, and the request is allowed. A rate limiter is a protective
control, not an authorisation control: if DynamoDB is unavailable, refusing every request
turns a dependency blip into a full outage, which is strictly worse than briefly not
enforcing a limit. The WARNING is the compensating control, so alarm on it, because a
limiter that has been failing open for a week is invisible otherwise. Anything that must
deny on failure is authorisation and does not belong here.

Responses carry the current IETF draft fields. `draft-ietf-httpapi-ratelimit-headers`
dropped the old `RateLimit-Limit` / `RateLimit-Remaining` / `RateLimit-Reset` triple at
draft-08 in favour of two RFC 9651 structured fields, and draft-11 of 23 May 2026 defines
only those:

```http
RateLimit: "default";r=4;t=30
RateLimit-Policy: "default";q=10;w=60
```

`r` is the remaining quota, `t` the seconds until reset, `q` the quota and `w` the window.
The `X-RateLimit-*` triple is emitted alongside because that is what most clients actually
parse; the draft mentions it only as a survey of existing practice.

### `webbpulse.dynamodb`

A thin repository base over one table, plus the helpers every service was reimplementing.

```python
from webbpulse.dynamodb import Repository


class Posts(Repository):
    logical_name = "posts"

    def by_author(self, author_id: str) -> list[dict]:
        return list(self.iter_query(Key("pk").eq(f"author#{author_id}")))
```

`table_name("posts")` prefixes the logical name from `DYNAMODB_TABLE_PREFIX`, giving
`webbpulse-staging-posts`, which is what the Terraform `dynamodb-tables` module creates. The
boto3 resource is cached per process and created on first use, never at import.

`query` returns a `Page` carrying `items`, `last_evaluated_key`, `count` and `has_more`.
An empty `items` list with a non-`None` cursor is normal and does **not** mean no results,
which is the pagination bug every hand-rolled loop eventually has; `iter_query` follows
`LastEvaluatedKey` across pages so callers need not get it right.

`encode_numbers` recursively converts `float` to `Decimal` via `str`, because boto3 refuses
a float outright and going through `str` avoids the binary float error that `Decimal(0.1)`
carries. `ttl_at(datetime)` and `ttl_in(seconds)` produce the integer epoch **seconds** a
TTL attribute needs; milliseconds are the classic mistake and put expiry fifty thousand
years out. A TTL is a storage reclaim mechanism on DynamoDB's own schedule, never an access
control.

### `webbpulse.lambda_entry`

There is no Lambda handler and no Mangum. The AWS Lambda Web Adapter is an external
extension that starts before the application, turns each invoke into an ordinary HTTP
request against `127.0.0.1:$AWS_LWA_PORT`, and turns the response back. The application is a
normal ASGI server, so the identical image runs on Lambda, in a local container, and
anywhere else.

```python
# app/posts/entrypoint.py
from webbpulse.lambda_entry import run_uvicorn
from webbpulse.logging import configure_logging
from webbpulse.otel import configure_tracing
from app.posts import build_app


def main() -> None:
    configure_logging(level="INFO", service="posts", environment="staging")
    configure_tracing("webbpulse-staging-posts", environment="staging")
    run_uvicorn(build_app())


if __name__ == "__main__":
    main()
```

`run_uvicorn` binds `AWS_LWA_PORT`, falling back to `PORT` and then 8080, which is the
adapter's own precedence. Binding a port the adapter is not polling is the most common Web
Adapter misconfiguration and it presents as the readiness check never passing and the
function timing out with no application logs at all.

The Dockerfile is one `COPY` from a pinned public image. Version 1.0.1 is current, and the
image is multi-arch, so the same line serves arm64 and x86_64:

```dockerfile
# syntax=docker/dockerfile:1.7
FROM public.ecr.aws/docker/library/python:3.13-slim AS build
WORKDIR /build
COPY requirements.txt .
RUN --mount=type=secret,id=codeartifact_token \
    PIP_INDEX_URL="https://aws:$(cat /run/secrets/codeartifact_token)@webbpulse-432410731887.d.codeartifact.us-west-2.amazonaws.com/pypi/python/simple/" \
    pip install --no-cache-dir --target /deps -r requirements.txt

FROM public.ecr.aws/docker/library/python:3.13-slim
COPY --from=public.ecr.aws/awsguru/aws-lambda-adapter:1.0.1 /lambda-adapter /opt/extensions/lambda-adapter
COPY --from=build /deps /var/task
COPY app /var/task/app
ENV PYTHONPATH=/var/task \
    PYTHONUNBUFFERED=1 \
    AWS_LWA_PORT=8080 \
    AWS_LWA_READINESS_CHECK_PATH=/health \
    AWS_LWA_ASYNC_INIT=true
WORKDIR /var/task
CMD ["python", "-m", "app.posts.entrypoint"]
```

Each line there is a real failure mode:

- **`/opt/extensions/lambda-adapter` is the required destination.** Lambda only starts
  binaries it finds in `/opt/extensions`. Copied anywhere else the adapter never runs, the
  function has no handler, and every invoke times out.
- **The CodeArtifact token is a BuildKit secret mount, never a build arg or `ENV`.** Both of
  those persist into the image and are visible in `docker history`.
- **`PYTHONUNBUFFERED=1`** keeps log lines from sitting in a buffer while the execution
  environment is frozen between invokes and arriving attributed to a later request.
- **`AWS_LWA_ASYNC_INIT=true`** lets a slow import finish inside Lambda's 10 second init
  window instead of counting against the first invoke.
- **`AWS_LWA_READINESS_CHECK_PATH=/health`** must point at a route that does no I/O. The
  adapter's default is `/`.

### `webbpulse.testing`

Pytest fixtures for a moto-backed table and a `TestClient`. Enable them from a service's
`conftest.py`:

```python
pytest_plugins = ["webbpulse.testing"]
```

| Fixture or helper | What it gives you |
| --- | --- |
| `aws_credentials` | Placeholder credentials and region, so a mis-scoped mock cannot reach a real account |
| `dynamodb_resource` | A moto-mocked DynamoDB resource, with the package's cached resource cleared on both sides |
| `create_table(...)` | One on-demand table with an optional range key and TTL |
| `rate_limit_table` | The `rate-limits` table shaped exactly as Terraform creates it |
| `test_client(app, source_ip=...)` | A `TestClient` whose requests carry a realistic API Gateway request context |
| `make_request_context_headers(...)` | That header on its own, in either payload shape |

`test_client` is the one worth knowing about. Without the injected context header a
`TestClient` request has no API Gateway context at all, so `client_ip` falls back to the
peer address and a service's rate limit tests pass while never covering the branch that
actually runs in production.

## CI and releases

`.github/workflows/ci.yml` calls `WebbPulse/.github/.github/workflows/python-ci.yml@v1` on
every push and pull request, overriding the inputs that assume a backend service: this
package sits at the repository root and installs from `pyproject.toml`. A second job in the
same file runs mypy, because the reusable workflow has no type checking step and this
package ships `py.typed`, so its annotations are part of its contract.

`.github/workflows/publish.yml` calls
`WebbPulse/.github/.github/workflows/codeartifact-publish-python.yml@v1` on `v*` tags,
publishing to CodeArtifact domain `webbpulse`, repository `python`, in `us-west-2`. That
workflow is idempotent: it looks the version up first and skips with a notice rather than
failing, so re-running an already released tag stays green.

### Required repository configuration

| Secret | Used by | Value |
| --- | --- | --- |
| `CODEARTIFACT_PUBLISH_ROLE_ARN` | `publish.yml` | ARN of the OIDC role in the artifacts account allowed to publish to CodeArtifact |
| `CODEARTIFACT_DOMAIN_OWNER` | `publish.yml` | `432410731887`, the account that owns the `webbpulse` domain |

Both are passed straight through to the reusable workflow, which needs
`codeartifact:GetAuthorizationToken` and `sts:GetServiceBearerToken` on the assumed role.
The `publish` GitHub Environment named in `publish.yml` is where the release approval and
the environment-scoped secrets live; create it in repository settings. `ci.yml` needs no
secrets, because this package's own dependencies all come from PyPI.

### Cutting a release

The tag decides only *when* the workflow runs. The version that is published comes from
`src/webbpulse/_version.py` through hatchling, so set `__version__` and tag the same commit:

```bash
# edit src/webbpulse/_version.py to 0.2.0, commit it, then
git tag v0.2.0 && git push origin v0.2.0
```

Deriving the version from the tag instead would leave an sdist built outside a checkout
unversioned, and CodeArtifact rejects that.

## Per-app migration notes

Both backends grew these concerns independently, so the migration is mostly deletion. What
follows is what each app replaces, and what has to stay.

### CarModPicker

`backend/app/`. The app factory in `main.py` configures root logging inline, calls
`init_sentry()` before building the `FastAPI` object, then adds CORS, two
`@app.middleware("http")` functions and the error handlers.

| Shared module | Replaces |
| --- | --- |
| `config` | the pydantic-settings base and `.env` wiring in `core/config.py`, and the CORS origin parsing. The app's own fields become a subclass |
| `logging` | `core/logging.py`, `core/log_context.py`, and the inline `logging.basicConfig` block in `main.py` |
| `otel` | `core/sentry.py` in full, and its call from `main.py` |
| `http` | `api/utils/response_patterns.py`, `api/middleware/error_handler.py`, `api/middleware/request_context.py`, and the CORS block in `main.py` |
| `ratelimit` | `api/middleware/rate_limiter.py` in full, including `RateLimitConfig` and the eight `RATE_LIMIT_*` settings fields |
| `dynamodb` | `db/dynamo/client.py`, `serialization.py`, `errors.py`, and the generic body of `repository.py` |
| `lambda_entry` | `app/lambda_handler.py` entirely. The bare `Mangum(app, lifespan="off")` has no replacement import; the Web Adapter takes its place |
| `testing` | the moto and `reset_clients` fixture plumbing in `tests/conftest.py` |

Two things change behaviour rather than just moving:

- **Rate limiting becomes shared state.** The current limiter is in-process, eight
  `defaultdict(list)` timestamp lists, which counts per execution environment. Under Lambda
  that means the real ceiling is the configured limit multiplied by the number of warm
  environments, and it resets on every cold start. Moving to the DynamoDB table makes the
  limit mean what it says. The response headers change too: the per-minute and per-hour
  `X-RateLimit-*-Minute` / `-Hour` pairs become the single window described above, so any
  client parsing them needs checking.
- **Client IP stops trusting the caller.** `rate_limiter.py` reads the leftmost
  `X-Forwarded-For` hop and falls back to `request.client.host`. Behind API Gateway that
  leftmost hop is client-supplied, so the current limiter can be bypassed with one header.
  `client_ip` reads the API Gateway request context instead.

Secret loading also changes shape. `core/secrets.py` writes every key of the secret into
`os.environ`; `load_json_secret` returns a dict and caches it, leaving the environment
alone.

Staying in the app: the 25 `TableSpec` definitions, `car_inference.py` and
`category_inference.py`, `cloudwatch_emf.py`, the SES templates, `db/dynamo/search.py`,
`authorization.py`, the `chrome-extension://` CORS regex and the `null` origin, the
`X-Admin-Cron-Key` header, the `RUN_STARTUP_TASKS` seeding, and the sitemap routes. The
CORS regex and extra header mean `create_app` gets `cors_allow_origins` explicitly and the
app adds its own regex, rather than passing `settings` alone.

### WebbPulse-Portfolio

`backend/app/`. Smaller and closer to the shared shape already, but with no error envelope
and no request id at all.

| Shared module | Replaces |
| --- | --- |
| `config` | the `SECRET_FIELDS` / `resolve_secrets` validator, `LOCALHOST_ORIGINS` and `parse_cors_origins` in `config.py` |
| `logging` | `core/logging.py`, `RequestLoggingMiddleware` in `core/middleware.py`, and the `POWERTOOLS_*` settings |
| `otel` | the Powertools `inject_lambda_context` correlation wrapper |
| `http` | `TrailingSlashMiddleware`, the CORS block and the `/health` route in `main.py`. The error envelope and request id are new capability, not a replacement |
| `ratelimit` | `core/login_limiter.py` in full, including its `client_ip()` |
| `dynamodb` | `db/client.py` and `db/serializer.py` verbatim, the generic `Repository` base, and `table_name()` |
| `lambda_entry` | `app/lambda_handler.py` and `scripts/build_lambda.sh` |
| `testing` | the `mock_aws` fixture, `create_all_tables`, `db_client.reset()` and `secrets.reset_cache()` in `tests/conftest.py` |

Four things to watch:

- **`client_ip()` is the bug this package exists to fix.** It reads
  `request.scope["aws.event"]["requestContext"]["http"]["sourceIp"]` first. Mangum populates
  `aws.event`; the Web Adapter does not. So on migration that branch silently stops matching
  and the function falls through to the leftmost `X-Forwarded-For`, making the login limiter
  bypassable with one header, with nothing failing and no error logged.
- **The limiter moves table and gains fail-open.** Login failures are currently
  `LOGIN_FAIL#<ip>` items in the shared `meta` table; they move to the dedicated
  `<prefix>-rate-limits` table. The current code also propagates any `ClientError` other
  than the conditional failure, so DynamoDB being unavailable currently fails the login
  request closed. The shared limiter fails open and logs a WARNING instead.
- **`/health` must stop querying DynamoDB.** It currently calls `database_status()`, which
  reads the site content item. The Web Adapter polls that path on every cold start, so it
  has to become the liveness-only route; move the dependency check to a separate path.
- **Importing the app currently requires secrets.** The `resolve_secrets` validator raises
  when a secret field is still unset, so importing anything under `app/` fails without them.
  Settings construction moves behind an `lru_cache` accessor so that becomes a request-time
  failure rather than an import-time one.

Staying in the app: `PostRepository` and the per-entity ordering, `core/admin.py`,
`core/site_content.py` and `SeedMiddleware` (which must not be wired into the public
entrypoint), `api/seo.py`, the constant-time `_DUMMY_HASH` timing equaliser, the integer ids
and `skip`/`limit` the frontend depends on, and the trailing-slash tolerance.

### Not shared, deliberately

There is no shared `auth` module. The two apps use `python-jose` and PyJWT respectively, and
bcrypt 4.3.0 against 5.0.0, which differ in 72-byte truncation and default rounds. Merging
them would silently change how existing password hashes verify, so authentication stays
per-app until those are reconciled on purpose.
