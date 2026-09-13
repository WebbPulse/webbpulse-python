# webbpulse

Shared infrastructure code for WebbPulse FastAPI services on AWS Lambda. Every WebbPulse
backend had grown its own copy of the same concerns: settings and secret loading, JSON
logging, tracing, the FastAPI app factory, rate limiting, the DynamoDB access layer, password
hashing and JWTs, app-managed identity, the Lambda entrypoint, and the test fixtures. This
package is one typed and tested implementation of each, so a service imports them instead of
maintaining them. Nothing here runs an AWS call at import time, and the optional dependencies
sit behind extras, so a service installs only the surface it uses.

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
.venv/bin/pip install -e ".[aws-otel,dynamodb,fastapi,identity,oauth,otel,passkeys,security,testing]" \
  mypy ruff pytest-cov "boto3-stubs[dynamodb,kms,secretsmanager]" botocore-stubs
.venv/bin/ruff check . && .venv/bin/ruff format --check .
.venv/bin/mypy
.venv/bin/pytest
```

The base install carries only `pydantic` and `pydantic-settings`. Everything else is opt-in:

| Extra | Pulls in | Needed by |
| --- | --- | --- |
| `dynamodb` | `boto3`, `botocore` | `webbpulse.dynamodb`, `webbpulse.ratelimit`, secret loading in `webbpulse.config` |
| `fastapi` | `fastapi`, `starlette`, `uvicorn` | `webbpulse.http`, `webbpulse.lambda_entry`, the `webbpulse.ratelimit` dependency |
| `otel` | the OpenTelemetry SDK, the OTLP HTTP exporter, the FastAPI and botocore instrumentations | `webbpulse.otel` |
| `aws-otel` | the AWS OpenTelemetry distro | the SigV4 signed X-Ray exporter |
| `security` | `PyJWT`, `bcrypt` | `webbpulse.security` |
| `identity` | `PyJWT[crypto]`, `fastapi` | `webbpulse.identity` |
| `oauth` | `httpx` | OAuth sign-in, on top of `identity` |
| `passkeys` | `webauthn` | `webbpulse.identity.passkeys`, only when `passkeys_enabled` |
| `testing` | `moto`, `pytest`, `httpx2` | `webbpulse.testing` |

A typical service installs `webbpulse[fastapi,dynamodb,otel]` at runtime and adds `testing` in
its dev dependencies.

## Module map

| Module | What it provides | Reference |
| --- | --- | --- |
| `webbpulse.config` | `BaseServiceSettings`, the pydantic-settings base; `load_json_secret` for one Secrets Manager JSON secret | [configuration.md](docs/configuration.md) |
| `webbpulse.logging` | `configure_logging`, `get_logger`, `JsonFormatter`: one JSON object per line with `level` and an RFC 3339 `timestamp` | [logging-and-metrics.md](docs/logging-and-metrics.md) |
| `webbpulse.log_context` | `set_request_id`, `set_user_id`, `task_context`, `bind_context`, `LogContextFilter`: request and correlation context on ContextVars | [logging-and-metrics.md](docs/logging-and-metrics.md) |
| `webbpulse.metrics` | `emit`, `timed`, `MetricsEmitter`, `metrics_enabled_from_env`: CloudWatch Embedded Metric Format on stdout | [logging-and-metrics.md](docs/logging-and-metrics.md) |
| `webbpulse.otel` | `configure_tracing`, `instrument_fastapi`, `TailSamplingSpanProcessor`: tracing with errors always sampled | [tracing.md](docs/tracing.md), [tracing-sampling.md](docs/tracing-sampling.md) |
| `webbpulse.http` | `create_app`, `mount_all`, `health_router`, `RequestIdMiddleware`, `user_id_dependency`, and the shared error envelope | [http.md](docs/http.md), [error-handlers.md](docs/error-handlers.md) |
| `webbpulse.dynamodb` | `Repository`, `Page`, `table_name`, `ttl_at`, `ttl_in`, `encode_numbers`, and the `DynamoError` family | [data-access.md](docs/data-access.md) |
| `webbpulse.ratelimit` | `rate_limit`, a per-route fixed window limiter on one DynamoDB table, failing open | [data-access.md](docs/data-access.md) |
| `webbpulse.security` | `hash_password`, `verify_password`, `needs_rehash`, `create_token`, `decode_token`, `bearer_claims` | [security.md](docs/security.md) |
| `webbpulse.identity` | App-managed identity: password, session, email link, TOTP, OAuth and passkey flows, plus a KMS-backed `TokenService` and a JWKS | [identity.md](docs/identity.md), [the standard](docs/identity-standard.md) |
| `webbpulse.lambda_entry` | `run_uvicorn`, `is_lambda`, `resolve_port`: the AWS Lambda Web Adapter entrypoint, with no Mangum and no handler | [packaging.md](docs/packaging.md) |
| `webbpulse.testing` | Pytest fixtures: `test_client`, `create_table`, `rate_limit_table`, `make_request_context_headers` | [packaging.md](docs/packaging.md) |
| `webbpulse.ci` | Domain discovery for the per-domain pytest matrix in the organisation's reusable `python-ci.yml` | [configuration.md](docs/configuration.md) |

## Wiring a FastAPI domain Lambda

A complete domain, from settings to the process the Web Adapter talks to.

```python
# app/posts/settings.py
from functools import lru_cache

from webbpulse.config import BaseServiceSettings


class Settings(BaseServiceSettings):
    table_prefix: str = "webbpulse-staging"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
```

```python
# app/posts/repository.py
from webbpulse.dynamodb import Repository


class Posts(Repository):
    logical_name = "posts"
```

```python
# app/posts/api.py
from fastapi import APIRouter, Depends

from webbpulse.ratelimit import rate_limit

router = APIRouter(prefix="/posts", tags=["posts"])


@router.post("", dependencies=[Depends(rate_limit(limit=10, window_seconds=900, namespace="posts"))])
async def create_post() -> dict[str, str]:
    return {"status": "created"}
```

```python
# app/posts/app.py
from fastapi import FastAPI

from webbpulse.http import create_app

from app.posts.api import router
from app.posts.settings import get_settings


def build_app() -> FastAPI:
    return create_app(
        [router],
        service_name="posts",
        version="1.4.0",
        settings=get_settings(),
        dynamodb_error_handlers=True,
    )
```

```python
# app/posts/entrypoint.py
from webbpulse.lambda_entry import run_uvicorn
from webbpulse.logging import configure_logging
from webbpulse.otel import configure_tracing

from app.posts.app import build_app


def main() -> None:
    configure_logging(level="INFO", service="posts", environment="staging")
    configure_tracing("webbpulse-staging-posts", environment="staging")
    run_uvicorn(build_app())


if __name__ == "__main__":
    main()
```

`create_app` adds, in the order a request traverses them, CORS, `RequestIdMiddleware`, the
structured error handlers, and a `GET /health` route. Every error renders in one envelope,
so a validation failure, an unhandled exception and a request to a path that does not exist
all have the same shape and none leaks a stack trace:

```json
{"success": false, "status": 422, "message": "...", "request_id": "..."}
```

The container image, the Web Adapter environment variables and the Dockerfile are in
[packaging.md](docs/packaging.md).

## Hooks a consuming project implements

Everything below is a seam the package deliberately leaves to the product. Only
`IdentityHooks` is needed by a service that mounts identity; the storage ABCs all ship with
both a DynamoDB and an in-memory implementation, so a product subclasses one only to change
where the data lives.

| Hook | Kind | File | What the product owns |
| --- | --- | --- | --- |
| `IdentityHooks` | Protocol, `runtime_checkable` | `src/webbpulse/identity/hooks.py` | Who may sign in and what they may do: `load_user_by_id`, `load_user_by_email`, `may_authenticate`, `claims_for`, `on_user_created`, `create_user`, `mark_email_verified`, `user_repository`, `has_other_sign_in_method` |
| `BaseIdentityHooks` | Concrete base class | `src/webbpulse/identity/hooks.py` | The same surface, where every unimplemented hook raises `HookNotImplemented` at the call rather than at instantiation |
| `CredentialStore` | ABC | `src/webbpulse/identity/storage.py` | Where passwords live. `DynamoCredentialStore` and `InMemoryCredentialStore` ship |
| `RefreshTokenStore` | ABC | `src/webbpulse/identity/storage.py` | Refresh families and their rotation state |
| `IdentityTokenStore` | ABC | `src/webbpulse/identity/storage.py` | Single-use emailed verification and reset links |
| `TotpFactorStore` | ABC | `src/webbpulse/identity/storage.py` | Enrolled TOTP factors, holding only sealed seeds |
| `RecoveryCodeStore` | ABC | `src/webbpulse/identity/storage.py` | Hashed recovery codes |
| `PasskeyStore` | ABC | `src/webbpulse/identity/storage.py` | Registered WebAuthn credentials |
| `WebAuthnChallengeStore` | ABC | `src/webbpulse/identity/storage.py` | Single-use WebAuthn challenges |
| `LoginAttemptStore` | ABC | `src/webbpulse/identity/lockout.py` | Failed login attempts behind the progressive lockout |
| `OAuthStateStore` | ABC | `src/webbpulse/identity/oauth.py` | The in-flight authorization state |
| `OAuthLinkStore` | ABC | `src/webbpulse/identity/oauth.py` | The provider-to-user attachment |
| `EmailSender` | ABC | `src/webbpulse/identity/email.py` | Sending mail. `SesV2EmailSender` and `RecordingEmailSender` ship |
| `KmsClient` | Protocol | `src/webbpulse/identity/tokens.py` | The KMS surface `TokenService` signs with, so a test can substitute one |
| `KmsDataKeyClient` | Protocol | `src/webbpulse/identity/crypto.py` | The KMS surface `EnvelopeCipher` seals TOTP seeds with |
| `HttpClient` | Protocol | `src/webbpulse/identity/oauth.py` | The OAuth provider leg. `HttpxClient` ships |
| `SesV2Client` | Protocol | `src/webbpulse/identity/email.py` | The SES v2 surface `SesV2EmailSender` calls |

`IdentityStores` in `src/webbpulse/identity/storage.py` is the container that carries the
store instances into `build_identity_router`:

```python
import boto3

from webbpulse.identity import IdentitySettings, TokenService, build_identity_router

settings = IdentitySettings()  # reads IDENTITY_* from the environment
tokens = TokenService(settings, boto3.client("kms"))

app.include_router(build_identity_router(settings, hooks, stores, tokens=tokens))
```

## Gotchas

- **Do not call `set_user_id` from a sync (`def`) FastAPI dependency.** Starlette runs a sync
  dependency in a threadpool, which *copies* the context, so the binding is discarded and
  `user_id` reads `"-"` for the rest of the request. Nothing raises. Use
  `webbpulse.http.user_id_dependency`, which wraps the resolver in an `async def`, or `await
  webbpulse.http.bind_user_id(...)`. Portfolio shipped the broken shape to production.
- **Mount the identity router with no prefix.** The gateway builds the discovery URL as
  `issuer + "/.well-known/openid-configuration"`, so the issuer decides where the routes
  live and `build_identity_router` places itself there. A prefix of your own doubles the
  issuer path and hides both documents from the gateway.
- **Bind the port the Web Adapter polls.** `run_uvicorn` reads `AWS_LWA_PORT`, then `PORT`,
  then 8080. Binding anything else presents as the readiness check never passing and the
  function timing out with no application logs at all.
- **Copy the adapter to `/opt/extensions/lambda-adapter`.** Lambda starts only what it finds
  in `/opt/extensions`; anywhere else the adapter never runs and every invoke times out.
- **`AWS_LWA_READINESS_CHECK_PATH` must point at a route that does no I/O.** `GET /health`
  from `create_app` is that route. A health check that queries DynamoDB runs on every cold
  start.
- **The rate limiter fails open.** Every boto3 error is caught, logged at WARNING with
  `rate_limit_failed_open=True`, and the request is allowed. Alarm on that WARNING, because a
  limiter that has been failing open for a week is otherwise invisible. Anything that must
  deny on failure is authorisation and does not belong there.
- **CORS cannot allow credentials with a wildcard origin.** `create_app` raises `ValueError`
  when it is asked to, rather than letting the browser reject the response and make a server
  misconfiguration look like a client bug.
- **An empty `Page.items` with a non-`None` cursor is normal** and does not mean no results.
  Use `iter_query`, which follows `LastEvaluatedKey` across pages.
- **TTL attributes are epoch seconds, not milliseconds.** `ttl_at` and `ttl_in` produce the
  right unit. A TTL is a storage reclaim mechanism on DynamoDB's own schedule, never an
  access control.
- **`encode_numbers` converts `float` to `Decimal` via `str`.** boto3 refuses a float
  outright, and going through `str` avoids the binary float error `Decimal(0.1)` carries.
- **Every authorizer claim arrives as a string**, `exp` and `iat` included. `authorizer_claims`
  coerces them; reading the raw mapping and comparing `exp` as an integer will not work.
- **Passwords are truncated to 72 bytes internally.** bcrypt reads no more, and libraries
  disagree about the overflow: bcrypt 4.x truncates silently, 5.0 raises. `hash_password`
  truncates on a byte boundary so it behaves identically on both and still agrees with every
  hash already written.
- **Settings belong behind an `lru_cache` accessor, not at import.** A missing environment
  variable should fail a request, not the whole cold start.
- **`load_json_secret` is a function, never a module-level call.** An import that reaches
  Secrets Manager turns every cold start into a synchronous dependency on another service.
- **Use `test_client` from `webbpulse.testing`.** Without its injected API Gateway request
  context a `TestClient` request has none, so `client_ip` falls back to the peer address and
  rate limit tests pass while never covering the branch that runs in production.
- **Avoid `print()`.** Lambda captures it as plain text whatever the log format setting, which
  defeats both `application_log_level` filtering and the `{ $.level = "ERROR" }` metric filter.

## Further reading

| Document | Covers |
| --- | --- |
| [docs/identity-standard.md](docs/identity-standard.md) | The locked auth standard: goals, architecture, token design and security controls |
| [docs/identity-flows.md](docs/identity-flows.md) | Standard section 2.6: the nine request flows, step by step |
| [docs/identity-data-model.md](docs/identity-data-model.md) | Standard section 4: the tables, keys, indexes and every TTL |
| [docs/identity-configuration.md](docs/identity-configuration.md) | Standard section 6: `IdentitySettings`, mounting, and 6.3 `IdentityHooks` |
| [docs/identity-frontend.md](docs/identity-frontend.md) | Standard section 7: the frontend contract and the error codes |
| [docs/identity.md](docs/identity.md) | The identity package: routes, services, stores and wiring |
| [docs/identity-oauth.md](docs/identity-oauth.md) | OAuth sign-in and account linking |
| [docs/identity-passkeys.md](docs/identity-passkeys.md) | WebAuthn registration, passwordless sign-in and credential management |
| [docs/http.md](docs/http.md) | `create_app` and the error envelope shapes |
| [docs/error-handlers.md](docs/error-handlers.md) | DynamoDB and custom exception handlers |
| [docs/data-access.md](docs/data-access.md) | The repository base and the rate limiter |
| [docs/logging-and-metrics.md](docs/logging-and-metrics.md) | JSON logging, log context and EMF metrics |
| [docs/tracing.md](docs/tracing.md) | Tracing setup |
| [docs/tracing-sampling.md](docs/tracing-sampling.md) | The tail sampler and the Lambda flush |
| [docs/security.md](docs/security.md) | Password hashing and JWTs |
| [docs/configuration.md](docs/configuration.md) | Settings, secrets and the CI domain matrix |
| [docs/packaging.md](docs/packaging.md) | The Web Adapter entrypoint, the Dockerfile and the test fixtures |
| [docs/releases.md](docs/releases.md) | CI, publishing and cutting a release |
| [docs/migration-notes.md](docs/migration-notes.md) | What each consuming app replaced on adoption |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
