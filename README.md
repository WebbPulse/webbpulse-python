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

For local work on the package itself, uv owns the environment from `pyproject.toml` and the
committed `uv.lock`, and CI runs these same commands:

```bash
uv sync --locked
source .venv/bin/activate
ruff check src tests && ruff format --check src tests
mypy
python -m pytest -n 4 --cov=webbpulse
```

The base install carries only `pydantic` and `pydantic-settings`. Everything else is opt-in:

| Extra | Pulls in | Needed by |
| --- | --- | --- |
| `dynamodb` | `boto3`, `botocore` | `webbpulse.dynamodb`, `webbpulse.ratelimit`, `webbpulse.storage`, secret loading in `webbpulse.config` |
| `fastapi` | `fastapi`, `starlette`, `uvicorn` | `webbpulse.http`, `webbpulse.lambda_entry`, the `webbpulse.ratelimit` dependency |
| `otel` | the OpenTelemetry SDK, the OTLP HTTP exporter, the FastAPI and botocore instrumentations | `webbpulse.otel` |
| `aws-otel` | the AWS OpenTelemetry distro | the SigV4 signed X-Ray exporter |
| `security` | `PyJWT`, `bcrypt` | `webbpulse.security` |
| `identity` | `PyJWT[crypto]`, `fastapi` | `webbpulse.identity` |
| `oauth` | `httpx` | OAuth sign-in, on top of `identity` |
| `device-login` | `httpx`, `keyring` | `webbpulse.device_login`, a CLI signing in through the identity device grant |
| `github` | `httpx`, `PyJWT[crypto]` | `webbpulse.integrations.github` |
| `stripe` | `stripe` | `webbpulse.integrations.stripe` |
| `passkeys` | `webauthn` | `webbpulse.identity.passkeys`, only when `passkeys_enabled` |
| `testing` | `moto`, `pytest`, `httpx2` | `webbpulse.testing` |

A typical service installs `webbpulse[fastapi,dynamodb,otel]` at runtime and adds `testing` in
its dev dependencies.

## Module map

| Module | What it provides | Reference |
| --- | --- | --- |
| `webbpulse.config` | `BaseServiceSettings`, the pydantic-settings base; `load_json_secret` for one Secrets Manager JSON secret | [configuration.md](docs/configuration.md) |
| `webbpulse.logging` | `configure_logging`, `get_logger`, `JsonFormatter`: one JSON object per line with `level` and an RFC 3339 `timestamp`; an `extra` key that collides with a `LogRecord` attribute is emitted as `extra_<key>` | [logging-and-metrics.md](docs/logging-and-metrics.md) |
| `webbpulse.log_context` | `set_request_id`, `set_user_id`, `task_context`, `bind_context`, `LogContextFilter`: request and correlation context on ContextVars | [logging-and-metrics.md](docs/logging-and-metrics.md) |
| `webbpulse.metrics` | `emit`, `timed`, `MetricsEmitter`, `metrics_enabled_from_env`: CloudWatch Embedded Metric Format on stdout | [logging-and-metrics.md](docs/logging-and-metrics.md) |
| `webbpulse.otel` | `configure_tracing`, `instrument_fastapi`, `TailSamplingSpanProcessor`: tracing with errors always sampled | [tracing.md](docs/tracing.md), [tracing-sampling.md](docs/tracing-sampling.md) |
| `webbpulse.http` | `create_app`, `mount_all`, `health_router`, `RequestIdMiddleware`, `user_id_dependency`, the shared error envelope, `verify_hmac_signature`, `CursorPage` with `cursor_page`, `encode_cursor` and `decode_cursor`, and `conditional_response`, `not_modified_response` and `weak_etag` for ETag and 304 polling | [http.md](docs/http.md), [error-handlers.md](docs/error-handlers.md) |
| `webbpulse.composition` | `Domain`, `DomainRegistry`, `build_domain_app`, `domain_entrypoint`, `configure_tracing`, `check_secrets`, `local_authorizer`, `scope_for`: the domain registry and the one builder both composition roots go through | [composition.md](docs/composition.md) |
| `webbpulse.events` | `stream_consumer_app`, `register_stream_consumer`, `events_path`: the one route a DynamoDB Streams or SQS consumer serves behind the Web Adapter; `EventEnvelope`, `enqueue`, `deserialize_image` and `source_table` on the producing side | [events.md](docs/events.md) |
| `webbpulse.events.webhooks` | `WebhookDispatcher`, `WebhookSender`, `RetryPolicy`, `signature_headers`: signed outbound webhooks with jittered retries and a dead-letter hook | [webhooks.md](docs/webhooks.md) |
| `webbpulse.messages` | `STATUS_MESSAGES`, `refusal`, `forbidden`, `unauthenticated`, `rate_limited`: the user-facing sentence each refusal renders; `extract_mentions` for `@handle` mentions in Markdown | [error-handlers.md](docs/error-handlers.md) |
| `webbpulse.dynamodb` | `Repository` with `set_attributes`, `remove_attributes` and `get_many`, `Page`, `table_name`, `ttl_at`, `ttl_in`, `encode_numbers`, `new_ulid`, `IdempotencyStore`, and the `DynamoError` family, whose `ConditionFailed` every conditional write raises | [data-access.md](docs/data-access.md) |
| `webbpulse.storage` | `presigned_put`, `PresignedUpload`: a presigned S3 PUT bounded by a signed content type and content length; `presigned_get`, `PresignedDownload`: a presigned S3 GET with optional signed response headers; `UPLOAD_CONTENT_TYPES`, `is_allowed_upload` and `disposition_for` for what an upload may declare and how it is served back | [data-access.md](docs/data-access.md) |
| `webbpulse.ratelimit` | `rate_limit`, `rate_limit_middleware`, `LimitClass`, `classify`, `identity_from_principal`, a fixed window limiter on one DynamoDB table, failing open | [data-access.md](docs/data-access.md) |
| `webbpulse.email_cap` | `EmailSendCap`, `EmailCapPolicy`, `EmailCapLimits`: outbound email caps per recipient, per tenant and per app day on the rate limits table, off by default, failing open | [email-caps.md](docs/email-caps.md) |
| `webbpulse.security` | `hash_password`, `verify_password`, `needs_rehash`, `create_token`, `decode_token`, `bearer_claims` | [security.md](docs/security.md) |
| `webbpulse.identity` | App-managed identity: password, session, email link, TOTP, OAuth and passkey flows, plus a KMS-backed `TokenService` and a JWKS | [identity.md](docs/identity.md), [the standard](docs/identity-standard.md) |
| `webbpulse.identity.oauth_server` | An OAuth 2.1 authorization server for hosting a remote MCP server: discovery, PKCE code grant, dynamic registration, consent | [oauth-server.md](docs/oauth-server.md) |
| `webbpulse.integrations.github` | `GitHubAppClient`: the App JWT, cached installation tokens, check runs, commit statuses, issue comments and installation reads; `load_github_app_settings` for the standard `GITHUB_*` keys; `convert_manifest_code` for the App manifest flow | [GitHub App client](#github-app-client) |
| `webbpulse.integrations.stripe` | `load_stripe_settings` for the standard `STRIPE_*` keys; `stripe_client` for a `stripe.StripeClient`; `verify_webhook_event` and `claim_webhook_event` for a verified, exactly-once webhook receiver | [Stripe](#stripe) |
| `webbpulse.lambda_entry` | `run_uvicorn`, `is_lambda`, `resolve_port`: the AWS Lambda Web Adapter entrypoint, with no Mangum and no handler | [packaging.md](docs/packaging.md) |
| `webbpulse.testing` | Pytest fixtures: `test_client`, `create_table`, `rate_limit_table`, `make_request_context_headers`, `FakeKms`, `FakeIdempotencyStore`, `FakePresigner`, `FakeQueue`, `FakeWebhookSender`, `sign_stripe_payload`; `assert_entrypoint_isolation` for the per-domain image check; `primary_keys_only` (or `enforce_primary_keys`) makes moto refuse a key that is not exactly the table's primary key, as DynamoDB does | [packaging.md](docs/packaging.md) |
| `webbpulse.e2e` | A pytest plugin and generic post-deploy suite: route cut, coverage, reachability, identity, frontend and hygiene against a real stage | [e2e.md](docs/e2e.md) |
| `webbpulse.ops.config` | The `webbpulse-config` console script: operators set keys in the `<prefix>/app` secret and the `/<prefix>/config` parameter | [Operator config CLI](#operator-config-cli) |
| `webbpulse.ops.admin` | The `webbpulse-admin` console script: operators grant, revoke and list admins in a product's identity `users` table | [Operator admin CLI](#operator-admin-cli) |
| `webbpulse.tf` | The `wp-tf` console script: plan and apply runs on the WebbPulse Terraform control plane from a directory, with the log streamed | [Terraform CLI](#terraform-cli-wp-tf) |

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

## Operator config CLI

Every product keeps its secrets in one Secrets Manager JSON secret, `<prefix>/app`, and its
private non-secret configuration in one SSM String parameter, `/<prefix>/config`, holding a
JSON object. Terraform creates both and ignores their values; operators set the values with
their own AWS SSO identity through `webbpulse-config`. Every product already depends on
`webbpulse` with boto3 (the `dynamodb` extra), so the script is on the path in each product
repo:

```bash
export AWS_PROFILE=CarModPicker-Staging/AgentToolkit

uv run webbpulse-config --prefix carmodpicker-staging secret set OAUTH_GITHUB_CLIENT_SECRET
openssl rand -base64 32 | uv run webbpulse-config --prefix carmodpicker-staging secret set SECRET_KEY
uv run webbpulse-config --prefix carmodpicker-staging secret keys
uv run webbpulse-config --prefix carmodpicker-staging secret unset OLD_KEY

uv run webbpulse-config --prefix carmodpicker-staging config set ALLOWED_EMAILS '["a@b.c"]'
uv run webbpulse-config --prefix carmodpicker-staging config get ALLOWED_EMAILS
uv run webbpulse-config --prefix carmodpicker-staging config unset ALLOWED_EMAILS
```

| Command | Does |
| --- | --- |
| `secret set KEY` | Reads the value from a hidden, confirmed prompt on a terminal, otherwise from stdin with one trailing newline dropped, and merges it into the secret |
| `secret unset KEY` | Removes one key |
| `secret keys` | Prints key names, one per line; no command prints a secret value |
| `config set KEY VALUE` | Stores VALUE as JSON when it parses, otherwise as a string; `--string` forces a string. Creates a missing parameter holding just that key |
| `config get [KEY]` | Prints one value (a string raw, anything else as JSON), or the whole object |
| `config unset KEY` | Removes one key |

Target options go before or after the subcommand. `--prefix` resolves both names;
`--secret-id` and `--parameter-name` override either for an estate with non-standard names
(Portfolio's secret is `webbpulse-<env>/app`). `--profile` and `--region` default to the AWS
SDK chain, so `AWS_PROFILE` and the profile's region work unchanged.

Every write re-reads the current object, changes one key, keeps every other key, and checks
the current version again just before writing. If another writer landed in between it
retries from a fresh read, and after three retries it gives up without writing. Setting a
key to the value it already holds, or unsetting an absent key, writes nothing. Empty keys
and empty secret values are refused, and a secret key that is not UPPER_SNAKE draws a
warning.

`config set` on a parameter that does not exist yet creates it as a Standard tier `String`
holding `{"KEY": VALUE}`, with the description the platform-modules `operator-config` module
sets, and prints that it did. That seeds a fresh environment before its first plan imports the
parameter, with no raw `aws ssm put-parameter`. The create never overwrites: if another writer
created the parameter first, the key is merged into theirs as usual. Tags are not set, so an
estate whose provider has `default_tags` sees the import plan an in-place tag update. `config
get` and `config unset` on a missing parameter still exit `3` and create nothing.

Data goes to stdout and diagnostics to stderr. Exit codes: `0` ok, `1` AWS or SDK error, `2`
usage or a refused value, `3` the secret or parameter does not exist (apply terraform
first), `4` the stored value is not a JSON object, `5` a concurrent change outlasted the
retries, `6` `config get` found no such key.

## Operator admin CLI

A product admin is a row in the product's identity `users` table (`<prefix>-users`) with
`is_admin` set. `webbpulse-admin` grants, revokes and lists admins, finding a user by address
through the `email_lower-index` or by id:

```bash
uv run webbpulse-admin --profile CarModPicker-Staging/AdministratorAccess \
    --prefix carmodpicker-staging grant --email someone@example.com
uv run webbpulse-admin --profile CarModPicker-Staging/AdministratorAccess \
    --prefix carmodpicker-staging revoke --user-id 3f2c0e1a-0000-0000-0000-000000000000
uv run webbpulse-admin --profile CarModPicker-Staging/AdministratorAccess \
    --prefix carmodpicker-staging grant --email someone@example.com --dry-run
uv run webbpulse-admin --profile CarModPicker-Staging/AdministratorAccess \
    --prefix carmodpicker-staging list
```

| Command | Does |
| --- | --- |
| `grant (--email E \| --user-id ID) [--dry-run]` | Sets `is_admin`, `admin_granted_by` and `admin_granted_at`, and removes the revoke attributes |
| `revoke (--email E \| --user-id ID) [--dry-run]` | Clears `is_admin`, sets `admin_revoked_by` and `admin_revoked_at`, and removes the grant attributes |
| `list` | Prints each admin as `<user id>\t<masked email>`, sorted by id |

`--profile` is required: the tool never falls back to `AWS_PROFILE` or the default credential
chain. `--region` defaults to the profile's region. `--prefix` resolves `<prefix>-users` and
`--table-name` overrides it. Target options go before or after the subcommand.

Each write is one conditional `UpdateItem` requiring the row to exist and to be in the
opposite state, so a repeated grant or revoke writes nothing and says so, and a lost race
with another operator reads back as a no-op. The acting identity is the ARN
`sts:GetCallerIdentity` returns. Every `grant` and `revoke`, dry runs and no-ops included,
prints one JSON audit line on stdout (`event`, `action`, `user_id`, masked `email`, `table`,
`actor_arn`, `at`, `changed`, `dry_run`); the row itself keeps who made the latest change and
when. There is no separate audit table. Addresses are only ever printed masked, as
`t***@g***.com`.

Data goes to stdout and diagnostics to stderr. Exit codes: `0` ok, `1` AWS or SDK error, `2`
usage, `3` no such user, `4` the users table does not exist.

## Terraform CLI (`wp-tf`)

`wp-tf` replaces a remote `terraform plan` and `terraform apply` against HCP Terraform. It
tars a directory, starts a run on a control plane workspace and streams the log. Install it with the `tf`
extra (`uv tool install "webbpulse[tf]"` against the CodeArtifact index, or add the extra to a
project).

```bash
terraform login terraform.webbpulse.com
wp-tf plan -w my-workspace                  # plan the current directory
wp-tf plan infra/prod -w ws-... --detailed-exitcode --destroy
wp-tf plan -w my-workspace --no-follow      # print the run id and return
wp-tf apply infra/prod -w my-workspace      # plan, ask, then stream the apply
wp-tf apply -w my-workspace --auto-approve  # apply without asking
wp-tf confirm run-... [--comment ...] [--no-follow]
wp-tf discard run-... [--comment ...]
wp-tf logs run-... [--phase apply] [-f]
wp-tf status run-...
wp-tf workspaces
wp-tf login [--add-scope state:download]    # sign in through the browser
wp-tf logout
```

- **Key.** It looks for `WP_TF_TOKEN`, then `TF_TOKEN_<host>`, then the `wp-tf login`
  session in the OS keyring (refreshed as needed), then the key `terraform login` wrote to
  `credentials.tfrc.json`.
- **Login.** `wp-tf login` prints a URL and a code, you approve in the browser, and the
  session lasts up to 12 hours. `wp-tf logout` revokes the session on the server and forgets
  it.
- **Scopes.** With no flag, `wp-tf login` gets the control plane's default set.
  `--add-scope SCOPE` asks for the standard set (every read and write scope plus
  `runs:apply`) and the named scope, so adding one never drops the rest. `--scope SCOPE`
  asks for exactly the named scopes, for a narrower session. `state:download` and `admin`
  are granted only when named. `wp-tf login --help` lists the standard set.
- **Apply.** `wp-tf apply` uploads and plans like `plan`, prints the change counts, then asks
  `Only 'yes' will be accepted to approve.` on stderr and reads the answer from stdin. Any
  other answer discards the run and exits `1`. Without `--auto-approve` it refuses a stdin
  that is not a terminal instead of waiting. Confirming needs `runs:apply`; a 403 says to run
  `wp-tf login --add-scope runs:apply`. `confirm` and `discard` act on an existing run.
  Ctrl-C while the apply streams stops following and leaves the apply running.
- **Host.** `--host` or `WP_TF_HOST` sets the host, defaulting to
  `terraform.webbpulse.com`. The API origin comes from the host's discovery document and must
  be https on the host or a subdomain. `--api-url` or `WP_TF_API_URL` can name it instead; it
  must be https, except on a local stack (`localhost`).
- **Access gate.** A gated host needs the gate's origin-verify value. `WP_TF_GATE` wins when
  set. Otherwise, with AWS credentials that can read it, `wp-tf` reads the SecureString
  `/<prefix>/access-gate/origin-verify` from SSM. The prefix comes from `--gate-prefix`, then
  `WP_TF_GATE_PREFIX`, then the host: `webbpulse-terraform-prod` for `terraform.webbpulse.com`
  and `webbpulse-terraform-stg` for `staging.terraform.webbpulse.com`. The region is the AWS
  profile's, else `us-west-2`. With no credentials it goes on without a gate. A host default
  that cannot be read prints a warning naming the parameter, and a prefix named on purpose
  that cannot be read fails the command.
- **Working directory.** When a workspace has a working directory, run `wp-tf` from that
  directory. The upload is rooted that many levels up, as HCP Terraform does.
- **What the upload skips.** A `.terraformignore` at the upload root filters it with
  gitignore rules. `.git`, `.terraform` and local `*.tfstate` files are always skipped.
  `.tfvars` files are configuration, so they are uploaded. Uploads over 250 MB are refused.
- **Output and exit codes.** Log lines go to stdout and progress to stderr. It exits `0` when
  the plan or apply succeeds and `1` on any failure or a declined apply. It exits `2` under
  `--detailed-exitcode` when the plan has changes, and `130` after Ctrl-C, which cancels a
  run that is still planning. Tokens and the gate
  value are never printed.

## GitHub App client

`webbpulse.integrations.github` (the `github` extra) is a small synchronous client for a
GitHub App. It reads its configuration from the standard keys in the `<prefix>/app` secret,
with a non-empty environment variable of the same name winning per key:

| Key | Required | Holds |
| --- | --- | --- |
| `GITHUB_APP_ID` | yes | The App id |
| `GITHUB_PRIVATE_KEY` | yes | The App private key as PEM, PKCS1 or PKCS8, with real newlines; a literal `\n` is not unescaped |
| `GITHUB_APP_INSTALLATION_ID` | no | Pins one installation; without it the installation is looked up per repository and cached |
| `GITHUB_CLIENT_ID` | no | The App's OAuth client id, for the product's own use |
| `GITHUB_CLIENT_SECRET` | no | The App's OAuth client secret, for the product's own use |
| `GITHUB_WEBHOOK_SECRET` | no | The webhook signing secret, for the product's own use; check it with `webbpulse.http.verify_hmac_signature` |

```python
import os

from webbpulse.integrations.github import CheckRunOutput, GitHubAppClient, load_github_app_settings

settings = load_github_app_settings(os.environ["APP_SECRETS_ARN"])
with GitHubAppClient.from_settings(settings) as github:
    github.create_check_run(
        "WebbPulse/example",
        name="Example",
        head_sha=sha,
        conclusion="success",
        output=CheckRunOutput(title="Passed", summary="All checks passed."),
    )
```

Installation tokens are cached per client instance until five minutes before they expire.
Every failure is a `GitHubError` subclass chosen by status (`GitHubNotFound`,
`GitHubRateLimited` with `retry_after`, and so on). Only a 2xx is success: redirects are
never followed, and a 3xx, such as a renamed repository's 301, raises `GitHubRedirected`
with its `location`. The private key, client secret,
webhook secret and tokens stay out of reprs, error messages and logs. Webhook routing and
product naming stay in the product.

Typed reads cover commits, comparisons, pull requests with their commits and files, check
runs, issue comments, tags and releases. Reads retry a 5xx, a dropped connection or a refused
token (re-minted) up to `read_attempts` times with doubling backoff; writes never retry.
Listings take 100 per page and stop at a short page or after `max_pages` (default 10), so a
result of `100 * max_pages` items may be truncated. `download_tarball` and
`download_release_asset` stream to a file with a `max_bytes` limit and answer its size and
SHA-256. The redirect GitHub answers is followed only to its own archive and asset hosts,
without the installation token, and the signed URL never appears in errors or logs.

An App is created per environment through GitHub's manifest flow: the product posts its
manifest to `https://github.com/settings/apps/new` (or
`https://github.com/organizations/<org>/settings/apps/new`) with a `state`, GitHub redirects
back with a one-time `code`, and `convert_manifest_code(code)` answers the new App with its
credentials masked. It needs no App configuration. Write the credentials into the `app`
secret under the keys above in one version with
`SecretStore(client, secret_id).set_many(app.app_secret_values())` from `webbpulse.ops.config`,
or by hand with `webbpulse-config secret set`. The writer needs `secretsmanager:PutSecretValue`
on that secret only, and the app-secrets module needs `json_preserve_unmanaged` so an apply
keeps the keys.

## Stripe

`webbpulse.integrations.stripe` (the `stripe` extra) configures the official `stripe`
package from the standard keys in the `<prefix>/app` secret, with a non-empty environment
variable of the same name winning per key. Each product has its own Stripe account, so each
product and environment holds its own keys:

| Key | Required | Holds |
| --- | --- | --- |
| `STRIPE_API_KEY` | yes | A restricted key (`rk_`), preferred, or the secret key (`sk_`); a publishable key is refused |
| `STRIPE_WEBHOOK_SECRET` | no | The webhook endpoint's signing secret (`whsec_`); needed only to receive webhooks |
| `STRIPE_API_VERSION` | no | Pins the API version the client sends; left unset, the SDK's own version, which its types describe |

The keys are set by an operator with the `webbpulse-config` CLI, never through Terraform. A
webhook signing secret in particular must never pass through a Terraform variable, resource
or data source, since plan and state hold it in plaintext; the app-secrets module needs
`json_preserve_unmanaged` so an apply keeps the keys.

```bash
uv run webbpulse-config --prefix carmodpicker-staging secret set STRIPE_API_KEY
uv run webbpulse-config --prefix carmodpicker-staging secret set STRIPE_WEBHOOK_SECRET
```

```python
from webbpulse.integrations.stripe import (
    StripeSignatureError,
    claim_webhook_event,
    load_stripe_settings,
    stripe_client,
    verify_webhook_event,
)

settings = load_stripe_settings()
client = stripe_client(settings)
session = client.v1.checkout.sessions.create(params={"mode": "subscription", ...})

@router.post("/stripe/webhooks")
async def stripe_webhook(request: Request) -> Response:
    try:
        event = verify_webhook_event(await request.body(), request.headers.get("stripe-signature"), settings, client=client)
    except StripeSignatureError:
        return Response(status_code=400)
    if not claim_webhook_event(event, idempotency_store):
        return Response(status_code=200)
    handle(event)
    return Response(status_code=200)
```

`verify_webhook_event` takes the raw body bytes only, never a parsed and re-serialised
copy, and refuses a delivery signed more than five minutes ago. A missing signing secret
raises `StripeNotConfigured`; a missing, wrong, malformed or stale signature raises
`StripeSignatureError`; both are `StripeIntegrationError`. `claim_webhook_event` claims
`stripe:event:<id>` for seven days through any store with an `IdempotencyStore`-shaped
`claim`, and answers False for a redelivery; release `event_claim_key(event.id)` when the
work fails so Stripe's retry can win. In tests, `webbpulse.testing.sign_stripe_payload`
signs a body the way Stripe does, and `FakeIdempotencyStore` stands in for the table.

## Step-up gate

`require_recent_auth(max_age_seconds)` guards a sensitive route on how recently the person
signed in, read from the `auth_time` claim. It composes with the scope check by taking it as
its claims dependency, and API keys pass it, since a key has no login to age:

```python
from fastapi import Depends

from webbpulse.identity import claims_or_api_key, require_recent_auth, require_scopes

claims = claims_or_api_key(store=api_keys)
admin = require_scopes("workspace:admin", claims_dependency=claims)
sudo = require_recent_auth(600, claims_dependency=admin)


@router.delete("/workspaces/{workspace_id}")
def delete_workspace(workspace_id: str, caller=Depends(sudo)) -> None: ...
```

A login older than the window, or a token with no `auth_time`, is refused with a 401 in the
shared envelope and an RFC 9470 challenge, so a frontend can prompt for step-up and retry:

```
HTTP/1.1 401
WWW-Authenticate: Bearer error="insufficient_user_authentication", error_description="A more recent authentication is required", max_age=600

{"success": false, "status": 401, "message": "A more recent authentication is required.",
 "request_id": "...", "error_code": "STEP_UP_REQUIRED", "max_age": 600}
```

The client steps up on `POST <issuer path>/step-up` with a bearer token and one of
`{"password": "..."}`, `{"code": "123456"}` or `{"challenge_id": "...", "credential": {...}}`,
and gets `{"access_token", "token_type": "Bearer", "expires_in"}` back with no cookie change.
The password is checked exactly as login checks it and counts toward the same lockout; it is
enough on its own even when the user has MFA, as in GitHub sudo mode. A user with neither a
password nor a second factor gets 503 `MFA_NOT_CONFIGURED`. Step-up records its `auth_time` on
the refresh family, and a refresh carries the family's `auth_time` rather than bumping it, so
refreshing never counts as signing in again. In an e2e suite, `webbpulse.e2e.step_up(session,
password)` or the `stepped_up_session` fixture steps up the run's user and refreshes onto the
new `auth_time`. Tokens minted by the OAuth authorization server for MCP clients carry no
`auth_time`, so the gate refuses them by design.

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
| `ApiKeyStore` | ABC | `src/webbpulse/identity/api_keys.py` | Long-lived machine keys, stored as hashes. `DynamoApiKeyStore` and `InMemoryApiKeyStore` ship |
| `EmailSender` | ABC | `src/webbpulse/identity/email.py` | Sending mail. `SesV2EmailSender`, `RecordingEmailSender` and `CappedEmailSender` ship |
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
- **MCP `/authorize` reads the refresh cookie, so keep `cookie_path` at or above the
  issuer path.** A browser tab opened by an MCP client carries no bearer. Narrow the cookie
  path and a signed-in user is sent to `mcp_login_url`, or answered 401, every time. The
  login page must allowlist the returned authorize URL by exact origin and path.
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
  `rate_limit_failed_open=True`, counted as `RateLimitFailedOpen` in the `WebbPulse/RateLimit`
  namespace, and the request is allowed. Watch that metric, because a limiter that has been
  failing open for a week is otherwise invisible. Anything that must deny on failure is
  authorisation and does not belong there.
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
| [docs/oauth-server.md](docs/oauth-server.md) | The OAuth 2.1 authorization server for a remote MCP server |
| [docs/identity-passkeys.md](docs/identity-passkeys.md) | WebAuthn registration, passwordless sign-in and credential management |
| [docs/http.md](docs/http.md) | `create_app`, the error envelope shapes, and conditional GET |
| [docs/email-caps.md](docs/email-caps.md) | Outbound email send caps and `CappedEmailSender` |
| [docs/error-handlers.md](docs/error-handlers.md) | DynamoDB and custom exception handlers |
| [docs/events.md](docs/events.md) | The stream and queue consumer route, and publishing an event |
| [docs/webhooks.md](docs/webhooks.md) | Signed outbound webhooks: the scheme, the retries and the fake |
| [docs/data-access.md](docs/data-access.md) | The repository base, counters, ULIDs, idempotency claims, presigned uploads and the rate limiter |
| [docs/logging-and-metrics.md](docs/logging-and-metrics.md) | JSON logging, log context and EMF metrics |
| [docs/tracing.md](docs/tracing.md) | Tracing setup |
| [docs/tracing-sampling.md](docs/tracing-sampling.md) | The tail sampler and the Lambda flush |
| [docs/security.md](docs/security.md) | Password hashing and JWTs |
| [docs/configuration.md](docs/configuration.md) | Settings and secrets |
| [docs/packaging.md](docs/packaging.md) | The Web Adapter entrypoint, the Dockerfile and the test fixtures |
| [docs/e2e.md](docs/e2e.md) | The post-deploy end to end plugin: env vars, fixtures and product wiring |
| [docs/releases.md](docs/releases.md) | CI, publishing and cutting a release |
| [docs/migration-notes.md](docs/migration-notes.md) | What each consuming app replaced on adoption |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
