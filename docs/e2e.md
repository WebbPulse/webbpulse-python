# End to end tests: the `webbpulse.e2e` plugin

The post-deploy suite every product runs against a real stage. The plugin supplies the
fixtures and the generic tests; the product supplies its OpenAPI document and its cleanup.
Back to the [README](../README.md).

Install it with the `e2e` extra, which adds `httpx`, `boto3` and `pytest`:

```toml
[dependency-groups]
dev = ["webbpulse[e2e]"]
```

## What it checks

The generic suite runs in six groups, each parametrised so one route or one operation is one
junit case:

| Group | Asks |
| --- | --- |
| `TestRouteCut` | Every live route key is expressible, has an integration, and the access log confirms which key served the probe |
| `TestCoverage` | Every OpenAPI operation resolves to a live route, carries no trailing slash, and lands on a route whose authorizer matches its security requirement |
| `TestReachability` | Every operation is answered by the API rather than by the gate, the limiter or a catch-all |
| `TestIdentity` | Login returns an RS256 token carrying this environment's issuer and audience, refresh and logout work, the JWKS is reachable without the gate header, and a minted token with the wrong audience or an expired one is rejected |
| `TestFrontend` | The web origin serves the app shell, an unknown path renders it too, the bundle references this environment's API and no legacy route name, and the CORS preflight allows the headers the shared client sends |
| `TestHygiene` | Names carry the run prefix, the cleanup hook is registered, and created resources are tracked |

Two of those deserve their reasons stated, because both have shipped as green before.

The access log is the only place that says which `routeKey` matched, so a 200 alone never
proves the cut landed. Delivery is per stream and lags, so the lookup waits inside a budget
and reports a miss as a miss rather than as a routing failure.

Both limiter layers key on source IP alone, so every call from one runner shares one bucket.
The client paces itself under that budget and retries a 429 up to a cap; past the cap it
raises rather than banking the 429 as a pass, because a 429 is evidence about the limiter and
none at all about the route.

## Configuration

Every variable is read once, at the start of the session. A missing one fails immediately and
names every variable that is unset, rather than failing each test with a connection error.

| Variable | Meaning |
| --- | --- |
| `E2E_ENVIRONMENT` | `staging` or `production`. Production has no gate and mints nothing |
| `E2E_API_BASE_URL` | The API origin under test |
| `E2E_WEB_BASE_URL` | The deployed web origin, for the shell and bundle checks |
| `E2E_AWS_REGION` | The region holding the API, the log group and the KMS key |
| `E2E_API_ID` | The HTTP API id, for `apigatewayv2 get-routes` |
| `E2E_ACCESS_LOG_GROUP` | The access log group the route assertions correlate against |
| `E2E_USER_EMAIL` | The durable e2e user, which signs in through the real login route |
| `E2E_USER_PASSWORD` | That user's password. Never printed, and kept out of the dataclass repr |
| `E2E_RUN_ID` | This run's id, which becomes the `e2e-<run id>-` resource prefix |
| `E2E_GATE_SSM_PARAMETER` | The SSM SecureString holding the staging gate value. Required outside production |
| `E2E_MINT_ENABLED` | Set to enable the `minted_token` fixture. Unset elsewhere, and `mint_test_token` refuses production independently |
| `E2E_KMS_KEY_ID`, `E2E_ISSUER`, `E2E_AUDIENCE` | Required only when minting is enabled |
| `E2E_LEGACY_ROUTE_NAMES` | Comma separated paths that must no longer appear in the deployed bundle |

Staging sits behind an access gate: a CloudFront viewer function plus a REQUEST authorizer
admitting only requests carrying `x-origin-verify`. The `gate_headers` fixture reads that
value from SSM with decryption and puts it in a header, and nothing prints it. A staging run
with the parameter unset fails there rather than answering 401 to every probe, because the
gate's 401 reads exactly like a broken route.

## Fixtures

| Fixture | Gives |
| --- | --- |
| `e2e_env` | The parsed `E2EEnvironment`, including `resource_prefix` and `is_production` |
| `gate_headers` | The `x-origin-verify` header, or an empty mapping in production |
| `anon` | A paced client carrying the gate header and no identity |
| `user_session` | The durable user signed in through the real login route |
| `api` | The authenticated client, sharing the anonymous client's pacer |
| `minted_token` | Mints a token through KMS with no login. Skips unless `E2E_MINT_ENABLED` is set |
| `gateway_routes`, `route_keys` | The live routes, read once per run |
| `openapi_document`, `openapi_operations` | The product's document and its operations |
| `access_log` | Find an access log entry by request id, with a bounded wait |
| `http` | A plain client for the web origin, carrying no API gate header |
| `cors_request_headers` | The header names the shared TypeScript client sends |
| `created_resources` | A list this run appends to, handed to the cleanup hook at the end |

## Enabling it in a product

Two files under `e2e/`. The conftest:

```python
# e2e/conftest.py
import pytest

from app.main import build_app

pytest_plugins = ["webbpulse.e2e"]


def e2e_openapi_document():
    """The deployed commit's OpenAPI document, read at collection time."""
    return build_app().openapi()


@pytest.fixture(scope="session")
def openapi_document():
    """The same document, for the fixtures that take it."""
    return e2e_openapi_document()


@pytest.fixture(scope="session")
def cors_request_headers():
    """The header names @webbpulse/api-client sends."""
    return ("authorization", "content-type", "x-request-id")


def pytest_e2e_cleanup(env, phase, created):
    """Sweep stale e2e resources at the start and this run's at the end."""
    if phase == "start":
        return sweep_older_than_an_hour(prefix=env.resource_prefix.rsplit("-", 2)[0] + "-")
    return delete_all(created)
```

`e2e_openapi_document` is a module-level function as well as a fixture because collection
happens before any fixture runs, and the operation parametrisation needs the document then.

The suite itself is one line:

```python
# e2e/test_shared.py
from webbpulse.e2e.suite import *  # noqa: F401,F403
```

Product-specific tests go in sibling files and use the same fixtures.

The cleanup hook is called twice. At `start` it is handed an empty `created` list and should
delete anything carrying the `e2e-` prefix that is older than an hour, which is what a
previous run that died mid-way leaves behind. At `end` it is handed everything this run
appended to `created_resources`. Return a falsy value when the sweep was clean or a short
description of what could not be deleted; a description is surfaced as a warning and never
fails the suite, because a leftover must not cost the result of the tests that already ran.

## Running it locally against staging

Read the gate value from SSM straight into the environment, so it is never printed and never
written to a file:

```bash
E2E_ENVIRONMENT=staging \
E2E_API_BASE_URL=https://api.staging.example.com \
E2E_WEB_BASE_URL=https://www.staging.example.com \
E2E_AWS_REGION=us-west-2 \
E2E_API_ID=abc123 \
E2E_ACCESS_LOG_GROUP=/aws/apigateway/example-staging-api \
E2E_USER_EMAIL=e2e@example.com \
E2E_USER_PASSWORD="$(op read 'op://private/e2e-staging/password')" \
E2E_RUN_ID="local-$(date +%s)" \
E2E_GATE_SSM_PARAMETER=/example/staging/origin-verify \
uv run pytest e2e -v
```

`E2E_GATE_SSM_PARAMETER` names the parameter rather than carrying the value: the plugin reads
it with `WithDecryption=True` through the session's own credentials, so the value never
reaches the shell's history, its environment or the terminal.

Run it serially. `-n auto` would put several workers on one IP and against one bucket, so the
limiter would answer the run rather than the routes.
