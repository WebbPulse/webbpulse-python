# End to end tests: the `webbpulse.e2e` plugin

The post-deploy suite every product runs against a real stage. The plugin supplies the
fixtures and the generic tests; the product supplies its OpenAPI document and its cleanup.
Back to the [README](../README.md).

Install it with the `e2e` extra, which adds `httpx`, `boto3` and `pytest`. The reusable
`e2e.yml` workflow installs the `e2e` dependency group alone, so declare it as its own group:

```toml
[dependency-groups]
e2e = ["webbpulse[e2e]"]
```

## What it checks

The generic suite runs in seven groups, each parametrised so one route, one operation or one
journey is one junit case:

| Group | Asks |
| --- | --- |
| `TestRouteCut` | Every live route key is expressible, has an integration, and the access log confirms which key served the probe |
| `TestCoverage` | Every OpenAPI operation resolves to a live route, carries no trailing slash, and lands on a route whose identity authorizer matches its security requirement. The staging access gate does not count as identity, and where it is the only authorizer the check is skipped |
| `TestReachability` | Every operation is answered by the API rather than by the gate, the limiter or a catch-all. A mutation with no path parameter is probed anonymously only, so the run never signs its own user out |
| `TestIdentity` | Login returns an RS256 token carrying this environment's issuer and audience, refresh and logout work, the JWKS is reachable without the gate header, and a minted token with the wrong audience or an expired one is rejected |
| `TestFrontend` | The web origin serves the app shell, an unknown path renders it too, the bundle references this environment's API and no legacy route name, and the CORS preflight allows the headers the shared client sends. It goes through the staging gate on signed cookies, not the origin header |
| `TestBrowser` | A real browser signs in and out through the UI, every protected route bounces an anonymous visitor, every guest-only route bounces a signed-in one, every declared route paints with no console error and no failed API call, and every declared journey runs. An anonymous visit's own 401 or 403 is exempt in both collectors, because the browser reports one such response twice |
| `TestHygiene` | Names carry the run prefix, the cleanup hook is registered, and created resources are tracked |

Two of those deserve their reasons stated, because both have shipped as green before.

The access log is the only place that says which `routeKey` matched, so a 200 alone never
proves the cut landed. Delivery is per stream and lags, so the lookup waits inside a budget
and reports a miss as a miss rather than as a routing failure.

An anonymous visit to a public route is meant to provoke a 401: the shared
`@webbpulse/api-client` calls `POST /api/auth/refresh` on load, and with no session that is
the correct answer. The browser reports that one response twice, once to the response
listener and once as a resource-load `console.error`, so both collectors exempt it under the
same flag, the same status set and the same anonymous versus signed-in rule. The exemption
is narrow: the message must read as a resource-load report naming 401 or 403 for a URL under
this product's API base. A 404, a 500, a call to another origin and every uncaught page error
still fail the route.

The minted-token probe picks its own request out of the deployed configuration. It prefers a
route carrying a non-gate authorizer; where the access gate is the only authorizer it falls
back to a declared operation that requires auth and maps to a live route, and it sends that
operation's own method, because a route key of `ANY /api/admin/db-ops` may be served by a
router that defines only POST and a GET would be answered 404 before any auth dependency
runs. Candidates are ordered safest first: a safe method, then a mutation pointed at an
absent id. A mutation with no path parameter is never one, because the accepted-token probe
carries an admin token and would run it for real, and neither is the logout path.

Both limiter layers key on source IP alone, so every call from one runner shares one bucket.
Against staging nothing paces: the services there run with rate limiting off by the
`rate_limits_apply` convention, and the client's budget is zero for the same reason, so the
full suite runs as fast as the API answers. Against any other environment the client paces
itself under the budget and retries a 429 up to a cap; past the cap it raises rather than
banking the 429 as a pass, because a 429 is evidence about the limiter and none at all about
the route.

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
| `E2E_USER_EMAIL` | The durable e2e user, which signs in through the real login route. Not required when `E2E_READ_ONLY` is set |
| `E2E_USER_PASSWORD` | That user's password. Never printed, and kept out of the dataclass repr. Not required when `E2E_READ_ONLY` is set |
| `E2E_READ_ONLY` | Set to run the anonymous read-only smoke, which is what production runs. See below |
| `E2E_RUN_ID` | This run's id, which becomes the `e2e-<run id>-` resource prefix |
| `E2E_GATE_SSM_PARAMETER` | The SSM SecureString holding the staging gate value. Required outside production |
| `E2E_MINT_ENABLED` | Set to enable the `minted_token` fixture. Unset elsewhere, and `mint_test_token` refuses production independently |
| `E2E_KMS_KEY_ID`, `E2E_ISSUER`, `E2E_AUDIENCE` | Required only when minting is enabled |
| `E2E_LEGACY_ROUTE_NAMES` | Comma separated paths that must no longer appear in the deployed bundle |
| `E2E_GATE_SIGNING_KEY_SSM_PARAMETER` | The SSM SecureString holding the gate's CloudFront signing key. Set all three gate variables or none |
| `E2E_GATE_KEY_PAIR_ID` | The CloudFront public key id the gate trusts |
| `E2E_GATE_COOKIE_DOMAIN` | The domain the signed cookies are scoped to, such as `staging.example.com` |
| `E2E_BROWSER` | `chromium`, `firefox` or `webkit`. Defaults to `chromium` |
| `E2E_HEADLESS` | Set to `0` or `false` to watch the run. Defaults to headless |
| `E2E_BROWSER_ARTIFACTS_DIR` | Where a failure writes its trace and screenshot. Defaults to `e2e-browser-artifacts` |
| `E2E_BROWSER_TIMEOUT_MS` | Per-action timeout. Defaults to 15000 |

Staging sits behind an access gate: a CloudFront viewer function plus a REQUEST authorizer
admitting only requests carrying `x-origin-verify`. The `gate_headers` fixture reads that
value from SSM with decryption and puts it in a header, and nothing prints it. A staging run
with the parameter unset fails there rather than answering 401 to every probe, because the
gate's 401 reads exactly like a broken route.

The gate authorizer is not identity. It admits any caller presenting `x-origin-verify` or the
signed gate cookies without asking who they are, and the `http-api` module attaches it to
every route it creates, deliberately public ones included. The plugin recognises it from the
API's own configuration, by REQUEST type plus the `<prefix>-access-gate-origin-verify` name
`modules/staging-access-gate` always gives it, so no extra variable names it. Only a non-gate
authorizer counts as identity authorization, and the minted-token probes pick a route that
actually requires one.

On a staging API configured with `identity_jwt` null, the gate's own Lambda verifies the
identity token and holds each route's only authorizer slot, so no route carries a separate
identity authorizer. The deployed route table then cannot say which operations need a token,
and `TestCoverage` skips that check with that reason rather than failing every public
operation.

The web origin has its own gate, and it does not read a header. A CloudFront viewer-request
function admits a request only when it carries valid CloudFront signed cookies, so the plugin
signs its own: it reads the RSA key from `E2E_GATE_SIGNING_KEY_SSM_PARAMETER` with decryption
and produces the same custom policy the login Lambda produces, byte for byte, since the
function regex-matches the decoded policy. The cookies last an hour, are attached to both the
`http` client and every browser context, and are never printed: the policy and signature are
kept out of the dataclass repr, so a pytest failure report cannot leak a live session.

## Read-only mode

The full suite runs against staging. After a production deploy only an anonymous read-only
smoke runs, because production has no durable e2e user. `e2e.yml` v3.5.0 exports
`E2E_READ_ONLY=true` for production and leaves `E2E_USER_EMAIL` and `E2E_USER_PASSWORD`
empty, and the plugin does not require those two when the flag is set. Every other variable
is still required, so a workflow wired wrong is still refused at collection. The flag is
independent of `E2E_ENVIRONMENT`, so the mode can be exercised against staging.

`E2EEnvironment` exposes `read_only`, and a `signs_in` property the fixtures ask rather than
the raw flag.

The mode is enforced in one place. A case that signs in, writes or mutates carries the
`e2e_writes` marker, and a single collection hook skips every marked case with one shared
reason when the flag is set. Mark your own mutating cases with it:

```python
import pytest


@pytest.mark.e2e_writes
def test_creating_a_build_writes_a_row(api):
    """Runs against staging, skipped after a production deploy."""
```

That is the whole contract. A product cannot ship a mutating case that runs in production by
forgetting a per-test conditional, because there is no per-test conditional to forget. As a
backstop, the `user_session` fixture skips rather than attempting a login with no credential,
so even an unmarked case that asks for a session can only skip.

The browser cases are skipped per parameter rather than per test, because the render case
covers a protected route and every public one in the same test. A read-only run keeps the
public route parameters and skips the protected ones, and skips a journey that declares
`signed_in=True` or `mutates=True` while keeping the rest.

`pytest_e2e_cleanup` is not invoked at all, in either phase. The run creates nothing of its
own, and the start phase deletes stale resources, which is what a read-only run must not do.

What still runs anonymously:

| Still runs | Skipped |
| --- | --- |
| The route cut, every live route probed and correlated in the access log | Every case that signs in as the durable e2e user |
| Gateway coverage, every operation resolving to a live route | The authenticated reachability probe |
| Anonymous reachability, including a protected operation answering 401 or 403 | Sign in and out through the UI, and the guest-only redirect check |
| Frontend hygiene: the shell, the catch-all, the bundle and the preflight | Login, refresh and logout, and the token shape assertions |
| Protected routes redirecting an anonymous visitor | Every declared protected route's render case |
| Every declared public route rendering clean | Every journey with `signed_in=True` or `mutates=True` |
| Journeys declaring neither `signed_in` nor `mutates` | The cleanup hook, in both phases |

Minting is unchanged and stays governed by `E2E_MINT_ENABLED` alone. Production does not set
it, and `mint_test_token` refuses production independently of the flag.

## Fixtures

| Fixture | Gives |
| --- | --- |
| `e2e_env` | The parsed `E2EEnvironment`, including `resource_prefix`, `is_production` and `rate_limited` |
| `gate_headers` | The `x-origin-verify` header, or an empty mapping in production |
| `anon` | A client carrying the gate header and no identity, paced everywhere but staging |
| `user_session` | The durable user signed in through the real login route. Skips in read-only mode |
| `api` | The authenticated client, sharing the anonymous client's pacer |
| `minted_token` | Mints a token through KMS with no login. Skips unless `E2E_MINT_ENABLED` is set, in read-only mode too |
| `gateway_routes`, `route_keys` | The live routes, read once per run |
| `gateway_authorizers`, `gate_authorizers` | The API's authorizers, and the ids of the access gate ones among them |
| `openapi_document`, `openapi_operations` | The product's document and its operations |
| `access_log` | Find an access log entry by request id, with a bounded wait |
| `http` | A plain client for the web origin, carrying no API gate header |
| `cors_request_headers` | The header names the shared TypeScript client sends |
| `created_resources` | A list this run appends to, handed to the cleanup hook at the end |
| `gate_cookies` | The signed CloudFront cookies for the staging web origin, or None when no gate is configured |
| `playwright`, `browser` | Session scoped. Skipped with a reason when the browser binary is absent |
| `context`, `page` | Per test. The context carries the gate cookies and the web base URL, and traces |
| `console_errors`, `failed_requests` | What the page logged and which API calls failed, for the render assertions. Both exempt the 401 and 403 an anonymous visit provokes, on the same rule |
| `login_form` | The product's `LoginForm`, from `pytest_e2e_login_form` |
| `signed_in_page` | A page already signed in as the durable e2e user |

## Enabling it in a product

Two files under `e2e/`. The conftest:

```python
# e2e/conftest.py
import pytest

from webbpulse.e2e import E2E_PREFIX

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
        return sweep_older_than_an_hour(prefix=E2E_PREFIX)
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

## The browser suite

`TestBrowser` drives a real browser against the deployed web origin. A product opts in by
implementing three hooks, all optional; implement none and the whole group skips with a reason
naming the hook it would have needed.

```python
# e2e/conftest.py, alongside the cleanup hook above
from webbpulse.e2e import (
    Click,
    ExpectText,
    ExpectUrl,
    ExpectVisible,
    Fill,
    Goto,
    Journey,
    LoginForm,
    Record,
    RouteSpec,
)


def pytest_e2e_login_form(env):
    """Where the login form lives and which elements prove the state changed."""
    return LoginForm(path="/login", signed_in_marker="[data-testid=account-menu]")


def pytest_e2e_routes(env):
    """Every route the app serves, and who is allowed to see it."""
    return [
        RouteSpec(path="/", access="public"),
        RouteSpec(path="/login", access="guest-only"),
        RouteSpec(path="/garage", access="protected"),
        RouteSpec(path="/garage/new", access="protected"),
    ]


def pytest_e2e_journeys(env):
    """Short flows through the real UI."""
    return [
        Journey(
            name="browse the garage",
            steps=[Goto("/garage"), ExpectVisible("[data-testid=garage-list]")],
        ),
        Journey(
            name="create a build",
            steps=[
                Goto("/garage/new"),
                Fill("[data-testid=build-name]", "e2e-{run_id}-build"),
                Click("[data-testid=build-save]"),
                ExpectUrl("/garage/"),
                ExpectText("[data-testid=build-title]", "e2e-{run_id}-build"),
                Record("e2e-{run_id}-build"),
            ],
            mutates=True,
        ),
    ]
```

The locator defaults follow one convention: `data-testid` attributes named `login-email`,
`login-password`, `login-submit` and `sign-out`. A product that adds those four needs to
declare only the path and the signed-in marker.

`{run_id}` is the only placeholder, and it expands to this run's id, so every name a journey
creates carries the `e2e-` prefix the start-of-session sweep looks for.

Browser journeys may mutate in both environments, which is why `mutates=True` requires at
least one `Record` step. The refusal happens at construction, so a journey that would leak
fails collection rather than the stage. Whatever a `Record` carries reaches
`created_resources`, and the product's own `pytest_e2e_cleanup` deletes it.

A failing browser case writes a Playwright trace and a screenshot into
`E2E_BROWSER_ARTIFACTS_DIR`, named after the test. A passing one writes nothing.

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
