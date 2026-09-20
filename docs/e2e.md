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

The generic suite runs in nine groups, each parametrised so one route, one operation or one
journey is one junit case:

| Group | Asks |
| --- | --- |
| `TestRouteCut` | Every live route key is expressible, has an integration, and the response header or the access log confirms which key served the probe |
| `TestCoverage` | Every OpenAPI operation resolves to a live route, carries no trailing slash, and lands on a route whose identity authorizer matches its security requirement. The staging access gate does not count as identity, and where it is the only authorizer the check is skipped |
| `TestReachability` | Every operation is answered by the API rather than by the gate, the limiter or a catch-all. A mutation with no path parameter is probed anonymously only, so the run never signs its own user out |
| `TestIdentity` | Login returns an RS256 token carrying this environment's issuer and audience, refresh and logout work, the JWKS is reachable without the gate header, a minted token for the durable user's own subject reaches the function, and one with the wrong audience or an expired one is refused before it does |
| `TestFrontend` | The web origin serves the app shell, an unknown path renders it too, the bundle references this environment's API and no legacy route name, and the CORS preflight allows the headers the shared client sends. It goes through the staging gate on signed cookies, not the origin header |
| `TestBrowser` | A real browser signs in and out through the UI, every protected route bounces an anonymous visitor, every guest-only route bounces a signed-in one, every declared route paints with no console error and no failed API call, and every declared journey runs. An anonymous visit's own 401 or 403 is exempt in both collectors, because the browser reports one such response twice, and the auth client's cold-load session probe is exempt whoever is visiting |
| `TestHygiene` | Names carry the run prefix, the cleanup hook is registered, and created resources are tracked |
| `TestAccessLogHealth` | The gateway's own log of this run carries no 5xx, no request that matched no route key, and no `integrationErrorMessage`. Guarded so an empty sweep fails rather than passing vacuously. Skipped where no access log group is configured. Run-wide: it runs last in a serial run and is reported by the controller under xdist, see [Running it in parallel](#running-it-in-parallel) |
| `TestRouteCoverage` | Every operation the deployment serves was exercised by this run, or is named in `pytest_e2e_uncovered_routes` with the reason it is not. An allowlist entry for a route that is no longer served fails as stale. Run-wide: it runs last in a serial run and is reported by the controller under xdist, see [Running it in parallel](#running-it-in-parallel) |

Two of those deserve their reasons stated, because both have shipped as green before.

A 200 alone never proves the cut landed, because it does not say which `routeKey` matched.
Two things do. The shared HTTP layer echoes the gateway's own `routeKey` on every response
as `X-WebbPulse-Route-Key`, in every environment, read from the request context the Lambda
Web Adapter forwards, so a probe that reached the function proves the cut the moment it
answers. Where that header is absent the gateway answered before the function ran, which is
what an identity rejection, a gate rejection and the gateway's own 404 look like, and the
access log entry is then the only thing that names the key.

The group probes every live route up front through the `route_probes` fixture and only then
asks for the entries, and `AccessLogLookup` reads the whole delivery window in one
unfiltered scan rather than filtering for one request id at a time. Delivery is per stream
and lags roughly half a minute, so a group that has to fall back pays that lag once rather
than once per route; a rescan is throttled to one per poll interval across every caller, so
a run of misses costs one CloudWatch read between them. The per-request-id filtered read
stays available as `read_one`, for a single lookup outside the window. A miss inside the
budget is still reported as a miss rather than as a routing failure.

An anonymous visit to a public route is meant to provoke a 401, and the browser reports that
one response twice, once to the response listener and once as a resource-load
`console.error`. Both collectors exempt it under the same flag, the same status set and the
same anonymous versus signed-in rule. The exemption is narrow: the message must read as a
resource-load report naming 401 or 403 for a URL under this product's API base. A 404, a 500,
a call to another origin and every uncaught page error still fail the route.

One request is exempt on its own terms, whatever that flag says. The shared `@webbpulse/auth`
client sends `POST /api/auth/refresh` on every cold load to find out whether a refresh cookie
already exists, and before any sign in the API correctly answers 401 `NO_SESSION`. A
signed-in case makes that same call before it signs in, so holding it against the guard flag
failed the sign-in journey and every product journey that starts cold. Only that path with
that status is exempt: a 500 from it, a 401 from any other path, and the same path on another
origin all still fail.

A report-only Content Security Policy violation is exempt on its own terms too, in the
console collector alone. A third-party frame reports its own policy against its own origin,
as the AdSense iframe does with `frame-ancestors` against `www.google.com`, and the browser
says in the same breath that it took no further action. The app under test can neither cause
that nor fix it. The match is on the phrase `report-only Content Security Policy`, case
insensitively, so an enforced violation, which names no report-only directive and did block
something, still fails the route.

The minted-token probe picks its own request out of the deployed configuration. It prefers a
route carrying a non-gate authorizer; where the access gate is the only authorizer it falls
back to a declared operation that requires auth and maps to a live route, and it sends that
operation's own method, because a route key of `ANY /api/admin/db-ops` may be served by a
router that defines only POST and a GET would be answered 404 before any auth dependency
runs. Candidates are ordered safest first: a safe method, then a mutation pointed at an
absent id. A mutation with no path parameter is never one, because the accepted-token probe
carries an admin token and would run it for real, and neither is the logout path.

Both limiter layers key on source IP alone, so every call from one runner shares one bucket.
Against staging and against a local stack nothing paces: the services there run with rate
limiting off by the `rate_limits_apply` convention, and the client's budget is zero for the
same reason, so the full suite runs as fast as the API answers. Against any other environment the client paces
itself under the budget and retries a 429 up to a cap; past the cap it raises rather than
banking the 429 as a pass, because a 429 is evidence about the limiter and none at all about
the route.

## Configuration

Every variable is read once, at the start of the session. A missing one fails immediately and
names every variable that is unset, rather than failing each test with a connection error.

A shell with nothing set at all is treated differently from a half-configured one. With
`E2E_ENVIRONMENT` unset the suite is collected and every case skips, because that is a
product running its whole test tree rather than an e2e run wired wrong, and a collection
error there would break `pytest` and `--collect-only` across the repository. Set anything but
not everything and the run still fails naming the missing variables, because skipping past a
wiring mistake is how a suite goes quietly green against nothing.

| Variable | Meaning |
| --- | --- |
| `E2E_ENVIRONMENT` | `staging`, `production` or `local`. Production has no gate and mints nothing; `local` is a stack built from source and makes no AWS call. See below |
| `E2E_API_BASE_URL` | The API origin under test |
| `E2E_WEB_BASE_URL` | The deployed web origin, for the shell and bundle checks |
| `E2E_AWS_REGION` | The region holding the API, the log group and the KMS key |
| `E2E_API_ID` | The HTTP API id, for `apigatewayv2 get-routes`. Not required when the environment is `local` |
| `E2E_ACCESS_LOG_GROUP` | The access log group the route assertions correlate against. Not required when the environment is `local` |
| `E2E_USER_EMAIL` | The durable e2e user, which signs in through the real login route. Not required when `E2E_READ_ONLY` is set |
| `E2E_USER_PASSWORD` | That user's password. Never printed, and kept out of the dataclass repr. Not required when `E2E_READ_ONLY` is set |
| `E2E_READ_ONLY` | Set to run the anonymous read-only smoke, which is what production runs. See below |
| `E2E_RUN_ID` | This run's id, which becomes the `e2e-<run id>-` resource prefix |
| `E2E_GATE_SSM_PARAMETER` | The SSM SecureString holding the staging gate value. Required outside production and `local` |
| `E2E_MINT_ENABLED` | Set to enable the `minted_token` fixture. Unset elsewhere, ignored under `local`, which has no KMS key, and `mint_test_token` refuses production independently |
| `E2E_KMS_KEY_ID`, `E2E_ISSUER`, `E2E_AUDIENCE` | Required only when minting is enabled |
| `E2E_RATE_LIMIT_PER_MINUTE` | The pacing fallback for answers carrying no `X-RateLimit-Remaining-Minute` header. Defaults to 10, and is ignored where the target does not rate limit |
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

## The session keeps its own token current

The identity access token's TTL is ten minutes by default, and a full suite runs well past
that on one worker. A session that carried the login token for the whole run had every call
after the tenth minute answered `{"message": "Forbidden"}` by the gateway authorizer, or 401
by the app, including the fixtures that create the resources a case then asserts on, and
those failures read exactly like product bugs.

So the session, not the client, owns the access token. `user_session.client` asks the session
for a credential on every request, and the session refreshes through `POST /api/auth/refresh`
when the current token is within `refresh_skew` seconds of the `exp` it declares, which
defaults to 60. A token carrying no readable `exp` falls back to `access_token_ttl` measured
from when it was issued. Refresh is lazy, so a short run makes no extra calls at all.

A refusal the expiry check did not predict is also recovered from: a 401, or a 403 whose body
is the gateway's bare `{"message": "Forbidden"}` with no `error_code`, refreshes once and
retries the request once, and the second answer is surfaced as it is. The product's own 403
carries an `error_code` in the shared error envelope and is never retried, because it means
the caller is authenticated and not permitted, and a retry would double every permission
assertion in the suite. The retry re-sends the same in-memory body the call was given, which
is safe for every caller here; a streamed body would already be consumed.

The refresh endpoint rotates the refresh token on every call, so whatever it returns in the
body and whatever cookies it sets replace what the session held, the same way `login` stores
them. Presenting a spent token would be read as a replay and revoke the whole family. A
refresh that is itself refused raises `RefreshFailed` naming the session's user rather than a
generic HTTP failure, because at that point there is no credential left and every later case
would fail for the same reason.

The refresh is guarded by a lock, so several concurrent callers refresh once between them and
none loses the rotated refresh token to another. This applies to the ephemeral user and the
durable user alike, since both arrive through `login`. A client from `with_token` carries no
token source: asking for one specific token means that token, which is what the minted-token
cases assert on.

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
| The route cut, every live route probed and correlated | Every case that signs in as the durable e2e user |
| Gateway coverage, every operation resolving to a live route | The authenticated reachability probe |
| Anonymous reachability, including a protected operation answering 401 or 403 | Sign in and out through the UI, and the guest-only redirect check |
| Frontend hygiene: the shell, the catch-all, the bundle and the preflight | Login, refresh and logout, the token shape assertions, and the minted-token cases |
| Protected routes redirecting an anonymous visitor | Every declared protected route's render case |
| Every declared public route rendering clean | Every journey with `signed_in=True` or `mutates=True` |
| Journeys declaring neither `signed_in` nor `mutates` | The cleanup hook, in both phases |

Minting stays governed by `E2E_MINT_ENABLED`. Production does not set it, and
`mint_test_token` refuses production independently of the flag. The minted subject comes
from the `minted_subject` fixture, which reads the `sub` claim off the durable e2e user's
own access token, so read-only mode skips the mint cases as well: a made-up subject names no
real user, the API refuses the token on subject resolution, and a negative case would then
pass for a reason that has nothing to do with the `aud` or `exp` it claims to test. An
explicit `subject=` still overrides it.

The three mint cases assert on where the answer came from rather than on the status. The
function sets `X-WebbPulse-Route-Key` on every response it produces and a gateway or
authorizer denial never carries it, so that header is the proof. The accepted-token case
requires it to be present: the probe is whichever auth-requiring operation the configuration
offers first, which on a product with an admin surface is an admin route, and an app-level
401 or 403 there is still an accepted token because the authorizer verified it and the
application then made its own decision about the subject or the role. The wrong-audience and
expired cases require it to be absent alongside the 401 or 403, which is what separates a
gateway refusal from an app refusal carrying the same status.

## Running it on a local stack

`E2E_ENVIRONMENT=local` points the suite at a stack built from source on a CI runner: one
composed FastAPI app on `http://127.0.0.1:8000`, DynamoDB Local, and a vite preview server on
`http://127.0.0.1:4173`. The run makes no AWS API call at all, so no fixture on that path
constructs a boto3 client. The org reusable workflow `e2e-local.yml@v3` drives it.

The contract is the two base URLs, the region, the run id and a user the product seeds
itself:

```
E2E_ENVIRONMENT=local
E2E_API_BASE_URL=http://127.0.0.1:8000
E2E_WEB_BASE_URL=http://127.0.0.1:4173
E2E_AWS_REGION=us-west-2
E2E_RUN_ID=<run id>-<attempt>
E2E_BROWSER=chromium
E2E_HEADLESS=true
E2E_READ_ONLY=false
E2E_USER_EMAIL / E2E_USER_PASSWORD
```

`E2E_API_ID`, `E2E_ACCESS_LOG_GROUP`, `E2E_GATE_SSM_PARAMETER` and `E2E_MINT_ENABLED` are
left unset. They are not required here and setting `E2E_MINT_ENABLED` turns nothing on: a
local stack has no KMS key, so minting stays off, `admin_mint_token` is empty and the run
signs in as the durable local user from `E2E_USER_EMAIL` and `E2E_USER_PASSWORD`, which the
product seeds through its own admin seed or registration route. Read-only is still governed
by `E2E_READ_ONLY` alone, and a local stack is one source IP bucket so the pacer is off.

A local stack has no API Gateway, so nothing verifies the access token and nothing writes
the `x-amzn-request-context` header every authorized route reads through `identity_claims`
and `identity_subject`. Without a stand-in a perfectly valid token arrives carrying no
claims and every write answers 401. Products add `LocalAuthorizerMiddleware` from
`webbpulse.identity` in their composition root when `ENVIRONMENT` is local, wrapping the
composed app: `app = LocalAuthorizerMiddleware(app, identity_settings)`. It verifies the
bearer token in process against the key set the local signer derives, strips any inbound
copy of the request context header so a caller can never present claims of its own, and
publishes the verified claims in the shape the readers already expect. It refuses to be
constructed in any other environment, so there is no deployment in which it can stand in
for the gateway's own authorizer.

What each group does:

| Group | Locally |
| --- | --- |
| `TestRouteCut` | Skipped whole. It needs the deployed route table, the forwarded API Gateway request context and the CloudWatch access log, none of which exist locally |
| `TestCoverage` | Degraded. The route resolution and trailing slash cases run against a route table synthesized from the product's own OpenAPI document, so they compare the document to itself. The authorizer case is skipped |
| `TestReachability` | Runs, and is the highest value group locally: every operation is called and must answer a status its own spec declares |
| `TestIdentity` | Runs, minus the three minted-token cases, which skip because minting is off |
| `TestFrontend` | Runs. The bundle check asserts against the local API base URL and the CORS preflight runs against the local backend. There is no gate cookie to mint, so `gate_cookies` is None |
| `TestBrowser` | Runs, against the preview server |
| `TestHygiene` | Runs |
| `TestAccessLogHealth` | Skipped whole. There is no CloudWatch access log locally, and the sweep reads the gateway's own record of the run, which nothing else substitutes |
| `TestRouteCoverage` | Runs. Coverage is measured against the product's own OpenAPI document, so it is the same question locally as it is post deploy |

A green local run does not prove the route cut, the gateway's own precedence and CORS, the
authorizer, the access gate, per domain isolation or the stream consumers. Those are gateway
and deployment concerns and they stay in the post deploy run, which is the required check.

## Fixtures

| Fixture | Gives |
| --- | --- |
| `e2e_env` | The parsed `E2EEnvironment`, including `resource_prefix`, `is_production`, `is_local` and `rate_limited` |
| `gate_headers` | The `x-origin-verify` header, or an empty mapping in production and on a local stack |
| `anon` | A client carrying the gate header and no identity, paced everywhere but staging. It serves `get`, `post`, `put`, `patch`, `delete` and `options`, each through the same `request` path, so pacing, the 429 retry and the request record apply to every verb |
| `ephemeral_user` | This run's own login user, created at session start and deleted at the end, or None where the route is not offered |
| `ephemeral_user_attributes` | The attributes `ephemeral_user` creates that user with, empty by default. Override it where the product grants write scopes only to an admin or verified row |
| `credentials` | The email and password the suite signs in with: this run's ephemeral user where there is one, the durable user otherwise. The password is kept out of the repr |
| `user_session` | The run's user signed in through the real login route, refreshing its own access token before it expires and after a refusal that reads as an expired one. Skips in read-only mode |
| `api` | The authenticated client, sharing the anonymous client's pacer and asking the session for a live token on every request |
| `minted_subject` | The `sub` claim of the durable e2e user's access token, which is the subject a minted token has to name to resolve to a stored user |
| `minted_token` | Mints a token through KMS with no login, defaulting to `minted_subject` and taking an explicit `subject=` override. Skips unless `E2E_MINT_ENABLED` is set, and in read-only mode, where there is no user to mint for |
| `gateway_routes`, `route_keys` | The live routes, read once per run, or synthesized from the OpenAPI document on a local stack |
| `gateway_authorizers`, `gate_authorizers` | The API's authorizers, and the ids of the access gate ones among them |
| `openapi_document`, `openapi_operations` | The product's document and its operations |
| `access_log` | Find an access log entry by request id: the window scan first, then a bounded wait. Skips on a local stack, which has no access log |
| `route_probes` | Every live route probed once, up front, so the group waits out one delivery lag rather than one per route |
| `suite_requests` | Every request this run made, gathered from the shared record the clients all append to, so a whole-run check sees everything without any case registering itself |
| `access_log_health` | This run's own access log entries, correlated by request id from one forced window scan. Skips where `E2E_ACCESS_LOG_GROUP` is unset |
| `uncovered_routes` | The product's coverage allowlist, from `pytest_e2e_uncovered_routes`, with methods normalised to uppercase |
| `route_coverage` | What this run covered, left uncovered, allowlisted and what is stale, measured against the deployed operations |
| `http` | A plain client for the web origin, carrying no API gate header |
| `cors_request_headers` | The header names the shared TypeScript client sends |
| `created_resources` | A list this run appends to, handed to the cleanup hook at the end |
| `gate_cookies` | The signed CloudFront cookies for the staging web origin, or None when no gate is configured |
| `playwright`, `browser` | Session scoped. Skipped with a reason when the browser binary is absent |
| `context`, `page` | Per test. The context carries the gate cookies and the web base URL, and traces |
| `console_errors`, `failed_requests` | What the page logged and which API calls failed, for the render assertions. Both exempt the 401 and 403 an anonymous visit provokes, on the same rule |
| `login_form` | The product's `LoginForm`, from `pytest_e2e_login_form` |
| `signed_in_page` | A page already signed in as this run's e2e user |

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


def pytest_e2e_uncovered_routes(env):
    """The routes this product knowingly leaves unexercised, and why."""
    return {
        ("POST", "/api/attachments"): "needs a real multipart upload, covered by unit tests",
        ("GET", "/api/github/callback"): "reached only by GitHub's own redirect",
    }


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

Every wait polls rather than reading once. `ExpectText` re-reads its locator on a 250 ms tick
up to the browser timeout and reports the last text it saw, so a heading caught part way
through a lazy-chunk transition settles rather than failing. The guard cases watch the URL to
a real deadline of about five seconds, or the browser timeout if that is smaller, before
calling it settled, because a measured route guard redirect lands between 750 and 980 ms and
a single quiet tick used to report the protected path as final. Reaching the expected path
returns immediately, so a passing case costs nothing extra.

Browser journeys may mutate in both environments, which is why `mutates=True` requires at
least one `Record` step. The refusal happens at construction, so a journey that would leak
fails collection rather than the stage. Whatever a `Record` carries reaches
`created_resources`, and the product's own `pytest_e2e_cleanup` deletes it.

A failing browser case writes a Playwright trace and a screenshot into
`E2E_BROWSER_ARTIFACTS_DIR`, named after the test. A passing one writes nothing.

The trace is scrubbed before it lands there. Playwright records a `fill` step's parameters
verbatim, and every other typing path it offers records the value just as verbatim, so the
durable e2e user's password would otherwise sit in plaintext in a CI artifact. The trace is
written to a temporary file first, every occurrence of the password is replaced with
`[redacted]` in every entry of the zip, and only then is it moved into the artifacts
directory. The result stays openable by `playwright show-trace`.

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

The recommended invocation is `-n auto --dist loadgroup`, which is covered in the next
section.

## Running it in parallel

```bash
uv run pytest e2e -n auto --dist loadgroup
```

The route cut and reachability cases are independent read-only probes, one route each, and
there are hundreds of them. Everything else either signs in as the session user and mutates
it or drives one Playwright page, and those have to stay on one worker and in one order.

`--dist loadgroup` sends every test carrying the same `xdist_group` to the same worker. The
plugin marks the shared-state cases into one group during collection and leaves the probes
unmarked, so the scheduler spreads the probes and holds the rest together. Grouping is by
owning test class: `TestIdentity`, `TestBrowser` and `TestHygiene` are grouped, and
`TestRouteCut`, `TestCoverage`, `TestReachability` and `TestFrontend` are not. A product's own
case joins the group by carrying the `e2e_writes` marker, so it needs to name no group.

The marker is applied whether or not xdist is installed, since it is inert in a serial run.

Session fixtures under xdist run per worker rather than per run. That is safe for the
per-request groups by construction rather than by locking: each worker creates its own
ephemeral user keyed on its own worker id and deletes that one, and each opens its own access
log window. The window scan is unfiltered, so two workers reading overlapping windows cost one
extra CloudWatch read rather than a wrong answer. Nothing is created once per run, so there is
no lock file.

`TestAccessLogHealth` and `TestRouteCoverage` are the exception, because they measure the run
rather than one request. Per-worker session fixtures are exactly wrong for them: a worker
holds only the requests it sent, so a coverage verdict reached there would report every route
the other workers exercised as uncovered, and `--dist loadgroup` is free to schedule the
groups onto any worker.

They are therefore gathered differently in each mode, and reach the same verdicts either way:

- **Serially**, the plugin orders both groups after every other case during collection,
  health before coverage. They stay ordinary tests and the report reads as it always has.
  The ordering is what makes the whole-run claim true: without it, a product test file that
  sorts after `test_shared.py` runs after coverage was measured.
- **Under xdist**, both groups skip on the worker, naming the controller in the skip reason.
  Each worker writes the requests it recorded to a JSON file at `pytest_sessionfinish`, in a
  directory under the system temporary directory keyed on `E2E_RUN_ID` and the worker id.
  The controller, which is the one process that sees the whole run, reads every worker's file
  once they have all finished, runs the same checks over the union, prints the verdicts in the
  terminal summary under `webbpulse e2e run-wide checks`, and sets the exit status to
  tests-failed on any failure, so a controller-side finding turns the job red even though
  every individual test passed. It then removes the run directory.

Both paths call the same check functions, one per check, each returning a failure message or
None, so the two modes cannot drift apart. The access log half is skipped where
`E2E_ACCESS_LOG_GROUP` is unset, on the controller exactly as in the fixture, and coverage is
still measured.

Pacing is per worker, so a rate-limited target is hit by every worker at once against one
per-IP bucket. Against production, keep `-n` small or run serially.

## Ephemeral login users

The profile, social link and sign-in journeys all mutate whichever account they run as, so a
single durable user forced every run to serialise behind a per-branch concurrency group. When
minting is available, the plugin instead creates a fresh login user at session start and
deletes it at the end, and runs can then overlap.

The address is `e2e-<run id>-<worker id>@e2e.invalid`, on the domain RFC 2606 reserves so no
mail can reach a real inbox. The password is generated per run, lives in memory for the
session, reaches only the login call and the browser's `fill`, and is kept out of the
`Credentials` repr so no failure report can render it.

The durable user stays the fallback. Where the route is not offered, the plugin uses
`E2E_USER_EMAIL` and `E2E_USER_PASSWORD` exactly as before, and a read-only run signs in as
nobody. `credentials` is the fixture to depend on: it yields whichever user this run has.

The routes are `POST /api/auth/e2e/users` and `DELETE /api/auth/e2e/users/{user_id}`, and a
product mounts them by setting `IDENTITY_EPHEMERAL_USERS_ENABLED=true`. They are gated twice.
The flag is off by default and set only in staging, and the router additionally refuses to
mount them when the environment is a production one whatever the flag says, so a misconfigured
production deployment has no route to reach rather than a route that answers 403. The caller
must present a token carrying `admin` in its `roles` claim, which in staging means a
KMS-minted token the e2e workflow alone can produce.

Delete removes only the product's users row. The identity rows are the users-table stream
purge's to remove, so every run exercises the same deletion path production uses. A product
enabling the flag implements the `delete_user` hook.

### Gotchas

- **A record model must not annotate the address `EmailStr`.** The ephemeral address is on
  `e2e.invalid`, and `email-validator`, which Pydantic's `EmailStr` uses, refuses the
  special-use domains RFC 2606 reserves. Neither `test_environment=True` (which re-admits
  `.test` alone) nor `globally_deliverable=False` (which does not touch the special-use
  check) makes `.invalid` pass, so there is no setting that rescues it. A product whose
  persisted user record model uses `EmailStr` answers 500 on `POST /api/auth/e2e/users` and
  every ephemeral fixture then errors in a way that reads like a product bug. Keep `EmailStr`
  on request schemas, where rejecting an undeliverable address is the point, and let record
  models hold a plain `local@domain` string:

  ```python
  class UserCreateRequest(BaseModel):
      """What a caller may ask for. `EmailStr` belongs here."""

      email: EmailStr

  class UserRecord(BaseModel):
      """What is persisted. A plain shape, so the reserved e2e domain round trips."""

      email: str = Field(pattern=r"^[^@\s]+@[^@\s]+$")
  ```

  The ephemeral domain is deliberate and is not the thing to change: `.invalid` can never be
  delivered to, which is what keeps a product's new-account mail away from a real inbox. When
  creation does fail, `create_ephemeral_user` raises with the status, a bounded excerpt of the
  response body and, where the reserved domain is the likely cause, this hint in one line.

### Attributes on the created user

The user is created with the attributes `ephemeral_user_attributes` yields, which is an empty
mapping by default. A product that grants write scopes only to an admin or a verified row
overrides that one fixture rather than the whole of `ephemeral_user`:

```python
@pytest.fixture(scope="session")
def ephemeral_user_attributes() -> dict[str, object]:
    """This product grants write scopes only to an admin, verified row."""
    return {"is_admin": True, "email_verified": True}
```

The mapping reaches `create_ephemeral_user` as `attributes=` and nothing else reads it, so it
may carry whatever the product's own create route accepts. A user created with no attributes
holds read scopes alone wherever that is how the product authorises, and every write case
would be refused, which is the reason this exists. Overriding the whole fixture to pass one
argument meant reimplementing the create, the worker-id suffix and the delete-failure warning
alongside it.
