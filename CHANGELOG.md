# Changelog

Notable changes to the `webbpulse` package. The version here is the one in
`src/webbpulse/_version.py`, and a release is that edit plus the matching `v<version>` tag.

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.31.0

Adds an anonymous read-only mode to `webbpulse.e2e`, for the run that follows a production
deploy. The full suite runs against staging; production has no durable e2e user, so only an
anonymous smoke runs there. `e2e.yml` v3.5.0 exports `E2E_READ_ONLY=true` for production and
leaves `E2E_USER_EMAIL` and `E2E_USER_PASSWORD` empty.

`E2EEnvironment` gains `read_only`, read from `E2E_READ_ONLY`, and a `signs_in` property the
fixtures ask instead of the raw flag. When the flag is set the two user variables are no
longer required at collection; every other variable still is, so a workflow wired wrong is
still refused up front. The flag is independent of the stage name, so the mode is testable
against staging.

The mode is enforced in one place rather than per test. A new `e2e_writes` marker names a
case that signs in, writes or mutates, and a `pytest_collection_modifyitems` hook skips every
marked case with one shared reason when the flag is set. A product that marks a new mutating
test of its own gets the production skip for free and cannot ship one that runs there by
forgetting a conditional. The `user_session` fixture skips rather than attempting a login
with no credential, which is the backstop for a case that forgot the marker: it can only
skip, never sign in.

The browser cases are skipped per parameter, not per test, because the render case covers
both a protected route and every public one. A read-only run keeps the public route
parameters and skips the protected ones, and skips a journey declaring `signed_in=True` or
`mutates=True` while keeping the rest.

`pytest_e2e_cleanup` is not invoked at all in read-only mode, in either phase. The run
creates nothing of its own, and the start phase deletes stale resources, which is exactly
what a read-only run must not do.

What still runs anonymously: the route cut, gateway coverage, anonymous reachability
including that a protected operation answers 401 or 403 to an anonymous caller, frontend
hygiene, the protected-routes-redirect-anonymous-visitors check, every declared public route
rendering clean, and every journey declaring neither `signed_in` nor `mutates`. Minting stays
governed by `E2E_MINT_ENABLED` alone and is unchanged.

## 0.30.2

Fixes two more `webbpulse.e2e` bugs, found by running the suite against CarModPicker
staging. Neither is a product defect.

The two page collectors now agree about the same HTTP event. `FailedRequests` already
ignored the 401 or 403 an anonymous visit is meant to provoke, but `ConsoleErrors` recorded
every `console.error` unconditionally, and the shared `@webbpulse/api-client` calls
`POST /api/auth/refresh` on load, which anonymously returns 401 and which the browser logs
as a resource-load console error. Every public route failed the "renders clean" check on a
healthy app. `ConsoleErrors` now carries the same `ignore_guard_statuses` flag on the same
status set and the same anonymous versus signed-in rule, and ignores a console message only
when it reads as a resource-load report naming 401 or 403 for a URL under this product's API
base. The URL is read from the message's `location` when it carries one and from the message
text otherwise. Chromium's, Firefox's and WebKit's phrasings are all matched. Any other
console error, including a 404, a 500 and every uncaught page error, still fails the route.
New `resource_load_status` and `message_location_url` in `webbpulse.e2e.browser`.

The minted-token probe no longer picks a route with no handler for the probed method.
0.30.1 replaced `_first_authorized_route` with `_first_identity_route`, but that still
returned a bare `Route` the callers turned into a method with `_probe_method`, so the
CarModPicker shape of `ANY /api/admin/db-ops` in the route table with only
`POST /api/admin/db-ops` in the OpenAPI document was still wrong: the fallback looked for
`GET /api/admin/db-ops` among the declared operations, did not find it, and skipped. The
probe now resolves to a `ProbeTarget` carrying the matched operation's own method and path,
so the request reaches the auth dependency rather than a FastAPI 404, and an operation that
resolves to a `{proxy+}` key is probed at its own concrete path. Candidates are ordered
safest first: a GET, HEAD or OPTIONS, then a mutation with a path parameter pointed at an
absent id. A mutation with no path parameter is never a candidate, because the accepted-token
probe carries an admin token and the request would execute for real, and the logout path is
never one because probing it would end the run's own session.

## 0.30.1

Fixes four `webbpulse.e2e` bugs the first full run against the Portfolio staging deployment
turned up. All four are plugin bugs, not product defects.

An access log field the gateway had no value for is written as a literal `-`, not as an empty
string, because the access log format names every field it wants and the gateway renders an
unset `$context` variable that way. `parse_entry` read that as a value, so a healthy request
carrying `"integrationErrorMessage":"-"` looked like a failed integration and
`TestRouteCut::test_access_log_names_this_route_key` failed on a successful login. Every
string field now reads `-` as empty, through a shared `log_field` helper.

The staging access gate is no longer counted as identity authorization. It is a REQUEST
authorizer admitting any caller that presents `x-origin-verify` or the signed gate cookies,
and the `http-api` module attaches it to every route it creates, deliberately public ones
included, so `TestCoverage::test_authorizer_matches_the_operation` failed for every public
operation and the minted-token probes were handed a public route. The plugin now reads the
API's authorizers and recognises the gate from the configuration itself, by REQUEST type plus
the `<prefix>-access-gate-origin-verify` name `modules/staging-access-gate` always gives it,
so no new environment variable is needed. Only a non-gate authorizer counts as identity, and
the minted-token probes pick a route that actually requires one. Where the gate is the only
authorizer on the API, which is what `identity_jwt = null` deploys, the gate's own Lambda
verifies the identity token and no route carries a separate identity authorizer; the route
table cannot say which operations need one, so that check is skipped with that reason rather
than failing. New `gateway_authorizers` and `gate_authorizers` fixtures, and new
`Authorizer`, `fetch_authorizers`, `gate_authorizer_ids`, `route_requires_identity` and
`identity_authorization_is_observable` in `webbpulse.e2e.gateway`.

The "route renders clean" failure message now names the locator that was actually tried. A
`RouteSpec` carrying its own `root_locator` was reported against the shared `ROOT_SELECTORS`
it never looked at, so the message pointed at selectors that had nothing to do with the
failure.

`TestBrowser::test_sign_in_and_out_through_the_ui` no longer requires the path to change on
sign out. An app that renders its login form in place, as Portfolio `/admin` does, could never
pass that. Sign out is now judged by what the page shows: the signed-in marker is gone, the
login form is visible again, and a reload does not bring the marker back, which is still the
assertion that catches a session cleared in memory but left in storage.

## 0.30.0

Adds the browser layer to `webbpulse.e2e`, so the post-deploy suite exercises the deployed UI
and not only the API behind it.

`webbpulse.e2e.gate` signs the staging web gate's CloudFront cookies. `mint_gate_cookies`
reads the RSA key from SSM with decryption and builds the same custom policy the gate's login
Lambda builds, byte for byte, because the CloudFront viewer function regex-matches the decoded
policy. The `gate_cookies` fixture yields them for the session, or None when no gate is
configured, and the `http` fixture now carries them so the frontend checks reach the origin
through the gate rather than bouncing off it. The policy and the signature are kept out of the
dataclass repr, so a failure report cannot leak a live session.

`webbpulse.e2e.browser` supplies the `playwright`, `browser`, `context`, `page`,
`console_errors`, `failed_requests`, `login_form` and `signed_in_page` fixtures. The context
carries the gate cookies and the web base URL and records a trace; a failing test writes that
trace and a screenshot into `E2E_BROWSER_ARTIFACTS_DIR`, and a passing one writes nothing. A
machine with no browser binary skips the group with a reason instead of erroring.

Three optional hooks declare the product's UI contract: `pytest_e2e_login_form`,
`pytest_e2e_routes` and `pytest_e2e_journeys`, returning `LoginForm`, `RouteSpec` and
`Journey` values. `TestBrowser` parametrises them at collection, one route or one journey per
junit case: sign in and out through the UI, every protected route bounces an anonymous
visitor, every guest-only route bounces a signed-in one, every declared route paints with no
console error and no failed API call, and every declared journey runs. A journey that sets
`mutates=True` must carry a `Record` step, and the refusal happens at construction, so a
journey that would leak a resource fails collection rather than the stage.

New configuration: `E2E_GATE_SIGNING_KEY_SSM_PARAMETER`, `E2E_GATE_KEY_PAIR_ID` and
`E2E_GATE_COOKIE_DOMAIN`, which are set together or not at all, plus `E2E_BROWSER`,
`E2E_HEADLESS`, `E2E_BROWSER_ARTIFACTS_DIR` and `E2E_BROWSER_TIMEOUT_MS`.

The `e2e` extra gains `playwright` and `cryptography`.

## 0.29.0

Hoists the scaffolding the products had each written for themselves, and replaces the CI
domain matrix helper with a post-deploy end to end plugin.

`webbpulse.events` is the stream and queue consumer primitive. `register_stream_consumer`
mounts the adapter's pass-through route on a router, `stream_consumer_app` is the
entrypoint-shaped wrapper with root routes and error handlers and nothing else, and
`event_records`, `record_id` and `batch_item_failures` read and answer the
`ReportBatchItemFailures` envelope. The gateway guard is on by default and refuses with a
404. `identity.events` is rewritten on the primitive with every public name kept.

`webbpulse.messages` is the refusal copy catalogue. `STATUS_MESSAGES` is the table the
error handlers already rendered, made public, and `refusal`, `forbidden`, `unauthenticated`,
`not_found`, `conflict`, `validation_failed` and `rate_limited` build a sentence from a
safe default. The one rendered change: the rate limiter's 429 now says "Try again shortly."
rather than "Try again later.", matching the status table.

`webbpulse.ratelimit` can now express what the product limiters do. `LimitClass` and
`classify` name a cap and window per request class, `rate_limit_middleware` binds the whole
app with one counter row per class, `RateLimiter` gains `anchor` (clock aligned by default,
`first_request` for a lockout), `count_attribute` and `clear`, and a `renderer` owns the
429 body so each product keeps its own envelope. A failed-open response carries no
RateLimit headers.

`webbpulse.identity.claims` reads the staging gate shape as well as the native authorizer
shape: `GATE_CLAIMS_KEY`, `gate_claims`, `identity_claims`, `identity_subject` and
`subject_dependency`, with an absent authorizer answering `None` rather than raising.

`webbpulse.testing.FakeKms` is the one reconciled fake, taking one key or a mapping and a
`failing` set of key ids, with `fake_kms` and `rsa_key` fixtures.

`webbpulse.dynamodb` gains `scan` and `iter_scan`, `batch_get` with a capped retry of
`UnprocessedKeys` that raises `UnprocessedItems` when exhausted, and `transact_write` with
`put_action`, `delete_action`, `update_action` and `condition_check`.

`webbpulse.security` gains the one-secret-per-service wrapper: `app_secrets`,
`flatten_secret`, `load_app_secrets`, `apply_app_secrets` and `reset_secret_cache`, over a
new `config.read_json_secret`. Key names are logged, values never.

`webbpulse.e2e` is a pytest plugin and generic suite run against a deployed stage: route
cut, coverage, reachability, identity, frontend and hygiene, with the access log confirming
which route key served each probe and a paced client under the per-IP limiter. It ships as
the `e2e` extra and is driven by the organisation's reusable `e2e.yml` workflow.

Removed: `webbpulse.ci`. The reusable `python-ci.yml` v3 discovers domains itself, so the
helper had no caller left. CI and publishing run through the v3 uv workflows.

## 0.28.1

Fixes the stream route refusing the pass-through it exists for. The AWS Lambda Web Adapter
stamps `x-amzn-request-context` on every invocation, and on a pass-through the value is the
literal `null`; 0.28.0 read any non-empty header as a gateway caller and answered 404, so the
event source mapping consumed each `REMOVE` record without purging anything. The guard now
refuses only a request whose context is a JSON object, and no longer reads `x-amzn-requestid`.

## 0.28.0

Adds the asynchronous half of account deletion. `IdentityFlows.purge_user` deletes every
identity row for one user: refresh token families, credentials, passkeys, the TOTP factor,
recovery codes, OAuth links, outstanding identity tokens and WebAuthn challenges. It returns
a `PurgeResult` carrying a count per table, and logs one `identity.user_purged` event. It is
idempotent, so a user with no rows succeeds with zero counts and a retry of a partially
applied purge converges.

Refresh tokens are deleted rather than revoked. A purge is not a logout: nothing is left to
replay a token against, and a revoked row would outlive the user it belonged to.

Every store that could not already delete by user gained `delete_all_for_user`, abstract, in
memory and on DynamoDB. `Repository.delete_many` batches the deletes for the tables holding
many rows per user, and `DynamoRecoveryCodeStore.delete_for_user` now uses it instead of a
row at a time.

The `identity-tokens` and `webauthn-challenges` tables carry no user index, so their DynamoDB
stores raise `NotImplementedError` rather than scanning. `purge_user` records those in
`PurgeResult.unsupported` instead of failing, and both tables carry a TTL, so nothing is
retained permanently.

`build_identity_router` mounts a DynamoDB Streams route wherever the flows mount. Identity
Lambdas run behind the AWS Lambda Web Adapter, which posts a non-HTTP invocation as a JSON
body to its pass-through path and returns the response body as the function's result, so the
stream handler is an ordinary route rather than a second entrypoint. It handles only `REMOVE`
records, reads the user id from `dynamodb.Keys`, and answers with the `ReportBatchItemFailures`
shape so the event source mapping retries only the records that raised.

The route takes no auth and returns 404 to any request carrying an API Gateway request context
or request id, so it is reachable only through the adapter's pass-through. It sits at an
absolute path outside the issuer prefix, because that is where the adapter posts.

`IDENTITY_EVENTS_PATH` sets the path, falling back to the adapter's own
`AWS_LWA_PASS_THROUGH_PATH` and then to `/events`. `IDENTITY_USERS_KEY_ATTRIBUTE` names the
users table key attribute holding the user id, defaulting to `id`.

Adopters must enable the users table DynamoDB stream and an event source mapping to the
identity Lambda with `ReportBatchItemFailures`, or the purge never runs.

## 0.27.0

Restores an application level request log. `create_app` installs `RequestLoggingMiddleware`,
which emits one INFO line named `request` per HTTP request, carrying the method, the matched
route template, the status, the duration in milliseconds, the request id and, when one is
bound, the authenticated subject.

The API Gateway access log already records the same request at the edge. This line is the
in-process view: it sees the route template rather than the raw path, the handler's own
duration, and the subject the gateway never learns.

Nothing that can carry a secret is logged: no body, no header, no token and no query string.
The path is the matched template, so an id in a path segment does not give every request a
distinct value.

The middleware is pure ASGI rather than a `BaseHTTPMiddleware`, because `call_next` runs the
application in a child task whose context a `BaseHTTPMiddleware` cannot read back, and a user
id bound by `user_id_dependency` would never have reached the line.

Pass `request_log=False` to `create_app` where the gateway access log is the only per-request
record a service wants.

`bind_user_id` takes an optional `request`, and records the cleaned id on the request scope as
well as the context variable. `user_id_dependency` now passes it, which is what lets the log
line report a subject bound inside a route handler. Both remain backwards compatible.

OpenAPI advertises the error envelope the handlers actually render. `ErrorResponse` and
`ValidationErrorDetail` model the `"detailed"` shape, and `error_envelope_responses` builds the
`responses` mapping `create_app` passes to FastAPI, replacing the default `HTTPValidationError`
on the documented statuses.

## 0.26.0

Restores the security property that 0.25.2 could only degrade gracefully: a password change
or a password reset signs every other device out again.

### `refresh-tokens` has a user index, and the store uses it

0.25.2 stopped `change_password` answering 500, but it did so by reporting nothing revoked.
The user's other sessions kept working with the old password, which is the behaviour a
password change exists to prevent. v2.16.0 of the `identity` Terraform module adds
`user_id-family_id-index` to `refresh-tokens`, and `DynamoRefreshTokenStore.revoke_all_for_user`
now queries it rather than raising.

The query pages through every family the user holds, skips `except_family_id` so a password
change spares the session it was made from, and revokes each record with the same point write
`revoke_family` makes. The index projects `KEYS_ONLY`, which carries `token_hash`, `user_id`
and `family_id` and nothing else, so the hot rotation path pays for nothing it does not use.

Because a `KEYS_ONLY` row cannot say whether a record is already revoked, the revoking write
now carries that test as a condition. The returned count is how many records the call
changed, not how many it saw, and a concurrent revoke is no longer double counted.

### The index name comes from the environment

`DynamoRefreshTokenStore` reads `IDENTITY_REFRESH_USER_INDEX`, which the identity module sets
from v2.16.0, and falls back to `REFRESH_USER_INDEX` (`user_id-family_id-index`). Both are
exported from `webbpulse.identity`.

Passing `user_index=""` declares a table with no such index, and then `revoke_all_for_user`
raises `NotImplementedError` exactly as before. `SessionService.revoke_all_for_user` still
catches it, logs `session.revoke_all_unsupported` and returns 0, so a product whose table
predates the index keeps working unchanged.

**Upgrading:** apply the module at v2.16.0 first and let the index backfill report `ACTIVE`
before deploying this version. DynamoDB builds the index asynchronously and a query against
it returns partial results until then, which would revoke some of a user's sessions and not
others.

## 0.25.2

Fixes a 500 on `POST /api/auth/password`. Changing a password on the DynamoDB-backed
identity Lambda rehashed the password, then raised `NotImplementedError` while revoking the
user's other sessions, so a request that had already succeeded answered 500.

### A store that cannot enumerate now reports nothing revoked

`refresh-tokens` is keyed by token hash and carries no user index, because indexing the cold
path would cost a write on every rotation of the hot one, so `DynamoRefreshTokenStore.revoke_all_for_user`
raises rather than scanning. `logout_all` and `confirm_password_reset` both pass `family_ids`
and never reach it; `change_password` passed only `keep_family_id` and did.

`SessionService.revoke_all_for_user` now catches that `NotImplementedError`, logs a warning
under the event `session.revoke_all_unsupported` and returns 0. The store's contract is
unchanged: it still refuses to guess, and the docstring now says that a caller wanting anything
revoked on such a store has to pass `family_ids`. The in-memory store, which does have the
index, is untouched and still revokes everything.

### Change-password passes what it knows

`IdentityFlows.change_password` takes `family_ids` the way `logout_all` already did, and the
route forwards an optional `family_ids` array from the body alongside the `sid` it reads from
the verified claims.

**Behaviour change.** On DynamoDB, a password change no longer signs other devices out unless
the caller names their families. It succeeds and answers `{"changed": true}`; the caller's own
session is kept, as before. Sign-out-everywhere is unaffected, and a user who wants other
sessions gone should use it.

## 0.25.1

Quietens the span exporter's teardown logging, stops the tracer provider being shut down
twice, and logs the body of a rejected export so the X-Ray `403` can be diagnosed. No API
change beyond two new helpers, `shutdown_signalled` and `note_shutdown_signal`.

### The demotion window opened after the failure it explains

An export that fails because the process is going away is not a fault, so it logs at WARNING.
That judgement was made from `_tearing_down`, which is only set inside the processor's
`shutdown`. Under the Lambda Web Adapter the last request's synchronous flush runs between
uvicorn's "Shutting down" and "Waiting for application shutdown", so its `Failed to export
span batch code: 403` was emitted before anything had set the flag and kept its ERROR.

The window now opens at the first sign of shutdown. `configure_tracing` installs a `SIGTERM`
handler that chains whatever handler was already there, so uvicorn's graceful shutdown is
unchanged, and the lifespan wrapper flips the same flag when the ASGI shutdown event arrives.
`shutdown_signalled` reports the state and `note_shutdown_signal` opens it from any other
shutdown path. The OTLP exporter's own logger carries a filter for the life of the process that
demotes ERROR only once a signal has been seen, so a steady-state export failure is untouched.

### The provider was shut down twice

`configure_tracing` never passed `shutdown_on_exit=False`, so the SDK's own `atexit` hook shut
the provider down again after the lifespan had already done it, and the exporter answered
`Exporter already shutdown, ignoring call`. The flag is now passed and this package owns the
hook, registering an idempotent `atexit` so a process that never ran a lifespan still flushes.

There was a second source of the same line in `shutdown_tracing` itself: it shuts this
processor down for the bounded flush and then shuts the provider down, and the provider walks
its processor list and calls the same processor again. `TailSamplingSpanProcessor.shutdown` is
now idempotent, so only the first call reaches the exporter.

### A rejected export now says why

The OTLP HTTP exporter reports a failed batch as a status and a `reason` and discards the
response body, which is the only place the endpoint explains a `403`. The exporter's `_export`
is now wrapped so a non-2xx response logs one line carrying the status, the first 300
characters of the body, and the `x-amzn-requestid` and `x-amzn-errortype` headers when present,
at whatever level the teardown demotion decides. Only response data is read, never request
headers, so no credential or signature can reach the logs. This is a diagnostic and it stays in
the release.

## 0.25.0

`create_app` now allows the `X-Request-ID` and `X-Retry-Attempt` request headers through CORS by
default, and takes a `cors_allow_headers` override.

### A retried browser request failed its preflight

`@webbpulse/api-client` sets `x-request-id` on every request and adds `x-retry-attempt` once it
retries. The CORS allow list was hardcoded to `Accept, Authorization, Content-Type, Origin,
X-Request-ID`, so the first attempt passed its preflight and the retry was answered 400
`Disallowed CORS headers`. The browser then reported a CORS failure rather than the original
error that caused the retry, and no `create_app` argument could widen the list.

The default list is now `DEFAULT_CORS_ALLOW_HEADERS`, which adds `X-Retry-Attempt` alongside
`Accept-Language` and `Content-Language` so it covers the CORS safelisted request headers in
full. `RETRY_ATTEMPT_HEADER` is exported beside `REQUEST_ID_HEADER`. Passing
`cors_allow_headers` replaces the default outright.

Infrastructure in front of the app applies its own allow list. An API Gateway HTTP API with a
`cors_configuration` answers preflights itself on the routes it owns, so that list needs
`X-Retry-Attempt` too.

## 0.24.1

Fixes the intermittent `Failed to export span batch code: 403, reason: Forbidden` from the
X-Ray OTLP exporter. Exports are now single-flight across threads, and one SigV4 signature
always resolves its credentials once. No API change.

### Two threads signing at once produced a signature that did not match itself

`SigV4Auth.add_auth` does not read a credentials object once. It reads `token` while rewriting
headers, `secret_key` while deriving the signing key, and `access_key` while building
`Credential=` in the `Authorization` header: four separate attribute reads per signature.
`_ReresolvingCredentials` re-resolved on every one of them, and its non-refreshable branch
re-resolves by nulling `session._credentials` so the next `get_credentials` rebuilds it, which
mutates state every thread shares.

Nothing serialised the exporter either. `TailSamplingSpanProcessor._export` ran outside the
buffer lock by design, so the per-request flush, the lifespan shutdown flush and the provider
shutdown could all be inside `exporter.export` at once; a probe saw three. Two overlapping
signatures could then interleave, and a request went out with the access key id of one
resolution beside a signature derived from another's secret. X-Ray cannot verify that and
answers 403.

That explains the shape of the failure exactly: a minority of exports, never during request
handling, and clustered 20 to 160 ms after `Shutting down`, because the shutdown flush is the
one moment an in-flight request's flush reliably overlaps another export. Steady-state
single-threaded exports were always correctly signed, which is why spans kept landing.

A harness driving the real signing path measured 0.05 to 1.2 percent of signatures mixed
before the fix and none after, over 9600 signatures a run.

Two changes, because either alone leaves a hole. `_ReresolvingCredentials.pinned` scopes one
frozen snapshot to one signature, per thread and reentrant, and `_PinnedCredentialSession`
enters it around each request so every read inside agrees; re-resolution happens under a lock.
Outside a pinned scope each read still resolves afresh, so the credential refresh this class
exists for is unchanged. An `_export_lock` then makes export, the exporter's own `force_flush`
and its `shutdown` single-flight, which costs nothing in the steady state where the
per-request flush is already the only caller.

### Teardown export noise is no longer logged at ERROR

The OTLP exporter reports a failed batch through its own logger, which this package does not
route, so `Failed to export span batch due to timeout, max retries or shutdown.` and the read
timeout behind it arrived at ERROR. On the teardown path both are the expected outcome of a
flush deliberately bounded well under Lambda's grace period, not a fault, so they paged for
working as designed. `shutdown` now demotes that logger's ERROR records to WARNING for the
teardown window only, and never drops one. Every other export failure, the 403 included, keeps
its ERROR.

## Earlier releases

- **0.24.0** - `dynamodb_errors` and `dynamodb_error_handlers` accept a `DynamoDBErrorHandlerOptions` instead of only a bool, so the handler messages are actually configurable, and `install_dynamodb_error_handlers` gains `internal_error_message` for the 500 branch.
- **0.23.0** - `webbpulse.http` gains an `error_envelope` option choosing the whole error body shape, and `webbpulse.dynamodb` gains `ItemNotFound`, `ConditionFailed` and `TransactionCanceled` plus the handlers that render them.
- **0.22.0** - `instrument_fastapi` wraps the application's lifespan so buffered spans are flushed and the tracer provider shut down on container teardown, with a bounded flush timeout and quieter logging for a failed export on the way out.
- **0.21.0** - The `passkeys` extra widens to `webauthn>=2.7,<4` for py_webauthn 3.x, with `passkeys.SUPPORTED_COSE_ALGS` naming EdDSA, ES256 and RS256 explicitly so the ceremony is identical on either major.
- **0.20.0** - `POST /logout-all` names its own token families instead of relying on a user indexed scan, so it no longer answers 500 on a DynamoDB deployment; the release also carries the repository wide comment cleanup.
- **0.19.0** - Two `webbpulse.otel` workarounds for Lambda: SigV4 export credentials resolve afresh per signature rather than latching at cold start, and a frozen and thawed sandbox's non-positive export timeout no longer raises `ValueError` out of the exporter.
- **0.18.0** - `webbpulse.ci` adds domain discovery for the per-domain pytest matrix in the organisation's reusable `python-ci.yml`, driven by a `[tool.webbpulse.ci]` table with `domains` and `pytest-args` commands.
- **0.17.0** - A public anonymous `GET <prefix>/passkeys/availability` route answering `{"enabled", "passwordless"}`, so a frontend stops probing the passkey login options route to find out.
- **0.16.0** - A public anonymous `GET <prefix>/oauth/providers` discovery route with `display_name` on each provider, plus `OAuthService.start` refusing a provider that has a client id but no client secret.
- **0.15.0** - Identity M5: passkeys, with WebAuthn registration and passwordless sign-in, credential management, seven routes, single use challenge rows and two new DynamoDB tables behind a `passkeys` extra.
- **0.14.0** - Identity M6: OAuth sign-in and account linking against Google and GitHub, with five routes, the `oauth-states` and `oauth-links` tables, an `oauth` extra and a defaulted `has_other_sign_in_method` hook.
- **0.13.0** - Identity M4 security fix, breaking for two contracts: `POST /totp/disable` and `POST /recovery-codes` now require a `code` proving possession of the second factor.
- **0.12.1** - Housekeeping: `hash_password` and `needs_rehash` resolve `DEFAULT_ROUNDS` at call time rather than freezing it at import, and `uv.lock` is ignored.
- **0.12.0** - Identity M4: TOTP with KMS envelope encryption, recovery codes, the MFA ticket, step-up, and `amr` and `auth_time` on the access token, across six new routes and two new tables.
- **0.11.0** - Identity M3: email verification and password reset over SES, with the `EmailSender` interface, the single-use `LinkService`, four routes and an opt-in deployed-service contract suite.
- **0.10.0** - Identity M2: the password and session flows, register, login, change password, refresh with rotation and reuse detection, logout and logout-all, with every route moving under the issuer's path.
- **0.9.0** - Identity M1 foundations: `IdentitySettings`, the `IdentityHooks` seam, `TokenService` with key rotation, the authorizer claim reader and the storage interfaces, with the flows deliberately absent.
- **0.8.0** - Adoption ergonomics from two consuming services: `user_id_dependency` and `bind_user_id` for the sync dependency trap, `stream=` and `formatter=` on `configure_logging`, and `metrics_enabled_from_env`.
- **0.7.0** - The two observability primitives hoisted out of CarModPicker: `webbpulse.log_context` for request and correlation context on ContextVars, and `webbpulse.metrics` writing CloudWatch Embedded Metric Format to stdout.
- **0.6.0** - The M0 slice of the identity standard: `KmsSigner`, `public_jwk_from_kms` and `identity_router` serving the JWKS and discovery documents, proving an API Gateway JWT authorizer verifies a KMS signed token.
- **0.5.0** - `webbpulse.security`, the genuinely shared half of both backends' `security.py`: bcrypt hashing with `hash_password`, `verify_password` and `needs_rehash`, plus PyJWT `create_token`, `decode_token` and `bearer_claims`.
- **0.4.0** - `exception_map` and `ErrorSpec` let a service hand its own repository exception types to the package, so a repository that translates a `ClientError` before it escapes needs no handlers of its own.
- **0.3.0** - The `{success, status, message, request_id}` envelope gains opt-in `error_codes` and `validation_details`, a public `error_body`, the botocore `install_dynamodb_handlers`, and envelope rendering for Starlette's raw routing errors.
- **0.2.0** - `webbpulse.otel` switches to tail sampling with `TailSamplingSpanProcessor` so errors are always kept, adds an `aws-otel` extra with a SigV4 signed X-Ray exporter, and flushes once per request under the Lambda Web Adapter.
- **0.1.0** - First release: `config`, `logging`, `otel`, `http`, `dynamodb`, `ratelimit`, `lambda_entry` and `testing`.
