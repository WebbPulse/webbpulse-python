# Changelog

Notable changes to the `webbpulse` package. The version here is the one in
`src/webbpulse/_version.py`, and a release is that edit plus the matching `v<version>` tag.

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.24.0

`register_error_handlers(dynamodb_errors=...)` and `create_app(dynamodb_error_handlers=...)`
now accept a `DynamoDBErrorHandlerOptions` in place of `True`, and
`install_dynamodb_error_handlers` gains an `internal_error_message`. `True` and `False` behave
exactly as in 0.23.0, and the default wording is byte identical, so a consumer that passes
neither sees no change.

### The flag silently discarded the wording

0.23.0 shipped two ways to install the `webbpulse.dynamodb` handlers, and only one of them
could be configured. `install_dynamodb_error_handlers` took `not_found_message` and
`conflict_message`; the `dynamodb_errors` and `dynamodb_error_handlers` flags took a bool and
forwarded nothing. A consumer with its own wording that reached for the flag, which is the
path the README shows first, got the package defaults and a green test suite, because the
defaults are plausible sentences rather than placeholders. CarModPicker hit this adopting
0.23.0.

A bool cannot carry wording, so the flag now takes either. `DynamoDBErrorHandlerOptions` is a
frozen dataclass of the three messages, each defaulting to `None` for the package default, and
every field is forwarded. Passing `DynamoDBErrorHandlerOptions()` is the same as passing
`True`, which has a test, because an options object that pinned nothing silently reverting to
a different set of defaults would be the same class of bug one layer down.

### The 500 branch had no knob at all

`TransactionCanceled` renders a 409 when a cancellation reason is a failed condition and a 500
otherwise, and that 500 rendered the literal `"Internal server error."` with no way to change
it. Every other message in the handler was configurable, so a consumer pinning the other two
ended up with two of its own sentences and one of the package's. `internal_error_message`
closes it, and `DYNAMODB_ERROR_MESSAGES` gains an `"internal"` key holding the default, which
is unchanged including the trailing period. CarModPicker pins `"Internal server error"`
without one.

## 0.23.0

`webbpulse.http` gains an `error_envelope` option choosing the whole error body shape, and
`webbpulse.dynamodb` gains the three repository exception types plus the handlers that render
them. Both are opt in and the default body is byte identical to 0.22.0, so taking the release
changes nothing for a consumer that passes neither.

### Why a shape, not more keys

`error_codes` and `validation_details` compose a body one key at a time. That suited the
service adding a field, and not the service that already ships a shape and has to match it:
CarModPicker's handlers emit `{"success", "status", "message", "request_id", "error_code"}`
with a flat 422 `details` list and no `errors` key, and no combination of the two flags
produced exactly that, because `validation_details` adds `details` alongside `errors` rather
than instead of it. So the local handlers stayed, which is the thing worth removing.

`error_envelope` names the shape instead. `"default"` is the historical body. `"detailed"` is
the shape above, and it implies both flags, so naming it is the whole configuration. The
built-in shapes are pinned by tests adapted from CarModPicker's own exact-body tests, field by
field, including the absence of `errors`.

A callable is the third option, receiving an `ErrorContext` and returning the body. Every
handler routes through the resolved renderer, including the Starlette 404 for an unmatched
route, so a consumer never receives a raw `{"detail": "Not Found"}` unless it installs no
handlers at all. `validation_errors` on the context is how a renderer builds its own field
shape without reparsing pydantic's output, and `error_code` is always supplied to a callable,
because a renderer decides for itself whether to emit one.

Two rules are not shape choices and do not move: no shape carries Starlette's `detail`, and a
5xx never echoes its own message. A mapped 503 still renders "Internal server error." under
`"detailed"`, which has a test of its own, since the obvious reading of a named shape is that
it turns the sanitising off.

An unknown shape name raises `ValueError` when the app is built rather than as a 500 under
load, matching how `exception_map` has validated its entries since 0.3.0.

### The DynamoDB types the package was asking consumers to supply

`exception_map` has always been able to map a repository's exception types, and it assumed the
repository had some. `webbpulse.dynamodb` raised none of its own, so every consumer defined
`ItemNotFound`, `ConditionFailed` and `TransactionCanceled` again, with the same three
mappings, and the package documented the mapping it could not itself provide.

All three now live in `webbpulse.dynamodb` under a shared `DynamoError` base, and
`install_dynamodb_error_handlers` renders them: 404, 409, and for a cancelled transaction 409
when any cancellation reason is `ConditionalCheckFailed` and 500 otherwise. That last one is
the reason this is a handler rather than three `exception_map` entries, since the status
depends on the instance and not just its type. `create_app(dynamodb_error_handlers=True)` is
the same thing.

It needs no extra: the types are plain exceptions and importing them pulls in no botocore,
which is what separates this from `install_dynamodb_handlers`. That one handles a raw
`ClientError` a repository did not translate; this one handles what a repository raises after
translating it. A service doing both installs both, and they never contend because they are
keyed on different types.

Each exception records what an operator needs and nothing the caller should see. A table name
and key, a condition expression and a set of cancellation reasons all stay in the log, and
tests assert they are absent from the response text, because `ItemNotFound("users", {"id":
email})` is the natural way to raise it.

## 0.22.0

`webbpulse.otel`: buffered spans are flushed and the provider is shut down when the container
shuts down, which stops the intermittent OTLP export errors CarModPicker's staging Lambdas were
logging at teardown. Nothing in the public API changed shape, so consumers pick this up by
taking the release.

### The export was racing the sandbox teardown

The per-request flush `instrument_fastapi` installs resolves the trace a request produced and
exports it before the response returns, so the common case was never the problem. Two traces
survived it. One whose spans are still open when the response returns stays buffered by
design, because the tail decision cannot be made on an incomplete trace, and a background task
outliving the request is the normal way that happens. And a trace whose in-request export
failed is simply gone, with nothing holding it for a retry.

Both were left to whatever ran last. Nothing did: `shutdown_tracing` existed and was
documented as worth calling from a container's shutdown path, but nothing in the package called
it, and no consumer did either. So the final export attempt was whatever the exporter's own
teardown happened to do as the sandbox was torn down underneath it, which is the 403 and
failed-export noise, about 100 ms after uvicorn's shutdown.

`instrument_fastapi` now wraps the application's lifespan, so the ASGI shutdown event flushes
what is left and shuts the provider down. It wraps `router.lifespan_context` rather than
appending to `router.on_shutdown`, and that distinction is load bearing: Starlette only runs
`on_shutdown` under its default lifespan, and passing `lifespan=` replaces `lifespan_context`
outright and never consults the handler lists. Every service here builds its app with an
explicit `lifespan=`, so an `on_shutdown` hook would have been silently dead in exactly the
deployments that needed it. The wrapper runs after the application's own shutdown work, so a
span recorded while closing a client is still exported.

### The flush is bounded, and failing it is quiet

Lambda reserves only a slice of the 2000 ms shutdown budget for the runtime process before
`SIGKILL`, so the flush is bounded at 300 ms by default, settable with
`WEBBPULSE_OTEL_SHUTDOWN_FLUSH_TIMEOUT_MILLIS` or the new `shutdown_flush_timeout_millis`
argument, and clamped at 1500 ms however it is set. An unbounded flush does not export more; it
gets killed, loses the spans anyway, and fails the container's shutdown as well.

An export that fails on the way out now logs one WARNING naming the lost span count instead of
an ERROR with a traceback. On that path the failure is a race with the sandbox going away and
says nothing about the application, which is what made the noise worth alarming on and then
worth ignoring. An in-request export failure keeps its ERROR and its traceback. Neither
`TailSamplingSpanProcessor.shutdown` nor the lifespan hook can raise, because the only thing a
raise achieves there is turning a lost span batch into a failed shutdown.

### Why the processor is still not a `BatchSpanProcessor`

Worth recording, since the obvious reading of these symptoms is that the batch schedule needs
tuning. There is no `BatchSpanProcessor` in this pipeline and adding one would be a regression.
Its background thread does not run while the sandbox is frozen, so a batch waits until either
the next invocation thaws it past its own export deadline or the sandbox is destroyed, and
lowering `schedule_delay_millis` only narrows a window the freeze can land anywhere inside.
`SimpleSpanProcessor` is the usual Lambda answer and this module already matches its
synchronicity while keeping the tail decision, which `SimpleSpanProcessor` cannot make because
it exports each span before the trace's outcome is known. The module docstring now says so.

### Backward compatible

`shutdown_tracing()` still takes no arguments and behaves as before; the timeout is optional.
The lifespan wrapping is on by default and can be turned off with `flush_on_shutdown=False` for
a consumer that owns its own shutdown path. `TailSamplingSpanProcessor.shutdown` still accepts
a bare call. New names are `SHUTDOWN_FLUSH_TIMEOUT_ENV` and `resolve_shutdown_flush_timeout`.

## 0.21.0

The `passkeys` extra accepts py_webauthn 3.x. The range is now `webauthn>=2.7,<4`, which
unblocks consumers whose resolver was pinned to the 2.x line by the old upper bound.

### py_webauthn 3.x needed no porting, only an unpinned ceiling

3.0.0 is a major for reasons that do not touch this package. It adds ML-DSA-44, ML-DSA-65 and
ML-DSA-87 for credential public key verification, rejects CBOR carrying duplicate keys, and
changes which algorithms `generate_registration_options` offers. The call signatures this
package uses are untouched: `generate_registration_options`, `generate_authentication_options`,
`verify_registration_response`, `verify_authentication_response` and `options_to_json` keep
their parameters and return types, `webauthn.helpers.structs` keeps every name imported here,
and `VerifiedRegistration` and `VerifiedAuthentication` keep every field read here. The test
suite passes unchanged against both 2.8.0 and 3.0.0.

The one behaviour that does differ is the registration algorithm set. 2.x offered nine
algorithms and defaulted `supported_pub_key_algs` to the same nine; 3.0.0 narrowed both to
EdDSA, ES256 and RS256, and put EdDSA first. Left implicit, that would mean the algorithms an
authenticator may enrol under depend on which minor a consumer's lockfile happens to resolve.
So `passkeys.SUPPORTED_COSE_ALGS` names the three explicitly and passes them to both
`generate_registration_options` and `verify_registration_response`, making the ceremony
identical on either major. A new test asserts the offered set, and it fails on 2.x if the
argument is dropped.

Login is unaffected on both majors. `verify_authentication_response` consults no algorithm
list; it verifies with the algorithm of the stored public key, so credentials enrolled under
2.x with an algorithm outside the narrowed three keep working.

## 0.20.0

`webbpulse.identity`: `POST /logout-all` no longer answers 500 on a DynamoDB deployment. The
release also carries the repository wide comment cleanup, which changes no behaviour.

### `logout-all` names its own token families

The route called `flows.logout_all(subject, ip=ip)` with no `family_ids`, which falls through
`_revoke_families` to `SessionService.revoke_all_for_user` and then to
`DynamoRefreshTokenStore.revoke_all_for_user`. That method raises `NotImplementedError` by
design: `refresh-tokens` is keyed by token hash and carries no user index, because indexing
the cold path would cost a write on every rotation of the hot one. So every call to the route
on a DynamoDB backed deployment returned 500, CarModPicker staging included, while the
in-memory store used by every route level test has a working happy path and never reached the
raise.

The M2 docstrings already described the resolution, which is for the caller to name the
families, and the route now does. The access token's `sid` claim is the caller's own family
id, and the refresh cookie names a second one, resolved through the store by a new
`SessionService.family_of`. Both are handed to `flows.logout_all`, which gains a `presented`
argument for the cookie half. `_revoke_families` already takes the safe path for any
non-`None` list, the empty one included, so the raise is no longer reachable from this route.

New route level tests run over a store that refuses the user indexed scan the way the deployed
one does, so the gap that hid this cannot reopen silently.

### Docstrings are the only documentation surface

Every prose `#` comment is gone from `src/` and `tests/`, and docstrings now cover every
module, class, function and method. Directive comments are preserved exactly: the `noqa`,
`type: ignore` and `pragma: no cover` counts match the previous release, and any prose tail on
one was trimmed to the bare directive.

This is a documentation change only. Each Python file is AST-identical to 0.19.0 once
docstrings are normalised away, and `pyproject.toml` parses to the same values it did before,
so no consumer needs to do anything beyond taking the pin.

## 0.19.0

`webbpulse.otel`: two fixes for span export failures that were flapping CloudWatch alarms in
the CarModPicker staging environment. Both are defects in dependencies rather than in this
package, and both are worked around here because both only bite under Lambda.

### SigV4 credentials no longer latch at cold start

Exports to the X-Ray OTLP endpoint were being signed with whatever credentials the process
resolved on its very first export, for the entire life of the execution environment.

`aws-opentelemetry-distro`'s `AwsAuthSession` resolves credentials once, caches the object
and sets `_credentials_resolved` permanently, then builds a `SigV4Auth` from that one object
for every request. Its own comment says this is safe because `RefreshableCredentials` rotates
on attribute access, and on EC2 or ECS that is true. Under Lambda it is not: the execution
role arrives in `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`, so
botocore's `EnvProvider` wins the chain, and that provider only returns `RefreshableCredentials`
when `AWS_CREDENTIAL_EXPIRATION` is also set. Lambda does not set it, so what comes back is a
plain `Credentials` object that never re-reads the environment. `botocore.session.Session`
memoises its result too, so asking it again returns the same stale object.

The consequence is invisible until a container outlives its credentials, which needs a
function busy enough never to cold start inside the credential lifetime. The staging Python
domain Lambdas were exactly that: no `INIT_START` in twenty four hours. Past the expiry every
export was signed with a dead session token and rejected with
`Failed to export span batch code: 403, reason: Forbidden`, on every invocation, with nothing
in the application at fault and no path back short of the sandbox being recycled.

The session handed to `OTLPAwsSpanExporter` is now wrapped so its `get_credentials` returns a
credentials object that resolves afresh on each signature. Credentials that can already
refresh themselves are left alone to do so, since their own machinery may be talking to IMDS
or the container credential endpoint; only the non-refreshable case re-runs the provider
chain, which is three environment reads on an export that is already making an HTTPS request.

### A frozen and thawed sandbox no longer raises out of the exporter

`OTLPSpanExporter.export` fixes one deadline for the whole export and gives each retry the
remainder of it as that attempt's HTTP timeout. That assumes wall clock time tracks the work.
A Lambda sandbox frozen mid-export and thawed later breaks the assumption by however long the
freeze lasted, so the remainder goes negative and urllib3 rejects it outright:

```
ValueError: Attempted to set connect timeout to -221.00219130516052, but the timeout cannot
be set to a value less than or equal to 0.
```

`ValueError` is not a `requests.exceptions.RequestException`, so upstream's own retry loop
does not catch it and it escaped into this package's `_export`, which logged it at ERROR and
tripped the log metric filter behind it.

Two changes. The exporter's `requests` session is wrapped so a non-positive timeout is raised
to a one millisecond floor before urllib3 sees it, which preserves the caller's intent (the
deadline has passed, fail fast) while failing as a timeout that upstream already knows how to
account for. And `_export` now logs this one specific condition at WARNING rather than ERROR,
because a request that was served correctly and lost only some of its telemetry to a freeze
is not an application fault and should not page anyone. Every other exporter error keeps its
ERROR and its traceback.

## 0.18.0

`webbpulse.ci`: domain discovery for the per-domain pytest matrix in the organisation's
reusable `python-ci.yml`.

A service's test suite grows with its domains, and running it as one pytest invocation made
CI slower every time a domain was added. The reusable workflow now runs one job per domain,
so wall clock time tracks the largest domain rather than the sum of all of them. This module
is what tells that workflow which jobs to create.

The convention is declarative and lives in the service's own `pyproject.toml`, so adding a
domain to CI is adding a line rather than editing a workflow:

```toml
[tool.webbpulse.ci]
test-root = "tests"

[tool.webbpulse.ci.domains]
identity = ["tests/auth", "tests/dependencies"]
catalog = ["tests/api/endpoints/test_parts.py"]
```

A value may name a directory or a single test file, because a suite that is not yet split by
directory still has to be splittable: requiring the files to move first would make adopting
this a refactor rather than a configuration change.

Everything under `test-root` that no domain claims runs in a `shared` job, computed as a
deselection (`--ignore` per claimed path) rather than a list, so a new test file is covered
the moment it is written. Forgetting to claim a file makes it run in `shared`, which is
slower but never silent.

Two commands, both consumed by the workflow:

- `python -m webbpulse.ci domains` prints a JSON array of domain names for `fromJson` in a
  matrix `strategy`.
- `python -m webbpulse.ci pytest-args --domain <name>` prints that job's pytest path
  arguments, shell quoted.

The module imports only the standard library, so the workflow can call it in a bare
interpreter before the service's dependencies are installed.

## 0.17.0

Identity M5 follow-up: a public passkey availability route, so a frontend can ask whether
passkeys are offered instead of probing a route that costs something to call.

WebbPulse-Portfolio probes `POST /api/auth/login/passkey/options` on sign-in page load to
find out, and that is wrong twice over. It spends that route's rate limit budget, 30 per 15
minutes per IP, on sign-in *page loads* rather than on sign-ins, so a user who reloads the
page enough times is refused the passkey sign-in they then attempt. And the probe is not a
read: `begin_passkey_login` writes a WebAuthn challenge row per call, so every sign-in page
load in the estate leaves a row in the challenge table to expire, which is a storage cost
paid to answer a question about configuration. WebbPulse-Portfolio PR 182 added a
`sessionStorage` cache as a stopgap and asked for this route. A cache in one frontend is not
a fix: the first load of every session still pays both costs, and every other consumer pays
them in full.

### Added

- **`GET <prefix>/passkeys/availability`**, anonymous, answering
  `{"enabled": <bool>, "passwordless": <bool>}` from the `passkeys_enabled` and
  `passkeys_passwordless` settings. Carries `Cache-Control: public, max-age=300`, the same
  number `oauth/providers` and the JWKS carry and for the same reason: whether passkeys are
  on changes only when a deploy changes it, which is rare but is exactly the moment somebody
  is watching for the button to appear.

  `enabled` says the deployment registers and verifies passkeys at all, so an account
  settings page should offer to add one. `passwordless` says a passkey is a way *into* an
  account, so a sign-in page should offer the button, and it is the distinction
  `begin_passkey_login` already enforces.

  **`passwordless` is `false` whenever `enabled` is `false`.** `passkeys_passwordless`
  defaults to `True` and nothing else reads it against `passkeys_enabled`, so a deployment
  with passkeys switched off still holds `passwordless=True` and means nothing by it.
  Reporting that pair would tell a frontend to draw a "Sign in with a passkey" button
  against login routes that do not exist. The gate is in the route, so the two can never
  disagree and a client can read `passwordless` alone.

  The answer comes from settings rather than from whether the stores were supplied. A
  deployment with the capability on but no passkey table is a configuration error an operator
  has to fix, and reporting `enabled: false` for it would hide that error behind a frontend
  that quietly stops offering passkeys.

  **The route mounts in every deployment**, including one with passkeys switched off and the
  documents-only one that has no hooks and no stores at all, where it answers
  `{"enabled": false, "passwordless": false}` and `{"enabled": true, "passwordless": true}`
  respectively. It is the one passkey route that is unconditional, and the deliberate
  exception to the rule the other seven follow. Those do not mount when they cannot work,
  because a route that can only answer 503 is worse than an absent one; this one can always
  work, and its answer when passkeys are off is the correct answer rather than a degraded
  one. A route that were absent would answer 404, and a 404 is exactly the ambiguous signal
  this route exists to replace: indistinguishable from a routing mistake, a gateway
  misconfiguration, or an older version of this package.

  It consumes no rate limit budget and writes nothing. The response is two booleans derived
  from configuration, it holds nothing about any user, it touches no store and makes no call.
  Rate limiting it would mean a DynamoDB write per sign-in page load to protect a handler
  that reads two attributes, which is the cost the route was added to remove.

  It is tagged `identity` and `passkeys` in the OpenAPI document, and is deliberately
  annotated `-> Any` with `response_model=None` rather than `-> JSONResponse`, for the reason
  `oauth_providers` gives: under `from __future__ import annotations` the latter is an
  unresolvable string that FastAPI hands pydantic as a response model, which makes
  `app.openapi()` raise for the whole app. Every other route in `passkey_routes.py` carries
  that annotation; this one mounts everywhere, so it must not be what takes `/docs` away from
  a product that has no passkeys at all.

- **`register_passkey_availability`**, exported from `webbpulse.identity`, along with
  `PASSKEY_AVAILABILITY_PATH` and `PASSKEY_AVAILABILITY_CACHE_CONTROL`. This is the first
  time `webbpulse.identity.passkey_routes` exports anything through the package root.

### Changed

- **Nothing behavioural.** The seven passkey routes, their rate limits, their bodies and
  their gating are untouched, and so is every other route. A deployment that upgrades gains
  one anonymous `GET` and changes in no other way.

## 0.16.0

Identity M6 follow-up: a public OAuth provider discovery route, so a frontend can ask which
providers are available instead of guessing.

WebbPulse-Portfolio PR 170 had to infer availability by probing `GET /oauth/{provider}/start`
and reading the status code, which is wrong twice over. It spends that route's rate limit
budget, 20 per 15 minutes per IP, on sign-in *page loads* rather than on sign-ins, so a user
who reloads the page enough times is refused the sign-in they then attempt. And a non-200
cannot distinguish "this provider is not configured" from "this provider is configured and
something is briefly broken", so a transient failure silently removes a sign-in button. An
explicit list is a different question with an unambiguous answer.

### Added

- **`GET <prefix>/oauth/providers`**, anonymous, answering
  `{"providers": [{"id": "google", "display_name": "Google"}, ...]}`. Ordered as
  `PROVIDERS` defines, Google then GitHub, rather than in the order `oauth_providers`
  happens to be written in, so the buttons do not reshuffle between environments. Carries
  `Cache-Control: public, max-age=300`, matching the JWKS rather than the discovery
  document's hour: turning a provider on is exactly the moment somebody is watching for the
  button to appear.

  A provider appears only when it has **both** a client id and a client secret. See the
  behaviour change below for why the second half matters.

  **The route mounts in every deployment**, including one with no OAuth configured at all,
  where it answers `{"providers": []}`. It is the one OAuth route that is unconditional. A
  route that were absent when OAuth is off would answer 404, and a 404 is exactly the
  ambiguous signal this route exists to replace: indistinguishable from a routing mistake or
  an older version of this package. An empty list says "no providers, and I am sure".

- **`OAuthProviderConfig.display_name`**, and `display_name` on both baseline providers
  (`"Google"`, `"GitHub"`). Fixed in the package rather than left to each frontend, because
  a provider's name is the provider's to spell and three frontends inventing their own
  casing is three chances to get a third party's trademark wrong.

- **`OAuthService.available_providers()`**, returning the `OAuthProviderConfig` for each
  fully configured provider. Stricter than the existing `enabled_providers()`, which asks
  only for a client id and still decides whether the five flow routes mount.

- **`register_oauth_provider_discovery`**, exported from `webbpulse.identity`, along with
  `OAUTH_PROVIDERS_PATH` and `OAUTH_PROVIDERS_CACHE_CONTROL`.

  It is tagged `identity` and `oauth` in the OpenAPI document, and is the only identity route
  that appears there: the `.well-known` documents are `include_in_schema=False` because API
  Gateway fetches them rather than a client writing against them. It is deliberately
  annotated `-> Any` with `response_model=None` rather than `-> JSONResponse`, because under
  `from __future__ import annotations` the latter is an unresolvable string that FastAPI
  hands pydantic as a response model, which makes `app.openapi()` raise for the whole app.
  Every other route in this package carries that annotation; this one mounts everywhere, so
  it must not be what takes `/docs` away from a product that has no OAuth at all.

### Changed

- **`OAuthService.start` now refuses a provider that has a client id but no client secret**,
  with the existing `OAUTH_PROVIDER_UNAVAILABLE` code and a 503, before redirecting. Until
  now such a provider mounted, sent the user to Google, collected their consent, and only
  then failed at the token exchange on the way back, spending a real person's attention on a
  configuration error. The refusal names no configuration; the operator still gets the detail
  in a log line. `identity_from_callback` keeps its own check, since it is reachable
  directly.

  This is the only behaviour change in the release, and it converts a late failure into an
  early one for a deployment that was already broken. A fully configured provider is
  unaffected.

### Fixed

- **`_oauth_route_paths` in the M6 suite enumerated `app.routes`**, which under the FastAPI
  the CI installs (0.141) no longer holds a router's flattened routes: `include_router`
  mounts the router, so `app.routes` carries an empty-path mount and none of the real paths.
  The helper therefore returned the empty set for every input, and both "the OAuth routes are
  absent" tests passed against a fully configured router. It now reads `router.routes`, which
  is both correct on either FastAPI version and the honest thing to inspect, since the router
  is what this package builds and what a consumer mounts.

## 0.15.0

Identity M5: passkeys. WebAuthn registration and passwordless sign-in, credential
management, and two new DynamoDB tables. Additive throughout: nothing existing changes
shape, no route contract moves, and a deployment that does not create the two tables gets
0.14.0's behaviour with no passkey routes mounted at all.

### Added

- **`webbpulse.identity.passkeys`**, a new module holding `PasskeyService`: the WebAuthn
  registration and authentication ceremonies, the challenge lifecycle, the signature counter
  check and the credential management operations. It imports the `webauthn` package lazily
  inside the methods that need it, so the new `passkeys` extra is required only by a product
  that actually turns passkeys on.

- **`webbpulse.identity.passkey_routes`**, holding `register_passkey_routes`, which mounts
  seven routes when both M5 stores are present and `passkeys_enabled` is true:

  | Route | What it does |
  | --- | --- |
  | `POST /passkeys/register/options` | Registration options for the authenticated caller |
  | `POST /passkeys/register/verify` | Verify the attestation and store the credential |
  | `POST /login/passkey/options` | Authentication options, anonymous |
  | `POST /login/passkey/verify` | Verify the assertion and issue the session |
  | `GET /passkeys` | The caller's own passkeys |
  | `PATCH /passkeys/{credential_id}` | Rename one |
  | `DELETE /passkeys/{credential_id}` | Remove one |

- **Two tables.** `passkeys`, hash `user_id` and range `credential_id`, with a
  `credential_id-index` GSI for the login lookup and **no** TTL, because a credential is
  removed when its owner removes it and never on a timer. `webauthn-challenges`, hash
  `challenge_id`, TTL attribute `expires_at`. Both come with `PasskeyStore` and
  `WebAuthnChallengeStore` abstract bases and a Dynamo and an in-memory implementation each,
  matching every other store in the package, and two new optional fields on `IdentityStores`.

- **A `passkeys` extra**, `webauthn>=2.7,<3`. Separate from `identity` because WebAuthn is a
  capability a product turns on rather than part of the base slice.

- **`IdentityFlows` gained `begin_passkey_registration`, `finish_passkey_registration`,
  `begin_passkey_login`, `login_with_passkey`, `list_passkeys`, `rename_passkey` and
  `delete_passkey`**, plus a `passkeys` attribute that is `None` when the capability is off.
  `IdentityHooks` is **unchanged**: M5 adds no hook method and no product implementation
  needs updating.

### Security

- **Challenges are rows, not tokens, and are single use.** A WebAuthn challenge exists to
  make an assertion unreplayable, which is a claim about state that a signed token cannot
  make: a JWT verifies exactly as well the second time as the first, so a captured
  options-and-assertion pair replays for the whole of the token's lifetime. CarModPicker's
  implementation puts the challenge in a five minute JWT, and porting it unchanged would
  have carried that hole into the shared package. So a challenge is written to
  `webauthn-challenges` when options are generated, **deleted** when it is consumed, and
  refused when its deadline has passed regardless of whether DynamoDB's TTL has reached the
  row. Five minutes, and the row is spent by one attempt whatever the outcome, so a stolen
  challenge cannot be ground against.

- **The origin and the RP ID are verified against settings on every ceremony.** Both are
  required rather than defaulted, and the service raises naming the environment variable if
  either is missing, because an empty origin list makes the origin check vacuous and the
  origin check is the whole of what makes a passkey phishing resistant.

- **Signature counter regression is refused and logged at ERROR.** Section 6.1.3 of the
  WebAuthn specification treats a counter that fails to increase as evidence of a cloned
  authenticator. The check is this package's own rather than the library's: `finish_login`
  passes py_webauthn a stored count of zero so that the comparison happens here, where the
  regression is logged as the finding it is instead of disappearing into a generic
  verification failure, and where an upgrade to the library cannot quietly change it. Both
  counts being zero is the specification's documented exception and is allowed, because many
  authenticators, Apple's included, keep no counter at all.

  Counters **migrate as stored, never as zero**. A credential imported from another system
  keeps the count that system last saw. Importing at zero would disarm the check for that
  credential permanently, since every subsequent assertion would exceed zero and so would
  look correct forever.

- **A user-verified passkey counts as two factors, and the package says so in `amr`.** A
  passkey login sets `amr` to `["swk"]` when the authenticator did not verify the user, and
  `["swk", "pin", "mfa"]` when it did; both values are RFC 8176 registered. The reasoning:
  the assertion proves possession of a private key that never leaves the authenticator, and
  the `uv` flag proves the authenticator separately checked something the user knows or is
  before it would sign, which is possession plus knowledge or inherence in one gesture.

  The consequence is deliberate and is the one place the package decides an MFA policy
  rather than asking the product: a user with TOTP enrolled who signs in with a user-verified
  passkey is **not** challenged for a code. The same user signing in with a passkey that
  reports no user verification **is** challenged, exactly as a password is, and that path
  returns the existing `mfa_required` body so no client needs a new branch.

- **Enumeration resistance reaches the passkey login leg.** `POST /login/passkey/options`
  answers any input, including an address with no account, with a challenge and an empty
  `allowCredentials`, which is byte-identical to a genuine discoverable-credential request.
  Refusing, or answering with a different shape, would turn an unauthenticated route into an
  account oracle that needs no password. Every verify failure is one refusal with one
  message, and registering a credential already enrolled elsewhere answers without saying
  whose it is.

- **Passwordless sign-in is gated on `passkeys_passwordless`.** With it off, both login
  routes refuse and a passkey is a second factor and a managed credential but not an entry
  point. Registration, rename and delete require an authenticated subject read from the
  verified claims and never from the body.

- **The last passkey cannot be deleted by a user with no password.** Not a rule about
  passkeys so much as about not stranding somebody outside their own account. "Has a
  password" is read from the `credentials` store, which is where this package's own password
  lives, so **no new hook was needed**. A product whose users can sign in some other way the
  package cannot see still has `may_authenticate` and can refuse the delete in front of the
  route.

## 0.14.0

Identity M6: OAuth sign-in and account linking against Google and GitHub.

Additive. Every existing route, stored record and hooks implementation keeps working, and a
product that configures no provider gets no new routes and needs no new tables. The one
change to a shared interface is a new `IdentityHooks` method with a default, described below.

### Added

- **OAuth sign-in and account linking**, in two new modules: `webbpulse.identity.oauth` for
  the providers, the stores and the linking rules, and `webbpulse.identity.oauth_routes` for
  the five routes. Both are mounted automatically by `build_identity_router` when the product
  has configured at least one provider with a client id and supplied the two new stores; a
  route that could only answer 503 because nobody set `google_client_id` is worse than a
  route that is not in the OpenAPI document at all.

  Five routes: `GET /oauth/{provider}/start`, `GET /oauth/callback`,
  `POST /oauth/{provider}/link`, `GET /oauth/links` and `DELETE /oauth/{provider}/link`. The
  three management routes take their subject from verified claims and refuse an anonymous
  caller.

  The authorization code flow, with PKCE where the provider supports it. Google gets an S256
  challenge and a nonce and its ID token is verified against the published JWKS for
  signature, `iss`, `aud`, `exp` and `nonce`; GitHub's web flow documents neither PKCE nor an
  ID token, so its identity comes from `/user` plus `/user/emails`, where the verified
  primary address is preferred because `/user`'s `email` is an unverified profile field.

  The callback issues the same token pair as a password login, through the same path, and
  returns the `mfa_required` challenge when the account has TOTP enabled. The access token
  carries `amr: ["oauth", "<provider>"]`.

- **Two tables.** `oauth-states`, hash key `state`, TTL attribute `expires_at`, holding one
  in-flight authorization for ten minutes and spent by a conditional `DeleteItem` so a state
  is single use. `oauth-links`, hash key `provider_subject` (`provider#subject`) with a
  `user_id-index` GSI, holding one provider identity attached to one local user. Expiry is
  re-checked on every read, because DynamoDB TTL is storage reclamation and not access
  control.

  The `oauth-links` key diverges from section 4.2 of `docs/identity-standard.md`, which
  sketches a hash of `id` with two GSIs. Keying on the provider identity makes the uniqueness
  constraint the primary key, so attaching is one conditional put on
  `attribute_not_exists(provider_subject)` and needs no synthetic reservation rows.

- **`IdentityStores.oauth_states` and `IdentityStores.oauth_links`**, both optional and both
  defaulting to `None`, with `require_oauth_states()` and `require_oauth_links()` alongside
  the existing accessors. In-memory and DynamoDB implementations of each.

- **`IdentitySettings.oauth_redirect_uris`**, a list defaulting to empty, which means the
  single derived `<issuer>/oauth/callback`. Entries are matched by exact string equality: a
  prefix match would admit `https://app.example.com.attacker.test`.

- **`oauth_client_secrets` on `build_identity_router`**, a mapping of provider name to client
  secret. An argument rather than a settings field because the secrets come from the
  product's Secrets Manager JSON rather than an `IDENTITY_`-prefixed variable, and keeping
  them off the settings object keeps them out of anything that renders it. They are never
  logged, and a missing secret answers 503 with a message that names no configuration.

- **An `oauth` extra**, pulling in `httpx` for the provider calls. Only needed by a product
  that mounts the OAuth routes: the client is constructed lazily, so the package still
  imports without it.

- **`IdentityHooks.has_other_sign_in_method(user_id)`**, which reports whether the product
  holds a sign-in method this package cannot see. **It defaults to `False` on
  `BaseIdentityHooks`, so every existing hooks implementation stays valid with no change.**
  `False` is the safe default in the only direction that matters: it can make `unlink` refuse
  more often, never less, while `True` would let a product that had not implemented it delete
  a user's last credential. A product holding passkeys or another federated store should
  implement it.

### Security

- **An OAuth identity auto-links to an existing account only when the provider email and the
  local account email are both verified.** Either half alone is a takeover. Checking only the
  local side lets an attacker who registered a provider account with somebody else's address
  inherit that account; checking only the provider side lets an attacker who registered
  locally with a victim's address, and never verified it, be handed the victim's real
  provider identity. A refusal is `OAUTH_EMAIL_UNVERIFIED`, and the user signs in with their
  password and links from account settings, which needs no email check because they have
  proved they hold both sides. The message is identical whichever half failed, since naming
  it would enumerate accounts and their verification state.

- **Unlinking refuses when it would leave the account with no sign-in method.** Another OAuth
  link, a password, or the new hook each count as remaining, and the count happens before
  anything is deleted. Removing the last method is permanent lockout: nobody can log in, so
  nobody can add a method back. Remaining links are read from the GSI and then re-read from
  the base table by primary key, because the GSI is eventually consistent and over-counting
  is the one direction that permanently loses an account.

- **`state` is server-side, single use and provider-bound.** Unknown, expired and
  already-spent states all answer with one message and one code, because distinguishing them
  confirms that a guess found a real row. The PKCE verifier is written to the state row and
  never placed in the authorization URL, since a verifier the browser can read protects
  against nothing.

- **The JWKS is fetched through the module's own HTTP client**, not `PyJWKClient`, which
  fetches with `urllib` and no timeout. Every provider call now carries the same explicit
  timeout, so a provider that accepts a connection and never answers cannot hold a Lambda
  execution environment open until the function times out.

- **No provider tokens are stored.** Neither the access token nor the refresh token from the
  provider is written down. This design consumes a provider as an identity source and never
  calls a provider API afterwards, so a stored token would be a credential with no use.

## 0.13.0

Identity M4 security fix: `POST /totp/disable` and `POST /recovery-codes` now require proof
of possession of the second factor, not just a bearer access token.

**Breaking, for two route contracts.** Both routes previously took no body and acted on the
bearer subject alone. Both now require `{"code": "<string>"}`, and a request without it is a
422 rather than a success. Every other route is unchanged, and no stored data changes shape,
so there is no migration: the upgrade is a client change on the two calls.

### Security

- `POST /totp/disable` and `POST /recovery-codes` require a current TOTP code or an unused
  recovery code. Both routes are destructive to the second factor, and both were reachable
  with a short-lived access token and nothing else. An access token is short-lived but it is
  still a bearer secret, so a stolen one could switch off the very control that bounds what
  stealing it is worth, or invalidate the recovery codes the legitimate user would need to
  get back in. Requiring the factor means an attacker has to hold the second factor as well,
  which is the thing they were trying to get around.

  The code is verified by `MfaService.verify_challenge`, the same call the second leg of
  login and step-up already make, so a TOTP code and a recovery code are both accepted, the
  replay watermark and the single-use consumption are the ones already in place, and a
  recovery code presented to either route is spent exactly as it is on login. There is no
  second verification path to keep in step. A refusal is the existing `INVALID_MFA_CODE`
  envelope with the 401 `POST /login/totp` answers, and both routes now carry the same
  `mfa-verify` rate limit as that route: they accept the same codes, so they share the
  bound that makes a six digit code space out of reach.

  Verification happens **before** anything is deleted on both routes. A refused disable
  leaves the factor active and the recovery codes intact, and a refused regenerate leaves
  every existing code working, which matters because regenerating deletes the old set before
  writing the new one.

  There is deliberately **no step-up alternative** on these routes. Accepting a recently
  stepped-up access token instead of a code would reintroduce the same bearer-token-only
  path through a second door, and `code` is the single mechanism.

### Changed

- **Breaking.** `POST /api/auth/totp/disable` and `POST /api/auth/recovery-codes` take a
  required `code` field. A missing, non-string or blank one is a 422 `VALIDATION_ERROR`
  rather than an `INVALID_MFA_CODE`, so a client that forgot the field is told it forgot the
  field instead of showing the user "that code is not valid" for a request that never asked
  them for one. `@webbpulse/auth` sends `code` on both routes as of its matching release.

- `IdentityFlows` grows `disable_totp` and `regenerate_recovery_codes`, both taking a
  `user_id` and a `code`. The router calls these rather than reaching past the flows into
  `MfaService` as it did before, which is what puts the verification and the destructive
  write behind one call. `MfaService.disable_totp` and
  `MfaService.regenerate_recovery_codes` are unchanged and still verify nothing themselves:
  they are the mechanism, and the flow is the policy.

## 0.12.1

Housekeeping. The bcrypt cost is resolved when the function is called rather than when the
module is imported, so configuring it after import actually works.

**No behaviour changes for a caller that does nothing.** `DEFAULT_ROUNDS` is still 12, the
hash format is unchanged, the 72 byte truncation rule is unchanged and `verify_password` is
untouched. Every hash this package has ever written still verifies, and nothing needs a
migration.

### Fixed

- `hash_password` and `needs_rehash` read `DEFAULT_ROUNDS` at call time. Both were declared
  as `rounds: int = DEFAULT_ROUNDS`, and a default argument is evaluated once, as the `def`
  executes at import, then frozen into the function object. Rebinding
  `webbpulse.security.DEFAULT_ROUNDS` afterwards therefore never reached either function, so
  a service that configured the cost after importing the module, and a test that patched it
  down to bcrypt's minimum to stay fast, were both ignored, and ignored silently: there was
  no error, the work simply kept happening at cost 12.

  The signature is now `rounds: int | None = None`, resolved against the module attribute in
  the body. Passing `rounds=` explicitly still wins, as before. `DEFAULT_ROUNDS` loses its
  `Final` annotation, since the point is that a consumer may rebind it.

  This package's own identity suites had already hit this and worked around it by wrapping
  both functions, with a fixture docstring stating that patching the constant "does
  **nothing**". Those fixtures keep the wrapper, which pins the cost more tightly than a
  changed default can because it also lowers a call that passes `rounds=` explicitly.

- `uv.lock` is ignored. `uv` reads the `[dependency-groups]` table in `pyproject.toml` and
  writes a lockfile, which showed up as an untracked file in every checkout. The project
  pins nothing: CI and the README both install with `pip install -e`, so there is no
  lockfile to commit and a stray one is noise.

## 0.12.0

Identity M4: TOTP with KMS envelope encryption, recovery codes, the MFA ticket, step-up and
`amr` on the access token.

**Additive, with one behaviour change confined to users who enrol.** The six MFA routes
mount only when `totp_enabled` is on and the product supplies a TOTP factor store, a recovery
code store and an identity token store, on the same rule the M2 and M3 routes follow. A
service that supplies none of them mounts exactly what it mounted in 0.11.0. `login` changes
shape only for a user with an **active** factor: it answers 200 with a challenge instead of
tokens, and raises `MfaChallengeRequired` from the flow rather than returning a second
success shape, so a product that has not handled MFA fails loudly rather than handing out a
session.

**No frontend change is required.** The wire contract matches `@webbpulse/auth` 0.4.0: the
first leg returns `{"mfa_required": true, "mfa_ticket": "...", "factors": ["totp"]}` with
HTTP 200, and the second leg reads `mfa_ticket` and `code`.

**Still absent**, per section 9.1: passkeys (M5), OAuth (M6).

### Added

- `webbpulse.identity.totp`: RFC 6238 TOTP with no new dependency. Seed generation,
  the `otpauth://` provisioning URI, code generation and verification. Checked against all
  six RFC 6238 Appendix B vectors, which is the only test that catches a generator and a
  verifier that are wrong in the same direction.

  `verify_code` returns the matched **step** rather than a bool, because the caller has to
  store it: a code is accepted once per time step and a step at or below the stored watermark
  is refused, which is what stops a shoulder-surfed code being replayed inside its window.
  The window is one step either side of now, not three: each extra step multiplies an
  attacker's chance against a million-value space, and the rate limit is the other half of
  that bound.

  HMAC-SHA1 deliberately. Every mainstream authenticator ignores the `algorithm` parameter,
  so an SHA-256 seed produces codes the user's app cannot generate, and SHA-1's weakness is
  collision resistance, which HMAC does not depend on.

- `webbpulse.identity.crypto`: `EnvelopeCipher`, `SealedSecret` and the `KmsDataKeyClient`
  protocol. A fresh 256-bit data key per secret via `GenerateDataKey`, AES-256-GCM locally,
  and the wrapped key stored alongside the ciphertext. `{"user_id", "purpose"}` is the
  encryption context, so a ciphertext moved to another user's row fails to decrypt and a
  value encrypted for some later feature cannot be replayed as a TOTP seed.

  A key used for exactly one message makes GCM nonce reuse impossible by construction, which
  is why this is an envelope rather than a direct `kms:Encrypt`. Section 4.4 of the standard
  is updated to match: it previously argued the other way, on size.

- `webbpulse.identity.mfa`: `MfaService`, covering TOTP enrolment and verification, recovery
  codes, and the MFA ticket. Enrolment is inactive until a first code confirms it, and the
  confirming step is recorded at activation so that code cannot then be used to sign in.
  Recovery codes are issued at activation, ten of them, SHA-256 hashed at rest, single use,
  and regenerating replaces the whole set. Disabling TOTP deletes the codes too.

  Every refusal is one `MfaRejected` with one message, whatever went wrong. A distinct
  message for "you have no factor" tells an attacker which accounts to try something else on.

- `IdentityFlows.complete_mfa` and `IdentityFlows.step_up`. `complete_mfa` spends the ticket
  **before** checking the code, so a stolen ticket cannot be used to grind codes. `step_up`
  re-authenticates inside the existing session: `auth_time` moves and `amr` gains the factor,
  no new refresh family is started and no cookie is written.

- `amr` and `auth_time` on the access token. `pwd`, `otp` and `mfa` are RFC 8176 values;
  `recovery` is deliberately not one, because a printed backup code is a bearer secret rather
  than a possession factor and a route requiring a real second factor has to tell them apart.
  Both claims are applied **after** the product's `claims_for` hook, never merged with it: a
  hook that could set `amr` could assert a factor its user never satisfied.

- Two tables, `totp-factors` and `recovery-codes`, with `TotpFactorStore` and
  `RecoveryCodeStore` and in-memory and DynamoDB implementations of each. Activation, the
  step watermark and code consumption are all conditional writes, so two racing requests
  resolve to exactly one acceptance. The MFA ticket reuses `identity-tokens` with a new
  `mfa_ticket` purpose rather than taking a sixth table: it is the same entity the table
  already holds.

- Six routes under the issuer path: `POST /login/totp`, `POST /totp/enrol`,
  `POST /totp/activate`, `POST /totp/disable`, `POST /recovery-codes` and `POST /step-up`.
  `login/totp` must stay **outside** the gateway's JWT authorizer, since the ticket's audience
  is `<issuer>/mfa`; the other five sit behind it and read the subject from verified claims
  rather than from the body.

- `IDENTITY_DATA_KEY_ARN`, `IDENTITY_TOTP_ENABLED`, `IDENTITY_MFA_TICKET_TTL` and
  `IDENTITY_MFA_REQUIRED_FOR_ROLES` settings.

### Fixed

- The MFA routes mount before the email early-return in `_mount_flows`, not after it. Mounted
  after, a product running TOTP with no `EmailSender` configured had no second leg of login
  at all, silently. MFA needs no sender.

- `webbpulse.identity.totp` accepts a base32 seed that still has its padding. The decoder
  recomputed the padding from a length that included the padding already present, so an
  unmodified pasted seed was padded twice and rejected as the wrong length, which is exactly
  the case the tolerance existed to serve.

- The `otpauth://` provisioning URI is percent-encoded as a URI rather than as a form body. A
  space in the issuer became `+`, which a compliant authenticator reads literally and shows
  in the account name.

## 0.11.0

Identity M3: email verification and password reset over SES, plus a contract suite that
checks a deployed service against what API Gateway's JWT authorizer actually requires.

**Additive.** The four new routes mount only when a product supplies both an `EmailSender`
and an `identity-tokens` store, on the same rule the M2 flow routes follow. A service that
supplies neither mounts exactly what it mounted in 0.10.0. Nothing existing changes shape.

**Still absent**, per section 9.1: TOTP and MFA (M4), passkeys (M5), OAuth (M6).

### Added

- `webbpulse.identity.email`: the `EmailSender` ABC, `SesV2EmailSender` over SES v2
  `SendEmail`, `RecordingEmailSender` for tests, and the four message templates. No
  templating dependency: `string.Template` with `substitute` rather than `safe_substitute`,
  so a missing value raises in a test instead of mailing somebody a body containing `$link`.

  Every message carries both a plain text and an HTML part, rendered from the same values
  through one function, and the HTML part escapes what the text part takes raw.

  `ses_configuration_set` is omitted from the call when unset rather than sent empty. A
  configuration set that does not exist is a hard failure on every send, and an empty string
  is a name that does not exist rather than an absence.

- `webbpulse.identity.verification`: `LinkService`, the single-use link both flows are built
  from. 256 bits from a CSPRNG, only the SHA-256 stored, consumed by a conditional write so
  two racing clicks cannot both win, and expiry re-checked in code on every confirmation
  because a DynamoDB TTL is storage reclamation rather than access control.

  Every refusal carries one message and one code whatever went wrong. Telling a caller who
  guessed a value that it was "already used" confirms the guess found a real token.

- Four routes under the issuer path: `POST /verify-email`, `POST /verify-email/confirm`,
  `POST /reset` and `POST /reset/confirm`. Both request routes answer 200 for any address,
  per section 5.4, and the flow methods behind them return `None` on every path so a router
  cannot branch on the outcome even by accident.

- `IdentityFlows.request_verification`, `confirm_verification`, `request_password_reset` and
  `confirm_password_reset`, callable without FastAPI like the rest of the flow layer.

- `IdentityHooks.mark_email_verified`, the seam for the `email_verified` column. It lives on
  the product's `users` table, which section 4.2 gives to the `users` domain, so the package
  cannot write it. No default, unlike `claims_for` and `on_user_created`: a product that
  mounted the flow and forgot the hook would confirm addresses that never became verified.

- `tests/test_identity_contract.py`, skipped unless `WEBBPULSE_IDENTITY_CONTRACT_BASE_URL`
  names a deployed issuer. It fetches the discovery document and the advertised `jwks_uri`
  and asserts the shape API Gateway needs. **The default test run makes no network request.**

      WEBBPULSE_IDENTITY_CONTRACT_BASE_URL=https://api.staging.webbpulse.com/api/auth \
          pytest tests/test_identity_contract.py -v

### Changed

- `register` now mails a verification link on success and, for an address that already has
  an account, mails that address the notice section 5.4 specifies. Both are best effort: a
  failed send does not roll back an account that already exists, because that would leave a
  real account behind a 500 and a user who cannot register again.

- `change_password` and a completed reset both send a password-changed notice. Not required
  by the standard, and included because it is the one signal a user has that a takeover
  happened: an attacker who changes a password locks the owner out silently otherwise.

- A completed password reset revokes **every** refresh family for the user, keeping nothing,
  unlike `change_password`'s `keep_family_id`. The person resetting may not be signed in at
  all, and no session is known to be the owner's rather than the attacker's.

- `describe_expiry` renders a 24 hour lifetime as "24 hours" rather than "1 day", which is
  the wording section 4.3 uses and therefore the wording a support conversation will quote.

## 0.10.0

Identity M2: the password and session flows, on the foundations M1 built. Register, login,
change password, refresh with rotation and reuse detection, logout and logout-all, plus the
progressive lockout and the password policy behind them.

**Additive for anyone on M1.** The six flow routes mount only when a product supplies both
`hooks` and a credential store. `build_identity_router` called without them mounts exactly
what it mounted in 0.9.0, so a service that serves only a JWKS does not acquire a login
endpoint by upgrading. M1's route test passes unchanged.

**Still absent**, per section 9.1: email verification and reset (M3), TOTP and MFA (M4),
passkeys (M5), OAuth (M6).

### Breaking

- **Every route now mounts under the issuer's path.** 0.9.0 served the two `.well-known`
  documents at the origin whatever the issuer said, which is correct only for an issuer with
  no path. For the standard's own `https://<host>/api/auth` issuer the documents belong at
  `/api/auth/.well-known/...`, because API Gateway builds the discovery URL by appending to
  the issuer and `jwks_uri` is advertised the same way. `build_identity_router` now derives
  the prefix from `settings.issuer` and mounts everything under it, `/health` included.

  The Portfolio pilot hit this against 0.9.0: a test that followed the served `jwks_uri`
  found a 404, and the workaround was to mount the router with `prefix="/api/auth"`. **Remove
  that prefix when upgrading**, or every route doubles to `/api/auth/api/auth/...`. A product
  whose issuer has no path is unaffected: it still gets origin paths.

  `AUTH_PREFIX` is gone, replaced by `identity_prefix(settings)`. The `REGISTER_PATH`,
  `LOGIN_PATH`, `PASSWORD_PATH`, `REFRESH_PATH`, `LOGOUT_PATH` and `LOGOUT_ALL_PATH`
  constants are now suffixes relative to that prefix rather than absolute paths.

- **`cookie_path` defaults to the issuer's path** rather than a literal `/api/auth`, so the
  cookie is scoped to exactly the routes that spend it however the issuer is configured. An
  explicitly set `cookie_path` still wins. An issuer with no path scopes the cookie to `/`.

### Added

- `IdentityFlows`, the flow layer, with no FastAPI import anywhere in it. `register`,
  `login`, `change_password`, `refresh`, `logout` and `logout_all` are callable directly,
  which is what lets the flows be tested without a client and reused outside a request.

  `register` returns `None` rather than raising when the address is taken. Deliberately not
  an exception: an exception invites a caller to render it differently from the success
  case, and the whole point is that the two are indistinguishable.

- `SessionService`, the refresh family state machine. Rotation is one conditional write
  returning the prior state, so two concurrent refreshes cannot both succeed, and the six
  outcomes it distinguishes are `rotated`, `replayed`, `reuse`, `expired`, `revoked` and
  `unknown`.

  Reuse inside `refresh_reuse_grace` returns a working successor, because a client that
  raced itself is not an attacker. Reuse outside it revokes the whole family. The window is
  what keeps a flaky network from signing users out, and the revocation is what makes a
  stolen refresh token worth less than one use.

- The six routes under `/api/auth`: `register`, `login`, `password`, `refresh`, `logout`
  and `logout-all`. The access token is returned in the JSON body and never as a cookie;
  the refresh token is an httpOnly Secure SameSite=Lax cookie scoped to `cookie_path`.

  `refresh` and `logout` also check `Sec-Fetch-Site`. A refused cross-site request does
  **not** clear the cookie, which sounds like a missing cleanup and is not: clearing it
  would let any attacker page sign a victim out by provoking one refused request.

- Password policy in `webbpulse.identity.passwords`, NIST SP 800-63B shaped. Eight character
  minimum, no composition rules, no expiry, NFKC normalisation, and a rejection rather than
  a silent truncation over 72 UTF-8 bytes. `equalise_password_timing` spends one bcrypt
  verification on every login path that has no real hash to check, so an unknown address
  costs what a wrong password costs.

  `password_breach_check` remains a flag only. Passing `True` raises rather than quietly
  doing nothing, because a product that switched it on and got no check would believe it had
  a control it does not have.

- Progressive lockout in `webbpulse.identity.lockout`, with `InMemoryLoginAttemptStore` and
  `DynamoLoginAttemptStore`. Five consecutive failures start a delay doubling from one
  second to a fifteen minute cap, cleared by any success. Never a hard lock, because a hard
  lock on a known address is a denial of service anybody can trigger.

- `create_user` on `IdentityHooks`. Section 4.2 gives the `users` table to the product's own
  domain, so the package cannot write that row itself, and without this hook registration
  could hash a password and then have nowhere to put the account.

- `family_started_at` on `RefreshTokenRecord`. The 90 day absolute cap is a property of the
  family rather than of any one token, and without it each rotation would extend the rolling
  30 day window forever. Defaults to empty and falls back to the current token's own start,
  so a rolling deploy does not invalidate live sessions.

### Changed

- `RefreshTokenStore.revoke_all_for_user` takes `except_family_id`. Changing a password
  should revoke every other session and leave the caller signed in, and there was no way to
  express that. Still `NotImplementedError` on DynamoDB: both callers know the family ids
  they are revoking, so they revoke by id through the existing GSI rather than paying for a
  user index on the hot rotation path to serve a cold one.

- Login attempts are stamped to the millisecond and the in-memory store breaks remaining
  ties by insertion order. At one second resolution a failure and the retry that succeeds
  share a timestamp, and if that tie resolved the wrong way the consecutive-failure count
  was never cleared, locking an account that had just signed in correctly.

## 0.9.0

Identity M1: the foundations the flows rest on. `webbpulse.identity` becomes a package with
configuration, the product policy seam, storage interfaces, a token service that handles
rotation, and the claim reader for what the gateway authorizer leaves on the request.

**The flows are deliberately absent.** Login, refresh rotation, MFA, passkeys and OAuth are
M2 and later, per section 9.1 of `docs/identity-standard.md`. The router mounts the two
`.well-known` documents and `/health`, and nothing else.

**Additive for anyone on the M0 slice.** `src/webbpulse/identity.py` became
`src/webbpulse/identity/tokens.py`, and every name that was importable from
`webbpulse.identity` still is. The M0 test module passes unchanged, which is the test of
that claim.

### Added

- `IdentitySettings`, section 6.1 as a validated `BaseSettings` with `IDENTITY_` prefix.
  Safe defaults throughout: `cookie_secure` on, `httponly` not configurable at all, email
  verification required, a ten-minute access token.

  The validation is the point. A plaintext `issuer` is refused outside `local` and `test`; a
  trailing slash is stripped rather than trusted to match by hand in three places, which is
  the classic cause of every request being denied with no useful message; `SameSite=none`
  without `Secure` is refused; an access token TTL over an hour is refused, because a
  long-lived access token cannot be revoked.

- `IdentityHooks`, a `Protocol`, and `BaseIdentityHooks`, a concrete class whose
  unimplemented hooks raise `HookNotImplemented` naming the hook and the class. The product
  decides who may sign in; the package decides how signing in works.

  `may_authenticate` refuses by raising `AuthenticationRefused` rather than returning a
  bool. A hook that forgets to return anything returns `None`, and
  `if hooks.may_authenticate(user)` on a `None` admits the login. Raising has no such pair
  of readings: not raising is the only way to permit, and every mistake lands on the
  refusing side.

- `TokenService`: `mint_access_token`, `verify_access_token`, `jwks()`, `discovery()`, over
  as many keys as are configured.

  Rotation is the whole design. `signing_key_arns` is a list whose head signs and whose
  every element appears in the JWKS, so each step of section 3.5 is a one-line change.
  A token signed by a previous key keeps verifying while that key is listed and stops when
  it is retired, and a `kid` matching no configured key is rejected rather than falling back
  to trying every key, which would quietly undo the retirement.

  A key whose `kms:GetPublicKey` fails is omitted from the JWKS rather than failing it: a
  retired key id left in configuration must not deny every authorized request in the
  product. Every key failing is still fatal, because an empty JWKS would be cached by the
  gateway and deny everything for its whole interval.

  `verify_access_token` is **not** the production path. Behind API Gateway the authorizer
  has already checked the signature, issuer, audience and expiry. It exists for tests and
  for a service that verifies a token itself.

- `authorizer_claims()` and `read_authorizer_claims(request)`, the single parser for what
  the JWT authorizer leaves on the request.

  **Every claim value arrives as a string, `exp` and `iat` included.** That is a verified
  finding from the M0 staging spike, not an inference, and it is why this module exists:
  `exp > time.time()` on a string raises `TypeError`, and `bool("false")` is `True`.
  Integers, booleans, space-separated scopes and the bracketed comma form the gateway emits
  for array claims are all coerced, with the raw map kept on `.raw`.

  Three distinct failures, because they have three different causes: `MissingRequestContext`
  is a deployment fault, `UnparseableRequestContext` is a bug in our own code, and
  `NoClaimsSection` is a routing fault. All three render as one 401 with a fixed message,
  and the specific reason goes to the log rather than to the caller.

  A `local_fallback` is refused **at construction** in a production environment, not on the
  first request. A misconfiguration that only surfaces when an authenticated request
  arrives is one that reaches production and waits.

- Storage interfaces with a DynamoDB and an in-memory implementation each:
  `CredentialStore`, `RefreshTokenStore`, `IdentityTokenStore`, gathered in `IdentityStores`.

  Per-entity tables, not single-table, with the key design in the module docstring. TTL is a
  table-level setting, so mixing an expiring entity with a permanent one means the permanent
  items carry a TTL attribute that must never be set, and one bug silently deletes accounts.

  Only the SHA-256 of a token is stored, so a read of the table cannot be turned into a
  working session. `consume` is one conditional `UpdateItem` returning the prior state, not
  a read followed by a write: two concurrent refreshes both reading an unconsumed record is
  exactly the condition reuse detection exists to notice.

  The in-memory stores ship in the package rather than in the tests, because every consuming
  product would otherwise write one slightly differently, and a store whose expiry semantics
  differ from the real one is a suite that passes on behaviour production does not have.

- `build_identity_router(settings, hooks, stores)`, which a product mounts with no prefix.

  Both `.well-known` documents carry an explicit `Cache-Control`: 300 seconds for the JWKS
  and 3600 for discovery. The asymmetry is deliberate. Rotation moves through the JWKS, and
  a long cache there is what turns the promotion step into an outage.

  `hooks` and `stores` are accepted and held but unused in 0.9.0, so a product's composition
  root is written once rather than gaining an argument at every milestone.

### Changed

- `src/webbpulse/identity.py` is now `src/webbpulse/identity/tokens.py`, and
  `webbpulse.identity` is a package re-exporting the entire M0 surface. No import changes.

### Notes

- No new dependencies. The `identity` extra is unchanged at `PyJWT[crypto]>=2.9` and
  `fastapi>=0.115`; boto3 stays out of it, because the module takes a KMS client rather than
  constructing one.
- moto cannot be used for the KMS signing tests. Against moto 5.2.3, `create_key` and `sign`
  succeed but `get_public_key` returns `KeySpec: None` and the signature does not verify
  against the public key moto itself returns. The tests use a local RSA key behind the same
  `KmsClient` protocol, which differs from KMS only in who holds the private key.

## 0.8.0

Adoption ergonomics. Two services took 0.7.0 (WebbPulse-Portfolio #153, CarModPicker #380)
and between them found one silent failure and two places where the package was strict
enough that a consumer kept a local wrapper rather than delete one. All three are addressed
here.

**Additive. No behaviour changes to anything that does not pass a new argument.** A service
that upgrades and changes nothing gets byte-identical log lines, the same handler on the
same stream, and the same `MetricsEmitter` defaults.

### Added

- `webbpulse.http.user_id_dependency(get_user, *, attribute="id", extract=None)` and
  `webbpulse.http.bind_user_id(user_id)`, for the sync dependency trap.

  `set_user_id` called inside a **sync** (`def`) FastAPI dependency binds nothing the
  handler or any later log line can see. Starlette runs a sync dependency through
  `anyio.to_thread.run_sync`, which copies the context into a worker thread; the dependency
  mutates the copy and the copy is discarded on return. Nothing raises, the request
  succeeds, and `user_id` reads `"-"` for the rest of it. Portfolio shipped that to
  production, and it is the reason the fix is a helper rather than a paragraph.

  ```python
  from webbpulse.http import user_id_dependency

  CurrentUser = user_id_dependency(get_current_user)  # get_current_user may stay `def`


  @router.get("/me")
  async def me(user: User = Depends(CurrentUser)) -> UserRead: ...
  ```

  - `user_id_dependency` returns an `async def` dependency that resolves the service's own
    resolver as a sub-dependency, binds the id in the request's own context, and returns
    the resolved object unchanged. It is a drop-in swap at the call site: the handler
    receives the identical object. The wrapped resolver keeps its own dependencies and may
    be `def` or `async def`.
  - `attribute=` names the id attribute when it is not `.id`; `extract=` takes a callable
    for the case where the id is not a plain attribute at all, such as a claims dict.
  - A resolver returning `None`, the optional-authentication shape, binds nothing and
    leaves the `"-"` placeholder rather than binding the string `"None"`. An object with no
    usable id binds nothing too, rather than failing a request that would have succeeded.
  - `bind_user_id` is the same binding as an awaitable, for a service writing its own async
    wrapper. Being a coroutine is deliberate: the wrong shape leaves an un-awaited
    coroutine, which Python warns about and a suite under `-W error` fails on, so it stops
    being silent. `set_user_id` is unchanged and remains correct in a middleware, a
    `task_context` block or a CLI entry point, where the caller owns the context.

- `webbpulse.logging.configure_logging(stream=..., formatter=...)`, the two escape hatches
  CarModPicker kept a local wrapper module for.

  - `stream=` (default `sys.stdout`) routes **every handler the function installs**. Two
    CarModPicker commands write data on stdout and are compared byte for byte, so a log
    line landing there breaks the comparison; `stream=sys.stderr` gives that stdout back.
    The default is read at call time rather than bound at import, so a runtime that
    replaced `sys.stdout` is honoured.
  - `formatter=` takes `"json"` (the default, byte identical to 0.7.0), `"text"` for a
    human readable line on a TTY, or a `logging.Formatter` instance. An unknown selector
    raises `ValueError` **before** the existing handlers are removed, so a typo cannot
    leave the root logger with nothing attached.
  - `TextFormatter` and `TEXT_LOG_FORMAT` are exported for a service that wants the same
    line under its own wiring. `"text"` drops `service` and `environment` rather than
    rendering them, since locally there is one of each.

- `webbpulse.metrics.metrics_enabled_from_env(environment=None, *, testing_var="TESTING",
  environment_var="ENVIRONMENT", allowed=DEFAULT_METRIC_ENVIRONMENTS)`, returning a bool
  for `enabled=`.

  This is the gate CarModPicker's deleted `core/cloudwatch_emf.py` carried, hoisted so the
  next adopter does not write it again slightly differently: silent while the testing
  variable is truthy, live only in the environments named, which default to staging and
  production. Comparison is case-insensitive after a strip on both sides, since these
  values arrive from Terraform and a task definition. An unset or blank environment returns
  `False`, so a missing variable fails closed to silence rather than to production-
  namespaced noise from an unidentified source.

  `DEFAULT_METRIC_ENVIRONMENTS` is exported as `("staging", "production")`.

  `MetricsEmitter` is untouched: `enabled` is still a constructor argument and still
  defaults to `True`. The helper reads environment variables and returns a bool, so it
  composes with `enabled=` rather than replacing it.

### Changed

- Nothing observable. `configure_logging` still installs one handler, on stdout, with
  `JsonFormatter`, when called the way 0.7.0 callers call it.

## 0.7.0

The two observability primitives CarModPicker grew on its own, hoisted so Portfolio can
have them too: request and correlation context on ContextVars, and CloudWatch metrics as
Embedded Metric Format.

Neither is a new dependency. `webbpulse.log_context` and `webbpulse.metrics` are standard
library only and have no extra, so every consumer gets them on the base install.

**Additive, with one behaviour change to `RequestIdMiddleware` described below.**

### Added

- `webbpulse.log_context`, request and correlation context on two ContextVars:

  ```python
  from webbpulse.log_context import set_user_id, task_context

  set_user_id(user.id)  # in the authentication dependency
  with task_context("crawler", job_id):  # for work outside any request
      run()
  ```

  - `request_id_var` and `user_id_var`, both defaulting to the `"-"` placeholder rather
    than `None`, because a metric filter pattern cannot distinguish a missing key from an
    empty one and a constant placeholder makes "no request scope" visible.
  - `set_request_id(value)` and `set_user_id(value)`, returning the reset token. Values are
    coerced to `str`, stripped of newlines and truncated to 128 characters, since the
    request id can arrive on an inbound `X-Request-ID` and the user id from a token claim.
  - `bind_context(request_id=..., user_id=...)` and `task_context(name, job_id)`, scope
    managers that restore the previous values on exit, including when the block raises, and
    that nest. `task_context` produces `bg:<name>:<job_id or "-">` with `user_id` of
    `"bg"`, which is the exact string CarModPicker's `bg_log_context` emits, so a saved
    Logs Insights query keeps matching. `log_context` is an alias of `task_context`.
  - `current_context()`, the bound values as a dict, omitting anything unset.
  - `LogContextFilter` and `attach_log_context(logger=None)`, for a service keeping its own
    formatter. Unlike the JSON path the filter always sets both attributes so a
    `%(request_id)s` format string does not raise, and it leaves a value passed explicitly
    at the call site alone. `attach_log_context` is idempotent per handler.
  - `set_span_context_attributes()`, copying the same values onto the active OpenTelemetry
    span as `webbpulse.request_id` and `webbpulse.user_id`, the names `webbpulse.http`
    already uses. A no-op without the `otel` extra or without a recording span, and it
    never raises.

- `webbpulse.metrics`, CloudWatch Embedded Metric Format on stdout:

  ```python
  from webbpulse.metrics import emit

  emit(
      namespace="CarModPicker/Crawlers",
      dimensions={"AdapterName": name, "Environment": env, "RunType": "live"},
      metrics={"Ingested": (n, "Count"), "ElapsedSeconds": (elapsed, "Seconds")},
      enabled=settings.environment in {"staging", "production"},
  )
  ```

  - `MetricsEmitter(namespace=..., dimensions=..., properties=..., enabled=..., stream=...)`
    with `set_dimensions`, `set_properties`, `put`, `document` and `flush`, usable as a
    context manager that flushes on exit including on an exception.
  - `emit(...)`, the one-shot form, and `timed(emitter, name, unit=...)`, which records a
    `perf_counter` duration and does so in a `finally` so a block that raised still reports
    how long it ran.
  - `UNITS` and `EMF_MAX_DIMENSIONS`.
  - `namespace` is required and never defaulted, so no service can inherit a shared
    namespace by accident.

### Changed

- `webbpulse.logging.JsonFormatter` merges the bound `log_context` values into every record
  it formats. A service calling `configure_logging` therefore gets `request_id` and
  `user_id` as top-level keys with no filter to attach. The merge fills gaps only, so an
  explicit `extra={"request_id": ...}` at a call site still wins.
- `webbpulse.http.RequestIdMiddleware` binds `request_id_var` for the life of the request
  in addition to setting `request.state` and echoing the header, and resets it in a
  `finally`. This is the one behaviour change in the release: an existing consumer's log
  lines start carrying `request_id` where they did not before. Nothing that read the id
  before reads it differently.

### Why the EMF document is written directly

`aws-embedded-metrics` was the obvious dependency and is not used, for two reasons that
both present as metrics silently not appearing:

- **Its sink auto-detection is wrong in this estate.** It falls back to a CloudWatch Agent
  sink over TCP when it cannot positively identify the runtime, and that agent exists on
  none of Lambda, ECS Fargate or App Runner. The documented fix is setting
  `AWS_EMF_ENVIRONMENT=Local` in every function and task definition, which is a thing to
  remember forever in Terraform. Writing to stdout unconditionally removes the setting and
  the failure mode together.
- **Its flush is asynchronous and can lose the last record a process emits.** CarModPicker
  worked around that by ordering an unrelated summary log line after the emission and
  pinning that ordering with a static-analysis test. `flush` here writes and flushes the
  stream synchronously before returning, so there is nothing to order and the test can go.

The wire format is AWS's, not the library's, and is unchanged: a document this module
writes and a document the library writes are the same document.

### Cardinality, which is the part that costs money

CloudWatch bills per distinct combination of namespace, metric name and dimension values,
so a dimension carrying a user id, a request id or a URL mints a billable metric per user,
per request or per URL. `set_dimensions` refuses more than nine, the documented ceiling,
and refuses a blank value, which would void the whole document and take every metric in it.
Unbounded values belong in `properties`: written into the log event, queryable in Logs
Insights, and creating no metric at all.

### Adoption

CarModPicker deletes `core/log_context.py` and swaps the imports across eight files.
`core/cloudwatch_emf.py` is a straight deletion rather than a swap: it has no call site
left, since the crawler tree `emit_crawler_run_metrics` served did not survive the
DynamoDB and Lambda migration, and CarModPicker's own split plan already lists it as dead
code. That deletion also drops `aws-embedded-metrics` from both requirements files and
lets `AWS_EMF_ENVIRONMENT=Local` come out of the Terraform. The old document's shape is
reproduced exactly by `emit` and pinned by a test here, so a restored crawler would keep
plan 02-05's alarm matching. Portfolio has neither primitive today, so both are new
capability there. The README's per-app migration notes carry the file-by-file detail.

## 0.6.0

The M0 slice of the identity standard (`docs/identity-standard.md`): enough of
`webbpulse.identity` to prove that an API Gateway HTTP API JWT authorizer verifies a token
this package signed with a real KMS key, against a JWKS this package served.

Deliberately not the whole standard. There is no user model, no password flow, no session,
no refresh rotation and no storage of any kind. Those land in 0.7.0 and later per section
9.1. What is here is the part every later milestone rests on, which is why it is proven
first.

**Additive. Nothing existing changes, and no module gains a dependency.**

### Added

- `webbpulse.identity`, behind a new `identity` extra (`PyJWT[crypto]`, `fastapi`):

  ```python
  from webbpulse.identity import KmsSigner, identity_router, public_jwk_from_kms

  signer = KmsSigner(kms_client, key_id)
  jwk = public_jwk_from_kms(kms_client, key_id)  # cache per execution environment
  app.include_router(identity_router(issuer=issuer, jwks=lambda: [jwk]))
  ```

- `KmsSigner(client, key_id)`, with `.kid`, `.sign(signing_input)` and
  `.encode(claims)`. Signs through `kms:Sign` with `MessageType="DIGEST"` and
  `SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256"`, so no key material is ever held.
- `public_jwk_from_kms(client, key_id)`, an RSA JWK with `kid` = base64url SHA-256 of the
  DER SubjectPublicKeyInfo. Refuses a key whose `KeySpec` is not `RSA_2048`.
- `kid_for_der(der_spki)`, the same derivation without a KMS client, for a verifier holding
  only the public key.
- `build_jwks(jwks)` and `build_discovery_document(issuer)`, the two document bodies. The
  issuer's trailing slash is normalised away in one place rather than at three call sites.
- `identity_router(issuer=..., jwks=...)`, serving `GET /.well-known/jwks.json` and
  `GET /.well-known/openid-configuration` at the origin. `jwks` is a callable so the caller
  owns the caching and a rotation changes the document without rebuilding the router.
- `mint_test_token(...)`, gated behind an explicit `enabled` argument **and** a refusal on
  `environment` of `production`. Raises `TokenMintingDisabled`.
- `JWS_ALGORITHM`, `KMS_SIGNING_ALGORITHM`, `DIGEST_MESSAGE_TYPE`, `KMS_KEY_SPEC`.

### The AWS behaviour this is built on, with the documentation it came from

- **Only RSA algorithms.** The HTTP API JWT authorizer's token validation workflow says
  "Check the token's algorithm and signature by using the public key that is fetched from
  the issuer's `jwks_uri`. Currently, only RSA-based algorithms are supported." That is what
  forces RS256 over the standard's preferred ES256, and it is not a preference this package
  can revisit while the built-in authorizer does the verifying.
- **PKCS1 v1.5, not PSS.** The KMS `Sign` documentation prefers PSS for RSA in general, but
  JWA binds `RS256` to PKCS1 v1.5 and `PS256` to PSS. Signing with PSS under an `RS256`
  header produces a token nothing verifies, and the failure is a 401 with no explanation.
- **`DIGEST` skips only the hashing.** "When the value is `DIGEST`, AWS KMS skips the
  hashing step in the signing algorithm." The padding still applies, so the algorithm name
  is unchanged.
- **The RSA signature needs no reshaping.** "When used with the supported RSA signing
  algorithms, the encoding of this value is defined by PKCS #1 in RFC 8017", which is the
  octet string JWS wants. ECDSA would have needed the DER-to-r||s conversion.
- **The key is cached for two hours.** "API Gateway can cache the public key for two hours.
  As a best practice, when you rotate keys, allow a grace period during which both the old
  and new keys are valid." The standard's three hour overlap is that grace period.

### What is still unproven, and where it gets settled

The standard's section 3.4 records that AWS does not document whether the authorizer
resolves `<issuer>/.well-known/openid-configuration` and follows its `jwks_uri`, or fetches
a JWKS from the issuer directly. Re-reading both the developer guide and the `JWTConfiguration`
API reference for 0.6.0 did not settle it: the guide says only "the issuer's `jwks_uri`",
and the API reference describes `issuer` as "The base domain of the identity provider that
issues JSON Web Tokens" with no mention of `.well-known` at all. This release is written so
either behaviour works, serving both documents at the origin, and the Portfolio staging
spike is what answers it empirically.

`moto`'s fidelity for `kms:Sign` with `RSASSA_PKCS1_V1_5_SHA_256` is also still unconfirmed
(section 9.4), so the unit suite does not use it for signing. `tests/test_identity.py` fakes
the client with a real `cryptography` PKCS1 v1.5 signature over the digest, which is the
documented KMS contract, and then verifies the resulting token with PyJWT using **only** the
JWK this module emitted. That is what proves the JWK encoding: a wrong `n`, a wrong `e`, a
`kid` mismatch or a differently assembled signing input all fail it. The signing seam stays
fakeable exactly so the moto question never has to be answered.

### Naming

`TokenMintingDisabled`, not `TestTokenDisabled`. pytest collects any class whose name starts
with `Test`, so the more natural name makes a consumer's suite fail at collection with
`PytestCollectionWarning: cannot collect test class`. Renaming the exception once here is
cheaper than every consumer adding a `python_classes` override.

## 0.5.0

Both backends carried a near-identical `security.py`: bcrypt password hashing plus JWT
sign and verify. The README said there would be no shared auth module, on the grounds that
the two apps used `python-jose` against PyJWT and bcrypt 4.3.0 against 5.0.0, and that
merging them would change how existing hashes verify. Half of that turned out to be true
and half of it did not, so this release shares the half that is genuinely common and leaves
the half that is not.

**No stored hash changes and no issued token is invalidated.** Adoption is a drop-in.

### Added

- `webbpulse.security`, behind a new `security` extra (`PyJWT`, `bcrypt`):

  ```python
  from webbpulse.security import hash_password, verify_password, create_token, decode_token

  hashed = hash_password(password)
  if verify_password(password, user.hashed_password):
      token = create_token({"sub": user.username}, secret, expires_in=timedelta(minutes=30))

  claims = decode_token(token, secret)  # raises ExpiredToken / InvalidToken
  ```

- `hash_password(password, *, rounds=12)` and `verify_password(password, hashed)`.
- `needs_rehash(hashed, *, rounds=12)`, for upgrading a hash's cost on the next successful
  login, which is the only moment the plaintext is available to re-hash.
- `create_token(claims, secret, *, expires_in=None, algorithm="HS256", issuer=None,
  audience=None, now=None)` and `decode_token(token, secret, *, algorithms=None,
  issuer=None, audience=None, require=None, leeway=0)`.
- `bearer_claims(secret, *, ..., auto_error=True)`, an optional FastAPI dependency returning
  the decoded claims. It needs the `fastapi` extra, and the rest of the module does not.
- `TokenError` and its subclasses `ExpiredToken` and `InvalidToken`.
- `BCRYPT_MAX_BYTES`, `DEFAULT_ROUNDS` and `DEFAULT_ALGORITHM`.

### The two claims in the 0.4.0 README, checked

- **The rounds did not actually differ.** bcrypt's default cost is 12 on both 4.3.0 and
  5.0.0, and CarModPicker passes `rounds=12` explicitly, so both apps have been writing cost
  12 hashes all along. `DEFAULT_ROUNDS` is 12 and every existing hash verifies unchanged.
- **The 72 byte handling really did differ, and it is a live bug.** bcrypt 4.x silently
  truncates a password over 72 bytes; bcrypt 5.0 raises `ValueError`. Portfolio truncates to
  `[:72]` by hand, so it is safe on either. CarModPicker does not, and it is pinned to
  bcrypt 5.0.0, so **a password longer than 72 bytes is currently a 500 rather than a
  login** on both signup and password reset. This module truncates internally, so it behaves
  the same on 4.x and 5.x and that failure goes away on adoption.
- Hashes are mutually verifiable across bcrypt 4.3.0 and 5.0.0, verified both directions.

### Behaviour

- Truncation is on a **byte** boundary, not a character boundary, matching what both apps
  and bcrypt itself already do. Trimming back to the last whole UTF-8 character would feed
  bcrypt different bytes and disagree with every existing hash.
- `verify_password` returns `False` rather than raising for a `None` or empty stored hash
  (an OAuth-only account has no password) and for a corrupt one. A bad stored value is a
  failed login, not a 500. It is deliberately not constant time across the "no hash" case;
  a service wanting that should verify against a fixed dummy hash, as CarModPicker's
  `_DUMMY_HASH` already does, since that decision is bound up with its user lookup.
- `needs_rehash` returns `True` only for a **lower** cost. A hash written at a higher cost
  is left alone rather than re-hashed down, which would weaken accounts a previous, more
  cautious setting had protected. An unparseable hash returns `True`.
- `decode_token` always passes an explicit `algorithms` list and never reads `alg` from the
  token header, which is what refuses both `alg: none` and the RS256-verified-as-an-HMAC
  confusion. `issuer` and `audience`, when given, are verified rather than merely returned.
- `InvalidToken`'s message does not say which check failed. Telling a caller whether the
  signature or the audience was wrong narrows the search for a forgery; the reason stays on
  the exception chain for the log.
- `bearer_claims` raises `HTTPException(401)` with a mapping detail, so
  `register_error_handlers` renders it in **the package's existing envelope**. No new error
  shape is introduced. The `error_code` is `TOKEN_EXPIRED` or `INVALID_TOKEN`, carried on
  the raise so the distinction survives whether or not the app sets `error_codes=True`, and
  the 401 carries `WWW-Authenticate: Bearer`.

### Notes

- **PyJWT, not python-jose.** `python-jose` is effectively unmaintained and validates less
  by default. An HS256 token is interchangeable between the two libraries, verified both
  directions, so Portfolio switching invalidates no already-issued session.
- The module imports on the base install and imports `bcrypt` and `jwt` inside the
  functions, so a consumer that only wants the JWT half never needs bcrypt present.
  `bearer_claims` is the only part needing the `fastapi` extra.
- Nothing about a user, a role, an admin or a `sub` convention is in this module. Those are
  what actually differ between the two apps, and guessing at them here would force a fork.

## 0.4.0

CarModPicker's repository layer translates a conditional check failure into its own
exception class before anything else sees it, so the 0.3.0 botocore handlers never fired for
it and the service kept three thin handlers of its own built on `error_body`. This release
lets the caller hand those types to the package instead. **The new parameter defaults to
`None` and every 0.3.0 body is unchanged when it is omitted.**

### Added

- `exception_map` on `install_dynamodb_handlers`, on the `dynamodb` path of
  `register_error_handlers`, and on `create_app`. It maps the service's own exception types
  onto statuses, so a repository layer that raises `ItemNotFound` rather than letting a
  botocore `ClientError` escape needs no handlers of its own:

  ```python
  app = create_app(
      [posts_router],
      dynamodb_handlers=True,
      exception_map={ItemNotFound: 404, ConditionFailed: 409, TransactionCanceled: 409},
  )
  ```

- `ErrorSpec(status, message=None, error_code=None, retry_after=None)`, the longer form of a
  mapping value for when the default message, the code or a `Retry-After` needs saying
  explicitly. A bare int status is shorthand for `ErrorSpec(status)`. Exported as
  `webbpulse.http.ErrorSpec`.
- `ExceptionMap`, the type alias for what `exception_map` accepts, so a consumer can annotate
  its own mapping constant.

### Behaviour

- The rendered envelope is the one `error_body` already builds, so a consumer dropping its
  own handlers sees byte identical responses. `error_code` appears only when
  `error_codes=True`, including a code an `ErrorSpec` names: the spec chooses which code, not
  whether there is one.
- A `message` the spec does not give defaults to the wording already used for that status.
  The 409 and 503 wordings are the ones the botocore branches send, so a caller-supplied
  `ConditionFailed` reads exactly like a `ConditionalCheckFailedException`.
- A mapped status of 500 or above never echoes its `message`. It logs at error with a stack
  trace and returns the generic "Internal server error.", because a message written for an
  internal exception is not written for a stranger. A mapped 4xx logs at warning instead,
  since a lost race is the ordinary outcome and not a page.
- Every mapped handler logs with the request id and the exception type name, matching the
  botocore branches, and no branch puts the exception's own text in the response body.
- The mapping is validated when the app is built, not when a request arrives. A key that is
  not an exception class raises `TypeError`, a value that is neither an int nor an
  `ErrorSpec` raises `TypeError`, and a status outside 100 to 599 raises `ValueError`. A
  wiring mistake should surface at import rather than as a 500 under load.
- Passing `exception_map` without `dynamodb=True` installs only these handlers and imports no
  botocore, so a service with no DynamoDB at all can use it on the base install. The mapping
  is also validated before the botocore import on the `dynamodb=True` path, so a bad mapping
  is a `TypeError` and not a confusing `ImportError` from a missing extra.
- `Retry-After` on the DynamoDB throttling branch is unchanged, and `ErrorSpec.retry_after`
  is how a mapped type asks for the same header.

## 0.3.0

The org standardises on the `{success, status, message, request_id}` envelope for every
backend. This release makes that envelope carry what the other services needed, so they can
adopt it without forking the handlers. **Every addition is opt in and the default body is
byte identical to 0.2.0**, so an existing caller upgrades with no change.

### Added

- `error_body(status_code, message, request, *, error_code=None, details=None, **extra)`, the
  envelope builder, now public. The four base fields are always present and in the same
  order; `error_code` and `details` are omitted entirely when unset. Exported as
  `webbpulse.http.error_body`.
- `register_error_handlers` takes `error_codes`, `validation_details`,
  `validation_error_code` and `dynamodb` keyword arguments, all defaulting to off.
  `error_codes=True` adds a stable `error_code` per status (`NOT_FOUND`, `CONFLICT`,
  `INTERNAL_ERROR` and so on); `validation_details=True` adds `details` to the 422 body as a
  list of `{"field", "message", "type"}` entries, with the field path flattened to a dotted
  string and the `query`/`body` prefix dropped. The 0.2.0 `errors` key stays exactly as it
  was alongside it, because dropping it would break a reader.
- `create_app` takes the matching `error_codes`, `validation_details` and
  `dynamodb_handlers` keyword arguments and passes them through.
- A route can set a per-response code without turning any option on, by raising an
  `HTTPException` whose `detail` is a mapping carrying `message` and optionally `error_code`
  and `details`. A mapping detail that has no usable `message` renders the generic
  "Request failed." rather than being echoed, so an internal dict cannot leak.
- `install_dynamodb_handlers(app, *, error_codes=False)` maps botocore `ClientError` raised
  by DynamoDB onto the envelope. `ConditionalCheckFailedException` is a **409**, not a 500,
  because a failed condition means someone else got there first and that is a caller visible
  conflict. `ProvisionedThroughputExceededException`, `ThrottlingException` and
  `RequestLimitExceeded` are a **503** with `Retry-After`, because they are transient and a
  500 tells a client not to bother retrying. `ResourceNotFoundException` is a **500** logged
  at error, never a 404: a missing table is a deployment fault, and a 404 would send an
  operator hunting for a missing record instead. `TransactionCanceledException` is inspected
  rather than assumed, and is a 409 when any entry in `CancellationReasons` is
  `ConditionalCheckFailed` and a 500 otherwise. Every branch logs with the request id and
  the AWS error code, and no branch puts AWS text in the response body.
- `DYNAMODB_RETRY_AFTER_SECONDS`, the value sent on a throttling 503. Deliberately short,
  since on-demand capacity recovers in seconds and a long value turns a brief spike into a
  long outage.
- Starlette's raw routing errors now render the envelope. An unmatched route and a wrong
  method previously fell through as `{"detail": "Not Found"}`, a different shape from every
  handled error in the same API, which is what CarModPicker was leaking to its frontend.

### Notes

- The DynamoDB handlers are opt in and import botocore lazily, inside the function, so the
  base install still needs no boto3. Install the existing `dynamodb` extra to use them. This
  is verified against a genuinely boto3-free install, not just a mocked one.
- No `dynamodb` extra was added, because the package already had one covering
  `webbpulse.config` secret loading, `webbpulse.dynamodb` and `webbpulse.ratelimit`. The new
  handlers ride on it rather than duplicating it.

## 0.2.0

### Added

- `webbpulse.otel` now tail samples, so **errors are always kept** whatever the ratio says.
  A head sampler decides when the root span starts, before the request has been handled, so
  it cannot know that a request is about to fail; a ratio of 0.1 therefore discards 90
  percent of the failures too. Every span is now recorded, buffered per trace, and judged
  once at flush time: a trace is exported if any span in it carries `StatusCode.ERROR` or an
  `exception` event, or if its trace id falls below the configured probability.
- `TailSamplingSpanProcessor`, the processor that does it. It wraps the exporter rather than
  sitting beside one, so it is the export path; do not register a `BatchSpanProcessor` for
  the same exporter alongside it.
- `configure_tracing` takes `sample_ratio`, `always_sample_errors`, `max_spans_per_trace`,
  `on_overflow`, `max_buffered_traces`, `max_trace_age_seconds` and `export_timeout_millis`
  keyword arguments. All have defaults, so existing call sites are unaffected.
- `WEBBPULSE_OTEL_SAMPLE_RATIO` sets the ratio from the environment, which is how Terraform
  sets 1.0 on staging and 0.1 on production without a code change. It falls back to
  `OTEL_TRACES_SAMPLER_ARG`, but only when `OTEL_TRACES_SAMPLER` is `traceidratio` or
  `parentbased_traceidratio`, and then to 1.0. An unparseable or out-of-range value warns and
  is skipped rather than raising, so a typo costs money instead of availability.
- `flush_tracing()`, which resolves the buffered traces and exports the kept ones. This is
  where the tail decision is made, so a Lambda invocation has to reach it before the
  execution environment is frozen. `shutdown_tracing()` flushes too.
- `instrument_fastapi` now wraps the instrumented app in an ASGI middleware that flushes once
  the request is complete, which is the only point that works under the Lambda Web Adapter:
  the invocation ends when the HTTP response completes and the sandbox freezes immediately,
  so a background task or `atexit` hook is caught mid-flight. It wraps from the outside
  rather than being added with `add_middleware`, because `FastAPIInstrumentor.instrument_app`
  makes `OpenTelemetryMiddleware` outermost and an inner flush would run before the server
  span had ended, exporting the previous request's trace and leaving the current one
  buffered. On by default when `AWS_LAMBDA_FUNCTION_NAME` is set, off otherwise, and
  `flush_per_request` decides explicitly. The flush runs on a worker thread rather than the
  event loop, since it exports synchronously over HTTP and awaiting it inline stalls every
  other connection the process is serving. It never raises into the request; a failure is
  logged at WARNING and the response is returned unchanged.
- `TailSamplingSpanProcessor` counts open spans per trace and `force_flush` resolves only the
  traces with none left, so a concurrent request's flush can no longer judge a half-built
  trace and split it across two decisions. `shutdown` still resolves everything, since there
  is no later flush to defer to.
- `max_buffered_traces` (default 1024) and `max_trace_age_seconds` (default 300) bound the
  buffer in count and in age. Eviction judges the trace rather than discarding it, so an
  error trace still exports, and `evicted_traces` counts it. The count bound only evicts
  traces with no spans still open, since judging an in-flight trace early is the bug the
  open-span tracking exists to prevent; the age bound will evict an in-flight trace, which is
  the deliberate exception. It has to be: a leaked span or an abandoned request never
  completes, so the count bound alone can be pinned indefinitely by traces it refuses to
  touch, and under Lambda nothing else ever reclaims them. A trace open for five minutes is
  not a request in progress.
- An `aws-otel` extra, `pip install "webbpulse[otel,aws-otel]"`, bringing
  `aws-opentelemetry-distro` and `botocore`. `configure_tracing` now builds the exporter
  itself: `OTLPAwsSpanExporter` when the resolved endpoint is the X-Ray OTLP one, so requests
  are signed with SigV4, and a plain `OTLPSpanExporter` for anything else. Only the exporter
  class is taken from the distribution; its configurator and `opentelemetry-instrument` entry
  point are not used. Without the extra it warns, naming the extra, and falls back to the
  unsigned exporter.
- `resolve_sample_ratio()` and the `SAMPLE_RATIO_ENV` constant are public, for a service that
  wants to log or assert on the ratio it resolved.

### Changed

- `configure_tracing` now passes an explicit `ParentBased(root=ALWAYS_ON)` sampler to the
  `TracerProvider` instead of letting the SDK pick one. `TracerProvider.__init__` falls back
  to `sampling._get_from_env_or_default()`, which reads `OTEL_TRACES_SAMPLER`; leaving that
  fallback in place would let a ratio sampler in the environment, or one installed by the
  ADOT configurator, pre-drop spans before the tail step ever saw them and silently defeat
  "errors are always sampled". Spans arriving with a sampled-out decision from an upstream
  service are still honoured, because the root sampler only applies to locally started traces.
- `configure_tracing` registers `TailSamplingSpanProcessor` where it previously registered a
  `BatchSpanProcessor`. Nothing is exported until a flush, which is a behaviour change for
  any caller that relied on the batch processor's own timer.
- The tracing pipeline is now built entirely in process. There is no collector, no sidecar,
  no Lambda extension, and nothing runs under `opentelemetry-instrument`. That last one is
  the point: an auto-instrumentation configurator calls `set_tracer_provider` itself, and the
  global provider is set-once per process, so whichever of it and `configure_tracing` ran
  first would win and the other would be silently ignored, leaving either no tail sampling or
  no signed exporter with nothing in the logs to say which.

### Fixed

- Overflow markers are cleared only for traces that have fully completed. Clearing them for a
  still-open trace let its remaining spans start buffering again and be judged a second time,
  so a "keep" could become a "drop" and, under `on_overflow="drop"`, fragments of an already
  dropped trace could still be exported.
- Spans are handed to the exporter outside the processor lock. Exporting under it made every
  `on_end` in the process block on the X-Ray HTTP round trip.
- X-Ray endpoint detection matches `xray.<region>.amazonaws.com`, the FIPS form
  `xray-fips.<region>.amazonaws.com` and the interface VPC endpoint form
  `<vpce-id>.xray.<region>.vpce.amazonaws.com` explicitly, and derives the signing region
  from each. The previous substring test on `.amazonaws.com/v1/traces` matched any AWS-hosted
  OTLP endpoint, and the VPC endpoint form was signed for `AWS_REGION` instead of its own
  region, which fails as a credential scope mismatch. The FIPS endpoint is the one a caller
  under a FIPS mandate cannot simply switch away from, and it was silently getting an
  unsigned exporter and a 403.
- `flush_timeout_millis` now bounds the export. It is passed to the exporter as its `timeout`
  (in seconds, floored at 1), which is a deadline across the whole export including its
  retries. Previously it was only forwarded to `force_flush`, which is a no-op on the OTLP
  exporter, so the exporter kept its own 10 second default and the value bounded nothing: a
  slow or unreachable endpoint could hold a request open far past the configured timeout.
- An overflowed trace's marker is discarded once its last span ends. `force_flush` only walks
  the buffers, and an overflowed trace has no buffer entry, so its marker was never reachable
  and the marker sets grew without bound, uncapped by `max_buffered_traces`. Under
  `on_overflow="drop"` a later trace reusing the id would also have been dropped in silence.
- `instrument_fastapi` is idempotent with respect to the flush wrapper, so calling it twice
  no longer nests two flush layers and flushes twice per request.
- `instrument_fastapi` logs a WARNING when called on an application whose middleware stack is
  already built. `FastAPIInstrumentor` cannot inject the server span middleware into a built
  stack, so the app looks instrumented and emits no spans at all, which is harder to diagnose
  than not instrumenting it.

### Notes for consumers

The environment variable contract shrank to one optional variable,
`WEBBPULSE_OTEL_SAMPLE_RATIO`. `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL`, `OTEL_PYTHON_DISTRO`,
`OTEL_PYTHON_CONFIGURATOR` and `OTEL_TRACES_SAMPLER` are no longer needed and can be removed
from function environments: the protocol is implicit in the exporter class, the distribution
is used as a library rather than a launcher, and the sampler is passed explicitly.

Install with the `aws-otel` extra wherever the X-Ray endpoint is the target, and call
`instrument_fastapi(app)` so the per-request flush is wired. See the README's
`webbpulse.otel` section.

## 0.1.0

- First release: `config`, `logging`, `otel`, `http`, `dynamodb`, `ratelimit`,
  `lambda_entry` and `testing`.
