# Changelog

Notable changes to the `webbpulse` package. The version here is the one in
`src/webbpulse/_version.py`, and a release is that edit plus the matching `v<version>` tag.

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
