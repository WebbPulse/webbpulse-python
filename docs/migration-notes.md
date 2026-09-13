# Per-app migration notes

What each consuming app replaced when it adopted this package, and what stayed behind. CI and
release mechanics are in [releases.md](releases.md). Back to the [README](../README.md).

## Per-app migration notes

Both backends grew these concerns independently, so the migration is mostly deletion. What
follows is what each app replaces, and what has to stay.

## CarModPicker

`backend/app/`. The app factory in `main.py` configures root logging inline, calls
`init_sentry()` before building the `FastAPI` object, then adds CORS, two
`@app.middleware("http")` functions and the error handlers.

| Shared module | Replaces |
| --- | --- |
| `config` | the pydantic-settings base and `.env` wiring in `core/config.py`, and the CORS origin parsing. The app's own fields become a subclass |
| `logging` | `core/logging.py` and the inline `logging.basicConfig` block in `main.py` |
| `log_context` | `core/log_context.py` in full: both ContextVars, `RequestContextFilter` and `bg_log_context` |
| `metrics` | `core/cloudwatch_emf.py` in full, and the `aws-embedded-metrics` dependency with it |
| `otel` | `core/sentry.py` in full, and its call from `main.py` |
| `http` | `api/utils/response_patterns.py`, `api/middleware/error_handler.py`, `api/middleware/request_context.py`, and the CORS block in `main.py` |
| `ratelimit` | `api/middleware/rate_limiter.py` in full, including `RateLimitConfig` and the eight `RATE_LIMIT_*` settings fields |
| `dynamodb` | `db/dynamo/client.py`, `serialization.py`, `errors.py`, and the generic body of `repository.py` |
| `security` | the password and JWT halves of `api/dependencies/auth.py`: `verify_password`, `get_password_hash`, `create_access_token` and the raw `jwt.decode` calls repeated across `endpoints/auth/core.py`. The user lookup, the `disabled` and `email_verified` checks and the admin dependencies stay |
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
`category_inference.py`, the SES templates, `db/dynamo/search.py`,
`authorization.py`, the `chrome-extension://` CORS regex and the `null` origin, the
`X-Admin-Cron-Key` header, the `RUN_STARTUP_TASKS` seeding, and the sitemap routes. The
CORS regex and extra header mean `create_app` gets `cors_allow_origins` explicitly and the
app adds its own regex, rather than passing `settings` alone.

## WebbPulse-Portfolio

`backend/app/`. Smaller and closer to the shared shape already, but with no error envelope
and no request id at all.

| Shared module | Replaces |
| --- | --- |
| `config` | the `SECRET_FIELDS` / `resolve_secrets` validator, `LOCALHOST_ORIGINS` and `parse_cors_origins` in `config.py` |
| `logging` | `core/logging.py`, `RequestLoggingMiddleware` in `core/middleware.py`, and the `POWERTOOLS_*` settings |
| `log_context` | nothing. Portfolio has no request id or correlation context at all, so this is new capability |
| `metrics` | nothing. Portfolio emits no custom metrics today; this is what it would use when it starts |
| `otel` | the Powertools `inject_lambda_context` correlation wrapper |
| `http` | `TrailingSlashMiddleware`, the CORS block and the `/health` route in `main.py`. The error envelope and request id are new capability, not a replacement |
| `ratelimit` | `core/login_limiter.py` in full, including its `client_ip()` |
| `dynamodb` | `db/client.py` and `db/serializer.py` verbatim, the generic `Repository` base, and `table_name()` |
| `security` | the password and JWT halves of `core/security.py`: `_encode`, `verify_password`, `get_password_hash`, `create_access_token` and `verify_token`. `get_current_user` and `require_admin` stay, rebuilt on `bearer_claims` |
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

## Adopting `log_context` and `metrics`

Both are additive, so each can land on its own without touching the other or anything
already migrated.

**CarModPicker** is an import swap and one deletion each.

- `core/log_context.py` is deleted. The three call sites that import from it,
  `api/dependencies/auth.py`, `api/middleware/request_context.py` and `core/sentry.py`,
  import from `webbpulse.log_context` instead. `RequestContextFilter` becomes
  `LogContextFilter` and `bg_log_context` becomes `task_context`, which is the same
  contract under a name that is not abbreviated; both emit the identical
  `bg:<task>:<job>` string, so no saved Logs Insights query changes. `tests/conftest.py`'s
  `caplog_with_context` fixture and `tests/test_log_propagation.py` follow the same
  rename. `core/logging.py`'s `_attach_request_context` becomes a call to
  `attach_log_context()`.
- `api/middleware/request_context.py` can go entirely once `RequestIdMiddleware` is
  mounted, since that middleware now sets `request.state` and binds the ContextVar and
  echoes the header, which is everything the local one did. Until then the local
  middleware keeps working: it sets the same ContextVar under the same name.
- `core/logging.py`'s local `configure_logging` wrapper can go as of 0.8.0. It existed for
  two reasons and both are now arguments: `stream=sys.stderr` for the commands whose stdout
  is data and is compared byte for byte, and `formatter="text"` for a readable line on a
  TTY. The deployed call passes neither and is byte identical to what it emits today.
- `core/cloudwatch_emf.py` is a straight deletion, not a swap. It has no call site left:
  `emit_crawler_run_metrics` served a crawler tree that the DynamoDB and Lambda migration
  removed, which CarModPicker's own `docs/migration/split-plan.md` already lists as dead
  code to delete on the way through. Deleting it drops `aws-embedded-metrics` from
  `requirements.txt` and `requirements-lambda.txt` and lets `AWS_EMF_ENVIRONMENT=Local`
  come out of the Terraform, since there is no sink to auto-detect any more.
- `webbpulse.metrics` is then what CarModPicker uses for its *next* metric rather than a
  replacement for a current one. The shape is preserved regardless: `emit` with a
  `namespace`, three `Count` and `Seconds` metrics and `AdapterName`/`Environment`/`RunType`
  dimensions reproduces the old document byte for byte, so a restored crawler would keep
  plan 02-05's alarm matching. That equivalence is pinned by a test in this package.
- The gate that module carried, silent unless `TESTING` is not `"true"` and the environment
  is staging or production, is `metrics_enabled_from_env` as of 0.8.0 rather than something
  to reimplement at the next call site.

**WebbPulse-Portfolio** gains capability rather than replacing any.

- It has no request id today. Mounting `RequestIdMiddleware`, which the `http` migration
  already brings, is what starts populating `request_id` on every log line, with no other
  change.
- Its logger is `aws_lambda_powertools.Logger`, whose `inject_lambda_context` correlation
  wrapper does not run under the Web Adapter, since there is no handler to decorate. That
  is the gap `log_context` fills, and it is why the Powertools dependency can go at the
  same time as `core/logging.py`.
- Its `get_current_user` is a `def` dependency, so the `set_user_id` call in it binds
  nothing. That is the trap above, and the fix is to wrap it once at the call site with
  `user_id_dependency`; the resolver itself does not have to change and can stay `def`.
- It emits no custom metrics. `webbpulse.metrics` is what it uses when it starts, with its
  own namespace; nothing has to change for the adoption itself.

## Not shared, deliberately

The **primitives** of authentication are shared as of 0.5.0, in `webbpulse.security`. Up to
0.4.0 they were not, on the grounds that the two apps disagreed on JWT library, bcrypt major
version, 72 byte truncation and default rounds. Checking that reasoning found half of it
wrong: the default cost is 12 on both bcrypt 4.3.0 and 5.0.0, and CarModPicker passes 12
explicitly, so no stored hash changes. The truncation difference was real, and was already a
live 500 in CarModPicker rather than a reason to keep two copies. Hashes verify across both
bcrypt majors and HS256 tokens across both JWT libraries, both verified in the test suite.

What stays per-app is the **policy** above those primitives, and it is most of the file in
each case: which claim carries the identity, the user lookup behind it, whether an inactive
or unverified account may authenticate, the admin and superuser checks, the per-user session
expiry clamp, the constant-time `_DUMMY_HASH` equaliser, and every OAuth, WebAuthn and TOTP
flow. `decode_token` returns the claims and stops; the rest is the service's.
