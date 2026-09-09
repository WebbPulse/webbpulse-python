# Changelog

Notable changes to the `webbpulse` package. The version here is the one in
`src/webbpulse/_version.py`, and a release is that edit plus the matching `v<version>` tag.

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
  jwk = public_jwk_from_kms(kms_client, key_id)   # cache per execution environment
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
