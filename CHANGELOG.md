# Changelog

Notable changes to the `webbpulse` package. The version here is the one in
`src/webbpulse/_version.py`, and a release is that edit plus the matching `v<version>` tag.

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### `e2e`: sessions refresh their access token

`IdentitySession` logged in once and carried that access token for the whole run. The
identity access token's TTL is ten minutes by default and a full suite runs well past it on
one worker, so every call after the tenth minute was answered `{"message": "Forbidden"}` by
the gateway authorizer or 401 by the app. That included the fixtures that create the
resources a case then asserts on, so the failures read as product bugs in whichever cases
happened to run late.

The session now owns the token rather than the client. `user_session.client` asks it for a
credential on every request, and it refreshes through `DEFAULT_REFRESH_PATH` when the current
token is within `refresh_skew` seconds of the `exp` it declares, 60 by default. The `exp` is
read by decoding the payload without verification, the same way `decode_claims` reads the
rest; a token carrying no readable `exp` falls back to `access_token_ttl` measured from when
it was issued. Refresh is lazy, so a run that finishes inside the TTL makes no extra calls.

A refusal the expiry check did not predict is recovered from too. A 401, or a 403 whose body
is the gateway's bare `{"message": "Forbidden"}` with no `error_code`, refreshes once and
retries the request once, and the second answer is surfaced as it is. A product 403 carries
an `error_code` in the shared error envelope and is not retried: it means authenticated and
not permitted, and retrying it would double every permission assertion in the suite and
report the same refusal a call later.

The refresh endpoint rotates the refresh token, so the body and the cookies it answers with
replace what the session held, mirroring what `login` stores. Keeping the spent one would
present it again on the next refresh, which the rotation detection reads as a replay and
answers by revoking the family. A refresh that is itself refused raises the new
`RefreshFailed` naming the session's user, rather than surfacing a generic 401 from a route
nobody asked about.

The refresh is guarded by a lock, so concurrent callers refresh once between them and none
loses the rotated token to another. Ephemeral and durable users share the path, both arriving
through `login`. A `with_token` clone carries no token source, because asking for one specific
token means that token, which is what the minted-token cases assert on.

## 0.48.0

### `e2e`: run-wide access log checks read the gateway fields correctly

Two of the four shapes `TestAccessLogHealth` swept for in 0.47.0 were built on a wrong
reading of the HTTP API access log fields, and both failed every real suite.

`$context.integrationStatus` is the status AWS Lambda returned for the invocation, not the
status the function returned. For a Lambda proxy integration it is 200 whenever the function
ran, so a product 401, 403, 404 or 422 all log it as 200, and a gateway-side refusal that
never invoked anything logs `-`. The check that failed a 401 or 403 whose `integrationStatus`
was 200 therefore had it exactly backwards: 200 is the proof the product answered. It is
removed rather than inverted, and not replaced by a variant keyed on `authorizerError` or
`errorType`, because a run-wide "the authorizer refused something" check cannot be sound:
the suite's own route probes and every negative auth case are refused on purpose, and the
run has no way to tell an expected refusal from an unexpected one. The function's own status
is `$context.integration.status`, which the `platform-modules` `http-api` default access log
format does not emit.

`no_integration_reported_an_error` now reads `integrationErrorMessage` alone. It used to
prefer `$context.error.message`, which is an API Gateway error message populated on every
gateway-side refusal, including the authorizer refusing the unauthenticated probes the suite
sends deliberately. On a 1232-entry CarModPicker staging run `integrationErrorMessage` was
`-` on every entry while `errorMessage` was set on each refusal.

`AccessLogEntry` gains `authorizer_error`, `error_type` and an `integration_invoked`
property, true when `integrationStatus` parsed to a non-zero value or an integration latency
was recorded. The diagnostic line a failing check prints now says `invoked=yes|no` and names
the authorizer error where there is one, instead of printing an `integrationStatus` that is
200 for every invocation whatever the function answered.

Step-up re-authentication now takes a passkey as well as a TOTP or recovery code, for a
product that wants a confirm button gated on a fresh WebAuthn gesture rather than a code
typed out of an app.

`POST {prefix}/step-up/passkey/options` is the new route, bearer authenticated and rate
limited like the passkey login options route. It answers the same `{challenge_id, publicKey}`
shape, but the challenge is scoped: `allowCredentials` is the subject's own registered
passkeys and `userVerification` is `required`, so a discoverable credential belonging to
somebody else cannot answer it. It is deliberately not gated on `passkeys_passwordless`,
which decides whether a passkey is a way *into* an account and says nothing about
re-authenticating inside one. A subject with no passkey gets `PASSKEY_NONE_REGISTERED` as a
404, an honest answer because the caller is asking about their own account, and a deployment
with passkeys off keeps the existing `PASSKEYS_DISABLED` 501.

`POST {prefix}/step-up` keeps taking `{"code": "..."}` unchanged and now also takes
`{"challenge_id": "...", "credential": {...}}`. The assertion must answer a step-up challenge
minted for this subject, present a credential this subject owns, and report user
verification; each of the three is refused with the envelope the passkey login verify route
already uses. A body carrying neither field, or both, is the existing 422 rather than a
silent preference for one factor. Success is byte for byte the code path's body, with `amr`
`["pwd", "swk"]` plus `mfa`, a fresh `auth_time`, no new refresh family and no cookie.

Behind them, `PasskeyService.begin_step_up` and `finish_step_up`, `IdentityFlows`
`begin_passkey_step_up` and `step_up_with_passkey`, and a third `step_up` value on the
`webauthn-challenges` table's `purpose` attribute, which keeps the three ceremonies apart so
a login challenge can never be spent as a re-authentication. `IdentityFlows.step_up` is
unchanged, and `STEP_UP_PASSKEY_OPTIONS_PATH` is exported from `webbpulse.identity`.
Five gaps `webbpulse.composition` and its isolation check hit on the first product to
migrate onto them. All five are source-compatible: every default is the behaviour that
shipped, so an adopter changing nothing sees no change.

- `domain_entrypoint` takes a `configure_logging` callable, given this domain's service
  name, defaulting to the package's own. A product whose log format is not the package's
  now passes its own and keeps `settings`, instead of passing `settings=None` and redoing
  logging, tracing and the secrets check inside `check` to keep the documented order.
- `entrypoint_imports` defaults `package_root` to `"app.domains."`, the default
  `assert_entrypoint_isolation` already had and the docs already implied.
- `entrypoint_imports` and `assert_entrypoint_isolation` take `allowed_foreign`, the
  exception list for a foreign module every domain legitimately imports, such as the
  identity glue a product's shared local authorizer is built from. A collection applies to
  every domain and a mapping applies per domain; anything outside it is refused as before.
  A listed module covers its own submodules, and the packages between it and `package_root`
  are allowed exactly, since Python cannot import a submodule without its parents. Naming
  one module of a domain never opens the rest of it.
- `Domain` gains `metadata`, a mapping the builder never reads, for product facts such as a
  `seeds` flag. `extra` is documented as `create_app` keyword arguments and nothing else,
  since it is forwarded verbatim.
- `docs/composition.md` gains a migration section on the fields a migrating product must
  set explicitly, `router_prefix` and `service_name_template`, whose package defaults
  silently unprefix a product's routes and rename its logged service.

The tenant-facing half of `webbpulse.identity.api_keys` and `webbpulse.identity.share_tokens`,
so a multi-tenant product can list, cap and revoke its own credentials without a table beside
the package's. Everything here is additive: every new field is optional with a default, every
new store method is concrete on the base class, and no existing caller changes.

A share token now names a target. `ShareTarget` is a type and an id, stored flat as
`target_type`, `target_id` and a `target_key` of `"<type>#<id>"`, and `record.target` reads it
back. `list_for_target` and `revoke_all_for_target` answer "every link onto this issue" and
"revoke everything pointing at this view" through the new `tenant_id-target_key-index` GSI,
hash `tenant_id` and range `target_key`, which is one query on an exact key rather than a
tenant read filtered afterwards. That distinction is the point: a filtered listing fetches
rows for targets the caller may not be allowed to see, and a product whose authorization rule
is "never fetch an invisible project's links" cannot use one. The index name and keys are a
contract with `platform-modules/aws//modules/identity`, which is adding the same index. The
attribute is sparse, so a token minted with no target stays out of the index and resolves
exactly as before. Never a scan.

An API key record gained `key_id`, `kind`, `created_by` and `metadata`. `key_id` is a revoke
handle that is not the hash, allocated by `mint` and spent by `revoke_api_key_by_id`, so a
settings page revokes by a name in a URL rather than by a value one hash away from the
credential. `kind` is free-form and defaults to `"user"`; `created_by` records who minted a
key whose subject is not a person, and is `None` rather than `""` when unrecorded; `metadata`
round-trips through the store untouched. `count_for_tenant` is the per-create cap check, and
`DynamoApiKeyStore` answers it with a paginated `Select="COUNT"` query on
`tenant_id-created_at-index` that counts index entries server side and returns no rows at all.

Records written before any of this load unchanged. A row with no `key_id` comes back with an
empty one and `revoke_handle` falls back to the hash, which `revoke_by_id` also accepts, so an
old key stays revocable by the same call as a new one; nothing is backfilled, so a listing
renders an id for a new key and a hash for an old one. A missing `kind` defaults, a missing
creator is `None`, and missing metadata is an empty mapping.

`webbpulse.testing` gained `assert_api_key_store_contract` and
`assert_share_token_store_contract`, which hold a product's own store implementation to all of
the above from one test, in the shape `assert_users_repository_contract` already had.

Standupless deletes `backend/app/common/db/dynamo/share_links.py` and the
`WorkspaceApiKeyStore` half of `api_keys.py` once it adopts. `ws_target-index` becomes
`tenant_id-target_key-index`, `list_for_target` and `list_for_targets` map straight across,
`project_id` and `title` move into `capability`, `new_key_id` becomes `new_api_key_id`,
`ApiKeyRepository.revoke(workspace_id, key_id)` becomes `revoke_api_key_by_id`, and
`count_for_workspace` becomes `count_for_tenant`. The `svc#<workspace_id>` service subject and
the 25-key cap stay the product's own: the package stores the subject a product hands it and
counts rows, and neither the prefix nor the number is the package's to choose. The package's
count includes revoked rows, so a product capping only live keys subtracts them itself.

## 0.47.0

Two whole-run checks in `webbpulse.e2e`, from the Standupless test hardening build, plus the
collection fix that build needed locally.

`TestAccessLogHealth` sweeps the gateway's own access log for this run and fails on four
shapes a per-case assertion cannot see: any 5xx, any 401 or 403 whose `integrationStatus` is
200, any non-`OPTIONS` request that matched no route key, and any integration error message.
The middle one is the one that matters most: a rejection the function never saw is the
authorizer or the gate refusing, and from outside it reads exactly like a product permission
check. The error message is read through `log_field`, so the literal `-` the gateway renders
for an unset context variable is not reported as an error on every healthy request. The
group is guarded by `test_the_access_log_carries_this_runs_requests`, which fails when
nothing correlated, because an empty sweep is what a wrong log group produces and the four
checks below would all pass on it. It skips where `E2E_ACCESS_LOG_GROUP` is unset.

`TestRouteCoverage` asks the inverse of every other group: which served operations nothing
exercised. Concrete request paths are matched back to templated routes by specificity, the
way API Gateway matches them, so `/api/issues/7/comments` is credited to
`/api/issues/{issue_id}/comments` rather than to `/api/issues/{issue_id}`. Products supply
only their allowlist, through the new `pytest_e2e_uncovered_routes` hook; the matching, the
staleness check and the empty-reason check are the package's. An entry naming a route the
deployment no longer serves fails as stale, so an allowlist cannot outlive the gap it
excuses. Both groups read the run through the new `suite_requests` fixture, which is the
shared record every client already appends to, so no case has to register itself.

Both whole-run groups are gathered so the measurement is genuinely whole-run in both
scheduling modes. Session fixtures under xdist are per worker, so a group scheduled onto a
worker sees only that worker's requests, and `--dist loadgroup` was free to put it anywhere:
`test_every_served_route_was_exercised_or_is_allowlisted` would have failed on staging as
soon as a product picked the release up, reporting every route the other workers exercised as
uncovered. A serial run had no ordering guarantee either, since a product test file that
sorts after `test_shared.py` ran after coverage was measured.

Serially, the plugin now orders both groups after every other case during collection, health
before coverage, and they stay ordinary tests. Under xdist they skip on the worker with a
reason naming the controller, each worker writes its own requests to a JSON file at
`pytest_sessionfinish` under a directory keyed on `E2E_RUN_ID` and the worker id, and the
controller reads every file once the workers have finished, runs the same checks over the
union, prints the verdicts in the terminal summary and sets the exit status to tests-failed
on any failure, so a controller-side finding turns the job red although every individual test
passed. The run directory is removed afterwards, and the access log half is skipped where
`E2E_ACCESS_LOG_GROUP` is unset exactly as the fixture skips it. Both paths call the same
check functions in the new `webbpulse.e2e.runwide`, one per check returning a failure message
or None, so the two modes cannot drift.

`RequestRecord.path` now records the path alone, through the new
`webbpulse.e2e.client.recorded_path`. A caller that inlines a query string rather than passing
`params=` would otherwise have its request matched against no served template and reported as
a request to a route the deployment does not serve, rather than as coverage of the one it
reached.

A shell with no `E2E_*` set now collects and skips instead of erroring. `pytest_generate_tests`
and `e2e_env` both went through `E2EEnvironment.from_environ()`, which raises, so any
`pytest` or `--collect-only` over a product's whole tree died at collection naming variables
the run never needed, and each product was working around it locally. `environment_for_collection()`
returns None for a wholly unset shell and the suite parametrises a skipped placeholder. A
partially configured shell still raises, because that is a wiring mistake and skipping past
one is how a suite goes green against nothing.

## 0.46.0

Two gaps in the `webbpulse.e2e` plugin found while adopting it in the Terraform runner.

`ephemeral_user_attributes` is a new session-scoped fixture yielding the attributes
`ephemeral_user` creates this run's login user with, an empty mapping by default. A product
that grants write scopes only to an admin or a verified row previously had to override the
whole `ephemeral_user` fixture to pass one argument, and so reimplemented the create call,
the worker-id suffix and the delete-failure warning alongside it. Overriding the new fixture
alone is now enough, and the mapping is copied into the request body, so a session-scoped
mapping cannot be mutated through it. The default is empty, so no existing caller changes.

The shared browser sign-in case reads the signed-in marker through `.first`. A SPA header
carrying both a brand link and a nav link to the same route resolves the marker to two
elements, and Playwright's strict mode raises on a multiple-match `is_visible`, which failed
the case against an app that was working. Nothing is weakened: one visible match is what the
assertion always meant, and the two `count() == 0` assertions after signing out are
unchanged, so a session the app never cleared still fails.


## 0.45.0

Two generic helpers the Standupless and Terraform-runner builds were each keeping a local
copy of.

`Repository(..., read_only=True)` in `webbpulse.dynamodb` makes every write raise the new
`ReadOnlyTable`, a `PermissionError` that is deliberately not a `DynamoError`, so a
broad data-layer handler cannot swallow it. It mirrors a
function whose IAM policy grants only reads on a table, so a route that writes where it
holds no grant fails a unit test instead of returning an AccessDenied in staging. The
refusal names the table and the method and appends the caller's `read_only_hint`, so the
message can point at the registry entry and the Terraform grant that have to move together.
The guarded names are exported as `WRITE_METHODS`, and the guard is installed on
`Repository` itself, so a product subclass inherits it. A test classifies every public
method on the class as a read or a write, so a new write method cannot be added without
being guarded. The refusal happens before the table resource is resolved, so no credentials
are needed to refuse. The flag is opt in and defaults to `False`, so no existing caller
changes.

This replaces Standupless's local `ReadOnlyRepository` and `ReadOnlyTable` in
`backend/app/common/db/dynamo/base.py` with zero behaviour change. Delete the local
`ReadOnlyTable`, `WRITE_METHODS`, `ReadOnlyRepository` and `_refusing`, import
`ReadOnlyTable` from `webbpulse.dynamodb`, and have `_package_repository` pass
`read_only=read_only` with the product's existing sentence as `read_only_hint` rather than
choosing a class. The local guard list and the package's are the same thirteen methods.

`Redactor` in `webbpulse.logging` masks registered secret values in text before it is
emitted, for a process that streams output it does not control. Registration is longest
first, so a secret containing a shorter registered one is masked whole; empty values and
anything shorter than `MIN_REDACTABLE_LENGTH` (4) are ignored. `webbpulse.logging` imports
nothing beyond the standard library, now held by test, so a runner that wants only this
pays no import cost for the rest of the package.

`configure_logging` already took `stream=` as of 0.8.0, so the stdout-to-stderr redirection
both products wrap locally needs no package change.

`webbpulse.testing.create_table` now takes the raw `CreateTable` pieces a table needs beyond
a hash key, a range key and a TTL: `attribute_definitions`, `global_secondary_indexes`,
`stream_specification`, and `request` for a whole keyword mapping, such as the one
`webbpulse.identity.storage.TableSpec.create_table_request` builds. Keys in `request` win
over the ones the helper builds and `TableName` is always the `name` argument, so a product
whose tables carry indexes or streams creates them through the helper and still gets the
waiting and the TTL, which `CreateTable` never covers. The existing keyword-only signature is
unchanged.

`webbpulse.testing.dynamodb_reset_hooks` is a new overridable fixture yielding the callables
`dynamodb_resource` runs on setup and teardown. The package's own `reset_resource_cache`
always runs first and is not in the list, which is empty by default. A product that memoises
its own boto3 resource returns its reset from an override in its `conftest.py` and deletes
the wrapper fixture it needed before, and everything depending on `dynamodb_resource` picks
the override up.

Tenant-scoped API keys and share tokens, the two credential gaps the Standupless M6 build
had rebuilt product-side.

`webbpulse.identity.api_keys`: the `api-keys` spec gains a `tenant_id` attribute and the
`tenant_id-created_at-index` GSI, `ApiKeyStore` gains concrete `list_for_tenant` and
`revoke_all_for_tenant` (default empty, never a scan), and `verify_for_tenant`, exported as
`verify_api_key_for_tenant`, refuses a key presented against another tenant with `None`. In
`scopes`, `claims_or_api_key(tenant=...)`, `require_tenant`, `claims_tenant` and
`tenant_matches` enforce the binding on a route; a mismatch is a 401, not a 403, so it never
confirms that a tenant exists. Session JWTs carry no tenant and count as unbound.

`webbpulse.identity.share_tokens` is a third credential kind: a `wps_` bearer with 256 bits
of entropy, stored as its SHA-256, whose authority is one opaque `capability` mapping.
`mint_share_token`, `verify_share_token`, `revoke_share_token`, `claims_or_credential` (JWT,
then API key, then share token) and `share_token_capability` ship with in-memory and
DynamoDB stores. A share carries no `scope`, so `require_scopes` refuses it and a route opts
in through `share_token_capability`.

The `share-tokens` table is ahead of the identity terraform module; `docs/identity.md`
holds the exact table contract and the Standupless migration.

`webbpulse.composition` is the layer above `create_app` that three products each kept a
near-identical copy of. It adds `Domain` and `DomainRegistry` for the descriptor a product
declares, `build_domain_app` for the one builder both composition roots go through,
`domain_entrypoint` returning the `(build_app, main)` pair a per-domain `entrypoint.py`
binds, plus `configure_logging`, `configure_tracing`, `check_secrets`, `local_authorizer`,
`RepositoryScope` and `scope_for`. `webbpulse.testing` gains `assert_entrypoint_isolation`
and `entrypoint_imports`, the subprocess check both products test today, parameterised by
the registry.

Three choices are load-bearing. `Domain.load_routers` is a callable, not a list of routers,
because importing the registry must import no domain package and that lazy import is what
keeps one domain's image free of the others' code. `configure_tracing` sits behind
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, because with that unset the exporter falls back to
this region's X-Ray endpoint and a function with no X-Ray grant then retries a 403 on every
export for the life of the process, in silence. `configure` hooks run before the routers
and `after_routers` after, so product middleware sits inside the CORS and request id
middleware while anything needing the finished route table still sees it.

`Domain.tables`, `read_tables` and `bundle_for` are not folded in: they resolve through a
product's own registry and bundle type, so they stay in the product and read `scope_for`.

### Migration for adopters

Before and after for a `wiring.py`, an `entrypoint.py` and the isolation test are in
[composition.md](docs/composition.md#migration-for-adopters), with what each of the three
products keeps locally. The Dockerfile CMD does not change.

The DynamoDB glue three products were hand-writing to mount `webbpulse.identity` is in the
package: a product's glue is now its `claims_for` override and its table prefix.
`webbpulse.identity.dynamo_stores(prefix, *, region_name=None, endpoint_url=None)` builds the
`IdentityStores` from the package's own table constants, `dynamo_login_attempts` the lockout
store, and `build_dynamo_router(settings, hooks, *, prefix=None, ...)` is
`build_identity_router` with those stores and the signing client built for you; every other
argument passes through and `stores`, `attempts` and `kms_client` override what would be built.
Neither factory makes an AWS call at import.

`webbpulse.identity.users` holds the shared account row, `User`, and `DynamoUsersRepository`,
generic over the model so a product with extra fields passes a subclass. `update` aliases every
attribute name and rewrites `email_lower` whenever `email` is set. `users_repository` accepts
either `prefix` or `table_name`, and both is a `ValueError`. `User.email` is a plain `str`, not
`EmailStr`, so `email-validator` stays out of every Lambda.

`DynamoUsersHooks(BaseIdentityHooks)` implements every hook over that repository except
`claims_for`, with `ACCOUNT_DISABLED` and `EMAIL_NOT_VERIFIED` behind one `REFUSAL_MESSAGE`.
`create_identity_tables(client, prefix="", *, skip_existing=True, include_users=True)` creates
every identity table and applies each TTL, for a local stack or a test suite. `webbpulse.testing`
gains the `identity_tables` fixture and `assert_users_repository_contract(repository)`.

Nothing here changes behaviour. The before-and-after for `package_glue.py`, `identity_hooks.py`
and `users.py` is in [identity-data-model.md](docs/identity-data-model.md) section 4.5.
## 0.44.0

Three gaps the Standupless M5 build found on 0.43.0: an HKDF the products were hand-rolling,
the stream sequence number a consumer dedupes on, and a mail outage answering 500.

`webbpulse.security.derive_key(master, info, length=32, *, salt=b"")` is HKDF-SHA256 to
RFC 5869, extract then expand, and it is now the one HKDF in the package: the identity TOTP
cipher's `SecretMasterKeyCipher._derive` was calling `cryptography`'s HKDF and now composes
the same primitive, which is byte for byte what it produced before, so no sealed seed needs
rewrapping. One stored secret becomes a key per purpose, because two `info` strings under one
master give independent keys and leaking one says nothing about another or about the master.
`info` is text rather than bytes because it is a context label and not key material, and the
advice is to version it and include everything the key is scoped to in a fixed order, so two
scopes can never render the same string. The default salt is empty, which is the RFC's own
zero-filled default and is what makes a key that must be re-derived on every request
reproducible; a random salt stored beside the ciphertext belongs to a fresh derivation, as
sealing a secret is. Over 255 times the hash length raises rather than wrapping the block
counter and silently repeating the output, and a negative length raises rather than being an
empty key.

`extract_key` and `expand_key` are public as well, which is the part that matters for
adoption. A product whose master key is already high-entropy random commonly hashed it and
expanded from that with no extract step, and those keys are in production: `derive_key` does
**not** reproduce them, because the extract step changes the output. `expand_key(sha256(
master).digest(), info, length)` does, exactly, so an existing derivation swaps to
`expand_key` with no key rotation and anything new starts on `derive_key`.

`webbpulse.events.record_sequence(record)` reads a DynamoDB Streams record's
`dynamodb.SequenceNumber`, which is what a consumer orders and dedupes on and which every
consumer was otherwise reading by hand. An event source mapping retries a whole batch, so a
handler sees a record it has already applied and skips it by storing the highest sequence
applied per item. The value comes back as an `int` rather than the decimal string the record
carries, because one far exceeds 64 bits: `int` is arbitrary precision so the comparison is
exact, while string comparison orders `"100"` before `"99"` and a float loses the low digits.
Ordering holds within one partition key only. A record with no sequence number, an SQS one
for instance, raises `ValueError` rather than reporting zero, which would replay everything
already applied.

An identity send that the provider refuses on a path that reports failures, which is
`request_password_reset` and the deliberate `request_verification` resend, now answers **503
with `EMAIL_UNAVAILABLE`** instead of surfacing `EmailSendFailed` as a 500. A mail provider
being down is retryable and is not the service being broken, and the two statuses tell a
client different things about whether to try again. The refusal is built from nothing but the
failure: its message is the fixed `EMAIL_UNAVAILABLE_MESSAGE`, naming neither the address
asked about nor the provider's reason, so the body is identical for every account and a
caller reads no account's existence out of an outage. The provider's reason stays in the log.
Every other send is unchanged and still best effort, so a registration or a password change
still succeeds when its notice cannot be delivered.

## 0.43.0

Five gaps the Standupless M3 build found on 0.42.0: a REMOVE update, stream source
discrimination, the upload allow list, a list envelope under an API's own plural key, and the
events path variable the platform module has been emitting all along.

`Repository.remove_attributes(key, names)` is the counterpart to `set_attributes` and what a
sparse global secondary index needs. Such an index holds only the items carrying its key
attribute, so an item leaves one by having that attribute deleted; setting it to null or to an
empty string keeps the item in the index and in every query that reads it, which is how an
"unread" index ends up never emptying. Aliasing follows `set_attributes` in its own `#rm{index}`
namespace, so a conditional removal cannot collide with the `#n{index}` placeholders boto3 mints
for an `Attr` condition. Removing an attribute the item does not carry is a no-op to DynamoDB and
so idempotent, an empty sequence returns `None` rather than sending an empty `UpdateExpression`,
a repeated name is sent once because DynamoDB refuses an expression naming one path twice, and a
failing condition raises `ConditionFailed` the way every other conditional write does.

`webbpulse.events.source_table(record)` reads the table name out of a DynamoDB Streams record's
`eventSourceARN`, so a consumer behind two streams tells them apart without hand parsing. The
name comes back as the stream carries it, which is the physical name and still prefixed, so the
comparison to write is against `table_name("issues")` rather than against `"issues"`. A record
with no source ARN, or one that is not a DynamoDB stream ARN, raises `ValueError`: a record that
cannot be placed would otherwise be routed to whichever handler happened to be first.

`webbpulse.storage` gains `UPLOAD_CONTENT_TYPES`, `is_allowed_upload` and `disposition_for`,
which every product taking an upload was about to rewrite. The allow list covers the common
image types, PDF, plain text, CSV, JSON, zip and the six Office types in both the legacy and the
OOXML spellings, since a browser sends whichever one the source application stamped on the file.
What is absent is the point: `text/html`, because an HTML attachment served from the
application's own origin is stored cross-site scripting and no downstream check makes it safe,
and `application/octet-stream`, because it is what a browser sends when it recognises nothing, so
admitting it admits everything. The check belongs before the signing rather than after the object
lands, since the type goes into the signature and refusing it there is what keeps the object from
existing at all. `disposition_for(content_type, filename)` answers `inline` for the handful of
types a browser displays natively and `attachment` for everything else, which makes an
unrecognised type safe by default because a downloaded file is inert while an inline one renders
in the application's origin; `image/svg+xml` is an allowed upload and never an inline one,
because an SVG is scripted markup. The filename is quoted per RFC 6266, with the quotes inside it
escaped so a name cannot close the parameter and inject another, and a name that is not ASCII is
sent twice, a transliterated `filename` and the RFC 5987 `filename*` carrying the real UTF-8
name. Any directory separator and any control character is stripped, since the filename is a
display name and a header value, never a path.

`webbpulse.http.cursor_page(item_type, items_key)` builds a `CursorPage` whose items render
under an API's own plural key, `{"issues": [...]}` rather than `{"items": [...]}`, which is a
house style a product otherwise keeps by hand-rolling the envelope and losing `from_page`,
`has_more` and the cursor with it. The result is a real subclass of `CursorPage[ItemT]`, so only
the wire name moves: the field is still `items` in Python, `page.items` reads the same whichever
model a route returns, and a helper written against `CursorPage` keeps working. It is an alias
rather than a renamed field, which is what keeps `items` working for every existing caller, and
`CursorPage` itself is unchanged on the wire. `serialize_by_alias` makes a response render under
the plural key without a route remembering `by_alias=True`, and FastAPI reads the alias for the
OpenAPI document too, so the schema and the body agree. Models are cached per item type, key and
name, because two structurally identical models sharing a name collide in the OpenAPI document
and come out as `IssuesPage` and `IssuesPage1`.

`events_path()` now reads `APP_EVENTS_PATH` between `IDENTITY_EVENTS_PATH` and
`AWS_LWA_PASS_THROUGH_PATH`. The `lambda-function` module has been emitting one `events_path`
input as both `AWS_LWA_PASS_THROUGH_PATH`, for the adapter, and `APP_EVENTS_PATH`, for the
application, precisely so the two cannot drift apart, and this side was reading only the
adapter's half. Both come from the one input, so they agree whichever is consulted first.

## 0.42.0

Three gaps the Standupless build hit on 0.41.0, filled in the DynamoDB repository, plus a
presigned S3 GET.

`Repository.put`, `update` and `delete` now raise `ConditionFailed` when a condition
expression does not hold, instead of letting a botocore `ClientError` out. The type, its
docs and its 409 mapping through `install_dynamodb_error_handlers` already existed and
nothing ever raised them, so a lost uniqueness race surfaced as an opaque 500 and each
product wrote the same `except ClientError` decode around every conditional write. Only
`ConditionalCheckFailedException` is translated; every other error code is re-raised
untouched, so a throttle or an access denial stays a fault rather than becoming a conflict,
and the original `ClientError` remains on `__cause__`. This changes behaviour for a caller
that caught `ClientError` around a `Repository` conditional write; the identity and rate
limiter stores that did so moved with it.

`Repository.set_attributes(key, attributes)` applies a partial update, aliasing every
attribute name against DynamoDB's reserved words. The aliases use a `#set{index}` namespace
rather than `#n{index}`, which collides with the placeholders boto3 mints for an `Attr`
condition from its own `#n0` counter: the name maps merge into one request, the later
definition wins, and the update silently writes to the attribute the condition named.

`Repository.get_many(ids)` batch-reads a table keyed on one attribute and returns the items
keyed by that id, adding the de-duplication `BatchGetItem` requires and the pairing back to
the requesting id an unordered batch response needs. Misses are omitted, the way `get`
answers `None`.

`webbpulse.storage` gains `presigned_get`, the reading half of `presigned_put`, so a private
bucket stays private and a browser fetches an object directly rather than through a Lambda
that would buffer the bytes and pay for the time. It takes the same shape and client handling
as the upload: bucket, key, `expires_in` defaulting to `DEFAULT_EXPIRES_IN` and capped at
SigV4's `MAX_EXPIRES_IN`, an injectable client, and a region and endpoint for the client
cached per pair. It returns a frozen `PresignedDownload` carrying `url`, `bucket`, `key` and
`expires_in`. The upload bounds a PUT with a signed content type and content length; the GET
equivalents are the response header overrides, so the optional `response_content_type` and
`response_content_disposition` go into the signature as `ResponseContentType` and
`ResponseContentDisposition`, and S3 returns them with the object while a holder of the URL
cannot change them. Omit one and S3 serves the stored metadata. Validation mirrors the upload
path and runs before any signing, so an empty bucket or key, an `expires_in` outside the
range, or either override passed as an empty string is a `ValueError` rather than a URL S3
rejects. The URL is a bearer credential for one key until it expires, which the docs say
plainly. `webbpulse.testing.FakePresigner` covers it unchanged.

## 0.41.0

Five feature sets landed together: DynamoDB counters and idempotency, S3 presigned uploads,
API keys with scope enforcement, the producing side of events with signed webhooks, and an
OAuth 2.1 authorization server for remote MCP servers.

`Repository.increment(key, attribute, by=1)` allocates from a DynamoDB counter in a single
`ADD` update and returns the new value, creating the item if absent, for gap-tolerant issue
key sequences. `new_ulid()` mints a lexicographically time-sortable ULID with no new runtime
dependency. `IdempotencyStore.claim(key, ttl_seconds)` wins or loses a one-shot claim through
a conditional put with a TTL, so a redelivered message does the work once, with
`FakeIdempotencyStore` in `webbpulse.testing`. `UnprocessedItems` now renders as a 503 with
`Retry-After` through `install_dynamodb_error_handlers`, configurable with
`unprocessed_message`, instead of an opaque 500. The new `webbpulse.storage` module adds
`presigned_put`, signing a bounded S3 PUT whose content type and content length are inside the
signature, with `FakePresigner` alongside it.

Added `webbpulse.identity.api_keys` and `webbpulse.identity.scopes`. API keys are minted once
and stored only as a SHA-256 hash with a display prefix, verified through an `ApiKeyStore` with
DynamoDB and in-memory implementations, and revoked by plaintext or hash. A verified key adapts
to the same `AuthorizerClaims` the gateway produces, so one authorization path serves both
callers. `effective_scopes` intersects a key's stored ceiling with its minter's live membership,
keeping a key from outliving the role it was minted under. `claims_or_api_key` accepts either
credential and fails closed, and `require_scopes` refuses a caller missing any named scope with
a 403 in the package's error envelope. The `api-keys` table joins `TABLES` for the platform
identity module to provision.

`webbpulse.events` gains the producing side: `EventEnvelope` is the shape a domain event is
published in, `enqueue` puts one on an SQS queue, defaulting the FIFO group to the envelope's
scope and the deduplication id to its event id, and `deserialize_image` reads a DynamoDB Streams
record image back into plain Python values through botocore's own `TypeDeserializer`. The new
`webbpulse.events.webhooks` dispatches outbound signed webhooks: HMAC-SHA256 over the timestamp
and the body together under `X-Webhook-Signature` and `X-Webhook-Timestamp`, a replay window, a
bounded retry policy with jittered exponential backoff that retries transport failures and the
not-now statuses but never a permanent 4xx, and a dead-letter hook called once when every attempt
has failed. `webbpulse.http` gains `verify_hmac_signature`, the receiving half of that scheme and
of GitHub's `X-Hub-Signature-256`, which compares in constant time and raises `SignatureMismatch`
rather than returning a boolean a caller can forget to check, plus `CursorPage` with
`encode_cursor` and `decode_cursor` for opaque, tamper-evident pagination cursors that bridge
`dynamodb.Page` without `http` importing `dynamodb`. `webbpulse.messages.extract_mentions` returns
the ordered unique `@handle` mentions in a Markdown body, ignoring code spans and code blocks.
`webbpulse.testing` gains `FakeQueue` and `FakeWebhookSender`. `events` is a package now so
`events.webhooks` sits beside the consumer route it complements, and its public surface is
unchanged.

Added an OAuth 2.1 authorization server for hosting a remote MCP server, in
`webbpulse.identity.oauth_server`, mounted by `build_identity_router` behind `mcp_oauth_enabled`
and off by default. It implements the MCP authorization spec (2025-06-18) over RFC 8414, 9728,
7591, 7636, 8707 and 7009: authorization server and protected resource metadata, an authorization
code grant with PKCE S256 required and an RFC 8707 `resource` bound into the token audience, a
consent step that binds the token to one tenant, dynamic client registration for public clients,
and revocation. Tokens are the same RS256 access tokens `TokenService` already mints, so an
existing API Gateway JWT authorizer and `coerce_claims` handle them unchanged. Turning the flag on
also extends the OIDC discovery document with `authorization_endpoint`, `token_endpoint`,
`registration_endpoint`, `code_challenge_methods_supported`, `scopes_supported` and
`response_types_supported`. New stores `OAuthClientStore`, `AuthorizationCodeStore` and
`ConsentStore` ship with DynamoDB and in-memory implementations and a separate
`OAUTH_SERVER_TABLES`, so a product that leaves the flag off provisions nothing extra.

The claims dependencies answer again. `identity.claims` imported `Request` only under
`TYPE_CHECKING`, so under postponed annotations FastAPI could not resolve `request: Request` on
the dependencies `subject_dependency` and `authorizer_claims` build, read the parameter as a query
field, and every route depending on either answered 422 before the dependency ran. Both now bind
`fastapi.Request` into the module globals through `_bind_fastapi_request`, as `router` and the
other route modules do, and are covered by requests through a test client rather than by direct
calls alone.

The only dependency change is dev-time: `boto3-stubs` gains the `s3` extra for mypy. There is no
new runtime dependency, `webbpulse.storage` using the boto3 already in the `dynamodb` extra.

## 0.40.0

TOTP seeds can be sealed under a master key from the app secret instead of a KMS key.

`IDENTITY_TOTP_CIPHER` picks the cipher. `kms` stays the default and is unchanged: a per-seed
data key wrapped through `GenerateDataKey` under `IDENTITY_DATA_KEY_ARN`. `secret` is new and
derives a per-seed key with HKDF-SHA256 from a base64 32 byte master key, so an environment
that uses it needs no symmetric KMS key and makes no KMS call when a user enrols or logs in.
The key is resolved on first use from `IDENTITY_TOTP_MASTER_KEY` where set and from the
`mfa_master_key` entry of the app secret otherwise; a deployed environment should use the
secret, since a variable would hold the key in the function's configuration in plaintext.

Both ciphers bind `{"user_id", "purpose"}` into the ciphertext, the `secret` one through the
HKDF info rather than a KMS encryption context, so a seed moved to another row still fails to
open. Stored rows are self describing: the `secret` format writes `secret_scheme`, the `kms`
format omits it and reads back as the envelope, and each cipher refuses the other's records.
The formats are not interchangeable, so switching an environment or rotating the master key
means every enrolled user re-enrols.

Settings validation refuses `secret` without a base64 32 byte master key, at startup rather
than at the first enrolment.

## 0.39.0

The local-stack authorizer moved into the shared package, and the identity router's route
annotations now resolve.

`LocalAuthorizerMiddleware` stands in for the API Gateway JWT authorizer on a stack that has
no gateway. Deployed, the gateway verifies the access token and the Lambda Web Adapter hands
the function its claims in `x-amzn-request-context`; a local e2e stack has neither, so a
valid token arrives with no claims and every authorized route answers 401. The middleware is
pure ASGI: it strips any inbound copy of that header so a caller can never present claims of
its own, verifies the `Authorization: Bearer` token in process against the key set the local
signer derives, and injects the verified claims in the shape `identity_claims` and
`identity_subject` already read. The verifier is built lazily through the new
`InProcessKeyClient`, a kid-indexed in-memory key client, so `JwksVerifier` never fetches the
JWKS over HTTP from the process serving it. Constructing it outside the local environment
raises, taking the environment from `IdentitySettings.environment` unless one is passed
explicitly. The first product copy of this lived in WebbPulse-Portfolio; every product's
`e2e-local.yml@v3` stack now adds the shared one in its composition root instead.

The identity route handlers are annotated `-> JSONResponse` under postponed annotations, and
`JSONResponse` was visible only under `TYPE_CHECKING`, so FastAPI could not resolve the
return annotation and `app.openapi()` raised `PydanticUserError` on any app mounting the
identity router. `_bind_fastapi_request` in `router`, `oauth_routes`, `passkey_routes` and
`ephemeral_routes` now binds `JSONResponse` into the module globals alongside `Request`,
which keeps the package's rule that importing `webbpulse.identity` imports no fastapi.

## 0.38.3

The ephemeral e2e user routes now verify a bearer token in process where no authorizer ran.

`refuse_non_admin` resolved its caller through the API Gateway authorizer's claims alone, so
a deployment whose identity surface sits behind one coarse route key with the staging access
gate on it and no JWT authorizer refused every call with 401 `NOT_AUTHENTICATED`, whatever
token the caller held. That is exactly CarModPicker staging, where a valid KMS-minted admin
token arrives with no claims attached to it.

Both routes now resolve the caller the way the rest of the identity router already does:
verified authorizer claims win where an authorizer ran, and the `Authorization: Bearer` token
is verified in process with the router's own `TokenService` where none did. The subject and
the roles both come from whichever source answered, with `roles` coerced to a list on either
path, since an authorizer flattens a single-element array claim to a bare string while a
token verified in process carries the native list. The 401 and 403 split is unchanged, and a
token that fails verification is 401 rather than 500. `register_ephemeral_routes` takes a
`tokens` argument to do this, which `build_identity_router` passes.

## 0.38.2

A failing ephemeral e2e user route now says why it failed.

`create_ephemeral_user` raised a message naming only the status, so today's CarModPicker
staging 422 reported that the route answered 422 and nothing about the cause, which was a
validation error the shared envelope described in full. The raised message now renders that
envelope: `error_code`, `message`, `request_id` and one compact line per `details` entry,
with a raw `loc`/`msg` detail read as well as the `field`/`message` shape. A body that is
not JSON is excerpted to 300 characters, and an empty body says so rather than rendering as
nothing. Only the response is read, so neither the generated password nor the admin token
can reach a message.

Cleanup gained the same rendering through the new `describe_delete_failure`, which returns
why a delete failed instead of discarding it, and the session teardown warning now names
that reason. `delete_ephemeral_user` keeps its boolean contract and its promise never to
raise.

`admin_mint_token` no longer swallows a mint failure in silence. A run that asked to mint
and could not now warns with the exception type and message before falling back to the
durable user, so a denied KMS call is visible in the run output rather than looking like an
ordinary durable-user run. No token value reaches the warning.

## 0.38.1

The ephemeral e2e user routes answer requests again. FastAPI resolved the handlers'
`request` parameter against a `Request` that existed only under `TYPE_CHECKING`, so it read
the parameter as a required body field and every `POST /e2e/users` and `DELETE
/e2e/users/{user_id}` answered 422 before the handler ran. The module now binds
`fastapi.Request` into its globals the way the identity router does, and the routes are
covered by requests through a test client rather than by flow calls alone.

## 0.38.0

A `local` environment kind for the e2e plugin, and the identity pieces a local stack needs.

The `webbpulse.e2e` plugin can now run against a stack built from source on a CI runner:
one composed FastAPI app, DynamoDB Local and a vite preview server, with no AWS API call at
all. `E2E_ENVIRONMENT=local` is the switch, and the contract is the two base URLs, the
region, the run id and a user the product seeds itself. `E2E_API_ID` and
`E2E_ACCESS_LOG_GROUP` are no longer required there, and `E2E_GATE_SSM_PARAMETER` and
`E2E_MINT_ENABLED` are ignored. Setting the mint flag locally turns nothing on, because a
local stack has no KMS key, so `admin_mint_token` is empty and the run falls back to the
durable user from `E2E_USER_EMAIL` and `E2E_USER_PASSWORD`. Read-only stays governed by
`E2E_READ_ONLY` alone, and the pacer is off because one runner is one source IP bucket.

No fixture on the local path builds an AWS client. `gate_headers` yields an empty mapping
without reading SSM, `gateway_authorizers` is empty, `access_log` skips rather than
constructing a logs client, and `CollectionInputs` no longer imports boto3 at all there:
the route table is synthesized from the product's own OpenAPI document through the new
`routes_from_openapi`, one route per declared operation with the authorizer flag taken from
the operation's declared security. `gate_cookies`, `admin_mint_token` and `minted_token`
now pull `boto3_session` lazily, so a run that has no gate and cannot mint constructs no
session anywhere.

Group behaviour follows from what a local stack can prove. `TestRouteCut` is skipped whole,
since it needs the deployed route table, the forwarded API Gateway request context and the
CloudWatch access log. `TestCoverage` runs degraded: the route resolution cases compare the
document to a table synthesized from that same document, and the authorizer case skips.
`TestReachability`, `TestIdentity` minus the three minted-token cases, `TestFrontend`,
`TestBrowser` and `TestHygiene` all run, and those are where a local run earns its place: a
broken handler, a broken login, a broken bundle and a broken page are all caught before the
branch is deployed. Every skip reason says it is a gateway concern that runs post deploy, so
a skipped case does not read as a passed one.

This release also carries the identity work that landed unreleased. `webbpulse.identity.storage`
gained `TABLES`, the ten identity tables as `TableSpec` values transcribed from
`platform-modules/aws//modules/identity`, with `TableAttribute`, `TableIndex`,
`create_table_request()` and `time_to_live_request()`, so a local bootstrap and the deployed
module cannot drift. `LocalSigner` is a supported signer implementing the same two-method
`KmsClient` protocol `TokenService` signs through, with a 2048-bit RSA key derived
deterministically from a seed so `kid` is stable across restarts, reached through the new
`IdentitySettings.signer` and `local_signer_seed` and the `signing_client(settings)` helper.
It refuses production twice over, at settings validation and in the constructor, the way
`mint_test_token` does. `RATE_LIMIT_FREE_ENVIRONMENTS` gained `"local"`. Two hash and range
key rows in `docs/identity-data-model.md` were wrong and are corrected.

One login defect the CarModPicker staging runs surfaced. `IdentityFlows.login` recorded a
lockout failure against the empty email key whenever the address was blank, so the
anonymous reachability probe, which posts an empty login on every run, walked the empty
key up to the fifteen minute delay and every later empty submission answered 429. A blank
address is now refused with the ordinary invalid-credentials answer before lockout is
consulted and records no attempt: lockout protects one account, and the empty key names
none.

## 0.37.0

Concurrent e2e runs, a parallel suite, and three pacing and correlation defects the
CarModPicker staging and production runs surfaced.

An e2e run can now create its own login user instead of sharing one durable account. The
profile, social-link and sign-in journeys all mutate whichever account they run as, so a
single durable user forced every caller to serialise behind a per-branch concurrency group.
Where minting is available the plugin now creates a fresh user at session start and deletes
it at the end, and callers can drop that concurrency group. The address is under the
RFC 2606 reserved `e2e.invalid` domain so no mail can reach a real inbox, and the generated
password lives in memory for the session, reaches only the login call and the browser's
`fill`, and is kept out of the `Credentials` repr. The durable user remains the fallback
wherever the route is not offered, and a read-only run still signs in as nobody. The new
`credentials` fixture is what the suite and the browser layer now sign in through, so both
pick up the ephemeral user transparently.

The routes behind it are `POST /api/auth/e2e/users` and
`DELETE /api/auth/e2e/users/{user_id}`, mounted only when the new `ephemeral_users_enabled`
identity setting is true. They are gated twice, because creating a verified account with a
chosen password and no email round trip is exactly the capability an attacker wants: the
flag is off by default, and the router refuses to mount the routes in a production
environment whatever the flag says, so a misconfigured production deployment has no route to
reach rather than a route that answers 403. The caller must present a token carrying `admin`
in its `roles` claim. Delete removes only the product's users row and leaves the identity
rows to the users-table stream purge, so every run exercises the same deletion path
production uses; a product enabling the flag implements the new `delete_user` hook.

The suite runs under pytest-xdist. The route cut and reachability cases are independent
read-only probes and are left schedulable, while everything sharing the session user or the
one Playwright page is marked into a single `xdist_group` during collection, so
`-n auto --dist loadgroup` parallelises the probes and keeps the rest together and in order.
Session fixtures are per worker rather than per run, which is safe by construction rather
than by locking: each worker creates and deletes its own user keyed on its worker id, and
the access-log window scan is unfiltered, so overlapping windows cost an extra CloudWatch
read rather than a wrong answer.

Pacing now treats the `X-RateLimit-Remaining-Minute` header as the budget rather than as a
ceiling on a fixed local count. The products limit per route class, so no single number
describes a GET class allowing two hundred a minute and an auth class allowing ten; taking
the lower of the header and a fallback of ten meant the header could only ever lower the
budget, and a production sweep paced itself into a full window wait every ninth call. A
production read-only run spent about thirty-six minutes that way while the gateway access
log showed no request over five seconds and not one 429. Answers arriving without the header
came from the gateway, the access gate or the authorizer, never reached the application and
spent none of its limiter's budget, so they are no longer counted against it. The fallback
is now configurable through `E2E_RATE_LIMIT_PER_MINUTE` and still defaults to ten.

The access-log fallback no longer burns its whole budget on reads that do nothing. The
window scan is throttled to one CloudWatch read per poll interval across all callers, and
`find` was using that throttled scan inside its own wait loop, so a lookup entering the loop
just after another case had scanned slept the poll interval, read nothing, and repeated
against an unchanged cache. Where in the throttle window a case happened to start decided
how much of the budget it burned, which is why two CarModPicker route-cut cases cost sixty
one and forty three seconds while the rest cost milliseconds. Every iteration now forces a
real read, and the lookup gives up once a scan begun after the delivery grace period has
finished without the entry, since a window already read past that point is evidence the
entry is not coming rather than that it is late.

`TestCoverage`'s authorizer assertion is aware of the identity mode it is checking. In
native JWT mode the products publish coarse `ANY` and `{proxy+}` routes and verify tokens in
process, so a coarse route carries no per-operation opinion to compare against and the case
now skips it and leaves the claim to the reachability group. A per-route authorizer in front
of an operation declaring `requires_auth` false is accepted under the identity prefix, where
the authorizer is the optional-identity one, and is still a failure anywhere else. Gate mode
keeps the strict equality. The mode is read from the route table itself rather than from a
new environment variable. This removes thirty one failures a healthy CarModPicker production
deployment was producing.

## 0.36.0

Four defects in `webbpulse.e2e` that the CarModPicker staging runs found, all of them cases
failing on a healthy deployment.

The minted-token cases judge where the answer came from rather than what status it carried.
On CarModPicker the access-gate authorizer verified a minted token across all ninety-six
route keys and invoked the integration, and the application then answered 401 because it
maps `sub` to a stored user id. A case asserting only that the status was not 401 therefore
failed on an authorizer that was working. All three cases now read `X-WebbPulse-Route-Key`,
which the shared request-id middleware sets on every response the function produces and
which a gateway or authorizer denial never carries. The accepted-token case requires it to
be present, so an app-level 401 or 403 on an admin-only probe passes, and its failure message
reports the status and the first 200 bytes of the body rather than restating the expectation.
The wrong-audience and expired cases require it to be absent alongside the 401 or 403, which
is what separates a gateway refusal from an application refusal carrying the same status.
The new `_looks_like_a_gateway_denial` recognises the gateway's bare one-key `Unauthorized`
and `Forbidden` bodies as a secondary signal, sharing its body check with the existing
`_looks_like_a_gateway_404`.

The default minted subject is now a fixture of its own. `minted_subject` reads the `sub`
claim off the durable e2e user's access token and `minted_token` defaults to it, with an
explicit `subject=` still overriding. A session whose token carries no `sub` skips rather
than minting a token that names no real subject, and the docstrings of the wrong-audience
and expired cases, which already claimed the subject was the durable user's own, are now
true of what the fixture does.

`ConsoleErrors.record` drops report-only Content Security Policy violations unconditionally,
through the new `is_report_only_csp_violation`. The AdSense iframe reports its own
`frame-ancestors` policy against `www.google.com` and the browser states that it took no
further action, so the app under test can neither cause it nor fix it, and it failed
`public:/` on an otherwise clean render. The match is on `report-only Content Security
Policy`, case insensitively; an enforced violation names no report-only directive and still
fails the route.

The sign-in and sign-out steps wait for the page to settle rather than for one marker. A
header that reads the session store shows the signed-in marker as soon as the store holds a
user, which is before the router has swapped the login route away, so for a frame the marker
and the login form are both on the page. `sign_in` returned inside that frame, the sign-out
click landed mid-transition, and the signed-out wait was then satisfied instantly by the
login form that had never left, so the assertion read the header of a page still showing the
old session and called a correct sign-out a failure. `sign_in` now also waits for the submit
button to detach, and the new `sign_out` waits for the signed-in marker to detach before
reading the signed-out one. That second wait matters on its own: the shared `@webbpulse/auth`
client holds `isAuthenticated` true while the logout call is in flight, deliberately, so the
marker stays up until the call settles and an assertion made before then is reading a session
the app is still in the middle of ending. A session the app genuinely never clears still
fails, which is the defect the case exists for.

## 0.35.0

Five defects the first staging runs of the browser layer found, four in `webbpulse.e2e` and
one in `webbpulse.identity`.

`ExpectText` polls instead of reading once. It waited for the locator, read `inner_text` a
single time and asserted immediately, so a heading read part way through a lazy-chunk
transition or a profile field read milliseconds after a submit click failed a correct app.
It now re-reads on the same 250 ms tick `ExpectUrl` uses, up to the browser timeout, and the
failure names the last text seen rather than the first.

`_settle` waits for a real redirect. Returning on the first unchanged 400 ms tick called the
protected path settled while the guard was still working, and measured redirects land
between 750 and 980 ms, so the guard cases reported a phantom security failure. It now polls
to a deadline of five seconds, or the browser timeout when that is smaller, short-circuiting
as soon as the URL reaches the path the caller expects. The redirect-loop refusal is
unchanged.

The shared `@webbpulse/auth` client's cold-load session probe is exempt in both collectors
whatever `ignore_guard_statuses` says. That client sends `POST /api/auth/refresh` on every
cold load to learn whether a refresh cookie exists, and before any sign in the API correctly
answers 401 `NO_SESSION`. Signed-in cases do not set the guard flag, so that one console
error failed the sign-in journey and every product journey starting from a cold load. The
new `is_session_probe` matches on the URL path under this product's API base plus that one
status, because the console listener may only ever see the message text and a URL. Nothing
else gains an exemption and the existing guard semantics are untouched.

Playwright traces no longer carry the durable e2e user's password. Playwright records a
`fill` step's parameters verbatim, and every other typing path it offers records the value
just as verbatim, so there is no way to type a password that keeps it out of the recording.
The trace is now written to a temporary file, every occurrence of the password is replaced
with `[redacted]` in every entry of the zip, `.trace`, `.network` and resource files alike,
and only then is it moved into the artifacts directory. The new `redact_zip` does the work
and the result stays openable by `playwright show-trace`.

`build_identity_router` declares the statuses its routes really answer. Every route carried
FastAPI's default 200 plus 422 alone, so an adopter's published OpenAPI document promised
statuses the routes do not keep and the post-deploy suite flagged them. The three new tables
`IDENTITY_ROUTE_RESPONSES`, `OAUTH_ROUTE_RESPONSES` and `PASSKEY_ROUTE_RESPONSES` are keyed
by method and unprefixed path and applied to whatever the deployment mounted, so a route the
deployment did not mount is simply absent. `POST /register` declares 201, `GET
/oauth/callback` declares the 303 every browser leg takes, `DELETE /oauth/{provider}/link`
and `DELETE /passkeys/{credential_id}` declare the 409 that refuses removing the last way
into an account, and every rate limited route declares 429 whatever this deployment's
limiter setting is. Adopters carrying their own stopgap table can delete it.

## 0.34.0

`webbpulse.identity` gains `JwksVerifier`, which verifies an access token against the
issuer's published JWKS over HTTPS rather than through `kms:GetPublicKey`. `TokenService`
reads its keys from KMS and so builds only where the signing key ARNs and that grant are,
which is the identity function alone; a domain function holding nothing but the issuer and
the audience now has a supported way to resolve a bearer token in process. That is what an
optional-auth route needs, because the gateway publishes claims only for the route keys it
enforces a token on and an optional-auth route is never one of those.

RS256 only, with `iss`, `aud`, `exp` and `nbf` all verified and `exp`, `iat`, `iss` and
`sub` all required. `alg` is checked against the header before any key is fetched, so an
`alg: none` or HS256 token is refused without a network call, and `typ` is asserted
positively against `access` unless a caller names another. Every rejection is
`InvalidToken`, the same type `TokenService.verify_access_token` raises.

The key set is cached across invocations by `PyJWKClient`, with `lifespan` bounding how
long a set is served and `cooldown_duration` bounding how often an unknown `kid` may
trigger a refetch, so a signing key rotation is picked up without an unbounded fetch loop.
`discovery_jwks_uri` resolves the `jwks_uri` from the issuer's discovery document and
refuses one that points at another origin; passing `jwks_uri` directly skips that fetch.
`JwksVerifier.from_settings` builds one from `IdentitySettings` without reading a signing
key ARN. New exports: `JwksVerifier`, `discovery_jwks_uri`, `DEFAULT_CACHE_LIFESPAN`,
`DEFAULT_COOLDOWN` and `DEFAULT_TIMEOUT`.

## 0.33.0

The e2e route cut group proves a cut from the response rather than from the access log, and
where it still needs the log it pays one delivery lag for the whole group instead of one per
route. On the first full CarModPicker staging run that group was 3393 s of a 60 minute wall,
147 routes at a median of 27 s each, and the run ran out of OIDC credentials before it
finished.

`RequestIdMiddleware` now echoes the gateway's matched `routeKey` as `X-WebbPulse-Route-Key`
on every response in every environment, read verbatim from the request context the Lambda
Web Adapter forwards and absent when that header is not there. `webbpulse.http` exports
`ROUTE_KEY_HEADER`, `route_key` and `request_context`.
`TestRouteCut.test_access_log_names_this_route_key` reads that header as its primary proof
and falls back to the access log only for a request the gateway answered before the function
ran, which is what an identity rejection, a gate rejection and the gateway's own 404 look
like.

A new session-scoped `route_probes` fixture probes every live route up front, with the same
method, path and precedence-shadowing rules the per-route case used, and opens the lookup's
delivery window at the first probe. `AccessLogLookup` gains `open_window`, `scan_window` and
`read_one`: `find` consults the cache, scans the whole window unfiltered, and only then
polls, with a rescan throttled to one per poll interval across every caller. The
per-request-id filtered read stays as `read_one` for a single lookup outside the window.
`DEFAULT_WAIT_SECONDS` and `DEFAULT_POLL_SECONDS` mean what they meant, and a miss inside
the budget is still a miss. The three per-route cases and their parametrisation are
unchanged, so the junit shape is the same.

`E2EClient` gains `put` and `patch`, through the same `request` path as the other four, so
pacing, the 429 retry and the request record apply to them.

Two minted-token defects are fixed. `minted_token` defaults its subject to the durable e2e
user's own id instead of a made-up `<prefix>mint`, which named no real user, so the API
refused every minted token on subject resolution and the two negative cases passed for the
wrong reason; the fixture needs the user session and therefore skips in read-only mode, and
the three mint cases carry `e2e_writes`. The accepted-token case now treats a 403 as proof
the token authenticated, since the probe is whichever auth-requiring operation the
configuration offers first and on a product with an admin surface that is an admin route;
only a 401 fails it. Those messages say "the API" rather than "the authorizer", because a
product that verifies tokens in process has no gateway JWT authorizer.

## 0.32.1

`build_identity_router` defaults `limiter_enabled` to the same convention: `None` now means
`rate_limits_apply(settings.environment)`, so the login, MFA and email flow limits are off
in staging without the product passing anything. An explicit `True` or `False` still wins.

## 0.32.0

Staging is never rate limited, as one convention shared by the services and the e2e suite.
`webbpulse.config` gains `RATE_LIMIT_FREE_ENVIRONMENTS`, `rate_limits_apply(environment)`
and the `BaseServiceSettings.rate_limiting_enabled` property; wire every limiter a service
has through the property, including `rate_limit_middleware(enabled=...)`. Reaching staging
already takes the access gate, and the full suite runs there, so throttling it only paces
the tests. Every other environment keeps its limits.

`E2EEnvironment.rate_limited` reads the same convention and the `anon` client's budget is
zero against staging, so `Pacer` never waits there; a zero `per_minute` now means unpaced.

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
