# `webbpulse.identity`

App-managed identity: the routes, the services, the stores, and the wiring. The normative
contract lives in [the identity standard](identity-standard.md); this file is the package's
own reference for it. Back to the [README](../README.md).

## `webbpulse.identity`

App-managed identity: password flows, refresh sessions, email verification and password
reset, TOTP and recovery codes, configuration, the product policy seam, storage interfaces,
a KMS-backed token service, and the reader for the claims an API Gateway HTTP API JWT
authorizer leaves on a request. Needs the `identity` extra.

This completes `docs/identity-standard.md`. M1 built the foundations, M2 added the password
and session flows, M3 added the two emailed link flows, M4 added multi-factor
authentication, M6 added federated sign-in against Google and GitHub, and M5 adds passkeys:
WebAuthn registration and passwordless sign-in, credential management, and stored
single-use challenges.

OAuth needs the `oauth` extra on top of `identity`, for `httpx`, and passkeys need the
`passkeys` extra, for `webauthn`. A product that mounts neither set of routes needs
neither: both are constructed lazily, so importing the package without them works.

```python
from webbpulse.identity import IdentitySettings, TokenService, build_identity_router, signing_client

settings = IdentitySettings()  # reads IDENTITY_* from the environment
tokens = TokenService(settings, signing_client(settings))

# One per execution environment: it caches a JWK per configured key.
app.include_router(build_identity_router(settings, hooks, stores, tokens=tokens))
```

`signing_client` returns a boto3 KMS client, or `LocalSigner` when `IDENTITY_SIGNER=local`.
See [the configuration surface](identity-configuration.md) for the switch and
[the data model](identity-data-model.md) for `TABLES`.

| Piece | What it owns |
| --- | --- |
| `IdentitySettings` | Section 6.1 as validated settings, `IDENTITY_` prefixed |
| `IdentityHooks` | The product's own policy: who may sign in, what claims they get, and creating the user row |
| `IdentityFlows` | Register, login, change password, refresh, logout, logout-all, verify email, reset password, passkey registration and sign-in, with no FastAPI dependency |
| `SessionService` | Refresh families: rotation, reuse detection, the grace window, revocation |
| `LinkService` | Single-use emailed links: minting, hashing, expiry, purpose, consumption |
| `MfaService` | TOTP enrolment and verification, recovery codes, and the MFA ticket |
| `OAuthService` | The provider leg, the linking rules, and the last-sign-in-method count |
| `OAuthStateStore` and `OAuthLinkStore` | The in-flight authorization and the provider-to-user attachment |
| `PasskeyService` | WebAuthn ceremonies, the challenge lifecycle, the signature counter check, credential management |
| `EnvelopeCipher` | Sealing a TOTP seed under a per-secret KMS data key with a per-user encryption context |
| `EmailSender` | Sending mail, with an SES v2 implementation and a recording one for tests |
| `TokenService` | Minting, local verification, JWKS, discovery, rotation across keys |
| `LocalSigner` | An in-process RSA signer standing in for KMS on a local stack, refused in production |
| `TABLES` | The ten identity tables as `TableSpec`, matching the Terraform identity module |
| `JwksVerifier` | Verifying an access token against the issuer's published JWKS, with no KMS grant |
| `authorizer_claims` | Reading and coercing what the authorizer put on the request |
| `CredentialStore` and friends | Storage interfaces, with DynamoDB and in-memory implementations |

**Every route mounts under the issuer's path, so mount the router with no prefix.** The
gateway builds the discovery URL as `issuer + "/.well-known/openid-configuration"` and
`jwks_uri` is advertised the same way, so the issuer decides where the routes live.
`build_identity_router` derives the prefix and places itself there. With the standard's
`https://<host>/api/auth` issuer:

| Route | What it does |
| --- | --- |
| `GET /api/auth/.well-known/openid-configuration` | Discovery, fetched by the gateway at authorizer creation |
| `GET /api/auth/.well-known/jwks.json` | The verification keys, followed out of discovery |
| `GET /api/auth/health` | The probe shape every service in the estate shares |
| `POST /api/auth/register` | Creates an account through the `create_user` hook and signs it in |
| `POST /api/auth/login` | Verifies a password, applies lockout, starts a refresh family |
| `POST /api/auth/password` | Changes a password and revokes every other session |
| `POST /api/auth/refresh` | Rotates the refresh family and returns a new access token |
| `POST /api/auth/logout` | Revokes the presented family |
| `POST /api/auth/logout-all` | Revokes every family for the user |
| `POST /api/auth/verify-email` | Mails a fresh verification link, answering 200 either way |
| `POST /api/auth/verify-email/confirm` | Spends a verification link and marks the address verified |
| `POST /api/auth/reset` | Mails a reset link, answering 200 either way |
| `POST /api/auth/reset/confirm` | Spends a reset link, sets the new password, revokes every session |
| `POST /api/auth/login/totp` | The second leg of login: exchanges an MFA ticket plus a code for tokens |
| `POST /api/auth/totp/enrol` | Starts an enrolment and returns the seed and provisioning URI once |
| `POST /api/auth/totp/activate` | Confirms an enrolment with its first code and returns recovery codes |
| `POST /api/auth/totp/disable` | Removes the factor and every recovery code with it, on a `code` |
| `POST /api/auth/recovery-codes` | Replaces the set on a `code`, invalidating every previous code |
| `POST /api/auth/step-up` | Re-authenticates inside the session for a fresher `auth_time` |
| `GET /api/auth/oauth/providers` | The providers this deployment can sign a user in with, anonymous |
| `GET /api/auth/oauth/{provider}/start` | Mints a state and redirects the browser to the provider |
| `GET /api/auth/oauth/callback` | Spends the state, verifies the provider's answer, issues the token pair |
| `POST /api/auth/oauth/{provider}/link` | Starts a link for the authenticated account, returning the URL |
| `GET /api/auth/oauth/links` | The providers attached to this account, for a settings page |
| `DELETE /api/auth/oauth/{provider}/link` | Detaches a provider, unless it is the last way in |
| `GET /api/auth/passkeys/availability` | Whether passkeys and passwordless sign-in are on, anonymous |
| `POST /api/auth/passkeys/register/options` | WebAuthn registration options for the authenticated caller |
| `POST /api/auth/passkeys/register/verify` | Verifies the attestation and stores the credential |
| `POST /api/auth/login/passkey/options` | WebAuthn authentication options, anonymous |
| `POST /api/auth/login/passkey/verify` | Verifies the assertion and issues the same token pair as `/login` |
| `GET /api/auth/passkeys` | The caller's own passkeys |
| `PATCH /api/auth/passkeys/{credential_id}` | Renames one of the caller's passkeys |
| `DELETE /api/auth/passkeys/{credential_id}` | Removes one of the caller's passkeys |

An issuer with no path gives the same routes at the origin. Adding a prefix of your own
doubles the issuer path and hides the documents from the gateway. **This changed in
0.10.0**: 0.9.0 served the documents at the origin regardless of the issuer, so a product
that compensated with `prefix="/api/auth"` must drop it when upgrading.

**The flow routes mount conditionally.** The six password and session `POST` routes appear
only when the product supplies both `hooks` and a credential store. Called without them the
router mounts exactly what M1 mounted, the two `.well-known` documents and `/health`, so a
service that only serves a JWKS does not acquire a login endpoint by upgrading. The four
email routes need more still: an `EmailSender` and an identity token store, and without
both of those the other ten routes mount without them. The six MFA routes need `totp_enabled`
plus a TOTP factor store, a recovery code store and an identity token store, and they mount
independently of the email routes: a product can run TOTP with no sender configured at all.
The seven passkey routes need `passkeys_enabled` plus a passkey store and a WebAuthn
challenge store, and they mount independently of both: a product can run passwordless
sign-in with no email and no TOTP. A route that cannot do its job should not exist to be
called.

**Two routes are the deliberate exception.** `GET /oauth/providers`, from 0.16.0, and
`GET /passkeys/availability`, from 0.17.0, mount in **every** deployment, including the
documents-only one, answering `{"providers": []}` and
`{"enabled": false, "passwordless": false}` where the feature is off. Both exist so a
frontend gets one authoritative answer everywhere rather than a 404 it has to interpret, and
a 404 is indistinguishable from a routing mistake or an older version of this package. Each
is anonymous, touches no store, and carries `Cache-Control: public, max-age=300`.

**Login answers 200 with a challenge when a factor is enrolled.** The first leg returns
`{"mfa_required": true, "mfa_ticket": "...", "factors": ["totp"]}` rather than tokens, and
rather than a 401: nothing was refused, since the password was correct. The second leg posts
that ticket and a code to `/login/totp` and gets the ordinary token response. The ticket is
short-lived, single use, and carries an audience of `<issuer>/mfa` rather than the API's, so
the gateway's authorizer refuses it anywhere else. `/login/totp` therefore has to sit outside
the authorizer; the other five MFA routes sit behind it and read their subject from the
verified claims, never from the body.

**Disabling TOTP and regenerating recovery codes each need a code, not just a token.**
Both routes take `{"code": "..."}` alongside the bearer token, and the code is either a
current TOTP code or an unused recovery code, which is then spent. Both are destructive to
the second factor, so the access token alone must not be enough: it is short-lived but it is
still a bearer secret, and a stolen one would otherwise switch off the control that bounds
what stealing it is worth, or invalidate the codes the real user needs to get back in. The
code goes through the same verification the second leg of login uses, a wrong one is the
same 401 `INVALID_MFA_CODE`, and both routes share that route's rate limit. Verification
runs before anything is deleted, so a refused call leaves the factor and the existing codes
exactly as they were. A missing or blank `code` is a 422 `VALIDATION_ERROR` instead, because
a client that forgot the field should be told that rather than shown "that code is not
valid". **This changed in 0.13.0**: both routes previously took no body at all, so a client
must be updated to send one.

**A TOTP seed is never stored in the clear.** Each one is sealed under its own key with
`{"user_id", "purpose"}` bound in, so a ciphertext moved to another user's row fails to
decrypt. `IDENTITY_TOTP_CIPHER` picks which cipher does it:

- `kms`, the default, wraps a per-seed KMS data key through `GenerateDataKey`. Set
  `IDENTITY_DATA_KEY_ARN` to a symmetric key, distinct from the signing key. Reading a seed
  needs both table access and `kms:Decrypt`.
- `secret` derives a per-seed key with HKDF-SHA256 from a base64 32 byte master key. No KMS
  key and no KMS call on the path. Reading a seed needs both table access and the app secret.
  The key is resolved on first use from `IDENTITY_TOTP_MASTER_KEY` where it is set, and from
  the `mfa_master_key` entry of the app secret behind `APP_SECRETS_ARN` otherwise. A deployed
  environment should use the secret: an environment variable would put the key in the
  function's configuration in plaintext.

The two formats are not interchangeable. A stored row carries `secret_scheme` in the `secret`
format and omits it in the `kms` format, so each cipher refuses the other's records rather
than misreading them; switching an environment, or rotating the master key, means every
enrolled user re-enrols. Recovery codes are the opposite case and are SHA-256 hashed rather
than encrypted: verification only ever compares them.

**The access token is returned in the JSON body and the refresh token is a cookie.** The
access token is short-lived, ten minutes by default, and is never set as a cookie: it is
carried in an `Authorization` header where no browser will send it automatically. The
refresh token is the opposite, an httpOnly Secure SameSite=Lax cookie scoped to
`cookie_path`, so no script can read it and no cross-site form can spend it. `cookie_path`
defaults to the issuer's path, the same place the routes mount, so the cookie reaches
exactly what spends it.

**Rotation detects reuse, and reuse revokes the family.** Every refresh consumes the
presented token and mints its successor in one conditional write, so two concurrent
refreshes cannot both succeed. Presenting an already consumed token inside
`refresh_reuse_grace` is treated as a client that raced itself and returns a working
successor; presenting one after that window is treated as a stolen token and revokes the
whole family, signing out both the attacker and the victim.

**Wrong password and unknown email are indistinguishable.** Identical status, body and
`error_code`, and the same cost: a login for an address that does not exist still runs one
bcrypt verification against a dummy hash, so the response time does not answer the question
the body refuses to. Registering an address that is already taken returns 200 with no
session rather than an error, for the same reason.

**Lockout is progressive, never permanent.** Five consecutive failures start a delay that
doubles from one second to a fifteen minute cap, and any success clears it. There is no
hard lock, because a hard lock on a known address is a denial of service anybody can
trigger.

**The emailed links point at the frontend, and both confirmations are `POST`.** A reset link
carries no password, so a page has to collect one, and a `GET` that consumes state is spent
by the first mail scanner that follows it. `frontend_base_url` plus `VERIFY_LINK_PATH` and
`RESET_LINK_PATH` build the URL that goes in the mail; the frontend posts the token back to
the route above.

**Both request routes answer 200 whether or not the address exists.** A reset request
always returns "If that address has an account, a link is on its way." and a verification
resend always returns the same shape, so neither route answers the question of who has an
account here. Rate limits apply per address and per IP on both, so an unlimited resend
cannot be used as a mail relay pointed at addresses an attacker supplies.

**Links are single use, hashed at rest and short lived.** 256 bits from the system CSPRNG,
only the SHA-256 stored, consumed by one conditional write. Verification links last 24
hours and reset links one hour. A confirmation checks the stored record's purpose before
spending it, so a verification link pasted into the reset page is refused without being
burned.

**A completed reset revokes every session and keeps none**, unlike `change_password`, which
takes a `keep_family_id` so the caller stays signed in. The person resetting may not be
signed in at all, and no session is known to be theirs rather than the attacker's. A reset
also marks the address verified, because it proves the same control of the mailbox that a
verification link proves.

**Password changes and completed resets send a notice, and no notice carries a live token.**
It is the one signal a user has that somebody else took the account over. Every notice links
to the bare reset page rather than to an issued link, so a message triggered by somebody
typing an address into a form cannot become an unrate-limited link mailer.

**`SesV2EmailSender` builds both bodies itself, with no templating dependency.** Plain text
plus a minimal HTML body from `string.Template`, with every interpolation HTML escaped.
`RecordingEmailSender` keeps what it was asked to send, for tests and for a local run with
no AWS credentials at all.

## OAuth and passkeys

Federated sign-in is documented in [identity-oauth.md](identity-oauth.md) and passkeys in
[identity-passkeys.md](identity-passkeys.md).

## API keys and scope enforcement

`webbpulse.identity.api_keys` mints long-lived credentials for machine callers, and
`webbpulse.identity.scopes` guards routes on what a caller may do. A key is minted once,
shown once, and stored only as a SHA-256 hash with a short clear-text prefix for display, so
a leaked table authenticates as nobody.

```python
from webbpulse.identity import DynamoApiKeyStore, mint_api_key

store = DynamoApiKeyStore(repository)
minted = mint_api_key(
    user_id=user.id,
    tenant_id=tenant.id,
    scopes=["issues:read", "issues:write"],
    name="CI deploy key",
    store=store,
)
return {"key": minted.plaintext, "prefix": minted.record.prefix}
```

`minted.plaintext` is the only time the key exists outside the caller's own storage. Put it
in that one response and nowhere else, least of all a log line.

A key is a delegation, never a promotion. The scopes on a record are the ceiling its minter
held at mint time, and membership changes afterwards, so a request must intersect the two:

```python
from webbpulse.identity import effective_scopes

granted = effective_scopes(record.scopes, live_scopes_for(record.user_id))
```

Without that intersection a key outlives the role it was minted under, which is how a removed
admin keeps admin access through a key nobody remembers. `claims_or_api_key` does it for you
when given a `live_scopes` callable, and that is the form to reach for.

`claims_or_api_key` returns the same `AuthorizerClaims` a JWT would, so a route cannot tell a
key from a signed-in person and there is no second authorization path to keep in step. It
tries the authorizer first and only falls back to a bearer value carrying the `wpk_` prefix,
so adding it never weakens a route that already had an authorizer. Every failure is the same
401: a missing credential, an unknown, revoked or expired key, and a membership lookup that
raises are indistinguishable to the caller.

```python
from fastapi import Depends

from webbpulse.identity import claims_or_api_key, require_scopes

claims = claims_or_api_key(store=store, live_scopes=live_scopes_for_key)


@router.post("/issues", dependencies=[Depends(require_scopes("issues:write", claims_dependency=claims))])
def create_issue() -> Issue: ...
```

`require_scopes` needs every scope it names, never any one of them, and refuses with a 403
carrying `webbpulse.messages.forbidden` and the `INSUFFICIENT_SCOPE` code. The missing names
are not in the body: naming them tells a caller what to go and acquire. `is_api_key_actor`
reads the `actor_kind` claim for the route that must refuse a key outright, such as changing a
password or minting another key, because a key must never mint its own successor.

The `api-keys` table is in `TABLES` alongside every other identity table, so the platform
identity module provisions it with the rest. It carries no TTL deliberately: expiry is checked
on the read path, because a key that vanished from the table would be indistinguishable from
one that never existed, and an expired key its owner can still see and delete is the better
operator experience.

### Tenant-scoped keys

A key already names the tenant it acts inside, and `claims_for_key` puts it on the claims as
`tenant_id`, so a product can fail closed on a mismatch. Two things make that practical.

`list_for_tenant` and `revoke_all_for_tenant` answer "every key in this workspace" and stop a
tenant authenticating at once, through the `tenant_id-created_at-index` GSI. The `key_hash`
partition cannot answer either without a scan, which is why a multi-tenant product otherwise
grew its own key table beside this one. Both are concrete rather than abstract on
`ApiKeyStore`, so a store written before they existed still satisfies the protocol; the
default answers empty rather than scanning, because a silent scan on a settings page is worse
than an empty list.

```python
from webbpulse.identity import verify_api_key_for_tenant

record = verify_api_key_for_tenant(presented, store, workspace_id)
```

`verify_api_key_for_tenant` is `verify` plus the binding check: a key minted in one tenant
must never reach another, which is the cross-tenant reach a scoped credential exists to
prevent. It answers `None` for a mismatch, like every other refusal, so a key cannot be walked
across tenant ids to learn which ones exist. An empty tenant refuses rather than matching
everything: a caller that could not work out which tenant it is in must not be the one
deciding a key may act.

On a route, either spelling does it. `claims_or_api_key(tenant=...)` checks inline, and
`require_tenant("workspace_id", claims_dependency=...)` wraps a claims dependency that already
exists. Both refuse with the same 401 an unknown credential gets rather than a 403, because a
403 would confirm the tenant in the path exists.

```python
claims = claims_or_api_key(
    store=store,
    live_scopes=live_scopes_for_key,
    tenant=lambda request: request.path_params["workspace_id"],
)
```

`claims_tenant` reads the binding off any claims object and `tenant_matches` decides one
against a tenant id, answering true for claims carrying no tenant at all: a session JWT is
unbound, because a person's authority is their membership read fresh in whichever tenant the
path names, and an unbound credential is not one bound somewhere else.

### Key ids, kinds and the per-tenant cap

A record carries four fields a product would otherwise keep in a table of its own, all of
them optional and all of them defaulted, so nothing that mints a key today changes.

`key_id` is the revoke handle. It is deliberately not the hash: a settings page that has to
name the hash to revoke a key renders a value one hash away from the credential, whereas an
id is a name and can go in a URL. `mint` allocates one, `revoke_api_key_by_id` spends it, and
neither ever holds a secret:

```python
from webbpulse.identity import mint_api_key, revoke_api_key_by_id

minted = mint_api_key(
    user_id=subject,
    tenant_id=workspace.id,
    scopes=payload.scopes,
    name=payload.name,
    kind="workspace",
    created_by=actor.id,
    metadata={"label": payload.label},
    store=store,
)
return {"key_id": minted.record.key_id, "secret": minted.plaintext}


revoke_api_key_by_id(workspace.id, key_id, store)
```

The tenant comes first on every id-taking call, so a key id from one product's URL can never
resolve a row in another tenant even if the id were guessed. An unknown id, a key in another
tenant and one already revoked are all `None`, so ids cannot be walked to learn which exist.

`kind` is free-form and defaults to `KIND_USER`. Nothing in the package interprets it; the
usual second kind is a service key whose subject is the tenant rather than a person, which
matters because it survives its minter leaving. `created_by` records who minted a key when
that is someone other than its subject, and is `None` rather than `""` when unrecorded, so
"not recorded" stays distinguishable from "recorded as nobody". `metadata` is a mapping the
store round-trips untouched.

A record written before any of this existed loads unchanged: the id comes back empty, the
kind defaults, the creator is `None` and the metadata is empty. `revoke_handle` is what a
caller reads for a handle either way, answering the `key_id` when there is one and the hash
when there is not, and `revoke_api_key_by_id` accepts both. Nothing is backfilled, so a
listing renders an id for a new key and a hash for an old one.

`count_for_tenant` is the cap check, and it is cheap enough to run on every create:
`DynamoApiKeyStore` answers it with a `Select="COUNT"` query on `tenant_id-created_at-index`,
which counts index entries server side and returns no items at all. It paginates, so a tenant
whose entries spill past 1 MB cannot be walked past its cap. Never a scan.

```python
if store.count_for_tenant(workspace.id) >= MAX_KEYS_PER_TENANT:
    raise HTTPException(status_code=409, detail=AT_LIMIT)
```

It counts every row, revoked ones included, because "how many rows exist" is what an index
counts cheaply and "how many are still usable" is not: revocation is an attribute rather than
a key, so counting around it would mean reading the rows. A product capping only live keys
subtracts them itself.

`get_by_id`, `revoke_by_id` and `count_for_tenant` are concrete rather than abstract on
`ApiKeyStore`, so a store written before they existed still satisfies the protocol; the
defaults are built on `list_for_tenant`, which means a store with no tenant index answers
nothing rather than scanning. `webbpulse.testing.assert_api_key_store_contract` holds a
product's own store to all of it from one test.

## Share tokens

`webbpulse.identity.share_tokens` is the third credential kind, beside a session JWT and an
API key. A share token opens a public read-only link: holding it is the whole of the
authorization, there is no account behind it, and it grants exactly what its stored row says.

The payload is opaque to the package. A product decides what a token opens and reads it back
out of `record.capability`, so this is not an issue tracker's share link, an album's share
link or a report's share link, but all three.

```python
from webbpulse.identity import DynamoShareTokenStore, mint_share_token

store = DynamoShareTokenStore(repository)
minted = mint_share_token(
    tenant_id=workspace.id,
    capability={"kind": "issue", "issue_id": issue.id, "project_id": issue.project_id},
    name="Design review",
    created_by=user.id,
    expires_in=timedelta(days=30),
    store=store,
)
return {"url": f"https://{host}/shared/{minted.plaintext}"}
```

`minted.plaintext` is the only time the token exists outside the store, exactly as with an API
key: 256 bits of CSPRNG entropy behind a `wps_` prefix, stored only as its SHA-256 and with no
clear-text fragment at all. Because the token normally lives in a URL it will reach browser
history and referrer headers, which is what `expires_in` and the revocation verb are for.

Keep the capability closed. It is the whole of what the token grants, so a bound that would
otherwise be a filter applied after the fact belongs in the row: name the one resource rather
than a query that could later widen.

`verify_share_token` answers `None` for every refusal, unknown, revoked and expired alike,
because the reader is anonymous and telling those apart says whether a guessed value ever
existed. `revoke_share_token` takes either the plaintext or the stored hash, and a store
offers `list_for_tenant`, `revoke_all_for_tenant` and `delete_all_for_tenant` for the settings
page and the tenant purge.

### Sharing a named target

`capability` is opaque, which leaves one question the package has to answer itself: "every
link onto this issue". A tenant-wide listing filtered afterwards would answer it, but it
would also fetch rows for targets the caller may not see, so the target is a first-class
field rather than a convention inside the payload.

```python
from webbpulse.identity import ShareTarget, mint_share_token

minted = mint_share_token(
    tenant_id=workspace.id,
    target=ShareTarget(type="issue", id=issue.id),
    capability={"project_id": issue.project_id, "title": issue.title},
    store=store,
)

links = store.list_for_target(workspace.id, ("issue", issue.id))
store.revoke_all_for_target(workspace.id, ("issue", issue.id))
```

It is stored flat, as `target_type` and `target_id` plus a `target_key` of `"<type>#<id>"`,
and `record.target` reads it back as a `ShareTarget`. A `(type, id)` pair is accepted
anywhere the value type is, because a product listing several targets usually has tuples in
hand. Everything else about what a token grants stays in `capability`.

`list_for_target` is one query on `tenant_id-target_key-index`, hash `tenant_id` and range
`target_key`, so the tenant bounds the read and the range key names the whole target: the
rows for that one resource come back and nothing else is read or paid for. Never a scan, and
never a tenant read with a filter. A caller holding several visible targets fans out over
exact keys, which is what keeps an invisible target's links from being fetched at all.
`revoke_all_for_target` is the verb for a resource being deleted or made private, built on
the listing so a store that cannot list revokes nothing and returns zero rather than
appearing to have succeeded.

The target is optional and the index is sparse: a token minted without one carries no
`target_key`, stays out of the index entirely rather than collecting under a degenerate key,
and resolves exactly as it always did. `list_for_target` is concrete on `ShareTokenStore`, so
a store written before it existed still satisfies the protocol, and
`webbpulse.testing.assert_share_token_store_contract` holds a product's own store to it.

`claims_or_credential` resolves all three kinds into one claims object, in the order JWT, API
key, share token, so the weakest is consulted only where neither stronger one arrived and
adding it cannot weaken a route that had an authorizer. It reads the token from the bearer
header or from the path, since a share link is a URL a browser opens and a browser cannot set
a header.

```python
from fastapi import Depends

from webbpulse.identity import claims_or_credential, share_token_capability

resolver = claims_or_credential(store=key_store, share_store=share_store, live_scopes=live)


@router.get("/shared/{token}")
def read_shared(claims: AuthorizerClaims = Depends(resolver)) -> SharedTarget:
    capability = share_token_capability(claims)
    ...
```

A share token's claims carry `sub` of `"share"`, the tenant, the capability and an `actor_kind`
of `share_token`, and deliberately no `scope`: `require_scopes` therefore refuses one outright,
which is the right default. A route that means to admit a share says so by reading
`share_token_capability`, which answers an empty mapping for a JWT and for a key, so it can be
read unconditionally. `is_share_token_actor` is there for the route that must refuse one.

The `share-tokens` table is in `TABLES` with the rest. Unlike `api-keys` it does carry a TTL on
`expires_at`: a share is a link a person hands out and forgets, so the table would otherwise
grow without bound and there is no owner for whom an expired share staying visible is worth
anything. Expiry is still enforced on the read path, because the sweep is not prompt.

### Terraform the identity module still needs

The `api-keys` tenant index ships in `platform-modules/aws//modules/identity` behind
`api_keys_table_enabled`. The `share-tokens` table is ahead of the module until it gains a
matching flag; until then a product using share tokens has no table at all.

`api-keys` carries one attribute and one GSI beyond its `key_hash` hash key:

| | |
| --- | --- |
| attribute | `tenant_id` (`S`) |
| index name | `tenant_id-created_at-index` |
| hash key | `tenant_id` |
| range key | `created_at` |
| projection | `ALL` |

`share-tokens` is a new table, with two indexes:

| | |
| --- | --- |
| attributes | `token_hash` (`S`), `tenant_id` (`S`), `created_at` (`S`), `target_key` (`S`) |
| hash key | `token_hash` |
| range key | none |
| projection | `ALL` on both indexes |
| TTL attribute | `expires_at` |
| billing | `PAY_PER_REQUEST` |

| index name | hash key | range key |
| --- | --- | --- |
| `tenant_id-created_at-index` | `tenant_id` | `created_at` |
| `tenant_id-target_key-index` | `tenant_id` | `target_key` |

`tenant_id-target_key-index` is sparse: `target_key` is written only when a row names a
target, so a token minted without one stays out of the index rather than collecting under a
degenerate key. Those index names and keys are a contract with the module, which provisions
the same two.

Adding a GSI to a live `api-keys` table is an online operation and no data has to be
backfilled: every row already carries `tenant_id`, because `mint` has always written it, so
rows appear in the new index as it builds.

### Migrating a product-local copy

Standupless keeps two shims this module replaces once the tables exist. `WorkspaceApiKeyStore`
and its `key_hash-index` go away: `ApiKeyRepository.list_for_workspace` becomes
`store.list_for_tenant(workspace_id)`, and `_check_tenant_binding` becomes `tenant_matches`
or `claims_or_api_key(tenant=...)`. `share_links.py` becomes `DynamoShareTokenStore`: `target_type` and
`target_id` become the record's own target, `project_id` and `title` move into `capability`,
and `ws_target-index` becomes `tenant_id-target_key-index`. The key splits differently, the
product's `<ws>#<type>#<id>` hash against the package's `tenant_id` hash with a `<type>#<id>`
range, and both scope a listing to one tenant and one target, so `list_for_target` and
`list_for_targets` map straight across. Existing `shr_` links do not migrate, since the
package hashes `wps_` tokens; re-mint them or read the old table until they expire.

On the key side, `ApiKey`'s `key_id`, `kind` and `created_by` are now on `ApiKeyRecord`,
`new_key_id` is `new_api_key_id`, `ApiKeyRepository.revoke(workspace_id, key_id)` is
`revoke_api_key_by_id`, and `count_for_workspace` is `count_for_tenant`, with the caveat that
the package's count includes revoked rows.
