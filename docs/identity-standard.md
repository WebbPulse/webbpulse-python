# The WebbPulse unified identity standard

The locked auth standard. Every product mounts `webbpulse.identity` and configures it.
MUST / MUST NOT / SHOULD are the contract.

---

## 1. Goals, non-goals, and the locked decisions

### 1.1 Goals

1. One implementation of every flow, mounted rather than copied.
2. A product configures capabilities through settings. It MUST NOT compose its own routes and
   MUST NOT subclass a router to change a flow.
3. Access tokens are verified by the JWT authorizer before any domain Lambda is invoked. A
   domain function reads claims and MUST NOT re-verify a signature.
4. The signing key is a KMS key. No signing secret exists in any environment variable,
   Secrets Manager value, or process memory.
5. Adoption invalidates no stored password hash and carries every passkey and TOTP enrolment
   across without re-enrolment.

### 1.2 Non-goals

No cross-product SSO; no central auth server (each product runs its own copy in its own AWS
account); no Cognito; no user migration or account linking across products; no OAuth
authorization server (Google and GitHub are consumed as identity sources; tokens are issued
only to the product's own first party frontend); no SCIM, directory sync or enterprise SSO.

### 1.3 The locked decisions

- **App-managed identity, not Cognito**, in each product's own `identity` domain Lambda, an
  OCI image on arm64 behind the Lambda Web Adapter.
- **Mandatory baseline in every product.** Password login with bcrypt via
  `webbpulse.security`; email verification and reset over SES with single-use links rate
  limited through `webbpulse.ratelimit`; TOTP with recovery codes; passkeys via py_webauthn,
  passwordless and as a second factor; OAuth with Google and GitHub linked to a local account.
- **Asymmetric tokens signed by KMS**, JWKS and OIDC discovery served by the identity
  function, rotation by `kid` with overlap.
- **Sessions.** A short-lived access token held in memory and never in `localStorage`, plus an
  httpOnly Secure SameSite refresh cookie with rotation and reuse detection, refresh tokens
  stored hashed with a TTL, logout revoking the whole family.
- **Storage in DynamoDB** through `webbpulse.dynamodb.Repository`, observability through
  `webbpulse.otel` and `webbpulse.logging`, errors through `webbpulse.http`.

---

## 2. Architecture

### 2.1 Components

`webbpulse.identity` is a flat module package: `settings.py` (`IdentitySettings`), `hooks.py`
(`IdentityHooks`, `BaseIdentityHooks`), `router.py` (`build_identity_router`,
`identity_prefix`, route path constants), `oauth_routes.py`, `passkey_routes.py`, `flows.py`
(`IdentityFlows`), `service.py` (`TokenService`), `tokens.py` (`KmsSigner`, `build_jwks`,
`build_discovery_document`, `kid_for_der`), `sessions.py` (`SessionService`), `passwords.py`,
`mfa.py` (`MfaService`), `totp.py`, `passkeys.py` (`PasskeyService`), `oauth.py`
(`OAuthService`), `verification.py` (`LinkService`), `crypto.py` (`EnvelopeCipher`,
`KmsDataKeyClient`), `email.py` (`EmailSender`, `SesV2EmailSender`), `lockout.py`,
`storage.py` (stores and table constants), `claims.py` (`authorizer_claims`,
`coerce_claims`).

- **Service modules import no FastAPI.** Every flow MUST be callable without a request object.
  Routers are thin: parse, call a service, render.
- **Storage subclasses `webbpulse.dynamodb.Repository`.** No ORM.
- **Nothing calls AWS at import.** KMS, SES and DynamoDB clients MUST be built on first use.

### 2.2 Where it runs

The identity app mounts into each product's `identity` domain Lambda under one prefix derived
from the issuer. `build_identity_router` is the only entry point:

```python
router = build_identity_router(
    identity_settings(),
    CarModPickerHooks(),
    oauth_client_secrets={"google": ..., "github": ...},
)
```

The discovery, JWKS, health, OAuth provider and passkey availability routes always mount; each
flow mounts only when its hooks and stores are supplied.

### 2.3 Public routes, authorized routes, and the authorizer

Paths are relative to the issuer prefix (normally `/api/auth`).

| Route | Authorizer |
|---|---|
| `POST /register`, `POST /login` | none |
| `POST /login/totp` (holds an MFA ticket, not an access token) | none |
| `POST /login/passkey/options`, `/login/passkey/verify` | none |
| `POST /refresh` (the cookie authenticates it) | none |
| `POST /logout`, `POST /logout-all` (MUST work with an expired access token) | none |
| `POST /verify-email`, `/verify-email/confirm`, `POST /reset`, `/reset/confirm` | none |
| `GET /oauth/{provider}/start`, `GET /oauth/callback` | none |
| `GET /oauth/providers`, `GET /passkeys/availability`, `GET /health` | none |
| `GET /.well-known/openid-configuration`, `GET /.well-known/jwks.json` | none |
| `POST /password` | bearer |
| `POST /totp/enrol`, `/totp/activate`, `/totp/disable` | bearer |
| `POST /recovery-codes`, `POST /step-up` | bearer |
| `POST /passkeys/register/options`, `/passkeys/register/verify` | bearer |
| `GET /passkeys`, `DELETE /passkeys/{credential_id}` | bearer |
| `POST /oauth/{provider}/link`, `GET /oauth/links` | bearer |

**The two discovery routes MUST be reachable without authentication and without the staging
access gate.** The authorizer fetches them holding no cookies; if a gate authorizer covers
them the JWT authorizer cannot fetch the JWKS and every authorized route fails closed.

An HTTP API attaches at most one authorizer per route, so the public and authorized halves of
the prefix cannot both sit under one greedy route key. The rule: **leave the whole identity
prefix unauthorized at the gateway and have the identity app verify its own bearer tokens**
for the authorized subset, via `TokenService` with the JWKS public key. The JWT authorizer
applies to **every other domain**.

A route key MUST NOT end in a slash: the failure is an apply-time `BadRequestException` while
the plan is green. Write `/api/auth`, never `/api/auth/`.

### 2.4 How a domain Lambda reads claims

A domain function MUST NOT verify anything. The Lambda Web Adapter forwards the request
context as **plain JSON** (not base64) in `x-amzn-request-context`; claims are at
`requestContext.authorizer.jwt.claims`. Every claim value arrives as a **string**, `exp` and
`iat` included, so `coerce_claims` converts them: `INTEGER_CLAIMS` is `exp`, `iat`, `nbf`,
`auth_time`; `BOOLEAN_CLAIMS` is `email_verified`; `ARRAY_CLAIMS` is `amr`, `roles`, `groups`,
`aud`.

```python
from webbpulse.identity import authorizer_claims

Principal = Annotated[AuthorizerClaims, Depends(authorizer_claims())]


@router.get("/api/build-lists")
async def list_build_lists(principal: Principal, repos: Repositories = Depends(...)):
    return repos.build_lists.for_user(principal["sub"])
```

- **`authorizer_claims()` MUST be the only parser of this header**, and MUST parse plain JSON.
- **It MUST distinguish "no header" from "unparseable header" from "no claims"**:
  `MissingRequestContext`, `UnparseableRequestContext`, `NoClaimsSection`, all subclasses of
  `ClaimsUnavailable`. None of the three is an anonymous caller.
- **It MUST NOT swallow a decode error into an empty mapping.**
- It raises 401 in the package envelope when the section is absent.

**Local seam.** `local_fallback=True` verifies the bearer token in-process against the JWKS.
It MUST be refused when `environment` is `production` or `prod`.

### 2.5 The staging access gate interaction

A gated staging API attaches a REQUEST authorizer to every route, and a route takes one
authorizer, so the JWT and gate authorizers MUST NOT both be attached to the same route.
Whatever the resolution: **the two `.well-known` routes MUST carry
`authorization_type = "NONE"` on every environment, gated or not.** API Gateway fetches
discovery when the authorizer is **created**, carrying no gate cookie and no origin-verify
header; behind the gate that fetch gets a 401 and `CreateAuthorizer` fails.

### 2.6 Request flows

The nine request flows (password login with and without MFA, passkey registration and
login, OAuth link and login, refresh rotation with reuse detection, logout, and email
verification and password reset) are normative and live in
[identity-flows.md](identity-flows.md).

---

## 3. Token design

### 3.1 The algorithm

**It MUST be RS256**: the JWT authorizer supports only RSA-based algorithms. `JWS_ALGORITHM`
is `RS256`, `KMS_KEY_SPEC` is `RSA_2048`, `KMS_SIGNING_ALGORITHM` is
`RSASSA_PKCS1_V1_5_SHA_256`.

- **PKCS1 v1.5, not PSS.** Signing with PSS and labelling it RS256 verifies nowhere.
- **RSA_2048, not larger.** A 4096-bit key means a slower `kms:Sign` on the hot path.

### 3.2 Claims and lifetimes

| Claim | Value | Note |
|---|---|---|
| `iss` | `https://api.<domain>/api/auth` | MUST exactly match the authorizer's issuer |
| `sub` | the user's `id` | see 3.3 |
| `aud` | `<product>-api` | matched by the authorizer |
| `exp` | `iat` + 10 minutes | |
| `iat`, `nbf` | issue time | the authorizer checks both |
| `jti` | random | audit correlation, not revocation |
| `sid` | the refresh family id | ties a token to its session |
| `typ` | `access` | **mandatory**, asserted positively by every verifier |
| `amr` | e.g. `["pwd","otp"]` | `pwd`, `otp`, `mfa`, `recovery`, `swk`, `pin`, `oauth` |
| `roles` | e.g. `["admin"]` | from the product's hooks, never invented here |
| `scope` | space-delimited | so a route can use `authorizationScopes` |
| `email`, `email_verified` | convenience | |

**Every token MUST carry `typ`, and every verifier MUST assert the value it expects.** A
missing `typ` is a rejection, never a default: one signing key covers several purposes
(`ACCESS_TOKEN_TYPE` = `access`, `MFA_TICKET_TYPE` = `mfa_ticket`). `REGISTERED_CLAIMS`
(`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `typ`, `sid`) are owned by the token service:
any returned from a hook MUST be dropped.

`exp` is **10 minutes**, capped at one hour by `MAX_ACCESS_TOKEN_TTL`. The refresh cookie is
**30 days rolling**, reset on each rotation, absolute cap **90 days**; `refresh_absolute_ttl`
MUST NOT be shorter than `refresh_token_ttl`. MFA ticket **5 minutes**, `aud` `<issuer>/mfa`,
single use. Verification links **24 hours**, reset links **1 hour**. `clock_skew_leeway` is 30
seconds.

### 3.3 What `sub` is

`sub` MUST be the user's immutable `id`, not the username and not the email. A rename would
otherwise invalidate every live token, and a reused username would inherit its sessions.

### 3.4 JWKS and discovery

**Both documents are served under the issuer's path, not at the origin.** For an issuer of
`https://<host>/api/auth`:

```
GET /api/auth/.well-known/openid-configuration
GET /api/auth/.well-known/jwks.json
```

`build_identity_router` derives the prefix from `settings.issuer` via `identity_prefix`, so a
product MUST mount the router with **no prefix of its own**. An issuer with no path gives the
origin paths; both are supported.

`JWKS_PATH` returns a `keys` array per RFC 7517. Each RSA verification key:

```json
{
  "kty": "RSA",
  "use": "sig",
  "alg": "RS256",
  "kid": "<see 3.5>",
  "n": "<base64url of the modulus, big-endian, unpadded>",
  "e": "AQAB"
}
```

`n` and `e` come from `kms:GetPublicKey`, a DER SubjectPublicKeyInfo; `public_jwk_from_kms`
parses it once and caches the JWK for the execution environment's life.

`DISCOVERY_PATH` returns the five members OIDC Discovery requires: `issuer`, `jwks_uri`,
`response_types_supported`, `subject_types_supported`,
`id_token_signing_alg_values_supported`. **`issuer` MUST be byte-identical to the `iss` claim
and the authorizer's configured issuer**; `IdentitySettings` strips trailing slashes from
`issuer` and `frontend_base_url`. The issuer MUST be absolute `http(s)` with no query or
fragment; `http` only in `local` and `test`.

Discovery is cached `public, max-age=3600` (`DISCOVERY_CACHE_CONTROL`), the JWKS
`public, max-age=300` (`JWKS_CACHE_CONTROL`).

**API Gateway fetches both at `CreateAuthorizer` time**, not only when a request is verified.
The authorizer cannot be created unless discovery already answers with a valid document and
the advertised `jwks_uri` answers **anonymously**.

**The key cache is per authorizer host**, so both routes are on the **hot path**, not just the
deployment path.

**Deployment ordering.** Nothing in the authorizer's arguments implies the dependency:

- The `.well-known` routes and their function MUST come **before** the authorizer, by explicit
  `depends_on`.
- The discovery routes MUST be declared **separately** from protected routes. One `for_each`
  over both makes the whole map wait on the authorizer, and every route is skipped.
- `depends_on` orders API calls, not their effects. **Poll the live discovery URL between the
  two.**

### 3.5 How `kid` is chosen, and rotation

`kid` is the **base64url of the SHA-256 of the DER SubjectPublicKeyInfo** from
`kms:GetPublicKey` (`kid_for_der`). It MUST NOT be the KMS key id or ARN: that would put an
AWS account number in a public document and would not change with the key material.

Rotation is by **adding a key, not mutating one**. KMS automatic key rotation MUST NOT be used
for the signing key: old tokens would reference a `kid` no longer served.

1. Create `identity-signing-<n+1>`. `IDENTITY_SIGNING_KEY_ARNS` lists both, active first.
2. Deploy. JWKS serves **both**. Nothing signs with the new key yet.
3. Wait **three hours** (API Gateway can cache the public key for two).
4. Promote the new key to active signer and deploy. The old key is still served.
5. After one access-token lifetime plus margin, drop the old key and deploy. Schedule the KMS
   key for deletion no sooner than 30 days later.

Steps 2 and 4 MUST be separate deploys: serving a `kid` nothing has signed with is harmless,
signing with a `kid` not yet in every cache is an outage.

`signing_key_arns` MUST name at least one key, MUST NOT exceed `MAX_SIGNING_KEYS` (4), and
MUST NOT contain duplicates. Every key listed is trusted to verify, so a retired key left
there is still a live signer's key. `active_signing_key_arn` is the first entry;
`previous_signing_key_arns` is the rest.

### 3.6 Signing mechanics

Signs with **`MessageType: DIGEST`** (`DIGEST_MESSAGE_TYPE`): the SHA-256 of
`base64url(header) + "." + base64url(payload)` is sent as a 32-byte digest, removing the
4096-byte `Message` limit. `SigningAlgorithm` stays `RSASSA_PKCS1_V1_5_SHA_256`; KMS skips only
the hashing, not the padding. The signature is the raw PKCS #1 octet string JWS wants,
base64url-encoded as-is. One `kms:Sign` per issued access token.

Token minting MUST be refused in `production` and `prod` where a non-KMS test path would
otherwise be used (`TokenMintingDisabled`); `mint_test_token` is for tests only.

```json
{"alg": "RS256", "typ": "JWT", "kid": "<base64url sha256 of the DER>"}
{"typ": "access", "sub": "<user id>", "iss": "https://api.example.com/api/auth",
 "aud": "example-api", "iat": 1788935958, "nbf": 1788935958,
 "exp": 1788936558, "jti": "a1a1818c2f364e1396951d1cd5382801"}
```

The in-process fallback verifier (2.4) MUST reject, as the gateway does: a signature with one
character changed, `alg: none` with the signature segment removed, and HS256 signed with the
JWKS public modulus as the secret (algorithm confusion, prevented by the `alg` allowlist).

**In the access log the status code alone lies**: both an accepted and a rejected request can
end as a 401. `integrationLatency` separates them: a rejected request never reaches the
integration, so the field is empty and the body is the gateway's `{"message":"Unauthorized"}`.

---

## 4. Data model

The per-entity tables, their keys and indexes, every TTL, and the TOTP seed envelope
encryption rules are normative and live in
[identity-data-model.md](identity-data-model.md).

---

## 5. Security controls

### 5.1 Rate limits and lockout

Rate limiting protects the service; lockout protects an account. Limits use
`webbpulse.ratelimit`, whose `namespace` keeps counters independent.

| Route | Key | Limit | Constant |
|---|---|---|---|
| login | IP | 20 / 15 min | `LOGIN_IP_LIMIT` |
| login | email | 10 / 15 min | `LOGIN_EMAIL_LIMIT` |
| refresh | IP | 120 / 15 min | `REFRESH_IP_LIMIT` |
| register | IP | 5 / hour | `REGISTER_IP_LIMIT` |
| reset request | email | 3 / hour | `RESET_EMAIL_LIMIT` |
| reset request | IP | 10 / hour | `RESET_IP_LIMIT` |
| verification resend | email | 3 / hour | `VERIFY_EMAIL_LIMIT` |
| verification resend | IP | 10 / hour | `VERIFY_IP_LIMIT` |
| TOTP verify | user | 10 / 15 min | `TOTP_VERIFY_LIMIT` |
| TOTP enrol | IP | 10 / hour | `TOTP_ENROL_IP_LIMIT` |
| passkey options | IP | 30 / 15 min | `PASSKEY_OPTIONS_LIMIT` |
| passkey login | IP | 30 / 15 min | `PASSKEY_LOGIN_LIMIT` |
| passkey register | IP | 10 / hour | `PASSKEY_REGISTER_LIMIT` |
| OAuth start | IP | 20 / 15 min | `OAUTH_START_IP_LIMIT` |

Login MUST be limited by **both** IP and email: by IP alone a distributed attacker walks past
it; by email alone one attacker can lock out a known user.

**Lockout is progressive, not binary.** After `LOCKOUT_THRESHOLD` (5) consecutive failures
within `LOCKOUT_LOOKBACK` (24 hours), a delay doubles from `LOCKOUT_BASE_DELAY` (1 second) to
`LOCKOUT_MAX_DELAY` (15 minutes), cleared by any success. A hard lock MUST be avoided: it hands
the attacker a denial-of-service tool. **Passkey and OAuth logins MUST NOT be blocked by
password lockout.**

The limiter **fails open** by design, logging `rate_limit_failed_open=True` at WARNING.
Identity SHOULD alarm on that line: a limiter failing open unnoticed is the state in which
credential stuffing is invisible.

### 5.2 Credential stuffing

- **Breach corpus check on set.** Optional, off by default (`password_breach_check`). Checked
  at registration, change and reset using k-anonymity (send the first 5 hex of the SHA-1,
  compare suffixes locally) so the password never leaves the service. Fails open with a
  WARNING.
- **Global anomaly signal.** `login-attempts` is keyed by both email and IP, so a spike in
  distinct emails from one IP, or one email from many IPs, is a query.

### 5.3 Constant-time comparison

**Every comparison of a secret MUST use `hmac.compare_digest`** (`constant_time_equals`):
recovery codes, token hashes, OAuth state, TOTP codes. A `==` on any of these is a timing
oracle.

`webbpulse.security.verify_password` is constant-time in bcrypt's comparison but **not** across
the no-hash case: returning `False` immediately is measurably faster than running bcrypt. When
no user is found, or the user has no password credential, `equalise_password_timing` MUST
verify against a **fixed dummy bcrypt hash** and discard the result, so both paths cost one
bcrypt verification.

### 5.4 Enumeration resistance

| Endpoint | Response |
|---|---|
| login, wrong password | 401, `INVALID_CREDENTIALS_MESSAGE` |
| login, no such user | 401, identical body, after the dummy hash verification |
| register, email taken | 200, plus an email to the existing address (`render_registration_notice`) |
| reset request | 200 always, `RESET_REQUESTED_MESSAGE` |
| verification resend | 200 always |

Registration MUST NOT say "that email is taken". Residual leak, accepted: rate limit counters
are per email, so existence is still inferable from a 429 boundary.

### 5.5 The refresh cookie: attributes, CSRF, CORS

Frontend and API sit under one registrable domain, so `www.<domain>` to `api.<domain>` is
**cross-origin but same-site**:

```
Set-Cookie: wp_refresh=<token>; Domain=<registrable domain>; Path=/api/auth;
            HttpOnly; Secure; SameSite=Lax; Max-Age=2592000
```

- `httponly` is **always `True`**: a control, not a setting.
- `SameSite=Lax` is available only because of the shared parent domain; it withholds the cookie
  from cross-site subresource requests including `fetch`, the CSRF vector. `None` is required
  only for a frontend on a different registrable domain than its API.
- **`cookie_samesite="none"` requires `cookie_secure=True`.** Browsers reject `SameSite=None`
  without `Secure`; the symptom is a login that appears to succeed and never persists.
  `IdentitySettings` refuses the combination.
- **`cookie_domain` MUST NOT have a leading dot** and MUST NOT be a single label other than
  `localhost`. Empty makes it host-only, correct locally.
- **`cookie_path` MUST be absolute.** Unset it derives from the issuer's path, so the cookie
  reaches exactly the routes that spend it.

**CSRF posture.** `SameSite=Lax` is primary, with two supplements:

1. `/refresh` and `/logout` MUST require a `Sec-Fetch-Site` in `ALLOWED_FETCH_SITES`
   (`same-origin`, `same-site`, `none`) when present; otherwise refuse with
   `CROSS_SITE_REQUEST`. The header cannot be set by page JavaScript.
2. The refresh response body carries the access token, which an attacker's page cannot read
   cross-origin. This is why no synchroniser token is specified.

**CORS.** `create_app` already refuses credentials with a wildcard origin. Origins stay the
exact list each product configures and `allow_credentials` stays `True`.

### 5.6 Password policy

NIST SP 800-63B shaped:

- **Minimum 8 characters** (`MIN_PASSWORD_CHARACTERS`), else `PASSWORD_TOO_SHORT`.
- **No composition rules.** **No periodic expiry**; rotation only on evidence of compromise.
- **All Unicode accepted**, normalised to NFKC (`normalise_password`) before hashing.
- **Breach list check** on set (5.2), only when a product opts in.

**The 72-byte bcrypt limit.** bcrypt reads at most 72 bytes, so `webbpulse.security` truncates
to 72 on a byte boundary in both `hash_password` and `verify_password`. A truncated password
shares a hash with every other password having the same first 72 bytes, so **passwords MUST be
rejected above `MAX_PASSWORD_BYTES` (72) of UTF-8** at registration, change and reset, with
`PASSWORD_TOO_LONG` and a message about bytes rather than characters (a 64-character emoji
password exceeds it). Accepting longer would mean pre-hashing with SHA-256, invalidating every
existing hash.

`needs_rehash` runs after every successful verification, upgrading cost on login.

### 5.7 Audit events

Written to `login-attempts` where they concern a login, and **always** emitted as a structured
log line through `webbpulse.logging`.

`login.success`, `login.failure`, `login.locked`, `mfa.challenge`, `mfa.success`,
`mfa.failure`, `totp.enrolled`, `totp.disabled`, `recovery.used`, `recovery.regenerated`,
`passkey.registered`, `passkey.removed`, `passkey.counter_anomaly`, `oauth.linked`,
`oauth.unlinked`, `oauth.login`, `password.changed`, `password.reset_requested`,
`password.reset_completed`, `email.verification_sent`, `email.verified`, `session.refreshed`,
`session.reuse_detected`, `session.revoked`, `session.logout_all`.

Each carries `user_id`, `request_id`, source IP, a coarse user-agent class, and the outcome.
**No event carries a token, code, seed, or password**, hashed or otherwise.

`session.reuse_detected` and `passkey.counter_anomaly` SHOULD page rather than merely log.

### 5.8 Secret handling

One JSON secret per service per environment, `webbpulse-<env>/app`, resolved through
`APP_SECRETS_ARN` and `load_json_secret`, cached per ARN for the process lifetime and **never
called at import**. Identity adds `google_client_secret` and `github_client_secret` to it.

**Secrets MUST NOT be `IdentitySettings` fields.** Client secrets are passed to
`build_identity_router` as `oauth_client_secrets`, resolved from `load_json_secret` at request
time. There is deliberately **no JWT signing secret**.

IAM for the identity function: `kms:Sign` and `kms:GetPublicKey` on the signing key,
`kms:Encrypt`/`kms:Decrypt`/`kms:GenerateDataKey` on the data key with the encryption-context
condition, `ses:SendEmail`, DynamoDB read/write on its own tables. **No other function gets
`kms:Sign`.**

### 5.9 Threat model

| Threat | Control | Residual |
|---|---|---|
| Password guessing, one account | Per-email limit, progressive delay, optional breach check | Slow low-volume guessing |
| Credential stuffing, distributed | Per-IP and per-email limits, anomaly data | A clean IP pool plus a valid password succeeds; MFA is the answer |
| Stolen access token | 10-minute lifetime, `aud` scoped per product | Valid until expiry; cannot be revoked (2.6) |
| Stolen refresh cookie | httpOnly, Secure, Lax, Path-scoped; rotation with reuse detection | Attacker who refreshes first wins; the victim's next attempt kills the family |
| XSS in the SPA | Access token in memory only, refresh cookie httpOnly | XSS can still call the API while the page lives |
| CSRF on refresh or logout | SameSite=Lax, `Sec-Fetch-Site` check, unreadable response | Very old browsers without either signal |
| Database read | bcrypt hashes, hashed tokens and codes, KMS-encrypted seeds | Passkey public keys and emails exposed; neither is a credential |
| Signing key theft | Material never leaves KMS; only `kms:Sign` granted | The identity role can mint tokens; CloudTrail on `kms:Sign` detects |
| OAuth account takeover | Automatic linking only on a provider-verified email | A provider that wrongly asserts verification |
| Passkey cloning | Signature counter check with anomaly event | Authenticators that always report 0 |
| Enumeration | Uniform responses, dummy-hash timing equalisation | Rate-limit boundaries still differ (5.4) |
| MFA bypass by skipping leg two | Leg one issues only an `aud`-scoped single-use ticket | None known |
| Token confusion across purposes | Mandatory `typ` asserted positively, plus `aud` separation | None known |
| Reset link interception | 1-hour single-use hashed token; success revokes all sessions | Mailbox compromise |
| Verification link replay | Hash stored, deleted on use, checked in code as well as TTL | None known |

---

## 6. Configuration surface

`IdentitySettings`, how the router is mounted, and **section 6.3, `IdentityHooks`, the
product's own policy**, are normative and live in
[identity-configuration.md](identity-configuration.md).

---

## 7. Frontend contract

The frontend contract, `@webbpulse/auth`, `@webbpulse/api-client` and the error contract
with its error codes, is normative and lives in
[identity-frontend.md](identity-frontend.md).
