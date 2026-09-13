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
import boto3
from webbpulse.identity import IdentitySettings, TokenService, build_identity_router

settings = IdentitySettings()  # reads IDENTITY_* from the environment
tokens = TokenService(settings, boto3.client("kms"))

# One per execution environment: it caches a JWK per configured key.
app.include_router(build_identity_router(settings, hooks, stores, tokens=tokens))
```

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

**A TOTP seed is never stored in the clear.** Each one is sealed under its own KMS data key
with `{"user_id", "purpose"}` as the encryption context, so a ciphertext moved to another
user's row fails to decrypt, and reading a seed needs both table access and `kms:Decrypt`.
Set `IDENTITY_DATA_KEY_ARN` to a symmetric key, distinct from the signing key. Recovery codes
are the opposite case and are SHA-256 hashed rather than encrypted: verification only ever
compares them.

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
