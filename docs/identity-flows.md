# Identity standard: request flows

Section 2.6 of [the identity standard](identity-standard.md), split out for length. Every
statement here is normative and belongs to that standard. Back to the [README](../README.md).

### 2.6 Request flows

#### Password login, no MFA

1. `POST /login {email, password}`.
2. Rate limit by IP and by email; load the user by email.
3. `verify_password`, **always** against a dummy hash when the user or credential is absent.
4. Write a login attempt; write the refresh family and first token hash with a TTL.
5. `kms:Sign` the digest of `header.payload`.
6. `200 {access_token, expires_in}` plus `Set-Cookie` refresh.

Access token in the JSON body, **never** a cookie; refresh token in the cookie, **never** the
body: JavaScript MUST NOT be able to read it.

#### Password login, MFA required

Leg one returns **no access token**, but an MFA ticket: `typ` `mfa_ticket`, `aud`
`<issuer>/mfa`, a `sid` binding it to the pending session, plus the satisfiable factors.

1. `POST /login` returns `200 {mfa_required: true, mfa_ticket, factors: ["totp","passkey"]}`.
2. `POST /login/totp {mfa_ticket, code}`: verify the ticket (`typ`, `aud`, `exp`, `sid`), then
   the TOTP code in window.
3. `200 {access_token, ...}` plus `Set-Cookie` refresh.

The ticket MUST be rejected by every other audience, and is single use: its `jti` is recorded
and a replay refused. `POST /step-up` raises `amr` inside a session; sensitive routes MUST
assert on `amr`, not a boolean.

#### Passkey registration

1. `POST /passkeys/register/options` (bearer): store a challenge with a 300 second TTL keyed
   by user; return `PublicKeyCredentialCreationOptions`.
2. The SPA calls `navigator.credentials.create()`.
3. `POST /passkeys/register/verify {attestation}`: get and **delete** the challenge (single
   use), run `verify_registration_response(expected_rp_id, expected_origin)`, store
   `{credential_id, public_key, sign_count, transports}`, return 201.

COSE: Ed25519 (-8), ES256 (-7), RS256 (-257). A passkey name caps at 64 chars.

#### Passkey login, passwordless

`POST /login/passkey/options` then `/login/passkey/verify`. Options carry an **empty**
`allowCredentials` so the authenticator offers discoverable credentials. Verification looks
the credential up by `credential_id`, checks the signature, then the counter: **if the stored
counter is non-zero and the new one is not greater, the login MUST be refused** and a
`passkey.counter_anomaly` event raised (conditional on non-zero because some authenticators
always report zero).

Yields `amr` including `swk`, plus `pin` on user verification. A passkey with UV satisfies MFA
alone; without UV it counts as one factor.

#### OAuth link and login

1. `GET /oauth/{provider}/start`: store `{state, pkce_verifier, mode, return_to}` with a 600
   second TTL; 302 to the provider with `state` and `code_challenge`.
2. `GET /oauth/callback?code&state`: get and **delete** the state (single use, constant-time
   compare), exchange code plus verifier, read `id_token` or userinfo.
3. Look up the link by `provider_account_key`. Exists: issue a session, 302 to the frontend.
   No link but a provider-verified email matches a local user: attach the link. Neither:
   create the user (`email_verified` from the provider) and store the link.

**The link MUST only be made automatically when the provider asserts the email is verified**
(`email_verified` for Google, a verified primary address from the GitHub emails endpoint);
otherwise stop with `OAUTH_EMAIL_UNVERIFIED`, since attaching on email alone is takeover.
`mode` distinguishes a login from a link by an already-authenticated user, so a callback
cannot be replayed into the other meaning. `redirect_uri` MUST be checked against
`oauth_redirect_uris` by **exact string equality, never a prefix**. `provider_account_key` is
`"<provider>#<subject>"`. `OAuthService.unlink` MUST refuse to remove the last sign-in method
(`OAUTH_LAST_SIGN_IN_METHOD`), consulting `has_other_sign_in_method`.

#### Refresh rotation with reuse detection

A **family** is one login: `family_id`, user, device class, generation counter. Each refresh
token is a random 256-bit value; **only its SHA-256 hash is stored**. Rotation replaces the
hash and increments the generation.

`POST /refresh` (cookie only) does a conditional update on `hash(token)` to consume it:

- Succeeded: write the next hash at generation + 1, return `200 {access_token}` plus a new
  cookie.
- Failed, token matches a **consumed** generation: reuse. Revoke the **entire family**, 401
  with the cookie cleared.
- No such token: 401 with the cookie cleared.

The check and the consume MUST be one atomic operation: a single `UpdateItem` with a
`ConditionExpression`.

**Concurrent refresh is benign.** A consumed token replayed within `refresh_reuse_grace`
(default 10 seconds) returns the *same* successor the first call minted, stored on the
consumed record; beyond the window a replay is theft. Grace zero is stricter.

#### Logout

`POST /logout` revokes the **whole family**, not the single token, and clears the cookie;
revoking one token would leave a stolen sibling live. `POST /logout-all` revokes every family
for the user, which a password change calls.

**A logout cannot invalidate an already-issued access token**, which is why the lifetime is
short (3.2). Anything needing instant revocation MUST be enforced by the owning domain.

#### Email verification and password reset

One primitive: a single-use, time-limited link. `POST /verify-email` and `POST /reset` request
one; `POST /verify-email/confirm` and `POST /reset/confirm` consume one. Emailed links point
at the frontend paths `/verify-email` (`VERIFY_LINK_PATH`) and `/reset-password`
(`RESET_LINK_PATH`) with a `token` query parameter.

The token is 256 bits. **Only its hash is stored**; the email carries the raw value.
Verification hashes the presented value, looks it up, **checks the expiry in code as well as
the DynamoDB TTL**, and deletes it on use. TTL MUST NOT be treated as access control.

**Password reset MUST revoke every refresh family for that user on success.** Both request
endpoints MUST answer **identically whether or not the address exists** (5.4) and are rate
limited per address and per IP. A failed confirmation answers with
`CONFIRMATION_FAILED_MESSAGE`.
