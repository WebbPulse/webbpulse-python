# Identity: OAuth sign-in and account linking

Federated sign-in and account linking against Google and GitHub: the routes, the state and
link tables, and the rules about attaching and detaching a provider. The rest of the identity
package is in [identity.md](identity.md); the normative contract is in
[the identity standard](identity-standard.md). Back to the [README](../README.md).

## OAuth

**An OAuth identity attaches to an existing account only when both emails are verified.**
The provider's must be verified and the local account's must be verified, and either one
alone is not enough. Both halves are a takeover: an attacker who registers a GitHub account
with somebody else's address would inherit that account if only the local side were checked,
and an attacker who registers locally with a victim's address and never verifies it would be
handed the victim's real Google identity if only the provider side were checked. When the
rule refuses, the answer is `OAUTH_EMAIL_UNVERIFIED` and the user signs in with their
password and links from account settings, which needs no email check at all because they
have proved they hold both sides. The refusal says the same sentence whichever half failed,
because naming it would enumerate accounts and their verification state.

**Unlinking counts what would remain, and refuses to leave nothing.** Removing the last
sign-in method is permanent lockout: nobody can log in, so nobody can add a method back, and
the account is unreachable by any path this design has. Another OAuth link, a password in
the credential store, or a `True` from the `has_other_sign_in_method` hook each count as
remaining. **That hook is new in 0.14.0 and defaults to `False`**, so a hooks class written
before M6 keeps working: `False` can only make the refusal fire more often, while `True`
would let a product that had not implemented it delete a user's last credential. A product
holding sign-in methods this package cannot see, passkeys among them, should implement it.

### What the frontend calls, and what comes back on the callback

Two things a client needs and cannot work out for itself: which providers to draw buttons
for, and what the browser will be carrying when it lands back on the frontend.

**Ask `GET /api/auth/oauth/providers` which providers exist.** It is anonymous, cheap and
cached for five minutes, and it answers:

```json
{"providers": [{"id": "google", "display_name": "Google"}, {"id": "github", "display_name": "GitHub"}]}
```

Render one button per entry, in the order given, labelled with `display_name`, pointing at
`/api/auth/oauth/{id}/start`. The order is fixed by the package rather than by configuration,
so the layout is the same in every environment.

**Do not infer availability by probing `start`.** That was the pre-0.16.0 workaround and it
is wrong twice: it spends the start route's rate limit budget, 20 per 15 minutes per IP, on
page loads rather than on sign-ins, so a user who reloads the sign-in page enough times is
refused the sign-in they then attempt; and a non-200 cannot tell "not configured" from
"configured and briefly broken", so a transient failure hides a sign-in button. The route
mounts in **every** deployment, answering `{"providers": []}` where OAuth is off, so an empty
list is a real answer and never a 404 to interpret.

A provider is listed only when it has both a client id and a client secret. From 0.16.0 a
provider with an id and no secret is refused by `start` with a 503 and
`OAUTH_PROVIDER_UNAVAILABLE` rather than redirecting the user to the provider and failing at
the token exchange on the way back.

**The callback comes back to the frontend as a redirect carrying one query parameter.** The
callback never renders JSON, because the user is looking at a browser and a JSON error body
renders as text on a blank page. The frontend route named by `return_to`, or
`frontend_base_url`, should branch on whichever of these is present:

| Parameter | Meaning | What the frontend does |
| --- | --- | --- |
| `oauth=1` | A login succeeded. The refresh cookie is set on this redirect. | Call `POST /api/auth/refresh` for an access token, then continue |
| `oauth_linked=1` | A `link` succeeded for the signed-in account | Refresh the settings page's linked-provider list |
| `mfa_ticket=<ticket>` | The account has a second factor | Prompt for a code and `POST /api/auth/login/totp` with `{mfa_ticket, code}` |
| `oauth_error=<code>` | The flow was refused | Render a message for the code |

It is the only identity route that appears in the OpenAPI document, tagged `identity` and
`oauth`. The `.well-known` documents are `include_in_schema=False` because API Gateway
fetches them rather than a client writing against them; this one every frontend writes
against, so it belongs in `/docs`.

`oauth_error` carries one of this package's own error codes, never a provider string, so
nothing attacker-influenced reaches the URL. The ones worth handling by name are
`OAUTH_CANCELLED`, which is the user pressing Cancel on the consent screen and deserves no
error styling at all, and `OAUTH_EMAIL_UNVERIFIED`, which means the user should sign in with
their password and link from account settings. Anything else is a generic failure.

**The state is server-side, single use, and spent by a conditional delete.** `oauth-states`
is keyed on `state` with a ten minute TTL, and the callback spends the row with a
`DeleteItem` carrying `attribute_exists(state)` and `ReturnValues=ALL_OLD`, so two concurrent
callbacks cannot both succeed. TTL is storage reclamation and never access control: DynamoDB
deletes on its own schedule and an expired row stays readable for days, so expiry is
re-checked on every read. Every state failure, unknown, expired or already spent, answers
with one message and one code, because distinguishing them confirms to an attacker that a
guess found a real row.

**PKCE where the provider supports it, and a nonce where there is an ID token.** Google gets
an S256 challenge and a nonce; GitHub's web flow documents neither, and sending a challenge
it ignores would be security theatre. The verifier is written to the state row and never put
in the authorization URL, since a verifier the browser can read protects against nothing.
Google's ID token is verified properly: the signature against the published JWKS, then
`iss`, `aud`, `exp` and the `nonce` this flow generated. The JWKS is fetched through the
module's own HTTP client rather than `PyJWKClient`, which fetches with `urllib` and no
timeout, and a provider that accepts a connection and never answers would otherwise hold a
Lambda execution environment open until the function times out.

**GitHub's identity needs two calls, and only the second one is trustworthy.** `/user` gives
the subject, but its `email` is the public profile address: user-chosen and never verified.
`/user/emails` is the only place GitHub says which address it confirmed, and since the
auto-link rule turns on that being a real assertion, the verified primary is preferred and an
unverified address is reported as unverified rather than dropped.

**The callback issues exactly what a password login issues, MFA included.** Same token pair,
same rotating refresh family, same httpOnly cookie, through the same `_issue` path, so an
OAuth session is not a second kind of session with its own rules. When the account has TOTP
enabled the callback returns the `mfa_required` challenge instead of tokens: a provider
proving who somebody is does not prove possession of their second factor, and without this
"add Google to your account" would be a way to turn MFA off. The access token carries
`amr: ["oauth", "<provider>"]`, both the general fact and the specific one, so a policy can
require any federated sign-in or Google in particular.

**Client secrets are arguments, not settings, and are never logged.** They arrive as
`oauth_client_secrets` on `build_identity_router` because they come from the product's own
Secrets Manager JSON, not from an `IDENTITY_`-prefixed environment variable, and keeping them
out of the settings object keeps them out of anything that renders it. A missing secret
answers 503 with a message that names no configuration; the operator gets the detail in a log
line instead of the anonymous caller.

**Redirect URIs are matched by exact string equality against an allow-list.** The
`redirect_uri` is where a provider sends a live authorization code, so an unvalidated one is
the open-redirect half of an OAuth flow. A prefix match would admit
`https://app.example.com.attacker.test`, which is a domain an attacker can register today.
`oauth_redirect_uris` empty means the single derived `<issuer>/oauth/callback`. The value is
checked when it enters the state table rather than when it is used, so a stored row is safe
to act on without re-deriving trust, and the exact value is replayed on the token exchange
because providers refuse an exchange that differs by a byte.

**`oauth-links` is keyed on `provider#subject` with a `user_id-index` GSI**, rather than a
second table keyed by user. A second table would need two writes kept in step with no
cross-table transaction available on `Repository`, and a half-failed pair leaves an orphaned
link that `unlink` cannot find; a GSI cannot disagree with its base table. The price is
eventual consistency, so the last-method count re-reads the base table by primary key for
each candidate before counting it, because over-counting there is the one direction that
permanently loses an account. Attaching an identity is a conditional put on
`attribute_not_exists(provider_subject)`, so a race resolves to one winner rather than
silently moving a provider identity between accounts. This diverges from section 4.2 of
`docs/identity-standard.md`, which sketches a hash of `id` with two GSIs; the key here is the
uniqueness constraint itself, which needs no synthetic reservation rows to enforce.

**No provider tokens are stored.** Neither the access token nor the refresh token from the
provider is written down. This design consumes a provider as an identity source and never
calls a provider API on the user's behalf afterwards, and a stored token nobody spends is a
stored credential with no use, which is all cost.

**Passwords follow NIST SP 800-63B.** Eight character minimum, no composition rules, no
expiry, NFKC normalised, and a rejection rather than a silent truncation over 72 UTF-8
bytes. That last cap is bcrypt's, and the message says bytes because a 64 character
password of emoji is well over it.

**Every authorizer claim arrives as a string**, `exp` and `iat` included. That is a verified
finding from the M0 staging spike, and it is why `authorizer_claims` exists rather than a
dictionary access: `exp > time.time()` on a string raises `TypeError`, and `bool("false")`
is `True`. It coerces integers, booleans, space-separated scopes and the bracketed comma
form the gateway emits for array claims, and keeps the raw map on `.raw`.

**Rotation is a list, and its head signs.** `signing_key_arns` puts every configured key in
the JWKS and signs with the first, so each step of section 3.5 is a one-line change: add the
new key, deploy, move it to the front, deploy, drop the old one once no token it signed can
still be alive. A token signed by a previous key verifies for as long as that key is listed.
A `kid` matching no configured key is rejected rather than falling back to trying every key,
which would quietly undo the retirement.

**A key whose `kms:GetPublicKey` fails is omitted from the JWKS rather than failing it.** A
retired key id left in configuration must not deny every authorized request in the product.
Every key failing is still fatal, because an empty JWKS would be cached by the gateway and
deny everything for its whole interval.

**The stores hash what they hold.** Only the SHA-256 of a refresh or verification token is
stored, so a read of the table cannot be turned into a working session. `consume` is one
conditional `UpdateItem` returning the prior state rather than a read followed by a write,
because two concurrent refreshes both reading an unconsumed record is exactly the condition
reuse detection exists to notice.

**RS256, and there was no choice.** The API Gateway documentation for HTTP API JWT
authorizers says, in the token validation workflow, "Check the token's algorithm and
signature by using the public key that is fetched from the issuer's `jwks_uri`. Currently,
only RSA-based algorithms are supported." ES256 is ECDSA and so is excluded. The KMS key is
`RSA_2048` with `RSASSA_PKCS1_V1_5_SHA_256`, not a PSS variant: JWA binds `RS256` to
PKCS1 v1.5, and a PSS signature under an `RS256` header verifies nowhere.

**The private key never leaves KMS.** `KmsSigner` hashes the JWS signing input itself and
calls `kms:Sign` with `MessageType="DIGEST"`, which the KMS documentation describes as
skipping "the hashing step in the signing algorithm". That keeps the request 32 bytes and
puts the 4096 byte `Message` limit permanently out of scope. The returned RSA signature is
"defined by PKCS #1 in RFC 8017", which is exactly what JWS wants, so it is base64url
encoded as-is.

**`kid` is the base64url SHA-256 of the DER SubjectPublicKeyInfo**, so it is a pure function
of the key material: stable across redeploys, identical in every process, and never an AWS
account identifier in a public document. Rotation is by adding a second key rather than
mutating one, and the JWKS serves both through the overlap.

**Both `.well-known` routes must be reachable with no authorizer at all**, including no
staging access gate. API Gateway fetches them itself, holding no cookies. A gate in front of
either one means the JWT authorizer cannot retrieve the key and every authorized route fails
closed.

`verify_access_token` verifies a token locally against the configured keys. It is **not**
the production path: behind API Gateway the authorizer has already checked the signature,
issuer, audience and expiry before the Lambda runs, and re-verifying would add a JWKS lookup
to every request to re-establish what the platform guarantees. It exists for tests and for a
service that verifies a token itself.

`mint_test_token` signs an access token without authenticating anybody, for exercising an
authorizer end to end. It has two independent gates: an `enabled` argument with no default,
so no call site is accidental, and a refusal on `environment` of `production` on top of
that, so one flag left true in the wrong place is still refused. It raises
`TokenMintingDisabled`, which is named for the condition rather than the helper because
pytest collects any class named `Test*`.
