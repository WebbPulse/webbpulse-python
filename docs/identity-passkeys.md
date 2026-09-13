# Identity: passkeys

WebAuthn registration, passwordless sign-in, credential management, and the two tables the
Terraform platform module creates for them. The rest of the identity package is in
[identity.md](identity.md); the normative contract is in
[the identity standard](identity-standard.md). Back to the [README](../README.md).

## Passkeys

**The two passkey tables the Terraform platform module has to create.** The identity module
already creates `users`, `credentials`, `refresh-tokens`, `identity-tokens`, `login-attempts`,
`totp-factors` and `recovery-codes`; M5 adds two more, and the names and key shapes here are
the contract between that module and this package.

| Table | Hash key | Range key | Index | TTL attribute |
| --- | --- | --- | --- | --- |
| `passkeys` | `user_id` | `credential_id` | `credential_id-index` on `credential_id` | **none** |
| `webauthn-challenges` | `challenge_id` | none | none | `expires_at` |

`passkeys` is keyed the way it is because the management page reads its own writes: listing
a user's credentials must be a `query` on the base table, which is consistent, rather than
on a GSI, which cannot be. The login lookup goes the other way, from a credential id to its
owner, and that one tolerates eventual consistency because a credential that has just been
registered is not being signed in with in the same instant. There is deliberately **no TTL**
on it: a passkey is removed when its owner removes it and never on a timer.

`webauthn-challenges` carries the TTL, on `expires_at`, and the attribute name is part of
the contract. Pointing the module at a different attribute would not break anything visibly,
because expiry is enforced in code on every read regardless: the rows would simply never be
reclaimed and the table would grow forever. TTL here is storage reclamation, not access
control, which is the same rule every other expiring table in this package follows.

**A passkey challenge is a row, and that is the point of M5.** A challenge exists to make an
assertion unreplayable, which is a claim about state that a signed token cannot make: a JWT
verifies exactly as well the second time as the first, so a captured options-and-assertion
pair replays for the whole of the token's lifetime and adjusting that lifetime only moves
the window. So a challenge is written when options are generated, deleted when it is
consumed, and refused once its five minute deadline has passed whether or not DynamoDB has
reclaimed the row. It is spent by one attempt whatever the outcome, so a stolen challenge
cannot be ground against.

**A user-verified passkey counts as two factors, and a user with TOTP enrolled is not asked
for a code.** A passkey login sets `amr` to `["swk"]` when the authenticator did not verify
the user and `["swk", "pin", "mfa"]` when it did, both RFC 8176 registered values. The
assertion proves possession of a private key that never leaves the authenticator, and the
`uv` flag proves the authenticator separately checked something the user knows or is before
it would sign: possession plus knowledge or inherence, in one gesture. A passkey that reports
no user verification proves possession only, so it is one factor and **is** challenged for a
second exactly as a password is, returning the same `mfa_required` body. This is the one
place the package decides an MFA policy on the product's behalf rather than asking, which is
why it is written down here: a product that disagrees needs to know it is a choice.

**Signature counters are checked here, not by the library, and migrate as stored.** A counter
that fails to increase is evidence of a cloned authenticator, per section 6.1.3 of the
WebAuthn specification. `finish_login` passes py_webauthn a stored count of zero so that the
comparison happens in this package, where a regression is logged at ERROR as the finding it
is rather than folded into a generic verification failure, and where a library upgrade cannot
quietly change it. Both counts being zero is the specification's documented exception and is
allowed, because many authenticators, Apple's included, keep no counter at all. A credential
imported from another system keeps the count that system last saw: importing at zero would
disarm the check for that credential forever, since every later assertion would exceed zero.

**The origin and the RP ID are required, never defaulted.** `IDENTITY_RP_ID` and
`IDENTITY_WEBAUTHN_ORIGINS` are checked when a ceremony runs and the error names the
variable, because an empty origin list makes the origin check vacuous and that check is the
whole of what makes a passkey phishing resistant. `rp_id` is the registrable domain, hashed
into every credential and immutable for that credential's life.

**Ask `GET /api/auth/passkeys/availability` whether to draw the passkey button.** New in
0.17.0, anonymous, cheap and cached for five minutes, and it answers:

```json
{"enabled": true, "passwordless": true}
```

`enabled` is `passkeys_enabled`: the deployment registers and verifies passkeys, so an
account settings page should offer to add one. `passwordless` is additionally
`passkeys_passwordless`: a passkey is a way *into* an account, so a sign-in page should offer
the button. `passwordless` is never `true` while `enabled` is `false`, so a client can read
it alone.

**Do not infer availability by probing `login/passkey/options`.** That was the pre-0.17.0
workaround and it is wrong twice. It spends that route's rate limit budget, 30 per 15 minutes
per IP, on sign-in *page loads* rather than on sign-ins, so a user who reloads the page
enough times is refused the passkey sign-in they then attempt. And the probe is not a read:
it writes a WebAuthn challenge row per call, so every sign-in page load in the estate leaves
a row in the challenge table to expire, which is a storage cost paid to answer a question
about configuration. Caching the probe's result in the browser only defers both costs: the
first load of every session still pays them in full. The availability route mounts in
**every** deployment, so `{"enabled": false, "passwordless": false}` is a real answer and
never a 404 to interpret.

**`POST /login/passkey/options` answers any input, including an unknown address.** It returns
a challenge and an empty `allowCredentials`, which is byte-identical to a genuine
discoverable-credential request, so an unauthenticated route does not become an account
oracle that needs no password. Passwordless sign-in is gated on `passkeys_passwordless`:
with it off, both login routes refuse and a passkey is a managed credential and a second
factor but not an entry point.

**The last passkey cannot be deleted by a user with no password.** Less a rule about passkeys
than about not stranding somebody outside their own account, and it applies only to the last
one: two passkeys, delete either. "Has a password" is read from the `credentials` store,
which is where this package's own password lives, so **M5 added no hook** and `IdentityHooks`
is unchanged. A product whose users can sign in some other way the package cannot see still
has `may_authenticate` and can refuse the delete in front of the route.
