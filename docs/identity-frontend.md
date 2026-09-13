# Identity standard: the frontend contract

Section 7 of [the identity standard](identity-standard.md), split out for length. Every
statement here is normative and belongs to that standard. Back to the [README](../README.md).

## 7. Frontend contract

### 7.1 `@webbpulse/auth`

```ts
const auth = createAuthClient({
  baseUrl: "https://api.carmodpicker.com",
  onSessionEnded: () => router.navigate("/login"),
});

await auth.login({ email, password });     // may return {mfaRequired, factors, ticket}
await auth.completeTotp({ ticket, code });
await auth.loginWithPasskey();             // discoverable credentials
await auth.registerPasskey();              // requires a session
auth.startOAuth("google", { returnTo });   // full-page redirect
await auth.logout();
auth.getAccessToken();                     // in-memory, may be null
auth.subscribe(listener);
```

- **The access token lives in a module-scoped variable.** Not `localStorage`, not
  `sessionStorage`, not a readable cookie. A reload loses it, which silent refresh repairs.
- **Silent refresh on load.** On startup call `/refresh` once with credentials. A valid cookie
  means signed in with no login screen; otherwise render anonymous.
- **Proactive refresh** at 80% of `expires_in`.
- **One retry on 401, exactly once.** A second 401 ends the session. **The retry MUST NOT
  recurse.**
- **A single-flight refresh.** Concurrent 401s MUST share one in-flight refresh promise;
  without it ten parallel requests fire ten rotations and nine look like reuse, revoking the
  family. This is the frontend half of what the 10-second grace window (2.6) covers on the
  server; both are needed.
- **Every request sends `credentials: "include"`**, or the cookie is never attached
  cross-origin.
- Guards MUST NOT unmount the login view on `isLoading`: `isLoading` means the session is
  unknown, `isBusy` means a call is in flight. Spinning on `isLoading` loses the MFA challenge.

The `localStorage`-backed token store is **removed, not deprecated**: a **major version** of
`@webbpulse/auth`.

### 7.2 `@webbpulse/api-client`

A request pipeline that asks the auth client for a token, attaches `Authorization: Bearer`,
and delegates 401 handling to the same single-flight refresh. It keeps working with no auth
client supplied, for public calls.

### 7.3 Error contract

Identity routes answer in the package envelope (`success`, `status`, `message`, `request_id`,
`error_code`), so the frontend **switches on `error_code` and never parses prose**.

- Credentials and policy: `INVALID_CREDENTIALS`, `CREDENTIAL_REQUIRED`, `PASSWORD_TOO_SHORT`,
  `PASSWORD_TOO_LONG`, `TOO_MANY_ATTEMPTS`, `EMAIL_VERIFICATION_REQUIRED`, `EMAIL_REQUIRED`,
  `USER_NOT_FOUND`, `USER_ID_MISSING`.
- Session: `NOT_AUTHENTICATED`, `NO_SESSION`, `CROSS_SITE_REQUEST`.
- MFA: `MFA_TICKET_INVALID`, `MFA_NOT_CONFIGURED`, `NO_PENDING_ENROLMENT`,
  `TOTP_ALREADY_ENABLED`.
- Passkeys: `PASSKEY_NOT_FOUND`, `PASSKEY_CHALLENGE_INVALID`, `PASSKEY_ALREADY_REGISTERED`,
  `PASSKEY_NAME_REQUIRED`, `PASSKEY_LOGIN_DISABLED`, `PASSKEYS_DISABLED`.
- OAuth: `OAUTH_STATE_INVALID`, `OAUTH_CODE_MISSING`, `OAUTH_CANCELLED`,
  `OAUTH_EXCHANGE_FAILED`, `OAUTH_USERINFO_FAILED`, `OAUTH_ID_TOKEN_INVALID`,
  `OAUTH_NONCE_MISMATCH`, `OAUTH_EMAIL_MISSING`, `OAUTH_EMAIL_UNVERIFIED`, `OAUTH_NOT_LINKED`,
  `OAUTH_ALREADY_LINKED`, `OAUTH_ACCOUNT_MISSING`, `OAUTH_LAST_SIGN_IN_METHOD`,
  `OAUTH_REDIRECT_NOT_ALLOWED`, `OAUTH_PROVIDER_UNKNOWN`, `OAUTH_PROVIDER_UNAVAILABLE`.
- Capability off: `PASSWORDS_DISABLED`, `REGISTRATION_DISABLED`, `EMAIL_NOT_CONFIGURED`,
  `LAST_CREDENTIAL`.
- From `webbpulse.security` and `webbpulse.http`: `TOKEN_EXPIRED`, `INVALID_TOKEN`,
  `RATE_LIMITED`.
