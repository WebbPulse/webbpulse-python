# Identity standard: the configuration surface

Section 6 of [the identity standard](identity-standard.md), split out for length. Every
statement here is normative and belongs to that standard. **Section 6.3 is the section the
`HookNotImplemented` error message in `src/webbpulse/identity/hooks.py` points at.** Back to
the [README](../README.md).

## 6. Configuration surface

### 6.1 `IdentitySettings`

`webbpulse.identity.settings.IdentitySettings` is a `BaseSettings` with the `IDENTITY_`
prefix. List fields accept a **JSON array only, never bare CSV**. Capability flags default
**on**: they exist to be turned off locally and to stage a rollout, not to opt out
permanently.

| Field | Default | Meaning |
|---|---|---|
| `environment` | `"local"` | Gates the `http://` issuer allowance and the local fallbacks |
| `issuer` | required | The `iss` claim, the discovery `issuer`, the authorizer's issuer |
| `audience` | required | The `aud` claim |
| `signing_key_arns` | required | KMS RSA_2048 signing keys, active first |
| `data_key_arn` | `""` | Symmetric KMS key for TOTP seed encryption |
| `passwords_enabled` | `True` | |
| `registration_enabled` | `True` | |
| `email_verification_required` | `True` | |
| `totp_enabled` | `True` | |
| `passkeys_enabled` | `True` | |
| `passkeys_passwordless` | `True` | |
| `oauth_providers` | `["google","github"]` | `OAuthProvider` literals |
| `password_breach_check` | `False` | Opt in to the breach corpus check (5.2) |
| `mfa_required_for_roles` | `[]` | |
| `access_token_ttl` | 10 minutes | Capped at `MAX_ACCESS_TOKEN_TTL` (1 hour), must be positive |
| `refresh_token_ttl` | 30 days | Rolling, reset on each rotation |
| `refresh_absolute_ttl` | 90 days | MUST NOT be shorter than `refresh_token_ttl` |
| `refresh_reuse_grace` | 10 seconds | Zero is stricter; MUST NOT be negative |
| `mfa_ticket_ttl` | 5 minutes | |
| `email_verification_ttl` | 24 hours | |
| `password_reset_ttl` | 1 hour | |
| `clock_skew_leeway` | 30 seconds | Tolerance on local `exp` and `nbf` checks |
| `cookie_name` | `"wp_refresh"` | |
| `cookie_domain` | `""` | Registrable domain; empty is host-only |
| `cookie_path` | `""` | Empty derives from the issuer's path |
| `cookie_samesite` | `"lax"` | `lax`, `strict` or `none` |
| `cookie_secure` | `True` | |
| `rp_id` | `""` | WebAuthn RP ID, normally the registrable domain |
| `rp_name` | `""` | |
| `webauthn_origins` | `[]` | Every exact frontend origin |
| `email_from` | `""` | |
| `ses_configuration_set` | `None` | |
| `frontend_base_url` | `""` | Where emailed links point |
| `product_name`, `support_email`, `logo_url` | `""`, `""`, `None` | Branding |
| `google_client_id`, `github_client_id` | `""` | Client **ids** only; secrets never live here |
| `oauth_redirect_uris` | `[]` | Exact-match allow-list; empty means `<issuer>/oauth/callback` |

Derived: `active_signing_key_arn`, `previous_signing_key_arns`, `discovery_url`, `jwks_url`,
`cookie_kwargs()` for `Response.set_cookie`.

**`rp_id` cannot be changed later.** It is hashed into every credential and immutable for its
life; the browser refuses a ceremony whose RP ID is not a registrable domain suffix of the
current origin. Choose the **registrable domain** rather than a host, so `www.` and future
subdomains share credentials. **A passkey can never follow a user to a different registrable
domain**, nor across environments.

### 6.2 Mounting it

```python
from webbpulse.identity import IdentitySettings, build_identity_router


def build() -> APIRouter:
    s = settings()
    return build_identity_router(
        IdentitySettings(
            issuer=f"https://{s.api_host}/api/auth",
            audience="carmodpicker-api",
            signing_key_arns=s.identity_signing_key_arns,
            data_key_arn=s.identity_data_key_arn,
            cookie_domain=s.registrable_domain,
            rp_id=s.registrable_domain,
            rp_name="CarModPicker",
            webauthn_origins=[f"https://{s.domain}", f"https://www.{s.domain}"],
            email_from=s.email_from,
            frontend_base_url=f"https://{s.domain}",
            product_name="CarModPicker",
            support_email=f"support@{s.domain}",
            google_client_id=s.google_client_id,
            github_client_id=s.github_client_id,
        ),
        hooks=CarModPickerHooks(),
    )
```

**Mount the returned router with no prefix**, even where other routers sit under `/api/v1`:
`app.include_router(build())`. The router places itself under the issuer's path
(`identity_prefix`). Your own prefix doubles it, giving `/api/auth/api/auth/login`, and puts
the `.well-known` documents where API Gateway will not look.

### 6.3 `IdentityHooks`, the product's own policy

The product decides **who may sign in and what they may do**; the package decides **how signing
in works**. **No hook may change a ceremony, a lifetime, or a verification rule.**

`IdentityHooks` is a runtime-checkable `Protocol`, satisfied without inheritance. Every method
may be `def` or `async def`. `BaseIdentityHooks` is a concrete base whose unimplemented hooks
raise `HookNotImplemented` at the call, not at instantiation, so a partial implementation can
exist.

| Hook | Contract |
|---|---|
| `load_user_by_id(user_id)` | The user with this id, or `None`. `user_id` is the `sub` claim: the immutable id, never a username or email. Required. |
| `load_user_by_email(email)` | The user with this email, or `None`. `email` arrives lowercased and stripped. **Returning `None` MUST cost the same as returning a user**, or the lookup becomes an enumeration oracle. Required. |
| `may_authenticate(user)` | Raise `AuthenticationRefused` to refuse, return `None` to permit. The message reaches the caller, so it **MUST NOT distinguish an existing account from a missing one**. Carries `error_code`, default `AUTHENTICATION_REFUSED`. Required. |
| `claims_for(user)` | The product's own claims: roles, scopes, tenant. **Never the registered claims**: any returned here are dropped rather than honoured. Defaults to `{}`. |
| `on_user_created(user, via)` | Product-side side effects for a new account; `via` names how it came to exist. Raising fails the registration. Defaults to a no-op. |
| `create_user(*, email, attributes)` | Create the user row and return it. The product owns the `users` table and its schema. **The returned mapping MUST carry the immutable user id under `id`.** Required. |
| `mark_email_verified(user_id)` | Record that the address is confirmed. Called only after a link is consumed, so it re-checks nothing. Raising fails the confirmation after the link is spent. Required. |
| `user_repository()` | The product's own users table, as a `webbpulse.dynamodb.Repository`. Typed `object` so this module needs no `dynamodb` extra. Required. |
| `has_other_sign_in_method(user_id)` | Whether the user holds a sign-in method the package cannot see. Asked by `OAuthService.unlink`. **Do not count OAuth links or the password here.** Defaults to `False`. |
