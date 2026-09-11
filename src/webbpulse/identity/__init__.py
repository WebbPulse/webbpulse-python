"""App-managed identity: settings, hooks, storage, token service, and authorizer claims.

This is the shared implementation of `docs/identity-standard.md`. One FastAPI app, mounted
per product into its own `identity` Lambda, with no shared user database: everything a
product owns is behind `IdentityHooks` and the abstract stores in `storage`, and everything
the standard fixes is here.

## Module layout

- `tokens`: the primitives. `KmsSigner`, the JWK and JWKS builders, the discovery
  document. One key at a time.
- `service`: `TokenService`. Minting, local verification, and rotation across several
  keys at once.
- `settings`: `IdentitySettings`, the whole of section 6.1 as a validated settings class.
- `hooks`: `IdentityHooks`, the seam where a product's own policy lives.
- `storage`: the abstract stores, the DynamoDB implementations, and the in-memory ones.
- `claims`: `authorizer_claims`, reading and coercing what the gateway authorizer put on
  the request.
- `passwords`: section 5.6's policy and section 5.3's dummy-hash timing equalisation.
- `lockout`: section 5.1's progressive lockout and the `login-attempts` store.
- `sessions`: `SessionService`, the refresh family state machine.
- `email`: `EmailSender`, the SES v2 implementation, the recording double for tests, and
  the four message templates.
- `verification`: `LinkService`, the single-use link primitive both email verification and
  password reset are built from.
- `totp`: RFC 6238 code generation, the provisioning URI, and the replay window.
- `crypto`: `EnvelopeCipher`, KMS envelope encryption for the TOTP seed at rest.
- `mfa`: `MfaService`, tying those two to the stores, the ticket and the recovery codes.
- `flows`: `IdentityFlows`, the M2 to M4 flow logic with no FastAPI imports.
- `router`: `build_identity_router`, which is what a product mounts.

## What 0.12.0 does and does not do

M1 built the **foundations**: configuration, the policy seam, the storage interfaces, the
token service, and claim reading.

M2 added the **password and session flows**: register, login, change password, refresh with
rotation and reuse detection, logout and logout-all. The router mounts them when a product
supplies hooks and stores, and mounts only the three documents when it does not.

M3 adds **email verification and password reset over SES**: a single-use hashed link, the
four routes that issue and spend one, and the four messages that carry them. Both request
routes answer 200 whatever the address is, per section 5.4, and a completed reset revokes
every refresh family the user had. The four routes appear only when the product supplies an
`EmailSender` and an `identity-tokens` store, on the same rule the flow routes follow.

M4 adds **TOTP, recovery codes, the MFA ticket, step-up and `amr`**. A login by a user with
an active factor answers 200 with a challenge rather than tokens, and the second leg
exchanges the ticket plus a code for the session. Seeds are sealed with KMS envelope
encryption and never stored in plaintext; a code is accepted once per time step, ever; and
every access token now carries `amr` and `auth_time`, which is what lets a sensitive route
assert on the factor actually used rather than on a boolean.

Passkeys are M5 and OAuth is M6, per section 9.1 of the standard.

## The two things most likely to go wrong

1. **The `.well-known` routes must be anonymous.** API Gateway fetches them itself, with no
   cookie and no token. A gate in front of either one means the authorizer cannot fetch the
   signing key and every authorized route in the product fails closed.
2. **Every authorizer claim arrives as a string**, `exp` and `iat` included. `claims` owns
   the coercion back to integers, lists and booleans, and it is the only place that should.
3. **`login/totp` must stay outside the authorizer.** It carries an MFA ticket, whose
   audience is `<issuer>/mfa` and which the gateway's authorizer will not accept, so putting
   it behind the authorizer breaks the second leg of every MFA login.
"""

from __future__ import annotations

from webbpulse.identity.claims import (
    ARRAY_CLAIMS,
    BOOLEAN_CLAIMS,
    INTEGER_CLAIMS,
    AuthorizerClaims,
    ClaimsUnavailable,
    MissingRequestContext,
    NoClaimsSection,
    UnparseableRequestContext,
    authorizer_claims,
    coerce_claims,
    read_authorizer_claims,
)
from webbpulse.identity.crypto import (
    TOTP_ENCRYPTION_PURPOSE,
    EnvelopeCipher,
    EnvelopeDecryptionFailed,
    KmsDataKeyClient,
    SealedSecret,
    encryption_context,
)
from webbpulse.identity.email import (
    EmailMessage,
    EmailSender,
    EmailSendFailed,
    RecordingEmailSender,
    SesV2Client,
    SesV2EmailSender,
    render_password_changed,
    render_password_reset,
    render_registration_notice,
    render_verification,
)
from webbpulse.identity.flows import (
    INVALID_CREDENTIALS_MESSAGE,
    PASSWORD_CREDENTIAL_TYPE,
    AuthResult,
    IdentityFlows,
    LoginRejected,
    MfaChallengeRequired,
    RateLimited,
)
from webbpulse.identity.hooks import (
    AuthenticationRefused,
    BaseIdentityHooks,
    HookNotImplemented,
    IdentityHooks,
)
from webbpulse.identity.lockout import (
    ATTEMPT_TTL,
    LOCKOUT_BASE_DELAY,
    LOCKOUT_MAX_DELAY,
    LOCKOUT_THRESHOLD,
    LOGIN_ATTEMPTS_TABLE,
    DynamoLoginAttemptStore,
    InMemoryLoginAttemptStore,
    LockoutState,
    LoginAttempt,
    LoginAttemptStore,
    email_key,
    ip_key,
    lockout_state,
    new_attempt,
)
from webbpulse.identity.mfa import (
    AMR_MFA,
    AMR_OTP,
    AMR_PASSWORD,
    AMR_RECOVERY,
    RECOVERY_CODE_COUNT,
    TOTP_FACTOR,
    Enrolment,
    MfaChallenge,
    MfaRejected,
    MfaService,
    RecoveryCodeSet,
    hash_recovery_code,
    normalise_recovery_code,
)
from webbpulse.identity.oauth import (
    AMR_OAUTH,
    GITHUB_PROVIDER,
    GOOGLE_PROVIDER,
    OAUTH_LINK_USER_INDEX,
    OAUTH_LINKS_TABLE,
    OAUTH_STATE_TTL_SECONDS,
    OAUTH_STATES_TABLE,
    PROVIDERS,
    DynamoOAuthLinkStore,
    DynamoOAuthStateStore,
    HttpClient,
    HttpResponse,
    HttpxClient,
    InMemoryOAuthLinkStore,
    InMemoryOAuthStateStore,
    OAuthAuthorization,
    OAuthIdentity,
    OAuthLinkRecord,
    OAuthLinkStore,
    OAuthProviderConfig,
    OAuthRejected,
    OAuthService,
    OAuthStateRecord,
    OAuthStateStore,
    new_pkce_verifier,
    pkce_challenge,
    provider_account_key,
)
from webbpulse.identity.oauth_routes import (
    OAUTH_CALLBACK_PATH,
    OAUTH_LINK_PATH,
    OAUTH_LINKS_PATH,
    OAUTH_PROVIDERS_CACHE_CONTROL,
    OAUTH_PROVIDERS_PATH,
    OAUTH_START_IP_LIMIT,
    OAUTH_START_PATH,
    register_oauth_provider_discovery,
    register_oauth_routes,
)
from webbpulse.identity.passkey_routes import (
    PASSKEY_AVAILABILITY_CACHE_CONTROL,
    PASSKEY_AVAILABILITY_PATH,
    register_passkey_availability,
)
from webbpulse.identity.passkeys import (
    AMR_PASSKEY,
    AMR_PIN,
    CHALLENGE_TTL_SECONDS,
    AssertionResult,
    PasskeyRejected,
    PasskeyService,
    RegistrationChallenge,
)
from webbpulse.identity.passwords import (
    MAX_PASSWORD_BYTES,
    MIN_PASSWORD_CHARACTERS,
    PasswordRejected,
    check_password,
    equalise_password_timing,
    normalise_password,
)
from webbpulse.identity.router import (
    ALLOWED_FETCH_SITES,
    DISCOVERY_CACHE_CONTROL,
    HEALTH_PATH,
    JWKS_CACHE_CONTROL,
    LOGIN_PATH,
    LOGIN_TOTP_PATH,
    LOGOUT_ALL_PATH,
    LOGOUT_PATH,
    PASSWORD_PATH,
    RECOVERY_CODES_PATH,
    REFRESH_PATH,
    REGISTER_PATH,
    RESET_CONFIRM_PATH,
    RESET_EMAIL_LIMIT,
    RESET_IP_LIMIT,
    RESET_REQUEST_PATH,
    RESET_REQUESTED_MESSAGE,
    STEP_UP_PATH,
    TOTP_ACTIVATE_PATH,
    TOTP_DISABLE_PATH,
    TOTP_ENROL_IP_LIMIT,
    TOTP_ENROL_PATH,
    TOTP_VERIFY_LIMIT,
    VERIFY_CONFIRM_PATH,
    VERIFY_EMAIL_LIMIT,
    VERIFY_IP_LIMIT,
    VERIFY_REQUEST_PATH,
    build_identity_router,
    identity_prefix,
)
from webbpulse.identity.service import (
    ACCESS_TOKEN_TYPE,
    MFA_TICKET_TYPE,
    REGISTERED_CLAIMS,
    InvalidToken,
    TokenService,
)
from webbpulse.identity.sessions import (
    IssuedRefresh,
    RotationOutcome,
    RotationResult,
    SessionService,
)
from webbpulse.identity.settings import IdentitySettings
from webbpulse.identity.storage import (
    CREDENTIALS_TABLE,
    IDENTITY_TOKENS_TABLE,
    PASSKEY_CREDENTIAL_INDEX,
    PASSKEYS_TABLE,
    RECOVERY_CODES_TABLE,
    REFRESH_FAMILY_INDEX,
    REFRESH_TOKENS_TABLE,
    TOTP_FACTORS_TABLE,
    USERS_TABLE,
    WEBAUTHN_CHALLENGES_TABLE,
    CredentialRecord,
    CredentialStore,
    DynamoCredentialStore,
    DynamoIdentityTokenStore,
    DynamoPasskeyStore,
    DynamoRecoveryCodeStore,
    DynamoRefreshTokenStore,
    DynamoTotpFactorStore,
    DynamoWebAuthnChallengeStore,
    IdentityStores,
    IdentityTokenRecord,
    IdentityTokenStore,
    InMemoryCredentialStore,
    InMemoryIdentityTokenStore,
    InMemoryPasskeyStore,
    InMemoryRecoveryCodeStore,
    InMemoryRefreshTokenStore,
    InMemoryTotpFactorStore,
    InMemoryWebAuthnChallengeStore,
    PasskeyRecord,
    PasskeyStore,
    RecoveryCodeRecord,
    RecoveryCodeStore,
    RefreshTokenRecord,
    RefreshTokenStore,
    TotpFactorRecord,
    TotpFactorStore,
    WebAuthnChallengeRecord,
    WebAuthnChallengeStore,
    constant_time_equals,
    hash_token,
    is_expired,
    new_token,
)

# The M0 surface, re-exported unchanged. `identity.py` became `identity/tokens.py` in 0.9.0,
# and every one of these names was importable from `webbpulse.identity` before that move.
# Re-exporting them here keeps that true, so the move is not a breaking change for a
# consumer already on the M0 slice.
from webbpulse.identity.tokens import (
    DIGEST_MESSAGE_TYPE,
    DISCOVERY_PATH,
    JWKS_PATH,
    JWS_ALGORITHM,
    KMS_KEY_SPEC,
    KMS_SIGNING_ALGORITHM,
    KmsClient,
    KmsSigner,
    TokenMintingDisabled,
    build_discovery_document,
    build_jwks,
    identity_router,
    kid_for_der,
    mint_test_token,
    public_jwk_from_kms,
)
from webbpulse.identity.verification import (
    CONFIRMATION_FAILED_MESSAGE,
    RESET_LINK_PATH,
    VERIFY_LINK_PATH,
    ConfirmationFailed,
    IssuedLink,
    LinkService,
    describe_expiry,
)

__all__ = [
    "ACCESS_TOKEN_TYPE",
    "ALLOWED_FETCH_SITES",
    "AMR_MFA",
    "AMR_OAUTH",
    "AMR_OTP",
    "AMR_PASSKEY",
    "AMR_PASSWORD",
    "AMR_PIN",
    "AMR_RECOVERY",
    "ARRAY_CLAIMS",
    "ATTEMPT_TTL",
    "BOOLEAN_CLAIMS",
    "CHALLENGE_TTL_SECONDS",
    "CONFIRMATION_FAILED_MESSAGE",
    "CREDENTIALS_TABLE",
    "DIGEST_MESSAGE_TYPE",
    "DISCOVERY_CACHE_CONTROL",
    "DISCOVERY_PATH",
    "GITHUB_PROVIDER",
    "GOOGLE_PROVIDER",
    "HEALTH_PATH",
    "IDENTITY_TOKENS_TABLE",
    "INTEGER_CLAIMS",
    "INVALID_CREDENTIALS_MESSAGE",
    "JWKS_CACHE_CONTROL",
    "JWKS_PATH",
    "JWS_ALGORITHM",
    "KMS_KEY_SPEC",
    "KMS_SIGNING_ALGORITHM",
    "LOCKOUT_BASE_DELAY",
    "LOCKOUT_MAX_DELAY",
    "LOCKOUT_THRESHOLD",
    "LOGIN_ATTEMPTS_TABLE",
    "LOGIN_PATH",
    "LOGIN_TOTP_PATH",
    "LOGOUT_ALL_PATH",
    "LOGOUT_PATH",
    "MAX_PASSWORD_BYTES",
    "MFA_TICKET_TYPE",
    "MIN_PASSWORD_CHARACTERS",
    "OAUTH_CALLBACK_PATH",
    "OAUTH_LINKS_PATH",
    "OAUTH_LINKS_TABLE",
    "OAUTH_LINK_PATH",
    "OAUTH_LINK_USER_INDEX",
    "OAUTH_PROVIDERS_CACHE_CONTROL",
    "OAUTH_PROVIDERS_PATH",
    "OAUTH_START_IP_LIMIT",
    "OAUTH_START_PATH",
    "OAUTH_STATES_TABLE",
    "OAUTH_STATE_TTL_SECONDS",
    "PASSKEYS_TABLE",
    "PASSKEY_AVAILABILITY_CACHE_CONTROL",
    "PASSKEY_AVAILABILITY_PATH",
    "PASSKEY_CREDENTIAL_INDEX",
    "PASSWORD_CREDENTIAL_TYPE",
    "PASSWORD_PATH",
    "PROVIDERS",
    "RECOVERY_CODES_PATH",
    "RECOVERY_CODES_TABLE",
    "RECOVERY_CODE_COUNT",
    "REFRESH_FAMILY_INDEX",
    "REFRESH_PATH",
    "REFRESH_TOKENS_TABLE",
    "REGISTERED_CLAIMS",
    "REGISTER_PATH",
    "RESET_CONFIRM_PATH",
    "RESET_EMAIL_LIMIT",
    "RESET_IP_LIMIT",
    "RESET_LINK_PATH",
    "RESET_REQUESTED_MESSAGE",
    "RESET_REQUEST_PATH",
    "STEP_UP_PATH",
    "TOTP_ACTIVATE_PATH",
    "TOTP_DISABLE_PATH",
    "TOTP_ENCRYPTION_PURPOSE",
    "TOTP_ENROL_IP_LIMIT",
    "TOTP_ENROL_PATH",
    "TOTP_FACTOR",
    "TOTP_FACTORS_TABLE",
    "TOTP_VERIFY_LIMIT",
    "USERS_TABLE",
    "VERIFY_CONFIRM_PATH",
    "VERIFY_EMAIL_LIMIT",
    "VERIFY_IP_LIMIT",
    "VERIFY_LINK_PATH",
    "VERIFY_REQUEST_PATH",
    "WEBAUTHN_CHALLENGES_TABLE",
    "AssertionResult",
    "AuthResult",
    "AuthenticationRefused",
    "AuthorizerClaims",
    "BaseIdentityHooks",
    "ClaimsUnavailable",
    "ConfirmationFailed",
    "CredentialRecord",
    "CredentialStore",
    "DynamoCredentialStore",
    "DynamoIdentityTokenStore",
    "DynamoLoginAttemptStore",
    "DynamoOAuthLinkStore",
    "DynamoOAuthStateStore",
    "DynamoPasskeyStore",
    "DynamoRecoveryCodeStore",
    "DynamoRefreshTokenStore",
    "DynamoTotpFactorStore",
    "DynamoWebAuthnChallengeStore",
    "EmailMessage",
    "EmailSendFailed",
    "EmailSender",
    "Enrolment",
    "EnvelopeCipher",
    "EnvelopeDecryptionFailed",
    "HookNotImplemented",
    "HttpClient",
    "HttpResponse",
    "HttpxClient",
    "IdentityFlows",
    "IdentityHooks",
    "IdentitySettings",
    "IdentityStores",
    "IdentityTokenRecord",
    "IdentityTokenStore",
    "InMemoryCredentialStore",
    "InMemoryIdentityTokenStore",
    "InMemoryLoginAttemptStore",
    "InMemoryOAuthLinkStore",
    "InMemoryOAuthStateStore",
    "InMemoryPasskeyStore",
    "InMemoryRecoveryCodeStore",
    "InMemoryRefreshTokenStore",
    "InMemoryTotpFactorStore",
    "InMemoryWebAuthnChallengeStore",
    "InvalidToken",
    "IssuedLink",
    "IssuedRefresh",
    "KmsClient",
    "KmsDataKeyClient",
    "KmsSigner",
    "LinkService",
    "LockoutState",
    "LoginAttempt",
    "LoginAttemptStore",
    "LoginRejected",
    "MfaChallenge",
    "MfaChallengeRequired",
    "MfaRejected",
    "MfaService",
    "MissingRequestContext",
    "NoClaimsSection",
    "OAuthAuthorization",
    "OAuthIdentity",
    "OAuthLinkRecord",
    "OAuthLinkStore",
    "OAuthProviderConfig",
    "OAuthRejected",
    "OAuthService",
    "OAuthStateRecord",
    "OAuthStateStore",
    "PasskeyRecord",
    "PasskeyRejected",
    "PasskeyService",
    "PasskeyStore",
    "PasswordRejected",
    "RateLimited",
    "RecordingEmailSender",
    "RecoveryCodeRecord",
    "RecoveryCodeSet",
    "RecoveryCodeStore",
    "RefreshTokenRecord",
    "RefreshTokenStore",
    "RegistrationChallenge",
    "RotationOutcome",
    "RotationResult",
    "SealedSecret",
    "SesV2Client",
    "SesV2EmailSender",
    "SessionService",
    "TokenMintingDisabled",
    "TokenService",
    "TotpFactorRecord",
    "TotpFactorStore",
    "UnparseableRequestContext",
    "WebAuthnChallengeRecord",
    "WebAuthnChallengeStore",
    "authorizer_claims",
    "build_discovery_document",
    "build_identity_router",
    "build_jwks",
    "check_password",
    "coerce_claims",
    "constant_time_equals",
    "describe_expiry",
    "email_key",
    "encryption_context",
    "equalise_password_timing",
    "hash_recovery_code",
    "hash_token",
    "identity_prefix",
    "identity_router",
    "ip_key",
    "is_expired",
    "kid_for_der",
    "lockout_state",
    "mint_test_token",
    "new_attempt",
    "new_pkce_verifier",
    "new_token",
    "normalise_password",
    "normalise_recovery_code",
    "pkce_challenge",
    "provider_account_key",
    "public_jwk_from_kms",
    "read_authorizer_claims",
    "register_oauth_provider_discovery",
    "register_oauth_routes",
    "register_passkey_availability",
    "render_password_changed",
    "render_password_reset",
    "render_registration_notice",
    "render_verification",
]
