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
- `router`: `build_identity_router`, which is what a product mounts.

## What 0.9.0 does and does not do

M1 builds the **foundations**: configuration, the policy seam, the storage interfaces, the
token service, and claim reading. The router mounts only the two `.well-known` documents
and `/health`.

The flows are deliberately absent. Login, refresh rotation, MFA, passkeys and OAuth are M2
and later, per section 9.1 of the standard. `IdentityHooks` and `IdentityStores` are already
arguments to `build_identity_router` so that adding them changes routes rather than every
product's composition root.

## The two things most likely to go wrong

1. **The `.well-known` routes must be anonymous.** API Gateway fetches them itself, with no
   cookie and no token. A gate in front of either one means the authorizer cannot fetch the
   signing key and every authorized route in the product fails closed.
2. **Every authorizer claim arrives as a string**, `exp` and `iat` included. `claims` owns
   the coercion back to integers, lists and booleans, and it is the only place that should.
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
from webbpulse.identity.hooks import (
    AuthenticationRefused,
    BaseIdentityHooks,
    HookNotImplemented,
    IdentityHooks,
)
from webbpulse.identity.router import (
    DISCOVERY_CACHE_CONTROL,
    HEALTH_PATH,
    JWKS_CACHE_CONTROL,
    build_identity_router,
)
from webbpulse.identity.service import REGISTERED_CLAIMS, InvalidToken, TokenService
from webbpulse.identity.settings import IdentitySettings
from webbpulse.identity.storage import (
    CREDENTIALS_TABLE,
    IDENTITY_TOKENS_TABLE,
    REFRESH_FAMILY_INDEX,
    REFRESH_TOKENS_TABLE,
    USERS_TABLE,
    CredentialRecord,
    CredentialStore,
    DynamoCredentialStore,
    DynamoIdentityTokenStore,
    DynamoRefreshTokenStore,
    IdentityStores,
    IdentityTokenRecord,
    IdentityTokenStore,
    InMemoryCredentialStore,
    InMemoryIdentityTokenStore,
    InMemoryRefreshTokenStore,
    RefreshTokenRecord,
    RefreshTokenStore,
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

__all__ = [
    "ARRAY_CLAIMS",
    "BOOLEAN_CLAIMS",
    "CREDENTIALS_TABLE",
    "DIGEST_MESSAGE_TYPE",
    "DISCOVERY_CACHE_CONTROL",
    "DISCOVERY_PATH",
    "HEALTH_PATH",
    "IDENTITY_TOKENS_TABLE",
    "INTEGER_CLAIMS",
    "JWKS_CACHE_CONTROL",
    "JWKS_PATH",
    "JWS_ALGORITHM",
    "KMS_KEY_SPEC",
    "KMS_SIGNING_ALGORITHM",
    "REFRESH_FAMILY_INDEX",
    "REFRESH_TOKENS_TABLE",
    "REGISTERED_CLAIMS",
    "USERS_TABLE",
    "AuthenticationRefused",
    "AuthorizerClaims",
    "BaseIdentityHooks",
    "ClaimsUnavailable",
    "CredentialRecord",
    "CredentialStore",
    "DynamoCredentialStore",
    "DynamoIdentityTokenStore",
    "DynamoRefreshTokenStore",
    "HookNotImplemented",
    "IdentityHooks",
    "IdentitySettings",
    "IdentityStores",
    "IdentityTokenRecord",
    "IdentityTokenStore",
    "InMemoryCredentialStore",
    "InMemoryIdentityTokenStore",
    "InMemoryRefreshTokenStore",
    "InvalidToken",
    "KmsClient",
    "KmsSigner",
    "MissingRequestContext",
    "NoClaimsSection",
    "RefreshTokenRecord",
    "RefreshTokenStore",
    "TokenMintingDisabled",
    "TokenService",
    "UnparseableRequestContext",
    "authorizer_claims",
    "build_discovery_document",
    "build_identity_router",
    "build_jwks",
    "coerce_claims",
    "constant_time_equals",
    "hash_token",
    "identity_router",
    "is_expired",
    "kid_for_der",
    "mint_test_token",
    "new_token",
    "public_jwk_from_kms",
    "read_authorizer_claims",
]
