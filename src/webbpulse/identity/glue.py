"""The DynamoDB glue every product was hand-writing to mount the identity router.

`dynamo_stores` builds the nine stores from one prefix, `build_dynamo_router` wraps
`build_identity_router` around them, and `create_identity_tables` creates the tables plus
their TTLs for a local stack or a test suite. Between them they replace the ~55 lines of
identical `package_glue.py` and the identical create-tables loop three products were
keeping, so a product's glue is its `claims_for` override and its table prefix.

Every import is inside a function body, so importing this module builds no AWS client.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Mapping

    from fastapi import APIRouter

    from webbpulse.identity.email import EmailSender
    from webbpulse.identity.hooks import IdentityHooks
    from webbpulse.identity.lockout import LoginAttemptStore
    from webbpulse.identity.oauth_server import ConsentRenderer, TenantResolver
    from webbpulse.identity.oauth_server_storage import OAuthServerStores
    from webbpulse.identity.service import TokenService
    from webbpulse.identity.settings import IdentitySettings
    from webbpulse.identity.storage import IdentityStores
    from webbpulse.identity.tokens import KmsClient

__all__ = [
    "build_dynamo_router",
    "create_identity_tables",
    "dynamo_login_attempts",
    "dynamo_stores",
]


def dynamo_stores(
    prefix: str | None = None,
    *,
    region_name: str | None = None,
    endpoint_url: str | None = None,
) -> IdentityStores:
    """Every identity store, backed by the tables under `prefix`.

    The nine stores `build_identity_router` reads, built from the package's own table
    constants rather than names a product restates. The login attempt store is not among
    them because `build_identity_router` takes it separately; `build_dynamo_router` builds
    that one itself.

    Constructing these makes no AWS call: each repository resolves its table on first use.
    """
    from webbpulse.identity.oauth import (
        OAUTH_LINKS_TABLE,
        OAUTH_STATES_TABLE,
        DynamoOAuthLinkStore,
        DynamoOAuthStateStore,
    )
    from webbpulse.identity.storage import (
        CREDENTIALS_TABLE,
        IDENTITY_TOKENS_TABLE,
        PASSKEYS_TABLE,
        RECOVERY_CODES_TABLE,
        REFRESH_TOKENS_TABLE,
        TOTP_FACTORS_TABLE,
        WEBAUTHN_CHALLENGES_TABLE,
        DynamoCredentialStore,
        DynamoIdentityTokenStore,
        DynamoPasskeyStore,
        DynamoRecoveryCodeStore,
        DynamoRefreshTokenStore,
        DynamoTotpFactorStore,
        DynamoWebAuthnChallengeStore,
        IdentityStores,
    )

    def repository(logical_name: str) -> Any:
        """A package repository for one identity table under this prefix."""
        return _repository(logical_name, prefix=prefix, region_name=region_name, endpoint_url=endpoint_url)

    return IdentityStores(
        credentials=DynamoCredentialStore(repository(CREDENTIALS_TABLE)),
        refresh_tokens=DynamoRefreshTokenStore(repository(REFRESH_TOKENS_TABLE)),
        identity_tokens=DynamoIdentityTokenStore(repository(IDENTITY_TOKENS_TABLE)),
        totp_factors=DynamoTotpFactorStore(repository(TOTP_FACTORS_TABLE)),
        recovery_codes=DynamoRecoveryCodeStore(repository(RECOVERY_CODES_TABLE)),
        oauth_states=DynamoOAuthStateStore(repository(OAUTH_STATES_TABLE)),
        oauth_links=DynamoOAuthLinkStore(repository(OAUTH_LINKS_TABLE)),
        passkeys=DynamoPasskeyStore(repository(PASSKEYS_TABLE)),
        webauthn_challenges=DynamoWebAuthnChallengeStore(repository(WEBAUTHN_CHALLENGES_TABLE)),
    )


def dynamo_login_attempts(
    prefix: str | None = None,
    *,
    region_name: str | None = None,
    endpoint_url: str | None = None,
) -> LoginAttemptStore:
    """The login attempt store for the lockout table under `prefix`.

    Separate from `dynamo_stores` because `build_identity_router` takes it as its own
    argument rather than as a field of `IdentityStores`.
    """
    from webbpulse.identity.lockout import LOGIN_ATTEMPTS_TABLE, DynamoLoginAttemptStore

    return DynamoLoginAttemptStore(
        _repository(LOGIN_ATTEMPTS_TABLE, prefix=prefix, region_name=region_name, endpoint_url=endpoint_url)
    )


def build_dynamo_router(
    settings: IdentitySettings,
    hooks: IdentityHooks | None = None,
    *,
    prefix: str | None = None,
    region_name: str | None = None,
    endpoint_url: str | None = None,
    service: str = "identity",
    version: str = "",
    stores: IdentityStores | None = None,
    attempts: LoginAttemptStore | None = None,
    tokens: TokenService | None = None,
    kms_client: KmsClient | None = None,
    email_sender: EmailSender | None = None,
    limiter_enabled: bool | None = None,
    oauth_client_secrets: Mapping[str, str] | None = None,
    oauth_server_stores: OAuthServerStores | None = None,
    consent_renderer: ConsentRenderer | None = None,
    tenant_resolver: TenantResolver | None = None,
) -> APIRouter:
    """The identity router over the DynamoDB tables under `prefix`.

    `build_identity_router` with the stores, the login attempt store and the signing client
    built from `prefix` and `settings` rather than assembled by the caller. Everything
    `build_identity_router` takes is passed through, so a product that mounts the OAuth
    authorization server or stamps its own claims loses nothing by adopting this.

    `stores`, `attempts` and `kms_client` override what would be built, which is how a test
    substitutes in-memory stores or a fake KMS. The router carries the issuer's own path, so
    mount it with no prefix of its own: a prefix would double every path.
    """
    from webbpulse.identity.local_signer import signing_client
    from webbpulse.identity.router import build_identity_router

    resolved_stores = (
        stores if stores is not None else dynamo_stores(prefix, region_name=region_name, endpoint_url=endpoint_url)
    )
    resolved_attempts = (
        attempts
        if attempts is not None
        else dynamo_login_attempts(prefix, region_name=region_name, endpoint_url=endpoint_url)
    )
    return build_identity_router(
        settings,
        hooks,
        resolved_stores,
        tokens=tokens,
        kms_client=kms_client if kms_client is not None else signing_client(settings),
        service=service,
        version=version,
        attempts=resolved_attempts,
        email_sender=email_sender,
        limiter_enabled=limiter_enabled,
        oauth_client_secrets=oauth_client_secrets,
        oauth_server_stores=oauth_server_stores,
        consent_renderer=consent_renderer,
        tenant_resolver=tenant_resolver,
    )


def create_identity_tables(
    client: Any,
    prefix: str = "",
    *,
    skip_existing: bool = True,
    include_users: bool = True,
) -> list[str]:
    """Create every identity table under `prefix` and return the names created.

    Walks `webbpulse.identity.storage.TABLES`, applying each spec's TTL through
    `update_time_to_live` afterwards, because TTL is not part of `CreateTable`. The `users`
    table is included by default, since a product on `DynamoUsersRepository` needs it and
    only the products that name it themselves opt out.

    For a local stack or a test suite. In AWS these tables are the identity module's, so
    a caller against a real account is creating tables Terraform believes it owns.

    Args:
        client: A DynamoDB **client**, not a resource: `create_table` and
            `update_time_to_live` are client calls.
        prefix: The estate's table prefix, or `""` for the bare logical names moto wants.
        skip_existing: Skip a table `list_tables` already reports, rather than letting
            `CreateTable` raise `ResourceInUseException`.
        include_users: Whether to create the shared `users` table alongside the package's
            own. `False` for a product whose stack or own script names that table.

    Returns:
        The physical names created, in creation order, omitting any that were skipped.
    """
    from webbpulse.identity.storage import TABLES
    from webbpulse.identity.users import USERS_TABLE_SPEC

    specs = (*TABLES, USERS_TABLE_SPEC) if include_users else TABLES
    existing: set[str] = set()
    if skip_existing:
        existing = set(client.list_tables().get("TableNames", []))

    created: list[str] = []
    for spec in specs:
        name = spec.table_name(prefix)
        if skip_existing and name in existing:
            continue
        client.create_table(**spec.create_table_request(prefix))
        created.append(name)
        ttl_request = spec.time_to_live_request(prefix)
        if ttl_request is not None:
            client.update_time_to_live(**ttl_request)
    return created


def _repository(
    logical_name: str,
    *,
    prefix: str | None,
    region_name: str | None,
    endpoint_url: str | None,
) -> Any:
    """One package repository, with prefix, region and endpoint passed explicitly.

    Explicit rather than environment-resolved so a product's glue reads the same settings
    object as the rest of its backend.
    """
    from webbpulse.dynamodb import Repository

    return Repository(
        logical_name,
        prefix=prefix,
        region_name=region_name,
        endpoint_url=endpoint_url,
    )
