"""The hoisted DynamoDB glue: the stores, the router, the users repository and the hooks.

Covers what three products were hand-writing, so an adopter deleting its own copy is
deleting something these tests hold in place.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from webbpulse.identity import (
    ACCOUNT_DISABLED,
    CREDENTIALS_TABLE,
    EMAIL_INDEX,
    EMAIL_NOT_VERIFIED,
    TABLES,
    USERS_TABLE,
    AuthenticationRefused,
    CredentialRecord,
    DynamoUsersHooks,
    DynamoUsersRepository,
    User,
    build_dynamo_router,
    create_identity_tables,
    dynamo_login_attempts,
    dynamo_stores,
    users_repository,
)
from webbpulse.testing import assert_users_repository_contract

PREFIX = "webbpulse-test"
EMAIL = "Someone@Example.COM"
ISSUER = "https://identity.example.com"
AUDIENCE = "example"
SIGNING_KEY = "arn:aws:kms:us-west-2:111122223333:key/aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa"


def make_settings() -> Any:
    """`IdentitySettings` for a router this module builds."""
    from webbpulse.identity import IdentitySettings

    return IdentitySettings(
        environment="test",
        issuer=ISSUER,
        audience=AUDIENCE,
        signing_key_arns=[SIGNING_KEY],
    )


@pytest.fixture
def users(identity_tables: Any) -> DynamoUsersRepository[User]:
    """A users repository against the moto-backed `users` table."""
    del identity_tables
    return DynamoUsersRepository(prefix="")


@pytest.fixture
def hooks(users: DynamoUsersRepository[User]) -> DynamoUsersHooks[User]:
    """Hooks over that repository, with no product claims of their own."""
    return DynamoUsersHooks(users)


def _route_paths(router: Any) -> set[str]:
    """Every path the router declares, for a test asserting a route group mounted."""
    return {getattr(route, "path", "") for route in router.routes}


def _create(users: DynamoUsersRepository[User], email: str = EMAIL) -> User:
    """Store one user and return it."""
    return users.create(User(id="user-1", email=email, display_name="Someone"))


def test_the_users_repository_satisfies_the_shared_contract(users: DynamoUsersRepository[User]) -> None:
    """The reusable contract an adopting product runs against its own repository."""
    assert_users_repository_contract(users)


def test_a_user_round_trips(users: DynamoUsersRepository[User]) -> None:
    """The row written is the row read back."""
    _create(users)
    stored = users.get("user-1")
    assert stored is not None
    assert stored.display_name == "Someone"
    assert stored.email_verified is False
    assert stored.is_admin is False
    assert stored.disabled is False


def test_the_stored_item_carries_the_index_attribute(users: DynamoUsersRepository[User]) -> None:
    """`email_lower` is written alongside the address, or the GSI never sees the row."""
    _create(users)
    item = users.repository.get({"id": "user-1"})
    assert item is not None
    assert item["email_lower"] == "someone@example.com"


def test_the_repository_reports_the_logical_name(users: DynamoUsersRepository[User]) -> None:
    """A caller reading `logical_name` sees `users`, whichever way the table was named."""
    assert users.repository.logical_name == USERS_TABLE


def test_a_whole_table_name_is_used_verbatim() -> None:
    """A stack that named the table outright gets that name, not a prefixed one."""
    repository = users_repository(table_name="control-plane-prod-users")
    assert repository.table_name == "control-plane-prod-users"
    assert repository.logical_name == USERS_TABLE


def test_a_prefix_follows_the_estate_naming_rule() -> None:
    """The other pattern: `<prefix>-users`, as the platform module provisions it."""
    assert users_repository(prefix=PREFIX).table_name == f"{PREFIX}-{USERS_TABLE}"


def test_a_prefix_and_a_table_name_together_are_refused() -> None:
    """The two would disagree, so passing both is a caller's bug rather than a precedence rule."""
    with pytest.raises(ValueError, match="not both"):
        DynamoUsersRepository(prefix=PREFIX, table_name="something-users")


def test_an_update_aliases_reserved_words(users: DynamoUsersRepository[User]) -> None:
    """DynamoDB rejects `name` and `status` unaliased, so every attribute is aliased."""
    _create(users)
    updated = users.update("user-1", display_name="Renamed", disabled=True)
    assert updated.display_name == "Renamed"
    assert updated.disabled is True


def test_an_update_with_no_attributes_returns_the_row(users: DynamoUsersRepository[User]) -> None:
    """Nothing to set means no `UpdateItem`, since DynamoDB refuses an empty expression."""
    _create(users)
    assert users.update("user-1").display_name == "Someone"


def test_a_subclassed_model_round_trips(identity_tables: Any) -> None:
    """A product adding fields passes its subclass rather than writing a second repository."""
    del identity_tables

    class ProductUser(User):
        """A product's user row, with one extra field."""

        tier: str = "free"

    repository: DynamoUsersRepository[ProductUser] = DynamoUsersRepository(prefix="", model=ProductUser)
    repository.create(ProductUser(id="user-2", email="a@example.com", tier="pro"))
    stored = repository.get("user-2")
    assert stored is not None
    assert stored.tier == "pro"


def test_the_email_index_name_is_the_shared_one() -> None:
    """Every product's stack provisions this index name, so it is pinned here."""
    assert EMAIL_INDEX == "email_lower-index"


def test_disabled_accounts_are_refused(hooks: DynamoUsersHooks[User]) -> None:
    """A switched-off account gets the disabled code, and the message says nothing more."""
    with pytest.raises(AuthenticationRefused) as refused:
        hooks.may_authenticate({"disabled": True, "email_verified": True})
    assert refused.value.error_code == ACCOUNT_DISABLED


def test_unverified_accounts_are_refused(hooks: DynamoUsersHooks[User]) -> None:
    """An unconfirmed address cannot sign in, and the refusal names why for the client."""
    with pytest.raises(AuthenticationRefused) as refused:
        hooks.may_authenticate({"disabled": False, "email_verified": False})
    assert refused.value.error_code == EMAIL_NOT_VERIFIED


def test_the_refusals_share_one_message(hooks: DynamoUsersHooks[User]) -> None:
    """Two refusals that read differently would be an account enumeration oracle."""
    with pytest.raises(AuthenticationRefused) as disabled:
        hooks.may_authenticate({"disabled": True})
    with pytest.raises(AuthenticationRefused) as unverified:
        hooks.may_authenticate({"email_verified": False})
    assert disabled.value.message == unverified.value.message


def test_an_enabled_verified_account_is_permitted(hooks: DynamoUsersHooks[User]) -> None:
    """Permitting is returning `None`, so the refusing side is the one you fall into."""
    hooks.may_authenticate({"disabled": False, "email_verified": True})


def test_hooks_load_a_user_by_id_and_by_email(hooks: DynamoUsersHooks[User]) -> None:
    """Both lookups answer the plain mapping the protocol returns."""
    _create(hooks.users)
    by_id = hooks.load_user_by_id("user-1")
    assert by_id is not None
    assert by_id["id"] == "user-1"
    by_email = hooks.load_user_by_email("someone@example.com")
    assert by_email is not None
    assert by_email["id"] == "user-1"


def test_hooks_answer_none_for_a_user_who_is_not_there(hooks: DynamoUsersHooks[User]) -> None:
    """A miss is `None` rather than an error, on both lookups."""
    assert hooks.load_user_by_id("missing") is None
    assert hooks.load_user_by_email("nobody@example.com") is None


def test_create_user_derives_a_display_name(hooks: DynamoUsersHooks[User]) -> None:
    """With none supplied the address's local part stands in."""
    created = hooks.create_user(email="jordan@example.com", attributes={})
    assert created["display_name"] == "jordan"
    assert created["email"] == "jordan@example.com"


def test_create_user_keeps_a_supplied_display_name(hooks: DynamoUsersHooks[User]) -> None:
    """A name the registration carried is not overwritten by the derived one."""
    created = hooks.create_user(email="jordan@example.com", attributes={"display_name": "Jordan"})
    assert created["display_name"] == "Jordan"


def test_create_user_drops_the_id_and_the_password(hooks: DynamoUsersHooks[User]) -> None:
    """The id is the model's to mint, and the password lives in the credentials table."""
    created = hooks.create_user(
        email="jordan@example.com",
        attributes={"id": "forged", "hashed_password": "secret"},
    )
    assert created["id"] != "forged"
    assert "hashed_password" not in created


def test_marking_an_address_verified_writes_the_row(hooks: DynamoUsersHooks[User]) -> None:
    """The flag the refusal reads is set on the users row."""
    _create(hooks.users)
    hooks.mark_email_verified("user-1")
    stored = hooks.users.get("user-1")
    assert stored is not None
    assert stored.email_verified is True


def test_marking_a_missing_user_verified_raises(hooks: DynamoUsersHooks[User]) -> None:
    """The link is already spent, so a silent pass would leave the user stuck."""
    with pytest.raises(ValueError, match="found no user"):
        hooks.mark_email_verified("missing")


def test_deleting_a_user_is_idempotent(hooks: DynamoUsersHooks[User]) -> None:
    """A teardown running twice reports the second run honestly rather than raising."""
    _create(hooks.users)
    assert hooks.delete_user("user-1") is True
    assert hooks.delete_user("user-1") is False


def test_the_default_claims_are_empty(hooks: DynamoUsersHooks[User]) -> None:
    """Correct for a product with no roles, so `claims_for` is the only hook to override."""
    assert hooks.claims_for({"is_admin": True}) == {}


def test_a_subclass_overrides_only_claims_for(hooks: DynamoUsersHooks[User]) -> None:
    """What an adopting product's hooks class becomes: one method over this base."""

    class ProductHooks(DynamoUsersHooks[User]):
        """A product's hooks, stamping roles and a display name."""

        def claims_for(self, user: Mapping[str, Any]) -> Mapping[str, Any]:
            """The roles list and the display name."""
            roles = ["admin"] if user.get("is_admin") else []
            return {"roles": roles, "display_name": user.get("display_name", "")}

    product = ProductHooks(hooks.users)
    _create(product.users)
    loaded = product.load_user_by_id("user-1")
    assert loaded is not None
    assert product.claims_for(dict(loaded)) == {"roles": [], "display_name": "Someone"}
    assert product.has_other_sign_in_method("user-1") is False


def test_hooks_hand_the_purge_the_underlying_repository(hooks: DynamoUsersHooks[User]) -> None:
    """`user_repository` is the `webbpulse.dynamodb.Repository` the purge reaches for."""
    from webbpulse.dynamodb import Repository

    assert isinstance(hooks.user_repository(), Repository)


def test_on_user_created_does_nothing(hooks: DynamoUsersHooks[User]) -> None:
    """The register flow sends the email, so the default side effect is none."""
    hooks.on_user_created({"id": "user-1"}, "register")


def test_dynamo_stores_builds_every_store(identity_tables: Any) -> None:
    """The nine stores `build_identity_router` reads, none of them left `None`."""
    del identity_tables
    stores = dynamo_stores("")
    assert stores.credentials is not None
    assert stores.refresh_tokens is not None
    assert stores.identity_tokens is not None
    assert stores.totp_factors is not None
    assert stores.recovery_codes is not None
    assert stores.oauth_states is not None
    assert stores.oauth_links is not None
    assert stores.passkeys is not None
    assert stores.webauthn_challenges is not None


def test_dynamo_stores_names_the_tables_under_the_prefix(dynamodb_resource: Any) -> None:
    """The stores read the prefixed tables, so a write lands where `create_identity_tables` built.

    Asserted by writing through a store against tables created under the same prefix: a store
    naming a table differently would raise `ResourceNotFoundException` here.
    """
    client = dynamodb_resource.meta.client
    create_identity_tables(client, PREFIX)
    credentials = dynamo_stores(PREFIX).require_credentials()
    credentials.put(CredentialRecord(user_id="user-1", credential_type="password", secret="hashed"))
    stored = credentials.get("user-1", "password")
    assert stored is not None
    assert f"{PREFIX}-{CREDENTIALS_TABLE}" in set(client.list_tables()["TableNames"])


def test_dynamo_stores_builds_no_client() -> None:
    """Constructing the stores must not touch AWS, so a cold Lambda import stays cheap."""
    assert dynamo_stores("nonexistent-prefix") is not None


def test_the_login_attempt_store_is_built_separately() -> None:
    """`build_identity_router` takes it as its own argument, not as a store field."""
    assert dynamo_login_attempts(PREFIX) is not None


def test_create_identity_tables_creates_every_table(dynamodb_resource: Any) -> None:
    """Every spec in TABLES, plus `users`, and nothing is left out."""
    client = dynamodb_resource.meta.client
    created = create_identity_tables(client, "")
    names = set(client.list_tables()["TableNames"])
    assert names == set(created)
    assert {spec.table_name("") for spec in TABLES} <= names
    assert USERS_TABLE in names


def test_create_identity_tables_can_omit_the_users_table(dynamodb_resource: Any) -> None:
    """A product whose own stack names that table opts out."""
    client = dynamodb_resource.meta.client
    created = create_identity_tables(client, "", include_users=False)
    assert USERS_TABLE not in created


def test_create_identity_tables_applies_the_declared_ttls(dynamodb_resource: Any) -> None:
    """TTL is not part of `CreateTable`, so a table that declares one has it applied."""
    client = dynamodb_resource.meta.client
    create_identity_tables(client, "")
    for spec in TABLES:
        if spec.ttl_attribute is None:
            continue
        described = client.describe_time_to_live(TableName=spec.table_name(""))
        description = described["TimeToLiveDescription"]
        assert description["TimeToLiveStatus"] == "ENABLED"
        assert description["AttributeName"] == spec.ttl_attribute


def test_create_identity_tables_skips_what_is_already_there(dynamodb_resource: Any) -> None:
    """A second run creates nothing rather than raising `ResourceInUseException`."""
    client = dynamodb_resource.meta.client
    create_identity_tables(client, "")
    assert create_identity_tables(client, "") == []


def test_create_identity_tables_honours_the_prefix(dynamodb_resource: Any) -> None:
    """The estate's `<prefix>-<logical>` rule, so a local stack matches a deployed one."""
    client = dynamodb_resource.meta.client
    created = create_identity_tables(client, PREFIX)
    assert all(name.startswith(f"{PREFIX}-") for name in created)


def test_build_dynamo_router_mounts_the_discovery_routes(identity_tables: Any, fake_kms: Any) -> None:
    """The router the products mount, built from a prefix rather than assembled by hand."""
    del identity_tables
    router = build_dynamo_router(
        make_settings(),
        DynamoUsersHooks(prefix=""),
        prefix="",
        service="example-identity",
        version="1.0.0",
        kms_client=fake_kms,
    )
    paths = _route_paths(router)
    assert any(path.endswith("/jwks.json") for path in paths)
    assert any("openid-configuration" in path for path in paths)


def test_build_dynamo_router_accepts_substituted_stores(fake_kms: Any) -> None:
    """A test passes in-memory stores, so the router needs no table at all."""
    from webbpulse.identity import (
        IdentityStores,
        InMemoryCredentialStore,
        InMemoryIdentityTokenStore,
        InMemoryRefreshTokenStore,
    )

    router = build_dynamo_router(
        make_settings(),
        DynamoUsersHooks(prefix=""),
        stores=IdentityStores(
            credentials=InMemoryCredentialStore(),
            refresh_tokens=InMemoryRefreshTokenStore(),
            identity_tokens=InMemoryIdentityTokenStore(),
        ),
        prefix="",
        kms_client=fake_kms,
    )
    paths = _route_paths(router)
    assert any(path.endswith("/login") for path in paths)
