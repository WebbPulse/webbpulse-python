"""Tests for the account deletion purge: the flow, the store deletes, and the stream route.

Covers `IdentityFlows.purge_user` across every identity table, the `delete_all_for_user`
store methods in memory and against moto, and the DynamoDB Streams pass-through route.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from webbpulse.identity import (
    OAUTH_LINK_USER_INDEX,
    AuthenticationRefused,
    BaseIdentityHooks,
    CredentialRecord,
    IdentitySettings,
    IdentityStores,
    IdentityTokenRecord,
    InMemoryCredentialStore,
    InMemoryIdentityTokenStore,
    InMemoryOAuthLinkStore,
    InMemoryPasskeyStore,
    InMemoryRecoveryCodeStore,
    InMemoryRefreshTokenStore,
    InMemoryTotpFactorStore,
    InMemoryWebAuthnChallengeStore,
    OAuthLinkRecord,
    PasskeyRecord,
    PurgeResult,
    RecoveryCodeRecord,
    RefreshTokenRecord,
    TokenService,
    TotpFactorRecord,
    WebAuthnChallengeRecord,
    build_identity_router,
    events_path,
    users_key_attribute,
)
from webbpulse.identity.events import (
    DEFAULT_EVENTS_PATH,
    DEFAULT_USERS_KEY_ATTRIBUTE,
    EVENTS_PATH_ENV,
    LWA_PASS_THROUGH_PATH_ENV,
    USERS_KEY_ATTRIBUTE_ENV,
)
from webbpulse.identity.flows import IdentityFlows

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Iterator, Mapping

cryptography = pytest.importorskip("cryptography")
fastapi = pytest.importorskip("fastapi")

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

KEY_A = "arn:aws:kms:us-west-2:111122223333:key/aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa"
ISSUER = "https://api.staging.example.com/api/auth"
AUDIENCE = "webbpulse-staging"
USER_ID = "user-0001"
OTHER_USER_ID = "user-0002"
FAR_FUTURE = 4_102_444_800


class FakeKms:
    """A KMS client signing for real with a local private key."""

    def __init__(self, keys: dict[str, rsa.RSAPrivateKey]) -> None:
        """Hold the private keys by key id."""
        self._keys = keys

    def get_public_key(self, *, KeyId: str) -> dict[str, Any]:
        """Return a `kms:GetPublicKey` shaped response for the named key."""
        der = (
            self._keys[KeyId]
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        return {
            "KeyId": KeyId,
            "PublicKey": der,
            "KeySpec": "RSA_2048",
            "KeyUsage": "SIGN_VERIFY",
            "SigningAlgorithms": ["RSASSA_PKCS1_V1_5_SHA_256"],
        }

    def sign(self, *, KeyId: str, Message: bytes, MessageType: str, SigningAlgorithm: str) -> dict[str, Any]:
        """Return a real PKCS #1 v1.5 signature over the digest, using the named key."""
        signature = self._keys[KeyId].sign(Message, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
        return {"KeyId": KeyId, "Signature": signature, "SigningAlgorithm": SigningAlgorithm}


class FakeHooks(BaseIdentityHooks):
    """The minimum product policy the purge flow and the router need."""

    def __init__(self) -> None:
        """Start with no users."""
        self.users: dict[str, dict[str, Any]] = {}

    def load_user_by_id(self, user_id: str) -> Mapping[str, Any] | None:
        """Return the user with this id, or None."""
        return self.users.get(user_id)

    def load_user_by_email(self, email: str) -> Mapping[str, Any] | None:
        """Return the user with this email, or None."""
        for user in self.users.values():
            if str(user.get("email", "")).lower() == email.lower():
                return user
        return None

    def may_authenticate(self, user: Mapping[str, Any]) -> None:
        """Permit every user, and refuse a disabled one."""
        if user.get("disabled"):
            raise AuthenticationRefused("This account is disabled.", error_code="DISABLED")

    def create_user(self, *, email: str, attributes: Mapping[str, Any]) -> Mapping[str, Any]:
        """Create and return a user for this email."""
        user = {"id": USER_ID, "email": email, **dict(attributes)}
        self.users[USER_ID] = user
        return user


def make_settings(**overrides: Any) -> IdentitySettings:
    """Build `IdentitySettings` from this module's defaults with the given overrides."""
    base: dict[str, Any] = {
        "environment": "test",
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "signing_key_arns": [KEY_A],
        "email_verification_required": False,
        "totp_enabled": False,
        "passkeys_enabled": False,
    }
    base.update(overrides)
    return IdentitySettings(**base)


@pytest.fixture(scope="module")
def module_key() -> rsa.RSAPrivateKey:
    """One 2048-bit key for the module, since generation is slow."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def kms(module_key: rsa.RSAPrivateKey) -> FakeKms:
    """Return a locally signing KMS stand-in holding the module key."""
    return FakeKms({KEY_A: module_key})


@pytest.fixture
def stores() -> IdentityStores:
    """Every identity store, in memory, so a purge has something to remove from each."""
    return IdentityStores(
        credentials=InMemoryCredentialStore(),
        refresh_tokens=InMemoryRefreshTokenStore(),
        identity_tokens=InMemoryIdentityTokenStore(),
        totp_factors=InMemoryTotpFactorStore(),
        recovery_codes=InMemoryRecoveryCodeStore(),
        oauth_links=InMemoryOAuthLinkStore(),
        passkeys=InMemoryPasskeyStore(),
        webauthn_challenges=InMemoryWebAuthnChallengeStore(),
    )


@pytest.fixture
def flows(kms: FakeKms, stores: IdentityStores) -> IdentityFlows:
    """`IdentityFlows` over the in-memory stores."""
    settings = make_settings()
    return IdentityFlows(settings, FakeHooks(), stores, TokenService(settings, kms))


def seed_every_table(stores: IdentityStores, *, user_id: str = USER_ID) -> None:
    """Write one or more rows for this user into every identity table."""
    stores.require_credentials().put(CredentialRecord(user_id=user_id, credential_type="password", secret="hashed"))
    for generation in range(2):
        stores.require_refresh_tokens().put(
            RefreshTokenRecord(
                token_hash=f"{user_id}-hash-{generation}",
                family_id=f"{user_id}-family",
                user_id=user_id,
                generation=generation,
                created_at="2026-09-13T00:00:00Z",
                expires_at=FAR_FUTURE,
            )
        )
    stores.require_identity_tokens().put(
        IdentityTokenRecord(
            token_hash=f"{user_id}-link",
            purpose="reset_password",
            user_id=user_id,
            created_at="2026-09-13T00:00:00Z",
            expires_at=FAR_FUTURE,
        )
    )
    stores.require_totp_factors().put(
        TotpFactorRecord(
            user_id=user_id,
            secret_ciphertext="sealed",
            secret_nonce="nonce",
            wrapped_data_key="wrapped",
            created_at="2026-09-13T00:00:00Z",
            activated_at="2026-09-13T00:00:00Z",
        )
    )
    stores.require_recovery_codes().put_many(
        [
            RecoveryCodeRecord(user_id=user_id, code_hash=f"{user_id}-code-{index}", created_at="2026-09-13T00:00:00Z")
            for index in range(3)
        ]
    )
    stores.require_oauth_links().put(
        OAuthLinkRecord(
            provider_subject=f"google#{user_id}",
            provider="google",
            subject=user_id,
            user_id=user_id,
            linked_at="2026-09-13T00:00:00Z",
        )
    )
    stores.require_passkeys().put(
        PasskeyRecord(
            user_id=user_id,
            credential_id=f"{user_id}-cred",
            public_key="cose",
        )
    )
    stores.require_webauthn_challenges().put(
        WebAuthnChallengeRecord(
            challenge_id=f"{user_id}-challenge",
            challenge="raw",
            purpose="register",
            created_at="2026-09-13T00:00:00Z",
            expires_at=FAR_FUTURE,
            user_id=user_id,
        )
    )


def test_purge_user_empties_every_identity_table(flows: IdentityFlows, stores: IdentityStores) -> None:
    """Every table gives up its rows, and the result counts what each one gave."""
    seed_every_table(stores)

    result = flows.purge_user(USER_ID)

    assert result == PurgeResult(
        user_id=USER_ID,
        refresh_tokens=2,
        credentials=1,
        passkeys=1,
        totp_factors=1,
        recovery_codes=3,
        oauth_links=1,
        identity_tokens=1,
        webauthn_challenges=1,
    )
    assert result.total == 11
    assert stores.require_credentials().get(USER_ID, "password") is None
    assert stores.require_refresh_tokens().get(f"{USER_ID}-hash-0") is None
    assert stores.require_identity_tokens().get(f"{USER_ID}-link") is None
    assert stores.require_totp_factors().get(USER_ID) is None
    assert stores.require_recovery_codes().list_for_user(USER_ID) == []
    assert stores.require_oauth_links().list_for_user(USER_ID) == []
    assert stores.require_passkeys().list_for_user(USER_ID) == []
    assert stores.require_webauthn_challenges().consume(f"{USER_ID}-challenge") is None


def test_purge_user_leaves_another_user_alone(flows: IdentityFlows, stores: IdentityStores) -> None:
    """Every delete is scoped to one user, so a bystander keeps every row."""
    seed_every_table(stores)
    seed_every_table(stores, user_id=OTHER_USER_ID)

    flows.purge_user(USER_ID)

    assert stores.require_credentials().get(OTHER_USER_ID, "password") is not None
    assert stores.require_refresh_tokens().get(f"{OTHER_USER_ID}-hash-0") is not None
    assert stores.require_totp_factors().get(OTHER_USER_ID) is not None
    assert len(stores.require_recovery_codes().list_for_user(OTHER_USER_ID)) == 3
    assert len(stores.require_passkeys().list_for_user(OTHER_USER_ID)) == 1
    assert len(stores.require_oauth_links().list_for_user(OTHER_USER_ID)) == 1


def test_purge_user_is_idempotent(flows: IdentityFlows, stores: IdentityStores) -> None:
    """A second purge, and a purge of a user with nothing, both succeed with zero counts."""
    seed_every_table(stores)
    flows.purge_user(USER_ID)

    again = flows.purge_user(USER_ID)
    assert again.total == 0
    assert again.counts() == dict.fromkeys(again.counts(), 0)

    never_existed = flows.purge_user("nobody-at-all")
    assert never_existed.total == 0
    assert never_existed.unsupported == ()


def test_purge_user_logs_one_structured_event(
    flows: IdentityFlows, stores: IdentityStores, caplog: pytest.LogCaptureFixture
) -> None:
    """One `identity.user_purged` line carries the user id and the per-table counts."""
    seed_every_table(stores)

    with caplog.at_level("INFO"):
        flows.purge_user(USER_ID)

    lines = [record for record in caplog.records if record.__dict__.get("event") == "identity.user_purged"]
    assert len(lines) == 1
    fields = lines[0].__dict__
    assert fields["user_id"] == USER_ID
    assert fields["refresh_tokens"] == 2
    assert fields["recovery_codes"] == 3
    assert fields["total_rows"] == 11


def test_purge_user_records_a_table_that_cannot_enumerate_a_user(
    flows: IdentityFlows, stores: IdentityStores, caplog: pytest.LogCaptureFixture
) -> None:
    """A store raising `NotImplementedError` is recorded rather than failing the purge."""
    seed_every_table(stores)

    def refuse(user_id: str) -> int:
        """Stand in for a table with no user index."""
        raise NotImplementedError("no user index")

    stores.require_identity_tokens().delete_all_for_user = refuse  # type: ignore[method-assign]

    with caplog.at_level("WARNING"):
        result = flows.purge_user(USER_ID)

    assert result.unsupported == ("identity_tokens",)
    assert result.identity_tokens == 0
    assert result.credentials == 1
    assert any(record.__dict__.get("event") == "identity.purge_unsupported" for record in caplog.records)


def test_purge_user_surfaces_a_real_store_failure(flows: IdentityFlows, stores: IdentityStores) -> None:
    """Anything other than `NotImplementedError` propagates, so the stream retries the record."""
    seed_every_table(stores)

    def explode(user_id: str) -> int:
        """Stand in for a throttled or unreachable table."""
        raise RuntimeError("ProvisionedThroughputExceededException")

    stores.require_passkeys().delete_all_for_user = explode  # type: ignore[method-assign]

    with pytest.raises(RuntimeError):
        flows.purge_user(USER_ID)


def test_purge_user_skips_a_store_that_was_never_configured(kms: FakeKms) -> None:
    """A product mounting only passwords purges what it has and counts zero for the rest."""
    stores = IdentityStores(
        credentials=InMemoryCredentialStore(),
        refresh_tokens=InMemoryRefreshTokenStore(),
    )
    settings = make_settings()
    flows = IdentityFlows(settings, FakeHooks(), stores, TokenService(settings, kms))
    stores.require_credentials().put(CredentialRecord(user_id=USER_ID, credential_type="password", secret="hashed"))

    result = flows.purge_user(USER_ID)

    assert result.credentials == 1
    assert result.passkeys == 0
    assert result.oauth_links == 0
    assert result.unsupported == ()


def test_purge_user_refuses_an_empty_user_id(flows: IdentityFlows) -> None:
    """An empty id would delete nothing while reporting success, so it is refused."""
    with pytest.raises(ValueError, match="user id"):
        flows.purge_user("   ")


def test_in_memory_stores_delete_only_the_named_user(stores: IdentityStores) -> None:
    """Each `delete_all_for_user` returns what it deleted and leaves other users alone."""
    seed_every_table(stores)
    seed_every_table(stores, user_id=OTHER_USER_ID)

    assert stores.require_credentials().delete_all_for_user(USER_ID) == 1
    assert stores.require_refresh_tokens().delete_all_for_user(USER_ID) == 2
    assert stores.require_identity_tokens().delete_all_for_user(USER_ID) == 1
    assert stores.require_recovery_codes().delete_for_user(USER_ID) == 3
    assert stores.require_oauth_links().delete_all_for_user(USER_ID) == 1
    assert stores.require_passkeys().delete_all_for_user(USER_ID) == 1
    assert stores.require_webauthn_challenges().delete_all_for_user(USER_ID) == 1

    assert stores.require_credentials().delete_all_for_user(USER_ID) == 0
    assert stores.require_refresh_tokens().delete_all_for_user(USER_ID) == 0
    assert stores.require_passkeys().delete_all_for_user(OTHER_USER_ID) == 1


def test_the_challenge_store_ignores_an_empty_user_id(stores: IdentityStores) -> None:
    """A discoverable-credential login challenge carries no user id and is never matched."""
    challenges = stores.require_webauthn_challenges()
    challenges.put(
        WebAuthnChallengeRecord(
            challenge_id="anonymous",
            challenge="raw",
            purpose="login",
            created_at="2026-09-13T00:00:00Z",
            expires_at=FAR_FUTURE,
        )
    )

    assert challenges.delete_all_for_user("") == 0
    assert challenges.consume("anonymous") is not None


def _create_table(resource: Any, name: str, **kwargs: Any) -> Any:
    """Create one on-demand table and wait for it, passing the caller's key and index shape."""
    table = resource.create_table(TableName=name, BillingMode="PAY_PER_REQUEST", **kwargs)
    table.wait_until_exists()
    return table


@pytest.fixture
def dynamo_credentials(dynamodb_resource: Any) -> Any:
    """A `DynamoCredentialStore` over a moto-backed `credentials` table."""
    from webbpulse.dynamodb import Repository
    from webbpulse.identity.storage import DynamoCredentialStore

    _create_table(
        dynamodb_resource,
        "credentials",
        KeySchema=[
            {"AttributeName": "user_id", "KeyType": "HASH"},
            {"AttributeName": "credential_type", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_id", "AttributeType": "S"},
            {"AttributeName": "credential_type", "AttributeType": "S"},
        ],
    )
    return DynamoCredentialStore(Repository("credentials", prefix="", region_name="us-west-2"))


@pytest.fixture
def dynamo_refresh(dynamodb_resource: Any) -> Any:
    """A `DynamoRefreshTokenStore` over a moto-backed table carrying the user index."""
    from webbpulse.dynamodb import Repository
    from webbpulse.identity.storage import DynamoRefreshTokenStore

    _create_table(
        dynamodb_resource,
        "refresh-tokens",
        KeySchema=[{"AttributeName": "token_hash", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "token_hash", "AttributeType": "S"},
            {"AttributeName": "user_id", "AttributeType": "S"},
            {"AttributeName": "family_id", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "user_id-family_id-index",
                "KeySchema": [
                    {"AttributeName": "user_id", "KeyType": "HASH"},
                    {"AttributeName": "family_id", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "KEYS_ONLY"},
            }
        ],
    )
    return DynamoRefreshTokenStore(Repository("refresh-tokens", prefix="", region_name="us-west-2"))


@pytest.fixture
def dynamo_passkeys(dynamodb_resource: Any) -> Any:
    """A `DynamoPasskeyStore` over a moto-backed `passkeys` table."""
    from webbpulse.dynamodb import Repository
    from webbpulse.identity.storage import DynamoPasskeyStore

    _create_table(
        dynamodb_resource,
        "passkeys",
        KeySchema=[
            {"AttributeName": "user_id", "KeyType": "HASH"},
            {"AttributeName": "credential_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_id", "AttributeType": "S"},
            {"AttributeName": "credential_id", "AttributeType": "S"},
        ],
    )
    return DynamoPasskeyStore(Repository("passkeys", prefix="", region_name="us-west-2"))


@pytest.fixture
def dynamo_recovery_codes(dynamodb_resource: Any) -> Any:
    """A `DynamoRecoveryCodeStore` over a moto-backed `recovery-codes` table."""
    from webbpulse.dynamodb import Repository
    from webbpulse.identity.storage import DynamoRecoveryCodeStore

    _create_table(
        dynamodb_resource,
        "recovery-codes",
        KeySchema=[
            {"AttributeName": "user_id", "KeyType": "HASH"},
            {"AttributeName": "code_hash", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_id", "AttributeType": "S"},
            {"AttributeName": "code_hash", "AttributeType": "S"},
        ],
    )
    return DynamoRecoveryCodeStore(Repository("recovery-codes", prefix="", region_name="us-west-2"))


@pytest.fixture
def dynamo_oauth_links(dynamodb_resource: Any) -> Any:
    """A `DynamoOAuthLinkStore` over a moto-backed `oauth-links` table with its GSI."""
    from webbpulse.dynamodb import Repository
    from webbpulse.identity.oauth import DynamoOAuthLinkStore

    _create_table(
        dynamodb_resource,
        "oauth-links",
        KeySchema=[{"AttributeName": "provider_subject", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "provider_subject", "AttributeType": "S"},
            {"AttributeName": "user_id", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": OAUTH_LINK_USER_INDEX,
                "KeySchema": [{"AttributeName": "user_id", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    )
    return DynamoOAuthLinkStore(Repository("oauth-links", prefix="", region_name="us-west-2"))


def test_dynamo_credentials_delete_every_type_for_one_user(dynamo_credentials: Any) -> None:
    """Every credential type in the user's partition goes, and nobody else's does."""
    for credential_type in ("password", "legacy"):
        dynamo_credentials.put(CredentialRecord(user_id=USER_ID, credential_type=credential_type, secret="hashed"))
    dynamo_credentials.put(CredentialRecord(user_id=OTHER_USER_ID, credential_type="password", secret="hashed"))

    assert dynamo_credentials.delete_all_for_user(USER_ID) == 2
    assert dynamo_credentials.get(USER_ID, "password") is None
    assert dynamo_credentials.get(OTHER_USER_ID, "password") is not None
    assert dynamo_credentials.delete_all_for_user(USER_ID) == 0


def test_dynamo_refresh_deletes_rather_than_revokes(dynamo_refresh: Any) -> None:
    """The purge removes the rows outright, unlike `revoke_all_for_user` which marks them."""
    for index in range(3):
        dynamo_refresh.put(
            RefreshTokenRecord(
                token_hash=f"hash-{index}",
                family_id=f"family-{index}",
                user_id=USER_ID,
                generation=0,
                created_at="2026-09-13T00:00:00Z",
                expires_at=FAR_FUTURE,
            )
        )
    dynamo_refresh.put(
        RefreshTokenRecord(
            token_hash="theirs",
            family_id="theirs",
            user_id=OTHER_USER_ID,
            generation=0,
            created_at="2026-09-13T00:00:00Z",
            expires_at=FAR_FUTURE,
        )
    )

    assert dynamo_refresh.delete_all_for_user(USER_ID) == 3
    assert dynamo_refresh.get("hash-0") is None
    assert dynamo_refresh.get("theirs") is not None
    assert dynamo_refresh.delete_all_for_user(USER_ID) == 0


def test_dynamo_refresh_pages_through_a_large_result(dynamo_refresh: Any) -> None:
    """The query follows LastEvaluatedKey, so a user with many rows is fully purged."""
    for index in range(60):
        dynamo_refresh.put(
            RefreshTokenRecord(
                token_hash=f"hash-{index:03d}",
                family_id=f"family-{index:03d}",
                user_id=USER_ID,
                generation=0,
                created_at="2026-09-13T00:00:00Z",
                expires_at=FAR_FUTURE,
            )
        )

    assert dynamo_refresh.delete_all_for_user(USER_ID) == 60
    assert dynamo_refresh.get("hash-059") is None


def test_dynamo_refresh_without_an_index_says_so(dynamodb_resource: Any) -> None:
    """A table provisioned before the user index cannot enumerate, and says so rather than guessing."""
    from webbpulse.dynamodb import Repository
    from webbpulse.identity.storage import DynamoRefreshTokenStore

    _create_table(
        dynamodb_resource,
        "refresh-tokens",
        KeySchema=[{"AttributeName": "token_hash", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "token_hash", "AttributeType": "S"}],
    )
    store = DynamoRefreshTokenStore(Repository("refresh-tokens", prefix="", region_name="us-west-2"), user_index="")

    with pytest.raises(NotImplementedError):
        store.delete_all_for_user(USER_ID)


def test_dynamo_passkeys_delete_every_credential_for_one_user(dynamo_passkeys: Any) -> None:
    """Every passkey in the user's partition goes, and nobody else's does."""
    for index in range(2):
        dynamo_passkeys.put(PasskeyRecord(user_id=USER_ID, credential_id=f"cred-{index}", public_key="cose"))
    dynamo_passkeys.put(PasskeyRecord(user_id=OTHER_USER_ID, credential_id="theirs", public_key="cose"))

    assert dynamo_passkeys.delete_all_for_user(USER_ID) == 2
    assert dynamo_passkeys.list_for_user(USER_ID) == []
    assert len(dynamo_passkeys.list_for_user(OTHER_USER_ID)) == 1
    assert dynamo_passkeys.delete_all_for_user(USER_ID) == 0


def test_dynamo_recovery_codes_delete_the_whole_set(dynamo_recovery_codes: Any) -> None:
    """`delete_for_user` batches the deletes and reports the size of the set it removed."""
    dynamo_recovery_codes.put_many(
        [
            RecoveryCodeRecord(user_id=USER_ID, code_hash=f"code-{index}", created_at="2026-09-13T00:00:00Z")
            for index in range(30)
        ]
    )

    assert dynamo_recovery_codes.delete_for_user(USER_ID) == 30
    assert dynamo_recovery_codes.list_for_user(USER_ID) == []
    assert dynamo_recovery_codes.delete_for_user(USER_ID) == 0


def test_dynamo_oauth_links_delete_every_provider_for_one_user(dynamo_oauth_links: Any) -> None:
    """Every provider link the user holds goes, through the user index."""
    for provider in ("google", "github"):
        dynamo_oauth_links.put(
            OAuthLinkRecord(
                provider_subject=f"{provider}#{USER_ID}",
                provider=provider,
                subject=USER_ID,
                user_id=USER_ID,
                linked_at="2026-09-13T00:00:00Z",
            )
        )
    dynamo_oauth_links.put(
        OAuthLinkRecord(
            provider_subject=f"google#{OTHER_USER_ID}",
            provider="google",
            subject=OTHER_USER_ID,
            user_id=OTHER_USER_ID,
            linked_at="2026-09-13T00:00:00Z",
        )
    )

    assert dynamo_oauth_links.delete_all_for_user(USER_ID) == 2
    assert dynamo_oauth_links.list_for_user(USER_ID) == []
    assert len(dynamo_oauth_links.list_for_user(OTHER_USER_ID)) == 1
    assert dynamo_oauth_links.delete_all_for_user(USER_ID) == 0


def test_dynamo_identity_tokens_and_challenges_report_no_index(dynamodb_resource: Any) -> None:
    """Neither table carries a user index, and both say so rather than scanning."""
    from webbpulse.dynamodb import Repository
    from webbpulse.identity.storage import DynamoIdentityTokenStore, DynamoWebAuthnChallengeStore

    tokens = DynamoIdentityTokenStore(Repository("identity-tokens", prefix="", region_name="us-west-2"))
    challenges = DynamoWebAuthnChallengeStore(Repository("webauthn-challenges", prefix="", region_name="us-west-2"))

    with pytest.raises(NotImplementedError):
        tokens.delete_all_for_user(USER_ID)
    with pytest.raises(NotImplementedError):
        challenges.delete_all_for_user(USER_ID)


def test_repository_delete_many_tolerates_an_empty_key_list(dynamo_passkeys: Any) -> None:
    """Nothing to delete is not a batch write at all."""
    from webbpulse.dynamodb import Repository

    repo = Repository("passkeys", prefix="", region_name="us-west-2")
    assert repo.delete_many([]) == 0


def test_events_path_prefers_the_identity_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    """`IDENTITY_EVENTS_PATH` wins, then the adapter's own, then `/events`."""
    monkeypatch.delenv(EVENTS_PATH_ENV, raising=False)
    monkeypatch.delenv(LWA_PASS_THROUGH_PATH_ENV, raising=False)
    assert events_path() == DEFAULT_EVENTS_PATH

    monkeypatch.setenv(LWA_PASS_THROUGH_PATH_ENV, "/stream")
    assert events_path() == "/stream"

    monkeypatch.setenv(EVENTS_PATH_ENV, "purge/")
    assert events_path() == "/purge"


def test_users_key_attribute_defaults_to_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """`IDENTITY_USERS_KEY_ATTRIBUTE` names the key attribute, defaulting to `id`."""
    monkeypatch.delenv(USERS_KEY_ATTRIBUTE_ENV, raising=False)
    assert users_key_attribute() == DEFAULT_USERS_KEY_ATTRIBUTE

    monkeypatch.setenv(USERS_KEY_ATTRIBUTE_ENV, "user_id")
    assert users_key_attribute() == "user_id"


def remove_record(user_id: str, *, event_id: str = "evt-1", key_attribute: str = "id") -> dict[str, Any]:
    """One `REMOVE` record as a DynamoDB Stream sends it."""
    return {
        "eventID": event_id,
        "eventName": "REMOVE",
        "dynamodb": {"Keys": {key_attribute: {"S": user_id}}},
    }


@pytest.fixture
def events_client(kms: FakeKms, stores: IdentityStores) -> Iterator[tuple[TestClient, IdentityStores]]:
    """A client for an app mounting the identity router, with no gateway headers by default."""
    app = FastAPI()
    app.include_router(build_identity_router(make_settings(), FakeHooks(), stores, kms_client=kms))
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client, stores


def test_a_remove_record_purges_that_user(events_client: tuple[TestClient, IdentityStores]) -> None:
    """A `REMOVE` record empties the user's identity tables and reports no failures."""
    client, stores = events_client
    seed_every_table(stores)

    response = client.post(DEFAULT_EVENTS_PATH, json={"Records": [remove_record(USER_ID)]})

    assert response.status_code == 200
    assert response.json() == {"batchItemFailures": []}
    assert stores.require_credentials().get(USER_ID, "password") is None
    assert stores.require_passkeys().list_for_user(USER_ID) == []


def test_insert_and_modify_records_are_ignored(events_client: tuple[TestClient, IdentityStores]) -> None:
    """Creating or updating a users row says nothing about identity data, so nothing is purged."""
    client, stores = events_client
    seed_every_table(stores)

    for event_name in ("INSERT", "MODIFY"):
        record = remove_record(USER_ID) | {"eventName": event_name}
        response = client.post(DEFAULT_EVENTS_PATH, json={"Records": [record]})
        assert response.status_code == 200
        assert response.json() == {"batchItemFailures": []}

    assert stores.require_credentials().get(USER_ID, "password") is not None
    assert len(stores.require_passkeys().list_for_user(USER_ID)) == 1


def test_a_failing_record_is_reported_and_the_rest_still_purge(
    events_client: tuple[TestClient, IdentityStores],
) -> None:
    """Only the record that raised comes back, so the mapping retries it alone."""
    client, stores = events_client
    seed_every_table(stores)
    seed_every_table(stores, user_id=OTHER_USER_ID)

    real_delete = stores.require_passkeys().delete_all_for_user

    def selective(user_id: str) -> int:
        """Fail only for the first user, as a throttled partition would."""
        if user_id == USER_ID:
            raise RuntimeError("ProvisionedThroughputExceededException")
        return real_delete(user_id)

    stores.require_passkeys().delete_all_for_user = selective  # type: ignore[method-assign]

    response = client.post(
        DEFAULT_EVENTS_PATH,
        json={
            "Records": [
                remove_record(USER_ID, event_id="evt-bad"),
                remove_record(OTHER_USER_ID, event_id="evt-good"),
            ]
        },
    )

    assert response.status_code == 200
    assert response.json() == {"batchItemFailures": [{"itemIdentifier": "evt-bad"}]}
    assert stores.require_credentials().get(OTHER_USER_ID, "password") is None


def test_a_gateway_originated_request_is_refused(events_client: tuple[TestClient, IdentityStores]) -> None:
    """The route is reachable only through the adapter's pass-through, so a gateway call gets a 404."""
    from webbpulse.http import REQUEST_CONTEXT_HEADER

    client, stores = events_client
    seed_every_table(stores)
    body = {"Records": [remove_record(USER_ID)]}

    context = client.post(
        DEFAULT_EVENTS_PATH,
        json=body,
        headers={REQUEST_CONTEXT_HEADER: json.dumps({"requestId": "abc", "http": {"method": "POST"}})},
    )
    request_id = client.post(DEFAULT_EVENTS_PATH, json=body, headers={"x-amzn-requestid": "abc"})

    assert context.status_code == 404
    assert request_id.status_code == 404
    assert stores.require_credentials().get(USER_ID, "password") is not None


def test_a_record_with_no_readable_user_id_is_skipped(
    events_client: tuple[TestClient, IdentityStores], caplog: pytest.LogCaptureFixture
) -> None:
    """A key under a different attribute is logged and skipped, never reported as a failure."""
    client, stores = events_client
    seed_every_table(stores)

    with caplog.at_level("WARNING"):
        response = client.post(
            DEFAULT_EVENTS_PATH,
            json={"Records": [remove_record(USER_ID, key_attribute="pk")]},
        )

    assert response.json() == {"batchItemFailures": []}
    assert stores.require_credentials().get(USER_ID, "password") is not None
    assert any(record.__dict__.get("event") == "identity.purge_record_unreadable" for record in caplog.records)


def test_an_empty_batch_is_answered_with_no_failures(events_client: tuple[TestClient, IdentityStores]) -> None:
    """An empty or shapeless event is not an error: there is nothing to purge."""
    client, _ = events_client

    assert client.post(DEFAULT_EVENTS_PATH, json={"Records": []}).json() == {"batchItemFailures": []}
    assert client.post(DEFAULT_EVENTS_PATH, json=[]).json() == {"batchItemFailures": []}


def test_the_auth_routes_are_untouched(events_client: tuple[TestClient, IdentityStores]) -> None:
    """Mounting the stream route leaves the `/api/auth` prefix and its documents alone."""
    client, _ = events_client

    discovery = client.get("/api/auth/.well-known/openid-configuration")
    assert discovery.status_code == 200
    assert discovery.json()["issuer"] == ISSUER
    assert client.get("/api/auth/health").status_code == 200
    assert client.post("/api/auth/login", json={"email": "nobody@example.com", "password": "x"}).status_code == 401
