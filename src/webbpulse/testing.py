"""Pytest fixtures for services built on this package.

Enable them with `pytest_plugins = ["webbpulse.testing"]`. They cover a moto-backed
DynamoDB table, a `TestClient` whose requests carry a realistic API Gateway request
context, and a locally signing KMS stand-in. `FakeIdempotencyStore`, `FakePresigner`,
`FakeQueue` and `FakeWebhookSender` are the doubles for the seams a handler reaches the
outside world through, so a test needs neither moto nor a socket. `assert_entrypoint_isolation`
is the composition-layer check: it builds every domain's entrypoint in its own interpreter
and holds that each one imports its own domain package and no other. Import only from tests;
it needs the `testing` extra, and `FakeKms` additionally needs `cryptography`, which the
`identity` extra brings in.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Collection, Iterator, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from mypy_boto3_dynamodb.service_resource import Table

__all__ = [
    "EntrypointImports",
    "FakeIdempotencyStore",
    "FakeKms",
    "FakePresigner",
    "FakeQueue",
    "FakeWebhookSender",
    "assert_api_key_store_contract",
    "assert_entrypoint_isolation",
    "assert_share_token_store_contract",
    "assert_users_repository_contract",
    "aws_credentials",
    "create_table",
    "dynamodb_reset_hooks",
    "dynamodb_resource",
    "entrypoint_imports",
    "fake_kms",
    "identity_tables",
    "make_request_context_headers",
    "rate_limit_table",
    "rsa_key",
    "test_client",
]

_RATE_LIMIT_TABLE = "rate-limits"


@pytest.fixture
def aws_credentials() -> Iterator[None]:
    """Install fake AWS credentials and region for the duration of a test.

    botocore resolves credentials before moto intercepts anything, so setting them keeps
    the suite reproducible and stops a mis-scoped mock from reaching a real account.
    """
    previous = dict(os.environ)
    os.environ.update(
        {
            "AWS_ACCESS_KEY_ID": "testing",
            "AWS_SECRET_ACCESS_KEY": "testing",
            "AWS_SECURITY_TOKEN": "testing",
            "AWS_SESSION_TOKEN": "testing",
            "AWS_DEFAULT_REGION": "us-west-2",
            "AWS_REGION": "us-west-2",
        }
    )
    os.environ.pop("AWS_PROFILE", None)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(previous)


@pytest.fixture
def dynamodb_reset_hooks() -> list[Callable[[], None]]:
    """The cache-clearing callables `dynamodb_resource` runs on setup and teardown.

    The package's own `reset_resource_cache` is always run and is not in this list. A product
    that memoises its own boto3 resource overrides this fixture to add its reset, so its
    conftest drops the wrapper fixture it would otherwise have needed:

    ```python
    @pytest.fixture
    def dynamodb_reset_hooks() -> list[Callable[[], None]]:
        from app.db.client import reset_clients

        return [reset_clients]
    ```

    Each hook runs once before the mock opens and once after it closes, in the order given.
    """
    return []


@pytest.fixture
def dynamodb_resource(aws_credentials: None, dynamodb_reset_hooks: list[Callable[[], None]]) -> Iterator[Any]:
    """A moto-mocked DynamoDB service resource.

    The cached resource in `webbpulse.dynamodb` is cleared on both sides, along with every
    callable `dynamodb_reset_hooks` yields, so no client leaks into or out of the mock.
    """
    import boto3
    from moto import mock_aws

    from webbpulse.dynamodb import reset_resource_cache

    def reset() -> None:
        """Clear the package's cached resource and then every caller-supplied cache."""
        reset_resource_cache()
        for hook in dynamodb_reset_hooks:
            hook()

    reset()
    with mock_aws():
        yield boto3.resource("dynamodb", region_name="us-west-2")
    reset()


def create_table(
    resource: Any,
    name: str,
    *,
    hash_key: str = "pk",
    range_key: str | None = None,
    ttl_attribute: str | None = None,
    attribute_definitions: Collection[Mapping[str, str]] = (),
    global_secondary_indexes: Collection[Mapping[str, Any]] = (),
    stream_specification: Mapping[str, Any] | None = None,
    request: Mapping[str, Any] | None = None,
) -> Table:
    """Create one on-demand table, wait for it to exist and apply its TTL.

    The keyword arguments shape the common case. `request` is the escape hatch for anything
    they do not cover: a product holding a whole `CreateTable` keyword mapping, such as the
    one `webbpulse.identity.storage.TableSpec.create_table_request` builds, passes it whole
    and still gets the waiting and the TTL this helper does. Its keys win over the ones built
    here, so `request={"BillingMode": "PROVISIONED", ...}` overrides the default billing mode,
    and `TableName` is always `name`.

    Args:
        resource: A DynamoDB service resource, usually the `dynamodb_resource` fixture.
        name: The table name, which overrides any `TableName` in `request`.
        hash_key: The partition key attribute, typed `S`.
        range_key: The sort key attribute, typed `S`, or `None` for a hash-only table.
        ttl_attribute: Enables time to live on this attribute after the table exists. TTL is
            not part of `CreateTable`, so it is a second call either way.
        attribute_definitions: Extra `AttributeDefinitions` entries, for attributes an index
            keys on. They are merged with the key attributes, later entries winning, since
            DynamoDB rejects a name defined twice.
        global_secondary_indexes: `GlobalSecondaryIndexes` entries, passed through as given.
        stream_specification: The `StreamSpecification`, for a table a consumer test reads a
            stream from.
        request: Any further `CreateTable` keyword arguments, merged over everything above.

    Returns:
        The created `Table`, ready to use.
    """
    attributes: dict[str, dict[str, str]] = {hash_key: {"AttributeName": hash_key, "AttributeType": "S"}}
    schema: list[dict[str, str]] = [{"AttributeName": hash_key, "KeyType": "HASH"}]
    if range_key:
        attributes[range_key] = {"AttributeName": range_key, "AttributeType": "S"}
        schema.append({"AttributeName": range_key, "KeyType": "RANGE"})
    for definition in attribute_definitions:
        attributes[definition["AttributeName"]] = dict(definition)

    kwargs: dict[str, Any] = {
        "KeySchema": schema,
        "AttributeDefinitions": list(attributes.values()),
        "BillingMode": "PAY_PER_REQUEST",
    }
    if global_secondary_indexes:
        kwargs["GlobalSecondaryIndexes"] = [dict(index) for index in global_secondary_indexes]
    if stream_specification is not None:
        kwargs["StreamSpecification"] = dict(stream_specification)
    if request:
        kwargs.update(request)
    kwargs["TableName"] = name

    table = resource.create_table(**kwargs)
    table.wait_until_exists()
    if ttl_attribute:
        resource.meta.client.update_time_to_live(
            TableName=name,
            TimeToLiveSpecification={"Enabled": True, "AttributeName": ttl_attribute},
        )
    typed_table: Table = table
    return typed_table


@pytest.fixture
def rate_limit_table(dynamodb_resource: Any) -> Table:
    """The `rate-limits` table, shaped as the Terraform module creates it.

    Neither moto nor DynamoDB expires items promptly, so assert on the window key changing
    rather than on an old item having gone.
    """
    from webbpulse.ratelimit import TTL_ATTRIBUTE

    return create_table(dynamodb_resource, _RATE_LIMIT_TABLE, ttl_attribute=TTL_ATTRIBUTE)


@pytest.fixture
def identity_tables(dynamodb_resource: Any) -> Any:
    """Every identity table plus `users`, created under no prefix in the moto mock.

    The tables `webbpulse.identity.glue.create_identity_tables` builds, so a test drives the
    same schema a deployed service does. Yields the DynamoDB client they were created with,
    for a test that needs a second call against it.
    """
    from webbpulse.identity.glue import create_identity_tables

    client = dynamodb_resource.meta.client
    create_identity_tables(client, "")
    return client


def assert_users_repository_contract(repository: Any, *, email: str = "Someone@Example.COM") -> None:
    """Assert one users repository satisfies the shared contract, or raise `AssertionError`.

    The behaviour every product's `users` table owes the identity hooks: a row that round
    trips, a case-insensitive address lookup, an update that keeps the lookup index in step,
    a `KeyError` for an absent row, a batch read that skips what is gone, and a delete that
    is idempotent. A product with its own repository calls this from one test rather than
    restating the six.

    `repository` is anything with `webbpulse.identity.DynamoUsersRepository`'s methods, so a
    product's own class qualifies without importing this package's model.
    """
    from webbpulse.identity.users import User

    stored = repository.create(User(id="contract-1", email=email, display_name="Someone"))
    assert stored.id == "contract-1"

    found = repository.get("contract-1")
    assert found is not None, "A created user must be readable by id."
    assert found.display_name == "Someone"
    assert found.email_verified is False

    assert repository.get_by_email(email.lower()) is not None, "The address lookup must ignore case."
    assert repository.get_by_email(email.upper()) is not None, "The address lookup must ignore case."
    assert repository.get_by_email(f"  {email}  ") is not None, "The address lookup must ignore space."
    assert repository.get_by_email("nobody@example.com") is None
    assert repository.get_by_email("") is None

    verified = repository.update("contract-1", email_verified=True)
    assert verified.email_verified is True

    moved = repository.update("contract-1", email="Moved@Example.COM")
    assert moved.email_lower == "moved@example.com"
    assert repository.get_by_email("moved@example.com") is not None
    assert repository.get_by_email(email) is None, "The index must not still carry the old address."

    try:
        repository.update("missing", display_name="Nobody")
    except KeyError:
        pass
    else:  # pragma: no cover
        raise AssertionError("update must raise KeyError for a row that is not there.")

    many = repository.get_many(["contract-1", "missing"])
    assert set(many) == {"contract-1"}, "get_many must skip an id that is gone."

    assert repository.get("") is None
    assert repository.delete("contract-1") is True
    assert repository.delete("contract-1") is False, "delete must be idempotent."
    assert repository.get("contract-1") is None


def assert_api_key_store_contract(store: Any, *, tenant_id: str = "contract-tenant") -> None:
    """Assert one `ApiKeyStore` satisfies the shared contract, or raise `AssertionError`.

    The behaviour the identity package's verification and a settings page owe every store: a
    minted key that round trips with its id, kind, creator and metadata intact, a tenant
    listing, a count cheap enough to gate a create on, a revoke by id that needs no secret,
    and a row written before `key_id` existed staying revocable through its hash.

    `store` is anything with `webbpulse.identity.ApiKeyStore`'s methods, so a product's own
    class qualifies without subclassing this package's base.

    The store must be empty of `tenant_id` when this is called, because the contract asserts
    exact counts.
    """
    import dataclasses

    from webbpulse.identity.api_keys import ApiKeyRecord, hash_key, mint, verify

    assert store.count_for_tenant(tenant_id) == 0, "A tenant with no keys must count zero."
    assert store.list_for_tenant(tenant_id) == [], "A tenant with no keys must list empty."

    minted = mint(
        user_id="contract-user",
        tenant_id=tenant_id,
        scopes=["issues:read"],
        name="Contract key",
        store=store,
        kind="service",
        created_by="contract-admin",
        metadata={"label": "ci", "nested": {"team": "platform"}},
        created_at="2026-01-01T00:00:00Z",
    )
    record = minted.record
    assert record.key_id, "mint must allocate a key_id."
    assert record.revoke_handle == record.key_id

    stored = store.get(record.key_hash)
    assert stored is not None, "A minted key must be readable by its hash."
    assert stored.key_id == record.key_id, "key_id must round trip."
    assert stored.kind == "service", "kind must round trip."
    assert stored.created_by == "contract-admin", "created_by must round trip."
    assert stored.metadata == {"label": "ci", "nested": {"team": "platform"}}, "metadata must round trip untouched."

    assert store.count_for_tenant(tenant_id) == 1
    assert [row.key_id for row in store.list_for_tenant(tenant_id)] == [record.key_id]
    assert store.count_for_tenant("") == 0, "An empty tenant must never count another tenant's keys."

    found = store.get_by_id(tenant_id, record.key_id)
    assert found is not None, "get_by_id must find a key by its id."
    assert found.key_hash == record.key_hash
    assert store.get_by_id("other-tenant", record.key_id) is None, "A key id must not resolve in another tenant."
    assert store.get_by_id(tenant_id, "missing") is None
    assert store.get_by_id(tenant_id, "") is None

    assert verify(minted.plaintext, store) is not None, "A fresh key must verify."
    revoked = store.revoke_by_id(tenant_id, record.key_id)
    assert revoked is not None, "revoke_by_id must revoke a live key."
    assert store.revoke_by_id(tenant_id, record.key_id) is None, "A second revoke must report nothing to do."
    assert verify(minted.plaintext, store) is None, "A revoked key must stop verifying."

    legacy_plaintext = "wpk_contract-legacy"
    legacy = ApiKeyRecord(
        key_hash=hash_key(legacy_plaintext),
        user_id="contract-user",
        tenant_id=tenant_id,
        prefix="wpk_contract",
        created_at="2026-01-02T00:00:00Z",
    )
    assert legacy.key_id == "", "A record built without a key_id must have none."
    assert legacy.revoke_handle == legacy.key_hash, "revoke_handle must fall back to the hash."
    store.put(legacy)

    reloaded = store.get(legacy.key_hash)
    assert reloaded is not None, "A row with no key_id must still load."
    assert reloaded.key_id == ""
    assert reloaded.kind == "user", "A row with no kind must default to the user kind."
    assert reloaded.created_by is None, "An unrecorded creator must be None, not an empty string."
    assert reloaded.metadata == {}

    assert store.count_for_tenant(tenant_id) == 2
    by_hash = store.get_by_id(tenant_id, legacy.key_hash)
    assert by_hash is not None, "A row with no key_id must be reachable by its hash."
    assert store.revoke_by_id(tenant_id, legacy.key_hash) is not None, "A legacy row must be revocable by its hash."
    assert verify(legacy_plaintext, store) is None

    adopted = dataclasses.replace(legacy, key_hash=hash_key("wpk_contract-adopted"), key_id="adopted-id")
    assert adopted.revoke_handle == "adopted-id"


def assert_share_token_store_contract(store: Any, *, tenant_id: str = "contract-tenant") -> None:
    """Assert one `ShareTokenStore` satisfies the shared contract, or raise `AssertionError`.

    The behaviour a product's share listing owes every store: a token that round trips with
    its target, a per-target listing that returns that target's rows and no other's, a revoke
    that clears every link onto one resource, and a token minted with no target staying
    resolvable while never appearing in a target listing.

    `store` is anything with `webbpulse.identity.ShareTokenStore`'s methods.

    The store must be empty of `tenant_id` when this is called, because the contract asserts
    exact listings.
    """
    from webbpulse.identity.share_tokens import ShareTarget, mint_share_token, verify_share_token

    issue = ShareTarget(type="issue", id="i1")
    other = ShareTarget(type="issue", id="i2")
    view = ShareTarget(type="view", id="i1")

    assert store.list_for_target(tenant_id, issue) == [], "A target with no links must list empty."

    first = mint_share_token(
        tenant_id=tenant_id,
        capability={"project_id": "p1", "title": "One"},
        target=issue,
        store=store,
        created_at="2026-01-01T00:00:00Z",
    )
    second = mint_share_token(
        tenant_id=tenant_id,
        capability={"project_id": "p1", "title": "Two"},
        target=("issue", "i1"),
        store=store,
        created_at="2026-01-02T00:00:00Z",
    )
    mint_share_token(tenant_id=tenant_id, target=other, store=store, created_at="2026-01-03T00:00:00Z")
    mint_share_token(tenant_id=tenant_id, target=view, store=store, created_at="2026-01-04T00:00:00Z")
    untargeted = mint_share_token(tenant_id=tenant_id, store=store, created_at="2026-01-05T00:00:00Z")

    stored = store.get(first.record.token_hash)
    assert stored is not None
    assert stored.target == issue, "The target must round trip."
    assert stored.target_key == "issue#i1"
    assert stored.capability == {"project_id": "p1", "title": "One"}, "capability must round trip beside the target."

    hashes = [row.token_hash for row in store.list_for_target(tenant_id, issue)]
    assert hashes == [first.record.token_hash, second.record.token_hash], "A target listing is oldest first."

    assert [row.token_hash for row in store.list_for_target(tenant_id, other)] == [
        row.token_hash for row in store.list_for_target(tenant_id, ("issue", "i2"))
    ], "A pair and a ShareTarget must name the same target."

    view_rows = store.list_for_target(tenant_id, view)
    assert len(view_rows) == 1, "A type and an id must be matched together, not either alone."
    assert view_rows[0].target_type == "view"

    assert store.list_for_target("other-tenant", issue) == [], "A target must not resolve in another tenant."
    assert store.list_for_target("", issue) == [], "An empty tenant must never span tenants."
    assert store.list_for_target(tenant_id, ("issue", "")) == [], "An incomplete target must list empty."

    assert untargeted.record.target_key == "", "A token with no target carries no target key."
    assert verify_share_token(untargeted.plaintext, store) is not None, "A token with no target still resolves."
    assert all(row.token_hash != untargeted.record.token_hash for row in store.list_for_target(tenant_id, issue)), (
        "A token with no target must not appear in a target listing."
    )

    assert store.revoke_all_for_target(tenant_id, issue) == 2, "Revoking a target clears every link onto it."
    assert store.revoke_all_for_target(tenant_id, issue) == 0, "A second revoke must report nothing to do."
    assert verify_share_token(first.plaintext, store) is None
    assert verify_share_token(second.plaintext, store) is None
    assert len(store.list_for_target(tenant_id, issue)) == 2, "A revoked link stays listed."
    assert store.revoke_all_for_target(tenant_id, other) == 1, "Another target must be untouched."


def make_request_context_headers(
    source_ip: str = "203.0.113.10",
    *,
    payload_format: str = "2.0",
    extra: Mapping[str, Any] | None = None,
) -> dict[str, str]:
    """Build the `x-amzn-request-context` header the Web Adapter injects.

    `payload_format="2.0"` produces the HTTP API shape and `"1.0"` the REST shape, and both
    are worth exercising.
    """
    if payload_format == "2.0":
        context: dict[str, Any] = {
            "requestId": "test-request-id",
            "http": {"method": "GET", "path": "/", "sourceIp": source_ip},
        }
    elif payload_format == "1.0":
        context = {"requestId": "test-request-id", "identity": {"sourceIp": source_ip}}
    else:
        raise ValueError(f"payload_format must be '1.0' or '2.0', got {payload_format!r}.")
    if extra:
        context.update(extra)

    from webbpulse.http import REQUEST_CONTEXT_HEADER

    return {REQUEST_CONTEXT_HEADER: json.dumps(context)}


@pytest.fixture
def test_client() -> Iterator[Any]:
    """A factory returning a `TestClient` for an app, with an API Gateway context header.

    The default headers make `client_ip` return the given `source_ip` rather than falling
    back to the testserver peer. Every client the factory builds is closed at teardown.
    """
    from fastapi.testclient import TestClient

    clients: list[TestClient] = []

    def factory(
        app: FastAPI,
        *,
        source_ip: str = "203.0.113.10",
        payload_format: str = "2.0",
        raise_server_exceptions: bool = False,
        **kwargs: Any,
    ) -> TestClient:
        """Build a client for `app` whose requests carry the API Gateway context header.

        `raise_server_exceptions` is off by default so the 500 envelope is rendered and
        can be asserted on.
        """
        client = TestClient(
            app,
            headers=make_request_context_headers(source_ip, payload_format=payload_format),
            raise_server_exceptions=raise_server_exceptions,
            **kwargs,
        )
        clients.append(client)
        return client

    yield factory
    for client in clients:
        client.close()


class FakeKms:
    """A stand-in for the KMS client the identity token service signs with.

    It signs for real with private keys held in the process, so a token it mints verifies
    against the JWKs built from the same keys and a test can assert on the whole chain
    rather than on a stubbed signature. It implements the two calls the token service makes,
    `get_public_key` and `sign`, with KMS's own keyword-only argument spelling.

    Signing is over the digest the caller passes, without re-hashing it, which is what
    `MessageType="DIGEST"` means in the KMS contract, and the signature is the raw PKCS #1
    v1.5 octet string KMS returns.
    """

    def __init__(
        self,
        keys: Any,
        der: bytes | None = None,
        *,
        key_spec: str = "RSA_2048",
        failing: Collection[str] = (),
    ) -> None:
        """Hold the signing keys and what to report about them.

        Args:
            keys: One `RSAPrivateKey`, or a mapping of key id to `RSAPrivateKey` for a test
                that rotates or serves several. A single key answers for every key id asked
                for, which is what a single-key test wants.
            der: The DER SubjectPublicKeyInfo to report for a single key. Derived from the
                key when omitted; pass it only to report a public key that does not match
                what the fake signs with.
            key_spec: The `KeySpec` to report. `RSA_2048` matches `KMS_KEY_SPEC`.
            failing: Key ids whose `get_public_key` raises, for exercising the token
                service's handling of a signing key that has gone away.

        Raises:
            ValueError: When `der` is passed alongside a mapping of keys, where it could
                only apply to one of them.
        """
        if isinstance(keys, Mapping):
            if der is not None:
                raise ValueError("der applies to a single key; with a key mapping the DER is derived per key.")
            self._keys: dict[str, Any] = dict(keys)
            self._single: Any | None = None
        else:
            self._keys = {}
            self._single = keys
        self._der = der
        self._key_spec = key_spec
        self._failing = frozenset(failing)
        self.get_public_key_calls: list[str] = []
        self.sign_calls: list[dict[str, Any]] = []

    def _key_for(self, key_id: str) -> Any:
        """The private key serving `key_id`, or raise `KeyError` for an unknown one."""
        if self._single is not None:
            return self._single
        return self._keys[key_id]

    def der_for(self, key_id: str) -> bytes:
        """The DER SubjectPublicKeyInfo this fake reports for `key_id`.

        Useful for asserting on a `kid`, which `kid_for_der` derives from exactly these
        bytes.
        """
        if self._single is not None and self._der is not None:
            return self._der
        from cryptography.hazmat.primitives import serialization

        public_bytes: bytes = (
            self._key_for(key_id)
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        return public_bytes

    def get_public_key(self, *, KeyId: str) -> dict[str, Any]:
        """Answer the `kms:GetPublicKey` shape for one key, recording the call.

        Raises `RuntimeError` naming the key when it is in `failing`, standing in for the
        `NotFoundException` a deleted key produces.
        """
        self.get_public_key_calls.append(KeyId)
        if KeyId in self._failing:
            raise RuntimeError(f"NotFoundException: key {KeyId} does not exist")

        from webbpulse.identity import KMS_SIGNING_ALGORITHM

        return {
            "KeyId": KeyId,
            "PublicKey": self.der_for(KeyId),
            "KeySpec": self._key_spec,
            "KeyUsage": "SIGN_VERIFY",
            "SigningAlgorithms": [KMS_SIGNING_ALGORITHM],
        }

    def sign(self, *, KeyId: str, Message: bytes, MessageType: str, SigningAlgorithm: str) -> dict[str, Any]:
        """Sign the prehashed message the way KMS would, recording the call.

        The arguments are recorded on `sign_calls` before signing, so a test can assert the
        token service asked for `DIGEST` and `RSASSA_PKCS1_V1_5_SHA_256` rather than
        trusting that it did.
        """
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, utils

        self.sign_calls.append(
            {
                "KeyId": KeyId,
                "Message": Message,
                "MessageType": MessageType,
                "SigningAlgorithm": SigningAlgorithm,
            }
        )
        signature = self._key_for(KeyId).sign(Message, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
        return {"KeyId": KeyId, "Signature": signature, "SigningAlgorithm": SigningAlgorithm}


@pytest.fixture
def fake_kms(rsa_key: Any) -> FakeKms:
    """A locally signing KMS stand-in for one test, over the module's shared RSA key.

    Depends on `rsa_key`, so a module wanting several keys builds `FakeKms` directly with a
    mapping rather than through this fixture.
    """
    return FakeKms(rsa_key)


@pytest.fixture(scope="module")
def rsa_key() -> Any:
    """One 2048-bit RSA key for the module. Generation is slow enough to be worth sharing."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeIdempotencyStore:
    """An in-process stand-in for `webbpulse.dynamodb.IdempotencyStore`, without a table.

    It answers `claim` and `release` with the same signatures, so a handler typed against the
    real store takes this one with no adapter. Claims are held in a dict with the monotonic
    deadline each was taken under, and expiry is evaluated on read: unlike DynamoDB's TTL,
    which deletes on its own schedule, this one forgets a key the moment its window passes, so
    a test asserting that a replay after expiry wins need not sleep on a background sweeper.

    `claims` records every key `claim` was called with, winners and losers alike, which is what
    a test asserting that a handler claimed before doing the work reads.
    """

    def __init__(self, *, now: Any | None = None) -> None:
        """Start with nothing claimed, optionally over a caller-supplied clock.

        Args:
            now: A zero-argument callable returning seconds as a float, defaulting to
                `time.monotonic`. Pass one to drive expiry forward without sleeping.
        """
        import time

        self._now = now if now is not None else time.monotonic
        self._deadlines: dict[str, float] = {}
        self.claims: list[str] = []

    def claim(self, key: str, ttl_seconds: float) -> bool:
        """Claim `key`, answering whether this caller won, exactly as the real store does.

        Raises:
            ValueError: When `ttl_seconds` is not positive, matching the real store.
        """
        if ttl_seconds <= 0:
            raise ValueError(f"claim needs a positive ttl_seconds, got {ttl_seconds}.")
        self.claims.append(key)
        moment = self._now()
        deadline = self._deadlines.get(key)
        if deadline is not None and deadline > moment:
            return False
        self._deadlines[key] = moment + ttl_seconds
        return True

    def release(self, key: str) -> None:
        """Drop a claim. Releasing a key nobody claimed is not an error."""
        self._deadlines.pop(key, None)


class FakePresigner:
    """A stand-in for the S3 client `webbpulse.storage.presigned_put` signs with.

    It returns a deterministic URL rather than a signed one and records the arguments it was
    asked to sign, which is the assertion worth making: a presigned PUT's guard lives entirely
    in the `Params` that go into the signature, so a test proves the content type and the
    length were signed in rather than merely returned as headers.
    """

    def __init__(self, base_url: str = "https://s3.example.invalid") -> None:
        """Hold the host the generated URLs are built under and start with no calls."""
        self.base_url = base_url
        self.calls: list[dict[str, Any]] = []

    def generate_presigned_url(
        self,
        ClientMethod: str,
        Params: dict[str, Any],
        ExpiresIn: int,
        HttpMethod: str | None = None,
    ) -> str:
        """Record the request and answer a URL naming the bucket and key it authorises."""
        self.calls.append(
            {
                "ClientMethod": ClientMethod,
                "Params": dict(Params),
                "ExpiresIn": ExpiresIn,
                "HttpMethod": HttpMethod,
            }
        )
        return f"{self.base_url}/{Params['Bucket']}/{Params['Key']}?X-Amz-Expires={ExpiresIn}"


class FakeQueue:
    """A stand-in for the SQS client `webbpulse.events.enqueue` sends through.

    It records every `send_message` request whole, so a test asserts on the body that was
    sent, on the FIFO group and deduplication ids, and on the order of the sends, rather
    than on a mock's call object. It satisfies `webbpulse.events.QueueClient` structurally,
    so no inheritance and no moto.

    `failing` makes the next sends raise, which is how a test exercises a producer's own
    error handling: pass the number of sends that should fail before one succeeds.
    """

    def __init__(self, *, failing: int = 0) -> None:
        """Start with an empty log and `failing` sends set to raise."""
        self.requests: list[dict[str, Any]] = []
        self._failing = failing
        self._sent = 0

    def send_message(self, **kwargs: Any) -> dict[str, Any]:
        """Record one send and answer the `MessageId` shape SQS returns.

        Raises `RuntimeError` while the failure budget lasts, standing in for the
        `ClientError` a throttled or missing queue produces.
        """
        self.requests.append(dict(kwargs))
        if self._failing > 0:
            self._failing -= 1
            raise RuntimeError("ServiceUnavailable: the queue did not accept the message")
        self._sent += 1
        return {"MessageId": f"msg-{self._sent}", "MD5OfMessageBody": "0" * 32}

    @property
    def bodies(self) -> list[Any]:
        """Every sent `MessageBody`, parsed from JSON, in the order it was sent."""
        return [json.loads(request["MessageBody"]) for request in self.requests]

    @property
    def last_body(self) -> Any:
        """The most recent parsed `MessageBody`, or `None` when nothing was sent."""
        return self.bodies[-1] if self.requests else None


class FakeWebhookSender:
    """A stand-in for the transport `webbpulse.events.webhooks.WebhookDispatcher` posts through.

    Every call is recorded on `calls` with the url, the body and the headers, so a test can
    verify the signature the dispatcher produced by re-deriving it, and the responses are
    scripted: `responses` is consumed one per attempt, and once it runs out `default`
    answers the rest. That is what makes a retry test deterministic, with no sleeping and no
    socket.

    It satisfies `WebhookSender` structurally, so it needs neither `httpx` nor inheritance.
    """

    def __init__(
        self,
        responses: Collection[Any] = (),
        *,
        default: Any = None,
    ) -> None:
        """Hold the scripted responses and the one to answer with after they run out.

        Args:
            responses: The `WebhookResponse` values to answer with, one per attempt, in
                order. An `int` is accepted as shorthand for a response with that status.
            default: What to answer once `responses` is exhausted. A 200 when omitted, so a
                fake with no script always delivers.
        """
        from webbpulse.events.webhooks import WebhookResponse

        self.calls: list[dict[str, Any]] = []
        self._scripted = [_as_webhook_response(item) for item in responses]
        self._default = _as_webhook_response(default) if default is not None else WebhookResponse(status_code=200)

    def post(self, url: str, *, body: bytes, headers: Mapping[str, str], timeout: float) -> Any:
        """Record the attempt and answer the next scripted response."""
        self.calls.append({"url": url, "body": body, "headers": dict(headers), "timeout": timeout})
        if self._scripted:
            return self._scripted.pop(0)
        return self._default

    @property
    def attempts(self) -> int:
        """How many times the dispatcher posted."""
        return len(self.calls)

    @property
    def last_call(self) -> dict[str, Any] | None:
        """The most recent recorded attempt, or `None` when nothing was posted."""
        return self.calls[-1] if self.calls else None


def _as_webhook_response(item: Any) -> Any:
    """Read a scripted entry as a `WebhookResponse`, accepting a bare status code."""
    from webbpulse.events.webhooks import WebhookResponse

    return WebhookResponse(status_code=item) if isinstance(item, int) else item


@dataclass(frozen=True)
class EntrypointImports:
    """What one domain's entrypoint imported in a fresh interpreter.

    `foreign` is the assertion that matters: the modules under `package_root` that belong to
    some other domain. An empty `foreign` is the claim that makes N images smaller than N
    copies of one image.
    """

    domain: str
    module: str
    imported: frozenset[str]
    foreign: frozenset[str]

    def __bool__(self) -> bool:
        """Whether this entrypoint imported only its own domain."""
        return not self.foreign


def entrypoint_imports(
    domain: str,
    *,
    module: str,
    package: str,
    package_root: str = "app.domains.",
    allowed_foreign: Collection[str] = (),
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float = 180.0,
) -> EntrypointImports:
    """Build one domain's entrypoint in a subprocess and report what it imported.

    A subprocess because the suite calling this has already imported every domain, so an
    in-process check would read the suite's imports rather than the image's. The child runs
    with a stripped environment, so an entrypoint that needed credentials to build would
    fail here rather than in a cold start.

    `module` is the entrypoint module to import, `package` the domain's own package under
    `package_root`, and `package_root` the prefix every domain package shares, defaulting to
    `"app.domains."` as `assert_entrypoint_isolation` does.

    `allowed_foreign` names module paths every domain may import although they live under
    another domain, for the case a product's shared middleware legitimately needs one
    domain's glue: an authorizer every domain mounts, built from the identity domain's
    `package_glue`, is the shape this is for. A listed module and its submodules are not
    reported as foreign; everything else still is. Raises `AssertionError` when the child
    fails, with its stderr.
    """
    import subprocess  # nosec B404
    import sys

    program = _ENTRYPOINT_PROBE.format(module=module, root=package_root)
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": str(cwd) if cwd is not None else os.environ.get("PYTHONPATH", ""),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    environment.update(env or {})
    result = subprocess.run(  # nosec B603
        [sys.executable, "-c", program],
        cwd=str(cwd) if cwd is not None else None,
        env=environment,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    assert result.returncode == 0, f"building the {domain} entrypoint in a fresh interpreter failed:\n{result.stderr}"

    imported = frozenset(name for name in json.loads(result.stdout.strip().splitlines()[-1]) if name)
    own = f"{package_root}{package}"
    allowed = tuple(allowed_foreign)
    ancestors = _allowed_ancestors(allowed, package_root)
    foreign = frozenset(
        name
        for name in imported
        if name != package_root.rstrip(".")
        and name != own
        and not name.startswith(f"{own}.")
        and name not in ancestors
        and not any(name == permitted or name.startswith(f"{permitted}.") for permitted in allowed)
    )
    return EntrypointImports(domain=domain, module=module, imported=imported, foreign=foreign)


def _allowed_ancestors(allowed_foreign: Collection[str], package_root: str) -> frozenset[str]:
    """The packages between each allowed module and `package_root`, exactly and no further.

    Importing `app.domains.identity.package_glue` imports `app.domains.identity` as well,
    because Python cannot reach a submodule without its parents, and reporting that parent
    as foreign would defeat the allowance. These are matched exactly rather than by prefix,
    so allowing one module of a domain never opens the rest of it: the glue lands in every
    image and that domain's endpoints must not follow it there.
    """
    root = package_root.rstrip(".")
    ancestors: set[str] = set()
    for permitted in allowed_foreign:
        parts = permitted.split(".")
        for index in range(len(parts) - 1, 0, -1):
            ancestor = ".".join(parts[:index])
            if ancestor == root or not ancestor.startswith(f"{root}."):
                break
            ancestors.add(ancestor)
    return frozenset(ancestors)


_ENTRYPOINT_PROBE = (
    "import json, sys\n"
    "import importlib\n"
    "entrypoint = importlib.import_module({module!r})\n"
    "entrypoint.build_app()\n"
    "print(json.dumps(sorted(m for m in sys.modules if m.startswith({root!r}))))\n"
)


def assert_entrypoint_isolation(
    registry: Mapping[str, Any],
    *,
    entrypoint_module: Callable[[str], str] | None = None,
    package_root: str = "app.domains.",
    module_template: str = "{root}{package}.entrypoint",
    allowed_foreign: Mapping[str, Collection[str]] | Collection[str] = (),
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    domains: Collection[str] | None = None,
) -> dict[str, EntrypointImports]:
    """Every domain's entrypoint imports its own domain package and no other.

    The whole-registry form of `entrypoint_imports`, and what a product's
    `tests/entrypoints/test_entrypoint_isolation.py` becomes: one call, parameterised by
    the registry, asserting the same thing both adopting products assert today. Raises
    `AssertionError` naming every domain that reached into another, and returns the probe
    results so a caller can assert something further about them.

    `entrypoint_module` maps a domain name to its package name, defaulting to the registry's
    own method when it has one and to a hyphen-to-underscore translation otherwise.

    `allowed_foreign` is the exception list for a foreign module every domain legitimately
    imports, such as the identity glue a product's shared local authorizer is built from.
    A collection of module paths applies to every domain; a mapping of domain name to
    collection applies per domain, and a domain the mapping does not name allows none.
    Anything outside it is refused exactly as before.
    """
    resolve = entrypoint_module
    if resolve is None:
        registry_resolver = getattr(registry, "entrypoint_module", None)
        resolve = registry_resolver if callable(registry_resolver) else (lambda name: name.replace("-", "_"))

    results: dict[str, EntrypointImports] = {}
    for domain in domains if domains is not None else registry:
        package = resolve(domain)
        results[domain] = entrypoint_imports(
            domain,
            module=module_template.format(root=package_root, package=package),
            package=package,
            package_root=package_root,
            allowed_foreign=_allowed_foreign_for(allowed_foreign, domain),
            cwd=cwd,
            env=env,
        )

    leaked = {domain: sorted(result.foreign) for domain, result in results.items() if result.foreign}
    assert not leaked, "\n".join(f"the {domain} image also imported {modules}" for domain, modules in leaked.items())
    return results


def _allowed_foreign_for(
    allowed_foreign: Mapping[str, Collection[str]] | Collection[str],
    domain: str,
) -> Collection[str]:
    """The foreign modules one domain may import, from either shape of the argument.

    A mapping is read per domain and names nothing for a domain it omits; any other
    collection applies to every domain alike.
    """
    if isinstance(allowed_foreign, Mapping):
        return allowed_foreign.get(domain, ())
    return allowed_foreign
