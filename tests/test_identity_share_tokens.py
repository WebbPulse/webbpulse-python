"""`webbpulse.identity.share_tokens`, and the tenant dimension on `api_keys`.

Two properties worth stating once: a share token's whole authority is the capability its row
carries, and a credential bound to one tenant never acts inside another.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

from webbpulse.identity.api_keys import (
    ACTOR_CLAIM,
    API_KEY_TABLE,
    API_KEY_TENANT_INDEX,
    TENANT_CLAIM,
    FakeApiKeyStore,
    mint,
    verify_for_tenant,
)
from webbpulse.identity.claims import AuthorizerClaims
from webbpulse.identity.scopes import (
    UNAUTHENTICATED_ERROR_CODE,
    claims_or_api_key,
    claims_tenant,
    require_scopes,
    require_tenant,
    tenant_matches,
)
from webbpulse.identity.share_tokens import (
    ACTOR_SHARE_TOKEN,
    CAPABILITY_CLAIM,
    SHARE_TOKEN_PREFIX,
    SHARE_TOKEN_SUBJECT,
    SHARE_TOKEN_TABLE,
    SHARE_TOKEN_TENANT_INDEX,
    FakeShareTokenStore,
    ShareTokenRecord,
    claims_for_share_token,
    claims_or_credential,
    hash_share_token,
    is_share_token,
    is_share_token_actor,
    mint_share_token,
    new_share_token,
    revoke_share_token,
    share_token_capability,
    verify_share_token,
)

if TYPE_CHECKING:  # pragma: no cover
    from fastapi.testclient import TestClient


@pytest.fixture
def keys() -> FakeApiKeyStore:
    """An empty in-memory API key store."""
    return FakeApiKeyStore()


@pytest.fixture
def shares() -> FakeShareTokenStore:
    """An empty in-memory share token store."""
    return FakeShareTokenStore()


def test_a_tenant_can_list_its_own_keys(keys: FakeApiKeyStore) -> None:
    """The gap this closes: every key of one tenant, without a scan."""
    mint(user_id="u1", tenant_id="t1", scopes=[], store=keys, created_at="2026-01-01T00:00:00Z")
    mint(user_id="u2", tenant_id="t1", scopes=[], store=keys, created_at="2026-01-02T00:00:00Z")
    mint(user_id="u1", tenant_id="t2", scopes=[], store=keys)

    listed = keys.list_for_tenant("t1")

    assert [record.user_id for record in listed] == ["u1", "u2"]
    assert all(record.tenant_id == "t1" for record in listed)


def test_revoking_a_tenant_revokes_only_that_tenants_keys(keys: FakeApiKeyStore) -> None:
    """The offboarding verb stops one tenant authenticating and leaves every other alone."""
    a = mint(user_id="u1", tenant_id="t1", scopes=[], store=keys)
    b = mint(user_id="u2", tenant_id="t1", scopes=[], store=keys)
    other = mint(user_id="u3", tenant_id="t2", scopes=[], store=keys)

    assert keys.revoke_all_for_tenant("t1") == 2

    for minted in (a, b):
        record = keys.get(minted.record.key_hash)
        assert record is not None and record.is_revoked
    kept = keys.get(other.record.key_hash)
    assert kept is not None and not kept.is_revoked


def test_revoking_a_tenant_twice_revokes_nothing_the_second_time(keys: FakeApiKeyStore) -> None:
    """An already revoked key is not counted again, so the number means what it says."""
    mint(user_id="u1", tenant_id="t1", scopes=[], store=keys)

    assert keys.revoke_all_for_tenant("t1") == 1
    assert keys.revoke_all_for_tenant("t1") == 0


def test_a_store_without_a_tenant_index_answers_empty_rather_than_scanning() -> None:
    """The default keeps a store written before this method existed satisfying the protocol."""
    from webbpulse.identity.api_keys import ApiKeyRecord, ApiKeyStore

    class Legacy(ApiKeyStore):
        """A store predating the tenant dimension, implementing only the original six."""

        def get(self, key_hash: str) -> ApiKeyRecord | None:
            """No rows."""
            return None

        def put(self, record: ApiKeyRecord) -> None:
            """Discard."""

        def list_for_user(self, user_id: str) -> list[ApiKeyRecord]:
            """No rows."""
            return []

        def revoke(self, key_hash: str, *, revoked_at: str | None = None) -> ApiKeyRecord | None:
            """Nothing to revoke."""
            return None

        def touch(self, key_hash: str, *, used_at: str | None = None) -> None:
            """Discard."""

        def delete_all_for_user(self, user_id: str) -> int:
            """Nothing to delete."""
            return 0

    store = Legacy()

    assert store.list_for_tenant("t1") == []
    assert store.revoke_all_for_tenant("t1") == 0


def test_verify_for_tenant_refuses_a_key_from_another_tenant(keys: FakeApiKeyStore) -> None:
    """A key minted in one tenant may never act in another, whatever its minter belongs to."""
    minted = mint(user_id="u1", tenant_id="t1", scopes=["issues:read"], store=keys)

    assert verify_for_tenant(minted.plaintext, keys, "t1") is not None
    assert verify_for_tenant(minted.plaintext, keys, "t2") is None


def test_verify_for_tenant_refuses_an_unresolved_tenant(keys: FakeApiKeyStore) -> None:
    """An empty tenant refuses rather than matching everything."""
    minted = mint(user_id="u1", tenant_id="t1", scopes=[], store=keys)

    assert verify_for_tenant(minted.plaintext, keys, "") is None


def test_the_tenant_reaches_the_claims(keys: FakeApiKeyStore) -> None:
    """A product fails closed on mismatch by reading the tenant off the claims it was given."""
    minted = mint(user_id="u1", tenant_id="t1", scopes=[], store=keys)

    from webbpulse.identity.api_keys import claims_for_key

    claims = claims_for_key(minted.record)

    assert claims[TENANT_CLAIM] == "t1"
    assert claims_tenant(claims) == "t1"
    assert tenant_matches(claims, "t1")
    assert not tenant_matches(claims, "t2")


def test_an_unbound_credential_matches_every_tenant() -> None:
    """A session JWT carries no tenant, and is not a credential bound somewhere else."""
    claims = AuthorizerClaims({"sub": "u1"})

    assert claims_tenant(claims) == ""
    assert tenant_matches(claims, "t1")


def test_the_api_key_table_declares_the_tenant_index() -> None:
    """The GSI the platform identity module must provision, named and keyed exactly."""
    index = {gsi.name: gsi for gsi in API_KEY_TABLE.global_secondary_indexes}[API_KEY_TENANT_INDEX]

    assert (index.hash_key, index.range_key, index.projection_type) == ("tenant_id", "created_at", "ALL")
    assert ("tenant_id", "S") in {(attribute.name, attribute.type) for attribute in API_KEY_TABLE.attributes}


def test_a_minted_share_token_carries_the_prefix_and_fresh_entropy() -> None:
    """Every token starts with its own prefix, distinct from a key's, and no two are alike."""
    tokens = {new_share_token() for _ in range(32)}

    assert len(tokens) == 32
    assert all(token.startswith(SHARE_TOKEN_PREFIX) for token in tokens)
    assert all(is_share_token(token) for token in tokens)
    assert not is_share_token("wpk_something")


def test_only_the_hash_is_stored(shares: FakeShareTokenStore) -> None:
    """The plaintext exists once, in the mint return value, and nowhere in the store."""
    minted = mint_share_token(tenant_id="t1", capability={"view": "v1"}, store=shares)

    stored = shares.get(minted.record.token_hash)

    assert stored is not None
    assert stored.token_hash == hash_share_token(minted.plaintext)
    assert minted.plaintext not in str(dataclasses.asdict(stored))


def test_the_capability_payload_is_opaque(shares: FakeShareTokenStore) -> None:
    """Whatever a product puts there comes back unchanged, so the package is not issue specific."""
    payload = {"kind": "gallery", "album_id": "a1", "nested": {"page": 2}}
    minted = mint_share_token(tenant_id="t1", capability=payload, store=shares)

    record = verify_share_token(minted.plaintext, shares)

    assert record is not None
    assert record.capability == payload


@pytest.mark.parametrize("presented", ["", "wpk_notashare", "nonsense"])
def test_a_value_of_the_wrong_shape_never_reaches_the_store(shares: FakeShareTokenStore, presented: str) -> None:
    """The prefix test decides which verifier runs, so a key is not run through this one."""
    assert verify_share_token(presented, shares) is None


def test_an_unknown_revoked_and_expired_token_are_indistinguishable(shares: FakeShareTokenStore) -> None:
    """`None` for every refusal, because the reader is anonymous."""
    revoked = mint_share_token(tenant_id="t1", store=shares)
    revoke_share_token(revoked.plaintext, shares)
    expired = mint_share_token(tenant_id="t1", expires_at=datetime.now(UTC) - timedelta(days=1), store=shares)

    assert verify_share_token(f"{SHARE_TOKEN_PREFIX}unknown", shares) is None
    assert verify_share_token(revoked.plaintext, shares) is None
    assert verify_share_token(expired.plaintext, shares) is None


def test_expires_in_is_the_duration_form_a_route_has(shares: FakeShareTokenStore) -> None:
    """A route usually holds a number of days rather than an instant."""
    minted = mint_share_token(tenant_id="t1", expires_in=timedelta(days=7), store=shares)

    assert minted.record.expires_at > datetime.now(UTC).timestamp()
    assert verify_share_token(minted.plaintext, shares) is not None


def test_a_token_with_no_expiry_never_expires(shares: FakeShareTokenStore) -> None:
    """A zero `expires_at` is the link that stays open until it is revoked."""
    minted = mint_share_token(tenant_id="t1", store=shares)

    assert minted.record.expires_at == 0
    assert not minted.record.is_expired(now=datetime(2099, 1, 1, tzinfo=UTC))


def test_revoking_by_hash_and_by_plaintext_both_work(shares: FakeShareTokenStore) -> None:
    """A settings page has the hash and a link holder has the plaintext."""
    by_hash = mint_share_token(tenant_id="t1", store=shares)
    by_text = mint_share_token(tenant_id="t1", store=shares)

    assert revoke_share_token(by_hash.record.token_hash, shares) is not None
    assert revoke_share_token(by_text.plaintext, shares) is not None
    assert revoke_share_token(by_text.plaintext, shares) is None


def test_a_tenant_lists_and_revokes_its_shares(shares: FakeShareTokenStore) -> None:
    """The settings page read and the offboarding verb, both through the tenant index."""
    mint_share_token(tenant_id="t1", store=shares, created_at="2026-01-01T00:00:00Z")
    mint_share_token(tenant_id="t1", store=shares, created_at="2026-01-02T00:00:00Z")
    mint_share_token(tenant_id="t2", store=shares)

    assert len(shares.list_for_tenant("t1")) == 2
    assert shares.revoke_all_for_tenant("t1") == 2
    assert len(shares.list_for_tenant("t2")) == 1
    assert shares.delete_all_for_tenant("t1") == 2
    assert shares.list_for_tenant("t1") == []


def test_touching_records_use_and_tolerates_an_absent_row(shares: FakeShareTokenStore) -> None:
    """Best effort: a stamp on a row that is gone is not an error."""
    minted = mint_share_token(tenant_id="t1", store=shares)

    verify_share_token(minted.plaintext, shares)
    stored = shares.get(minted.record.token_hash)

    assert stored is not None and stored.last_used_at
    shares.touch("no-such-hash")


def test_claims_for_a_share_token_carry_the_capability_and_no_scope() -> None:
    """The gateway's own shape, with the capability in place of a scope set."""
    record = ShareTokenRecord(token_hash="h", tenant_id="t1", capability={"issue": "i1"})

    claims = claims_for_share_token(record)

    assert claims["sub"] == SHARE_TOKEN_SUBJECT
    assert claims[TENANT_CLAIM] == "t1"
    assert claims[ACTOR_CLAIM] == ACTOR_SHARE_TOKEN
    assert claims[CAPABILITY_CLAIM] == {"issue": "i1"}
    assert "scope" not in claims
    assert is_share_token_actor(claims)
    assert share_token_capability(claims) == {"issue": "i1"}


def test_a_key_and_a_jwt_carry_no_capability(keys: FakeApiKeyStore) -> None:
    """A route reads the capability unconditionally and gets nothing where there is none."""
    minted = mint(user_id="u1", tenant_id="t1", scopes=["issues:read"], store=keys)

    from webbpulse.identity.api_keys import claims_for_key

    assert share_token_capability(claims_for_key(minted.record)) == {}
    assert share_token_capability(AuthorizerClaims({"sub": "u1"})) == {}
    assert not is_share_token_actor(AuthorizerClaims({"sub": "u1"}))


def test_the_share_token_table_declares_its_index_and_ttl() -> None:
    """The second GSI the platform identity module must provision, and the TTL attribute."""
    index = {gsi.name: gsi for gsi in SHARE_TOKEN_TABLE.global_secondary_indexes}[SHARE_TOKEN_TENANT_INDEX]

    assert SHARE_TOKEN_TABLE.hash_key == "token_hash"
    assert (index.hash_key, index.range_key) == ("tenant_id", "created_at")
    assert SHARE_TOKEN_TABLE.ttl_attribute == "expires_at"


def test_the_share_token_table_is_in_tables() -> None:
    """It is provisioned with the rest of identity rather than by a product's own terraform."""
    from webbpulse.identity.storage import TABLES

    assert SHARE_TOKEN_TABLE in TABLES


def _three_credential_app(**kwargs: Any) -> TestClient:
    """A one-route app resolving all three credential kinds, returning a client for it."""
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    resolver = claims_or_credential(**kwargs)

    @app.get("/shared/{token}")
    def read_shared(claims: AuthorizerClaims = Depends(resolver)) -> dict[str, Any]:
        """Echo what the resolved credential turned out to be."""
        return {
            "sub": claims["sub"],
            "actor": claims.get(ACTOR_CLAIM, "user"),
            "capability": share_token_capability(claims),
        }

    return TestClient(app, raise_server_exceptions=False)


def test_a_share_token_in_the_path_resolves(shares: FakeShareTokenStore) -> None:
    """A share link is a URL a browser opens, so the token arrives in the path."""
    minted = mint_share_token(tenant_id="t1", capability={"issue": "i1"}, store=shares)

    response = _three_credential_app(share_store=shares).get(f"/shared/{minted.plaintext}")

    assert response.status_code == 200
    assert response.json() == {
        "sub": SHARE_TOKEN_SUBJECT,
        "actor": ACTOR_SHARE_TOKEN,
        "capability": {"issue": "i1"},
    }


def test_a_share_token_in_the_bearer_header_resolves(shares: FakeShareTokenStore) -> None:
    """A machine caller presents it as a bearer value instead."""
    minted = mint_share_token(tenant_id="t1", capability={"view": "v1"}, store=shares)

    response = _three_credential_app(share_store=shares).get(
        "/shared/placeholder", headers={"Authorization": f"Bearer {minted.plaintext}"}
    )

    assert response.status_code == 200
    assert response.json()["capability"] == {"view": "v1"}


def test_an_api_key_still_resolves_alongside_a_share_store(keys: FakeApiKeyStore, shares: FakeShareTokenStore) -> None:
    """The stronger credential wins, so adding the share path never widens a route."""
    minted = mint(user_id="u1", tenant_id="t1", scopes=["issues:read"], store=keys)

    response = _three_credential_app(share_store=shares, store=keys).get(
        "/shared/placeholder", headers={"Authorization": f"Bearer {minted.plaintext}"}
    )

    assert response.status_code == 200
    assert response.json()["sub"] == "u1"
    assert response.json()["capability"] == {}


@pytest.mark.parametrize("token", ["not-a-token", f"{SHARE_TOKEN_PREFIX}unknown"])
def test_no_usable_credential_is_the_same_401(shares: FakeShareTokenStore, token: str) -> None:
    """Every refusal is one body, so nothing says whether a guessed token ever existed."""
    response = _three_credential_app(share_store=shares).get(f"/shared/{token}")

    assert response.status_code == 401
    assert response.json()["detail"]["error_code"] == UNAUTHENTICATED_ERROR_CODE


def test_a_revoked_share_is_refused_at_the_route(shares: FakeShareTokenStore) -> None:
    """Revocation is enforced by the dependency, not only by `verify_share_token`."""
    minted = mint_share_token(tenant_id="t1", store=shares)
    revoke_share_token(minted.plaintext, shares)

    response = _three_credential_app(share_store=shares).get(f"/shared/{minted.plaintext}")

    assert response.status_code == 401


def test_without_a_share_store_the_share_path_is_closed(shares: FakeShareTokenStore) -> None:
    """A dependency built with no share store lets no token through."""
    minted = mint_share_token(tenant_id="t1", store=shares)

    response = _three_credential_app().get(f"/shared/{minted.plaintext}")

    assert response.status_code == 401


def test_a_share_token_carries_no_scopes_so_require_scopes_refuses_it(shares: FakeShareTokenStore) -> None:
    """A share's authority is its capability, never a scope, so a scoped route is closed to it."""
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    minted = mint_share_token(tenant_id="t1", capability={"issue": "i1"}, store=shares)
    app = FastAPI()
    guard = require_scopes("issues:read", claims_dependency=claims_or_credential(share_store=shares))

    @app.get("/shared/{token}")
    def read_shared(claims: AuthorizerClaims = Depends(guard)) -> dict[str, str]:
        """Never reached by a share token."""
        return {"sub": claims["sub"]}

    response = TestClient(app, raise_server_exceptions=False).get(f"/shared/{minted.plaintext}")

    assert response.status_code == 403


def _tenant_app(keys: FakeApiKeyStore, *, inline: bool) -> TestClient:
    """A tenant-scoped route, guarded either inside `claims_or_api_key` or by `require_tenant`."""
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    if inline:
        resolver = claims_or_api_key(
            store=keys,
            tenant=lambda request: str(request.path_params.get("tenant_id", "")),
        )
    else:
        resolver = require_tenant("tenant_id", claims_dependency=claims_or_api_key(store=keys))

    @app.get("/tenants/{tenant_id}/issues")
    def read_issues(claims: AuthorizerClaims = Depends(resolver)) -> dict[str, str]:
        """Echo the tenant authorization was decided against."""
        return {"tenant": claims_tenant(claims)}

    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.parametrize("inline", [True, False])
def test_a_key_reaches_its_own_tenant_and_no_other(keys: FakeApiKeyStore, inline: bool) -> None:
    """Both spellings of the binding check refuse a key walked across tenant ids."""
    minted = mint(user_id="u1", tenant_id="t1", scopes=[], store=keys)
    client = _tenant_app(keys, inline=inline)
    headers = {"Authorization": f"Bearer {minted.plaintext}"}

    assert client.get("/tenants/t1/issues", headers=headers).status_code == 200
    assert client.get("/tenants/t1/issues", headers=headers).json() == {"tenant": "t1"}

    refused = client.get("/tenants/t2/issues", headers=headers)
    assert refused.status_code == 401
    assert refused.json()["detail"]["error_code"] == UNAUTHENTICATED_ERROR_CODE


def test_a_tenant_resolver_that_raises_fails_closed(keys: FakeApiKeyStore) -> None:
    """Failing to learn which tenant a request is in is exactly when a bound key must not pass."""
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    def explode(request: Any) -> str:
        """Fail the way a malformed path would."""
        raise RuntimeError("no tenant here")

    minted = mint(user_id="u1", tenant_id="t1", scopes=[], store=keys)
    app = FastAPI()
    resolver = claims_or_api_key(store=keys, tenant=explode)

    @app.get("/issues")
    def read_issues(claims: AuthorizerClaims = Depends(resolver)) -> dict[str, str]:
        """Never reached."""
        return {"tenant": claims_tenant(claims)}

    response = TestClient(app, raise_server_exceptions=False).get(
        "/issues", headers={"Authorization": f"Bearer {minted.plaintext}"}
    )

    assert response.status_code == 401


def test_the_dynamo_stores_round_trip(dynamodb_resource: Any) -> None:
    """Both tables answer their tenant index against a real DynamoDB, moto backed."""
    from webbpulse.dynamodb import Repository
    from webbpulse.identity.api_keys import DynamoApiKeyStore
    from webbpulse.identity.share_tokens import DynamoShareTokenStore

    client = dynamodb_resource.meta.client
    for spec in (API_KEY_TABLE, SHARE_TOKEN_TABLE):
        client.create_table(**spec.create_table_request("wp-local"))

    key_store = DynamoApiKeyStore(Repository(API_KEY_TABLE.logical_name, prefix="wp-local"))
    share_store = DynamoShareTokenStore(Repository(SHARE_TOKEN_TABLE.logical_name, prefix="wp-local"))

    mint(user_id="u1", tenant_id="t1", scopes=["issues:read"], store=key_store, created_at="2026-01-01T00:00:00Z")
    mint(user_id="u2", tenant_id="t1", scopes=[], store=key_store, created_at="2026-01-02T00:00:00Z")
    mint(user_id="u3", tenant_id="t2", scopes=[], store=key_store, created_at="2026-01-03T00:00:00Z")

    assert [record.user_id for record in key_store.list_for_tenant("t1")] == ["u1", "u2"]
    assert key_store.revoke_all_for_tenant("t1") == 2
    assert [record.user_id for record in key_store.list_for_tenant("t2")] == ["u3"]

    minted = mint_share_token(tenant_id="t1", capability={"issue": "i1"}, name="Design review", store=share_store)
    resolved = verify_share_token(minted.plaintext, share_store)

    assert resolved is not None
    assert resolved.capability == {"issue": "i1"}
    assert [record.name for record in share_store.list_for_tenant("t1")] == ["Design review"]
    assert share_store.revoke_all_for_tenant("t1") == 1
    assert verify_share_token(minted.plaintext, share_store) is None
    assert share_store.delete_all_for_tenant("t1") == 1
    assert share_store.list_for_tenant("t1") == []
