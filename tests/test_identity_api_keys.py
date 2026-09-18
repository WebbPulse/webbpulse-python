"""`webbpulse.identity.api_keys` and `webbpulse.identity.scopes`.

The two properties worth stating once: a plaintext key exists only in the `mint` return
value, and a key never authorizes more than its minter currently holds.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

from webbpulse.identity.api_keys import (
    ACTOR_API_KEY,
    ACTOR_CLAIM,
    API_KEY_PREFIX,
    PREFIX_DISPLAY_LENGTH,
    TENANT_CLAIM,
    ApiKeyRecord,
    FakeApiKeyStore,
    claims_for_key,
    effective_scopes,
    hash_key,
    is_api_key,
    mint,
    new_key,
    revoke,
    verify,
)
from webbpulse.identity.claims import AuthorizerClaims
from webbpulse.identity.scopes import (
    FORBIDDEN_ERROR_CODE,
    UNAUTHENTICATED_ERROR_CODE,
    claims_or_api_key,
    claims_scopes,
    has_scopes,
    is_api_key_actor,
    missing_scopes,
    require_scopes,
)

if TYPE_CHECKING:  # pragma: no cover
    from fastapi.testclient import TestClient


@pytest.fixture
def store() -> FakeApiKeyStore:
    """An empty in-memory key store."""
    return FakeApiKeyStore()


def test_a_minted_key_carries_the_prefix_and_fresh_entropy() -> None:
    """Every key starts with the scanner-visible prefix and no two are alike."""
    keys = {new_key() for _ in range(32)}
    assert len(keys) == 32
    assert all(key.startswith(API_KEY_PREFIX) for key in keys)
    assert all(is_api_key(key) for key in keys)


def test_the_store_never_holds_the_plaintext(store: FakeApiKeyStore) -> None:
    """The record carries a hash and a display prefix, and nothing that authenticates."""
    minted = mint(user_id="u1", tenant_id="t1", scopes=["issues:write"], store=store)

    record = store.get(minted.record.key_hash)
    assert record is not None
    assert record.key_hash == hash_key(minted.plaintext)
    assert minted.plaintext not in str(dataclasses.asdict(record))
    assert record.prefix == minted.plaintext[:PREFIX_DISPLAY_LENGTH]
    assert len(record.prefix) < len(minted.plaintext)


def test_scopes_are_normalised_at_mint(store: FakeApiKeyStore) -> None:
    """Duplicates, blanks and ordering collapse, so a record compares the same every time."""
    minted = mint(
        user_id="u1",
        tenant_id="t1",
        scopes=["issues:write", " issues:read ", "issues:write", ""],
        store=store,
    )

    assert minted.record.scopes == ("issues:read", "issues:write")


def test_verify_resolves_a_good_key(store: FakeApiKeyStore) -> None:
    """A presented plaintext resolves to its own record."""
    minted = mint(user_id="u1", tenant_id="t1", scopes=["issues:read"], store=store)

    resolved = verify(minted.plaintext, store)

    assert resolved is not None
    assert resolved.user_id == "u1"
    assert resolved.tenant_id == "t1"


@pytest.mark.parametrize(
    "presented",
    ["", "not-a-key", "Bearer wpk_x", f"{API_KEY_PREFIX}wrong-secret"],
)
def test_verify_refuses_anything_that_is_not_a_live_key(store: FakeApiKeyStore, presented: str) -> None:
    """A wrong shape and an unknown hash are the same `None`, telling a caller nothing."""
    mint(user_id="u1", tenant_id="t1", scopes=["issues:read"], store=store)

    assert verify(presented, store) is None


def test_verify_refuses_a_revoked_key(store: FakeApiKeyStore) -> None:
    """Revocation takes effect on the next request, with no cache to wait for."""
    minted = mint(user_id="u1", tenant_id="t1", scopes=["issues:read"], store=store)
    assert verify(minted.plaintext, store) is not None

    assert revoke(minted.plaintext, store) is not None
    assert verify(minted.plaintext, store) is None


def test_revoking_twice_reports_nothing_left_to_do(store: FakeApiKeyStore) -> None:
    """The second revoke answers `None`, so a caller can tell it changed nothing."""
    minted = mint(user_id="u1", tenant_id="t1", scopes=[], store=store)

    assert revoke(minted.record.key_hash, store) is not None
    assert revoke(minted.record.key_hash, store) is None


def test_verify_refuses_an_expired_key(store: FakeApiKeyStore) -> None:
    """Expiry is enforced on the read path, because the table has no TTL."""
    past = datetime.now(UTC) - timedelta(days=1)
    minted = mint(user_id="u1", tenant_id="t1", scopes=[], expires_at=past, store=store)

    assert verify(minted.plaintext, store) is None


def test_a_key_with_no_expiry_keeps_working(store: FakeApiKeyStore) -> None:
    """A zero `expires_at` is "never", not "already expired"."""
    minted = mint(user_id="u1", tenant_id="t1", scopes=[], store=store)

    assert minted.record.expires_at == 0
    assert verify(minted.plaintext, store) is not None


def test_verify_stamps_last_used(store: FakeApiKeyStore) -> None:
    """A successful verification records the use, for an operator auditing stale keys."""
    minted = mint(user_id="u1", tenant_id="t1", scopes=[], store=store)
    assert minted.record.last_used_at == ""

    verify(minted.plaintext, store)

    stamped = store.get(minted.record.key_hash)
    assert stamped is not None
    assert stamped.last_used_at


def test_listing_and_purging_a_users_keys(store: FakeApiKeyStore) -> None:
    """The user index backs a settings page and the account deletion purge."""
    mint(user_id="u1", tenant_id="t1", scopes=[], store=store, created_at="2026-01-01T00:00:00Z")
    mint(user_id="u1", tenant_id="t1", scopes=[], store=store, created_at="2026-01-02T00:00:00Z")
    mint(user_id="u2", tenant_id="t1", scopes=[], store=store)

    assert len(store.list_for_user("u1")) == 2
    assert store.delete_all_for_user("u1") == 2
    assert store.list_for_user("u1") == []
    assert len(store.list_for_user("u2")) == 1


@pytest.mark.parametrize(
    ("key_scopes", "live_scopes", "expected"),
    [
        (["a", "b"], ["a", "b"], ("a", "b")),
        (["a", "b"], ["a"], ("a",)),
        (["a"], ["a", "b"], ("a",)),
        (["a"], [], ()),
        ([], ["a"], ()),
    ],
)
def test_effective_scopes_is_an_intersection(
    key_scopes: list[str], live_scopes: list[str], expected: tuple[str, ...]
) -> None:
    """A key is a delegation: neither side alone decides, and the narrower one wins."""
    assert effective_scopes(key_scopes, live_scopes) == expected


def test_a_key_does_not_outlive_the_role_it_was_minted_under() -> None:
    """The whole point of the intersection, stated as the case it defends against."""
    minted = mint(user_id="u1", tenant_id="t1", scopes=["admin:write"])

    assert effective_scopes(minted.record.scopes, ["issues:read"]) == ()


def test_claims_for_key_is_the_gateway_shape() -> None:
    """The adapter yields the claims a JWT would, so there is one authorization path."""
    minted = mint(user_id="u1", tenant_id="t1", scopes=["issues:read", "issues:write"])

    claims = claims_for_key(minted.record)

    assert isinstance(claims, AuthorizerClaims)
    assert claims["sub"] == "u1"
    assert claims[TENANT_CLAIM] == "t1"
    assert claims[ACTOR_CLAIM] == ACTOR_API_KEY
    assert claims["scope"] == "issues:read issues:write"
    assert claims["scopes"] == ["issues:read", "issues:write"]
    assert is_api_key_actor(claims)


def test_claims_for_key_takes_the_intersected_scopes() -> None:
    """The claims carry what the key may spend now, not what it was minted with."""
    minted = mint(user_id="u1", tenant_id="t1", scopes=["issues:read", "admin:write"])

    claims = claims_for_key(minted.record, scopes=effective_scopes(minted.record.scopes, ["issues:read"]))

    assert claims["scopes"] == ["issues:read"]


def test_a_jwt_caller_is_not_an_api_key_actor() -> None:
    """Claims with no actor marker read as a person, so a key-only refusal is precise."""
    assert not is_api_key_actor(AuthorizerClaims({"sub": "u1", "scope": "issues:read"}))


@pytest.mark.parametrize(
    ("claims", "expected"),
    [
        ({"scope": "a b"}, ("a", "b")),
        ({"scopes": ["a", "b"]}, ("a", "b")),
        ({}, ()),
        ({"scope": ""}, ()),
    ],
)
def test_claims_scopes_reads_either_spelling(claims: dict[str, Any], expected: tuple[str, ...]) -> None:
    """Coerced and raw claims both answer, so the guard works either side of coercion."""
    assert claims_scopes(claims) == expected


def test_missing_scopes_requires_every_one() -> None:
    """Every named scope must be held, never any one of them."""
    claims = AuthorizerClaims({"sub": "u1", "scope": "issues:read"})

    assert has_scopes(claims, ["issues:read"])
    assert not has_scopes(claims, ["issues:read", "issues:write"])
    assert missing_scopes(claims, ["issues:read", "issues:write"]) == ("issues:write",)


def _app(**kwargs: Any) -> TestClient:
    """A one-route app guarded by `require_scopes`, returning a client for it."""
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    guard = require_scopes("issues:write", claims_dependency=claims_or_api_key(**kwargs))

    @app.get("/issues")
    def read_issues(claims: AuthorizerClaims = Depends(guard)) -> dict[str, Any]:
        """Echo the subject the guard resolved."""
        return {"sub": claims["sub"], "scopes": claims_scopes(claims)}

    return TestClient(app, raise_server_exceptions=False)


def test_a_key_with_the_scope_reaches_the_route() -> None:
    """The end to end path: a bearer key becomes claims and satisfies the guard."""
    store = FakeApiKeyStore()
    minted = mint(user_id="u1", tenant_id="t1", scopes=["issues:write"], store=store)

    response = _app(store=store).get("/issues", headers={"Authorization": f"Bearer {minted.plaintext}"})

    assert response.status_code == 200
    assert response.json() == {"sub": "u1", "scopes": ["issues:write"]}


def test_a_key_without_the_scope_is_refused_with_the_envelope() -> None:
    """A 403 carrying the package's message and the narrower `INSUFFICIENT_SCOPE` code."""
    store = FakeApiKeyStore()
    minted = mint(user_id="u1", tenant_id="t1", scopes=["issues:read"], store=store)

    response = _app(store=store).get("/issues", headers={"Authorization": f"Bearer {minted.plaintext}"})

    assert response.status_code == 403
    assert response.json()["detail"]["error_code"] == FORBIDDEN_ERROR_CODE
    assert "issues:write" not in response.text


def test_live_membership_narrows_what_a_key_may_spend() -> None:
    """A key minted broad is refused once its minter's membership no longer covers it."""
    store = FakeApiKeyStore()
    minted = mint(user_id="u1", tenant_id="t1", scopes=["issues:write"], store=store)

    client = _app(store=store, live_scopes=lambda record: ["issues:read"])
    response = client.get("/issues", headers={"Authorization": f"Bearer {minted.plaintext}"})

    assert response.status_code == 403


def test_an_async_live_scopes_callable_is_awaited() -> None:
    """The membership loader is usually a database read, so it may be `async def`."""
    store = FakeApiKeyStore()
    minted = mint(user_id="u1", tenant_id="t1", scopes=["issues:write"], store=store)

    async def live(record: ApiKeyRecord) -> list[str]:
        """Return the minter's live membership."""
        return ["issues:write"]

    response = _app(store=store, live_scopes=live).get(
        "/issues", headers={"Authorization": f"Bearer {minted.plaintext}"}
    )

    assert response.status_code == 200


def test_a_failing_live_scopes_callable_fails_closed() -> None:
    """A membership lookup that raises refuses the request rather than granting nothing."""
    store = FakeApiKeyStore()
    minted = mint(user_id="u1", tenant_id="t1", scopes=["issues:write"], store=store)

    def live(record: ApiKeyRecord) -> list[str]:
        """Fail the way a database outage would."""
        raise RuntimeError("membership unavailable")

    response = _app(store=store, live_scopes=live).get(
        "/issues", headers={"Authorization": f"Bearer {minted.plaintext}"}
    )

    assert response.status_code == 401


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer not-a-key"},
        {"Authorization": "Basic dXNlcjpwYXNz"},
        {"Authorization": f"Bearer {API_KEY_PREFIX}unknown"},
    ],
)
def test_no_usable_credential_is_a_401_and_never_anonymous(headers: dict[str, str]) -> None:
    """Every failed path is the same 401 body, so nothing distinguishes them to a caller."""
    store = FakeApiKeyStore()

    response = _app(store=store).get("/issues", headers=headers)

    assert response.status_code == 401
    assert response.json()["detail"]["error_code"] == UNAUTHENTICATED_ERROR_CODE
    assert response.headers["www-authenticate"] == "Bearer"


def test_a_revoked_key_is_refused_at_the_route() -> None:
    """Revocation is enforced by the dependency, not only by `verify`."""
    store = FakeApiKeyStore()
    minted = mint(user_id="u1", tenant_id="t1", scopes=["issues:write"], store=store)
    revoke(minted.plaintext, store)

    response = _app(store=store).get("/issues", headers={"Authorization": f"Bearer {minted.plaintext}"})

    assert response.status_code == 401


def test_without_a_store_the_key_path_is_closed() -> None:
    """A dependency built with no store is authorizer-only and lets no key through."""
    store = FakeApiKeyStore()
    minted = mint(user_id="u1", tenant_id="t1", scopes=["issues:write"], store=store)

    response = _app().get("/issues", headers={"Authorization": f"Bearer {minted.plaintext}"})

    assert response.status_code == 401


def test_mint_without_a_store_writes_nothing(store: FakeApiKeyStore) -> None:
    """A caller writing through its own transaction gets the record back unstored."""
    minted = mint(user_id="u1", tenant_id="t1", scopes=["issues:read"])

    assert store.get(minted.record.key_hash) is None
    assert minted.record.user_id == "u1"


def test_an_expired_record_is_still_readable(store: FakeApiKeyStore) -> None:
    """No TTL: an expired key stays visible so an owner can see and delete it."""
    past = datetime.now(UTC) - timedelta(days=1)
    minted = mint(user_id="u1", tenant_id="t1", scopes=[], expires_at=past, store=store)

    record = store.get(minted.record.key_hash)
    assert record is not None
    assert record.is_expired()
    assert not record.is_usable()


def test_a_record_reports_its_own_state() -> None:
    """`is_revoked`, `is_expired` and `is_usable` are the three questions a caller asks."""
    record = ApiKeyRecord(key_hash="h", user_id="u1", tenant_id="t1", prefix="wpk_abc")

    assert record.is_usable()
    assert not record.is_revoked
    assert dataclasses.replace(record, revoked_at="2026-01-01T00:00:00Z").is_revoked
    assert not dataclasses.replace(record, revoked_at="2026-01-01T00:00:00Z").is_usable()
