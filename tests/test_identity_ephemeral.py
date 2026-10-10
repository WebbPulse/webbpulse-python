"""Tests for the ephemeral e2e user flow and its admin-only routes.

The capability under test is deliberately dangerous: it creates a verified account with a
chosen password and no email round trip. What is worth pinning is therefore mostly what it
refuses. The flag is off by default, production refuses to mount the routes whatever the
flag says, and a caller without the admin role is turned away.

The delete path deletes only the product's users row on purpose. The identity rows are the
stream purge's to remove, so doing them inline here would leave the production deletion path
untested by every run that uses this.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any

import pytest

from webbpulse.identity import (
    AuthenticationRefused,
    BaseIdentityHooks,
    IdentitySettings,
    IdentityStores,
    InMemoryCredentialStore,
    InMemoryIdentityTokenStore,
    InMemoryOAuthLinkStore,
    InMemoryPasskeyStore,
    InMemoryRecoveryCodeStore,
    InMemoryRefreshTokenStore,
    InMemoryTotpFactorStore,
    InMemoryWebAuthnChallengeStore,
    TokenService,
)
from webbpulse.identity.ephemeral_routes import (
    EPHEMERAL_USER_ITEM_PATH,
    EPHEMERAL_USERS_PATH,
    EPHEMERAL_USERS_SWEEP_PATH,
)
from webbpulse.identity.ephemeral_sweep import (
    EPHEMERAL_SWEEP_DEFAULT_AGE,
    EPHEMERAL_SWEEP_LIMIT,
    EPHEMERAL_SWEEP_MINIMUM_AGE,
    created_at_of,
    is_ephemeral_email,
    users_scan_source,
)
from webbpulse.identity.flows import EPHEMERAL_VIA, IdentityFlows, LoginRejected

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Mapping

pytest.importorskip("cryptography")
pytest.importorskip("fastapi")

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

KEY_A = "arn:aws:kms:us-west-2:111122223333:key/aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa"
ISSUER = "https://api.staging.example.com/api/auth"
AUDIENCE = "webbpulse-staging"
EMAIL = "e2e-run-123@e2e.invalid"
PASSWORD = "Aa1-nMPqTvZx3RkLwYsBdEfGhJ2u4C6t"


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
    """The minimum product policy the ephemeral flow needs, recording what it was asked."""

    def __init__(self) -> None:
        """Start with no users and nothing recorded."""
        self.users: dict[str, dict[str, Any]] = {}
        self.created: list[tuple[str, str]] = []
        self.deleted: list[str] = []
        self._next = 1

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
        user_id = f"user-{self._next:04d}"
        self._next += 1
        user = {"id": user_id, "email": email, **dict(attributes)}
        self.users[user_id] = user
        return user

    def on_user_created(self, user: Mapping[str, Any], via: str) -> None:
        """Record the id and the route the account came to exist through."""
        self.created.append((str(user.get("id", "")), via))

    def delete_user(self, user_id: str) -> bool:
        """Delete the users row, reporting whether one was there."""
        self.deleted.append(user_id)
        return self.users.pop(user_id, None) is not None


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


def make_stores() -> IdentityStores:
    """Every identity store, in memory."""
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


@pytest.fixture(scope="module")
def module_key() -> rsa.RSAPrivateKey:
    """One 2048-bit key for the module, since generation is slow."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def hooks() -> FakeHooks:
    """A fresh product policy recording creations and deletions."""
    return FakeHooks()


def make_flows(hooks: FakeHooks, module_key: rsa.RSAPrivateKey, **overrides: Any) -> IdentityFlows:
    """`IdentityFlows` over in-memory stores with the given settings overrides."""
    settings = make_settings(**overrides)
    stores = make_stores()
    return IdentityFlows(settings, hooks, stores, TokenService(settings, FakeKms({KEY_A: module_key})))


class TestEphemeralFlow:
    """The create and delete flows, independent of how they are routed."""

    def test_it_creates_a_verified_user_the_suite_can_sign_in_as(
        self, hooks: FakeHooks, module_key: rsa.RSAPrivateKey
    ) -> None:
        """The account is created verified, so no email round trip stands in the way."""
        flows = make_flows(hooks, module_key, ephemeral_users_enabled=True)
        created = flows.create_ephemeral_user(email=EMAIL, password=PASSWORD)
        assert created["email"] == EMAIL
        user = hooks.users[created["user_id"]]
        assert user["email_verified"] is True

    def test_it_tells_the_product_the_account_came_from_an_e2e_run(
        self, hooks: FakeHooks, module_key: rsa.RSAPrivateKey
    ) -> None:
        """`on_user_created` carries a `via` the product can branch its side effects on."""
        flows = make_flows(hooks, module_key, ephemeral_users_enabled=True)
        created = flows.create_ephemeral_user(email=EMAIL, password=PASSWORD)
        assert hooks.created == [(created["user_id"], EPHEMERAL_VIA)]

    def test_the_created_user_has_a_password_credential(self, hooks: FakeHooks, module_key: rsa.RSAPrivateKey) -> None:
        """A user with no credential row could never sign in, which is the whole point."""
        flows = make_flows(hooks, module_key, ephemeral_users_enabled=True)
        created = flows.create_ephemeral_user(email=EMAIL, password=PASSWORD)
        record = flows._stores.require_credentials().get(created["user_id"], "password")
        assert record is not None
        assert record.secret != PASSWORD

    def test_it_refuses_when_the_flag_is_off(self, hooks: FakeHooks, module_key: rsa.RSAPrivateKey) -> None:
        """The default build has no ephemeral users at all."""
        flows = make_flows(hooks, module_key)
        with pytest.raises(LoginRejected) as caught:
            flows.create_ephemeral_user(email=EMAIL, password=PASSWORD)
        assert caught.value.error_code == "EPHEMERAL_USERS_DISABLED"
        assert hooks.users == {}

    def test_it_refuses_a_second_account_for_one_address(self, hooks: FakeHooks, module_key: rsa.RSAPrivateKey) -> None:
        """A duplicate is a conflict rather than a silent second account."""
        flows = make_flows(hooks, module_key, ephemeral_users_enabled=True)
        flows.create_ephemeral_user(email=EMAIL, password=PASSWORD)
        with pytest.raises(LoginRejected) as caught:
            flows.create_ephemeral_user(email=EMAIL, password=PASSWORD)
        assert caught.value.status_code == 409

    def test_it_refuses_an_empty_address(self, hooks: FakeHooks, module_key: rsa.RSAPrivateKey) -> None:
        """An account with no address could never be found again to delete."""
        flows = make_flows(hooks, module_key, ephemeral_users_enabled=True)
        with pytest.raises(LoginRejected) as caught:
            flows.create_ephemeral_user(email="", password=PASSWORD)
        assert caught.value.error_code == "EMAIL_REQUIRED"

    @pytest.mark.parametrize(
        "address",
        ["owner@example.com", "e2e-run@example.com", "someone@e2e.invalid", "e2e-run@e2e.invalid.example.com"],
    )
    def test_it_refuses_an_address_outside_the_e2e_convention(
        self, address: str, hooks: FakeHooks, module_key: rsa.RSAPrivateKey
    ) -> None:
        """Only `e2e-<run>@e2e.invalid` can be created, so the route never mints a real-looking account."""
        flows = make_flows(hooks, module_key, ephemeral_users_enabled=True)
        with pytest.raises(LoginRejected) as caught:
            flows.create_ephemeral_user(email=address, password=PASSWORD)
        assert caught.value.error_code == "EPHEMERAL_EMAIL_REQUIRED"
        assert caught.value.status_code == 400
        assert hooks.users == {}

    def test_delete_refuses_a_real_user_and_leaves_it_in_place(
        self, hooks: FakeHooks, module_key: rsa.RSAPrivateKey
    ) -> None:
        """An admin token cannot turn the e2e delete route against a real account."""
        real = hooks.create_user(email="owner@example.com", attributes={})
        flows = make_flows(hooks, module_key, ephemeral_users_enabled=True)
        with pytest.raises(LoginRejected) as caught:
            flows.delete_ephemeral_user(str(real["id"]))
        assert caught.value.error_code == "NOT_EPHEMERAL_USER"
        assert caught.value.status_code == 403
        assert hooks.deleted == []
        assert hooks.load_user_by_id(str(real["id"])) is not None

    def test_delete_removes_the_users_row_and_nothing_else(
        self, hooks: FakeHooks, module_key: rsa.RSAPrivateKey
    ) -> None:
        """Only the users row goes, leaving the stream purge to remove the identity rows.

        Deleting the identity rows inline would mean no run ever exercised the production
        deletion path, which is the path that matters.
        """
        flows = make_flows(hooks, module_key, ephemeral_users_enabled=True)
        created = flows.create_ephemeral_user(email=EMAIL, password=PASSWORD)
        user_id = created["user_id"]
        assert flows.delete_ephemeral_user(user_id) is True
        assert hooks.deleted == [user_id]
        assert flows._stores.require_credentials().get(user_id, "password") is not None

    def test_deleting_a_user_that_is_already_gone_is_not_an_error(
        self, hooks: FakeHooks, module_key: rsa.RSAPrivateKey
    ) -> None:
        """A retried teardown reports False rather than raising."""
        flows = make_flows(hooks, module_key, ephemeral_users_enabled=True)
        assert flows.delete_ephemeral_user("user-does-not-exist") is False

    def test_delete_refuses_when_the_flag_is_off(self, hooks: FakeHooks, module_key: rsa.RSAPrivateKey) -> None:
        """The delete route is gated by the same flag as the create route."""
        flows = make_flows(hooks, module_key)
        with pytest.raises(LoginRejected) as caught:
            flows.delete_ephemeral_user("user-0001")
        assert caught.value.error_code == "EPHEMERAL_USERS_DISABLED"

    def test_no_password_reaches_a_refusal_message(self, hooks: FakeHooks, module_key: rsa.RSAPrivateKey) -> None:
        """A refusal a caller or a log might see never carries the generated password."""
        flows = make_flows(hooks, module_key, ephemeral_users_enabled=True)
        flows.create_ephemeral_user(email=EMAIL, password=PASSWORD)
        with pytest.raises(LoginRejected) as caught:
            flows.create_ephemeral_user(email=EMAIL, password=PASSWORD)
        assert PASSWORD not in str(caught.value)
        assert PASSWORD not in caught.value.message


class TestEphemeralRouteMounting:
    """Which deployments offer the routes at all."""

    @staticmethod
    def mounted_paths(module_key: rsa.RSAPrivateKey, **overrides: Any) -> set[str]:
        """Every path a router built with these settings declares."""
        from webbpulse.identity import build_identity_router

        settings = make_settings(**overrides)
        router = build_identity_router(
            settings,
            FakeHooks(),
            make_stores(),
            tokens=TokenService(settings, FakeKms({KEY_A: module_key})),
        )
        return {getattr(route, "path", "") for route in router.routes}

    def test_the_routes_are_absent_by_default(self, module_key: rsa.RSAPrivateKey) -> None:
        """A product that has not opted in has no ephemeral routes to reach."""
        paths = self.mounted_paths(module_key)
        assert not any(path.endswith(EPHEMERAL_USERS_PATH) for path in paths)

    def test_the_routes_are_present_when_enabled_outside_production(self, module_key: rsa.RSAPrivateKey) -> None:
        """Staging opts in and gets both routes."""
        paths = self.mounted_paths(module_key, ephemeral_users_enabled=True, environment="staging")
        assert any(path.endswith(EPHEMERAL_USERS_PATH) for path in paths)
        assert any(path.endswith(EPHEMERAL_USER_ITEM_PATH) for path in paths)

    @pytest.mark.parametrize("environment", ["production", "prod", "Production", "PROD"])
    def test_production_refuses_to_mount_them_even_when_the_flag_is_on(
        self, environment: str, module_key: rsa.RSAPrivateKey
    ) -> None:
        """A misconfigured production deployment has no route, not a route that answers 403.

        Absent is the stronger answer: it cannot be reached by a caller who somehow holds an
        admin token.
        """
        paths = self.mounted_paths(module_key, ephemeral_users_enabled=True, environment=environment)
        assert not any(path.endswith(EPHEMERAL_USERS_PATH) for path in paths)


class TestCallerIsAdmin:
    """The role check the routes gate on."""

    @staticmethod
    def request_with(claims: Any) -> Any:
        """A request stand-in carrying these verified claims the way the adapter delivers them.

        The Lambda Web Adapter injects the gateway request context as a JSON header, so that
        is where the resolver looks rather than in the ASGI scope.
        """
        import json

        from webbpulse.http import REQUEST_CONTEXT_HEADER

        headers: dict[str, str] = {}
        if claims is not None:
            headers[REQUEST_CONTEXT_HEADER] = json.dumps({"authorizer": {"jwt": {"claims": claims}}})

        class FakeRequest:
            """The smallest request shape `identity_claims` reads."""

            def __init__(self) -> None:
                """Hold the headers the claims resolver reads."""
                self.headers = headers

        return FakeRequest()

    def test_a_roles_list_carrying_admin_passes(self) -> None:
        """The ordinary minted admin token shape."""
        from webbpulse.identity.ephemeral_routes import caller_is_admin

        assert caller_is_admin(self.request_with({"sub": "s", "roles": ["admin", "user"]})) is True

    def test_a_roles_list_without_admin_is_refused(self) -> None:
        """A signed-in non-admin, which is CarModPicker's durable e2e user."""
        from webbpulse.identity.ephemeral_routes import caller_is_admin

        assert caller_is_admin(self.request_with({"sub": "s", "roles": ["user"]})) is False

    def test_no_claims_at_all_is_refused(self) -> None:
        """An anonymous caller."""
        from webbpulse.identity.ephemeral_routes import caller_is_admin

        assert caller_is_admin(self.request_with(None)) is False

    def test_a_bare_admin_string_passes(self) -> None:
        """Some gateways flatten a single-element array claim to a string."""
        from webbpulse.identity.ephemeral_routes import caller_is_admin

        assert caller_is_admin(self.request_with({"sub": "s", "roles": "admin"})) is True


class TestEphemeralRoutesOverHttp:
    """The mounted routes answering real requests, which the flow tests alone cannot show.

    The staging CarModPicker deployment answered 422 to every create call because FastAPI
    read the handler's `request` parameter as a body field; a request through the router is
    the only test that catches that class of fault.
    """

    @staticmethod
    def client(module_key: rsa.RSAPrivateKey, hooks: FakeHooks, **overrides: Any) -> Any:
        """A test client over an app mounting the router with these settings."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from webbpulse.identity import build_identity_router

        settings = make_settings(ephemeral_users_enabled=True, environment="staging", **overrides)
        router = build_identity_router(
            settings,
            hooks,
            make_stores(),
            tokens=TokenService(settings, FakeKms({KEY_A: module_key})),
        )
        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    @staticmethod
    def bearer_for(module_key: rsa.RSAPrivateKey, subject: str, roles: list[str]) -> dict[str, str]:
        """An `Authorization` header carrying a token this module's own key minted.

        No request context header goes with it, which is how a request arrives at a staging
        deployment whose identity surface sits behind one coarse route key with no JWT
        authorizer on it.
        """
        settings = make_settings(ephemeral_users_enabled=True, environment="staging")
        tokens = TokenService(settings, FakeKms({KEY_A: module_key}))
        minted = tokens.mint_access_token(subject, claims={"roles": roles})
        return {"Authorization": f"Bearer {minted}"}

    @staticmethod
    def headers_for(claims: Mapping[str, Any] | None) -> dict[str, str]:
        """The request context header the Lambda Web Adapter injects behind API Gateway."""
        import json

        from webbpulse.http import REQUEST_CONTEXT_HEADER

        if claims is None:
            return {}
        return {REQUEST_CONTEXT_HEADER: json.dumps({"authorizer": {"jwt": {"claims": claims}}})}

    ADMIN: Mapping[str, Any] = {"sub": "admin-0001", "roles": ["admin", "user"]}

    PAYLOAD: Mapping[str, Any] = {"email": EMAIL, "password": PASSWORD, "attributes": {}}

    def test_an_admin_creates_and_deletes_a_user(self, hooks: FakeHooks, module_key: rsa.RSAPrivateKey) -> None:
        """The plugin's exact payload answers 201, and the delete answers 200 with `deleted`."""
        client = self.client(module_key, hooks)
        created = client.post("/api/auth/e2e/users", json=dict(self.PAYLOAD), headers=self.headers_for(self.ADMIN))
        assert created.status_code == 201, created.text
        body = created.json()
        assert body["email"] == EMAIL
        assert body["user_id"]
        assert PASSWORD not in created.text
        deleted = client.delete(f"/api/auth/e2e/users/{body['user_id']}", headers=self.headers_for(self.ADMIN))
        assert deleted.status_code == 200, deleted.text
        assert deleted.json() == {"user_id": body["user_id"], "deleted": True}
        assert hooks.load_user_by_email(EMAIL) is None

    def test_a_non_e2e_address_answers_400(self, hooks: FakeHooks, module_key: rsa.RSAPrivateKey) -> None:
        """The route refuses an address outside the convention before anything is created."""
        client = self.client(module_key, hooks)
        payload = {**dict(self.PAYLOAD), "email": "owner@example.com"}
        response = client.post("/api/auth/e2e/users", json=payload, headers=self.headers_for(self.ADMIN))
        assert response.status_code == 400
        assert response.json()["error_code"] == "EPHEMERAL_EMAIL_REQUIRED"
        assert hooks.users == {}

    def test_deleting_a_real_user_answers_403(self, hooks: FakeHooks, module_key: rsa.RSAPrivateKey) -> None:
        """The delete route leaves an account outside the convention alone."""
        real = hooks.create_user(email="owner@example.com", attributes={})
        client = self.client(module_key, hooks)
        response = client.delete(f"/api/auth/e2e/users/{real['id']}", headers=self.headers_for(self.ADMIN))
        assert response.status_code == 403
        assert response.json()["error_code"] == "NOT_EPHEMERAL_USER"
        assert hooks.load_user_by_id(str(real["id"])) is not None

    def test_an_anonymous_caller_is_refused(self, hooks: FakeHooks, module_key: rsa.RSAPrivateKey) -> None:
        """No claims at all reads as not signed in."""
        client = self.client(module_key, hooks)
        response = client.post("/api/auth/e2e/users", json=dict(self.PAYLOAD), headers=self.headers_for(None))
        assert response.status_code == 401
        assert response.json()["error_code"] == "NOT_AUTHENTICATED"

    def test_a_non_admin_is_refused(self, hooks: FakeHooks, module_key: rsa.RSAPrivateKey) -> None:
        """A signed-in user without the role, which is CarModPicker's durable e2e user."""
        client = self.client(module_key, hooks)
        claims = {"sub": "user-0001", "roles": ["user"]}
        response = client.post("/api/auth/e2e/users", json=dict(self.PAYLOAD), headers=self.headers_for(claims))
        assert response.status_code == 403
        assert response.json()["error_code"] == "ADMIN_REQUIRED"

    def test_a_policy_failure_answers_422_with_its_code(self, hooks: FakeHooks, module_key: rsa.RSAPrivateKey) -> None:
        """The one 422 the route means, distinguishable from a validation fault by its code."""
        client = self.client(module_key, hooks)
        payload = {"email": EMAIL, "password": "short", "attributes": {}}
        response = client.post("/api/auth/e2e/users", json=payload, headers=self.headers_for(self.ADMIN))
        assert response.status_code == 422
        assert response.json()["error_code"] == "PASSWORD_TOO_SHORT"

    def test_an_admin_bearer_token_with_no_authorizer_creates_a_user(
        self, hooks: FakeHooks, module_key: rsa.RSAPrivateKey
    ) -> None:
        """CarModPicker staging's real shape: a valid admin token and no authorizer claims.

        The whole identity surface sits behind one coarse route key with the access gate on
        it and no JWT authorizer, so nothing verifies the token before the function does.
        """
        client = self.client(module_key, hooks)
        response = client.post(
            "/api/auth/e2e/users",
            json=dict(self.PAYLOAD),
            headers=self.bearer_for(module_key, "admin-0001", ["admin", "user"]),
        )
        assert response.status_code == 201, response.text
        assert response.json()["email"] == EMAIL
        assert PASSWORD not in response.text

    def test_a_non_admin_bearer_token_with_no_authorizer_is_refused(
        self, hooks: FakeHooks, module_key: rsa.RSAPrivateKey
    ) -> None:
        """A verified token without the role is 403, the same as the authorizer path."""
        client = self.client(module_key, hooks)
        response = client.post(
            "/api/auth/e2e/users",
            json=dict(self.PAYLOAD),
            headers=self.bearer_for(module_key, "user-0001", ["user"]),
        )
        assert response.status_code == 403
        assert response.json()["error_code"] == "ADMIN_REQUIRED"

    def test_a_bearer_token_that_does_not_verify_is_refused_as_unauthenticated(
        self, hooks: FakeHooks, module_key: rsa.RSAPrivateKey
    ) -> None:
        """A token that fails verification is 401, never a 500."""
        client = self.client(module_key, hooks)
        response = client.post(
            "/api/auth/e2e/users",
            json=dict(self.PAYLOAD),
            headers={"Authorization": "Bearer not-a-token"},
        )
        assert response.status_code == 401
        assert response.json()["error_code"] == "NOT_AUTHENTICATED"

    def test_an_admin_bearer_token_deletes_a_user(self, hooks: FakeHooks, module_key: rsa.RSAPrivateKey) -> None:
        """The delete route resolves its caller the same way the create route does."""
        client = self.client(module_key, hooks)
        admin = self.bearer_for(module_key, "admin-0001", ["admin", "user"])
        created = client.post("/api/auth/e2e/users", json=dict(self.PAYLOAD), headers=admin)
        assert created.status_code == 201, created.text
        user_id = created.json()["user_id"]
        deleted = client.delete(f"/api/auth/e2e/users/{user_id}", headers=admin)
        assert deleted.status_code == 200, deleted.text
        assert deleted.json() == {"user_id": user_id, "deleted": True}


NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)
OLD = (NOW - timedelta(hours=5)).isoformat()
FRESH = (NOW - timedelta(minutes=30)).isoformat()
MIDDLE = (NOW - timedelta(hours=2)).isoformat()


class ListingHooks(FakeHooks):
    """A product that enumerates its own ephemeral users through the optional hook."""

    def __init__(self) -> None:
        """Start empty and record every cutoff the sweep asked for."""
        super().__init__()
        self.cutoffs: list[datetime] = []

    def list_ephemeral_users(self, created_before: datetime) -> list[Mapping[str, Any]]:
        """Return every row, so the sweep's own re-checks are what narrow it."""
        self.cutoffs.append(created_before)
        return list(self.users.values())


class FakeScanRepository:
    """A package `Repository` stand-in that only knows how to scan."""

    def __init__(self, rows: dict[str, dict[str, Any]]) -> None:
        """Share the hooks' users dict."""
        self.rows = rows
        self.filters: list[Any] = []

    def iter_scan(self, *, filter_expression: Any = None) -> list[dict[str, Any]]:
        """Return every row, recording the filter it was given."""
        self.filters.append(filter_expression)
        return list(self.rows.values())


class WrappedRepository:
    """A product repository holding the package `Repository` privately, as TF and Standupless do."""

    def __init__(self, inner: FakeScanRepository) -> None:
        """Wrap the scanning repository."""
        self._repository = inner


class ScanningHooks(FakeHooks):
    """A product whose users repository wraps a scannable package `Repository`."""

    def __init__(self) -> None:
        """Start empty with a scannable repository over the same rows."""
        super().__init__()
        self.scan = FakeScanRepository(self.users)

    def user_repository(self) -> object:
        """The wrapping product repository."""
        return WrappedRepository(self.scan)


def seed(hooks: FakeHooks, user_id: str, email: str, created_at: Any) -> None:
    """Put one users row in place directly."""
    hooks.users[user_id] = {"id": user_id, "email": email, "created_at": created_at}


def seed_mix(hooks: FakeHooks) -> None:
    """An old and a fresh ephemeral user, plus durable and real users of every age."""
    seed(hooks, "old-e2e", "e2e-run-1@e2e.invalid", OLD)
    seed(hooks, "fresh-e2e", "e2e-run-2@e2e.invalid", FRESH)
    seed(hooks, "middle-e2e", "e2e-run-3@e2e.invalid", MIDDLE)
    seed(hooks, "durable", "tyler+e2e-staging@webbpulse.com", OLD)
    seed(hooks, "real", "someone@example.com", OLD)
    seed(hooks, "lookalike", "e2e-run-4@e2e.invalid.example.com", OLD)
    seed(hooks, "undated", "e2e-run-5@e2e.invalid", None)


class TestEphemeralSweepHelpers:
    """The marker and timestamp checks every sweep candidate passes through."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("e2e-run-123@e2e.invalid", True),
            ("E2E-Run-123@E2E.INVALID", True),
            ("e2e@webbpulse.com", False),
            ("tyler+e2e-staging@webbpulse.com", False),
            ("e2e-run@e2e.invalid.example.com", False),
            ("x-e2e-run@e2e.invalid", False),
            ("e2e-@e2e.invalid", False),
            (None, False),
            (42, False),
        ],
    )
    def test_is_ephemeral_email(self, value: Any, expected: bool) -> None:
        """Only the exact `e2e-<run>@e2e.invalid` shape carries the marker."""
        assert is_ephemeral_email(value) is expected

    def test_created_at_reads_every_stored_shape(self) -> None:
        """ISO strings, datetimes and epoch seconds all come back aware."""
        assert created_at_of({"created_at": "2026-09-29T12:00:00Z"}) == NOW
        assert created_at_of({"created_at": NOW.replace(tzinfo=None)}) == NOW
        assert created_at_of({"created_at": Decimal(int(NOW.timestamp()))}) == NOW
        assert created_at_of({"created_at": "not a date"}) is None
        assert created_at_of({"created_at": True}) is None
        assert created_at_of({}) is None

    def test_scan_source_finds_the_wrapped_repository(self) -> None:
        """A repository that scans is used directly, a wrapper yields what it holds."""
        inner = FakeScanRepository({})
        assert users_scan_source(inner) is inner
        assert users_scan_source(WrappedRepository(inner)) is inner
        assert users_scan_source(object()) is None


class TestEphemeralSweepFlow:
    """The sweep deletes old marked users and nothing else."""

    def test_it_deletes_only_old_marked_users_through_the_listing_hook(self, module_key: rsa.RSAPrivateKey) -> None:
        """Durable, real, fresh, lookalike and undated rows all survive."""
        hooks = ListingHooks()
        seed_mix(hooks)
        flows = make_flows(hooks, module_key, ephemeral_users_enabled=True)
        result = flows.sweep_ephemeral_users(now=NOW)
        assert result["deleted"] == ["old-e2e"]
        assert result["deleted_count"] == 1
        assert set(hooks.users) == {"fresh-e2e", "middle-e2e", "durable", "real", "lookalike", "undated"}
        assert hooks.cutoffs == [NOW - EPHEMERAL_SWEEP_DEFAULT_AGE]

    def test_it_scans_a_wrapped_package_repository(self, module_key: rsa.RSAPrivateKey) -> None:
        """Without the hook the sweep scans the repository the product repository wraps."""
        pytest.importorskip("boto3")
        hooks = ScanningHooks()
        seed_mix(hooks)
        flows = make_flows(hooks, module_key, ephemeral_users_enabled=True)
        result = flows.sweep_ephemeral_users(now=NOW)
        assert result["deleted"] == ["old-e2e"]
        assert len(hooks.scan.filters) == 1
        assert hooks.scan.filters[0] is not None

    def test_a_shorter_age_widens_the_cutoff_but_never_below_the_floor(self, module_key: rsa.RSAPrivateKey) -> None:
        """Ninety minutes reaches the two hour old user; one minute still spares the fresh one."""
        hooks = ListingHooks()
        seed_mix(hooks)
        flows = make_flows(hooks, module_key, ephemeral_users_enabled=True)
        flows.sweep_ephemeral_users(older_than=timedelta(minutes=1), now=NOW)
        assert hooks.cutoffs[-1] == NOW - EPHEMERAL_SWEEP_MINIMUM_AGE
        assert "fresh-e2e" in hooks.users
        assert "middle-e2e" not in hooks.users

    def test_a_row_whose_address_changed_since_listing_is_spared(self, module_key: rsa.RSAPrivateKey) -> None:
        """The re-read before each delete wins over a stale listing."""

        class StaleHooks(ListingHooks):
            def list_ephemeral_users(self, created_before: datetime) -> list[Mapping[str, Any]]:
                """Return a stale copy claiming the marker."""
                return [{"id": "real", "email": "e2e-run-9@e2e.invalid", "created_at": OLD}]

        hooks = StaleHooks()
        seed(hooks, "real", "someone@example.com", OLD)
        flows = make_flows(hooks, module_key, ephemeral_users_enabled=True)
        assert flows.sweep_ephemeral_users(now=NOW)["deleted"] == []
        assert hooks.deleted == []

    def test_one_call_deletes_at_most_the_limit(self, module_key: rsa.RSAPrivateKey) -> None:
        """The rest wait for the next run."""
        hooks = ListingHooks()
        for index in range(EPHEMERAL_SWEEP_LIMIT + 5):
            seed(hooks, f"e2e-{index}", f"e2e-run-{index}@e2e.invalid", OLD)
        flows = make_flows(hooks, module_key, ephemeral_users_enabled=True)
        assert flows.sweep_ephemeral_users(now=NOW)["deleted_count"] == EPHEMERAL_SWEEP_LIMIT
        assert len(hooks.users) == 5

    def test_it_refuses_when_the_flag_is_off(self, module_key: rsa.RSAPrivateKey) -> None:
        """The same gate as create and delete."""
        hooks = ListingHooks()
        seed_mix(hooks)
        flows = make_flows(hooks, module_key)
        with pytest.raises(LoginRejected) as caught:
            flows.sweep_ephemeral_users(now=NOW)
        assert caught.value.status_code == 403
        assert caught.value.error_code == "EPHEMERAL_USERS_DISABLED"
        assert hooks.deleted == []

    def test_a_product_it_cannot_enumerate_answers_501(self, hooks: FakeHooks, module_key: rsa.RSAPrivateKey) -> None:
        """No listing hook and no scannable repository is unsupported, not a crash."""
        flows = make_flows(hooks, module_key, ephemeral_users_enabled=True)
        with pytest.raises(LoginRejected) as caught:
            flows.sweep_ephemeral_users(now=NOW)
        assert caught.value.status_code == 501
        assert caught.value.error_code == "EPHEMERAL_SWEEP_UNSUPPORTED"


class TestEphemeralSweepRoute:
    """The sweep route over HTTP, behind the same gate as the create and delete routes."""

    def test_it_is_mounted_beside_the_other_routes(self, module_key: rsa.RSAPrivateKey) -> None:
        """Staging with the flag on offers it."""
        paths = TestEphemeralRouteMounting.mounted_paths(
            module_key, ephemeral_users_enabled=True, environment="staging"
        )
        assert any(path.endswith(EPHEMERAL_USERS_SWEEP_PATH) for path in paths)

    @pytest.mark.parametrize(
        "overrides",
        [
            {},
            {"ephemeral_users_enabled": True, "environment": "production"},
            {"ephemeral_users_enabled": True, "environment": "prod"},
        ],
    )
    def test_it_is_absent_in_production_or_without_the_flag(
        self, overrides: dict[str, Any], module_key: rsa.RSAPrivateKey
    ) -> None:
        """Production never mounts it, whatever the flag says."""
        paths = TestEphemeralRouteMounting.mounted_paths(module_key, **overrides)
        assert not any(path.endswith(EPHEMERAL_USERS_SWEEP_PATH) for path in paths)

    def test_an_admin_sweeps(self, module_key: rsa.RSAPrivateKey) -> None:
        """The plugin's exact payload answers 200 and names what went."""
        hooks = ListingHooks()
        seed(hooks, "old-e2e", "e2e-run-1@e2e.invalid", "2000-01-01T00:00:00+00:00")
        seed(hooks, "durable", "e2e@webbpulse.com", "2000-01-01T00:00:00+00:00")
        client = TestEphemeralRoutesOverHttp.client(module_key, hooks)
        response = client.post(
            "/api/auth/e2e/users/sweep",
            json={"older_than_seconds": 3 * 60 * 60},
            headers=TestEphemeralRoutesOverHttp.headers_for(TestEphemeralRoutesOverHttp.ADMIN),
        )
        assert response.status_code == 200, response.text
        assert response.json()["deleted"] == ["old-e2e"]
        assert set(hooks.users) == {"durable"}

    def test_no_body_uses_the_default_age(self, module_key: rsa.RSAPrivateKey) -> None:
        """An empty request is valid."""
        hooks = ListingHooks()
        client = TestEphemeralRoutesOverHttp.client(module_key, hooks)
        response = client.post(
            "/api/auth/e2e/users/sweep",
            headers=TestEphemeralRoutesOverHttp.headers_for(TestEphemeralRoutesOverHttp.ADMIN),
        )
        assert response.status_code == 200, response.text
        assert response.json()["deleted_count"] == 0

    @pytest.mark.parametrize("age", [0, -5, "3600", True, 1.5])
    def test_a_bad_age_answers_400(self, age: Any, module_key: rsa.RSAPrivateKey) -> None:
        """Only a positive whole number of seconds is accepted."""
        client = TestEphemeralRoutesOverHttp.client(module_key, ListingHooks())
        response = client.post(
            "/api/auth/e2e/users/sweep",
            json={"older_than_seconds": age},
            headers=TestEphemeralRoutesOverHttp.headers_for(TestEphemeralRoutesOverHttp.ADMIN),
        )
        assert response.status_code == 400
        assert response.json()["error_code"] == "INVALID_SWEEP_AGE"

    def test_a_non_admin_is_refused_and_nothing_goes(self, module_key: rsa.RSAPrivateKey) -> None:
        """The durable e2e user cannot sweep."""
        hooks = ListingHooks()
        seed(hooks, "old-e2e", "e2e-run-1@e2e.invalid", OLD)
        client = TestEphemeralRoutesOverHttp.client(module_key, hooks)
        response = client.post(
            "/api/auth/e2e/users/sweep",
            headers=TestEphemeralRoutesOverHttp.headers_for({"sub": "user-0001", "roles": ["user"]}),
        )
        assert response.status_code == 403
        assert hooks.deleted == []

    def test_an_anonymous_caller_is_refused(self, module_key: rsa.RSAPrivateKey) -> None:
        """No claims reads as not signed in."""
        client = TestEphemeralRoutesOverHttp.client(module_key, ListingHooks())
        response = client.post("/api/auth/e2e/users/sweep")
        assert response.status_code == 401

    def test_an_unenumerable_product_answers_501(self, hooks: FakeHooks, module_key: rsa.RSAPrivateKey) -> None:
        """The plugin reads 501 as a backend that offers no sweep."""
        client = TestEphemeralRoutesOverHttp.client(module_key, hooks)
        response = client.post(
            "/api/auth/e2e/users/sweep",
            headers=TestEphemeralRoutesOverHttp.headers_for(TestEphemeralRoutesOverHttp.ADMIN),
        )
        assert response.status_code == 501
        assert response.json()["error_code"] == "EPHEMERAL_SWEEP_UNSUPPORTED"
