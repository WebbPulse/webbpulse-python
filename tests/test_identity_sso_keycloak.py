"""An OIDC single sign-on against a real Keycloak, run by the `sso-keycloak` CI job.

Skipped unless `KEYCLOAK_URL` points at a Keycloak started in dev mode with the bootstrap
admin `admin`/`admin`. The test builds its own realm, client and user, so it needs nothing
else and leaves nothing behind but that throwaway container.
"""

from __future__ import annotations

import html
import os
import re
import secrets
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qs, urljoin, urlsplit

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from fastapi import FastAPI
from fastapi.testclient import TestClient

from webbpulse.identity import (
    AMR_SSO,
    SSO_CONNECTION_CLAIM,
    BaseIdentityHooks,
    IdentitySettings,
    IdentityStores,
    InMemoryCredentialStore,
    InMemoryOAuthLinkStore,
    InMemoryOAuthStateStore,
    InMemoryRefreshTokenStore,
    OidcConnectionConfig,
    PublicUrlGuard,
    SecretMasterKeyCipher,
    SsoConnection,
    SsoHooks,
    SsoIdentity,
    SsoLoginOutcome,
    SsoService,
    TokenService,
    build_identity_router,
    identity_prefix,
    seal_oidc_client_secret,
)
from webbpulse.identity.oauth import HttpxClient

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "").rstrip("/")

pytestmark = pytest.mark.skipif(not KEYCLOAK_URL, reason="KEYCLOAK_URL is not set")

KEY = "arn:aws:kms:us-west-2:111122223333:key/aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa"
ISSUER = "https://api.example.test/api/auth"
FRONTEND = "https://app.example.test"
REALM = "acme"
CLIENT_ID = "example-app"
CONNECTION_ID = "conn_keycloak"
DOMAIN = "acme.example"
EMAIL = f"pat@{DOMAIN}"
PASSWORD = "correct horse battery staple"


class FakeKms:
    """Signs with a local private key, so `TokenService` mints verifiable tokens."""

    def __init__(self) -> None:
        """Generate the one signing key."""
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def get_public_key(self, *, KeyId: str) -> dict[str, Any]:
        """Return the DER public key, as KMS does."""
        der = self._key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return {
            "KeyId": KeyId,
            "PublicKey": der,
            "KeySpec": "RSA_2048",
            "KeyUsage": "SIGN_VERIFY",
            "SigningAlgorithms": ["RSASSA_PKCS1_V1_5_SHA_256"],
        }

    def sign(self, *, KeyId: str, Message: bytes, MessageType: str, SigningAlgorithm: str) -> dict[str, Any]:
        """Sign a prehashed message with the local key."""
        signature = self._key.sign(Message, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
        return {"KeyId": KeyId, "Signature": signature, "SigningAlgorithm": SigningAlgorithm}


class Hooks(BaseIdentityHooks):
    """A product with an in-memory user table."""

    def __init__(self) -> None:
        """Start with no users."""
        self.users: dict[str, dict[str, Any]] = {}

    def load_user_by_id(self, user_id: str) -> Mapping[str, Any] | None:
        """Return the user with this id, or None."""
        return self.users.get(user_id)

    def load_user_by_email(self, email: str) -> Mapping[str, Any] | None:
        """Return the user with this email, or None."""
        return next((u for u in self.users.values() if u["email"] == email.lower()), None)

    def may_authenticate(self, user: Mapping[str, Any]) -> None:
        """Let every user in."""
        return None

    def create_user(self, *, email: str, attributes: Mapping[str, Any]) -> Mapping[str, Any]:
        """Create and store a user."""
        user = {"id": f"user-{len(self.users) + 1}", "email": email, **dict(attributes)}
        self.users[user["id"]] = user
        return user


class Connections(SsoHooks):
    """One Keycloak connection, recording each login outcome."""

    def __init__(self, connection: SsoConnection) -> None:
        """Hold the connection."""
        self.connection = connection
        self.outcomes: list[SsoLoginOutcome] = []

    def load_connection(self, connection_id: str) -> SsoConnection | None:
        """The connection when the id matches."""
        return self.connection if connection_id == self.connection.connection_id else None

    def find_connection(self, *, email: str = "", tenant_hint: str = "") -> SsoConnection | None:
        """The connection for an address on its verified domain."""
        return self.connection if self.connection.trusts_email(email) else None

    def on_sso_login(
        self,
        user: Mapping[str, Any],
        connection: SsoConnection,
        identity: SsoIdentity,
        *,
        outcome: SsoLoginOutcome,
    ) -> None:
        """Record the outcome."""
        self.outcomes.append(outcome)


def _admin(http: httpx.Client) -> dict[str, str]:
    """Bearer headers for the bootstrap admin."""
    response = http.post(
        f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": "admin"},
    )
    response.raise_for_status()
    return {"authorization": f"Bearer {response.json()['access_token']}"}


def _provision_realm(http: httpx.Client, *, client_secret: str, redirect_uri: str) -> None:
    """Create the realm, a confidential PKCE client and one verified user."""
    headers = _admin(http)
    http.delete(f"{KEYCLOAK_URL}/admin/realms/{REALM}", headers=headers)
    http.post(
        f"{KEYCLOAK_URL}/admin/realms", headers=headers, json={"realm": REALM, "enabled": True}
    ).raise_for_status()
    http.post(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients",
        headers=headers,
        json={
            "clientId": CLIENT_ID,
            "enabled": True,
            "publicClient": False,
            "secret": client_secret,
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": False,
            "redirectUris": [redirect_uri],
            "attributes": {"pkce.code.challenge.method": "S256"},
        },
    ).raise_for_status()
    http.post(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/users",
        headers=headers,
        json={
            "username": "pat",
            "email": EMAIL,
            "firstName": "Pat",
            "lastName": "Example",
            "emailVerified": True,
            "enabled": True,
            "requiredActions": [],
            "credentials": [{"type": "password", "value": PASSWORD, "temporary": False}],
        },
    ).raise_for_status()


def _sign_in_at_keycloak(http: httpx.Client, authorization_url: str) -> dict[str, str]:
    """Load the login page, submit the password, and return the callback's query."""
    page = http.get(authorization_url)
    assert page.status_code == 200, page.text[:500]
    match = re.search(r'id="kc-form-login"[^>]*action="([^"]+)"', page.text) or re.search(
        r'action="([^"]+)"[^>]*id="kc-form-login"', page.text
    )
    assert match, "Keycloak login form not found"
    action = urljoin(str(page.url), html.unescape(match.group(1)))
    cookies = "; ".join(f"{cookie.name}={cookie.value}" for cookie in http.cookies.jar)
    response = http.post(
        action,
        data={"username": "pat", "password": PASSWORD, "credentialId": ""},
        headers={"cookie": cookies},
    )
    feedback = re.search(r'kc-feedback-text">([^<]*)<', response.text)
    assert response.status_code in {302, 303}, feedback.group(1) if feedback else response.text[:500]
    location = response.headers["location"]
    return {key: values[0] for key, values in parse_qs(urlsplit(location).query).items()}


def test_a_keycloak_user_signs_in_and_gets_an_sso_session() -> None:
    """Start, sign in at Keycloak, finish at the callback, and refresh the session."""
    settings = IdentitySettings(
        environment="test",
        issuer=ISSUER,
        audience="example-test",
        signing_key_arns=[KEY],
        email_verification_required=False,
        frontend_base_url=FRONTEND,
        product_name="Example",
        support_email="support@example.com",
    )
    client_secret = secrets.token_urlsafe(32)
    redirect_uri = f"{ISSUER}/sso/oidc/{CONNECTION_ID}/callback"
    cipher = SecretMasterKeyCipher(os.urandom(32))
    connection = SsoConnection(
        connection_id=CONNECTION_ID,
        tenant_id="tenant-acme",
        protocol="oidc",
        verified_domains=(DOMAIN,),
        oidc=OidcConnectionConfig(
            issuer=f"{KEYCLOAK_URL}/realms/{REALM}",
            client_id=CLIENT_ID,
            sealed_client_secret=seal_oidc_client_secret(
                cipher, connection_id=CONNECTION_ID, client_secret=client_secret
            ),
        ),
    )
    hooks = Hooks()
    connections = Connections(connection)
    stores = IdentityStores(
        credentials=InMemoryCredentialStore(),
        refresh_tokens=InMemoryRefreshTokenStore(),
        oauth_states=InMemoryOAuthStateStore(),
        oauth_links=InMemoryOAuthLinkStore(),
    )
    host = urlsplit(KEYCLOAK_URL).hostname or ""
    idp_http = httpx.Client(timeout=30.0, follow_redirects=False)
    service = SsoService(
        settings,
        hooks,
        connections,
        states=stores.require_oauth_states(),
        links=stores.require_oauth_links(),
        cipher=cipher,
        http_client=HttpxClient(client=idp_http),
        url_guard=PublicUrlGuard(trusted_hosts={host}),
    )
    kms = FakeKms()
    app = FastAPI()
    app.include_router(
        build_identity_router(settings, hooks, stores, kms_client=kms, limiter_enabled=False, sso=service)
    )
    client = TestClient(app, base_url="https://testserver", follow_redirects=False)
    prefix = identity_prefix(settings)

    with idp_http, httpx.Client(timeout=30.0, follow_redirects=False) as http:
        _provision_realm(http, client_secret=client_secret, redirect_uri=redirect_uri)

        for expected in ("provisioned", "linked"):
            http.cookies.clear()
            started = client.post(f"{prefix}/sso/start", json={"email": EMAIL})
            assert started.status_code == 200, started.text
            callback = _sign_in_at_keycloak(http, started.json()["authorization_url"])
            assert callback.get("iss") == f"{KEYCLOAK_URL}/realms/{REALM}"

            finished = client.get(f"{prefix}/sso/oidc/{CONNECTION_ID}/callback", params=callback)
            assert finished.status_code == 303
            assert finished.headers["location"].endswith("sso=1"), finished.headers["location"]
            assert connections.outcomes[-1] == expected

    refreshed = client.post(f"{prefix}/refresh")
    assert refreshed.status_code == 200, refreshed.text
    claims = TokenService(settings, kms).verify_access_token(refreshed.json()["access_token"])
    assert claims["amr"] == [AMR_SSO, "oidc"]
    assert claims[SSO_CONNECTION_CLAIM] == CONNECTION_ID
    assert len(hooks.users) == 1
