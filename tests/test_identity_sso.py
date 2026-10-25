"""Tests for per-tenant OIDC single sign-on, its session issuance and DNS domain verification."""

from __future__ import annotations

import base64
import logging
import os
import time
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlsplit

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
    DnsPythonTxtResolver,
    DomainVerificationUnavailable,
    IdentitySettings,
    IdentityStores,
    InMemoryCredentialStore,
    InMemoryIdentityTokenStore,
    InMemoryOAuthLinkStore,
    InMemoryOAuthStateStore,
    InMemoryRecoveryCodeStore,
    InMemoryRefreshTokenStore,
    InMemoryTotpFactorStore,
    OidcConnectionConfig,
    PublicUrlGuard,
    SecretMasterKeyCipher,
    SsoConnection,
    SsoHooks,
    SsoIdentity,
    SsoLoginOutcome,
    SsoRejected,
    SsoService,
    TokenService,
    build_identity_router,
    domain_of_email,
    domain_verification_challenge,
    identity_prefix,
    is_domain_verified,
    new_domain_verification_token,
    normalise_domain,
    open_oidc_client_secret,
    seal_oidc_client_secret,
    sso_connection_from_amr,
    sso_session_amr,
    strip_sso_markers,
    valid_connection_id,
)
from webbpulse.identity.flows import E2E_USER_ATTRIBUTE, IdentityFlows, MfaChallengeRequired
from webbpulse.identity.mfa import access_token_amr
from webbpulse.identity.oauth import OAUTH_LINK_BINDING_COOKIE, HttpxClient

if TYPE_CHECKING:
    from collections.abc import Iterator

KEY_A = "arn:aws:kms:us-west-2:111122223333:key/aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa"
ISSUER = "https://api.example.test/api/auth"
AUDIENCE = "example-test"
FRONTEND = "https://app.example.test"

IDP_ISSUER = "https://idp.example.test/realms/acme"
CLIENT_ID = "example-app"
CLIENT_SECRET = "acme-client-secret-value-that-must-never-be-logged"
CONNECTION_ID = "conn_acme"
TENANT_ID = "tenant-acme"
DOMAIN = "acme.example"
EMAIL = f"pat@{DOMAIN}"
SUBJECT = "f3c1a2b4-0000-4000-8000-000000000001"
PUBLIC_ADDRESS = "93.184.216.34"


class FakeKms:
    """Signs with a local private key, so `TokenService` mints verifiable tokens."""

    def __init__(self, keys: dict[str, rsa.RSAPrivateKey]) -> None:
        """Hold the RSA keys this fake signs with."""
        self._keys = keys

    def get_public_key(self, *, KeyId: str) -> dict[str, Any]:
        """Return the DER public key for a key id, as KMS does."""
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
        """Sign a prehashed message with the local private key for a key id."""
        signature = self._keys[KeyId].sign(Message, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
        return {"KeyId": KeyId, "Signature": signature, "SigningAlgorithm": SigningAlgorithm}

    def generate_data_key(
        self, *, KeyId: str, NumberOfBytes: int, EncryptionContext: Mapping[str, str]
    ) -> dict[str, Any]:
        """Envelope encryption, for the MFA path a single sign-on has to honour."""
        plaintext = os.urandom(NumberOfBytes)
        blob = base64.b64encode(plaintext) + b"|" + repr(sorted(EncryptionContext.items())).encode()
        return {"KeyId": KeyId, "Plaintext": plaintext, "CiphertextBlob": blob}

    def decrypt(self, *, CiphertextBlob: bytes, EncryptionContext: Mapping[str, str]) -> dict[str, Any]:
        """Unwrap a data key blob, failing when the encryption context does not match."""
        encoded, context = CiphertextBlob.split(b"|", 1)
        if context != repr(sorted(EncryptionContext.items())).encode():
            raise RuntimeError("InvalidCiphertextException")
        return {"KeyId": KEY_A, "Plaintext": base64.b64decode(encoded)}


def _b64url(raw: bytes) -> str:
    """Base64url encode bytes without padding."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class FakeOidcProvider:
    """An `httpx.MockTransport` standing in for one tenant's OIDC identity provider."""

    def __init__(self, key: rsa.RSAPrivateKey, *, issuer: str = IDP_ISSUER) -> None:
        """Start with a well-formed discovery document and no recorded requests."""
        self.key = key
        self.issuer = issuer
        self.requests: list[httpx.Request] = []
        self.nonce = ""
        self.claims_override: dict[str, Any] = {}
        self.drop_claims: set[str] = set()
        self.discovery_override: dict[str, Any] = {}
        self.token_status = 200
        self.token_error = ""
        self.id_token_override: str | None = None
        self.userinfo: dict[str, Any] = {}
        self.signing_key: rsa.RSAPrivateKey | None = None

    def discovery(self) -> dict[str, Any]:
        """The provider's discovery document."""
        body: dict[str, Any] = {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/protocol/openid-connect/auth",
            "token_endpoint": f"{self.issuer}/protocol/openid-connect/token",
            "jwks_uri": f"{self.issuer}/protocol/openid-connect/certs",
            "userinfo_endpoint": f"{self.issuer}/protocol/openid-connect/userinfo",
            "id_token_signing_alg_values_supported": ["RS256"],
            "authorization_response_iss_parameter_supported": True,
        }
        body.update(self.discovery_override)
        return body

    def jwks(self) -> dict[str, Any]:
        """The JWKS serving this provider's public signing key."""
        numbers = self.key.public_key().public_numbers()

        def to_b64(value: int) -> str:
            """Base64url encode an RSA key parameter."""
            return _b64url(value.to_bytes((value.bit_length() + 7) // 8, "big"))

        return {
            "keys": [
                {"kty": "RSA", "kid": "idp-key", "use": "sig", "alg": "RS256", "n": to_b64(numbers.n), "e": "AQAB"},
                {"kty": "RSA", "kid": "enc-key", "use": "enc", "n": to_b64(numbers.n), "e": to_b64(numbers.e)},
            ]
        }

    def id_token(self) -> str:
        """A genuinely signed ID token for the configured person and nonce."""
        import jwt

        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "aud": CLIENT_ID,
            "sub": SUBJECT,
            "email": EMAIL,
            "email_verified": True,
            "name": "Pat Example",
            "groups": ["engineering"],
            "iat": now,
            "exp": now + 300,
            "nonce": self.nonce,
        }
        claims.update(self.claims_override)
        for name in self.drop_claims:
            claims.pop(name, None)
        key = self.signing_key or self.key
        return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "idp-key"})

    def handler(self, request: httpx.Request) -> httpx.Response:
        """Answer a provider request by URL, recording it first."""
        self.requests.append(request)
        url = str(request.url).split("?", 1)[0]
        document = self.discovery()
        if url == f"{self.issuer}/.well-known/openid-configuration":
            return httpx.Response(200, json=document)
        if url == document["jwks_uri"]:
            return httpx.Response(200, json=self.jwks())
        if url == document["token_endpoint"]:
            if self.token_error:
                return httpx.Response(self.token_status, json={"error": self.token_error})
            token = self.id_token_override if self.id_token_override is not None else self.id_token()
            return httpx.Response(
                self.token_status,
                json={"access_token": "idp-access", "id_token": token, "token_type": "Bearer"},
            )
        if url == document["userinfo_endpoint"]:
            return httpx.Response(200, json=self.userinfo)
        return httpx.Response(404, json={"error": "unexpected_url"})

    def client(self) -> HttpxClient:
        """An HTTP client wired to this fake's mock transport."""
        return HttpxClient(client=httpx.Client(transport=httpx.MockTransport(self.handler)))

    def token_requests(self) -> list[httpx.Request]:
        """Every request made to the token endpoint."""
        return [r for r in self.requests if str(r.url) == self.discovery()["token_endpoint"]]


class FakeHooks(BaseIdentityHooks):
    """A product's identity policy, in memory."""

    def __init__(self) -> None:
        """Start with no users and no recorded hook calls."""
        self.users: dict[str, dict[str, Any]] = {}
        self.by_email: dict[str, str] = {}
        self.created_via: list[str] = []
        self._next = 1

    def add(self, email: str, **attributes: Any) -> dict[str, Any]:
        """Add a user with a fresh id."""
        identifier = f"user-{self._next:04d}"
        self._next += 1
        user = {"id": identifier, "email": email, **attributes}
        self.users[identifier] = user
        self.by_email[email.lower()] = identifier
        return user

    def load_user_by_id(self, user_id: str) -> Mapping[str, Any] | None:
        """Return the user with this id, or None."""
        return self.users.get(user_id)

    def load_user_by_email(self, email: str) -> Mapping[str, Any] | None:
        """Return the user with this email, or None."""
        identifier = self.by_email.get(email.lower())
        return self.users.get(identifier) if identifier else None

    def may_authenticate(self, user: Mapping[str, Any]) -> None:
        """Let every user in."""
        return None

    def claims_for(self, user: Mapping[str, Any]) -> Mapping[str, Any]:
        """Hook claims that try to forge `amr` and the connection claim."""
        return {"amr": ["forged"], SSO_CONNECTION_CLAIM: "forged"}

    def create_user(self, *, email: str, attributes: Mapping[str, Any]) -> Mapping[str, Any]:
        """Create and store a user from the provisioning attributes."""
        return self.add(email, **dict(attributes))

    def on_user_created(self, user: Mapping[str, Any], via: str) -> None:
        """Record how a new user was created."""
        self.created_via.append(via)


class FakeSsoHooks(SsoHooks):
    """A product's connection table and login policy, in memory."""

    def __init__(self, connections: Sequence[SsoConnection]) -> None:
        """Hold the connections and record every login outcome."""
        self.connections = {connection.connection_id: connection for connection in connections}
        self.slugs = {"acme": CONNECTION_ID}
        self.logins: list[tuple[str, str, SsoLoginOutcome]] = []
        self.refuse = False

    def load_connection(self, connection_id: str) -> SsoConnection | None:
        """The connection with this id, or None."""
        return self.connections.get(connection_id)

    def find_connection(self, *, email: str = "", tenant_hint: str = "") -> SsoConnection | None:
        """The connection for a verified domain or a tenant slug."""
        if tenant_hint:
            return self.connections.get(self.slugs.get(tenant_hint, ""))
        _, _, domain = email.rpartition("@")
        for connection in self.connections.values():
            if domain and domain in connection.verified_domains:
                return connection
        return None

    def on_sso_login(
        self,
        user: Mapping[str, Any],
        connection: SsoConnection,
        identity: SsoIdentity,
        *,
        outcome: SsoLoginOutcome,
    ) -> None:
        """Record the outcome, or refuse when told to."""
        if self.refuse:
            raise SsoRejected(
                "You are not a member of this organisation.", error_code="SSO_NOT_A_MEMBER", status_code=403
            )
        self.logins.append((str(user["id"]), connection.connection_id, outcome))


@pytest.fixture(autouse=True)
def cheap_bcrypt(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Pin bcrypt to its minimum cost for the whole module."""
    import webbpulse.security as security

    real_hash = security.hash_password

    def cheap(password: str, *, rounds: int = 4) -> str:
        """Hash a password at the minimum bcrypt cost."""
        return real_hash(password, rounds=rounds)

    monkeypatch.setattr(security, "hash_password", cheap)
    yield


@pytest.fixture(scope="module")
def module_key() -> rsa.RSAPrivateKey:
    """The key this module's own access tokens are signed with."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def idp_key() -> rsa.RSAPrivateKey:
    """The identity provider's signing key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def kms(module_key: rsa.RSAPrivateKey) -> FakeKms:
    """A KMS fake holding the module signing key."""
    return FakeKms({KEY_A: module_key})


@pytest.fixture
def provider(idp_key: rsa.RSAPrivateKey) -> FakeOidcProvider:
    """The tenant's identity provider fake."""
    return FakeOidcProvider(idp_key)


@pytest.fixture
def cipher() -> SecretMasterKeyCipher:
    """The cipher client secrets are sealed with."""
    return SecretMasterKeyCipher(os.urandom(32))


def make_settings(**overrides: Any) -> IdentitySettings:
    """Identity settings for this module, with per-test overrides applied."""
    base: dict[str, Any] = {
        "environment": "test",
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "signing_key_arns": [KEY_A],
        "email_verification_required": False,
        "frontend_base_url": FRONTEND,
        "product_name": "Example",
        "support_email": "support@example.com",
    }
    base.update(overrides)
    return IdentitySettings(**base)


def make_connection(
    cipher: SecretMasterKeyCipher,
    *,
    connection_id: str = CONNECTION_ID,
    issuer: str = IDP_ISSUER,
    **overrides: Any,
) -> SsoConnection:
    """An OIDC connection with its client secret sealed, as a product would store it."""
    auth_method = overrides.pop("token_endpoint_auth_method", "client_secret_basic")
    fields: dict[str, Any] = {
        "connection_id": connection_id,
        "tenant_id": TENANT_ID,
        "protocol": "oidc",
        "verified_domains": (DOMAIN,),
        "display_name": "Acme",
        "oidc": OidcConnectionConfig(
            issuer=issuer,
            client_id=CLIENT_ID,
            sealed_client_secret=seal_oidc_client_secret(
                cipher, connection_id=connection_id, client_secret=CLIENT_SECRET
            ),
            token_endpoint_auth_method=auth_method,
        ),
    }
    fields.update(overrides)
    return SsoConnection(**fields)


def public_guard() -> PublicUrlGuard:
    """The real guard, with a resolver that answers one public address for every host."""
    return PublicUrlGuard(resolver=lambda host: [PUBLIC_ADDRESS])


@pytest.fixture
def hooks() -> FakeHooks:
    """A fresh in-memory product."""
    return FakeHooks()


@pytest.fixture
def sso_hooks(cipher: SecretMasterKeyCipher) -> FakeSsoHooks:
    """One enabled OIDC connection for the Acme tenant."""
    return FakeSsoHooks([make_connection(cipher)])


@pytest.fixture
def stores() -> IdentityStores:
    """In-memory stores, including both OAuth tables SSO reuses."""
    return IdentityStores(
        credentials=InMemoryCredentialStore(),
        refresh_tokens=InMemoryRefreshTokenStore(),
        oauth_states=InMemoryOAuthStateStore(),
        oauth_links=InMemoryOAuthLinkStore(),
    )


def make_service(
    hooks: FakeHooks,
    sso_hooks: FakeSsoHooks,
    stores: IdentityStores,
    cipher: SecretMasterKeyCipher,
    provider: FakeOidcProvider,
    *,
    guard: Any = None,
) -> SsoService:
    """An `SsoService` over the in-memory stores and the provider fake."""
    return SsoService(
        make_settings(),
        hooks,
        sso_hooks,
        states=stores.require_oauth_states(),
        links=stores.require_oauth_links(),
        cipher=cipher,
        http_client=provider.client(),
        url_guard=guard if guard is not None else public_guard(),
    )


@pytest.fixture
def service(
    hooks: FakeHooks,
    sso_hooks: FakeSsoHooks,
    stores: IdentityStores,
    cipher: SecretMasterKeyCipher,
    provider: FakeOidcProvider,
) -> SsoService:
    """The SSO service under test."""
    return make_service(hooks, sso_hooks, stores, cipher, provider)


def query_of(url: str) -> dict[str, str]:
    """The query parameters of a URL, one value each."""
    return {key: values[0] for key, values in parse_qs(urlsplit(url).query).items()}


def run_callback(service: SsoService, provider: FakeOidcProvider, *, issuer: str = IDP_ISSUER) -> SsoIdentity:
    """Start a sign-in, echo its nonce from the provider, and finish it at the service."""
    authorization = service.start(connection_id=CONNECTION_ID)
    provider.nonce = query_of(authorization.authorization_url)["nonce"]
    record = service.consume_state(authorization.state, connection_id=CONNECTION_ID)
    return service.identity_from_oidc_callback(
        service.connection(CONNECTION_ID), code="code-1", issuer=issuer, state_record=record
    )


def test_the_session_amr_carries_sso_the_protocol_and_a_connection_marker() -> None:
    """The stored amr holds the marker; a token's amr never does."""
    amr = sso_session_amr("oidc", CONNECTION_ID)
    assert amr[:2] == (AMR_SSO, "oidc")
    assert sso_connection_from_amr(amr) == CONNECTION_ID
    assert strip_sso_markers(amr) == (AMR_SSO, "oidc")
    assert access_token_amr(amr) == (AMR_SSO, "oidc")
    assert sso_connection_from_amr(["pwd"]) == ""


def test_an_sso_factor_plus_a_one_time_code_counts_as_mfa() -> None:
    """`sso` is a factor, so a step-up on top of it is two."""
    assert "mfa" in access_token_amr([*sso_session_amr("oidc", CONNECTION_ID), "otp"])


@pytest.mark.parametrize("value", ["conn_acme", "A-1", "x" * 64])
def test_safe_connection_ids_are_accepted(value: str) -> None:
    """Letters, digits, hyphen and underscore up to 64 characters."""
    assert valid_connection_id(value)


@pytest.mark.parametrize("value", ["", "x" * 65, "a/b", "a#b", "a:b", "a b", "../x"])
def test_unsafe_connection_ids_are_refused(value: str) -> None:
    """Nothing that could break a URL path, a link key or an amr marker."""
    assert not valid_connection_id(value)


def test_a_connection_trusts_only_its_verified_domains(cipher: SecretMasterKeyCipher) -> None:
    """Case and a trailing dot do not matter; a subdomain or lookalike is not trusted."""
    connection = make_connection(cipher, verified_domains=("Acme.Example.",))
    assert connection.trusts_email("PAT@acme.example")
    assert not connection.trusts_email("pat@eng.acme.example")
    assert not connection.trusts_email("pat@acme.example.evil")
    assert not connection.trusts_email("not-an-email")


def test_a_client_secret_round_trips_and_is_bound_to_its_connection(cipher: SecretMasterKeyCipher) -> None:
    """A sealed secret moved to another connection does not open."""
    sealed = seal_oidc_client_secret(cipher, connection_id="one", client_secret=CLIENT_SECRET)
    assert CLIENT_SECRET not in sealed.ciphertext
    assert open_oidc_client_secret(cipher, connection_id="one", sealed=sealed) == CLIENT_SECRET
    with pytest.raises(SsoRejected) as excinfo:
        open_oidc_client_secret(cipher, connection_id="two", sealed=sealed)
    assert excinfo.value.error_code == "SSO_CONNECTION_UNAVAILABLE"
    assert excinfo.value.status_code == 503


def test_start_builds_a_pkce_url_and_writes_a_connection_bound_state(
    service: SsoService, stores: IdentityStores
) -> None:
    """S256 PKCE, a nonce, the per-connection callback and a state tied to the connection."""
    authorization = service.start(email=EMAIL, binding="digest")
    params = query_of(authorization.authorization_url)
    assert authorization.authorization_url.startswith(f"{IDP_ISSUER}/protocol/openid-connect/auth?")
    assert authorization.connection_id == CONNECTION_ID
    assert params["client_id"] == CLIENT_ID
    assert params["response_type"] == "code"
    assert params["code_challenge_method"] == "S256"
    assert params["nonce"]
    assert params["login_hint"] == EMAIL
    assert params["redirect_uri"] == f"{ISSUER}/sso/oidc/{CONNECTION_ID}/callback"
    assert "code_verifier" not in params
    assert CLIENT_SECRET not in authorization.authorization_url

    record = stores.require_oauth_states().consume(authorization.state)
    assert record is not None
    assert record.provider == f"sso:{CONNECTION_ID}"
    assert record.binding == "digest"
    assert record.nonce == params["nonce"]
    assert record.redirect_uri == params["redirect_uri"]


def test_start_finds_a_connection_by_tenant_slug(service: SsoService) -> None:
    """A sign-in page that knows the tenant does not need an address."""
    assert service.start(tenant_hint="acme").connection_id == CONNECTION_ID


@pytest.mark.parametrize(
    "kwargs",
    [
        {"email": "pat@unknown.example"},
        {"tenant_hint": "nobody"},
        {"connection_id": "missing"},
        {"connection_id": "a/b"},
    ],
)
def test_start_answers_one_not_found_for_every_miss(service: SsoService, kwargs: dict[str, str]) -> None:
    """The response does not reveal which tenants exist."""
    with pytest.raises(SsoRejected) as excinfo:
        service.start(**kwargs)
    assert excinfo.value.error_code == "SSO_CONNECTION_NOT_FOUND"
    assert excinfo.value.status_code == 404


def test_a_disabled_connection_cannot_start(
    hooks: FakeHooks, stores: IdentityStores, cipher: SecretMasterKeyCipher, provider: FakeOidcProvider
) -> None:
    """Disabling a connection stops new sign-ins at once."""
    service = make_service(hooks, FakeSsoHooks([make_connection(cipher, enabled=False)]), stores, cipher, provider)
    with pytest.raises(SsoRejected) as excinfo:
        service.start(connection_id=CONNECTION_ID)
    assert excinfo.value.error_code == "SSO_CONNECTION_NOT_FOUND"


def test_a_saml_connection_without_saml_wiring_answers_501(
    hooks: FakeHooks, stores: IdentityStores, cipher: SecretMasterKeyCipher, provider: FakeOidcProvider
) -> None:
    """A SAML connection on a service with no SAML replay store or config is unsupported."""
    saml = SsoConnection(connection_id="conn_saml", tenant_id=TENANT_ID, protocol="saml", verified_domains=(DOMAIN,))
    service = make_service(hooks, FakeSsoHooks([saml]), stores, cipher, provider)
    with pytest.raises(SsoRejected) as excinfo:
        service.start(connection_id="conn_saml")
    assert excinfo.value.status_code == 501


def test_a_state_is_spent_once_and_only_at_its_own_connection(service: SsoService) -> None:
    """A state minted for one tenant's provider cannot finish at another tenant's callback."""
    first = service.start(connection_id=CONNECTION_ID)
    with pytest.raises(SsoRejected) as excinfo:
        service.consume_state(first.state, connection_id="conn_other")
    assert excinfo.value.error_code == "SSO_STATE_INVALID"

    second = service.start(connection_id=CONNECTION_ID)
    assert service.consume_state(second.state, connection_id=CONNECTION_ID).provider == f"sso:{CONNECTION_ID}"
    with pytest.raises(SsoRejected):
        service.consume_state(second.state, connection_id=CONNECTION_ID)


def test_a_callback_yields_the_verified_identity(service: SsoService, provider: FakeOidcProvider) -> None:
    """Subject, email and the raw claims for role mapping, minus the protocol plumbing."""
    identity = run_callback(service, provider)
    assert identity.connection_id == CONNECTION_ID
    assert identity.protocol == "oidc"
    assert identity.subject == SUBJECT
    assert identity.email == EMAIL
    assert identity.email_verified is True
    assert identity.name == "Pat Example"
    assert identity.attributes["groups"] == ["engineering"]
    assert "nonce" not in identity.attributes
    assert identity.account_key == f"sso:{CONNECTION_ID}#{SUBJECT}"


def test_the_exchange_authenticates_with_basic_auth_and_sends_the_verifier(
    service: SsoService, provider: FakeOidcProvider
) -> None:
    """`client_secret_basic` by default, and the PKCE verifier on the exchange."""
    run_callback(service, provider)
    (request,) = provider.token_requests()
    form = dict(parse_qs(request.content.decode()))
    assert form["grant_type"] == ["authorization_code"]
    assert form["code"] == ["code-1"]
    assert form["code_verifier"][0]
    assert "client_secret" not in form
    expected = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    assert request.headers["authorization"] == f"Basic {expected}"


def test_client_secret_post_sends_the_secret_in_the_body(
    hooks: FakeHooks, stores: IdentityStores, cipher: SecretMasterKeyCipher, provider: FakeOidcProvider
) -> None:
    """Some providers accept only the form body."""
    connection = make_connection(cipher, token_endpoint_auth_method="client_secret_post")
    service = make_service(hooks, FakeSsoHooks([connection]), stores, cipher, provider)
    run_callback(service, provider)
    (request,) = provider.token_requests()
    form = dict(parse_qs(request.content.decode()))
    assert form["client_secret"] == [CLIENT_SECRET]
    assert form["client_id"] == [CLIENT_ID]
    assert "authorization" not in request.headers


def test_the_client_secret_never_reaches_a_log_record(
    service: SsoService, provider: FakeOidcProvider, caplog: pytest.LogCaptureFixture
) -> None:
    """Not on success and not on a failed exchange."""
    caplog.set_level(logging.DEBUG)
    run_callback(service, provider)
    provider.token_status = 400
    provider.token_error = "invalid_client"
    with pytest.raises(SsoRejected):
        run_callback(service, provider)
    for record in caplog.records:
        assert CLIENT_SECRET not in record.getMessage()
        assert CLIENT_SECRET not in repr(record.__dict__)


def test_a_failed_exchange_is_refused_without_the_provider_message(
    service: SsoService, provider: FakeOidcProvider
) -> None:
    """The provider's error string stays in the log."""
    provider.token_status = 400
    provider.token_error = "invalid_grant"
    with pytest.raises(SsoRejected) as excinfo:
        run_callback(service, provider)
    assert excinfo.value.error_code == "SSO_EXCHANGE_FAILED"
    assert "invalid_grant" not in excinfo.value.message


def test_an_iss_parameter_from_another_provider_is_refused(service: SsoService, provider: FakeOidcProvider) -> None:
    """RFC 9207: a response from a different tenant's provider is a mix-up."""
    with pytest.raises(SsoRejected) as excinfo:
        run_callback(service, provider, issuer="https://idp.example.test/realms/other")
    assert excinfo.value.error_code == "SSO_ISSUER_MISMATCH"
    assert provider.token_requests() == []


def test_a_missing_iss_is_refused_when_the_provider_advertises_it(
    service: SsoService, provider: FakeOidcProvider
) -> None:
    """A provider that promises `iss` must send it."""
    with pytest.raises(SsoRejected) as excinfo:
        run_callback(service, provider, issuer="")
    assert excinfo.value.error_code == "SSO_ISSUER_MISMATCH"


def test_a_missing_iss_is_accepted_when_the_provider_never_sends_it(
    service: SsoService, provider: FakeOidcProvider
) -> None:
    """Not every provider implements RFC 9207."""
    provider.discovery_override = {"authorization_response_iss_parameter_supported": False}
    assert run_callback(service, provider, issuer="").subject == SUBJECT


def test_a_wrong_nonce_is_refused(service: SsoService, provider: FakeOidcProvider) -> None:
    """An ID token replayed from another sign-in carries another nonce."""
    provider.claims_override = {"nonce": "replayed"}
    with pytest.raises(SsoRejected) as excinfo:
        run_callback(service, provider)
    assert excinfo.value.error_code == "SSO_NONCE_MISMATCH"


@pytest.mark.parametrize(
    "override",
    [
        {"aud": "another-app"},
        {"iss": "https://idp.example.test/realms/other"},
        {"exp": int(time.time()) - 3600, "iat": int(time.time()) - 7200},
        {"aud": [CLIENT_ID, "another-app"], "azp": "another-app"},
    ],
)
def test_an_id_token_that_fails_a_claim_check_is_refused(
    service: SsoService, provider: FakeOidcProvider, override: dict[str, Any]
) -> None:
    """Audience, issuer, expiry and authorised party are all checked."""
    provider.claims_override = override
    with pytest.raises(SsoRejected) as excinfo:
        run_callback(service, provider)
    assert excinfo.value.error_code == "SSO_ID_TOKEN_INVALID"


def test_an_id_token_signed_by_another_key_is_refused(service: SsoService, provider: FakeOidcProvider) -> None:
    """The signature is checked against the provider's JWKS."""
    provider.signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(SsoRejected) as excinfo:
        run_callback(service, provider)
    assert excinfo.value.error_code == "SSO_ID_TOKEN_INVALID"


@pytest.mark.parametrize("algorithm", ["HS256", "none"])
def test_a_symmetric_or_unsigned_id_token_is_refused(
    service: SsoService, provider: FakeOidcProvider, algorithm: str
) -> None:
    """The client secret is never accepted as a signing key, and `none` never at all."""
    import jwt

    now = int(time.time())
    claims = {"iss": IDP_ISSUER, "aud": CLIENT_ID, "sub": SUBJECT, "iat": now, "exp": now + 300}
    key: Any = CLIENT_SECRET * 2 if algorithm == "HS256" else None
    provider.id_token_override = jwt.encode(claims, key, algorithm=algorithm)
    with pytest.raises(SsoRejected) as excinfo:
        run_callback(service, provider)
    assert excinfo.value.error_code == "SSO_ID_TOKEN_INVALID"


def test_userinfo_supplies_an_email_the_id_token_left_out(service: SsoService, provider: FakeOidcProvider) -> None:
    """Only when its `sub` matches the ID token's."""
    provider.drop_claims = {"email", "email_verified"}
    provider.userinfo = {"sub": SUBJECT, "email": EMAIL.upper(), "email_verified": True}
    identity = run_callback(service, provider)
    assert identity.email == EMAIL
    assert identity.email_verified is True

    provider.userinfo = {"sub": "someone-else", "email": EMAIL, "email_verified": True}
    assert run_callback(service, provider).email == ""


def test_a_discovery_document_for_another_issuer_is_refused(
    hooks: FakeHooks, stores: IdentityStores, cipher: SecretMasterKeyCipher, provider: FakeOidcProvider
) -> None:
    """The document's `issuer` must equal the configured issuer exactly."""
    provider.discovery_override = {"issuer": "https://idp.example.test/realms/other"}
    service = make_service(hooks, FakeSsoHooks([make_connection(cipher)]), stores, cipher, provider)
    with pytest.raises(SsoRejected) as excinfo:
        service.start(connection_id=CONNECTION_ID)
    assert excinfo.value.error_code == "SSO_DISCOVERY_FAILED"
    assert excinfo.value.status_code == 502


@pytest.mark.parametrize(
    ("url", "addresses"),
    [
        ("http://idp.example.test/realms/acme", [PUBLIC_ADDRESS]),
        ("https://user:pass@idp.example.test/realms/acme", [PUBLIC_ADDRESS]),
        ("https://idp.example.test/realms/acme", ["127.0.0.1"]),
        ("https://idp.example.test/realms/acme", ["10.1.2.3"]),
        ("https://idp.example.test/realms/acme", ["169.254.169.254"]),
        ("https://idp.example.test/realms/acme", [PUBLIC_ADDRESS, "192.168.0.10"]),
        ("https://idp.example.test/realms/acme", ["::1"]),
        ("https://idp.example.test/realms/acme", ["fd00::1"]),
        ("https://idp.example.test/realms/acme", []),
    ],
)
def test_the_guard_refuses_anything_but_https_to_public_addresses(url: str, addresses: list[str]) -> None:
    """A tenant's issuer must not reach the metadata service or anything inside the network."""
    guard = PublicUrlGuard(resolver=lambda host: addresses)
    with pytest.raises(SsoRejected) as excinfo:
        guard(url)
    assert excinfo.value.error_code == "SSO_PROVIDER_URL_REFUSED"


def test_the_guard_passes_a_public_https_url_and_a_trusted_host() -> None:
    """`trusted_hosts` is how a local test provider is reached."""
    PublicUrlGuard(resolver=lambda host: [PUBLIC_ADDRESS])("https://idp.example.test/x")
    PublicUrlGuard(trusted_hosts={"localhost"}, resolver=lambda host: ["127.0.0.1"])("http://localhost:8080/x")


def test_a_private_issuer_is_refused_before_any_request(
    hooks: FakeHooks, stores: IdentityStores, cipher: SecretMasterKeyCipher, provider: FakeOidcProvider
) -> None:
    """The guard runs before discovery, so nothing is fetched."""
    guard = PublicUrlGuard(resolver=lambda host: ["10.0.0.5"])
    service = make_service(hooks, FakeSsoHooks([make_connection(cipher)]), stores, cipher, provider, guard=guard)
    with pytest.raises(SsoRejected) as excinfo:
        service.start(connection_id=CONNECTION_ID)
    assert excinfo.value.error_code == "SSO_PROVIDER_URL_REFUSED"
    assert provider.requests == []


def test_a_first_sign_in_on_a_verified_domain_provisions_and_links(
    service: SsoService, provider: FakeOidcProvider, hooks: FakeHooks, sso_hooks: FakeSsoHooks
) -> None:
    """JIT creates a verified account, links it, and tells the product."""
    connection = service.connection(CONNECTION_ID)
    user, outcome = service.resolve_login(connection, run_callback(service, provider))
    assert outcome == "provisioned"
    assert user["email"] == EMAIL
    assert user["email_verified"] is True
    assert hooks.created_via == ["sso"]
    assert sso_hooks.logins == [(str(user["id"]), CONNECTION_ID, "provisioned")]

    again, outcome = service.resolve_login(connection, run_callback(service, provider))
    assert outcome == "linked"
    assert again["id"] == user["id"]


def test_a_provisioned_sso_user_is_never_marked_as_e2e(
    service: SsoService, provider: FakeOidcProvider, hooks: FakeHooks
) -> None:
    """An IdP claim named `e2e_user` does not reach `create_user`, so JIT cannot mark an account."""
    provider.claims_override = {E2E_USER_ATTRIBUTE: True}
    user, outcome = service.resolve_login(service.connection(CONNECTION_ID), run_callback(service, provider))
    assert outcome == "provisioned"
    assert E2E_USER_ATTRIBUTE not in user
    assert E2E_USER_ATTRIBUTE not in hooks.users[str(user["id"])]


def test_the_link_follows_the_subject_not_the_email(
    service: SsoService, provider: FakeOidcProvider, hooks: FakeHooks
) -> None:
    """A renamed address at the provider still lands in the same account."""
    connection = service.connection(CONNECTION_ID)
    user, _ = service.resolve_login(connection, run_callback(service, provider))
    provider.claims_override = {"email": f"renamed@{DOMAIN}"}
    again, outcome = service.resolve_login(connection, run_callback(service, provider))
    assert outcome == "linked"
    assert again["id"] == user["id"]


def test_an_existing_verified_account_on_the_domain_is_auto_linked(
    service: SsoService, provider: FakeOidcProvider, hooks: FakeHooks
) -> None:
    """The tenant owns the domain, and the local address was proven too."""
    existing = hooks.add(EMAIL, email_verified=True)
    user, outcome = service.resolve_login(service.connection(CONNECTION_ID), run_callback(service, provider))
    assert outcome == "auto_linked"
    assert user["id"] == existing["id"]
    assert hooks.created_via == []


def test_an_existing_unverified_account_is_not_taken_over(
    service: SsoService, provider: FakeOidcProvider, hooks: FakeHooks
) -> None:
    """Someone who registered the address without proving it does not get a link."""
    hooks.add(EMAIL, email_verified=False)
    with pytest.raises(SsoRejected) as excinfo:
        service.resolve_login(service.connection(CONNECTION_ID), run_callback(service, provider))
    assert excinfo.value.error_code == "SSO_EMAIL_UNVERIFIED"
    assert excinfo.value.status_code == 409


def test_an_address_off_the_verified_domains_is_refused(
    service: SsoService, provider: FakeOidcProvider, hooks: FakeHooks
) -> None:
    """A tenant's provider cannot assert an address on someone else's domain."""
    victim = hooks.add("victim@elsewhere.example", email_verified=True)
    provider.claims_override = {"email": "victim@elsewhere.example"}
    with pytest.raises(SsoRejected) as excinfo:
        service.resolve_login(service.connection(CONNECTION_ID), run_callback(service, provider))
    assert excinfo.value.error_code == "SSO_DOMAIN_NOT_VERIFIED"
    assert excinfo.value.status_code == 403
    assert len(hooks.users) == 1
    assert hooks.users[str(victim["id"])] == victim


def test_provisioning_can_be_turned_off(
    hooks: FakeHooks, stores: IdentityStores, cipher: SecretMasterKeyCipher, provider: FakeOidcProvider
) -> None:
    """With JIT off only invited accounts may sign in."""
    service = make_service(
        hooks, FakeSsoHooks([make_connection(cipher, jit_provisioning=False)]), stores, cipher, provider
    )
    with pytest.raises(SsoRejected) as excinfo:
        service.resolve_login(service.connection(CONNECTION_ID), run_callback(service, provider))
    assert excinfo.value.error_code == "SSO_PROVISIONING_DISABLED"
    assert hooks.users == {}


def test_an_identity_with_no_email_cannot_create_or_attach(service: SsoService, provider: FakeOidcProvider) -> None:
    """Without an address there is nothing to check the verified domains against."""
    provider.drop_claims = {"email", "email_verified"}
    provider.discovery_override = {"userinfo_endpoint": ""}
    with pytest.raises(SsoRejected) as excinfo:
        service.resolve_login(service.connection(CONNECTION_ID), run_callback(service, provider))
    assert excinfo.value.error_code == "SSO_EMAIL_MISSING"


def test_the_product_hook_can_refuse_a_sign_in(
    service: SsoService, provider: FakeOidcProvider, sso_hooks: FakeSsoHooks
) -> None:
    """`on_sso_login` is where membership and role policy live."""
    sso_hooks.refuse = True
    with pytest.raises(SsoRejected) as excinfo:
        service.resolve_login(service.connection(CONNECTION_ID), run_callback(service, provider))
    assert excinfo.value.error_code == "SSO_NOT_A_MEMBER"


def test_an_identity_from_another_connection_is_refused(service: SsoService, provider: FakeOidcProvider) -> None:
    """The resolver never links an identity under a connection it did not come through."""
    identity = run_callback(service, provider)
    other = SsoIdentity(connection_id="conn_other", protocol="oidc", subject=identity.subject, email=identity.email)
    with pytest.raises(SsoRejected) as excinfo:
        service.resolve_login(service.connection(CONNECTION_ID), other)
    assert excinfo.value.error_code == "SSO_CONNECTION_MISMATCH"


@pytest.fixture
def flows(hooks: FakeHooks, stores: IdentityStores, kms: FakeKms) -> IdentityFlows:
    """Identity flows over the in-memory stores."""
    settings = make_settings()
    return IdentityFlows(settings, hooks, stores, TokenService(settings, kms), kms_client=kms)


def test_an_sso_session_carries_sso_in_amr_and_names_its_connection(
    flows: IdentityFlows, hooks: FakeHooks, kms: FakeKms
) -> None:
    """The product enforces per-tenant SSO from these two claims."""
    tokens = TokenService(make_settings(), kms)
    user = hooks.add(EMAIL, email_verified=True)
    result = flows.issue_for_sso(user, connection_id=CONNECTION_ID, protocol="oidc")
    claims = tokens.verify_access_token(result.access_token)
    assert claims["amr"] == [AMR_SSO, "oidc"]
    assert claims[SSO_CONNECTION_CLAIM] == CONNECTION_ID
    assert result.refresh_token


def test_a_refresh_keeps_the_sso_amr_and_connection(flows: IdentityFlows, hooks: FakeHooks, kms: FakeKms) -> None:
    """A rotated access token is still an SSO session from the same connection."""
    tokens = TokenService(make_settings(), kms)
    user = hooks.add(EMAIL, email_verified=True)
    first = flows.issue_for_sso(user, connection_id=CONNECTION_ID, protocol="oidc")
    rotated = flows.refresh(first.refresh_token)
    claims = tokens.verify_access_token(rotated.access_token)
    assert claims["amr"] == [AMR_SSO, "oidc"]
    assert claims[SSO_CONNECTION_CLAIM] == CONNECTION_ID


def test_a_hook_cannot_forge_the_connection_claim(flows: IdentityFlows, hooks: FakeHooks, kms: FakeKms) -> None:
    """A non-SSO session never carries `sso_connection`, whatever `claims_for` returns."""
    tokens = TokenService(make_settings(), kms)
    user = hooks.add(EMAIL, email_verified=True)
    result = flows.issue_for_oauth(user, provider="google")
    claims = tokens.verify_access_token(result.access_token)
    assert SSO_CONNECTION_CLAIM not in claims
    assert "forged" not in claims["amr"]


def test_an_sso_sign_in_honours_mfa(hooks: FakeHooks, stores: IdentityStores, kms: FakeKms) -> None:
    """The identity provider proving who someone is does not satisfy a local second factor."""
    from webbpulse.identity import totp as totp_module

    mfa_stores = IdentityStores(
        credentials=stores.credentials,
        refresh_tokens=stores.refresh_tokens,
        totp_factors=InMemoryTotpFactorStore(),
        recovery_codes=InMemoryRecoveryCodeStore(),
        identity_tokens=InMemoryIdentityTokenStore(),
    )
    settings = make_settings(data_key_arn=KEY_A)
    flows = IdentityFlows(settings, hooks, mfa_stores, TokenService(settings, kms), kms_client=kms)
    user = hooks.add(EMAIL, email_verified=True)
    assert flows.mfa is not None
    enrolment = flows.mfa.begin_enrolment(str(user["id"]), account_name=EMAIL)
    flows.mfa.confirm_enrolment(
        str(user["id"]), totp_module.generate_code(enrolment.secret, step=totp_module.current_step())
    )
    with pytest.raises(MfaChallengeRequired):
        flows.issue_for_sso(user, connection_id=CONNECTION_ID, protocol="oidc")


def build_client(
    hooks: FakeHooks, stores: IdentityStores, kms: FakeKms, service: SsoService
) -> tuple[TestClient, FastAPI]:
    """An HTTPS `TestClient` over a router with the SSO routes mounted."""
    app = FastAPI()
    app.include_router(
        build_identity_router(make_settings(), hooks, stores, kms_client=kms, limiter_enabled=False, sso=service)
    )
    return TestClient(app, base_url="https://testserver", follow_redirects=False), app


@pytest.fixture
def client(hooks: FakeHooks, stores: IdentityStores, kms: FakeKms, service: SsoService) -> TestClient:
    """The HTTPS test client."""
    return build_client(hooks, stores, kms, service)[0]


PREFIX = identity_prefix(make_settings())


def start_through_the_route(client: TestClient, provider: FakeOidcProvider, **body: str) -> dict[str, str]:
    """POST the start route and echo its nonce from the provider; returns the URL's params."""
    response = client.post(f"{PREFIX}/sso/start", json=body or {"email": EMAIL, "return_to": "/home"})
    assert response.status_code == 200, response.text
    assert response.json()["connection_id"] == CONNECTION_ID
    params = query_of(response.json()["authorization_url"])
    provider.nonce = params["nonce"]
    return params


def test_the_routes_sign_a_user_in_end_to_end(
    client: TestClient, provider: FakeOidcProvider, hooks: FakeHooks, kms: FakeKms
) -> None:
    """Start, come back from the provider, and leave with a refresh cookie and `sso=1`."""
    settings = make_settings()
    params = start_through_the_route(client, provider)
    assert client.cookies.get(OAUTH_LINK_BINDING_COOKIE)

    response = client.get(
        f"{PREFIX}/sso/oidc/{CONNECTION_ID}/callback",
        params={"state": params["state"], "code": "code-1", "iss": IDP_ISSUER},
    )
    assert response.status_code == 303
    assert response.headers["location"] == f"{FRONTEND}/home?sso=1"
    cookies = response.headers.get_list("set-cookie")
    assert any(c.startswith(f"{settings.cookie_name}=") for c in cookies)
    assert any(c.startswith(f'{OAUTH_LINK_BINDING_COOKIE}=""') for c in cookies)
    assert len(hooks.users) == 1

    refreshed = client.post(f"{PREFIX}/refresh")
    assert refreshed.status_code == 200, refreshed.text
    claims = TokenService(settings, kms).verify_access_token(refreshed.json()["access_token"])
    assert claims["amr"] == [AMR_SSO, "oidc"]
    assert claims[SSO_CONNECTION_CLAIM] == CONNECTION_ID


def test_the_callback_refuses_a_browser_that_did_not_start_the_sign_in(
    client: TestClient, provider: FakeOidcProvider, hooks: FakeHooks
) -> None:
    """A login CSRF lands nowhere: no binding cookie, no session."""
    settings = make_settings()
    params = start_through_the_route(client, provider)
    client.cookies.clear()
    response = client.get(
        f"{PREFIX}/sso/oidc/{CONNECTION_ID}/callback",
        params={"state": params["state"], "code": "code-1", "iss": IDP_ISSUER},
    )
    assert response.status_code == 303
    assert "sso_error=SSO_STATE_INVALID" in response.headers["location"]
    assert not any(c.startswith(f"{settings.cookie_name}=") for c in response.headers.get_list("set-cookie"))
    assert hooks.users == {}


def test_the_callback_refuses_a_state_from_another_connection(client: TestClient, provider: FakeOidcProvider) -> None:
    """The path's connection id must be the one the state was minted for."""
    params = start_through_the_route(client, provider)
    response = client.get(
        f"{PREFIX}/sso/oidc/conn_other/callback",
        params={"state": params["state"], "code": "code-1", "iss": IDP_ISSUER},
    )
    assert response.status_code == 303
    assert response.headers["location"] == f"{FRONTEND}?sso_error=SSO_STATE_INVALID"


def test_a_cancelled_sign_in_redirects_with_a_code(client: TestClient, provider: FakeOidcProvider) -> None:
    """The provider's own error text never reaches the URL."""
    params = start_through_the_route(client, provider)
    response = client.get(
        f"{PREFIX}/sso/oidc/{CONNECTION_ID}/callback",
        params={"state": params["state"], "error": "access_denied", "error_description": "<script>"},
    )
    assert response.status_code == 303
    assert response.headers["location"] == f"{FRONTEND}/home?sso_error=SSO_CANCELLED"


def test_a_refused_resolution_redirects_with_its_code(client: TestClient, provider: FakeOidcProvider) -> None:
    """An address off the verified domains comes back as `SSO_DOMAIN_NOT_VERIFIED`."""
    params = start_through_the_route(client, provider)
    provider.claims_override = {"email": "pat@elsewhere.example"}
    response = client.get(
        f"{PREFIX}/sso/oidc/{CONNECTION_ID}/callback",
        params={"state": params["state"], "code": "code-1", "iss": IDP_ISSUER},
    )
    assert response.status_code == 303
    assert response.headers["location"] == f"{FRONTEND}/home?sso_error=SSO_DOMAIN_NOT_VERIFIED"


def test_the_start_route_answers_404_json_for_an_unknown_address(client: TestClient) -> None:
    """The sign-in page falls back to the password form on this code."""
    response = client.post(f"{PREFIX}/sso/start", json={"email": "pat@unknown.example"})
    assert response.status_code == 404
    assert response.json()["error_code"] == "SSO_CONNECTION_NOT_FOUND"


def test_the_routes_appear_in_the_openapi_document(
    hooks: FakeHooks, stores: IdentityStores, kms: FakeKms, service: SsoService
) -> None:
    """The schema builds, and declares the real statuses."""
    _, app = build_client(hooks, stores, kms, service)
    paths = app.openapi()["paths"]
    assert "404" in paths[f"{PREFIX}/sso/start"]["post"]["responses"]
    assert "303" in paths[f"{PREFIX}/sso/oidc/{{connection_id}}/callback"]["get"]["responses"]


def test_no_sso_routes_mount_without_a_service(hooks: FakeHooks, stores: IdentityStores, kms: FakeKms) -> None:
    """A product that never passes `sso` gets nothing new."""
    router = build_identity_router(make_settings(), hooks, stores, kms_client=kms, limiter_enabled=False)
    assert not [route for route in router.routes if "/sso/" in str(getattr(route, "path", ""))]


def test_an_sso_service_without_flows_is_a_configuration_error(kms: FakeKms, service: SsoService) -> None:
    """Sessions are issued through the flows, so a router without hooks cannot host SSO."""
    with pytest.raises(ValueError, match="sso"):
        build_identity_router(make_settings(), kms_client=kms, sso=service)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Acme.Example.", "acme.example"),
        ("  sub.acme.example ", "sub.acme.example"),
        ("bücher.example", "xn--bcher-kva.example"),
    ],
)
def test_domains_are_normalised(raw: str, expected: str) -> None:
    """Lower case, no trailing dot, IDNA encoded."""
    assert normalise_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "localhost", "*.acme.example", "-acme.example", "acme..example", "10.0.0.1"])
def test_implausible_domains_are_refused(raw: str) -> None:
    """A single label, a wildcard, a bad label or an IP address."""
    with pytest.raises(ValueError):
        normalise_domain(raw)


def test_the_domain_of_an_email_is_normalised() -> None:
    """The part after the last `@`."""
    assert domain_of_email("Pat@ACME.example") == "acme.example"
    with pytest.raises(ValueError):
        domain_of_email("no-at-sign")


def test_the_challenge_is_a_prefixed_txt_record_at_the_apex() -> None:
    """`<prefix>-verification=<token>` on the domain itself."""
    token = new_domain_verification_token()
    assert len(token) >= 32
    challenge = domain_verification_challenge("ACME.example", token, prefix="example")
    assert challenge.domain == "acme.example"
    assert challenge.record_name == "acme.example"
    assert challenge.record_type == "TXT"
    assert challenge.record_value == f"example-verification={token}"


@pytest.mark.parametrize("prefix", ["", "Example", "ex ample", "-x", "x" * 40])
def test_a_bad_prefix_is_refused(prefix: str) -> None:
    """Lower-case letters, digits and inner hyphens only."""
    with pytest.raises(ValueError):
        domain_verification_challenge("acme.example", "token", prefix=prefix)


class FakeTxtResolver:
    """A `TxtResolver` answering from a dict, or failing when told to."""

    def __init__(self, records: Mapping[str, Sequence[str]], *, fail: bool = False) -> None:
        """Hold the records per name and whether every lookup fails."""
        self.records = records
        self.fail = fail
        self.names: list[str] = []

    def txt_records(self, name: str) -> Sequence[str]:
        """The records at `name`."""
        self.names.append(name)
        if self.fail:
            raise DomainVerificationUnavailable("Timeout")
        return self.records.get(name, [])


def test_a_published_token_verifies_the_domain() -> None:
    """Among other TXT records, with surrounding whitespace tolerated."""
    resolver = FakeTxtResolver({"acme.example": ["v=spf1 -all", " example-verification=tok-1 "]})
    assert is_domain_verified("Acme.Example", "tok-1", prefix="example", resolver=resolver)
    assert resolver.names == ["acme.example"]


@pytest.mark.parametrize(
    "records",
    [[], ["example-verification=tok-2"], ["other-verification=tok-1"], ["example-verification=tok-1x"]],
)
def test_a_missing_or_different_token_does_not_verify(records: list[str]) -> None:
    """Another product's record, another tenant's token or a longer string all fail."""
    resolver = FakeTxtResolver({"acme.example": records})
    assert not is_domain_verified("acme.example", "tok-1", prefix="example", resolver=resolver)


def test_a_dns_failure_is_not_read_as_unverified() -> None:
    """A timeout must not revoke a verified domain."""
    with pytest.raises(DomainVerificationUnavailable):
        is_domain_verified("acme.example", "tok-1", prefix="example", resolver=FakeTxtResolver({}, fail=True))


class _Rdata:
    """A TXT rdata stand-in carrying its character strings."""

    def __init__(self, *strings: bytes) -> None:
        """Hold the strings as dnspython does."""
        self.strings = strings


def test_the_dnspython_resolver_joins_strings_and_maps_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    """Split strings are joined; no such name is empty; a timeout is unavailable."""
    import dns.exception
    import dns.resolver

    outcome: dict[str, Any] = {"answer": [_Rdata(b"example-veri", b"fication=tok-1")]}

    def fake_resolve(self: Any, name: str, rdtype: str, lifetime: float = 0) -> Any:
        """Answer or raise as the test dictates."""
        if "raise" in outcome:
            raise outcome["raise"]
        return outcome["answer"]

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", fake_resolve)
    resolver = DnsPythonTxtResolver(nameservers=["192.0.2.53"])
    assert resolver.txt_records("acme.example") == ["example-verification=tok-1"]

    outcome["raise"] = dns.resolver.NXDOMAIN()  # type: ignore[no-untyped-call]
    assert resolver.txt_records("acme.example") == []

    outcome["raise"] = dns.exception.Timeout()  # type: ignore[no-untyped-call]
    with pytest.raises(DomainVerificationUnavailable):
        resolver.txt_records("acme.example")


def test_importing_identity_pulls_in_no_sso_dependency() -> None:
    """CarModPicker and Portfolio install no `sso` extra, so nothing may import it eagerly."""
    import subprocess
    import sys

    script = "import sys, webbpulse.identity; print(sorted({'dns', 'httpx', 'jwt'} & set(sys.modules)))"
    output = subprocess.run([sys.executable, "-c", script], check=True, capture_output=True, text=True).stdout
    assert "dns" not in output
