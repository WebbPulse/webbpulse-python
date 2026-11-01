"""Tests for OAuth sign-in, account linking, and the oauth-states and oauth-links tables."""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

import pytest

from webbpulse.identity import (
    OAUTH_APPLE_NOTIFICATIONS_PATH,
    OAUTH_LINK_USER_INDEX,
    OAUTH_LINKS_TABLE,
    OAUTH_STATE_TTL_SECONDS,
    OAUTH_STATES_TABLE,
    PROVIDERS,
    AuthenticationRefused,
    BaseIdentityHooks,
    CredentialRecord,
    DynamoOAuthLinkStore,
    DynamoOAuthStateStore,
    HttpResponse,
    IdentitySettings,
    IdentityStores,
    InMemoryCredentialStore,
    InMemoryIdentityTokenStore,
    InMemoryOAuthLinkStore,
    InMemoryOAuthStateStore,
    InMemoryPasskeyStore,
    InMemoryRecoveryCodeStore,
    InMemoryRefreshTokenStore,
    InMemoryTotpFactorStore,
    OAuthIdentity,
    OAuthRejected,
    OAuthService,
    OAuthStateRecord,
    PasskeyRecord,
    ProviderAccountEvent,
    ProviderTokens,
    RefreshTokenRecord,
    TokenService,
    build_identity_router,
    identity_prefix,
    new_pkce_verifier,
    pkce_challenge,
    provider_account_key,
)
from webbpulse.identity.flows import PASSWORD_CREDENTIAL_TYPE, IdentityFlows, MfaChallengeRequired
from webbpulse.identity.oauth import (
    AMR_OAUTH,
    APPLE_CLIENT_SECRET_TTL_SECONDS,
    APPLE_ISSUER,
    APPLE_PROVIDER,
    GITHUB_PROVIDER,
    GOOGLE_PROVIDER,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from fastapi import FastAPI
from fastapi.testclient import TestClient

KEY_A = "arn:aws:kms:us-west-2:111122223333:key/aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa"
DATA_KEY = "arn:aws:kms:us-west-2:111122223333:key/dddddddd-4444-4444-4444-dddddddddddd"
ISSUER = "https://api.staging.example.com/api/auth"
AUDIENCE = "webbpulse-staging"
FRONTEND = "https://staging.example.com"

GOOGLE_CLIENT_ID = "1234567890-abcdefg.apps.googleusercontent.com"
GITHUB_CLIENT_ID = "Iv1.0123456789abcdef"
APPLE_CLIENT_ID = "com.example.web"
APPLE_TEAM_ID = "TEAM123456"
APPLE_KEY_ID = "KEY1234567"
APPLE_SUB = "001234.abcdef0123456789.0123"
APPLE_RELAY_EMAIL = "abc123@privaterelay.appleid.com"
GOOGLE_SECRET = "google-client-secret-value"
GITHUB_SECRET = "github-client-secret-value"

EMAIL = "person@example.com"
GOOGLE_SUB = "115538274652819374652"
GITHUB_SUB = "8675309"


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
        """Envelope encryption, for the MFA path an OAuth login has to honour."""
        import secrets

        plaintext = secrets.token_bytes(NumberOfBytes)
        blob = base64.b64encode(plaintext) + b"|" + _context_bytes(EncryptionContext)
        return {"KeyId": KeyId, "Plaintext": plaintext, "CiphertextBlob": blob}

    def decrypt(self, *, CiphertextBlob: bytes, EncryptionContext: Mapping[str, str]) -> dict[str, Any]:
        """Unwrap a data key blob, failing when the encryption context does not match."""
        try:
            encoded, context = CiphertextBlob.split(b"|", 1)
        except ValueError as exc:
            raise RuntimeError("InvalidCiphertextException") from exc
        if context != _context_bytes(EncryptionContext):
            raise RuntimeError("InvalidCiphertextException")
        return {"KeyId": DATA_KEY, "Plaintext": base64.b64decode(encoded)}


def _context_bytes(context: Mapping[str, str]) -> bytes:
    """A stable byte encoding of an encryption context, for blob comparison."""
    return repr(sorted(context.items())).encode("utf-8")


def _b64url(raw: bytes) -> str:
    """Base64url encode bytes without padding."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class FakeProvider:
    """An `httpx.MockTransport` standing in for Google and GitHub."""

    def __init__(self, key: rsa.RSAPrivateKey) -> None:
        """Start with the default Google and GitHub answers and no recorded requests."""
        self.key = key
        self.requests: list[httpx.Request] = []
        self.token_status = 200
        self.token_error = ""
        self.id_token_override: str | None = None
        self.claims_override: dict[str, Any] = {}
        self.github_user: dict[str, Any] = {"id": int(GITHUB_SUB), "login": "octocat"}
        self.github_emails: Any = [
            {"email": EMAIL, "primary": True, "verified": True},
        ]
        self.github_emails_status = 200
        self.nonce_to_echo = ""
        self.apple_claims: dict[str, Any] = {}
        self.apple_refresh_token = ""
        self.apple_revoke_status = 200
        self.apple_revocations: list[dict[str, str]] = []
        self.jwks_status = 200

    def jwks(self) -> dict[str, Any]:
        """The JWKS document serving this fake's public signing key."""
        numbers = self.key.public_key().public_numbers()

        def to_b64(value: int) -> str:
            """Base64url encode an RSA key parameter."""
            length = (value.bit_length() + 7) // 8
            return _b64url(value.to_bytes(length, "big"))

        return {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "test-key",
                    "use": "sig",
                    "alg": "RS256",
                    "n": to_b64(numbers.n),
                    "e": to_b64(numbers.e),
                }
            ]
        }

    def id_token(self, *, nonce: str, **overrides: Any) -> str:
        """A genuinely signed Google ID token."""
        import jwt

        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": "https://accounts.google.com",
            "aud": GOOGLE_CLIENT_ID,
            "sub": GOOGLE_SUB,
            "email": EMAIL,
            "email_verified": True,
            "name": "A Person",
            "iat": now,
            "exp": now + 3600,
            "nonce": nonce,
        }
        claims.update(self.claims_override)
        claims.update(overrides)
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "test-key"})

    def apple_id_token(self) -> str:
        """A genuinely signed Apple ID token, with Apple's string booleans and no name."""
        import jwt

        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": APPLE_ISSUER,
            "aud": APPLE_CLIENT_ID,
            "sub": APPLE_SUB,
            "email": APPLE_RELAY_EMAIL,
            "email_verified": "true",
            "is_private_email": "true",
            "iat": now,
            "exp": now + 3600,
            "nonce": self.nonce_to_echo,
        }
        claims.update(self.apple_claims)
        return jwt.encode(
            {key: value for key, value in claims.items() if value is not None},
            self.key,
            algorithm="RS256",
            headers={"kid": "test-key"},
        )

    def handler(self, request: httpx.Request) -> httpx.Response:
        """Answer a provider request by URL, recording it first."""
        self.requests.append(request)
        url = str(request.url)

        if url in (PROVIDERS[GOOGLE_PROVIDER].jwks_url, PROVIDERS[APPLE_PROVIDER].jwks_url):
            return httpx.Response(self.jwks_status, json=self.jwks())

        if url == PROVIDERS[APPLE_PROVIDER].token_url:
            body = {"access_token": "apple-access", "id_token": self.apple_id_token()}
            if self.apple_refresh_token:
                body["refresh_token"] = self.apple_refresh_token
            return httpx.Response(200, json=body)

        if url == PROVIDERS[APPLE_PROVIDER].revoke_url:
            from urllib.parse import parse_qsl

            self.apple_revocations.append(dict(parse_qsl(request.content.decode())))
            return httpx.Response(self.apple_revoke_status, json={"error": "invalid_client"})

        if url == PROVIDERS[GOOGLE_PROVIDER].token_url:
            if self.token_error:
                return httpx.Response(self.token_status, json={"error": self.token_error})
            token = (
                self.id_token_override
                if self.id_token_override is not None
                else self.id_token(nonce=self.nonce_to_echo)
            )
            return httpx.Response(
                self.token_status,
                json={"access_token": "google-access", "id_token": token, "token_type": "Bearer"},
            )

        if url == PROVIDERS[GITHUB_PROVIDER].token_url:
            if self.token_error:
                return httpx.Response(self.token_status, json={"error": self.token_error})
            return httpx.Response(self.token_status, json={"access_token": "gho_test", "token_type": "bearer"})

        if url == PROVIDERS[GITHUB_PROVIDER].userinfo_url:
            return httpx.Response(200, json=self.github_user)

        if url == PROVIDERS[GITHUB_PROVIDER].emails_url:
            return httpx.Response(self.github_emails_status, json=self.github_emails)

        return httpx.Response(404, json={"error": "unexpected_url", "url": url})

    def client(self) -> Any:
        """An HTTP client wired to this fake's mock transport."""
        from webbpulse.identity.oauth import HttpxClient

        return HttpxClient(client=httpx.Client(transport=httpx.MockTransport(self.handler)))


def _parse_form(request: httpx.Request) -> dict[str, str]:
    """The form-encoded body of a request, as a dict."""
    from urllib.parse import parse_qsl

    return dict(parse_qsl(request.content.decode()))


@pytest.fixture(autouse=True)
def cheap_bcrypt(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Pin bcrypt to its minimum cost for the whole module."""
    import webbpulse.security as security

    real_hash = security.hash_password
    real_needs = security.needs_rehash

    def cheap(password: str, *, rounds: int = 4) -> str:
        """Hash a password at the minimum bcrypt cost."""
        return real_hash(password, rounds=rounds)

    def needs(hashed: str, *, rounds: int = 4) -> bool:
        """Report whether a hash needs rehashing at the minimum bcrypt cost."""
        return real_needs(hashed, rounds=rounds)

    monkeypatch.setattr(security, "hash_password", cheap)
    monkeypatch.setattr(security, "needs_rehash", needs)
    import webbpulse.identity.passwords as passwords

    monkeypatch.setattr(passwords, "_DUMMY_HASH", None)
    yield


@pytest.fixture(scope="module")
def module_key() -> rsa.RSAPrivateKey:
    """One 2048-bit key for the module's own token signing."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def provider_key() -> rsa.RSAPrivateKey:
    """A second key, standing in for Google's signing key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def kms(module_key: rsa.RSAPrivateKey) -> FakeKms:
    """A KMS fake holding the module signing key."""
    return FakeKms({KEY_A: module_key})


@pytest.fixture
def provider(provider_key: rsa.RSAPrivateKey) -> FakeProvider:
    """A provider fake signing with the separate provider key."""
    return FakeProvider(provider_key)


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
        "google_client_id": GOOGLE_CLIENT_ID,
        "github_client_id": GITHUB_CLIENT_ID,
    }
    base.update(overrides)
    return IdentitySettings(**base)


class FakeHooks(BaseIdentityHooks):
    """A product's identity policy, in memory."""

    def __init__(self, *, refuse: str = "") -> None:
        """Start with no users, no recorded hook calls and no extra sign-in methods."""
        self.users: dict[str, dict[str, Any]] = {}
        self.by_email: dict[str, str] = {}
        self.refuse = refuse
        self.calls: list[str] = []
        self.created_via: list[str] = []
        self.extra_sign_in_methods = False
        self._next = 1

    def add(self, email: str, *, user_id: str = "", **attributes: Any) -> dict[str, Any]:
        """Add a user, allocating an id when the caller gives none."""
        identifier = user_id or f"user-{self._next:04d}"
        self._next += 1
        user = {"id": identifier, "email": email, **attributes}
        self.users[identifier] = user
        self.by_email[email.lower()] = identifier
        return user

    def load_user_by_id(self, user_id: str) -> Mapping[str, Any] | None:
        """Return the user with this id, or None."""
        self.calls.append("load_user_by_id")
        return self.users.get(user_id)

    def load_user_by_email(self, email: str) -> Mapping[str, Any] | None:
        """Return the user with this email, matched case insensitively, or None."""
        self.calls.append("load_user_by_email")
        identifier = self.by_email.get(email.lower())
        return self.users.get(identifier) if identifier else None

    def may_authenticate(self, user: Mapping[str, Any]) -> None:
        """Refuse authentication when this fake is configured to refuse."""
        self.calls.append("may_authenticate")
        if self.refuse:
            raise AuthenticationRefused(self.refuse, error_code="ACCOUNT_DISABLED")

    def claims_for(self, user: Mapping[str, Any]) -> Mapping[str, Any]:
        """Return hook claims that try to forge `amr` and `auth_time`."""
        return {"amr": ["forged"], "auth_time": 1}

    def create_user(self, *, email: str, attributes: Mapping[str, Any]) -> Mapping[str, Any]:
        """Create and store a user from the registration attributes."""
        self.calls.append("create_user")
        return self.add(email, **dict(attributes))

    def on_user_created(self, user: Mapping[str, Any], via: str) -> None:
        """Record which provider a new user was created through."""
        self.created_via.append(via)

    def has_other_sign_in_method(self, user_id: str) -> bool:
        """Report whether this fake was told the user holds another sign-in method."""
        self.calls.append("has_other_sign_in_method")
        return self.extra_sign_in_methods


@pytest.fixture
def hooks() -> FakeHooks:
    """A fresh in-memory hooks product."""
    return FakeHooks()


@pytest.fixture
def stores() -> IdentityStores:
    """In-memory stores, including both OAuth tables."""
    return IdentityStores(
        credentials=InMemoryCredentialStore(),
        refresh_tokens=InMemoryRefreshTokenStore(),
        oauth_states=InMemoryOAuthStateStore(),
        oauth_links=InMemoryOAuthLinkStore(),
    )


@pytest.fixture
def oauth(hooks: FakeHooks, stores: IdentityStores, provider: FakeProvider) -> OAuthService:
    """An `OAuthService` wired to the in-memory stores, both client secrets and the provider fake."""
    return OAuthService(
        make_settings(),
        hooks,
        states=stores.require_oauth_states(),
        links=stores.require_oauth_links(),
        credentials=stores.credentials,
        client_secrets={GOOGLE_PROVIDER: GOOGLE_SECRET, GITHUB_PROVIDER: GITHUB_SECRET},
        http_client=provider.client(),
    )


def run_google_callback(
    oauth: OAuthService, provider: FakeProvider, *, mode: str = "login", user_id: str = ""
) -> OAuthIdentity:
    """Drive a Google start-then-callback and return the identity it resolved."""
    authorization = oauth.start(GOOGLE_PROVIDER, mode=mode, user_id=user_id)  # type: ignore[arg-type]
    record = oauth.consume_state(authorization.state)
    provider.nonce_to_echo = record.nonce
    return oauth.identity_from_callback(GOOGLE_PROVIDER, code="auth-code", state_record=record)


def test_pkce_verifier_meets_the_rfc_length_and_alphabet() -> None:
    """RFC 7636 requires 43 to 128 characters from the unreserved set."""
    verifier = new_pkce_verifier()
    assert 43 <= len(verifier) <= 128
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
    assert set(verifier) <= allowed


def test_pkce_challenge_matches_the_rfc_7636_worked_example() -> None:
    """Appendix B of RFC 7636 publishes one verifier and its S256 challenge."""
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert pkce_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_pkce_verifiers_are_unique_per_start() -> None:
    """Two verifiers generated in a row differ."""
    assert new_pkce_verifier() != new_pkce_verifier()


def test_google_offers_pkce_and_an_id_token_and_github_offers_neither() -> None:
    """The per-provider flags are the whole reason the provider table exists."""
    google = PROVIDERS[GOOGLE_PROVIDER]
    github = PROVIDERS[GITHUB_PROVIDER]
    assert google.supports_pkce and google.returns_id_token
    assert not github.supports_pkce and not github.returns_id_token
    assert github.emails_url, "GitHub needs the separate verified-addresses endpoint"


def test_github_scope_asks_only_for_what_the_flow_reads() -> None:
    """`user:email` and not `user`: the broader scope grants profile writes nothing uses."""
    scope = PROVIDERS[GITHUB_PROVIDER].scope
    assert "user:email" in scope
    assert "repo" not in scope
    assert "delete" not in scope


def test_provider_account_key_namespaces_the_subject_by_provider() -> None:
    """A bare subject would let a GitHub id collide with a Google one and inherit its user."""
    assert provider_account_key("google", "123") == "google#123"
    assert provider_account_key("github", "123") != provider_account_key("google", "123")


def test_start_builds_a_google_url_with_pkce_and_a_nonce(oauth: OAuthService) -> None:
    """The Google authorization URL carries the client id, S256 challenge, state, nonce and openid scope."""
    from urllib.parse import parse_qs, urlsplit

    authorization = oauth.start(GOOGLE_PROVIDER)
    parts = urlsplit(authorization.authorization_url)
    params = {key: value[0] for key, value in parse_qs(parts.query).items()}

    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == PROVIDERS[GOOGLE_PROVIDER].authorize_url
    assert params["client_id"] == GOOGLE_CLIENT_ID
    assert params["response_type"] == "code"
    assert params["code_challenge_method"] == "S256"
    assert params["state"] == authorization.state
    assert params["nonce"]
    assert "openid" in params["scope"]


def test_start_sends_the_challenge_and_never_the_verifier(oauth: OAuthService) -> None:
    """The verifier is the one value that must not reach the browser."""
    from urllib.parse import parse_qs, urlsplit

    authorization = oauth.start(GOOGLE_PROVIDER)
    params = {k: v[0] for k, v in parse_qs(urlsplit(authorization.authorization_url).query).items()}
    record = oauth.consume_state(authorization.state)

    assert record.pkce_verifier
    assert record.pkce_verifier not in authorization.authorization_url
    assert params["code_challenge"] == pkce_challenge(record.pkce_verifier)


def test_start_omits_pkce_and_nonce_for_github(oauth: OAuthService) -> None:
    """A GitHub start sends no challenge and no nonce, and stores neither."""
    authorization = oauth.start(GITHUB_PROVIDER)
    assert "code_challenge" not in authorization.authorization_url
    assert "nonce" not in authorization.authorization_url
    record = oauth.consume_state(authorization.state)
    assert record.pkce_verifier == ""
    assert record.nonce == ""


def test_start_writes_a_state_row_with_the_ten_minute_ttl(oauth: OAuthService) -> None:
    """The state row expires `OAUTH_STATE_TTL_SECONDS` after it is written."""
    before = int(time.time())
    authorization = oauth.start(GOOGLE_PROVIDER)
    record = oauth.consume_state(authorization.state)
    assert before + OAUTH_STATE_TTL_SECONDS - 5 <= record.expires_at <= before + OAUTH_STATE_TTL_SECONDS + 5


def test_two_starts_produce_different_states(oauth: OAuthService) -> None:
    """Each start mints a distinct state value."""
    assert oauth.start(GOOGLE_PROVIDER).state != oauth.start(GOOGLE_PROVIDER).state


def test_a_link_start_requires_a_user_id(oauth: OAuthService) -> None:
    """A `link` with no authenticated subject has no account to attach to."""
    with pytest.raises(OAuthRejected) as excinfo:
        oauth.start(GOOGLE_PROVIDER, mode="link")
    assert excinfo.value.status_code == 401


def test_a_login_state_never_carries_a_user_id(oauth: OAuthService) -> None:
    """The property that stops a login callback being replayed as a link."""
    authorization = oauth.start(GOOGLE_PROVIDER, mode="login", user_id="user-0001")
    assert oauth.consume_state(authorization.state).user_id == ""


def test_an_unconfigured_provider_is_not_available(hooks: FakeHooks, stores: IdentityStores) -> None:
    """A provider listed but given no client id must not redirect to a broken consent screen."""
    service = OAuthService(
        make_settings(github_client_id=""),
        hooks,
        states=stores.require_oauth_states(),
        links=stores.require_oauth_links(),
    )
    assert service.enabled_providers() == [GOOGLE_PROVIDER]
    with pytest.raises(OAuthRejected) as excinfo:
        service.start(GITHUB_PROVIDER)
    assert excinfo.value.status_code == 404


def test_an_unknown_provider_is_refused(oauth: OAuthService) -> None:
    """A provider name that is not in the table is refused."""
    with pytest.raises(OAuthRejected):
        oauth.start("facebook")


def test_a_redirect_uri_outside_the_allow_list_is_refused(hooks: FakeHooks, stores: IdentityStores) -> None:
    """The parameter a provider sends a live authorization code to. It is not a suggestion."""
    settings = make_settings(oauth_redirect_uris=[f"{ISSUER}/oauth/callback"])
    service = OAuthService(
        settings,
        hooks,
        states=stores.require_oauth_states(),
        links=stores.require_oauth_links(),
        client_secrets={GOOGLE_PROVIDER: GOOGLE_SECRET},
    )
    with pytest.raises(OAuthRejected) as excinfo:
        service.start(GOOGLE_PROVIDER, redirect_uri="https://attacker.test/steal")
    assert excinfo.value.error_code == "OAUTH_REDIRECT_NOT_ALLOWED"


def test_the_allow_list_is_exact_and_not_a_prefix(hooks: FakeHooks, stores: IdentityStores) -> None:
    """`https://app.example.com.attacker.test` is a domain an attacker can register today."""
    allowed = "https://app.example.com/oauth/callback"
    settings = make_settings(oauth_redirect_uris=[allowed])
    service = OAuthService(
        settings,
        hooks,
        states=stores.require_oauth_states(),
        links=stores.require_oauth_links(),
        client_secrets={GOOGLE_PROVIDER: GOOGLE_SECRET},
    )
    with pytest.raises(OAuthRejected):
        service.start(GOOGLE_PROVIDER, redirect_uri="https://app.example.com.attacker.test/cb")
    assert service.start(GOOGLE_PROVIDER, redirect_uri=allowed).authorization_url


def test_an_allowed_redirect_uri_is_stored_and_replayed_on_the_exchange(
    oauth: OAuthService, provider: FakeProvider
) -> None:
    """The provider refuses an exchange whose `redirect_uri` differs by a byte."""
    run_google_callback(oauth, provider)
    exchange = next(
        request for request in provider.requests if str(request.url) == PROVIDERS[GOOGLE_PROVIDER].token_url
    )
    assert _parse_form(exchange)["redirect_uri"] == f"{ISSUER}/oauth/callback"


def test_return_to_is_confined_to_the_frontend(oauth: OAuthService) -> None:
    """An echoed `return_to` is an open redirect that phishes through our own domain."""
    authorization = oauth.start(GOOGLE_PROVIDER, return_to="https://attacker.test/phish")
    assert oauth.consume_state(authorization.state).return_to == FRONTEND


def test_a_scheme_relative_return_to_is_refused(oauth: OAuthService) -> None:
    """`//attacker.test` is an absolute URL wearing a path's clothes."""
    authorization = oauth.start(GOOGLE_PROVIDER, return_to="//attacker.test/phish")
    assert oauth.consume_state(authorization.state).return_to == FRONTEND


def test_a_relative_return_to_is_resolved_against_the_frontend(oauth: OAuthService) -> None:
    """A path-only `return_to` is resolved against the frontend base URL."""
    authorization = oauth.start(GOOGLE_PROVIDER, return_to="/settings/security")
    assert oauth.consume_state(authorization.state).return_to == f"{FRONTEND}/settings/security"


def test_a_state_can_be_spent_only_once(oauth: OAuthService) -> None:
    """The replay defence. A happy-path-only test passes without one."""
    authorization = oauth.start(GOOGLE_PROVIDER)
    assert oauth.consume_state(authorization.state).state == authorization.state
    with pytest.raises(OAuthRejected) as excinfo:
        oauth.consume_state(authorization.state)
    assert excinfo.value.error_code == "OAUTH_STATE_INVALID"


def test_an_unknown_state_is_refused(oauth: OAuthService) -> None:
    """A state value that was never issued is refused."""
    with pytest.raises(OAuthRejected):
        oauth.consume_state("not-a-real-state")


def test_an_empty_state_is_refused(oauth: OAuthService) -> None:
    """An empty state value is refused."""
    with pytest.raises(OAuthRejected):
        oauth.consume_state("")


def test_an_expired_state_is_refused_even_though_dynamo_ttl_is_lazy() -> None:
    """TTL is storage reclamation, never access control: an expired row is readable for days."""
    states = InMemoryOAuthStateStore()
    states.put(
        OAuthStateRecord(
            state="stale",
            provider=GOOGLE_PROVIDER,
            mode="login",
            created_at="2020-01-01T00:00:00Z",
            expires_at=int(time.time()) - 1,
        )
    )
    assert states.consume("stale") is None


def test_a_state_from_one_provider_is_refused_at_another(oauth: OAuthService) -> None:
    """A Google state presented as a GitHub state is refused."""
    authorization = oauth.start(GOOGLE_PROVIDER)
    with pytest.raises(OAuthRejected):
        oauth.consume_state(authorization.state, provider=GITHUB_PROVIDER)


def test_every_state_failure_answers_identically(oauth: OAuthService) -> None:
    """Distinguishing unknown from expired from spent confirms a guess found a real row."""
    authorization = oauth.start(GOOGLE_PROVIDER)
    oauth.consume_state(authorization.state)

    codes = set()
    for state in (authorization.state, "never-existed", ""):
        with pytest.raises(OAuthRejected) as excinfo:
            oauth.consume_state(state)
        codes.add((excinfo.value.error_code, excinfo.value.message))
    assert len(codes) == 1


def test_a_google_callback_yields_a_verified_identity(oauth: OAuthService, provider: FakeProvider) -> None:
    """A completed Google callback resolves the provider, subject, email and verification state."""
    identity = run_google_callback(oauth, provider)
    assert identity.provider == GOOGLE_PROVIDER
    assert identity.subject == GOOGLE_SUB
    assert identity.email == EMAIL
    assert identity.email_verified is True


def test_the_exchange_sends_the_pkce_verifier_and_the_client_secret(
    oauth: OAuthService, provider: FakeProvider
) -> None:
    """The token exchange form carries the grant type, code, client secret and code verifier."""
    run_google_callback(oauth, provider)
    form = _parse_form(next(r for r in provider.requests if str(r.url) == PROVIDERS[GOOGLE_PROVIDER].token_url))
    assert form["grant_type"] == "authorization_code"
    assert form["code"] == "auth-code"
    assert form["client_secret"] == GOOGLE_SECRET
    assert form["code_verifier"]
    assert pkce_challenge(form["code_verifier"])


def test_an_id_token_signed_by_the_wrong_key_is_refused(
    oauth: OAuthService, provider: FakeProvider, module_key: rsa.RSAPrivateKey
) -> None:
    """The single most important assertion in this file."""
    import jwt

    authorization = oauth.start(GOOGLE_PROVIDER)
    record = oauth.consume_state(authorization.state)
    now = int(time.time())
    provider.id_token_override = jwt.encode(
        {
            "iss": "https://accounts.google.com",
            "aud": GOOGLE_CLIENT_ID,
            "sub": "attacker-subject",
            "email": "victim@example.com",
            "email_verified": True,
            "iat": now,
            "exp": now + 3600,
            "nonce": record.nonce,
        },
        module_key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )
    with pytest.raises(OAuthRejected) as excinfo:
        oauth.identity_from_callback(GOOGLE_PROVIDER, code="c", state_record=record)
    assert excinfo.value.error_code == "OAUTH_ID_TOKEN_INVALID"


def test_an_id_token_for_another_audience_is_refused(oauth: OAuthService, provider: FakeProvider) -> None:
    """A token minted for a different client id is a token from a different application."""
    authorization = oauth.start(GOOGLE_PROVIDER)
    record = oauth.consume_state(authorization.state)
    provider.id_token_override = provider.id_token(nonce=record.nonce, aud="someone-else.apps")
    with pytest.raises(OAuthRejected):
        oauth.identity_from_callback(GOOGLE_PROVIDER, code="c", state_record=record)


def test_an_id_token_from_another_issuer_is_refused(oauth: OAuthService, provider: FakeProvider) -> None:
    """An ID token whose `iss` is not Google is refused."""
    authorization = oauth.start(GOOGLE_PROVIDER)
    record = oauth.consume_state(authorization.state)
    provider.id_token_override = provider.id_token(nonce=record.nonce, iss="https://evil.test")
    with pytest.raises(OAuthRejected):
        oauth.identity_from_callback(GOOGLE_PROVIDER, code="c", state_record=record)


def test_an_expired_id_token_is_refused(oauth: OAuthService, provider: FakeProvider) -> None:
    """An ID token whose `exp` has passed is refused."""
    authorization = oauth.start(GOOGLE_PROVIDER)
    record = oauth.consume_state(authorization.state)
    now = int(time.time())
    provider.id_token_override = provider.id_token(nonce=record.nonce, iat=now - 7200, exp=now - 3600)
    with pytest.raises(OAuthRejected):
        oauth.identity_from_callback(GOOGLE_PROVIDER, code="c", state_record=record)


def test_a_replayed_id_token_with_the_wrong_nonce_is_refused(oauth: OAuthService, provider: FakeProvider) -> None:
    """The attack `nonce` exists to stop: a valid ID token lifted from another session."""
    authorization = oauth.start(GOOGLE_PROVIDER)
    record = oauth.consume_state(authorization.state)
    provider.id_token_override = provider.id_token(nonce="a-nonce-from-another-session")
    with pytest.raises(OAuthRejected) as excinfo:
        oauth.identity_from_callback(GOOGLE_PROVIDER, code="c", state_record=record)
    assert excinfo.value.error_code == "OAUTH_NONCE_MISMATCH"


def test_a_failed_token_exchange_does_not_leak_the_provider_message(
    oauth: OAuthService, provider: FakeProvider
) -> None:
    """The provider's `error_description` is attacker-influenced through `code`."""
    authorization = oauth.start(GOOGLE_PROVIDER)
    record = oauth.consume_state(authorization.state)
    provider.token_error = "invalid_grant<script>alert(1)</script>"
    provider.token_status = 400
    with pytest.raises(OAuthRejected) as excinfo:
        oauth.identity_from_callback(GOOGLE_PROVIDER, code="c", state_record=record)
    assert excinfo.value.error_code == "OAUTH_EXCHANGE_FAILED"
    assert "script" not in excinfo.value.message


def test_a_missing_client_secret_is_a_503_that_names_no_configuration(
    hooks: FakeHooks, stores: IdentityStores, provider: FakeProvider
) -> None:
    """The operator gets the detail in a log line; an anonymous caller gets none."""
    service = OAuthService(
        make_settings(),
        hooks,
        states=stores.require_oauth_states(),
        links=stores.require_oauth_links(),
        client_secrets={},
        http_client=provider.client(),
    )
    with pytest.raises(OAuthRejected) as excinfo:
        service.start(GOOGLE_PROVIDER)
    assert excinfo.value.status_code == 503
    assert excinfo.value.error_code == "OAUTH_PROVIDER_UNAVAILABLE"
    assert "secret" not in excinfo.value.message.lower()

    usable = OAuthService(
        make_settings(),
        hooks,
        states=stores.require_oauth_states(),
        links=stores.require_oauth_links(),
        client_secrets={GOOGLE_PROVIDER: GOOGLE_SECRET},
        http_client=provider.client(),
    )
    record = usable.consume_state(usable.start(GOOGLE_PROVIDER).state)
    with pytest.raises(OAuthRejected) as callback_exc:
        service.identity_from_callback(GOOGLE_PROVIDER, code="c", state_record=record)
    assert callback_exc.value.status_code == 503


def test_the_client_secret_never_appears_in_a_log_record(
    oauth: OAuthService, provider: FakeProvider, caplog: pytest.LogCaptureFixture
) -> None:
    """`never logged` is a requirement, so it gets an assertion rather than a convention."""
    import logging

    caplog.set_level(logging.DEBUG, logger="webbpulse.identity.oauth")
    provider.token_error = "invalid_grant"
    provider.token_status = 400
    authorization = oauth.start(GOOGLE_PROVIDER)
    record = oauth.consume_state(authorization.state)
    with pytest.raises(OAuthRejected):
        oauth.identity_from_callback(GOOGLE_PROVIDER, code="c", state_record=record)

    rendered = " ".join(record_.getMessage() + str(record_.__dict__) for record_ in caplog.records)
    assert GOOGLE_SECRET not in rendered
    assert GITHUB_SECRET not in rendered


def test_github_identity_comes_from_user_and_user_emails(oauth: OAuthService, provider: FakeProvider) -> None:
    """A GitHub callback calls both the userinfo and the emails endpoints to build the identity."""
    authorization = oauth.start(GITHUB_PROVIDER)
    record = oauth.consume_state(authorization.state)
    identity = oauth.identity_from_callback(GITHUB_PROVIDER, code="c", state_record=record)

    assert identity.subject == GITHUB_SUB
    assert identity.email == EMAIL
    assert identity.email_verified is True
    called = {str(request.url) for request in provider.requests}
    assert PROVIDERS[GITHUB_PROVIDER].userinfo_url in called
    assert PROVIDERS[GITHUB_PROVIDER].emails_url in called


def test_github_prefers_the_verified_primary_over_an_unverified_one(
    oauth: OAuthService, provider: FakeProvider
) -> None:
    """`/user`'s `email` is the public profile address: user-chosen and never verified."""
    provider.github_user = {
        "id": int(GITHUB_SUB),
        "login": "octocat",
        "email": "vanity@example.com",
    }
    provider.github_emails = [
        {"email": "unverified@example.com", "primary": True, "verified": False},
        {"email": "real@example.com", "primary": False, "verified": True},
    ]
    authorization = oauth.start(GITHUB_PROVIDER)
    record = oauth.consume_state(authorization.state)
    identity = oauth.identity_from_callback(GITHUB_PROVIDER, code="c", state_record=record)

    assert identity.email == "real@example.com"
    assert identity.email_verified is True


def test_github_reports_an_unverified_address_as_unverified(oauth: OAuthService, provider: FakeProvider) -> None:
    """An unverified GitHub primary address is carried through as unverified."""
    provider.github_emails = [{"email": EMAIL, "primary": True, "verified": False}]
    authorization = oauth.start(GITHUB_PROVIDER)
    record = oauth.consume_state(authorization.state)
    identity = oauth.identity_from_callback(GITHUB_PROVIDER, code="c", state_record=record)

    assert identity.email == EMAIL
    assert identity.email_verified is False


def test_a_github_exchange_sends_no_pkce_verifier(oauth: OAuthService, provider: FakeProvider) -> None:
    """The GitHub token exchange form carries no code verifier."""
    authorization = oauth.start(GITHUB_PROVIDER)
    record = oauth.consume_state(authorization.state)
    oauth.identity_from_callback(GITHUB_PROVIDER, code="c", state_record=record)
    form = _parse_form(next(r for r in provider.requests if str(r.url) == PROVIDERS[GITHUB_PROVIDER].token_url))
    assert "code_verifier" not in form


def test_the_github_exchange_asks_for_json(oauth: OAuthService, provider: FakeProvider) -> None:
    """GitHub answers form-encoded unless asked, and a form body parses as no body at all."""
    authorization = oauth.start(GITHUB_PROVIDER)
    record = oauth.consume_state(authorization.state)
    oauth.identity_from_callback(GITHUB_PROVIDER, code="c", state_record=record)
    request = next(r for r in provider.requests if str(r.url) == PROVIDERS[GITHUB_PROVIDER].token_url)
    assert request.headers["accept"] == "application/json"


def test_a_known_link_signs_the_user_in(oauth: OAuthService, provider: FakeProvider, hooks: FakeHooks) -> None:
    """An identity with an existing link resolves to that user with the `linked` outcome."""
    user = hooks.add(EMAIL, email_verified=True)
    identity = run_google_callback(oauth, provider)
    oauth.link(identity, user_id=str(user["id"]))

    resolved, outcome = oauth.resolve_login(identity)
    assert outcome == "linked"
    assert resolved["id"] == user["id"]


def test_both_sides_verified_auto_links(oauth: OAuthService, provider: FakeProvider, hooks: FakeHooks) -> None:
    """The locked decision's allowed case, and the only one."""
    user = hooks.add(EMAIL, email_verified=True)
    identity = run_google_callback(oauth, provider)

    resolved, outcome = oauth.resolve_login(identity)
    assert outcome == "auto_linked"
    assert resolved["id"] == user["id"]
    assert [record.provider for record in oauth.list_links(str(user["id"]))] == [GOOGLE_PROVIDER]


def test_an_unverified_provider_email_never_auto_links(
    oauth: OAuthService, provider: FakeProvider, hooks: FakeHooks
) -> None:
    """The provider is asserting an address the user typed and nobody checked."""
    user = hooks.add(EMAIL, email_verified=True)
    provider.claims_override = {"email_verified": False}
    identity = run_google_callback(oauth, provider)

    with pytest.raises(OAuthRejected) as excinfo:
        oauth.resolve_login(identity)
    assert excinfo.value.error_code == "OAUTH_EMAIL_UNVERIFIED"
    assert oauth.list_links(str(user["id"])) == []


def test_an_unverified_local_email_never_auto_links(
    oauth: OAuthService, provider: FakeProvider, hooks: FakeHooks
) -> None:
    """Takeover in the other direction, and the half that is easy to forget."""
    user = hooks.add(EMAIL, email_verified=False)
    identity = run_google_callback(oauth, provider)

    with pytest.raises(OAuthRejected) as excinfo:
        oauth.resolve_login(identity)
    assert excinfo.value.error_code == "OAUTH_EMAIL_UNVERIFIED"
    assert oauth.list_links(str(user["id"])) == []


def test_a_refused_auto_link_says_the_same_thing_either_way(
    oauth: OAuthService, provider: FakeProvider, hooks: FakeHooks
) -> None:
    """Naming which side was unverified enumerates accounts and their verification state."""
    hooks.add(EMAIL, email_verified=False)
    identity_a = run_google_callback(oauth, provider)
    with pytest.raises(OAuthRejected) as first:
        oauth.resolve_login(identity_a)

    provider.claims_override = {"email_verified": False}
    identity_b = OAuthIdentity(provider=GOOGLE_PROVIDER, subject="other", email=EMAIL, email_verified=False)
    with pytest.raises(OAuthRejected) as second:
        oauth.resolve_login(identity_b)

    assert first.value.message == second.value.message
    assert first.value.error_code == second.value.error_code


def test_an_unknown_identity_registers_a_new_account(
    oauth: OAuthService, provider: FakeProvider, hooks: FakeHooks
) -> None:
    """An identity with no link and no matching account registers a new user."""
    identity = run_google_callback(oauth, provider)
    user, outcome = oauth.resolve_login(identity)

    assert outcome == "registered"
    assert user["email"] == EMAIL
    assert user["email_verified"] is True
    assert hooks.created_via == [GOOGLE_PROVIDER]


def test_a_registration_carries_the_providers_verification_state(oauth: OAuthService, provider: FakeProvider) -> None:
    """An unverified provider address gives an unverified local account, not a trusted one."""
    provider.claims_override = {"email_verified": False}
    identity = run_google_callback(oauth, provider)
    user, outcome = oauth.resolve_login(identity)

    assert outcome == "registered"
    assert user["email_verified"] is False


def test_registration_can_be_switched_off(hooks: FakeHooks, stores: IdentityStores, provider: FakeProvider) -> None:
    """With registration disabled an unknown identity is refused with REGISTRATION_DISABLED."""
    service = OAuthService(
        make_settings(registration_enabled=False),
        hooks,
        states=stores.require_oauth_states(),
        links=stores.require_oauth_links(),
        client_secrets={GOOGLE_PROVIDER: GOOGLE_SECRET},
        http_client=provider.client(),
    )
    identity = run_google_callback(service, provider)
    with pytest.raises(OAuthRejected) as excinfo:
        service.resolve_login(identity)
    assert excinfo.value.error_code == "REGISTRATION_DISABLED"


def test_a_provider_that_shares_no_email_is_refused(oauth: OAuthService) -> None:
    """An identity with no email is refused with OAUTH_EMAIL_MISSING."""
    identity = OAuthIdentity(provider=GITHUB_PROVIDER, subject=GITHUB_SUB, email="", email_verified=False)
    with pytest.raises(OAuthRejected) as excinfo:
        oauth.resolve_login(identity)
    assert excinfo.value.error_code == "OAUTH_EMAIL_MISSING"


def test_a_link_whose_user_vanished_is_refused_and_cleaned_up(
    oauth: OAuthService, provider: FakeProvider, hooks: FakeHooks
) -> None:
    """Signing somebody in to an account that no longer exists is worse than refusing."""
    user = hooks.add(EMAIL, email_verified=True)
    identity = run_google_callback(oauth, provider)
    oauth.link(identity, user_id=str(user["id"]))
    hooks.users.clear()

    with pytest.raises(OAuthRejected) as excinfo:
        oauth.resolve_login(identity)
    assert excinfo.value.status_code == 401
    assert oauth.list_links(str(user["id"])) == []


def test_link_attaches_to_the_authenticated_account_without_an_email_check(
    oauth: OAuthService, provider: FakeProvider, hooks: FakeHooks
) -> None:
    """The path a refused auto-link sends people to."""
    user = hooks.add("different@example.com", email_verified=False)
    identity = run_google_callback(oauth, provider)

    record = oauth.link(identity, user_id=str(user["id"]))
    assert record.user_id == user["id"]
    assert record.provider_email == EMAIL


def test_linking_an_already_linked_identity_is_refused(
    oauth: OAuthService, provider: FakeProvider, hooks: FakeHooks
) -> None:
    """Linking an identity that is already attached elsewhere is a 409 OAUTH_ALREADY_LINKED."""
    first = hooks.add("first@example.com", email_verified=True)
    second = hooks.add("second@example.com", email_verified=True)
    identity = run_google_callback(oauth, provider)
    oauth.link(identity, user_id=str(first["id"]))

    with pytest.raises(OAuthRejected) as excinfo:
        oauth.link(identity, user_id=str(second["id"]))
    assert excinfo.value.error_code == "OAUTH_ALREADY_LINKED"
    assert excinfo.value.status_code == 409


def test_the_already_linked_refusal_does_not_say_whose_account(
    oauth: OAuthService, provider: FakeProvider, hooks: FakeHooks
) -> None:
    """ "You already linked this" and "somebody else did" are the same sentence on purpose."""
    owner = hooks.add("owner@example.com", email_verified=True)
    other = hooks.add("other@example.com", email_verified=True)
    identity = run_google_callback(oauth, provider)
    oauth.link(identity, user_id=str(owner["id"]))

    with pytest.raises(OAuthRejected) as mine:
        oauth.link(identity, user_id=str(owner["id"]))
    with pytest.raises(OAuthRejected) as theirs:
        oauth.link(identity, user_id=str(other["id"]))

    assert mine.value.message == theirs.value.message
    assert "owner@example.com" not in theirs.value.message


def test_list_links_returns_only_this_users_links(
    oauth: OAuthService, provider: FakeProvider, hooks: FakeHooks
) -> None:
    """Listing links returns this user's links, in provider order, and nobody else's."""
    mine = hooks.add("mine@example.com", email_verified=True)
    theirs = hooks.add("theirs@example.com", email_verified=True)
    oauth.link(OAuthIdentity(GOOGLE_PROVIDER, "sub-a", "a@example.com", True), user_id=str(mine["id"]))
    oauth.link(OAuthIdentity(GITHUB_PROVIDER, "sub-b", "b@example.com", True), user_id=str(mine["id"]))
    oauth.link(OAuthIdentity(GOOGLE_PROVIDER, "sub-c", "c@example.com", True), user_id=str(theirs["id"]))

    assert [r.provider for r in oauth.list_links(str(mine["id"]))] == [
        GITHUB_PROVIDER,
        GOOGLE_PROVIDER,
    ]
    assert len(oauth.list_links(str(theirs["id"]))) == 1


def test_no_provider_tokens_are_stored(oauth: OAuthService, provider: FakeProvider, hooks: FakeHooks) -> None:
    """Google and GitHub stay identity sources, so only Apple's revocable token is ever kept."""
    import dataclasses

    user = hooks.add(EMAIL, email_verified=True)
    identity = run_google_callback(oauth, provider)
    record = oauth.link(identity, user_id=str(user["id"]))

    values = " ".join(str(value) for value in dataclasses.asdict(record).values())
    assert "google-access" not in values
    assert "gho_test" not in values
    fields = {field.name for field in dataclasses.fields(record)}
    assert not {"access_token", "refresh_token"} & fields
    assert record.provider_token is None


def test_unlink_refuses_to_remove_the_only_sign_in_method(
    oauth: OAuthService, provider: FakeProvider, hooks: FakeHooks
) -> None:
    """Permanent lockout: nobody can log in, so nobody can add a method back."""
    user = hooks.add(EMAIL, email_verified=True)
    identity = run_google_callback(oauth, provider)
    oauth.link(identity, user_id=str(user["id"]))

    with pytest.raises(OAuthRejected) as excinfo:
        oauth.unlink(user_id=str(user["id"]), provider=GOOGLE_PROVIDER)
    assert excinfo.value.error_code == "OAUTH_LAST_SIGN_IN_METHOD"
    assert excinfo.value.status_code == 409
    assert len(oauth.list_links(str(user["id"]))) == 1


def test_unlink_allows_it_when_another_link_remains(oauth: OAuthService, hooks: FakeHooks) -> None:
    """Unlinking succeeds while a second provider link remains."""
    user = hooks.add(EMAIL, email_verified=True)
    oauth.link(OAuthIdentity(GOOGLE_PROVIDER, "g", EMAIL, True), user_id=str(user["id"]))
    oauth.link(OAuthIdentity(GITHUB_PROVIDER, "h", EMAIL, True), user_id=str(user["id"]))

    oauth.unlink(user_id=str(user["id"]), provider=GOOGLE_PROVIDER)
    assert [r.provider for r in oauth.list_links(str(user["id"]))] == [GITHUB_PROVIDER]


def test_unlink_allows_it_when_a_password_remains(
    oauth: OAuthService, stores: IdentityStores, hooks: FakeHooks
) -> None:
    """Unlinking succeeds while a password credential remains."""
    user = hooks.add(EMAIL, email_verified=True)
    stores.require_credentials().put(
        CredentialRecord(
            user_id=str(user["id"]),
            credential_type=PASSWORD_CREDENTIAL_TYPE,
            secret="$2b$04$abcdefghijklmnopqrstuv",
        )
    )
    oauth.link(OAuthIdentity(GOOGLE_PROVIDER, "g", EMAIL, True), user_id=str(user["id"]))

    oauth.unlink(user_id=str(user["id"]), provider=GOOGLE_PROVIDER)
    assert oauth.list_links(str(user["id"])) == []


def test_unlink_allows_it_when_the_hook_reports_a_passkey(oauth: OAuthService, hooks: FakeHooks) -> None:
    """Unlink succeeds when `has_other_sign_in_method` reports another credential."""
    user = hooks.add(EMAIL, email_verified=True)
    oauth.link(OAuthIdentity(GOOGLE_PROVIDER, "g", EMAIL, True), user_id=str(user["id"]))
    hooks.extra_sign_in_methods = True

    oauth.unlink(user_id=str(user["id"]), provider=GOOGLE_PROVIDER)
    assert oauth.list_links(str(user["id"])) == []


def test_the_new_hook_defaults_to_false_so_old_hooks_keep_working() -> None:
    """`False` refuses too often; `True` would let a product delete its users' last credential."""

    class PreM6Hooks(BaseIdentityHooks):
        """A hooks class written before M6, which cannot know about the new method."""

    assert PreM6Hooks().has_other_sign_in_method("user-0001") is False


def test_unlinking_a_provider_that_is_not_linked_is_a_404(oauth: OAuthService, hooks: FakeHooks) -> None:
    """Unlinking a provider the user never linked is a 404."""
    user = hooks.add(EMAIL, email_verified=True)
    with pytest.raises(OAuthRejected) as excinfo:
        oauth.unlink(user_id=str(user["id"]), provider=GOOGLE_PROVIDER)
    assert excinfo.value.status_code == 404


def test_unlink_does_not_touch_another_users_link(oauth: OAuthService, hooks: FakeHooks) -> None:
    """Unlinking one user's Google link leaves another user's Google link in place."""
    mine = hooks.add("mine@example.com", email_verified=True)
    theirs = hooks.add("theirs@example.com", email_verified=True)
    oauth.link(OAuthIdentity(GOOGLE_PROVIDER, "g1", "a@example.com", True), user_id=str(mine["id"]))
    oauth.link(OAuthIdentity(GOOGLE_PROVIDER, "g2", "b@example.com", True), user_id=str(theirs["id"]))
    hooks.extra_sign_in_methods = True

    oauth.unlink(user_id=str(mine["id"]), provider=GOOGLE_PROVIDER)
    assert len(oauth.list_links(str(theirs["id"]))) == 1


@pytest.fixture
def flows(hooks: FakeHooks, stores: IdentityStores, kms: FakeKms) -> IdentityFlows:
    """Identity flows wired to the in-memory stores, hooks and KMS fake."""
    settings = make_settings()
    return IdentityFlows(settings, hooks, stores, TokenService(settings, kms), kms_client=kms)


def test_an_oauth_login_issues_the_same_token_pair_a_password_login_does(
    flows: IdentityFlows, hooks: FakeHooks
) -> None:
    """An OAuth login issues an access token, a refresh token, a family id and an expiry."""
    user = hooks.add(EMAIL, email_verified=True)
    result = flows.issue_for_oauth(user, provider=GOOGLE_PROVIDER)

    assert result.access_token
    assert result.refresh_token
    assert result.family_id
    assert result.expires_in > 0


def test_the_access_token_records_the_provider_in_amr(flows: IdentityFlows, hooks: FakeHooks, kms: FakeKms) -> None:
    """A policy that wants "a Google session" cannot express that against a shared value."""
    settings = make_settings()
    tokens = TokenService(settings, kms)
    user = hooks.add(EMAIL, email_verified=True)
    result = flows.issue_for_oauth(user, provider=GOOGLE_PROVIDER)

    claims = tokens.verify_access_token(result.access_token)
    assert AMR_OAUTH in claims["amr"]
    assert GOOGLE_PROVIDER in claims["amr"]
    assert "forged" not in claims["amr"], "a hook must not be able to set amr"
    assert "mfa" not in claims["amr"], "one OAuth factor is not two"


def test_an_oauth_login_honours_mfa(hooks: FakeHooks, stores: IdentityStores, kms: FakeKms) -> None:
    """A provider proving identity does not prove possession of the second factor."""
    stores = IdentityStores(
        credentials=stores.credentials,
        refresh_tokens=stores.refresh_tokens,
        totp_factors=InMemoryTotpFactorStore(),
        recovery_codes=InMemoryRecoveryCodeStore(),
        identity_tokens=InMemoryIdentityTokenStore(),
        oauth_states=stores.oauth_states,
        oauth_links=stores.oauth_links,
    )
    settings = make_settings(data_key_arn=KEY_A)
    flows = IdentityFlows(settings, hooks, stores, TokenService(settings, kms), kms_client=kms)
    user = hooks.add(EMAIL, email_verified=True)
    assert flows.mfa is not None

    enrolment = flows.mfa.begin_enrolment(str(user["id"]), account_name=EMAIL)
    flows.mfa.confirm_enrolment(str(user["id"]), _totp_now(enrolment.secret))

    with pytest.raises(MfaChallengeRequired) as excinfo:
        flows.issue_for_oauth(user, provider=GOOGLE_PROVIDER)
    assert excinfo.value.challenge.as_body()["mfa_required"] is True


def test_an_oauth_login_respects_may_authenticate(hooks: FakeHooks, stores: IdentityStores, kms: FakeKms) -> None:
    """A suspended account must not become reachable through a second front door."""
    hooks.refuse = "This account is disabled."
    settings = make_settings()
    flows = IdentityFlows(settings, hooks, stores, TokenService(settings, kms), kms_client=kms)
    user = hooks.add(EMAIL, email_verified=True)

    with pytest.raises(AuthenticationRefused):
        flows.issue_for_oauth(user, provider=GOOGLE_PROVIDER)


def _totp_now(seed: str) -> str:
    """The current TOTP code for a seed, using the package's own generator."""
    from webbpulse.identity import totp as totp_module

    return totp_module.generate_code(seed, step=totp_module.current_step())


@pytest.fixture
def client(hooks: FakeHooks, stores: IdentityStores, kms: FakeKms, provider: FakeProvider) -> Any:
    """A `TestClient` over a router with the OAuth routes mounted."""
    settings = make_settings()
    app = FastAPI()
    router = build_identity_router(
        settings,
        hooks,
        stores,
        kms_client=kms,
        limiter_enabled=False,
        oauth_client_secrets={GOOGLE_PROVIDER: GOOGLE_SECRET, GITHUB_PROVIDER: GITHUB_SECRET},
    )
    app.include_router(router)
    return TestClient(app, follow_redirects=False)


def _oauth_route_paths(router: Any) -> set[str]:
    """The mounted paths that belong to this module, read off the router."""
    from webbpulse.identity.oauth_routes import (
        OAUTH_CALLBACK_PATH,
        OAUTH_LINK_PATH,
        OAUTH_LINKS_PATH,
        OAUTH_START_PATH,
    )

    ours = {OAUTH_START_PATH, OAUTH_CALLBACK_PATH, OAUTH_LINK_PATH, OAUTH_LINKS_PATH}
    prefix = identity_prefix(make_settings())
    mounted = {getattr(route, "path", "") for route in router.routes}
    return {path for path in ours if f"{prefix}{path}" in mounted}


def test_the_start_route_redirects_to_the_provider(client: Any) -> None:
    """The start route answers 302 to the provider's authorize URL."""
    response = client.get(f"{identity_prefix(make_settings())}/oauth/google/start")
    assert response.status_code == 302
    assert response.headers["location"].startswith(PROVIDERS[GOOGLE_PROVIDER].authorize_url)


def test_the_start_route_404s_for_an_unknown_provider(client: Any) -> None:
    """The start route answers 404 for a provider that is not in the table."""
    response = client.get(f"{identity_prefix(make_settings())}/oauth/facebook/start")
    assert response.status_code == 404


def test_the_link_routes_refuse_an_anonymous_caller(client: Any) -> None:
    """Every management route reads its subject from verified claims, never from a body."""
    prefix = identity_prefix(make_settings())
    for method, path in (
        ("post", f"{prefix}/oauth/google/link"),
        ("get", f"{prefix}/oauth/links"),
        ("delete", f"{prefix}/oauth/google/link"),
    ):
        response = getattr(client, method)(path, **({"json": {}} if method == "post" else {}))
        assert response.status_code == 401, (method, path)
        assert response.json()["error_code"] == "NOT_AUTHENTICATED"


def test_the_routes_are_absent_when_no_provider_is_configured(
    hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    """A route that can only answer 503 is worse than a route that does not exist."""
    settings = make_settings(google_client_id="", github_client_id="")
    router = build_identity_router(settings, hooks, stores, kms_client=kms, limiter_enabled=False)
    assert _oauth_route_paths(router) == set()


def test_the_routes_are_absent_when_the_stores_are_missing(hooks: FakeHooks, kms: FakeKms) -> None:
    """Without the OAuth stores none of the flow routes are mounted."""
    settings = make_settings()
    router = build_identity_router(
        settings,
        hooks,
        IdentityStores(
            credentials=InMemoryCredentialStore(),
            refresh_tokens=InMemoryRefreshTokenStore(),
        ),
        kms_client=kms,
        limiter_enabled=False,
    )
    assert _oauth_route_paths(router) == set()


def test_a_callback_with_a_bad_state_redirects_rather_than_rendering_json(client: Any) -> None:
    """The user is looking at a browser: a JSON body renders as text on a blank page."""
    response = client.get(f"{identity_prefix(make_settings())}/oauth/callback?state=nope&code=abc")
    assert response.status_code == 303
    assert response.headers["location"].startswith(FRONTEND)
    assert "oauth_error=OAUTH_STATE_INVALID" in response.headers["location"]


def test_a_cancelled_consent_screen_redirects_without_an_error_page(link_client: Any) -> None:
    """A callback carrying `error=access_denied` redirects with `oauth_error=OAUTH_CANCELLED`."""
    prefix = identity_prefix(make_settings())
    start = link_client.get(f"{prefix}/oauth/google/start")
    from urllib.parse import parse_qs, urlsplit

    state = parse_qs(urlsplit(start.headers["location"]).query)["state"][0]

    response = link_client.get(f"{prefix}/oauth/callback?state={state}&error=access_denied")
    assert response.status_code == 303
    assert "oauth_error=OAUTH_CANCELLED" in response.headers["location"]


def test_the_table_names_match_the_estate_convention() -> None:
    """Hyphenated logical names, as `webbpulse.dynamodb.table_name` expects them."""
    assert OAUTH_STATES_TABLE == "oauth-states"
    assert OAUTH_LINKS_TABLE == "oauth-links"
    assert "_" not in OAUTH_STATES_TABLE
    assert "_" not in OAUTH_LINKS_TABLE


@pytest.fixture
def oauth_tables(dynamodb_resource: Any) -> dict[str, Any]:
    """The two OAuth tables, shaped as the Terraform module must create them."""
    from webbpulse.testing import create_table

    states = create_table(dynamodb_resource, "test-oauth-states", hash_key="state", ttl_attribute="expires_at")
    links = dynamodb_resource.create_table(
        TableName="test-oauth-links",
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
        BillingMode="PAY_PER_REQUEST",
    )
    links.wait_until_exists()
    return {"states": states, "links": links}


def test_the_states_table_is_keyed_on_state_with_a_ttl(oauth_tables: dict[str, Any]) -> None:
    """The states table hashes on `state` and has TTL enabled on `expires_at`."""
    table = oauth_tables["states"]
    assert table.key_schema == [{"AttributeName": "state", "KeyType": "HASH"}]

    ttl = table.meta.client.describe_time_to_live(TableName=table.name)
    description = ttl["TimeToLiveDescription"]
    assert description["TimeToLiveStatus"] == "ENABLED"
    assert description["AttributeName"] == "expires_at"


def test_the_links_table_is_keyed_on_provider_subject_with_a_user_index(
    oauth_tables: dict[str, Any],
) -> None:
    """The links table hashes on `provider_subject` and carries a `user_id` index."""
    table = oauth_tables["links"]
    assert table.key_schema == [{"AttributeName": "provider_subject", "KeyType": "HASH"}]
    indexes = {index["IndexName"]: index for index in table.global_secondary_indexes}
    assert OAUTH_LINK_USER_INDEX in indexes
    assert indexes[OAUTH_LINK_USER_INDEX]["KeySchema"] == [{"AttributeName": "user_id", "KeyType": "HASH"}]


def test_the_links_table_has_no_ttl(oauth_tables: dict[str, Any]) -> None:
    """A sign-in method that expires on a schedule locks a user out of a live account."""
    table = oauth_tables["links"]
    ttl = table.meta.client.describe_time_to_live(TableName=table.name)
    assert ttl["TimeToLiveDescription"]["TimeToLiveStatus"] == "DISABLED"


def test_the_dynamo_state_store_spends_a_row_once(oauth_tables: dict[str, Any]) -> None:
    """Against moto, so the conditional delete is the real one DynamoDB performs."""
    from webbpulse.dynamodb import Repository, ttl_in

    store = DynamoOAuthStateStore(Repository("oauth-states", prefix="test"))
    record = OAuthStateRecord(
        state="state-value",
        provider=GOOGLE_PROVIDER,
        mode="login",
        created_at="2026-01-01T00:00:00Z",
        expires_at=ttl_in(OAUTH_STATE_TTL_SECONDS),
        pkce_verifier="verifier",
        nonce="nonce",
    )
    store.put(record)

    first = store.consume("state-value")
    assert first is not None
    assert first.pkce_verifier == "verifier"
    assert store.consume("state-value") is None


def test_the_dynamo_state_store_refuses_an_expired_row(oauth_tables: dict[str, Any]) -> None:
    """moto does not expire on TTL and neither does DynamoDB promptly, which is the point."""
    from webbpulse.dynamodb import Repository

    store = DynamoOAuthStateStore(Repository("oauth-states", prefix="test"))
    store.put(
        OAuthStateRecord(
            state="stale",
            provider=GOOGLE_PROVIDER,
            mode="login",
            created_at="2020-01-01T00:00:00Z",
            expires_at=int(time.time()) - 60,
        )
    )
    assert store.consume("stale") is None


def test_the_dynamo_link_store_claims_an_identity_exactly_once(
    oauth_tables: dict[str, Any],
) -> None:
    """The conditional write is the security control, not a nicety."""
    from webbpulse.dynamodb import Repository
    from webbpulse.identity.oauth import OAuthLinkRecord

    store = DynamoOAuthLinkStore(Repository("oauth-links", prefix="test"))

    def record_for(user_id: str) -> OAuthLinkRecord:
        """A Google link record for this user id."""
        return OAuthLinkRecord(
            provider_subject=provider_account_key(GOOGLE_PROVIDER, GOOGLE_SUB),
            provider=GOOGLE_PROVIDER,
            subject=GOOGLE_SUB,
            user_id=user_id,
            linked_at="2026-01-01T00:00:00Z",
        )

    assert store.claim(record_for("user-0001")) is True
    assert store.claim(record_for("user-0002")) is False

    stored = store.get(provider_account_key(GOOGLE_PROVIDER, GOOGLE_SUB))
    assert stored is not None
    assert stored.user_id == "user-0001"


def test_the_dynamo_link_store_lists_by_user_through_the_index(
    oauth_tables: dict[str, Any],
) -> None:
    """Listing by user returns that user's links through the index and nobody else's."""
    from webbpulse.dynamodb import Repository
    from webbpulse.identity.oauth import OAuthLinkRecord

    store = DynamoOAuthLinkStore(Repository("oauth-links", prefix="test"))
    for provider_name, subject in ((GOOGLE_PROVIDER, "g1"), (GITHUB_PROVIDER, "h1")):
        store.put(
            OAuthLinkRecord(
                provider_subject=provider_account_key(provider_name, subject),
                provider=provider_name,
                subject=subject,
                user_id="user-0001",
                linked_at="2026-01-01T00:00:00Z",
                provider_email=EMAIL,
                provider_email_verified=True,
            )
        )
    store.put(
        OAuthLinkRecord(
            provider_subject=provider_account_key(GOOGLE_PROVIDER, "g2"),
            provider=GOOGLE_PROVIDER,
            subject="g2",
            user_id="user-0002",
            linked_at="2026-01-01T00:00:00Z",
        )
    )

    mine = store.list_for_user("user-0001")
    assert {record.provider for record in mine} == {GOOGLE_PROVIDER, GITHUB_PROVIDER}
    assert len(store.list_for_user("user-0002")) == 1


def test_the_dynamo_link_store_round_trips_every_field(oauth_tables: dict[str, Any]) -> None:
    """A field that does not survive the round trip is a field the settings page loses."""
    from webbpulse.dynamodb import Repository
    from webbpulse.identity.oauth import OAuthLinkRecord

    store = DynamoOAuthLinkStore(Repository("oauth-links", prefix="test"))
    record = OAuthLinkRecord(
        provider_subject=provider_account_key(GOOGLE_PROVIDER, GOOGLE_SUB),
        provider=GOOGLE_PROVIDER,
        subject=GOOGLE_SUB,
        user_id="user-0001",
        linked_at="2026-01-01T00:00:00Z",
        provider_email=EMAIL,
        provider_email_verified=True,
        last_login_at="2026-01-02T00:00:00Z",
    )
    store.put(record)
    assert store.get(record.provider_subject) == record


def test_the_dynamo_link_store_delete_is_idempotent(oauth_tables: dict[str, Any]) -> None:
    """Deleting a link that does not exist is a no-op."""
    from webbpulse.dynamodb import Repository

    store = DynamoOAuthLinkStore(Repository("oauth-links", prefix="test"))
    store.delete("google#never-existed")
    assert store.get("google#never-existed") is None


def test_a_non_json_provider_response_becomes_a_refusal_not_a_crash(hooks: FakeHooks, stores: IdentityStores) -> None:
    """A provider answering an HTML error page is a real condition, not an exception."""
    from webbpulse.identity.oauth import HttpxClient

    def handler(request: httpx.Request) -> httpx.Response:
        """Answer every request with a non-JSON 502."""
        return httpx.Response(502, text="<html>Bad Gateway</html>")

    service = OAuthService(
        make_settings(),
        hooks,
        states=stores.require_oauth_states(),
        links=stores.require_oauth_links(),
        client_secrets={GOOGLE_PROVIDER: GOOGLE_SECRET},
        http_client=HttpxClient(client=httpx.Client(transport=httpx.MockTransport(handler))),
    )
    authorization = service.start(GOOGLE_PROVIDER)
    record = service.consume_state(authorization.state)
    with pytest.raises(OAuthRejected) as excinfo:
        service.identity_from_callback(GOOGLE_PROVIDER, code="c", state_record=record)
    assert excinfo.value.error_code == "OAUTH_EXCHANGE_FAILED"
    assert "html" not in excinfo.value.message.lower()


def test_http_response_reports_success_by_status_class() -> None:
    """`HttpResponse.ok` is true for 2xx and false otherwise."""
    assert HttpResponse(200, {}).ok
    assert HttpResponse(299, {}).ok
    assert not HttpResponse(400, {}).ok
    assert not HttpResponse(500, {}).ok


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (True, True),
        (False, False),
        ("true", True),
        ("false", False),
        ("True", True),
        (None, False),
        ("", False),
    ],
)
def test_a_provider_boolean_is_read_in_both_spellings(raw: object, expected: bool) -> None:
    """`bool("false")` is `True`, which is why this is a function and not a `bool()` call."""
    from webbpulse.identity.oauth import _as_bool

    assert _as_bool(raw) is expected


def _providers_router(
    hooks: FakeHooks,
    stores: IdentityStores,
    kms: FakeKms,
    *,
    secrets: dict[str, str] | None = None,
    **overrides: Any,
) -> Any:
    """A router built the way a product builds one, for the discovery tests."""
    return build_identity_router(
        make_settings(**overrides),
        hooks,
        stores,
        kms_client=kms,
        limiter_enabled=False,
        oauth_client_secrets=secrets,
    )


def _providers_client(router: Any) -> Any:
    """A `TestClient` over an app with this router mounted."""
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, follow_redirects=False)


def _get_providers(client: Any) -> Any:
    """GET the OAuth provider discovery route."""
    return client.get(f"{identity_prefix(make_settings())}/oauth/providers")


def test_discovery_lists_every_fully_configured_provider(
    hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    """Both halves configured, so both providers are offered."""
    client = _providers_client(
        _providers_router(
            hooks,
            stores,
            kms,
            secrets={GOOGLE_PROVIDER: GOOGLE_SECRET, GITHUB_PROVIDER: GITHUB_SECRET},
        )
    )
    response = _get_providers(client)
    assert response.status_code == 200
    assert response.json() == {
        "providers": [
            {"id": "google", "display_name": "Google"},
            {"id": "github", "display_name": "GitHub"},
        ]
    }


def test_discovery_order_follows_the_provider_table_not_the_settings_list(
    hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    """Stable order, so the buttons do not reshuffle between environments."""
    client = _providers_client(
        _providers_router(
            hooks,
            stores,
            kms,
            secrets={GOOGLE_PROVIDER: GOOGLE_SECRET, GITHUB_PROVIDER: GITHUB_SECRET},
            oauth_providers=["github", "google"],
        )
    )
    assert [entry["id"] for entry in _get_providers(client).json()["providers"]] == [
        "google",
        "github",
    ]


def test_a_provider_with_an_id_but_no_secret_is_not_advertised(
    hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    """The partial-configuration case, and the reason this route checks both halves."""
    client = _providers_client(_providers_router(hooks, stores, kms, secrets={GOOGLE_PROVIDER: GOOGLE_SECRET}))
    assert _get_providers(client).json() == {"providers": [{"id": "google", "display_name": "Google"}]}


def test_the_start_route_refuses_a_provider_with_no_secret_before_redirecting(
    hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    """A provider with a client id but no secret is refused with a 503, not redirected."""
    client = _providers_client(_providers_router(hooks, stores, kms, secrets={GOOGLE_PROVIDER: GOOGLE_SECRET}))
    prefix = identity_prefix(make_settings())

    refused = client.get(f"{prefix}/oauth/github/start")
    assert refused.status_code == 503
    assert refused.json()["error_code"] == "OAUTH_PROVIDER_UNAVAILABLE"
    assert "secret" not in refused.json()["message"].lower()

    assert client.get(f"{prefix}/oauth/google/start").status_code == 302


def test_discovery_is_empty_when_no_client_secret_is_supplied_at_all(
    hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    """Client ids without secrets is still nothing a user can sign in with."""
    assert _get_providers(_providers_client(_providers_router(hooks, stores, kms))).json() == {"providers": []}


def test_discovery_is_empty_when_no_provider_has_a_client_id(
    hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    """Secrets without client ids advertise no providers."""
    client = _providers_client(
        _providers_router(
            hooks,
            stores,
            kms,
            secrets={GOOGLE_PROVIDER: GOOGLE_SECRET, GITHUB_PROVIDER: GITHUB_SECRET},
            google_client_id="",
            github_client_id="",
        )
    )
    assert _get_providers(client).json() == {"providers": []}


def test_discovery_mounts_and_is_empty_when_the_oauth_stores_are_missing(hooks: FakeHooks, kms: FakeKms) -> None:
    """A deployment with nowhere to write a state row cannot complete a sign-in."""
    router = build_identity_router(
        make_settings(),
        hooks,
        IdentityStores(credentials=InMemoryCredentialStore(), refresh_tokens=InMemoryRefreshTokenStore()),
        kms_client=kms,
        limiter_enabled=False,
        oauth_client_secrets={GOOGLE_PROVIDER: GOOGLE_SECRET, GITHUB_PROVIDER: GITHUB_SECRET},
    )
    assert _oauth_route_paths(router) == set()
    assert _get_providers(_providers_client(router)).json() == {"providers": []}


def test_discovery_mounts_on_a_documents_only_router(kms: FakeKms) -> None:
    """The JWKS-only shape, with no hooks and no stores at all, still answers."""
    router = build_identity_router(make_settings(), kms_client=kms)
    response = _get_providers(_providers_client(router))
    assert response.status_code == 200
    assert response.json() == {"providers": []}


def test_discovery_carries_the_same_cache_policy_as_the_jwks(
    hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    """Five minutes: turning a provider on is exactly when somebody is watching for it."""
    from webbpulse.identity.oauth_routes import OAUTH_PROVIDERS_CACHE_CONTROL

    client = _providers_client(
        _providers_router(
            hooks,
            stores,
            kms,
            secrets={GOOGLE_PROVIDER: GOOGLE_SECRET, GITHUB_PROVIDER: GITHUB_SECRET},
        )
    )
    assert _get_providers(client).headers["cache-control"] == OAUTH_PROVIDERS_CACHE_CONTROL
    assert OAUTH_PROVIDERS_CACHE_CONTROL == "public, max-age=300"


def test_discovery_needs_no_token_and_sets_no_cookie(hooks: FakeHooks, stores: IdentityStores, kms: FakeKms) -> None:
    """It is read by the sign-in page, which by definition holds no token."""
    client = _providers_client(
        _providers_router(
            hooks,
            stores,
            kms,
            secrets={GOOGLE_PROVIDER: GOOGLE_SECRET, GITHUB_PROVIDER: GITHUB_SECRET},
        )
    )
    response = _get_providers(client)
    assert response.status_code == 200
    assert "authorization" not in {key.lower() for key in response.request.headers}
    assert "set-cookie" not in {key.lower() for key in response.headers}


def test_discovery_never_reveals_a_client_secret_or_a_client_id(
    hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    """It is an anonymous route, so what it does not say matters as much as what it does."""
    client = _providers_client(
        _providers_router(
            hooks,
            stores,
            kms,
            secrets={GOOGLE_PROVIDER: GOOGLE_SECRET, GITHUB_PROVIDER: GITHUB_SECRET},
        )
    )
    body = _get_providers(client).text
    for leaked in (GOOGLE_SECRET, GITHUB_SECRET, GOOGLE_CLIENT_ID, GITHUB_CLIENT_ID):
        assert leaked not in body


def test_available_providers_is_stricter_than_enabled_providers(
    hooks: FakeHooks, stores: IdentityStores, provider: FakeProvider
) -> None:
    """The service-level distinction the route rests on, asserted without a request."""
    service = OAuthService(
        make_settings(),
        hooks,
        states=stores.require_oauth_states(),
        links=stores.require_oauth_links(),
        client_secrets={GOOGLE_PROVIDER: GOOGLE_SECRET},
        http_client=provider.client(),
    )
    assert service.enabled_providers() == [GOOGLE_PROVIDER, GITHUB_PROVIDER]
    assert [config.name for config in service.available_providers()] == [GOOGLE_PROVIDER]


def test_every_provider_in_the_table_has_a_display_name() -> None:
    """A blank button is worse than a missing one, and the casing is the provider's to set."""
    assert {name: config.display_name for name, config in PROVIDERS.items()} == {
        GOOGLE_PROVIDER: "Google",
        GITHUB_PROVIDER: "GitHub",
        APPLE_PROVIDER: "Apple",
    }


def test_discovery_appears_in_the_openapi_document_under_an_oauth_tag(kms: FakeKms) -> None:
    """It is a documented public API, unlike the `.well-known` documents."""
    router = build_identity_router(make_settings(), kms_client=kms)
    app = FastAPI()
    app.include_router(router)

    schema = app.openapi()
    operation = schema["paths"][f"{identity_prefix(make_settings())}/oauth/providers"]["get"]
    assert operation["tags"] == ["identity", "oauth"]
    assert operation["tags"].count("identity") == 1


def _claims_header(user_id: str, *, auth_time: int | None) -> dict[str, str]:
    """An API Gateway authorizer context carrying `sub` and, when given, `auth_time`."""
    import json

    claims: dict[str, Any] = {"sub": user_id}
    if auth_time is not None:
        claims["auth_time"] = auth_time
    return {"x-amzn-request-context": json.dumps({"authorizer": {"jwt": {"claims": claims}}})}


@pytest.fixture
def link_stores(stores: IdentityStores) -> IdentityStores:
    """The in-memory stores plus a passkey store, sharing the same OAuth tables."""
    import dataclasses

    return dataclasses.replace(stores, passkeys=InMemoryPasskeyStore())


@pytest.fixture
def link_client(
    hooks: FakeHooks,
    link_stores: IdentityStores,
    kms: FakeKms,
    provider: FakeProvider,
    monkeypatch: pytest.MonkeyPatch,
) -> Any:
    """An HTTPS `TestClient` whose OAuth service talks to the provider fake."""
    import webbpulse.identity.oauth as oauth_module

    fake_http = provider.client()
    monkeypatch.setattr(oauth_module, "HttpxClient", lambda: fake_http)
    app = FastAPI()
    app.include_router(
        build_identity_router(
            make_settings(),
            hooks,
            link_stores,
            kms_client=kms,
            limiter_enabled=False,
            oauth_client_secrets={GOOGLE_PROVIDER: GOOGLE_SECRET, GITHUB_PROVIDER: GITHUB_SECRET},
        )
    )
    return TestClient(app, base_url="https://testserver", follow_redirects=False)


def _state_of(url: str) -> str:
    """The `state` query parameter of an authorization URL."""
    from urllib.parse import parse_qs, urlsplit

    return parse_qs(urlsplit(url).query)["state"][0]


def _start_github_link(link_client: Any, user_id: str) -> Any:
    """POST the GitHub link start as a freshly signed-in user."""
    prefix = identity_prefix(make_settings())
    return link_client.post(
        f"{prefix}/oauth/github/link",
        json={"return_to": "/security"},
        headers=_claims_header(user_id, auth_time=int(time.time())),
    )


def test_a_link_start_sets_an_httponly_binding_cookie_and_stores_only_its_digest(
    link_client: Any, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """The browser holds the secret; the state row holds only its hash."""
    from webbpulse.identity.oauth import OAUTH_LINK_BINDING_COOKIE

    user = hooks.add(EMAIL, email_verified=True)
    response = _start_github_link(link_client, str(user["id"]))
    assert response.status_code == 200
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{OAUTH_LINK_BINDING_COOKIE}=")
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "samesite=lax" in cookie.lower()
    secret = link_client.cookies.get(OAUTH_LINK_BINDING_COOKIE)
    record = stores.require_oauth_states().consume(_state_of(response.json()["authorization_url"]))
    assert record is not None
    assert record.binding
    assert record.binding != secret


def test_a_login_start_sets_a_binding_cookie_and_stores_only_its_digest(
    link_client: Any, stores: IdentityStores
) -> None:
    """A login binds its state to the starting browser just as a link does."""
    from webbpulse.identity.oauth import OAUTH_LINK_BINDING_COOKIE

    response = link_client.get(f"{identity_prefix(make_settings())}/oauth/github/start")
    assert response.status_code == 302
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{OAUTH_LINK_BINDING_COOKIE}=")
    assert "HttpOnly" in cookie
    assert "samesite=lax" in cookie.lower()
    secret = link_client.cookies.get(OAUTH_LINK_BINDING_COOKIE)
    record = stores.require_oauth_states().consume(_state_of(response.headers["location"]))
    assert record is not None
    assert record.mode == "login"
    assert record.binding
    assert record.binding != secret


def _link_github_then_start_login(link_client: Any, hooks: FakeHooks) -> str:
    """Link GitHub to a fresh user, then start a GitHub login and return its state."""
    user = hooks.add(EMAIL, email_verified=True)
    prefix = identity_prefix(make_settings())
    linked = _state_of(_start_github_link(link_client, str(user["id"])).json()["authorization_url"])
    link_client.get(f"{prefix}/oauth/callback?state={linked}&code=abc")
    return _state_of(link_client.get(f"{prefix}/oauth/github/start").headers["location"])


def test_a_login_completes_in_the_browser_that_started_it(link_client: Any, hooks: FakeHooks) -> None:
    """The matching cookie signs the user in and is cleared alongside the refresh cookie."""
    from webbpulse.identity.oauth import OAUTH_LINK_BINDING_COOKIE

    settings = make_settings()
    state = _link_github_then_start_login(link_client, hooks)

    response = link_client.get(f"{identity_prefix(settings)}/oauth/callback?state={state}&code=abc")
    assert response.status_code == 303
    assert "oauth=1" in response.headers["location"]
    cookies = response.headers.get_list("set-cookie")
    assert any(c.startswith(f"{settings.cookie_name}=") for c in cookies)
    assert any(c.startswith(f'{OAUTH_LINK_BINDING_COOKIE}=""') for c in cookies)


def test_an_mfa_ticket_travels_in_the_fragment_not_the_query(
    link_client: Any, hooks: FakeHooks, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ticket never reaches a server log, a proxy or a Referer header."""
    from urllib.parse import parse_qs, urlsplit

    from webbpulse.identity.mfa import MfaChallenge

    def challenge(self: IdentityFlows, *args: Any, **kwargs: Any) -> Any:
        """Answer the login with a second-factor challenge."""
        raise MfaChallengeRequired(MfaChallenge(ticket="tkt.with/odd+chars", factors=["totp"]))

    monkeypatch.setattr(IdentityFlows, "issue_for_oauth", challenge)
    settings = make_settings()
    state = _link_github_then_start_login(link_client, hooks)

    response = link_client.get(f"{identity_prefix(settings)}/oauth/callback?state={state}&code=abc")
    assert response.status_code == 303
    location = urlsplit(response.headers["location"])
    assert "mfa_ticket" not in parse_qs(location.query)
    assert parse_qs(location.fragment) == {"mfa_ticket": ["tkt.with/odd+chars"]}
    assert not any(c.startswith(f"{settings.cookie_name}=") for c in response.headers.get_list("set-cookie"))


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("https://app.example.com/login", "https://app.example.com/login#mfa_ticket=a%2Fb"),
        ("https://app.example.com/login?next=x", "https://app.example.com/login?next=x#mfa_ticket=a%2Fb"),
        ("https://app.example.com/login#tab=1", "https://app.example.com/login#tab=1&mfa_ticket=a%2Fb"),
        ("https://app.example.com/login#", "https://app.example.com/login#mfa_ticket=a%2Fb"),
        ("", "/#mfa_ticket=a%2Fb"),
    ],
)
def test_with_fragment_appends_to_the_fragment(target: str, expected: str) -> None:
    """The query is left alone and any existing fragment is kept."""
    from webbpulse.identity.oauth_routes import _with_fragment

    assert _with_fragment(target, "mfa_ticket", "a/b") == expected


def test_a_login_completed_in_another_browser_is_refused(link_client: Any, hooks: FakeHooks) -> None:
    """Login CSRF: a victim finishing an attacker's authorization URL is signed in to nothing."""
    settings = make_settings()
    state = _link_github_then_start_login(link_client, hooks)
    link_client.cookies.clear()

    response = link_client.get(f"{identity_prefix(settings)}/oauth/callback?state={state}&code=abc")
    assert response.status_code == 303
    assert "oauth_error=OAUTH_STATE_INVALID" in response.headers["location"]
    cookies = response.headers.get_list("set-cookie")
    assert not any(c.startswith(f"{settings.cookie_name}=") for c in cookies)


def test_a_login_with_a_forged_binding_cookie_is_refused(link_client: Any, hooks: FakeHooks) -> None:
    """A cookie that does not hash to the stored digest signs nobody in."""
    from webbpulse.identity.oauth import OAUTH_LINK_BINDING_COOKIE

    settings = make_settings()
    prefix = identity_prefix(settings)
    state = _link_github_then_start_login(link_client, hooks)
    link_client.cookies.clear()
    link_client.cookies.set(OAUTH_LINK_BINDING_COOKIE, "forged", path=prefix)

    response = link_client.get(f"{prefix}/oauth/callback?state={state}&code=abc")
    assert "oauth_error=OAUTH_STATE_INVALID" in response.headers["location"]
    cookies = response.headers.get_list("set-cookie")
    assert not any(c.startswith(f"{settings.cookie_name}=") for c in cookies)


def test_a_login_state_with_no_binding_is_refused(link_client: Any, stores: IdentityStores) -> None:
    """A row written before logins were bound fails once rather than skipping the check."""
    stores.require_oauth_states().put(
        OAuthStateRecord(
            state="unbound-login",
            provider=GITHUB_PROVIDER,
            mode="login",
            created_at="",
            expires_at=int(time.time()) + 600,
        )
    )

    response = link_client.get(f"{identity_prefix(make_settings())}/oauth/callback?state=unbound-login&code=abc")
    assert response.status_code == 303
    assert "oauth_error=OAUTH_STATE_INVALID" in response.headers["location"]


def test_a_link_completes_in_the_browser_that_started_it(
    link_client: Any, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """The happy path links the account, records the GitHub login and clears the cookie."""
    from webbpulse.identity.oauth import OAUTH_LINK_BINDING_COOKIE

    user = hooks.add("someone-else@example.com", email_verified=True)
    prefix = identity_prefix(make_settings())
    state = _state_of(_start_github_link(link_client, str(user["id"])).json()["authorization_url"])

    response = link_client.get(f"{prefix}/oauth/callback?state={state}&code=abc")
    assert response.status_code == 303
    assert response.headers["location"] == f"{FRONTEND}/security?oauth_linked=1"
    assert f'{OAUTH_LINK_BINDING_COOKIE}=""' in response.headers["set-cookie"]

    listed = link_client.get(
        f"{prefix}/oauth/links", headers=_claims_header(str(user["id"]), auth_time=int(time.time()))
    )
    assert listed.json()["links"][0]["provider"] == GITHUB_PROVIDER
    assert listed.json()["links"][0]["login"] == "octocat"
    assert listed.json()["links"][0]["email"] == EMAIL


def test_a_link_completed_in_another_browser_is_refused(
    link_client: Any, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Link CSRF: an attacker's authorization URL finished by a victim links nothing."""
    user = hooks.add(EMAIL, email_verified=True)
    prefix = identity_prefix(make_settings())
    state = _state_of(_start_github_link(link_client, str(user["id"])).json()["authorization_url"])
    link_client.cookies.clear()

    response = link_client.get(f"{prefix}/oauth/callback?state={state}&code=abc")
    assert response.status_code == 303
    assert "oauth_error=OAUTH_STATE_INVALID" in response.headers["location"]
    assert stores.require_oauth_links().list_for_user(str(user["id"])) == []


def test_a_link_with_a_forged_binding_cookie_is_refused(
    link_client: Any, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A cookie that does not hash to the stored digest is no binding at all."""
    from webbpulse.identity.oauth import OAUTH_LINK_BINDING_COOKIE

    user = hooks.add(EMAIL, email_verified=True)
    prefix = identity_prefix(make_settings())
    state = _state_of(_start_github_link(link_client, str(user["id"])).json()["authorization_url"])
    link_client.cookies.clear()
    link_client.cookies.set(OAUTH_LINK_BINDING_COOKIE, "forged", path=prefix)

    response = link_client.get(f"{prefix}/oauth/callback?state={state}&code=abc")
    assert "oauth_error=OAUTH_STATE_INVALID" in response.headers["location"]
    assert stores.require_oauth_links().list_for_user(str(user["id"])) == []


def test_the_binding_is_spent_with_the_state(link_client: Any, hooks: FakeHooks) -> None:
    """Replaying a finished link's callback is refused even in the same browser."""
    user = hooks.add(EMAIL, email_verified=True)
    prefix = identity_prefix(make_settings())
    state = _state_of(_start_github_link(link_client, str(user["id"])).json()["authorization_url"])
    link_client.get(f"{prefix}/oauth/callback?state={state}&code=abc")

    replay = link_client.get(f"{prefix}/oauth/callback?state={state}&code=abc")
    assert "oauth_error=OAUTH_STATE_INVALID" in replay.headers["location"]


def test_a_link_to_an_identity_owned_by_another_user_is_refused_over_the_routes(
    link_client: Any, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """The identity stays with its owner; the second account gets OAUTH_ALREADY_LINKED."""
    owner = hooks.add("owner@example.com", email_verified=True)
    other = hooks.add("other@example.com", email_verified=True)
    prefix = identity_prefix(make_settings())
    first = _state_of(_start_github_link(link_client, str(owner["id"])).json()["authorization_url"])
    link_client.get(f"{prefix}/oauth/callback?state={first}&code=abc")

    second = _state_of(_start_github_link(link_client, str(other["id"])).json()["authorization_url"])
    response = link_client.get(f"{prefix}/oauth/callback?state={second}&code=abc")
    assert "oauth_error=OAUTH_ALREADY_LINKED" in response.headers["location"]
    links = stores.require_oauth_links()
    assert [r.user_id for r in links.list_for_user(str(owner["id"]))] == [owner["id"]]
    assert links.list_for_user(str(other["id"])) == []


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("post", "/oauth/github/link"),
        ("delete", "/oauth/github/link"),
        ("get", "/oauth/github/start?mode=link"),
    ],
)
@pytest.mark.parametrize("auth_time", [None, 0, -3600])
def test_link_and_unlink_need_a_recent_sign_in(
    link_client: Any, hooks: FakeHooks, method: str, path: str, auth_time: int | None
) -> None:
    """A missing or stale `auth_time` is a 401 STEP_UP_REQUIRED carrying `max_age`."""
    user = hooks.add(EMAIL, email_verified=True)
    stamp = None if auth_time is None else (1 if auth_time == 0 else int(time.time()) + auth_time)
    prefix = identity_prefix(make_settings())
    response = getattr(link_client, method)(
        f"{prefix}{path}",
        headers=_claims_header(str(user["id"]), auth_time=stamp),
        **({"json": {}} if method == "post" else {}),
    )
    assert response.status_code == 401
    assert response.json()["error_code"] == "STEP_UP_REQUIRED"
    assert response.json()["max_age"] == 600
    assert "max_age=600" in response.headers["www-authenticate"]
    assert "set-cookie" not in response.headers


def test_a_zero_link_window_turns_the_step_up_off(hooks: FakeHooks, stores: IdentityStores, kms: FakeKms) -> None:
    """`oauth_link_max_auth_age=0` lets any signed-in caller start a link."""
    from datetime import timedelta

    user = hooks.add(EMAIL, email_verified=True)
    settings = make_settings(oauth_link_max_auth_age=timedelta(0))
    app = FastAPI()
    app.include_router(
        build_identity_router(
            settings,
            hooks,
            stores,
            kms_client=kms,
            limiter_enabled=False,
            oauth_client_secrets={GOOGLE_PROVIDER: GOOGLE_SECRET, GITHUB_PROVIDER: GITHUB_SECRET},
        )
    )
    response = TestClient(app, base_url="https://testserver").post(
        f"{identity_prefix(settings)}/oauth/github/link",
        json={},
        headers=_claims_header(str(user["id"]), auth_time=None),
    )
    assert response.status_code == 200


def test_a_negative_link_window_is_refused() -> None:
    """A negative window is a configuration mistake, not a way to turn the check off."""
    from datetime import timedelta

    with pytest.raises(ValueError, match="oauth_link_max_auth_age"):
        make_settings(oauth_link_max_auth_age=timedelta(seconds=-1))


def test_unlink_over_the_route_refuses_the_last_sign_in_method(
    link_client: Any, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """With no password, passkey or other link left, DELETE is a 409 and the link stays."""
    user = hooks.add(EMAIL, email_verified=True)
    prefix = identity_prefix(make_settings())
    state = _state_of(_start_github_link(link_client, str(user["id"])).json()["authorization_url"])
    link_client.get(f"{prefix}/oauth/callback?state={state}&code=abc")

    response = link_client.delete(
        f"{prefix}/oauth/github/link", headers=_claims_header(str(user["id"]), auth_time=int(time.time()))
    )
    assert response.status_code == 409
    assert response.json()["error_code"] == "OAUTH_LAST_SIGN_IN_METHOD"
    assert len(stores.require_oauth_links().list_for_user(str(user["id"]))) == 1


def test_unlink_over_the_route_succeeds_when_a_passkey_remains(
    link_client: Any, hooks: FakeHooks, link_stores: IdentityStores
) -> None:
    """A passwordless passkey is a way back in, so the link may go."""
    user = hooks.add(EMAIL, email_verified=True)
    prefix = identity_prefix(make_settings())
    state = _state_of(_start_github_link(link_client, str(user["id"])).json()["authorization_url"])
    link_client.get(f"{prefix}/oauth/callback?state={state}&code=abc")
    assert link_stores.passkeys is not None
    link_stores.passkeys.put(PasskeyRecord(user_id=str(user["id"]), credential_id="cred-1", public_key="pk"))

    response = link_client.delete(
        f"{prefix}/oauth/github/link", headers=_claims_header(str(user["id"]), auth_time=int(time.time()))
    )
    assert response.status_code == 200
    assert link_stores.require_oauth_links().list_for_user(str(user["id"])) == []


def _passkey_oauth(hooks: FakeHooks, stores: IdentityStores, **settings: Any) -> tuple[OAuthService, Any]:
    """An `OAuthService` that can see a passkey store, and that store."""
    passkeys = InMemoryPasskeyStore()
    service = OAuthService(
        make_settings(**settings),
        hooks,
        states=stores.require_oauth_states(),
        links=stores.require_oauth_links(),
        credentials=stores.credentials,
        passkeys=passkeys,
        client_secrets={GOOGLE_PROVIDER: GOOGLE_SECRET, GITHUB_PROVIDER: GITHUB_SECRET},
    )
    return service, passkeys


def test_unlink_counts_a_passwordless_passkey(hooks: FakeHooks, stores: IdentityStores) -> None:
    """A passkey the user can sign in with keeps them from being locked out."""
    oauth, passkeys = _passkey_oauth(hooks, stores)
    user = hooks.add(EMAIL, email_verified=True)
    oauth.link(OAuthIdentity(GOOGLE_PROVIDER, "g", EMAIL, True), user_id=str(user["id"]))
    passkeys.put(PasskeyRecord(user_id=str(user["id"]), credential_id="c", public_key="pk"))

    oauth.unlink(user_id=str(user["id"]), provider=GOOGLE_PROVIDER)
    assert oauth.list_links(str(user["id"])) == []


def test_unlink_ignores_a_passkey_that_cannot_sign_in_alone(hooks: FakeHooks, stores: IdentityStores) -> None:
    """With passwordless passkeys off, a passkey is a second factor, not a way in."""
    oauth, passkeys = _passkey_oauth(hooks, stores, passkeys_passwordless=False)
    user = hooks.add(EMAIL, email_verified=True)
    oauth.link(OAuthIdentity(GOOGLE_PROVIDER, "g", EMAIL, True), user_id=str(user["id"]))
    passkeys.put(PasskeyRecord(user_id=str(user["id"]), credential_id="c", public_key="pk"))

    with pytest.raises(OAuthRejected) as excinfo:
        oauth.unlink(user_id=str(user["id"]), provider=GOOGLE_PROVIDER)
    assert excinfo.value.error_code == "OAUTH_LAST_SIGN_IN_METHOD"


def test_linking_to_a_user_that_no_longer_exists_is_refused(oauth: OAuthService) -> None:
    """A link state that outlived its account never creates an orphan link."""
    with pytest.raises(OAuthRejected) as excinfo:
        oauth.link(OAuthIdentity(GOOGLE_PROVIDER, "g", EMAIL, True), user_id="user-gone")
    assert excinfo.value.error_code == "OAUTH_ACCOUNT_MISSING"
    assert oauth.list_links("user-gone") == []


def test_the_github_login_is_kept_on_the_link(oauth: OAuthService, provider: FakeProvider, hooks: FakeHooks) -> None:
    """The settings page shows `@octocat`, which only the userinfo call knows."""
    user = hooks.add(EMAIL, email_verified=True)
    authorization = oauth.start(GITHUB_PROVIDER, mode="link", user_id=str(user["id"]))
    record = oauth.consume_state(authorization.state)
    identity = oauth.identity_from_callback(GITHUB_PROVIDER, code="abc", state_record=record)
    assert identity.login == "octocat"
    assert oauth.link(identity, user_id=str(user["id"])).provider_login == "octocat"


def test_link_binding_matches_only_the_secret_it_was_made_from() -> None:
    """The digest check accepts its own secret and nothing else, and unbound rows pass."""
    from webbpulse.identity.oauth import link_binding_matches, new_link_binding

    secret, digest = new_link_binding()
    bound = OAuthStateRecord(
        state="s", provider=GITHUB_PROVIDER, mode="link", created_at="", expires_at=0, binding=digest
    )
    assert link_binding_matches(bound, secret)
    assert not link_binding_matches(bound, "")
    assert not link_binding_matches(bound, secret + "x")
    unbound = OAuthStateRecord(state="s", provider=GITHUB_PROVIDER, mode="link", created_at="", expires_at=0)
    assert link_binding_matches(unbound, "")


def test_the_dynamo_stores_round_trip_the_binding_and_the_login(oauth_tables: dict[str, Any]) -> None:
    """Both new fields survive DynamoDB, so the callback and the settings page can read them."""
    from webbpulse.dynamodb import Repository
    from webbpulse.identity.oauth import OAuthLinkRecord

    links = DynamoOAuthLinkStore(Repository("oauth-links", prefix="test"))
    record = OAuthLinkRecord(
        provider_subject=provider_account_key(GITHUB_PROVIDER, GITHUB_SUB),
        provider=GITHUB_PROVIDER,
        subject=GITHUB_SUB,
        user_id="user-0001",
        linked_at="2026-01-01T00:00:00Z",
        provider_email=EMAIL,
        provider_email_verified=True,
        provider_login="octocat",
    )
    links.put(record)
    assert links.get(record.provider_subject) == record

    states = DynamoOAuthStateStore(Repository("oauth-states", prefix="test"))
    state = OAuthStateRecord(
        state="bound-state",
        provider=GITHUB_PROVIDER,
        mode="link",
        created_at="2026-01-01T00:00:00Z",
        expires_at=int(time.time()) + 600,
        user_id="user-0001",
        binding="digest-value",
    )
    states.put(state)
    spent = states.consume("bound-state")
    assert spent is not None
    assert spent.binding == "digest-value"


@pytest.fixture(scope="module")
def apple_key() -> ec.EllipticCurvePrivateKey:
    """A P-256 key shaped like the `.p8` Apple issues."""
    return ec.generate_private_key(ec.SECP256R1())


def _apple_pem(key: ec.EllipticCurvePrivateKey) -> str:
    """The key as PKCS#8 PEM text, as a `.p8` file holds it."""
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _apple_settings(**overrides: Any) -> dict[str, Any]:
    """The three Apple settings, with per-test overrides applied."""
    return {
        "apple_client_id": APPLE_CLIENT_ID,
        "apple_team_id": APPLE_TEAM_ID,
        "apple_key_id": APPLE_KEY_ID,
        **overrides,
    }


def _form_post_routes(router: Any) -> list[str]:
    """The paths mounted for a POST to the OAuth callback."""
    return [route.path for route in router.routes if route.path.endswith("/oauth/callback") and "POST" in route.methods]


@pytest.fixture
def apple_client(
    hooks: FakeHooks,
    link_stores: IdentityStores,
    kms: FakeKms,
    provider: FakeProvider,
    apple_key: ec.EllipticCurvePrivateKey,
    monkeypatch: pytest.MonkeyPatch,
) -> Any:
    """An HTTPS `TestClient` for a product with Apple fully configured."""
    import webbpulse.identity.oauth as oauth_module

    fake_http = provider.client()
    monkeypatch.setattr(oauth_module, "HttpxClient", lambda: fake_http)
    app = FastAPI()
    app.include_router(
        _providers_router(hooks, link_stores, kms, secrets={APPLE_PROVIDER: _apple_pem(apple_key)}, **_apple_settings())
    )
    return TestClient(app, base_url="https://testserver", follow_redirects=False)


def _start_apple(client: Any, provider: FakeProvider) -> str:
    """Start an Apple sign-in, have the fake echo its nonce, and return the state."""
    from urllib.parse import parse_qs, urlsplit

    start = client.get(f"{identity_prefix(make_settings())}/oauth/apple/start")
    assert start.status_code == 302
    query = parse_qs(urlsplit(start.headers["location"]).query)
    provider.nonce_to_echo = query["nonce"][0]
    return str(query["state"][0])


def _post_apple(client: Any, fields: dict[str, str]) -> Any:
    """POST a form to the callback the way Apple's page makes the browser do it."""
    return client.post(
        f"{identity_prefix(make_settings())}/oauth/callback",
        content=urlencode(fields),
        headers={"content-type": "application/x-www-form-urlencoded", "sec-fetch-site": "cross-site"},
    )


APPLE_USER_FIELD = json.dumps({"name": {"firstName": "Ada", "lastName": "Lovelace"}, "email": APPLE_RELAY_EMAIL})


@pytest.mark.parametrize(
    ("settings", "with_key"),
    [
        ({}, False),
        ({}, True),
        ({"apple_client_id": APPLE_CLIENT_ID}, True),
        (_apple_settings(apple_team_id=""), True),
        (_apple_settings(apple_key_id=""), True),
        (_apple_settings(), False),
    ],
)
def test_apple_is_not_offered_until_all_four_values_are_set(
    settings: dict[str, Any],
    with_key: bool,
    hooks: FakeHooks,
    stores: IdentityStores,
    kms: FakeKms,
    apple_key: ec.EllipticCurvePrivateKey,
) -> None:
    """Any missing identifier, or the missing key, leaves the button off."""
    secrets = {GOOGLE_PROVIDER: GOOGLE_SECRET, GITHUB_PROVIDER: GITHUB_SECRET}
    if with_key:
        secrets[APPLE_PROVIDER] = _apple_pem(apple_key)
    client = _providers_client(_providers_router(hooks, stores, kms, secrets=secrets, **settings))
    names = [entry["id"] for entry in _get_providers(client).json()["providers"]]
    assert names == ["google", "github"]


def test_apple_is_offered_after_the_other_providers_once_configured(
    hooks: FakeHooks, stores: IdentityStores, kms: FakeKms, apple_key: ec.EllipticCurvePrivateKey
) -> None:
    """A complete configuration adds the button, labelled, in the stable order."""
    secrets = {GOOGLE_PROVIDER: GOOGLE_SECRET, GITHUB_PROVIDER: GITHUB_SECRET, APPLE_PROVIDER: _apple_pem(apple_key)}
    client = _providers_client(_providers_router(hooks, stores, kms, secrets=secrets, **_apple_settings()))
    entries = _get_providers(client).json()["providers"]
    assert [entry["id"] for entry in entries] == ["google", "github", "apple"]
    assert entries[-1]["display_name"] == "Apple"


def test_a_deployment_without_apple_mounts_no_form_post_route(
    hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    """Every other product keeps exactly the routes its gateway already carries."""
    secrets = {GOOGLE_PROVIDER: GOOGLE_SECRET, GITHUB_PROVIDER: GITHUB_SECRET}
    assert _form_post_routes(_providers_router(hooks, stores, kms, secrets=secrets)) == []


def test_an_apple_client_id_mounts_the_form_post_route(hooks: FakeHooks, stores: IdentityStores, kms: FakeKms) -> None:
    """The route follows the client id, like every other OAuth route."""
    router = _providers_router(hooks, stores, kms, apple_client_id=APPLE_CLIENT_ID)
    assert _form_post_routes(router) == [f"{identity_prefix(make_settings())}/oauth/callback"]


def test_an_apple_start_without_the_key_refuses_as_unavailable(
    hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    """A half-configured Apple cannot begin a sign-in."""
    client = _providers_client(_providers_router(hooks, stores, kms, **_apple_settings()))
    response = client.get(f"{identity_prefix(make_settings())}/oauth/apple/start")
    assert "OAUTH_PROVIDER_UNAVAILABLE" in response.headers.get("location", response.text)


def test_the_apple_authorize_url_asks_for_a_form_post_and_a_nonce_without_pkce(
    apple_client: Any,
) -> None:
    """Apple requires `form_post` for name and email, and does not do PKCE."""
    from urllib.parse import parse_qs, urlsplit

    start = apple_client.get(f"{identity_prefix(make_settings())}/oauth/apple/start")
    assert "scope=name%20email" in start.headers["location"]
    url = urlsplit(start.headers["location"])
    query = parse_qs(url.query)
    assert f"{url.scheme}://{url.netloc}{url.path}" == f"{APPLE_ISSUER}/auth/authorize"
    assert query["client_id"] == [APPLE_CLIENT_ID]
    assert query["response_mode"] == ["form_post"]
    assert query["response_type"] == ["code"]
    assert query["scope"] == ["name email"]
    assert query["nonce"][0]
    assert "code_challenge" not in query


def test_the_form_post_redirects_to_the_get_callback_without_the_name_in_the_url(
    apple_client: Any, provider: FakeProvider
) -> None:
    """Only the state and code travel on, and the redirect stays on this origin."""
    state = _start_apple(apple_client, provider)
    response = _post_apple(apple_client, {"state": state, "code": "abc", "user": APPLE_USER_FIELD})
    assert response.status_code == 303
    location = response.headers["location"]
    expected_query = urlencode({"state": state, "code": "abc"})
    assert location == f"{identity_prefix(make_settings())}/oauth/callback?{expected_query}"
    assert "Ada" not in location
    assert "user=" not in location


def test_the_first_apple_sign_in_registers_with_the_posted_name_and_relay_address(
    apple_client: Any, provider: FakeProvider, hooks: FakeHooks
) -> None:
    """The whole path: start, form post, GET with the binding cookie, new account."""
    state = _start_apple(apple_client, provider)
    posted = _post_apple(apple_client, {"state": state, "code": "abc", "user": APPLE_USER_FIELD})

    response = apple_client.get(posted.headers["location"], headers={"sec-fetch-site": "cross-site"})

    assert response.status_code == 303
    assert "oauth_error" not in response.headers["location"]
    user = hooks.users[hooks.by_email[APPLE_RELAY_EMAIL]]
    assert user["name"] == "Ada Lovelace"
    assert user["email_verified"] is True
    assert hooks.created_via == [APPLE_PROVIDER]


def test_a_later_apple_sign_in_without_a_name_or_email_finds_the_link(
    apple_client: Any, provider: FakeProvider, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Apple can drop the email on a return visit, and the link's verified flag survives."""
    first = _start_apple(apple_client, provider)
    apple_client.get(_post_apple(apple_client, {"state": first, "code": "abc"}).headers["location"])

    provider.apple_claims = {"email": None, "email_verified": None}
    again = _start_apple(apple_client, provider)
    response = apple_client.get(_post_apple(apple_client, {"state": again, "code": "def"}).headers["location"])

    assert "oauth_error" not in response.headers["location"]
    assert len(hooks.users) == 1
    link = stores.require_oauth_links().get(provider_account_key(APPLE_PROVIDER, APPLE_SUB))
    assert link is not None
    assert link.provider_email == APPLE_RELAY_EMAIL
    assert link.provider_email_verified is True


def test_a_new_apple_user_without_an_email_is_refused(apple_client: Any, provider: FakeProvider) -> None:
    """A Managed Apple Account can omit the email, and a new account needs one."""
    provider.apple_claims = {"email": None, "email_verified": None}
    state = _start_apple(apple_client, provider)
    response = apple_client.get(_post_apple(apple_client, {"state": state, "code": "abc"}).headers["location"])
    assert "oauth_error=OAUTH_EMAIL_MISSING" in response.headers["location"]


def test_the_exchange_presents_a_signed_apple_client_secret(
    apple_client: Any, provider: FakeProvider, apple_key: ec.EllipticCurvePrivateKey
) -> None:
    """The JWT verifies against the key and carries the claims Apple documents."""
    import jwt

    state = _start_apple(apple_client, provider)
    apple_client.get(_post_apple(apple_client, {"state": state, "code": "abc"}).headers["location"])

    exchange = next(r for r in provider.requests if str(r.url) == PROVIDERS[APPLE_PROVIDER].token_url)
    secret = _parse_form(exchange)["client_secret"]
    header = jwt.get_unverified_header(secret)
    claims = jwt.decode(secret, apple_key.public_key(), algorithms=["ES256"], audience=APPLE_ISSUER)
    assert header["alg"] == "ES256"
    assert header["kid"] == APPLE_KEY_ID
    assert claims["iss"] == APPLE_TEAM_ID
    assert claims["sub"] == APPLE_CLIENT_ID
    assert claims["exp"] - claims["iat"] == APPLE_CLIENT_SECRET_TTL_SECONDS


def test_a_key_stored_with_escaped_newlines_still_signs(
    hooks: FakeHooks,
    stores: IdentityStores,
    provider: FakeProvider,
    apple_key: ec.EllipticCurvePrivateKey,
) -> None:
    """A `.p8` flattened into one line of a JSON secret is the same key."""
    service = OAuthService(
        make_settings(**_apple_settings()),
        hooks,
        states=stores.require_oauth_states(),
        links=stores.require_oauth_links(),
        credentials=stores.credentials,
        client_secrets={APPLE_PROVIDER: _apple_pem(apple_key).replace("\n", "\\n")},
        http_client=provider.client(),
    )
    assert service.start(APPLE_PROVIDER, mode="login").state


def test_a_key_that_cannot_sign_refuses_without_logging_it(
    hooks: FakeHooks, stores: IdentityStores, provider: FakeProvider, caplog: pytest.LogCaptureFixture
) -> None:
    """A bad `.p8` looks like a missing one, and its text stays out of the log."""
    service = OAuthService(
        make_settings(**_apple_settings()),
        hooks,
        states=stores.require_oauth_states(),
        links=stores.require_oauth_links(),
        credentials=stores.credentials,
        client_secrets={APPLE_PROVIDER: "not-a-real-key-material"},
        http_client=provider.client(),
    )
    with pytest.raises(OAuthRejected) as refused:
        service.start(APPLE_PROVIDER, mode="login")
    assert refused.value.error_code == "OAUTH_PROVIDER_UNAVAILABLE"
    assert "not-a-real-key-material" not in caplog.text


def test_an_apple_cancellation_reaches_the_cancelled_outcome(apple_client: Any, provider: FakeProvider) -> None:
    """Apple posts `user_cancelled_authorize`, and the GET callback handles it as usual."""
    state = _start_apple(apple_client, provider)
    posted = _post_apple(apple_client, {"state": state, "error": "user_cancelled_authorize"})
    response = apple_client.get(posted.headers["location"])
    assert "oauth_error=OAUTH_CANCELLED" in response.headers["location"]


def test_a_form_post_replay_cannot_sign_in_twice(apple_client: Any, provider: FakeProvider) -> None:
    """The state is single-use even though the name path rewrites the row."""
    state = _start_apple(apple_client, provider)
    fields = {"state": state, "code": "abc", "user": APPLE_USER_FIELD}
    apple_client.get(_post_apple(apple_client, fields).headers["location"])

    replay = apple_client.get(_post_apple(apple_client, fields).headers["location"])

    assert "oauth_error=" in replay.headers["location"]


def test_a_form_post_from_another_browser_is_refused(
    apple_client: Any, provider: FakeProvider, hooks: FakeHooks
) -> None:
    """Without the binding cookie the GET callback refuses, as it does for Google."""
    state = _start_apple(apple_client, provider)
    posted = _post_apple(apple_client, {"state": state, "code": "abc", "user": APPLE_USER_FIELD})
    apple_client.cookies.clear()

    response = apple_client.get(posted.headers["location"])

    assert "oauth_error=OAUTH_STATE_INVALID" in response.headers["location"]
    assert hooks.users == {}


@pytest.mark.parametrize(
    "user",
    ["{not json", "[]", '"text"', '{"name": "flat"}', '{"name": {"firstName": 7}}', '{"email": "a@example.com"}'],
)
def test_a_malformed_user_field_is_ignored(
    user: str, apple_client: Any, provider: FakeProvider, hooks: FakeHooks
) -> None:
    """The field is unsigned, so bad input costs the name and not the sign-in."""
    state = _start_apple(apple_client, provider)
    posted = _post_apple(apple_client, {"state": state, "code": "abc", "user": user})
    response = apple_client.get(posted.headers["location"])
    assert "oauth_error" not in response.headers["location"]
    assert not hooks.users[hooks.by_email[APPLE_RELAY_EMAIL]].get("name")


def test_a_posted_name_is_normalised_and_capped(apple_client: Any, provider: FakeProvider, hooks: FakeHooks) -> None:
    """Whitespace collapses and a long name is cut at the limit."""
    state = _start_apple(apple_client, provider)
    user = json.dumps({"name": {"firstName": "  Ada  ", "lastName": "L" * 500}})
    apple_client.get(_post_apple(apple_client, {"state": state, "code": "abc", "user": user}).headers["location"])
    name = hooks.users[hooks.by_email[APPLE_RELAY_EMAIL]]["name"]
    assert name.startswith("Ada LL")
    assert len(name) == 200


def test_a_name_posted_against_a_google_state_is_dropped(apple_client: Any, stores: IdentityStores) -> None:
    """A form post only keeps a name for a provider that answers by form post."""
    states = stores.require_oauth_states()
    states.put(
        OAuthStateRecord(
            state="google-state",
            provider=GOOGLE_PROVIDER,
            mode="login",
            created_at="2026-01-01T00:00:00Z",
            expires_at=int(time.time()) + 600,
        )
    )
    _post_apple(apple_client, {"state": "google-state", "code": "abc", "user": APPLE_USER_FIELD})
    record = states.consume("google-state")
    assert record is not None
    assert record.profile_name == ""


@pytest.mark.parametrize(
    "fields",
    [
        {"state": "unknown-state", "code": "abc", "user": APPLE_USER_FIELD},
        {"code": "abc"},
        {"state": "s", "padding": "x" * (70 * 1024)},
        {f"field{index}": "x" for index in range(20)},
    ],
)
def test_a_bad_form_post_ends_on_the_state_refusal(fields: dict[str, str], apple_client: Any) -> None:
    """Unknown, missing, oversized or overlong forms all reach the one refusal path."""
    posted = _post_apple(apple_client, fields)
    assert posted.status_code == 303
    response = apple_client.get(posted.headers["location"])
    assert response.status_code == 303
    assert "oauth_error=" in response.headers["location"]


def test_the_form_post_route_is_rate_limited(hooks: FakeHooks, stores: IdentityStores, kms: FakeKms) -> None:
    """It is unauthenticated and writes to a table, so it carries a limit like the start route."""
    router = build_identity_router(
        make_settings(apple_client_id=APPLE_CLIENT_ID),
        hooks,
        stores,
        kms_client=kms,
        limiter_enabled=True,
    )
    routes: list[Any] = list(router.routes)
    route = next(route for route in routes if route.path.endswith("/oauth/callback") and "POST" in route.methods)
    assert route.dependencies


def test_the_profile_name_round_trips_through_dynamodb(oauth_tables: dict[str, Any]) -> None:
    """The name waits on the state row between the form post and the callback."""
    from webbpulse.dynamodb import Repository

    states = DynamoOAuthStateStore(Repository("oauth-states", prefix="test"))
    states.put(
        OAuthStateRecord(
            state="apple-state",
            provider=APPLE_PROVIDER,
            mode="login",
            created_at="2026-01-01T00:00:00Z",
            expires_at=int(time.time()) + 600,
            profile_name="Ada Lovelace",
        )
    )
    spent = states.consume("apple-state")
    assert spent is not None
    assert spent.profile_name == "Ada Lovelace"


APPLE_TOKEN_MASTER_KEY = base64.b64encode(bytes(range(32))).decode()
APPLE_USER_ID = "user-apple"
APPLE_LINK_KEY = provider_account_key(APPLE_PROVIDER, APPLE_SUB)
APPLE_REFRESH_TOKEN = "apple-refresh-token"
NOTIFICATIONS_PATH = f"{identity_prefix(make_settings())}{OAUTH_APPLE_NOTIFICATIONS_PATH}"


def _sealing_settings(**overrides: Any) -> dict[str, Any]:
    """Apple's settings plus a master key, so a provider token can be sealed."""
    return _apple_settings(totp_cipher="secret", totp_master_key=APPLE_TOKEN_MASTER_KEY, **overrides)


@pytest.fixture
def sealing_client(
    hooks: FakeHooks,
    link_stores: IdentityStores,
    kms: FakeKms,
    provider: FakeProvider,
    apple_key: ec.EllipticCurvePrivateKey,
    monkeypatch: pytest.MonkeyPatch,
) -> Any:
    """An HTTPS `TestClient` for a product with Apple configured and a key to seal tokens with."""
    import webbpulse.identity.oauth as oauth_module

    fake_http = provider.client()
    monkeypatch.setattr(oauth_module, "HttpxClient", lambda: fake_http)
    app = FastAPI()
    app.include_router(
        _providers_router(
            hooks, link_stores, kms, secrets={APPLE_PROVIDER: _apple_pem(apple_key)}, **_sealing_settings()
        )
    )
    return TestClient(app, base_url="https://testserver", follow_redirects=False)


def _provider_tokens(
    stores: IdentityStores, provider: FakeProvider, apple_key: ec.EllipticCurvePrivateKey, **http: Any
) -> ProviderTokens:
    """A `ProviderTokens` over the stores, sealing with the master key and calling the fake."""
    return ProviderTokens(
        make_settings(**_sealing_settings()),
        links=stores.require_oauth_links(),
        client_secrets={APPLE_PROVIDER: _apple_pem(apple_key)},
        http_client=http.get("client") or provider.client(),
    )


def _apple_identity(token: str = APPLE_REFRESH_TOKEN) -> OAuthIdentity:
    """An Apple identity carrying a refresh token."""
    return OAuthIdentity(
        provider=APPLE_PROVIDER,
        subject=APPLE_SUB,
        email=APPLE_RELAY_EMAIL,
        email_verified=True,
        provider_refresh_token=token,
    )


def _seed_apple_link(stores: IdentityStores, **overrides: Any) -> Any:
    """Write the Apple link the notifications act on, and return it."""
    from webbpulse.identity.oauth import OAuthLinkRecord

    fields: dict[str, Any] = {
        "provider_subject": APPLE_LINK_KEY,
        "provider": APPLE_PROVIDER,
        "subject": APPLE_SUB,
        "user_id": APPLE_USER_ID,
        "linked_at": "2026-01-01T00:00:00Z",
        "provider_email": APPLE_RELAY_EMAIL,
        "provider_email_verified": True,
        "last_login_at": "2026-01-01T00:00:00Z",
    }
    fields.update(overrides)
    record = OAuthLinkRecord(**fields)
    stores.require_oauth_links().put(record)
    return record


def _apple_notification(
    provider: FakeProvider,
    event_type: str,
    *,
    events: dict[str, Any] | None = None,
    raw_events: Any = None,
    **claims: Any,
) -> str:
    """A genuinely signed notification, with per-test changes to its claims and events."""
    import jwt

    now = int(time.time())
    body: dict[str, Any] = {
        "iss": APPLE_ISSUER,
        "aud": APPLE_CLIENT_ID,
        "iat": now,
        "jti": "notification-1",
        "events": {"type": event_type, "sub": APPLE_SUB, "event_time": now, **(events or {})},
    }
    body.update(claims)
    if raw_events is not None:
        body["events"] = raw_events
    return jwt.encode(body, provider.key, algorithm="RS256", headers={"kid": "test-key"})


def _post_notification(client: Any, payload: str) -> Any:
    """POST a notification the way Apple's sample shows it, as a JSON object."""
    return client.post(NOTIFICATIONS_PATH, json={"payload": payload})


def _seed_refresh_token(stores: IdentityStores) -> str:
    """Give the Apple user a live session, returning its token hash."""
    stores.require_refresh_tokens().put(
        RefreshTokenRecord(
            token_hash="apple-session",
            family_id="apple-family",
            user_id=APPLE_USER_ID,
            generation=0,
            created_at="2026-01-01T00:00:00Z",
            expires_at=int(time.time()) + 3600,
        )
    )
    return "apple-session"


def _session_revoked(stores: IdentityStores, token_hash: str) -> bool:
    """Whether a seeded session has been revoked."""
    record = stores.require_refresh_tokens().get(token_hash)
    assert record is not None
    return record.revoked


def _notification_routes(router: Any) -> list[str]:
    """The paths mounted for Apple's notifications."""
    return [route.path for route in router.routes if route.path.endswith(OAUTH_APPLE_NOTIFICATIONS_PATH)]


def test_a_deployment_without_apple_mounts_no_notification_route(
    hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    """Every other product keeps exactly the routes its gateway already carries."""
    secrets = {GOOGLE_PROVIDER: GOOGLE_SECRET, GITHUB_PROVIDER: GITHUB_SECRET}
    assert _notification_routes(_providers_router(hooks, stores, kms, secrets=secrets)) == []


def test_an_apple_client_id_without_the_key_still_mounts_the_notification_route(
    hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    """Verifying needs only Apple's public keys, so a missing `.p8` does not lose an event."""
    secrets = {GOOGLE_PROVIDER: GOOGLE_SECRET}
    router = _providers_router(hooks, stores, kms, secrets=secrets, apple_client_id=APPLE_CLIENT_ID)
    assert _notification_routes(router) == [NOTIFICATIONS_PATH]


def test_a_configured_apple_mounts_the_notification_route(
    hooks: FakeHooks, stores: IdentityStores, kms: FakeKms, apple_key: ec.EllipticCurvePrivateKey
) -> None:
    """A complete configuration adds the route under the identity prefix."""
    secrets = {APPLE_PROVIDER: _apple_pem(apple_key)}
    router = _providers_router(hooks, stores, kms, secrets=secrets, **_apple_settings())
    assert _notification_routes(router) == [NOTIFICATIONS_PATH]


def test_a_notification_signed_with_another_key_is_refused(
    sealing_client: Any, provider: FakeProvider, link_stores: IdentityStores
) -> None:
    """A valid shape under the published `kid` is worth nothing without Apple's signature."""
    import jwt

    record = _seed_apple_link(link_stores)
    now = int(time.time())
    forged = jwt.encode(
        {
            "iss": APPLE_ISSUER,
            "aud": APPLE_CLIENT_ID,
            "iat": now,
            "events": {"type": "account-deleted", "sub": APPLE_SUB, "event_time": now},
        },
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        algorithm="RS256",
        headers={"kid": "test-key"},
    )
    response = _post_notification(sealing_client, forged)
    assert response.status_code == 400
    assert "OAUTH_NOTIFICATION_INVALID" in response.text
    assert link_stores.require_oauth_links().get(APPLE_LINK_KEY) == record


def test_a_symmetric_notification_is_refused_without_a_key_fetch(sealing_client: Any, provider: FakeProvider) -> None:
    """RS256 is pinned, so an attacker's choice of algorithm never reaches verification."""
    import jwt

    forged = jwt.encode(
        {"iss": APPLE_ISSUER, "aud": APPLE_CLIENT_ID, "iat": int(time.time()), "events": {}},
        "a-shared-secret-long-enough-to-pass-the-minimum-key-length-check",
        algorithm="HS256",
        headers={"kid": "test-key"},
    )
    assert _post_notification(sealing_client, forged).status_code == 400
    assert provider.requests == []


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "https://appleid.example.com"},
        {"aud": "com.example.other"},
        {"exp": 1000},
    ],
)
def test_a_notification_with_bad_claims_is_refused(
    claims: dict[str, Any], sealing_client: Any, provider: FakeProvider, link_stores: IdentityStores
) -> None:
    """The issuer and audience are checked, and an `exp`, when one is sent, is honoured."""
    record = _seed_apple_link(link_stores)
    response = _post_notification(sealing_client, _apple_notification(provider, "account-deleted", **claims))
    assert response.status_code == 400
    assert link_stores.require_oauth_links().get(APPLE_LINK_KEY) == record


def test_an_unpublished_kid_is_refused(sealing_client: Any, provider: FakeProvider) -> None:
    """A signature under a key Apple does not publish cannot be checked, so it fails."""
    import jwt

    forged = jwt.encode(
        {"iss": APPLE_ISSUER, "aud": APPLE_CLIENT_ID, "iat": int(time.time()), "events": {}},
        provider.key,
        algorithm="RS256",
        headers={"kid": "another-key"},
    )
    assert _post_notification(sealing_client, forged).status_code == 400


@pytest.mark.parametrize("body", [b"", b"not a jws", b'{"payload": 5}', b'["payload"]', b"x" * 100_000])
def test_a_body_without_a_payload_is_refused(body: bytes, sealing_client: Any, provider: FakeProvider) -> None:
    """Junk ends at the header check, and costs no fetch of Apple's keys."""
    response = sealing_client.post(NOTIFICATIONS_PATH, content=body)
    assert response.status_code == 400
    assert provider.requests == []


def test_an_outage_at_apple_invites_a_redelivery(
    sealing_client: Any, provider: FakeProvider, link_stores: IdentityStores
) -> None:
    """A JWKS failure says nothing about the notification, so it answers 503 rather than 400."""
    record = _seed_apple_link(link_stores)
    provider.jwks_status = 500
    response = _post_notification(sealing_client, _apple_notification(provider, "account-deleted"))
    assert response.status_code == 503
    assert "OAUTH_NOTIFICATION_FAILED" in response.text
    assert link_stores.require_oauth_links().get(APPLE_LINK_KEY) == record


def test_the_audience_allow_list_replaces_the_client_id(
    hooks: FakeHooks,
    link_stores: IdentityStores,
    kms: FakeKms,
    provider: FakeProvider,
    apple_key: ec.EllipticCurvePrivateKey,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Notifications registered on another App ID verify once that App ID is listed."""
    import webbpulse.identity.oauth as oauth_module

    fake_http = provider.client()
    monkeypatch.setattr(oauth_module, "HttpxClient", lambda: fake_http)
    router = _providers_router(
        hooks,
        link_stores,
        kms,
        secrets={APPLE_PROVIDER: _apple_pem(apple_key)},
        **_sealing_settings(apple_notification_audiences=["com.example.app"]),
    )
    client = _providers_client(router)
    allowed = _apple_notification(provider, "email-enabled", aud="com.example.app")
    assert _post_notification(client, allowed).status_code == 200
    assert _post_notification(client, _apple_notification(provider, "email-enabled")).status_code == 200
    stranger = _apple_notification(provider, "email-enabled", aud="com.example.other")
    assert _post_notification(client, stranger).status_code == 400


def test_email_disabled_and_enabled_flip_the_flag_on_the_link(
    sealing_client: Any, provider: FakeProvider, link_stores: IdentityStores
) -> None:
    """Both keep the link and the session, and take the address Apple sent."""
    _seed_apple_link(link_stores)
    session = _seed_refresh_token(link_stores)
    links = link_stores.require_oauth_links()

    disabled = _apple_notification(
        provider, "email-disabled", events={"email": "New@PrivateRelay.AppleID.com", "is_private_email": "true"}
    )
    assert _post_notification(sealing_client, disabled).json() == {"received": True}
    record = links.get(APPLE_LINK_KEY)
    assert record is not None
    assert record.provider_email_disabled is True
    assert record.provider_email == "new@privaterelay.appleid.com"

    assert _post_notification(sealing_client, _apple_notification(provider, "email-enabled")).status_code == 200
    record = links.get(APPLE_LINK_KEY)
    assert record is not None
    assert record.provider_email_disabled is False
    assert record.provider_email == "new@privaterelay.appleid.com"
    assert _session_revoked(link_stores, session) is False


def test_consent_revoked_ends_sessions_and_drops_the_token_but_keeps_the_link(
    sealing_client: Any, provider: FakeProvider, link_stores: IdentityStores
) -> None:
    """A returning user lands on the same account, and Apple has already killed the token."""
    from webbpulse.identity import PROVIDER_TOKEN_PURPOSE
    from webbpulse.identity.crypto import SecretMasterKeyCipher

    sealed = SecretMasterKeyCipher(base64.b64decode(APPLE_TOKEN_MASTER_KEY)).seal(
        APPLE_REFRESH_TOKEN.encode(), user_id=APPLE_USER_ID, purpose=PROVIDER_TOKEN_PURPOSE
    )
    _seed_apple_link(link_stores, provider_token=sealed)
    session = _seed_refresh_token(link_stores)

    assert _post_notification(sealing_client, _apple_notification(provider, "consent-revoked")).status_code == 200

    record = link_stores.require_oauth_links().get(APPLE_LINK_KEY)
    assert record is not None
    assert record.provider_token is None
    assert _session_revoked(link_stores, session) is True
    assert provider.apple_revocations == []


def test_account_deleted_ends_sessions_and_removes_the_link_but_not_the_user(
    sealing_client: Any, provider: FakeProvider, link_stores: IdentityStores, hooks: FakeHooks
) -> None:
    """Deleting the local account is the product's call, through the hook."""
    hooks.add(APPLE_RELAY_EMAIL, user_id=APPLE_USER_ID)
    _seed_apple_link(link_stores)
    session = _seed_refresh_token(link_stores)

    assert _post_notification(sealing_client, _apple_notification(provider, "account-deleted")).status_code == 200

    assert link_stores.require_oauth_links().get(APPLE_LINK_KEY) is None
    assert _session_revoked(link_stores, session) is True
    assert APPLE_USER_ID in hooks.users


def test_a_redelivered_deletion_is_harmless(
    sealing_client: Any, provider: FakeProvider, link_stores: IdentityStores
) -> None:
    """The second delivery finds no link and still answers 200."""
    _seed_apple_link(link_stores)
    payload = _apple_notification(provider, "account-deleted")
    assert _post_notification(sealing_client, payload).status_code == 200
    assert _post_notification(sealing_client, payload).status_code == 200


def test_a_failed_session_revocation_keeps_the_link_for_the_redelivery(
    hooks: FakeHooks, link_stores: IdentityStores, provider: FakeProvider, caplog: pytest.LogCaptureFixture
) -> None:
    """Sessions end first, so a failure there leaves something for the next delivery to find."""
    from webbpulse.identity import AppleNotifications

    record = _seed_apple_link(link_stores)

    def fail(user_id: str) -> None:
        """Stand in for a session store that is down."""
        raise RuntimeError("secret detail")

    notifications = AppleNotifications(
        make_settings(**_apple_settings()),
        hooks,
        links=link_stores.require_oauth_links(),
        http_client=provider.client(),
        other_sign_in=lambda user_id, *, removing: False,
    )
    with pytest.raises(OAuthRejected) as excinfo:
        notifications.handle(_apple_notification(provider, "account-deleted"), end_sessions=fail)
    assert excinfo.value.status_code == 503
    assert link_stores.require_oauth_links().get(APPLE_LINK_KEY) == record
    assert "secret detail" not in caplog.text


@pytest.mark.parametrize("event_type", ["consent-revoked", "account-deleted"])
def test_an_ending_event_older_than_the_last_sign_in_is_ignored(
    event_type: str, sealing_client: Any, provider: FakeProvider, link_stores: IdentityStores
) -> None:
    """It describes an authorization the user has since granted again."""
    record = _seed_apple_link(link_stores, last_login_at="2026-06-01T00:00:00+00:00")
    session = _seed_refresh_token(link_stores)
    payload = _apple_notification(provider, event_type, events={"event_time": 1_000_000})
    assert _post_notification(sealing_client, payload).status_code == 200
    assert link_stores.require_oauth_links().get(APPLE_LINK_KEY) == record
    assert _session_revoked(link_stores, session) is False


def test_an_event_time_in_milliseconds_reads_as_seconds(
    sealing_client: Any, provider: FakeProvider, link_stores: IdentityStores
) -> None:
    """Apple's sample uses seconds, and a millisecond stamp must not look like the far future."""
    _seed_apple_link(link_stores, last_login_at="2099-01-01T00:00:00+00:00")
    stale = _apple_notification(provider, "account-deleted", events={"event_time": int(time.time() * 1000)})
    assert _post_notification(sealing_client, stale).status_code == 200
    assert link_stores.require_oauth_links().get(APPLE_LINK_KEY) is not None


def test_events_arrive_as_an_object_or_a_json_string(
    sealing_client: Any, provider: FakeProvider, link_stores: IdentityStores
) -> None:
    """Apple documents an object, and integrators report an encoded string, so both work."""
    _seed_apple_link(link_stores)
    now = int(time.time())
    encoded = json.dumps({"type": "account-deleted", "sub": APPLE_SUB, "event_time": now})
    payload = _apple_notification(provider, "ignored", raw_events=encoded)
    assert _post_notification(sealing_client, payload).status_code == 200
    assert link_stores.require_oauth_links().get(APPLE_LINK_KEY) is None


@pytest.mark.parametrize("events", ["not json", 5, {"sub": APPLE_SUB}, {"type": "email-enabled"}])
def test_unreadable_events_are_refused(events: Any, sealing_client: Any, provider: FakeProvider) -> None:
    """A verified token without a type and a subject still gives nothing to act on."""
    payload = _apple_notification(provider, "ignored", raw_events=events)
    assert _post_notification(sealing_client, payload).status_code == 400


def test_a_form_encoded_payload_is_read_too(
    sealing_client: Any, provider: FakeProvider, link_stores: IdentityStores
) -> None:
    """Apple's delivery encoding is not fully documented, so the form spelling also works."""
    _seed_apple_link(link_stores)
    response = sealing_client.post(
        NOTIFICATIONS_PATH,
        content=urlencode({"payload": _apple_notification(provider, "account-deleted")}),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 200
    assert link_stores.require_oauth_links().get(APPLE_LINK_KEY) is None


def test_an_unknown_event_or_subject_is_acknowledged_and_changes_nothing(
    sealing_client: Any, provider: FakeProvider, link_stores: IdentityStores
) -> None:
    """Apple gets its 200, so it has no reason to keep delivering either."""
    record = _seed_apple_link(link_stores)
    unknown_type = _apple_notification(provider, "brand-new-event")
    unknown_subject = _apple_notification(provider, "account-deleted", events={"sub": "000000.someone.else"})
    assert _post_notification(sealing_client, unknown_type).status_code == 200
    assert _post_notification(sealing_client, unknown_subject).status_code == 200
    assert link_stores.require_oauth_links().get(APPLE_LINK_KEY) == record


def test_the_hook_sees_the_event_and_can_take_over(
    sealing_client: Any,
    provider: FakeProvider,
    link_stores: IdentityStores,
    hooks: FakeHooks,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Returning `True` skips the default, which is how a product deletes the account instead."""
    seen: list[ProviderAccountEvent] = []

    def take_over(event: ProviderAccountEvent) -> bool:
        """Record the event and claim it."""
        seen.append(event)
        return True

    monkeypatch.setattr(hooks, "on_provider_account_event", take_over)
    record = _seed_apple_link(link_stores)
    session = _seed_refresh_token(link_stores)
    payload = _apple_notification(
        provider, "account-deleted", events={"email": APPLE_RELAY_EMAIL, "is_private_email": "true"}
    )

    assert _post_notification(sealing_client, payload).status_code == 200

    assert link_stores.require_oauth_links().get(APPLE_LINK_KEY) == record
    assert _session_revoked(link_stores, session) is False
    event = seen[0]
    assert (event.provider, event.event_type, event.user_id) == (APPLE_PROVIDER, "account-deleted", APPLE_USER_ID)
    assert (event.subject, event.email) == (APPLE_SUB, APPLE_RELAY_EMAIL)
    assert event.is_private_email is True
    assert event.jwt_id == "notification-1"
    assert event.event_time > 0
    assert event.has_other_sign_in is False
    assert APPLE_SUB not in repr(event)
    assert APPLE_RELAY_EMAIL not in repr(event)


def test_the_hook_is_told_about_another_way_in(
    sealing_client: Any,
    provider: FakeProvider,
    link_stores: IdentityStores,
    hooks: FakeHooks,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The last-way-in check is what lets a product decide whether to delete the account."""
    seen: list[ProviderAccountEvent] = []

    def record_event(event: ProviderAccountEvent) -> None:
        """Record the event and let the default run."""
        seen.append(event)

    monkeypatch.setattr(hooks, "on_provider_account_event", record_event)
    _seed_apple_link(link_stores)
    link_stores.require_credentials().put(
        CredentialRecord(user_id=APPLE_USER_ID, credential_type=PASSWORD_CREDENTIAL_TYPE, secret="hashed")
    )

    assert _post_notification(sealing_client, _apple_notification(provider, "account-deleted")).status_code == 200

    assert seen[0].has_other_sign_in is True
    assert link_stores.require_oauth_links().get(APPLE_LINK_KEY) is None


def test_a_raising_hook_answers_503_and_applies_nothing(
    sealing_client: Any,
    provider: FakeProvider,
    link_stores: IdentityStores,
    hooks: FakeHooks,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A redelivery gets another chance at the product's policy."""

    def explode(event: ProviderAccountEvent) -> None:
        """Stand in for a product whose handler failed."""
        raise RuntimeError("product failure")

    monkeypatch.setattr(hooks, "on_provider_account_event", explode)
    record = _seed_apple_link(link_stores)
    response = _post_notification(sealing_client, _apple_notification(provider, "account-deleted"))
    assert response.status_code == 503
    assert "product failure" not in response.text
    assert link_stores.require_oauth_links().get(APPLE_LINK_KEY) == record


def test_a_notification_never_logs_the_jws_subject_or_email(
    sealing_client: Any, provider: FakeProvider, link_stores: IdentityStores, caplog: pytest.LogCaptureFixture
) -> None:
    """The log line carries the event type, the outcome and the user id, and nothing Apple sent."""
    import logging

    caplog.set_level(logging.DEBUG, logger="webbpulse.identity")
    _seed_apple_link(link_stores)
    payload = _apple_notification(provider, "email-disabled", events={"email": APPLE_RELAY_EMAIL})
    assert _post_notification(sealing_client, payload).status_code == 200
    rendered = " ".join(record.getMessage() + str(record.__dict__) for record in caplog.records)
    assert "oauth.apple_notification" in rendered
    assert payload not in rendered
    assert APPLE_SUB not in rendered
    assert APPLE_RELAY_EMAIL not in rendered


def test_an_apple_sign_in_seals_the_refresh_token_onto_the_link(
    sealing_client: Any, provider: FakeProvider, link_stores: IdentityStores
) -> None:
    """Only ciphertext reaches the row, and the record's repr hides even that."""
    provider.apple_refresh_token = APPLE_REFRESH_TOKEN
    state = _start_apple(sealing_client, provider)
    posted = _post_apple(sealing_client, {"state": state, "code": "abc"})
    response = sealing_client.get(posted.headers["location"], headers={"sec-fetch-site": "cross-site"})
    assert "oauth_error" not in response.headers["location"]

    link = link_stores.require_oauth_links().get(APPLE_LINK_KEY)
    assert link is not None
    assert link.provider_token is not None
    assert APPLE_REFRESH_TOKEN not in str(link.provider_token.as_item())
    assert "provider_token" not in repr(link)


def test_a_later_sign_in_keeps_or_replaces_the_stored_token(
    sealing_client: Any, provider: FakeProvider, link_stores: IdentityStores
) -> None:
    """Apple does not always send a new token, and losing the old one would strand it."""

    def sign_in() -> Any:
        """Run one sign-in and return the link it leaves."""
        state = _start_apple(sealing_client, provider)
        posted = _post_apple(sealing_client, {"state": state, "code": "abc"})
        sealing_client.get(posted.headers["location"], headers={"sec-fetch-site": "cross-site"})
        return link_stores.require_oauth_links().get(APPLE_LINK_KEY)

    provider.apple_refresh_token = APPLE_REFRESH_TOKEN
    first = sign_in().provider_token
    provider.apple_refresh_token = ""
    assert sign_in().provider_token == first
    provider.apple_refresh_token = "a-newer-token"
    assert sign_in().provider_token != first


def test_a_sign_in_with_no_cipher_still_works_and_stores_nothing(
    apple_client: Any, provider: FakeProvider, link_stores: IdentityStores
) -> None:
    """The token is a nicety for deletion, never a condition of signing in."""
    provider.apple_refresh_token = APPLE_REFRESH_TOKEN
    state = _start_apple(apple_client, provider)
    posted = _post_apple(apple_client, {"state": state, "code": "abc"})
    response = apple_client.get(posted.headers["location"], headers={"sec-fetch-site": "cross-site"})
    assert "oauth_error" not in response.headers["location"]
    link = link_stores.require_oauth_links().get(APPLE_LINK_KEY)
    assert link is not None
    assert link.provider_token is None


def test_a_token_is_sealed_only_for_a_provider_that_can_revoke(
    stores: IdentityStores, provider: FakeProvider, apple_key: ec.EllipticCurvePrivateKey
) -> None:
    """Google and GitHub stay identity sources with nothing stored."""
    tokens = _provider_tokens(stores, provider, apple_key)
    google = OAuthIdentity(
        provider=GOOGLE_PROVIDER,
        subject=GOOGLE_SUB,
        email=EMAIL,
        email_verified=True,
        provider_refresh_token=APPLE_REFRESH_TOKEN,
    )
    assert tokens.seal(google, APPLE_USER_ID) is None
    assert tokens.seal(_apple_identity(token=""), APPLE_USER_ID) is None


def test_the_identity_repr_hides_the_refresh_token() -> None:
    """A logged identity must not leak the token it carries."""
    assert APPLE_REFRESH_TOKEN not in repr(_apple_identity())


def test_revoking_presents_the_token_and_a_minted_client_secret(
    stores: IdentityStores, provider: FakeProvider, apple_key: ec.EllipticCurvePrivateKey
) -> None:
    """The request is Apple's documented form, and the token is opened only to send it."""
    import jwt

    tokens = _provider_tokens(stores, provider, apple_key)
    sealed = tokens.seal(_apple_identity(), APPLE_USER_ID)
    record = _seed_apple_link(stores, provider_token=sealed)

    assert tokens.revoke(record) is True

    sent = provider.apple_revocations[0]
    assert sent["client_id"] == APPLE_CLIENT_ID
    assert sent["token"] == APPLE_REFRESH_TOKEN
    assert sent["token_type_hint"] == "refresh_token"
    claims = jwt.decode(sent["client_secret"], options={"verify_signature": False})
    assert (claims["iss"], claims["sub"], claims["aud"]) == (APPLE_TEAM_ID, APPLE_CLIENT_ID, APPLE_ISSUER)


def test_a_refused_revoke_logs_and_does_not_raise(
    stores: IdentityStores,
    provider: FakeProvider,
    apple_key: ec.EllipticCurvePrivateKey,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The deletion carries on, and the log line is what is left of the attempt."""
    tokens = _provider_tokens(stores, provider, apple_key)
    record = _seed_apple_link(stores, provider_token=tokens.seal(_apple_identity(), APPLE_USER_ID))
    provider.apple_revoke_status = 400
    assert tokens.revoke(record) is False
    assert "A provider token could not be revoked." in caplog.text
    assert APPLE_REFRESH_TOKEN not in caplog.text


def test_a_network_failure_on_revoke_does_not_raise(
    stores: IdentityStores, provider: FakeProvider, apple_key: ec.EllipticCurvePrivateKey
) -> None:
    """A provider that cannot be reached is the same as one that refused."""
    from webbpulse.identity.oauth import HttpxClient

    def unreachable(request: httpx.Request) -> httpx.Response:
        """Fail the way a blocked egress path does."""
        raise httpx.ConnectError("no route")

    broken = HttpxClient(client=httpx.Client(transport=httpx.MockTransport(unreachable)))
    tokens = _provider_tokens(stores, provider, apple_key, client=broken)
    record = _seed_apple_link(stores, provider_token=tokens.seal(_apple_identity(), APPLE_USER_ID))
    assert tokens.revoke(record) is False


def test_a_token_sealed_for_one_user_does_not_open_for_another(
    stores: IdentityStores, provider: FakeProvider, apple_key: ec.EllipticCurvePrivateKey
) -> None:
    """The cipher binds the token to its user, so a moved row sends nothing to Apple."""
    tokens = _provider_tokens(stores, provider, apple_key)
    sealed = tokens.seal(_apple_identity(), "someone-else")
    record = _seed_apple_link(stores, provider_token=sealed)
    assert tokens.revoke(record) is False
    assert provider.apple_revocations == []


def test_revoke_stored_refuses_a_link_that_is_no_longer_this_users(
    stores: IdentityStores, provider: FakeProvider, apple_key: ec.EllipticCurvePrivateKey
) -> None:
    """A stale index hit must not revoke the token of whoever holds the link now."""
    tokens = _provider_tokens(stores, provider, apple_key)
    _seed_apple_link(stores, provider_token=tokens.seal(_apple_identity(), APPLE_USER_ID))
    assert tokens.revoke_stored(APPLE_LINK_KEY, user_id="someone-else") is False
    assert tokens.revoke_stored("apple#missing", user_id=APPLE_USER_ID) is False
    assert provider.apple_revocations == []


def test_unlinking_apple_revokes_its_token_first(
    hooks: FakeHooks, stores: IdentityStores, provider: FakeProvider, apple_key: ec.EllipticCurvePrivateKey
) -> None:
    """Removing the link would otherwise leave the app authorized with no way to end it."""
    secrets = {APPLE_PROVIDER: _apple_pem(apple_key)}
    settings = make_settings(**_sealing_settings())
    tokens = _provider_tokens(stores, provider, apple_key)
    _seed_apple_link(stores, provider_token=tokens.seal(_apple_identity(), APPLE_USER_ID))
    stores.require_credentials().put(
        CredentialRecord(user_id=APPLE_USER_ID, credential_type=PASSWORD_CREDENTIAL_TYPE, secret="hashed")
    )
    service = OAuthService(
        settings,
        hooks,
        states=stores.require_oauth_states(),
        links=stores.require_oauth_links(),
        credentials=stores.require_credentials(),
        client_secrets=secrets,
        http_client=provider.client(),
    )

    service.unlink(user_id=APPLE_USER_ID, provider=APPLE_PROVIDER)

    assert stores.require_oauth_links().get(APPLE_LINK_KEY) is None
    assert provider.apple_revocations[0]["token"] == APPLE_REFRESH_TOKEN


def test_the_dynamo_link_store_round_trips_the_token_and_the_flag(
    oauth_tables: dict[str, Any], stores: IdentityStores, provider: FakeProvider, apple_key: ec.EllipticCurvePrivateKey
) -> None:
    """A sealed token and a disabled address survive the table, and absent ones stay absent."""
    from webbpulse.dynamodb import Repository

    links = DynamoOAuthLinkStore(Repository("oauth-links", prefix="test"))
    sealed = _provider_tokens(stores, provider, apple_key).seal(_apple_identity(), APPLE_USER_ID)
    record = _seed_apple_link(stores, provider_token=sealed, provider_email_disabled=True)
    links.put(record)
    assert links.get(APPLE_LINK_KEY) == record

    plain = _seed_apple_link(stores, provider_subject="apple#plain")
    links.put(plain)
    stored = links.get("apple#plain")
    assert stored is not None
    assert stored.provider_token is None
    assert stored.provider_email_disabled is False
