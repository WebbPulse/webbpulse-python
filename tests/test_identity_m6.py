"""Tests for the M6 identity work: OAuth sign-in, account linking, and the two new tables.

Section 9.4 of `docs/identity-standard.md` sets the strategy. Four things shape this file in
ways the M2 through M4 suites did not need:

- **The provider is mocked at the HTTP boundary, not above it.** Every provider call goes
  through an `httpx.MockTransport` serving hand-written responses, so the code under test
  builds a real request, encodes a real form body and parses a real JSON response. Stubbing
  `OAuthService._identity_from_id_token` instead would leave the actual parsing, the actual
  header handling and the actual GitHub two-call sequence untested, which is most of what
  can go wrong in this module.
- **Both halves of the auto-link rule get their own test.** The locked decision is that an
  OAuth identity attaches to an existing account only when the provider email **and** the
  local account email are verified. Those are two independent conditions and a test that
  only exercised one would pass against an implementation that checked only the other. So
  there is a test per side, plus one for the case where both hold.
- **Unlink is tested by counting down to the last method.** The refusal only fires in one
  state, and a test that unlinks a provider from an account with a password proves nothing
  about it. Each remaining-method source gets a test: another link, a password, and the
  `has_other_sign_in_method` hook.
- **Single use is tested by using twice.** The state row is spent by the callback, so every
  state test that matters replays it. A happy-path-only test passes against an
  implementation with no replay defence at all.

The KMS signing fake is M2's, redefined here rather than imported: `tests/` is not a package.

Google's ID token is signed with a real RSA key and served through a real JWKS document, so
`PyJWKClient` does the key lookup it does in production and the signature check is a real
one. An unsigned token or a monkeypatched `jwt.decode` would let the most important
assertion in the file, that a forged ID token is refused, pass vacuously.
"""

from __future__ import annotations

import base64
import time
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

import pytest

from webbpulse.identity import (
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
    InMemoryRecoveryCodeStore,
    InMemoryRefreshTokenStore,
    InMemoryTotpFactorStore,
    OAuthIdentity,
    OAuthRejected,
    OAuthService,
    OAuthStateRecord,
    TokenService,
    build_identity_router,
    identity_prefix,
    new_pkce_verifier,
    pkce_challenge,
    provider_account_key,
)
from webbpulse.identity.flows import PASSWORD_CREDENTIAL_TYPE, IdentityFlows, MfaChallengeRequired
from webbpulse.identity.oauth import AMR_OAUTH, GITHUB_PROVIDER, GOOGLE_PROVIDER

if TYPE_CHECKING:
    from collections.abc import Iterator

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from fastapi import FastAPI
from fastapi.testclient import TestClient

KEY_A = "arn:aws:kms:us-west-2:111122223333:key/aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa"
DATA_KEY = "arn:aws:kms:us-west-2:111122223333:key/dddddddd-4444-4444-4444-dddddddddddd"
ISSUER = "https://api.staging.example.com/api/auth"
AUDIENCE = "webbpulse-staging"
FRONTEND = "https://staging.example.com"

GOOGLE_CLIENT_ID = "1234567890-abcdefg.apps.googleusercontent.com"
GITHUB_CLIENT_ID = "Iv1.0123456789abcdef"
GOOGLE_SECRET = "google-client-secret-value"
GITHUB_SECRET = "github-client-secret-value"

EMAIL = "person@example.com"
GOOGLE_SUB = "115538274652819374652"
GITHUB_SUB = "8675309"


# ---------------------------------------------------------------------------
# KMS fake, signing only. M2's, unchanged.
# ---------------------------------------------------------------------------


class FakeKms:
    """Signs with a local private key, so `TokenService` mints verifiable tokens."""

    def __init__(self, keys: dict[str, rsa.RSAPrivateKey]) -> None:
        self._keys = keys

    def get_public_key(self, *, KeyId: str) -> dict[str, Any]:
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

    def sign(
        self, *, KeyId: str, Message: bytes, MessageType: str, SigningAlgorithm: str
    ) -> dict[str, Any]:
        signature = self._keys[KeyId].sign(
            Message, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
        )
        return {"KeyId": KeyId, "Signature": signature, "SigningAlgorithm": SigningAlgorithm}

    def generate_data_key(
        self, *, KeyId: str, NumberOfBytes: int, EncryptionContext: Mapping[str, str]
    ) -> dict[str, Any]:
        """Envelope encryption, for the MFA path an OAuth login has to honour."""
        import secrets

        plaintext = secrets.token_bytes(NumberOfBytes)
        blob = base64.b64encode(plaintext) + b"|" + _context_bytes(EncryptionContext)
        return {"KeyId": KeyId, "Plaintext": plaintext, "CiphertextBlob": blob}

    def decrypt(
        self, *, CiphertextBlob: bytes, EncryptionContext: Mapping[str, str]
    ) -> dict[str, Any]:
        try:
            encoded, context = CiphertextBlob.split(b"|", 1)
        except ValueError as exc:
            raise RuntimeError("InvalidCiphertextException") from exc
        if context != _context_bytes(EncryptionContext):
            raise RuntimeError("InvalidCiphertextException")
        return {"KeyId": DATA_KEY, "Plaintext": base64.b64decode(encoded)}


def _context_bytes(context: Mapping[str, str]) -> bytes:
    return repr(sorted(context.items())).encode("utf-8")


# ---------------------------------------------------------------------------
# The provider, mocked at the HTTP boundary
# ---------------------------------------------------------------------------


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class FakeProvider:
    """An `httpx.MockTransport` standing in for Google and GitHub.

    Routes by URL, so the code under test builds and sends the request it would send in
    production and this only supplies the answer. Every knob a test needs to turn is an
    attribute: the ID token claims, whether the token endpoint fails, what `/user/emails`
    returns.

    Google's ID token is genuinely signed with `key`, and `jwks` serves the matching public
    key at the URL `PROVIDERS["google"].jwks_url` names, so `PyJWKClient` performs a real
    lookup and `jwt.decode` performs a real signature verification.
    """

    def __init__(self, key: rsa.RSAPrivateKey) -> None:
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
        #: The nonce the ID token echoes back. The token endpoint never receives the nonce,
        #: so the fake cannot read it off the request: a test that wants a token to verify
        #: sets this to the nonce from its own state row, and a test of the mismatch path
        #: leaves it alone or overrides the token outright.
        self.nonce_to_echo = ""

    # ---- key material ----------------------------------------------------------------

    def jwks(self) -> dict[str, Any]:
        numbers = self.key.public_key().public_numbers()

        def to_b64(value: int) -> str:
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

    # ---- the transport ----------------------------------------------------------------

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = str(request.url)

        if url == PROVIDERS[GOOGLE_PROVIDER].jwks_url:
            return httpx.Response(200, json=self.jwks())

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
            return httpx.Response(
                self.token_status, json={"access_token": "gho_test", "token_type": "bearer"}
            )

        if url == PROVIDERS[GITHUB_PROVIDER].userinfo_url:
            return httpx.Response(200, json=self.github_user)

        if url == PROVIDERS[GITHUB_PROVIDER].emails_url:
            return httpx.Response(self.github_emails_status, json=self.github_emails)

        return httpx.Response(404, json={"error": "unexpected_url", "url": url})

    def client(self) -> Any:
        from webbpulse.identity.oauth import HttpxClient

        return HttpxClient(client=httpx.Client(transport=httpx.MockTransport(self.handler)))


def _parse_form(request: httpx.Request) -> dict[str, str]:
    from urllib.parse import parse_qsl

    return dict(parse_qsl(request.content.decode()))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def cheap_bcrypt(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Pin bcrypt to its minimum cost for the whole module. M2's fixture, unchanged."""
    import webbpulse.security as security

    real_hash = security.hash_password
    real_needs = security.needs_rehash

    def cheap(password: str, *, rounds: int = 4) -> str:
        return real_hash(password, rounds=rounds)

    def needs(hashed: str, *, rounds: int = 4) -> bool:
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
    """A second key, standing in for Google's signing key.

    Separate from `module_key` on purpose. If the provider signed with the same key this
    service signs with, a test asserting that a forged ID token is refused could pass for
    the wrong reason.
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def kms(module_key: rsa.RSAPrivateKey) -> FakeKms:
    return FakeKms({KEY_A: module_key})


@pytest.fixture
def provider(provider_key: rsa.RSAPrivateKey) -> FakeProvider:
    return FakeProvider(provider_key)


def make_settings(**overrides: Any) -> IdentitySettings:
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
    """A product's policy, in memory. M4's fake plus M6's optional hook."""

    def __init__(self, *, refuse: str = "") -> None:
        self.users: dict[str, dict[str, Any]] = {}
        self.by_email: dict[str, str] = {}
        self.refuse = refuse
        self.calls: list[str] = []
        self.created_via: list[str] = []
        self.extra_sign_in_methods = False
        self._next = 1

    def add(self, email: str, *, user_id: str = "", **attributes: Any) -> dict[str, Any]:
        identifier = user_id or f"user-{self._next:04d}"
        self._next += 1
        user = {"id": identifier, "email": email, **attributes}
        self.users[identifier] = user
        self.by_email[email.lower()] = identifier
        return user

    def load_user_by_id(self, user_id: str) -> Mapping[str, Any] | None:
        self.calls.append("load_user_by_id")
        return self.users.get(user_id)

    def load_user_by_email(self, email: str) -> Mapping[str, Any] | None:
        self.calls.append("load_user_by_email")
        identifier = self.by_email.get(email.lower())
        return self.users.get(identifier) if identifier else None

    def may_authenticate(self, user: Mapping[str, Any]) -> None:
        self.calls.append("may_authenticate")
        if self.refuse:
            raise AuthenticationRefused(self.refuse, error_code="ACCOUNT_DISABLED")

    def claims_for(self, user: Mapping[str, Any]) -> Mapping[str, Any]:
        # Deliberately tries to forge both, as M4's fake does. `_mint_access` must overwrite.
        return {"amr": ["forged"], "auth_time": 1}

    def create_user(self, *, email: str, attributes: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls.append("create_user")
        return self.add(email, **dict(attributes))

    def on_user_created(self, user: Mapping[str, Any], via: str) -> None:
        self.created_via.append(via)

    def has_other_sign_in_method(self, user_id: str) -> bool:
        self.calls.append("has_other_sign_in_method")
        return self.extra_sign_in_methods


@pytest.fixture
def hooks() -> FakeHooks:
    return FakeHooks()


@pytest.fixture
def stores() -> IdentityStores:
    return IdentityStores(
        credentials=InMemoryCredentialStore(),
        refresh_tokens=InMemoryRefreshTokenStore(),
        oauth_states=InMemoryOAuthStateStore(),
        oauth_links=InMemoryOAuthLinkStore(),
    )


@pytest.fixture
def oauth(hooks: FakeHooks, stores: IdentityStores, provider: FakeProvider) -> OAuthService:
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
    """Drive a Google start-then-callback and return the identity it resolved.

    A helper rather than repetition, because almost every test needs a completed provider
    leg before it can assert on the interesting part, and doing it by hand each time would
    bury the assertion.
    """
    authorization = oauth.start(GOOGLE_PROVIDER, mode=mode, user_id=user_id)  # type: ignore[arg-type]
    record = oauth.consume_state(authorization.state)
    provider.nonce_to_echo = record.nonce
    return oauth.identity_from_callback(GOOGLE_PROVIDER, code="auth-code", state_record=record)


# ---------------------------------------------------------------------------
# PKCE
# ---------------------------------------------------------------------------


def test_pkce_verifier_meets_the_rfc_length_and_alphabet() -> None:
    """RFC 7636 requires 43 to 128 characters from the unreserved set."""
    verifier = new_pkce_verifier()
    assert 43 <= len(verifier) <= 128
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
    assert set(verifier) <= allowed


def test_pkce_challenge_matches_the_rfc_7636_worked_example() -> None:
    """Appendix B of RFC 7636 publishes one verifier and its S256 challenge.

    Checking the challenge against our own implementation of the challenge would pass while
    both were wrong in the same direction, and the provider would be the one to disagree.
    """
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert pkce_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_pkce_verifiers_are_unique_per_start() -> None:
    assert new_pkce_verifier() != new_pkce_verifier()


# ---------------------------------------------------------------------------
# Provider metadata
# ---------------------------------------------------------------------------


def test_google_offers_pkce_and_an_id_token_and_github_offers_neither() -> None:
    """The per-provider flags are the whole reason the provider table exists.

    GitHub's web flow documents no `code_challenge` and returns no ID token. Sending a
    challenge it ignores would be security theatre, and expecting an ID token it never sends
    would break every GitHub sign-in.
    """
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


# ---------------------------------------------------------------------------
# start
# ---------------------------------------------------------------------------


def test_start_builds_a_google_url_with_pkce_and_a_nonce(oauth: OAuthService) -> None:
    from urllib.parse import parse_qs, urlsplit

    authorization = oauth.start(GOOGLE_PROVIDER)
    parts = urlsplit(authorization.authorization_url)
    params = {key: value[0] for key, value in parse_qs(parts.query).items()}

    assert (
        f"{parts.scheme}://{parts.netloc}{parts.path}" == PROVIDERS[GOOGLE_PROVIDER].authorize_url
    )
    assert params["client_id"] == GOOGLE_CLIENT_ID
    assert params["response_type"] == "code"
    assert params["code_challenge_method"] == "S256"
    assert params["state"] == authorization.state
    assert params["nonce"]
    assert "openid" in params["scope"]


def test_start_sends_the_challenge_and_never_the_verifier(oauth: OAuthService) -> None:
    """The verifier is the one value that must not reach the browser.

    If it went in the authorization URL, PKCE would protect against nothing: anyone who
    could intercept the code could read the verifier from the same place.
    """
    from urllib.parse import parse_qs, urlsplit

    authorization = oauth.start(GOOGLE_PROVIDER)
    params = {k: v[0] for k, v in parse_qs(urlsplit(authorization.authorization_url).query).items()}
    record = oauth.consume_state(authorization.state)

    assert record.pkce_verifier
    assert record.pkce_verifier not in authorization.authorization_url
    assert params["code_challenge"] == pkce_challenge(record.pkce_verifier)


def test_start_omits_pkce_and_nonce_for_github(oauth: OAuthService) -> None:
    authorization = oauth.start(GITHUB_PROVIDER)
    assert "code_challenge" not in authorization.authorization_url
    assert "nonce" not in authorization.authorization_url
    record = oauth.consume_state(authorization.state)
    assert record.pkce_verifier == ""
    assert record.nonce == ""


def test_start_writes_a_state_row_with_the_ten_minute_ttl(oauth: OAuthService) -> None:
    before = int(time.time())
    authorization = oauth.start(GOOGLE_PROVIDER)
    record = oauth.consume_state(authorization.state)
    assert (
        before + OAUTH_STATE_TTL_SECONDS - 5
        <= record.expires_at
        <= before + OAUTH_STATE_TTL_SECONDS + 5
    )


def test_two_starts_produce_different_states(oauth: OAuthService) -> None:
    assert oauth.start(GOOGLE_PROVIDER).state != oauth.start(GOOGLE_PROVIDER).state


def test_a_link_start_requires_a_user_id(oauth: OAuthService) -> None:
    """A `link` with no authenticated subject has no account to attach to."""
    with pytest.raises(OAuthRejected) as excinfo:
        oauth.start(GOOGLE_PROVIDER, mode="link")
    assert excinfo.value.status_code == 401


def test_a_login_state_never_carries_a_user_id(oauth: OAuthService) -> None:
    """The property that stops a login callback being replayed as a link.

    A login state with no user id on it means there is no account for a replayed callback
    to attach a provider identity to.
    """
    authorization = oauth.start(GOOGLE_PROVIDER, mode="login", user_id="user-0001")
    assert oauth.consume_state(authorization.state).user_id == ""


def test_an_unconfigured_provider_is_not_available(
    hooks: FakeHooks, stores: IdentityStores
) -> None:
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
    with pytest.raises(OAuthRejected):
        oauth.start("facebook")


# ---------------------------------------------------------------------------
# The redirect URI allow-list
# ---------------------------------------------------------------------------


def test_a_redirect_uri_outside_the_allow_list_is_refused(
    hooks: FakeHooks, stores: IdentityStores
) -> None:
    """The parameter a provider sends a live authorization code to. It is not a suggestion."""
    settings = make_settings(oauth_redirect_uris=[f"{ISSUER}/oauth/callback"])
    service = OAuthService(
        settings, hooks, states=stores.require_oauth_states(), links=stores.require_oauth_links()
    )
    with pytest.raises(OAuthRejected) as excinfo:
        service.start(GOOGLE_PROVIDER, redirect_uri="https://attacker.test/steal")
    assert excinfo.value.error_code == "OAUTH_REDIRECT_NOT_ALLOWED"


def test_the_allow_list_is_exact_and_not_a_prefix(hooks: FakeHooks, stores: IdentityStores) -> None:
    """`https://app.example.com.attacker.test` is a domain an attacker can register today.

    A prefix match on the allowed origin would admit it, which is why the check is string
    equality.
    """
    allowed = "https://app.example.com/oauth/callback"
    settings = make_settings(oauth_redirect_uris=[allowed])
    service = OAuthService(
        settings, hooks, states=stores.require_oauth_states(), links=stores.require_oauth_links()
    )
    with pytest.raises(OAuthRejected):
        service.start(GOOGLE_PROVIDER, redirect_uri="https://app.example.com.attacker.test/cb")
    # The exact value still works, so the check is not simply refusing everything.
    assert service.start(GOOGLE_PROVIDER, redirect_uri=allowed).authorization_url


def test_an_allowed_redirect_uri_is_stored_and_replayed_on_the_exchange(
    oauth: OAuthService, provider: FakeProvider
) -> None:
    """The provider refuses an exchange whose `redirect_uri` differs by a byte."""
    run_google_callback(oauth, provider)
    exchange = next(
        request
        for request in provider.requests
        if str(request.url) == PROVIDERS[GOOGLE_PROVIDER].token_url
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
    authorization = oauth.start(GOOGLE_PROVIDER, return_to="/settings/security")
    assert oauth.consume_state(authorization.state).return_to == f"{FRONTEND}/settings/security"


# ---------------------------------------------------------------------------
# state: single use, expiry, provider binding
# ---------------------------------------------------------------------------


def test_a_state_can_be_spent_only_once(oauth: OAuthService) -> None:
    """The replay defence. A happy-path-only test passes without one."""
    authorization = oauth.start(GOOGLE_PROVIDER)
    assert oauth.consume_state(authorization.state).state == authorization.state
    with pytest.raises(OAuthRejected) as excinfo:
        oauth.consume_state(authorization.state)
    assert excinfo.value.error_code == "OAUTH_STATE_INVALID"


def test_an_unknown_state_is_refused(oauth: OAuthService) -> None:
    with pytest.raises(OAuthRejected):
        oauth.consume_state("not-a-real-state")


def test_an_empty_state_is_refused(oauth: OAuthService) -> None:
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


# ---------------------------------------------------------------------------
# Google: the ID token is verified properly
# ---------------------------------------------------------------------------


def test_a_google_callback_yields_a_verified_identity(
    oauth: OAuthService, provider: FakeProvider
) -> None:
    identity = run_google_callback(oauth, provider)
    assert identity.provider == GOOGLE_PROVIDER
    assert identity.subject == GOOGLE_SUB
    assert identity.email == EMAIL
    assert identity.email_verified is True


def test_the_exchange_sends_the_pkce_verifier_and_the_client_secret(
    oauth: OAuthService, provider: FakeProvider
) -> None:
    run_google_callback(oauth, provider)
    form = _parse_form(
        next(r for r in provider.requests if str(r.url) == PROVIDERS[GOOGLE_PROVIDER].token_url)
    )
    assert form["grant_type"] == "authorization_code"
    assert form["code"] == "auth-code"
    assert form["client_secret"] == GOOGLE_SECRET
    assert form["code_verifier"]
    assert pkce_challenge(form["code_verifier"])


def test_an_id_token_signed_by_the_wrong_key_is_refused(
    oauth: OAuthService, provider: FakeProvider, module_key: rsa.RSAPrivateKey
) -> None:
    """The single most important assertion in this file.

    An ID token verified by decoding without checking the signature turns the whole flow
    into "anybody who can reach the callback is anybody they say they are".
    """
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
        module_key,  # not the provider's key
        algorithm="RS256",
        headers={"kid": "test-key"},
    )
    with pytest.raises(OAuthRejected) as excinfo:
        oauth.identity_from_callback(GOOGLE_PROVIDER, code="c", state_record=record)
    assert excinfo.value.error_code == "OAUTH_ID_TOKEN_INVALID"


def test_an_id_token_for_another_audience_is_refused(
    oauth: OAuthService, provider: FakeProvider
) -> None:
    """A token minted for a different client id is a token from a different application."""
    authorization = oauth.start(GOOGLE_PROVIDER)
    record = oauth.consume_state(authorization.state)
    provider.id_token_override = provider.id_token(nonce=record.nonce, aud="someone-else.apps")
    with pytest.raises(OAuthRejected):
        oauth.identity_from_callback(GOOGLE_PROVIDER, code="c", state_record=record)


def test_an_id_token_from_another_issuer_is_refused(
    oauth: OAuthService, provider: FakeProvider
) -> None:
    authorization = oauth.start(GOOGLE_PROVIDER)
    record = oauth.consume_state(authorization.state)
    provider.id_token_override = provider.id_token(nonce=record.nonce, iss="https://evil.test")
    with pytest.raises(OAuthRejected):
        oauth.identity_from_callback(GOOGLE_PROVIDER, code="c", state_record=record)


def test_an_expired_id_token_is_refused(oauth: OAuthService, provider: FakeProvider) -> None:
    authorization = oauth.start(GOOGLE_PROVIDER)
    record = oauth.consume_state(authorization.state)
    now = int(time.time())
    provider.id_token_override = provider.id_token(
        nonce=record.nonce, iat=now - 7200, exp=now - 3600
    )
    with pytest.raises(OAuthRejected):
        oauth.identity_from_callback(GOOGLE_PROVIDER, code="c", state_record=record)


def test_a_replayed_id_token_with_the_wrong_nonce_is_refused(
    oauth: OAuthService, provider: FakeProvider
) -> None:
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
    authorization = service.start(GOOGLE_PROVIDER)
    record = service.consume_state(authorization.state)
    with pytest.raises(OAuthRejected) as excinfo:
        service.identity_from_callback(GOOGLE_PROVIDER, code="c", state_record=record)
    assert excinfo.value.status_code == 503
    assert "secret" not in excinfo.value.message.lower()


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


# ---------------------------------------------------------------------------
# GitHub: two calls, and the verified-primary rule
# ---------------------------------------------------------------------------


def test_github_identity_comes_from_user_and_user_emails(
    oauth: OAuthService, provider: FakeProvider
) -> None:
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
    """`/user`'s `email` is the public profile address: user-chosen and never verified.

    Only `/user/emails` says which address GitHub confirmed, and the auto-link rule depends
    on that being a real assertion.
    """
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


def test_github_reports_an_unverified_address_as_unverified(
    oauth: OAuthService, provider: FakeProvider
) -> None:
    provider.github_emails = [{"email": EMAIL, "primary": True, "verified": False}]
    authorization = oauth.start(GITHUB_PROVIDER)
    record = oauth.consume_state(authorization.state)
    identity = oauth.identity_from_callback(GITHUB_PROVIDER, code="c", state_record=record)

    assert identity.email == EMAIL
    assert identity.email_verified is False


def test_a_github_exchange_sends_no_pkce_verifier(
    oauth: OAuthService, provider: FakeProvider
) -> None:
    authorization = oauth.start(GITHUB_PROVIDER)
    record = oauth.consume_state(authorization.state)
    oauth.identity_from_callback(GITHUB_PROVIDER, code="c", state_record=record)
    form = _parse_form(
        next(r for r in provider.requests if str(r.url) == PROVIDERS[GITHUB_PROVIDER].token_url)
    )
    assert "code_verifier" not in form


def test_the_github_exchange_asks_for_json(oauth: OAuthService, provider: FakeProvider) -> None:
    """GitHub answers form-encoded unless asked, and a form body parses as no body at all."""
    authorization = oauth.start(GITHUB_PROVIDER)
    record = oauth.consume_state(authorization.state)
    oauth.identity_from_callback(GITHUB_PROVIDER, code="c", state_record=record)
    request = next(
        r for r in provider.requests if str(r.url) == PROVIDERS[GITHUB_PROVIDER].token_url
    )
    assert request.headers["accept"] == "application/json"


# ---------------------------------------------------------------------------
# The auto-link rule: the heart of M6
# ---------------------------------------------------------------------------


def test_a_known_link_signs_the_user_in(
    oauth: OAuthService, provider: FakeProvider, hooks: FakeHooks
) -> None:
    user = hooks.add(EMAIL, email_verified=True)
    identity = run_google_callback(oauth, provider)
    oauth.link(identity, user_id=str(user["id"]))

    resolved, outcome = oauth.resolve_login(identity)
    assert outcome == "linked"
    assert resolved["id"] == user["id"]


def test_both_sides_verified_auto_links(
    oauth: OAuthService, provider: FakeProvider, hooks: FakeHooks
) -> None:
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
    """The provider is asserting an address the user typed and nobody checked.

    Registering a GitHub account with somebody else's address would otherwise take over
    their account.
    """
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
    """Takeover in the other direction, and the half that is easy to forget.

    An attacker who registered locally with a victim's address, unverified, would otherwise
    be handed the victim's real Google identity.
    """
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
    identity_b = OAuthIdentity(
        provider=GOOGLE_PROVIDER, subject="other", email=EMAIL, email_verified=False
    )
    with pytest.raises(OAuthRejected) as second:
        oauth.resolve_login(identity_b)

    assert first.value.message == second.value.message
    assert first.value.error_code == second.value.error_code


def test_an_unknown_identity_registers_a_new_account(
    oauth: OAuthService, provider: FakeProvider, hooks: FakeHooks
) -> None:
    identity = run_google_callback(oauth, provider)
    user, outcome = oauth.resolve_login(identity)

    assert outcome == "registered"
    assert user["email"] == EMAIL
    assert user["email_verified"] is True
    assert hooks.created_via == [GOOGLE_PROVIDER]


def test_a_registration_carries_the_providers_verification_state(
    oauth: OAuthService, provider: FakeProvider
) -> None:
    """An unverified provider address gives an unverified local account, not a trusted one."""
    provider.claims_override = {"email_verified": False}
    identity = run_google_callback(oauth, provider)
    user, outcome = oauth.resolve_login(identity)

    assert outcome == "registered"
    assert user["email_verified"] is False


def test_registration_can_be_switched_off(
    hooks: FakeHooks, stores: IdentityStores, provider: FakeProvider
) -> None:
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
    identity = OAuthIdentity(
        provider=GITHUB_PROVIDER, subject=GITHUB_SUB, email="", email_verified=False
    )
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


# ---------------------------------------------------------------------------
# link and list
# ---------------------------------------------------------------------------


def test_link_attaches_to_the_authenticated_account_without_an_email_check(
    oauth: OAuthService, provider: FakeProvider, hooks: FakeHooks
) -> None:
    """The path a refused auto-link sends people to.

    The user proved they hold the account with a token and the provider account with the
    provider's own flow, so no email needs to match at all.
    """
    user = hooks.add("different@example.com", email_verified=False)
    identity = run_google_callback(oauth, provider)

    record = oauth.link(identity, user_id=str(user["id"]))
    assert record.user_id == user["id"]
    assert record.provider_email == EMAIL


def test_linking_an_already_linked_identity_is_refused(
    oauth: OAuthService, provider: FakeProvider, hooks: FakeHooks
) -> None:
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
    mine = hooks.add("mine@example.com", email_verified=True)
    theirs = hooks.add("theirs@example.com", email_verified=True)
    oauth.link(
        OAuthIdentity(GOOGLE_PROVIDER, "sub-a", "a@example.com", True), user_id=str(mine["id"])
    )
    oauth.link(
        OAuthIdentity(GITHUB_PROVIDER, "sub-b", "b@example.com", True), user_id=str(mine["id"])
    )
    oauth.link(
        OAuthIdentity(GOOGLE_PROVIDER, "sub-c", "c@example.com", True), user_id=str(theirs["id"])
    )

    assert [r.provider for r in oauth.list_links(str(mine["id"]))] == [
        GITHUB_PROVIDER,
        GOOGLE_PROVIDER,
    ]
    assert len(oauth.list_links(str(theirs["id"]))) == 1


def test_no_provider_tokens_are_stored(
    oauth: OAuthService, provider: FakeProvider, hooks: FakeHooks
) -> None:
    """This design consumes a provider as an identity source and never calls its API.

    A stored token nobody spends is a stored credential with no use, which is all cost.
    """
    import dataclasses

    user = hooks.add(EMAIL, email_verified=True)
    identity = run_google_callback(oauth, provider)
    record = oauth.link(identity, user_id=str(user["id"]))

    values = " ".join(str(value) for value in dataclasses.asdict(record).values())
    assert "google-access" not in values
    assert "gho_test" not in values
    fields = {field.name for field in dataclasses.fields(record)}
    assert not {"access_token", "refresh_token", "provider_token"} & fields


# ---------------------------------------------------------------------------
# unlink: the last sign-in method
# ---------------------------------------------------------------------------


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
    user = hooks.add(EMAIL, email_verified=True)
    oauth.link(OAuthIdentity(GOOGLE_PROVIDER, "g", EMAIL, True), user_id=str(user["id"]))
    oauth.link(OAuthIdentity(GITHUB_PROVIDER, "h", EMAIL, True), user_id=str(user["id"]))

    oauth.unlink(user_id=str(user["id"]), provider=GOOGLE_PROVIDER)
    assert [r.provider for r in oauth.list_links(str(user["id"]))] == [GITHUB_PROVIDER]


def test_unlink_allows_it_when_a_password_remains(
    oauth: OAuthService, stores: IdentityStores, hooks: FakeHooks
) -> None:
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


def test_unlink_allows_it_when_the_hook_reports_a_passkey(
    oauth: OAuthService, hooks: FakeHooks
) -> None:
    """Passkeys are M5's table, which this module cannot see, so the product is asked."""
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


def test_unlinking_a_provider_that_is_not_linked_is_a_404(
    oauth: OAuthService, hooks: FakeHooks
) -> None:
    user = hooks.add(EMAIL, email_verified=True)
    with pytest.raises(OAuthRejected) as excinfo:
        oauth.unlink(user_id=str(user["id"]), provider=GOOGLE_PROVIDER)
    assert excinfo.value.status_code == 404


def test_unlink_does_not_touch_another_users_link(oauth: OAuthService, hooks: FakeHooks) -> None:
    mine = hooks.add("mine@example.com", email_verified=True)
    theirs = hooks.add("theirs@example.com", email_verified=True)
    oauth.link(OAuthIdentity(GOOGLE_PROVIDER, "g1", "a@example.com", True), user_id=str(mine["id"]))
    oauth.link(
        OAuthIdentity(GOOGLE_PROVIDER, "g2", "b@example.com", True), user_id=str(theirs["id"])
    )
    hooks.extra_sign_in_methods = True

    oauth.unlink(user_id=str(mine["id"]), provider=GOOGLE_PROVIDER)
    assert len(oauth.list_links(str(theirs["id"]))) == 1


# ---------------------------------------------------------------------------
# The session an OAuth login issues, and MFA
# ---------------------------------------------------------------------------


@pytest.fixture
def flows(hooks: FakeHooks, stores: IdentityStores, kms: FakeKms) -> IdentityFlows:
    settings = make_settings()
    return IdentityFlows(settings, hooks, stores, TokenService(settings, kms), kms_client=kms)


def test_an_oauth_login_issues_the_same_token_pair_a_password_login_does(
    flows: IdentityFlows, hooks: FakeHooks
) -> None:
    user = hooks.add(EMAIL, email_verified=True)
    result = flows.issue_for_oauth(user, provider=GOOGLE_PROVIDER)

    assert result.access_token
    assert result.refresh_token
    assert result.family_id
    assert result.expires_in > 0


def test_the_access_token_records_the_provider_in_amr(
    flows: IdentityFlows, hooks: FakeHooks, kms: FakeKms
) -> None:
    """A policy that wants "a Google session" cannot express that against a shared value."""
    settings = make_settings()
    tokens = TokenService(settings, kms)
    user = hooks.add(EMAIL, email_verified=True)
    result = flows.issue_for_oauth(user, provider=GOOGLE_PROVIDER)

    claims = tokens.verify_access_token(result.access_token)
    assert AMR_OAUTH in claims["amr"]
    assert GOOGLE_PROVIDER in claims["amr"]
    assert "forged" not in claims["amr"], "a hook must not be able to set amr"


def test_an_oauth_login_honours_mfa(hooks: FakeHooks, stores: IdentityStores, kms: FakeKms) -> None:
    """A provider proving identity does not prove possession of the second factor.

    Without this, "add Google to your account" would be a way to turn MFA off.
    """
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


def test_an_oauth_login_respects_may_authenticate(
    hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
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


# ---------------------------------------------------------------------------
# The routes
# ---------------------------------------------------------------------------


@pytest.fixture
def client(hooks: FakeHooks, stores: IdentityStores, kms: FakeKms, provider: FakeProvider) -> Any:
    """A `TestClient` over a router with the OAuth routes mounted.

    The provider transport is injected by replacing the service's HTTP client after the
    router is built, which is the only seam the router does not expose. Everything else,
    including the state store and the link store, is the real code path.
    """
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


def _oauth_route_paths(app: FastAPI) -> set[str]:
    """The mounted paths that belong to this module.

    Matched against the route module's own path constants rather than by searching for the
    substring "oauth", which also matches FastAPI's built-in `/docs/oauth2-redirect` and made
    the "no routes are mounted" assertions pass for the wrong reason.
    """
    from webbpulse.identity.oauth_routes import (
        OAUTH_CALLBACK_PATH,
        OAUTH_LINK_PATH,
        OAUTH_LINKS_PATH,
        OAUTH_START_PATH,
    )

    ours = {OAUTH_START_PATH, OAUTH_CALLBACK_PATH, OAUTH_LINK_PATH, OAUTH_LINKS_PATH}
    prefix = identity_prefix(make_settings())
    mounted = {getattr(route, "path", "") for route in app.routes}
    return {path for path in ours if f"{prefix}{path}" in mounted}


def test_the_start_route_redirects_to_the_provider(client: Any) -> None:
    response = client.get(f"{identity_prefix(make_settings())}/oauth/google/start")
    assert response.status_code == 302
    assert response.headers["location"].startswith(PROVIDERS[GOOGLE_PROVIDER].authorize_url)


def test_the_start_route_404s_for_an_unknown_provider(client: Any) -> None:
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
    app = FastAPI()
    app.include_router(
        build_identity_router(settings, hooks, stores, kms_client=kms, limiter_enabled=False)
    )
    assert _oauth_route_paths(app) == set()


def test_the_routes_are_absent_when_the_stores_are_missing(hooks: FakeHooks, kms: FakeKms) -> None:
    settings = make_settings()
    app = FastAPI()
    app.include_router(
        build_identity_router(
            settings,
            hooks,
            IdentityStores(
                credentials=InMemoryCredentialStore(),
                refresh_tokens=InMemoryRefreshTokenStore(),
            ),
            kms_client=kms,
            limiter_enabled=False,
        )
    )
    assert _oauth_route_paths(app) == set()


def test_a_callback_with_a_bad_state_redirects_rather_than_rendering_json(client: Any) -> None:
    """The user is looking at a browser: a JSON body renders as text on a blank page."""
    response = client.get(f"{identity_prefix(make_settings())}/oauth/callback?state=nope&code=abc")
    assert response.status_code == 303
    assert response.headers["location"].startswith(FRONTEND)
    assert "oauth_error=OAUTH_STATE_INVALID" in response.headers["location"]


def test_a_cancelled_consent_screen_redirects_without_an_error_page(client: Any) -> None:
    prefix = identity_prefix(make_settings())
    start = client.get(f"{prefix}/oauth/google/start")
    from urllib.parse import parse_qs, urlsplit

    state = parse_qs(urlsplit(start.headers["location"]).query)["state"][0]

    response = client.get(f"{prefix}/oauth/callback?state={state}&error=access_denied")
    assert response.status_code == 303
    assert "oauth_error=OAUTH_CANCELLED" in response.headers["location"]


# ---------------------------------------------------------------------------
# The tables
# ---------------------------------------------------------------------------


def test_the_table_names_match_the_estate_convention() -> None:
    """Hyphenated logical names, as `webbpulse.dynamodb.table_name` expects them."""
    assert OAUTH_STATES_TABLE == "oauth-states"
    assert OAUTH_LINKS_TABLE == "oauth-links"
    assert "_" not in OAUTH_STATES_TABLE
    assert "_" not in OAUTH_LINKS_TABLE


@pytest.fixture
def oauth_tables(dynamodb_resource: Any) -> dict[str, Any]:
    """The two M6 tables, shaped as the Terraform module must create them.

    `oauth-links` is built here rather than through `webbpulse.testing.create_table` because
    that helper has no GSI support, and the `user_id-index` is what `list` and the
    last-method count in `unlink` both read.
    """
    from webbpulse.testing import create_table

    states = create_table(
        dynamodb_resource, "test-oauth-states", hash_key="state", ttl_attribute="expires_at"
    )
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
    table = oauth_tables["states"]
    assert table.key_schema == [{"AttributeName": "state", "KeyType": "HASH"}]

    ttl = table.meta.client.describe_time_to_live(TableName=table.name)
    description = ttl["TimeToLiveDescription"]
    assert description["TimeToLiveStatus"] == "ENABLED"
    assert description["AttributeName"] == "expires_at"


def test_the_links_table_is_keyed_on_provider_subject_with_a_user_index(
    oauth_tables: dict[str, Any],
) -> None:
    table = oauth_tables["links"]
    assert table.key_schema == [{"AttributeName": "provider_subject", "KeyType": "HASH"}]
    indexes = {index["IndexName"]: index for index in table.global_secondary_indexes}
    assert OAUTH_LINK_USER_INDEX in indexes
    assert indexes[OAUTH_LINK_USER_INDEX]["KeySchema"] == [
        {"AttributeName": "user_id", "KeyType": "HASH"}
    ]


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
    """The conditional write is the security control, not a nicety.

    A read-then-write would let a second concurrent callback silently move a provider
    identity from one local account to another.
    """
    from webbpulse.dynamodb import Repository
    from webbpulse.identity.oauth import OAuthLinkRecord

    store = DynamoOAuthLinkStore(Repository("oauth-links", prefix="test"))

    def record_for(user_id: str) -> OAuthLinkRecord:
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
    from webbpulse.dynamodb import Repository

    store = DynamoOAuthLinkStore(Repository("oauth-links", prefix="test"))
    store.delete("google#never-existed")
    assert store.get("google#never-existed") is None


# ---------------------------------------------------------------------------
# The HTTP seam
# ---------------------------------------------------------------------------


def test_a_non_json_provider_response_becomes_a_refusal_not_a_crash(
    hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A provider answering an HTML error page is a real condition, not an exception."""
    from webbpulse.identity.oauth import HttpxClient

    def handler(request: httpx.Request) -> httpx.Response:
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
    """`bool("false")` is `True`, which is why this is a function and not a `bool()` call.

    Google has returned `email_verified` as both a real boolean and its string spelling.
    """
    from webbpulse.identity.oauth import _as_bool

    assert _as_bool(raw) is expected
