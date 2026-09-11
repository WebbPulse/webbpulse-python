"""Tests for the M1 identity surface: settings, hooks, storage, token service, claims."""

from __future__ import annotations

import json
import time
from typing import Any

import pytest

from webbpulse.identity import (
    KMS_SIGNING_ALGORITHM,
    AuthorizerClaims,
    BaseIdentityHooks,
    CredentialRecord,
    HookNotImplemented,
    IdentitySettings,
    IdentityStores,
    IdentityTokenRecord,
    InMemoryCredentialStore,
    InMemoryIdentityTokenStore,
    InMemoryRefreshTokenStore,
    InvalidToken,
    MissingRequestContext,
    NoClaimsSection,
    RefreshTokenRecord,
    TokenService,
    UnparseableRequestContext,
    build_identity_router,
    coerce_claims,
    hash_token,
    identity_prefix,
    is_expired,
    new_token,
    read_authorizer_claims,
)
from webbpulse.identity.hooks import AuthenticationRefused
from webbpulse.identity.router import DISCOVERY_CACHE_CONTROL, JWKS_CACHE_CONTROL

cryptography = pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils  # noqa: E402

KEY_A = "arn:aws:kms:us-west-2:111122223333:key/aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa"
KEY_B = "arn:aws:kms:us-west-2:111122223333:key/bbbbbbbb-2222-2222-2222-bbbbbbbbbbbb"
KEY_C = "arn:aws:kms:us-west-2:111122223333:key/cccccccc-3333-3333-3333-cccccccccccc"

ISSUER = "https://api.staging.example.com/api/auth"
AUDIENCE = "webbpulse-staging"


class MultiKeyFakeKms:
    """A KMS client serving several keys by id, signing for real with local private keys.

    It signs the digest without re-hashing and returns the raw PKCS #1 signature.
    `failing` names key ids whose `get_public_key` raises.
    """

    def __init__(
        self,
        keys: dict[str, rsa.RSAPrivateKey],
        *,
        failing: frozenset[str] = frozenset(),
    ) -> None:
        """Hold the keys by id and the set of key ids whose lookup should fail."""
        self._keys = keys
        self._failing = failing
        self.get_public_key_calls: list[str] = []

    def _der(self, key_id: str) -> bytes:
        """Return the DER SubjectPublicKeyInfo for one held key."""
        return (
            self._keys[key_id]
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    def get_public_key(self, *, KeyId: str) -> dict[str, Any]:
        """Record the call and return a `kms:GetPublicKey` response, or raise if failing."""
        self.get_public_key_calls.append(KeyId)
        if KeyId in self._failing:
            raise RuntimeError(f"NotFoundException: key {KeyId} does not exist")
        return {
            "KeyId": KeyId,
            "PublicKey": self._der(KeyId),
            "KeySpec": "RSA_2048",
            "KeyUsage": "SIGN_VERIFY",
            "SigningAlgorithms": [KMS_SIGNING_ALGORITHM],
        }

    def sign(
        self, *, KeyId: str, Message: bytes, MessageType: str, SigningAlgorithm: str
    ) -> dict[str, Any]:
        """Return a real PKCS #1 v1.5 signature over the digest, using the named key."""
        signature = self._keys[KeyId].sign(
            Message, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
        )
        return {"KeyId": KeyId, "Signature": signature, "SigningAlgorithm": SigningAlgorithm}


@pytest.fixture(scope="module")
def key_pair() -> dict[str, rsa.RSAPrivateKey]:
    """Three 2048-bit keys for the module. Generation is slow enough to be worth sharing."""
    return {
        KEY_A: rsa.generate_private_key(public_exponent=65537, key_size=2048),
        KEY_B: rsa.generate_private_key(public_exponent=65537, key_size=2048),
        KEY_C: rsa.generate_private_key(public_exponent=65537, key_size=2048),
    }


@pytest.fixture
def kms(key_pair: dict[str, rsa.RSAPrivateKey]) -> MultiKeyFakeKms:
    """Return a fresh multi-key KMS stand-in holding all three module keys."""
    return MultiKeyFakeKms(dict(key_pair))


def make_settings(**overrides: Any) -> IdentitySettings:
    """Build `IdentitySettings` from this module's defaults with the given overrides."""
    base: dict[str, Any] = {
        "environment": "test",
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "signing_key_arns": [KEY_A],
    }
    base.update(overrides)
    return IdentitySettings(**base)


def test_defaults_are_safe() -> None:
    """Settings default to a secure cookie, verified email, a 600s TTL and one active key."""
    settings = make_settings()
    assert settings.cookie_secure is True
    assert settings.cookie_samesite == "lax"
    assert settings.email_verification_required is True
    assert settings.access_token_ttl.total_seconds() == 600
    assert settings.active_signing_key_arn == KEY_A
    assert settings.previous_signing_key_arns == []


def test_cookie_kwargs_always_sets_httponly() -> None:
    """`cookie_kwargs` always sets `httponly`, which is not configurable."""
    kwargs = make_settings().cookie_kwargs()
    assert kwargs["httponly"] is True


def test_issuer_trailing_slash_is_stripped() -> None:
    """A trailing slash on the configured issuer is stripped."""
    assert make_settings(issuer=ISSUER + "/").issuer == ISSUER


@pytest.mark.parametrize(
    "bad",
    [
        "not-a-url",
        "ftp://example.com/auth",
        "https://example.com/auth?x=1",
        "https://example.com/auth#frag",
    ],
)
def test_bad_issuers_are_refused(bad: str) -> None:
    """A non-URL, non-http scheme, query string or fragment in the issuer raises."""
    with pytest.raises(ValueError):
        make_settings(issuer=bad)


def test_plaintext_issuer_refused_outside_local_and_test() -> None:
    """An `http://` issuer raises in production but is permitted in local."""
    with pytest.raises(ValueError):
        make_settings(environment="production", issuer="http://api.example.com/api/auth")
    assert make_settings(environment="local", issuer="http://localhost:8000").issuer


def test_signing_keys_must_be_non_empty_and_unique() -> None:
    """An empty or duplicated `signing_key_arns` list raises."""
    with pytest.raises(ValueError):
        make_settings(signing_key_arns=[])
    with pytest.raises(ValueError):
        make_settings(signing_key_arns=[KEY_A, KEY_A])


def test_access_token_ttl_is_capped() -> None:
    """An access token TTL over the cap raises."""
    with pytest.raises(ValueError):
        make_settings(access_token_ttl="PT4H")


def test_samesite_none_requires_secure() -> None:
    """`cookie_samesite="none"` with `cookie_secure=False` raises."""
    with pytest.raises(ValueError):
        make_settings(cookie_samesite="none", cookie_secure=False)


def test_absolute_refresh_ttl_cannot_be_shorter_than_the_rolling_one() -> None:
    """An absolute refresh TTL shorter than the rolling refresh TTL raises."""
    with pytest.raises(ValueError):
        make_settings(refresh_token_ttl="P30D", refresh_absolute_ttl="P7D")


def test_discovery_and_jwks_urls_are_derived_from_the_issuer() -> None:
    """`discovery_url` and `jwks_url` are the issuer plus their well-known suffixes."""
    settings = make_settings()
    assert settings.discovery_url == f"{ISSUER}/.well-known/openid-configuration"
    assert settings.jwks_url == f"{ISSUER}/.well-known/jwks.json"


GATEWAY_CLAIMS: dict[str, str] = {
    "sub": "user-abc-123",
    "iss": ISSUER,
    "aud": AUDIENCE,
    "exp": "1757400000",
    "iat": "1757399400",
    "email": "someone@example.com",
    "email_verified": "true",
    "scope": "openid profile email",
    "roles": "[admin, editor]",
}


def test_gateway_shaped_claims_are_coerced() -> None:
    """All-string gateway claims coerce to ints, bools and lists, leaving strings alone."""
    claims = coerce_claims(GATEWAY_CLAIMS)

    assert claims["exp"] == 1757400000
    assert isinstance(claims["exp"], int)
    assert claims["iat"] == 1757399400

    assert claims["email_verified"] is True

    assert claims["scopes"] == ["openid", "profile", "email"]
    assert claims["roles"] == ["admin", "editor"]

    assert claims["sub"] == "user-abc-123"
    assert claims["email"] == "someone@example.com"


def test_email_verified_false_is_false_not_truthy() -> None:
    """The string `"false"` coerces to `False`, not to a truthy value."""
    assert coerce_claims({"email_verified": "false"})["email_verified"] is False


def test_json_encoded_array_claim_is_parsed() -> None:
    """A JSON-encoded array claim is parsed into a list."""
    claims = coerce_claims({"roles": '["admin", "editor"]'})
    assert claims["roles"] == ["admin", "editor"]


def test_a_bare_array_claim_becomes_a_one_element_list() -> None:
    """A bare string `aud` becomes a one element list."""
    assert coerce_claims({"aud": AUDIENCE})["aud"] == [AUDIENCE]


def test_an_uncoercible_integer_claim_is_left_alone() -> None:
    """A non-numeric `exp` is left as the original string rather than zeroed."""
    assert coerce_claims({"exp": "not-a-number"})["exp"] == "not-a-number"


def test_raw_claims_are_preserved_alongside_the_coerced_ones() -> None:
    """`AuthorizerClaims` exposes coerced values while keeping the raw strings on `.raw`."""
    claims = AuthorizerClaims(GATEWAY_CLAIMS)
    assert claims["exp"] == 1757400000
    assert claims.raw["exp"] == "1757400000"


def test_repr_does_not_spill_email_or_scopes() -> None:
    """`repr` of a claims object omits the email while keeping the subject."""
    text = repr(AuthorizerClaims(GATEWAY_CLAIMS))
    assert "someone@example.com" not in text
    assert "user-abc-123" in text


def make_request(headers: dict[str, str]) -> Any:
    """Build a minimal Starlette GET request carrying the given headers."""
    from starlette.requests import Request

    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return Request({"type": "http", "method": "GET", "path": "/", "headers": raw})


def test_missing_request_context_header_is_distinguishable() -> None:
    """A request with no request-context header raises `MissingRequestContext`."""
    with pytest.raises(MissingRequestContext):
        read_authorizer_claims(make_request({}))


def test_unparseable_request_context_is_distinguishable() -> None:
    """A request-context header that is not JSON raises `UnparseableRequestContext`."""
    with pytest.raises(UnparseableRequestContext):
        read_authorizer_claims(make_request({"x-amzn-request-context": "{not json"}))


def test_a_context_without_a_claims_section_is_distinguishable() -> None:
    """A request context with no claims section raises `NoClaimsSection`."""
    context = json.dumps({"http": {"sourceIp": "203.0.113.10"}})
    with pytest.raises(NoClaimsSection):
        read_authorizer_claims(make_request({"x-amzn-request-context": context}))


def test_claims_are_read_from_a_plain_json_header() -> None:
    """Claims are read from a plain JSON request-context header and coerced."""
    context = json.dumps({"authorizer": {"jwt": {"claims": GATEWAY_CLAIMS}}})
    claims = read_authorizer_claims(make_request({"x-amzn-request-context": context}))
    assert claims["sub"] == "user-abc-123"
    assert claims["exp"] == 1757400000


def test_local_fallback_is_refused_in_production_at_construction_time() -> None:
    """A local fallback raises in production when the dependency is built, not per request."""
    from webbpulse.identity import authorizer_claims

    def fallback(request: Any) -> dict[str, str]:
        """Return a fixed local development claim set."""
        return {"sub": "dev"}

    with pytest.raises(ValueError):
        authorizer_claims(environment="production", local_fallback=fallback)

    assert authorizer_claims(environment="local", local_fallback=fallback)


def test_mint_and_verify_round_trip(kms: MultiKeyFakeKms) -> None:
    """A minted access token verifies back to its subject, issuer, audience and claims."""
    service = TokenService(make_settings(), kms)
    token = service.mint_access_token("user-1", claims={"roles": ["admin"]})

    claims = service.verify_access_token(token)
    assert claims["sub"] == "user-1"
    assert claims["iss"] == ISSUER
    assert claims["aud"] == AUDIENCE
    assert claims["roles"] == ["admin"]
    assert claims["typ"] == "access"
    assert claims["exp"] - claims["iat"] == 600


def test_product_claims_cannot_override_registered_ones(kms: MultiKeyFakeKms) -> None:
    """Product supplied claims cannot override the registered `iss`, `sub` or `exp`."""
    service = TokenService(make_settings(), kms)
    token = service.mint_access_token(
        "user-1",
        claims={"iss": "https://evil.example.com", "exp": 9999999999, "sub": "admin"},
    )
    claims = service.verify_access_token(token)
    assert claims["iss"] == ISSUER
    assert claims["sub"] == "user-1"
    assert claims["exp"] - claims["iat"] == 600


def test_wrong_audience_is_rejected(kms: MultiKeyFakeKms) -> None:
    """Verifying against a different audience raises `InvalidToken`."""
    service = TokenService(make_settings(), kms)
    token = service.mint_access_token("user-1")
    with pytest.raises(InvalidToken):
        service.verify_access_token(token, audience="some-other-api")


def test_an_expired_token_is_rejected(kms: MultiKeyFakeKms) -> None:
    """A token minted far enough in the past fails verification with `InvalidToken`."""
    service = TokenService(make_settings(), kms)
    long_ago = int(time.time()) - 4000
    token = service.mint_access_token("user-1", now=long_ago)
    with pytest.raises(InvalidToken):
        service.verify_access_token(token)


def test_jwks_lists_every_configured_key(kms: MultiKeyFakeKms) -> None:
    """The JWKS lists one distinct RS256 signing key per configured ARN, active one first."""
    service = TokenService(make_settings(signing_key_arns=[KEY_A, KEY_B]), kms)
    document = service.jwks()
    assert len(document["keys"]) == 2
    assert document["keys"][0]["kid"] == service.active_kid
    assert len({key["kid"] for key in document["keys"]}) == 2
    for key in document["keys"]:
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"
        assert key["use"] == "sig"


def test_previous_key_still_verifies_after_promotion(kms: MultiKeyFakeKms) -> None:
    """A token keeps verifying while its key stays listed and stops once it is retired."""
    introduced = TokenService(make_settings(signing_key_arns=[KEY_A, KEY_B]), kms)
    token_from_a = introduced.mint_access_token("user-1")

    promoted = TokenService(make_settings(signing_key_arns=[KEY_B, KEY_A]), kms)
    token_from_b = promoted.mint_access_token("user-2")

    assert promoted.verify_access_token(token_from_a)["sub"] == "user-1"
    assert promoted.verify_access_token(token_from_b)["sub"] == "user-2"
    assert promoted.active_kid != introduced.active_kid

    retired = TokenService(make_settings(signing_key_arns=[KEY_B]), kms)
    assert retired.verify_access_token(token_from_b)["sub"] == "user-2"
    with pytest.raises(InvalidToken) as excinfo:
        retired.verify_access_token(token_from_a)
    assert "unknown kid" in str(excinfo.value)


def test_a_token_from_an_unconfigured_key_is_rejected(kms: MultiKeyFakeKms) -> None:
    """A token signed by an unconfigured key is rejected with an unknown kid error."""
    stranger = TokenService(make_settings(signing_key_arns=[KEY_C]), kms)
    token = stranger.mint_access_token("user-1")

    service = TokenService(make_settings(signing_key_arns=[KEY_A, KEY_B]), kms)
    with pytest.raises(InvalidToken) as excinfo:
        service.verify_access_token(token)
    assert "unknown kid" in str(excinfo.value)


def test_public_keys_are_fetched_once_per_key(kms: MultiKeyFakeKms) -> None:
    """Repeated `jwks()` calls fetch each public key from KMS once, not per call."""
    service = TokenService(make_settings(signing_key_arns=[KEY_A, KEY_B]), kms)
    for _ in range(5):
        service.jwks()
    assert sorted(set(kms.get_public_key_calls)) == sorted({KEY_A, KEY_B})
    assert len(kms.get_public_key_calls) <= 3


def test_a_broken_key_is_omitted_rather_than_failing_the_document(
    key_pair: dict[str, rsa.RSAPrivateKey],
) -> None:
    """A key whose lookup fails is omitted from the JWKS rather than failing the document."""
    kms = MultiKeyFakeKms(dict(key_pair), failing=frozenset({KEY_B}))
    service = TokenService(make_settings(signing_key_arns=[KEY_A, KEY_B]), kms)
    document = service.jwks()
    assert len(document["keys"]) == 1
    assert document["keys"][0]["kid"] == service.active_kid


def test_every_key_failing_is_fatal(key_pair: dict[str, rsa.RSAPrivateKey]) -> None:
    """When every configured key fails to load, building the JWKS raises."""
    kms = MultiKeyFakeKms(dict(key_pair), failing=frozenset({KEY_A}))
    service = TokenService(make_settings(signing_key_arns=[KEY_A]), kms)
    with pytest.raises(RuntimeError):
        service.jwks()


def test_discovery_document_has_the_required_members(kms: MultiKeyFakeKms) -> None:
    """The discovery document carries the issuer, JWKS URI, RS256 and the required members."""
    document = TokenService(make_settings(), kms).discovery()
    assert document["issuer"] == ISSUER
    assert document["jwks_uri"] == f"{ISSUER}/.well-known/jwks.json"
    assert document["id_token_signing_alg_values_supported"] == ["RS256"]
    assert "response_types_supported" in document
    assert "subject_types_supported" in document


def build_app(kms: MultiKeyFakeKms, **kwargs: Any) -> Any:
    """Build a FastAPI app carrying the identity router for the given settings overrides."""
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(build_identity_router(make_settings(**kwargs), kms_client=kms))
    return app


def test_router_exposes_exactly_the_intended_routes(kms: MultiKeyFakeKms) -> None:
    """The router exposes exactly the discovery, JWKS, health, providers and passkey routes.

    All of them are served under the issuer's own path prefix.
    """
    from fastapi import FastAPI

    app = FastAPI()
    settings = make_settings()
    router = build_identity_router(settings, kms_client=kms)
    app.include_router(router)

    prefix = identity_prefix(settings)
    assert prefix == "/api/auth"

    paths = {route.path for route in router.routes}  # type: ignore[attr-defined]
    assert paths == {
        f"{prefix}/.well-known/openid-configuration",
        f"{prefix}/.well-known/jwks.json",
        f"{prefix}/health",
        f"{prefix}/oauth/providers",
        f"{prefix}/passkeys/availability",
    }


def test_documents_are_served_with_cache_control(kms: MultiKeyFakeKms) -> None:
    """Discovery and JWKS are served 200 with their expected `Cache-Control` headers."""
    from fastapi.testclient import TestClient

    client = TestClient(build_app(kms))

    discovery = client.get("/api/auth/.well-known/openid-configuration")
    assert discovery.status_code == 200
    assert discovery.headers["cache-control"] == DISCOVERY_CACHE_CONTROL
    assert discovery.json()["issuer"] == ISSUER

    jwks = client.get("/api/auth/.well-known/jwks.json")
    assert jwks.status_code == 200
    assert jwks.headers["cache-control"] == JWKS_CACHE_CONTROL
    assert len(jwks.json()["keys"]) == 1


def test_jwks_cache_is_shorter_than_discovery_cache() -> None:
    """The JWKS max-age is 300 seconds against discovery's 3600."""
    assert "max-age=300" in JWKS_CACHE_CONTROL
    assert "max-age=3600" in DISCOVERY_CACHE_CONTROL


def test_health_matches_the_package_shape(kms: MultiKeyFakeKms) -> None:
    """The health route returns the package's status, service and version body."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.include_router(
        build_identity_router(make_settings(), kms_client=kms, service="identity", version="0.9.0")
    )
    body = TestClient(app).get("/api/auth/health").json()
    assert body == {"status": "healthy", "service": "identity", "version": "0.9.0"}


def test_router_needs_a_token_service_or_a_kms_client() -> None:
    """Building the router with neither a token service nor a KMS client raises."""
    with pytest.raises(ValueError):
        build_identity_router(make_settings())


def test_unimplemented_hooks_raise_a_named_error() -> None:
    """An unimplemented hook raises `HookNotImplemented` naming the hook and the class."""

    class ProductHooks(BaseIdentityHooks):
        """A hooks subclass that implements nothing."""

    hooks = ProductHooks()
    with pytest.raises(HookNotImplemented) as excinfo:
        hooks.load_user_by_email("someone@example.com")
    assert "load_user_by_email" in str(excinfo.value)
    assert "ProductHooks" in str(excinfo.value)


def test_the_two_hooks_with_safe_defaults_do_not_raise() -> None:
    """`claims_for` defaults to no claims and `on_user_created` defaults to doing nothing."""
    hooks = BaseIdentityHooks()
    assert hooks.claims_for({"id": "user-1"}) == {}
    hooks.on_user_created({"id": "user-1"}, "password")


def test_may_authenticate_refuses_by_raising() -> None:
    """`may_authenticate` signals refusal by raising `AuthenticationRefused`, not by returning."""

    class ProductHooks(BaseIdentityHooks):
        """A hooks subclass that refuses disabled users."""

        def may_authenticate(self, user: Any) -> None:
            """Raise `AuthenticationRefused` when the user is disabled."""
            if user.get("disabled"):
                raise AuthenticationRefused("Invalid email or password.")

    hooks = ProductHooks()
    hooks.may_authenticate({"disabled": False})
    with pytest.raises(AuthenticationRefused) as excinfo:
        hooks.may_authenticate({"disabled": True})
    assert excinfo.value.error_code == "AUTHENTICATION_REFUSED"


def test_only_the_hash_of_a_token_is_stored() -> None:
    """A refresh token record holds only the 64 character hash, never the token itself."""
    token = new_token()
    record = RefreshTokenRecord(
        token_hash=hash_token(token),
        family_id="fam-1",
        user_id="user-1",
        generation=1,
        created_at="2026-09-09T00:00:00Z",
        expires_at=int(time.time()) + 3600,
    )
    assert record.token_hash != token
    assert token not in json.dumps(record.__dict__ if hasattr(record, "__dict__") else {})
    assert len(record.token_hash) == 64


def test_consume_is_single_use_and_returns_the_prior_state() -> None:
    """`consume` returns the prior record once and returns None on a second attempt."""
    store = InMemoryRefreshTokenStore()
    token_hash = hash_token(new_token())
    store.put(
        RefreshTokenRecord(
            token_hash=token_hash,
            family_id="fam-1",
            user_id="user-1",
            generation=1,
            created_at="2026-09-09T00:00:00Z",
            expires_at=int(time.time()) + 3600,
        )
    )

    previous = store.consume(token_hash, successor_hash="succ-hash")
    assert previous is not None
    assert previous.is_consumed is False

    assert store.consume(token_hash, successor_hash="other") is None
    assert store.get(token_hash).successor_hash == "succ-hash"  # type: ignore[union-attr]


def test_revoke_family_marks_every_generation() -> None:
    """`revoke_family` revokes every generation once and is idempotent afterwards."""
    store = InMemoryRefreshTokenStore()
    hashes_ = [hash_token(new_token()) for _ in range(3)]
    for generation, token_hash in enumerate(hashes_, start=1):
        store.put(
            RefreshTokenRecord(
                token_hash=token_hash,
                family_id="fam-1",
                user_id="user-1",
                generation=generation,
                created_at="2026-09-09T00:00:00Z",
                expires_at=int(time.time()) + 3600,
            )
        )
    assert store.revoke_family("fam-1") == 3
    assert all(store.get(h).revoked for h in hashes_)  # type: ignore[union-attr]
    assert store.revoke_family("fam-1") == 0


def test_expired_records_are_returned_not_hidden() -> None:
    """An expired record is still returned by `get`, with `is_expired` reporting True."""
    store = InMemoryRefreshTokenStore()
    token_hash = hash_token(new_token())
    store.put(
        RefreshTokenRecord(
            token_hash=token_hash,
            family_id="fam-1",
            user_id="user-1",
            generation=1,
            created_at="2020-01-01T00:00:00Z",
            expires_at=int(time.time()) - 10,
        )
    )
    record = store.get(token_hash)
    assert record is not None
    assert is_expired(record.expires_at) is True


def test_identity_tokens_are_single_use() -> None:
    """An identity token can be consumed once, and a second consume returns None."""
    store = InMemoryIdentityTokenStore()
    token_hash = hash_token(new_token())
    store.put(
        IdentityTokenRecord(
            token_hash=token_hash,
            purpose="reset_password",
            user_id="user-1",
            created_at="2026-09-09T00:00:00Z",
            expires_at=int(time.time()) + 3600,
        )
    )
    assert store.consume(token_hash) is not None
    assert store.consume(token_hash) is None


def test_credentials_round_trip_and_delete_is_idempotent() -> None:
    """A credential round trips through the store and deleting it twice does not raise."""
    store = InMemoryCredentialStore()
    store.put(CredentialRecord(user_id="user-1", credential_type="password", secret="$2b$hash"))
    record = store.get("user-1", "password")
    assert record is not None
    assert record.secret == "$2b$hash"
    assert record.created_at

    store.delete("user-1", "password")
    assert store.get("user-1", "password") is None
    store.delete("user-1", "password")


def test_identity_stores_require_reports_which_store_is_missing() -> None:
    """Requiring an unconfigured store raises an error naming that store."""
    stores = IdentityStores()
    with pytest.raises(ValueError) as excinfo:
        stores.require_refresh_tokens()
    assert "refresh_tokens" in str(excinfo.value)


def test_is_expired_uses_the_deadline_not_the_ttl_sweep() -> None:
    """`is_expired` compares against the recorded deadline, not a storage TTL sweep."""
    assert is_expired(int(time.time()) - 1) is True
    assert is_expired(int(time.time()) + 60) is False
