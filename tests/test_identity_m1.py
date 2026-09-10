"""Tests for the M1 identity surface: settings, hooks, storage, token service, claims.

`test_identity.py` covers the M0 slice and still passes unchanged, which is itself the test
that moving `identity.py` to `identity/tokens.py` broke no import.

Two tests here carry most of the weight:

- `test_previous_key_still_verifies_after_promotion` is the rotation proof. It signs with
  one key, promotes a second to active, and shows the first token still verifies while a
  token signed by a key that is no longer configured does not. That is the property the
  whole two-key scheme exists to provide, and getting it wrong presents as every session
  breaking at once during a routine deploy.
- `test_gateway_shaped_claims_are_coerced` is the M0 spike's finding turned into a
  regression test. Every claim value the authorizer emits is a **string**, `exp` included,
  and the observed `whoami` body is reproduced verbatim as the fixture rather than
  paraphrased, so a change in coercion is caught against real gateway output.

The multi-key fake is local to this module rather than shared with `test_identity.py`,
because that file's `FakeKms` is deliberately a one-key client and widening it would make
the M0 tests read as if rotation were part of what they prove.
"""

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

    Faithful in the two ways the output depends on, exactly as `test_identity.FakeKms` is:
    it signs the digest it is handed without re-hashing (`MessageType="DIGEST"`) and returns
    the raw PKCS #1 signature octet string. It differs from KMS only in who holds the key.

    `failing` names key ids that raise from `get_public_key`, which is how the "a retired
    key must not take the JWKS down" behaviour is exercised.
    """

    def __init__(
        self,
        keys: dict[str, rsa.RSAPrivateKey],
        *,
        failing: frozenset[str] = frozenset(),
    ) -> None:
        self._keys = keys
        self._failing = failing
        self.get_public_key_calls: list[str] = []

    def _der(self, key_id: str) -> bytes:
        return (
            self._keys[key_id]
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    def get_public_key(self, *, KeyId: str) -> dict[str, Any]:
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
    return MultiKeyFakeKms(dict(key_pair))


def make_settings(**overrides: Any) -> IdentitySettings:
    base: dict[str, Any] = {
        "environment": "test",
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "signing_key_arns": [KEY_A],
    }
    base.update(overrides)
    return IdentitySettings(**base)


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


def test_defaults_are_safe() -> None:
    settings = make_settings()
    assert settings.cookie_secure is True
    assert settings.cookie_samesite == "lax"
    assert settings.email_verification_required is True
    assert settings.access_token_ttl.total_seconds() == 600
    assert settings.active_signing_key_arn == KEY_A
    assert settings.previous_signing_key_arns == []


def test_cookie_kwargs_always_sets_httponly() -> None:
    """`httponly` is not configurable, and that is deliberate.

    A refresh cookie readable from JavaScript is an XSS-stealable session, which is the
    single thing the cookie design exists to prevent. A setting for it would only ever be
    a way to turn the protection off by accident.
    """
    kwargs = make_settings().cookie_kwargs()
    assert kwargs["httponly"] is True


def test_issuer_trailing_slash_is_stripped() -> None:
    """A trailing slash on one of three places is the classic cause of total denial."""
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
    with pytest.raises(ValueError):
        make_settings(issuer=bad)


def test_plaintext_issuer_refused_outside_local_and_test() -> None:
    with pytest.raises(ValueError):
        make_settings(environment="production", issuer="http://api.example.com/api/auth")
    # Permitted in local, where there is no TLS terminator in front of the app.
    assert make_settings(environment="local", issuer="http://localhost:8000").issuer


def test_signing_keys_must_be_non_empty_and_unique() -> None:
    with pytest.raises(ValueError):
        make_settings(signing_key_arns=[])
    with pytest.raises(ValueError):
        make_settings(signing_key_arns=[KEY_A, KEY_A])


def test_access_token_ttl_is_capped() -> None:
    """A long-lived access token cannot be revoked, so the cap is a hard validation."""
    with pytest.raises(ValueError):
        make_settings(access_token_ttl="PT4H")


def test_samesite_none_requires_secure() -> None:
    with pytest.raises(ValueError):
        make_settings(cookie_samesite="none", cookie_secure=False)


def test_absolute_refresh_ttl_cannot_be_shorter_than_the_rolling_one() -> None:
    with pytest.raises(ValueError):
        make_settings(refresh_token_ttl="P30D", refresh_absolute_ttl="P7D")


def test_discovery_and_jwks_urls_are_derived_from_the_issuer() -> None:
    settings = make_settings()
    assert settings.discovery_url == f"{ISSUER}/.well-known/openid-configuration"
    assert settings.jwks_url == f"{ISSUER}/.well-known/jwks.json"


# ---------------------------------------------------------------------------
# Claim coercion: the M0 spike's finding, as a regression test
# ---------------------------------------------------------------------------

#: Reproduced verbatim from the `whoami` probe in the M0 staging spike. Every value is a
#: string, including `exp`, `iat` and `email_verified`. Paraphrasing this fixture would
#: defeat its purpose.
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
    claims = coerce_claims(GATEWAY_CLAIMS)

    # Integers, not strings. `exp > time.time()` on a string raises TypeError, which is the
    # bug this coercion exists to prevent.
    assert claims["exp"] == 1757400000
    assert isinstance(claims["exp"], int)
    assert claims["iat"] == 1757399400

    # Booleans, not the truthy string "false".
    assert claims["email_verified"] is True

    # Space-separated scope becomes a list, and the bracketed comma form the gateway uses
    # for a JSON array claim becomes one too.
    assert claims["scopes"] == ["openid", "profile", "email"]
    assert claims["roles"] == ["admin", "editor"]

    # Untouched.
    assert claims["sub"] == "user-abc-123"
    assert claims["email"] == "someone@example.com"


def test_email_verified_false_is_false_not_truthy() -> None:
    """The failure mode worth a dedicated test: `bool("false")` is `True`."""
    assert coerce_claims({"email_verified": "false"})["email_verified"] is False


def test_json_encoded_array_claim_is_parsed() -> None:
    claims = coerce_claims({"roles": '["admin", "editor"]'})
    assert claims["roles"] == ["admin", "editor"]


def test_a_bare_array_claim_becomes_a_one_element_list() -> None:
    assert coerce_claims({"aud": AUDIENCE})["aud"] == [AUDIENCE]


def test_an_uncoercible_integer_claim_is_left_alone() -> None:
    """Better a string `exp` a caller can notice than a silent zero it cannot."""
    assert coerce_claims({"exp": "not-a-number"})["exp"] == "not-a-number"


def test_raw_claims_are_preserved_alongside_the_coerced_ones() -> None:
    claims = AuthorizerClaims(GATEWAY_CLAIMS)
    assert claims["exp"] == 1757400000
    assert claims.raw["exp"] == "1757400000"


def test_repr_does_not_spill_email_or_scopes() -> None:
    """A claims object reaching a log line must not carry PII into it."""
    text = repr(AuthorizerClaims(GATEWAY_CLAIMS))
    assert "someone@example.com" not in text
    assert "user-abc-123" in text


# ---------------------------------------------------------------------------
# Reading claims off a request
# ---------------------------------------------------------------------------


def make_request(headers: dict[str, str]) -> Any:
    from starlette.requests import Request

    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return Request({"type": "http", "method": "GET", "path": "/", "headers": raw})


def test_missing_request_context_header_is_distinguishable() -> None:
    with pytest.raises(MissingRequestContext):
        read_authorizer_claims(make_request({}))


def test_unparseable_request_context_is_distinguishable() -> None:
    with pytest.raises(UnparseableRequestContext):
        read_authorizer_claims(make_request({"x-amzn-request-context": "{not json"}))


def test_a_context_without_a_claims_section_is_distinguishable() -> None:
    """An anonymous route reached through this dependency is a routing fault, not a 500."""
    context = json.dumps({"http": {"sourceIp": "203.0.113.10"}})
    with pytest.raises(NoClaimsSection):
        read_authorizer_claims(make_request({"x-amzn-request-context": context}))


def test_claims_are_read_from_a_plain_json_header() -> None:
    """The Web Adapter forwards the context as plain JSON, never base64. M0 confirmed it."""
    context = json.dumps({"authorizer": {"jwt": {"claims": GATEWAY_CLAIMS}}})
    claims = read_authorizer_claims(make_request({"x-amzn-request-context": context}))
    assert claims["sub"] == "user-abc-123"
    assert claims["exp"] == 1757400000


def test_local_fallback_is_refused_in_production_at_construction_time() -> None:
    """Refused when the dependency is built, not when a request arrives.

    A misconfiguration that only surfaces on the first authenticated request is one that
    reaches production and waits. This one cannot start.
    """
    from webbpulse.identity import authorizer_claims

    def fallback(request: Any) -> dict[str, str]:
        return {"sub": "dev"}

    with pytest.raises(ValueError):
        authorizer_claims(environment="production", local_fallback=fallback)

    # Permitted where it is meant to be used.
    assert authorizer_claims(environment="local", local_fallback=fallback)


# ---------------------------------------------------------------------------
# Token service: minting, verification, rotation
# ---------------------------------------------------------------------------


def test_mint_and_verify_round_trip(kms: MultiKeyFakeKms) -> None:
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
    """A hook able to rewrite `iss` or `exp` could mint a token for another issuer.

    So the registered claims win, and the product's attempt is dropped rather than merged.
    """
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
    service = TokenService(make_settings(), kms)
    token = service.mint_access_token("user-1")
    with pytest.raises(InvalidToken):
        service.verify_access_token(token, audience="some-other-api")


def test_an_expired_token_is_rejected(kms: MultiKeyFakeKms) -> None:
    service = TokenService(make_settings(), kms)
    long_ago = int(time.time()) - 4000
    token = service.mint_access_token("user-1", now=long_ago)
    with pytest.raises(InvalidToken):
        service.verify_access_token(token)


def test_jwks_lists_every_configured_key(kms: MultiKeyFakeKms) -> None:
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
    """The rotation proof, walking sections 3.5's steps 2 through 4.

    A token signed before the promotion must keep verifying while its key is still listed,
    and must stop when the key is retired. Getting this wrong breaks every live session at
    once during what looks like a routine configuration change.
    """
    # Step 2, introduce: both keys listed, A still active.
    introduced = TokenService(make_settings(signing_key_arns=[KEY_A, KEY_B]), kms)
    token_from_a = introduced.mint_access_token("user-1")

    # Step 3, promote: B is active, A still listed.
    promoted = TokenService(make_settings(signing_key_arns=[KEY_B, KEY_A]), kms)
    token_from_b = promoted.mint_access_token("user-2")

    assert promoted.verify_access_token(token_from_a)["sub"] == "user-1"
    assert promoted.verify_access_token(token_from_b)["sub"] == "user-2"
    assert promoted.active_kid != introduced.active_kid

    # Step 4, retire: A is gone, and tokens it signed no longer verify.
    retired = TokenService(make_settings(signing_key_arns=[KEY_B]), kms)
    assert retired.verify_access_token(token_from_b)["sub"] == "user-2"
    with pytest.raises(InvalidToken) as excinfo:
        retired.verify_access_token(token_from_a)
    assert "unknown kid" in str(excinfo.value)


def test_a_token_from_an_unconfigured_key_is_rejected(kms: MultiKeyFakeKms) -> None:
    """Not merely unverifiable: rejected by `kid` before any signature check."""
    stranger = TokenService(make_settings(signing_key_arns=[KEY_C]), kms)
    token = stranger.mint_access_token("user-1")

    service = TokenService(make_settings(signing_key_arns=[KEY_A, KEY_B]), kms)
    with pytest.raises(InvalidToken) as excinfo:
        service.verify_access_token(token)
    assert "unknown kid" in str(excinfo.value)


def test_public_keys_are_fetched_once_per_key(kms: MultiKeyFakeKms) -> None:
    """The gateway refetches the JWKS often, so a `GetPublicKey` per fetch would be hot."""
    service = TokenService(make_settings(signing_key_arns=[KEY_A, KEY_B]), kms)
    for _ in range(5):
        service.jwks()
    assert sorted(set(kms.get_public_key_calls)) == sorted({KEY_A, KEY_B})
    # One per key for the JWKs, plus the active signer resolving its own kid.
    assert len(kms.get_public_key_calls) <= 3


def test_a_broken_key_is_omitted_rather_than_failing_the_document(
    key_pair: dict[str, rsa.RSAPrivateKey],
) -> None:
    """A retired key id left in configuration must not deny every authorized request."""
    kms = MultiKeyFakeKms(dict(key_pair), failing=frozenset({KEY_B}))
    service = TokenService(make_settings(signing_key_arns=[KEY_A, KEY_B]), kms)
    document = service.jwks()
    assert len(document["keys"]) == 1
    assert document["keys"][0]["kid"] == service.active_kid


def test_every_key_failing_is_fatal(key_pair: dict[str, rsa.RSAPrivateKey]) -> None:
    """An empty JWKS would be cached by the gateway and deny everything for its interval."""
    kms = MultiKeyFakeKms(dict(key_pair), failing=frozenset({KEY_A}))
    service = TokenService(make_settings(signing_key_arns=[KEY_A]), kms)
    with pytest.raises(RuntimeError):
        service.jwks()


def test_discovery_document_has_the_required_members(kms: MultiKeyFakeKms) -> None:
    """The five members OpenID Connect Discovery 1.0 requires of a signing-only provider."""
    document = TokenService(make_settings(), kms).discovery()
    assert document["issuer"] == ISSUER
    assert document["jwks_uri"] == f"{ISSUER}/.well-known/jwks.json"
    assert document["id_token_signing_alg_values_supported"] == ["RS256"]
    assert "response_types_supported" in document
    assert "subject_types_supported" in document


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------


def build_app(kms: MultiKeyFakeKms, **kwargs: Any) -> Any:
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(build_identity_router(make_settings(**kwargs), kms_client=kms))
    return app


def test_router_exposes_exactly_the_intended_routes(kms: MultiKeyFakeKms) -> None:
    """M1 mounts three routes. A flow route appearing here is a milestone leaking early.

    The paths carry the issuer's own path, `/api/auth` for this suite's `ISSUER`, because
    that is where API Gateway fetches discovery and where the advertised `jwks_uri` points.
    0.10.0 corrected this: 0.9.0 served them at the origin whatever the issuer said, so the
    documents answered 200 at a path nothing fetched.
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
        # Unconditional from 0.16.0, even with no OAuth configured at all: the frontend
        # gets one authoritative answer in every deployment instead of a 404 to interpret.
        f"{prefix}/oauth/providers",
    }


def test_documents_are_served_with_cache_control(kms: MultiKeyFakeKms) -> None:
    """Both are on the anonymous hot path and the gateway refetches them."""
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
    """Rotation moves through the JWKS, so a long cache there is what causes an outage."""
    assert "max-age=300" in JWKS_CACHE_CONTROL
    assert "max-age=3600" in DISCOVERY_CACHE_CONTROL


def test_health_matches_the_package_shape(kms: MultiKeyFakeKms) -> None:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.include_router(
        build_identity_router(make_settings(), kms_client=kms, service="identity", version="0.9.0")
    )
    body = TestClient(app).get("/api/auth/health").json()
    assert body == {"status": "healthy", "service": "identity", "version": "0.9.0"}


def test_router_needs_a_token_service_or_a_kms_client() -> None:
    with pytest.raises(ValueError):
        build_identity_router(make_settings())


# ---------------------------------------------------------------------------
# Hooks
# ---------------------------------------------------------------------------


def test_unimplemented_hooks_raise_a_named_error() -> None:
    class ProductHooks(BaseIdentityHooks):
        pass

    hooks = ProductHooks()
    with pytest.raises(HookNotImplemented) as excinfo:
        hooks.load_user_by_email("someone@example.com")
    assert "load_user_by_email" in str(excinfo.value)
    assert "ProductHooks" in str(excinfo.value)


def test_the_two_hooks_with_safe_defaults_do_not_raise() -> None:
    """No roles and no side effects are both defensible defaults. Nothing else is."""
    hooks = BaseIdentityHooks()
    assert hooks.claims_for({"id": "user-1"}) == {}
    hooks.on_user_created({"id": "user-1"}, "password")  # must not raise


def test_may_authenticate_refuses_by_raising() -> None:
    class ProductHooks(BaseIdentityHooks):
        def may_authenticate(self, user: Any) -> None:
            if user.get("disabled"):
                raise AuthenticationRefused("Invalid email or password.")

    hooks = ProductHooks()
    hooks.may_authenticate({"disabled": False})  # permitted: not raising is the only yes
    with pytest.raises(AuthenticationRefused) as excinfo:
        hooks.may_authenticate({"disabled": True})
    assert excinfo.value.error_code == "AUTHENTICATION_REFUSED"


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


def test_only_the_hash_of_a_token_is_stored() -> None:
    """A read of the table must not be turnable into a working session."""
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
    assert len(record.token_hash) == 64  # hex SHA-256


def test_consume_is_single_use_and_returns_the_prior_state() -> None:
    """The contract both implementations share, and the one reuse detection rests on."""
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

    # A second consume fails rather than overwriting the first, which is what turns a
    # concurrent replay into a detectable event rather than a silent success.
    assert store.consume(token_hash, successor_hash="other") is None
    assert store.get(token_hash).successor_hash == "succ-hash"  # type: ignore[union-attr]


def test_revoke_family_marks_every_generation() -> None:
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
    # Idempotent: nothing left to revoke.
    assert store.revoke_family("fam-1") == 0


def test_expired_records_are_returned_not_hidden() -> None:
    """The caller has to tell "expired" from "never existed" to decide 401 versus reuse."""
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
    """M1 passes no stores, so the error a flow hits in M2 must name what to configure."""
    stores = IdentityStores()
    with pytest.raises(ValueError) as excinfo:
        stores.require_refresh_tokens()
    assert "refresh_tokens" in str(excinfo.value)


def test_is_expired_uses_the_deadline_not_the_ttl_sweep() -> None:
    """TTL is storage reclamation; DynamoDB deletes on its own schedule up to days later."""
    assert is_expired(int(time.time()) - 1) is True
    assert is_expired(int(time.time()) + 60) is False
