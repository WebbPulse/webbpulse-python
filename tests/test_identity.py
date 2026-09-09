"""Tests for `webbpulse.identity`.

The important test in this file is `test_pyjwt_verifies_a_kms_shaped_token_against_the_jwk`.
Everything else checks a detail; that one checks the whole claim M0 exists to make.

**What it proves, and why the fake is not cheating.** A locally generated RSA key stands in
for the KMS key. The fake client returns that key's DER SubjectPublicKeyInfo from
`get_public_key` and, from `sign`, a real `RSASSA-PKCS1-v1_5` SHA-256 signature over the
digest it was handed. That is precisely the contract the KMS documentation states for
`MessageType="DIGEST"` with `SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256"`: KMS "skips the
hashing step in the signing algorithm" and returns a signature whose "encoding ... is
defined by PKCS #1 in RFC 8017". So the fake differs from KMS in who holds the private key
and in nothing else that the output depends on.

PyJWT then verifies the resulting token using **only** the JWK this module emitted, through
`PyJWKClient`'s own JWK-to-key path. Nothing in the verification touches the original key
object. If `n` or `e` were encoded wrong, if `kid` disagreed between the header and the JWK,
or if the signing input were assembled differently from what the signature covers, this test
fails. That is the encoding proof the milestone asks for.

**Why not moto.** The standard's section 9.4 records that moto's fidelity for `kms:Sign`
with `RSASSA_PKCS1_V1_5_SHA_256` against a real JWT verifier could not be confirmed. A test
that passes because moto and this module make the same mistake would prove nothing, so the
signing seam is faked with a real cryptographic primitive instead and the fidelity question
is settled against real KMS in the staging spike rather than here. `botocore.stub.Stubber`
covers the request-shape assertions, where the point is the exact parameters sent.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import pytest

from webbpulse.identity import (
    DIGEST_MESSAGE_TYPE,
    JWS_ALGORITHM,
    KMS_SIGNING_ALGORITHM,
    KmsSigner,
    TokenMintingDisabled,
    build_discovery_document,
    build_jwks,
    identity_router,
    kid_for_der,
    mint_test_token,
    public_jwk_from_kms,
)

cryptography = pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402

KEY_ID = "arn:aws:kms:us-west-2:111122223333:key/11111111-2222-3333-4444-555555555555"
ISSUER = "https://api.staging.example.com"
AUDIENCE = "webbpulse-staging"


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    """One 2048-bit key for the module. Generation is slow enough to be worth sharing."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def der_spki(rsa_key: rsa.RSAPrivateKey) -> bytes:
    return rsa_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


class FakeKms:
    """A KMS client that signs for real, with the private key held locally.

    Faithful to the documented KMS contract in the two ways the output depends on: it
    signs the digest it is given without re-hashing it (`MessageType="DIGEST"`), and it
    returns the raw PKCS #1 signature octet string rather than any wrapper.
    """

    def __init__(self, key: rsa.RSAPrivateKey, der: bytes, *, key_spec: str = "RSA_2048"):
        self._key = key
        self._der = der
        self._key_spec = key_spec
        self.sign_calls: list[dict[str, Any]] = []

    def get_public_key(self, *, KeyId: str) -> dict[str, Any]:
        return {
            "KeyId": KeyId,
            "PublicKey": self._der,
            "KeySpec": self._key_spec,
            "KeyUsage": "SIGN_VERIFY",
            "SigningAlgorithms": [KMS_SIGNING_ALGORITHM],
        }

    def sign(
        self, *, KeyId: str, Message: bytes, MessageType: str, SigningAlgorithm: str
    ) -> dict[str, Any]:
        self.sign_calls.append(
            {
                "KeyId": KeyId,
                "Message": Message,
                "MessageType": MessageType,
                "SigningAlgorithm": SigningAlgorithm,
            }
        )
        assert MessageType == DIGEST_MESSAGE_TYPE
        assert SigningAlgorithm == KMS_SIGNING_ALGORITHM
        # Prehashed: sign the digest as-is, which is what DIGEST means.
        signature = self._key.sign(
            Message,
            padding.PKCS1v15(),
            cryptography.hazmat.primitives.asymmetric.utils.Prehashed(hashes.SHA256()),
        )
        return {"KeyId": KeyId, "Signature": signature, "SigningAlgorithm": SigningAlgorithm}


@pytest.fixture
def fake_kms(rsa_key: rsa.RSAPrivateKey, der_spki: bytes) -> FakeKms:
    return FakeKms(rsa_key, der_spki)


# ---------------------------------------------------------------------------
# The proof: a token of this module's construction verifies against this module's JWK.
# ---------------------------------------------------------------------------


def test_pyjwt_verifies_a_kms_shaped_token_against_the_jwk(fake_kms: FakeKms) -> None:
    """End to end: sign with the KMS path, verify with PyJWT using only the emitted JWK.

    This is the encoding proof. The verification key is reconstructed from the JWK's `n`
    and `e` alone, so a wrong integer encoding cannot pass.
    """
    jwt = pytest.importorskip("jwt")

    signer = KmsSigner(fake_kms, KEY_ID)
    token = mint_test_token(
        signer,
        enabled=True,
        environment="staging",
        issuer=ISSUER,
        audience=AUDIENCE,
        subject="user-123",
    )

    jwk = public_jwk_from_kms(fake_kms, KEY_ID)
    # Reconstructed from the JWK, never from the original key object.
    verification_key = jwt.PyJWK.from_dict(jwk).key

    claims = jwt.decode(
        token,
        verification_key,
        algorithms=[JWS_ALGORITHM],
        issuer=ISSUER,
        audience=AUDIENCE,
        options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub"]},
    )

    assert claims["typ"] == "access"
    assert claims["sub"] == "user-123"
    assert claims["iss"] == ISSUER
    assert claims["aud"] == AUDIENCE
    assert claims["exp"] == claims["iat"] + 600
    assert claims["nbf"] == claims["iat"]
    assert len(claims["jti"]) == 32

    header = jwt.get_unverified_header(token)
    assert header == {"alg": "RS256", "typ": "JWT", "kid": jwk["kid"]}


def test_a_tampered_payload_fails_verification(fake_kms: FakeKms) -> None:
    """The signature covers the payload, so rewriting a claim invalidates the token."""
    jwt = pytest.importorskip("jwt")

    signer = KmsSigner(fake_kms, KEY_ID)
    token = mint_test_token(
        signer,
        enabled=True,
        environment="staging",
        issuer=ISSUER,
        audience=AUDIENCE,
        subject="user-123",
    )
    header_b64, payload_b64, signature_b64 = token.split(".")

    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
    payload["sub"] = "somebody-else"
    forged = (
        base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )

    key = jwt.PyJWK.from_dict(public_jwk_from_kms(fake_kms, KEY_ID)).key
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(
            f"{header_b64}.{forged}.{signature_b64}",
            key,
            algorithms=[JWS_ALGORITHM],
            issuer=ISSUER,
            audience=AUDIENCE,
        )


# ---------------------------------------------------------------------------
# The KMS request shape, asserted against botocore's own model via Stubber.
# ---------------------------------------------------------------------------


def test_sign_sends_a_digest_with_the_pkcs1_algorithm(der_spki: bytes) -> None:
    """`kms:Sign` is called with the SHA-256 digest, `DIGEST`, and the PKCS1 algorithm.

    Through `Stubber`, so the parameter names and types are validated against botocore's
    service model rather than against a hand-written fake that would accept a typo.
    """
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber

    # An explicit session with dummy credentials, not the default one. `Stubber` never lets
    # a request reach the network, but the client still resolves credentials when it is
    # built, so a default session would pick up whatever profile the developer happens to
    # have configured and fail here for reasons that have nothing to do with this module.
    session = boto3.session.Session(
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        aws_session_token="testing",
        region_name="us-west-2",
    )
    client = session.client("kms")
    signing_input = b"header.payload"
    expected_digest = hashlib.sha256(signing_input).digest()

    with Stubber(client) as stubber:
        stubber.add_response(
            "sign",
            {"KeyId": KEY_ID, "Signature": b"sig", "SigningAlgorithm": KMS_SIGNING_ALGORITHM},
            {
                "KeyId": KEY_ID,
                "Message": expected_digest,
                "MessageType": "DIGEST",
                "SigningAlgorithm": "RSASSA_PKCS1_V1_5_SHA_256",
            },
        )
        signer = KmsSigner(client, KEY_ID)
        assert signer.sign(signing_input) == b"sig"
        stubber.assert_no_pending_responses()

    assert len(expected_digest) == 32


def test_get_public_key_is_called_once_per_signer_for_the_kid(fake_kms: FakeKms) -> None:
    """`kid` is derived once and held, not fetched per signature."""
    signer = KmsSigner(fake_kms, KEY_ID)
    calls: list[str] = []
    original = fake_kms.get_public_key

    def counting(*, KeyId: str) -> dict[str, Any]:
        calls.append(KeyId)
        return original(KeyId=KeyId)

    fake_kms.get_public_key = counting  # type: ignore[method-assign]
    assert signer.kid == signer.kid
    signer.encode({"sub": "a"})
    signer.encode({"sub": "b"})
    assert len(calls) == 1


# ---------------------------------------------------------------------------
# `kid` and the JWK fields.
# ---------------------------------------------------------------------------


def test_kid_is_the_base64url_sha256_of_the_der_spki(fake_kms: FakeKms, der_spki: bytes) -> None:
    expected = base64.urlsafe_b64encode(hashlib.sha256(der_spki).digest()).rstrip(b"=").decode()
    assert kid_for_der(der_spki) == expected
    assert public_jwk_from_kms(fake_kms, KEY_ID)["kid"] == expected
    assert KmsSigner(fake_kms, KEY_ID).kid == expected
    assert "=" not in expected


def test_kid_differs_between_two_keys(der_spki: bytes) -> None:
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_der = other.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert kid_for_der(der_spki) != kid_for_der(other_der)


def test_jwk_fields_match_the_rsa_public_numbers(
    fake_kms: FakeKms, rsa_key: rsa.RSAPrivateKey
) -> None:
    """`n` and `e` are minimum-length big-endian, with no DER leading zero carried over."""
    jwk = public_jwk_from_kms(fake_kms, KEY_ID)
    numbers = rsa_key.public_key().public_numbers()

    n_bytes = base64.urlsafe_b64decode(jwk["n"] + "==")
    e_bytes = base64.urlsafe_b64decode(jwk["e"] + "=")

    assert int.from_bytes(n_bytes, "big") == numbers.n
    assert int.from_bytes(e_bytes, "big") == numbers.e
    # A 2048-bit modulus is exactly 256 bytes with no leading zero. DER would have added
    # one to keep the integer positive, and carrying it here is the classic JWK bug.
    assert len(n_bytes) == 256
    assert n_bytes[0] != 0
    # 65537 is the standard exponent and encodes as AQAB.
    assert jwk["e"] == "AQAB"

    assert jwk["kty"] == "RSA"
    assert jwk["use"] == "sig"
    assert jwk["alg"] == "RS256"


def test_a_non_rsa_2048_key_spec_is_refused(rsa_key: rsa.RSAPrivateKey, der_spki: bytes) -> None:
    """A key created with the wrong spec fails here rather than at the authorizer."""
    wrong = FakeKms(rsa_key, der_spki, key_spec="RSA_4096")
    with pytest.raises(ValueError, match="RSA_2048"):
        public_jwk_from_kms(wrong, KEY_ID)


# ---------------------------------------------------------------------------
# The two documents.
# ---------------------------------------------------------------------------


def test_build_jwks_wraps_keys_in_an_array(fake_kms: FakeKms) -> None:
    jwk = public_jwk_from_kms(fake_kms, KEY_ID)
    assert build_jwks([jwk]) == {"keys": [jwk]}
    assert build_jwks([jwk, jwk])["keys"] == [jwk, jwk]


def test_discovery_document_has_the_five_required_members() -> None:
    doc = build_discovery_document(ISSUER)
    assert set(doc) == {
        "issuer",
        "jwks_uri",
        "response_types_supported",
        "subject_types_supported",
        "id_token_signing_alg_values_supported",
    }
    assert doc["issuer"] == ISSUER
    assert doc["jwks_uri"] == f"{ISSUER}/.well-known/jwks.json"
    assert doc["id_token_signing_alg_values_supported"] == ["RS256"]


def test_a_trailing_slash_on_the_issuer_is_normalised_away() -> None:
    """The classic failure: `iss` and the authorizer's issuer differing by one byte."""
    assert build_discovery_document(f"{ISSUER}/")["issuer"] == ISSUER
    assert build_discovery_document(f"{ISSUER}/")["jwks_uri"] == (f"{ISSUER}/.well-known/jwks.json")


def test_router_serves_both_documents_at_the_origin(fake_kms: FakeKms) -> None:
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    jwk = public_jwk_from_kms(fake_kms, KEY_ID)
    app = fastapi.FastAPI()
    app.include_router(identity_router(issuer=ISSUER, jwks=lambda: [jwk]))
    client = TestClient(app)

    jwks_response = client.get("/.well-known/jwks.json")
    assert jwks_response.status_code == 200
    assert jwks_response.json() == {"keys": [jwk]}

    discovery = client.get("/.well-known/openid-configuration")
    assert discovery.status_code == 200
    assert discovery.json()["jwks_uri"] == f"{ISSUER}/.well-known/jwks.json"


def test_router_rejects_a_non_callable_jwks() -> None:
    pytest.importorskip("fastapi")
    with pytest.raises(TypeError, match="callable"):
        identity_router(issuer=ISSUER, jwks=[{"kty": "RSA"}])


def test_the_jwks_callable_is_read_per_request(fake_kms: FakeKms) -> None:
    """A rotation that adds a key changes the document without rebuilding the router."""
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    keys: list[dict[str, str]] = []
    app = fastapi.FastAPI()
    app.include_router(identity_router(issuer=ISSUER, jwks=lambda: keys))
    client = TestClient(app)

    assert client.get("/.well-known/jwks.json").json() == {"keys": []}
    keys.append(public_jwk_from_kms(fake_kms, KEY_ID))
    assert len(client.get("/.well-known/jwks.json").json()["keys"]) == 1


# ---------------------------------------------------------------------------
# `mint_test_token`'s two gates.
# ---------------------------------------------------------------------------


def test_mint_test_token_is_refused_unless_enabled(fake_kms: FakeKms) -> None:
    with pytest.raises(TokenMintingDisabled, match="disabled"):
        mint_test_token(
            KmsSigner(fake_kms, KEY_ID),
            enabled=False,
            environment="staging",
            issuer=ISSUER,
            audience=AUDIENCE,
            subject="user-123",
        )


@pytest.mark.parametrize("environment", ["production", "PRODUCTION", "prod"])
def test_mint_test_token_is_refused_in_production_even_when_enabled(
    fake_kms: FakeKms, environment: str
) -> None:
    """The second gate. A flag left true in the wrong place is still refused."""
    with pytest.raises(TokenMintingDisabled, match="refused"):
        mint_test_token(
            KmsSigner(fake_kms, KEY_ID),
            enabled=True,
            environment=environment,
            issuer=ISSUER,
            audience=AUDIENCE,
            subject="user-123",
        )


def test_extra_claims_cannot_overwrite_the_reserved_ones(fake_kms: FakeKms) -> None:
    """The seam adds claims under the reserved set, never over it."""
    jwt = pytest.importorskip("jwt")

    token = mint_test_token(
        KmsSigner(fake_kms, KEY_ID),
        enabled=True,
        environment="staging",
        issuer=ISSUER,
        audience=AUDIENCE,
        subject="user-123",
        extra_claims={"iss": "https://evil.example.com", "typ": "reset", "roles": ["admin"]},
    )
    claims = jwt.decode(token, options={"verify_signature": False}, audience=AUDIENCE)
    assert claims["iss"] == ISSUER
    assert claims["typ"] == "access"
    assert claims["roles"] == ["admin"]


def test_expiry_defaults_to_ten_minutes(fake_kms: FakeKms) -> None:
    """Section 3.2 of the standard: a ten minute access token."""
    jwt = pytest.importorskip("jwt")

    token = mint_test_token(
        KmsSigner(fake_kms, KEY_ID),
        enabled=True,
        environment="staging",
        issuer=ISSUER,
        audience=AUDIENCE,
        subject="user-123",
        now=1_700_000_000,
    )
    claims = jwt.decode(token, options={"verify_signature": False}, audience=AUDIENCE)
    assert claims["iat"] == 1_700_000_000
    assert claims["exp"] == 1_700_000_600
