"""Tests for `webbpulse.testing.FakeKms`.

The fake is the reconciliation of five near-identical copies across the org, so its own
behaviour is pinned here: it signs for real, it serves one key or many, it records what it
was asked for, and it can be made to fail a key lookup.
"""

from __future__ import annotations

from typing import Any

import pytest

from webbpulse.identity import DIGEST_MESSAGE_TYPE, KMS_SIGNING_ALGORITHM, KmsSigner, kid_for_der, public_jwk_from_kms
from webbpulse.testing import FakeKms

cryptography = pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils  # noqa: E402

KEY_A = "arn:aws:kms:us-west-2:111122223333:key/aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa"
KEY_B = "arn:aws:kms:us-west-2:111122223333:key/bbbbbbbb-2222-2222-2222-bbbbbbbbbbbb"


@pytest.fixture(scope="module")
def second_key() -> rsa.RSAPrivateKey:
    """A second 2048-bit key, for the multi-key cases."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def der_of(key: rsa.RSAPrivateKey) -> bytes:
    """The DER SubjectPublicKeyInfo for a key, the bytes a `kid` is derived from."""
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def test_get_public_key_answers_the_kms_shape(fake_kms: FakeKms, rsa_key: rsa.RSAPrivateKey) -> None:
    """The response carries every member the token service reads, for the held key."""
    response = fake_kms.get_public_key(KeyId=KEY_A)
    assert response["KeyId"] == KEY_A
    assert response["PublicKey"] == der_of(rsa_key)
    assert response["KeySpec"] == "RSA_2048"
    assert response["KeyUsage"] == "SIGN_VERIFY"
    assert response["SigningAlgorithms"] == [KMS_SIGNING_ALGORITHM]


def test_a_single_key_answers_for_every_key_id(fake_kms: FakeKms) -> None:
    """One key serves whatever id is asked for, which is what a single-key test wants."""
    assert fake_kms.get_public_key(KeyId=KEY_A)["PublicKey"] == fake_kms.get_public_key(KeyId=KEY_B)["PublicKey"]


def test_the_signature_verifies_against_the_held_public_key(fake_kms: FakeKms, rsa_key: rsa.RSAPrivateKey) -> None:
    """The fake signs for real, so the signature verifies rather than merely being bytes."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(b"header.payload")
    prehashed = digest.finalize()

    signature = fake_kms.sign(
        KeyId=KEY_A,
        Message=prehashed,
        MessageType=DIGEST_MESSAGE_TYPE,
        SigningAlgorithm=KMS_SIGNING_ALGORITHM,
    )["Signature"]

    rsa_key.public_key().verify(signature, prehashed, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))


def test_sign_treats_the_message_as_the_digest(fake_kms: FakeKms, rsa_key: rsa.RSAPrivateKey) -> None:
    """`MessageType=DIGEST` means the message is already the digest and is not hashed again.

    Signing the signing input directly, as a fake that re-hashed would effectively do,
    produces a different signature from signing its digest, and only the latter is what KMS
    returns for a `DIGEST` call.
    """
    signing_input = b"header.payload"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(signing_input)
    prehashed = digest.finalize()

    over_digest = fake_kms.sign(
        KeyId=KEY_A,
        Message=prehashed,
        MessageType=DIGEST_MESSAGE_TYPE,
        SigningAlgorithm=KMS_SIGNING_ALGORITHM,
    )["Signature"]
    over_rehash = rsa_key.sign(prehashed, padding.PKCS1v15(), hashes.SHA256())

    assert over_digest != over_rehash
    assert over_digest == rsa_key.sign(prehashed, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))


def test_calls_are_recorded_for_assertion(fake_kms: FakeKms) -> None:
    """Both calls are recorded, so a test asserts what was asked for rather than trusting it."""
    fake_kms.get_public_key(KeyId=KEY_A)
    fake_kms.sign(
        KeyId=KEY_A,
        Message=b"0" * 32,
        MessageType=DIGEST_MESSAGE_TYPE,
        SigningAlgorithm=KMS_SIGNING_ALGORITHM,
    )

    assert fake_kms.get_public_key_calls == [KEY_A]
    assert fake_kms.sign_calls[0]["MessageType"] == DIGEST_MESSAGE_TYPE
    assert fake_kms.sign_calls[0]["SigningAlgorithm"] == KMS_SIGNING_ALGORITHM


def test_a_key_mapping_serves_each_key_by_id(rsa_key: rsa.RSAPrivateKey, second_key: rsa.RSAPrivateKey) -> None:
    """With a mapping, each key id gets its own key, which is what a rotation test needs."""
    kms = FakeKms({KEY_A: rsa_key, KEY_B: second_key})
    assert kms.get_public_key(KeyId=KEY_A)["PublicKey"] == der_of(rsa_key)
    assert kms.get_public_key(KeyId=KEY_B)["PublicKey"] == der_of(second_key)


def test_an_unknown_key_id_raises_against_a_mapping(rsa_key: rsa.RSAPrivateKey) -> None:
    """A key the fake was not given is a `KeyError`, not a silent wrong signature."""
    kms = FakeKms({KEY_A: rsa_key})
    with pytest.raises(KeyError):
        kms.get_public_key(KeyId=KEY_B)


def test_a_failing_key_raises_on_lookup(rsa_key: rsa.RSAPrivateKey, second_key: rsa.RSAPrivateKey) -> None:
    """`failing` stands in for the NotFoundException a deleted signing key produces."""
    kms = FakeKms({KEY_A: rsa_key, KEY_B: second_key}, failing={KEY_B})
    assert kms.get_public_key(KeyId=KEY_A)["KeyId"] == KEY_A
    with pytest.raises(RuntimeError, match="NotFoundException"):
        kms.get_public_key(KeyId=KEY_B)
    assert kms.get_public_key_calls == [KEY_A, KEY_B]


def test_the_key_spec_is_reportable(rsa_key: rsa.RSAPrivateKey) -> None:
    """A wrong `KeySpec` is reportable, so the token service's refusal of one is testable."""
    assert FakeKms(rsa_key, key_spec="RSA_4096").get_public_key(KeyId=KEY_A)["KeySpec"] == "RSA_4096"


def test_a_supplied_der_overrides_the_derived_one(rsa_key: rsa.RSAPrivateKey, second_key: rsa.RSAPrivateKey) -> None:
    """Passing `der` reports a public key that does not match what is signed with."""
    kms = FakeKms(rsa_key, der_of(second_key))
    assert kms.get_public_key(KeyId=KEY_A)["PublicKey"] == der_of(second_key)
    assert kms.der_for(KEY_A) == der_of(second_key)


def test_a_der_alongside_a_key_mapping_is_refused(rsa_key: rsa.RSAPrivateKey) -> None:
    """One DER cannot describe several keys, so passing both is a construction error."""
    with pytest.raises(ValueError, match="single key"):
        FakeKms({KEY_A: rsa_key}, der_of(rsa_key))


def test_der_for_matches_the_kid_the_signer_derives(fake_kms: FakeKms, rsa_key: rsa.RSAPrivateKey) -> None:
    """`der_for` returns exactly the bytes `kid_for_der` hashes, so a kid is assertable."""
    assert fake_kms.der_for(KEY_A) == der_of(rsa_key)
    assert KmsSigner(fake_kms, KEY_A).kid == kid_for_der(fake_kms.der_for(KEY_A))


def test_a_token_signed_through_the_fake_verifies_against_its_jwk(fake_kms: FakeKms) -> None:
    """End to end: the fake drives a real `KmsSigner` whose token verifies against the JWK."""
    jwt = pytest.importorskip("jwt")
    signer = KmsSigner(fake_kms, KEY_A)
    token = signer.encode({"sub": "user-1", "iss": "https://example.test", "aud": "aud"})

    key: Any = jwt.PyJWK.from_dict(public_jwk_from_kms(fake_kms, KEY_A)).key
    claims = jwt.decode(token, key, algorithms=["RS256"], issuer="https://example.test", audience="aud")
    assert claims["sub"] == "user-1"
