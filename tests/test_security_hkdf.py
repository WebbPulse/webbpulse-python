"""Tests for the HKDF-SHA256 derivation in `webbpulse.security`.

RFC 5869 appendix A.1 pins extract, expand and the pair against the published vector, and
the rest covers the separation `info` buys, the length ceiling, and the two callers that
now share the primitive: the identity TOTP cipher and a product deriving a webhook key.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from webbpulse.security import HASH_LENGTH, derive_key, expand_key, extract_key

A1_IKM = bytes.fromhex("0b" * 22)
"""RFC 5869 A.1 input keying material: 22 bytes of 0x0b."""

A1_SALT = bytes.fromhex("000102030405060708090a0b0c")
"""RFC 5869 A.1 salt."""

A1_INFO = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
"""RFC 5869 A.1 info."""

A1_PRK = bytes.fromhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
"""RFC 5869 A.1 expected pseudorandom key."""

A1_OKM = bytes.fromhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
"""RFC 5869 A.1 expected output keying material, 42 bytes."""


def test_extract_matches_rfc_5869_a1() -> None:
    """`extract_key` reproduces the PRK of RFC 5869 test case A.1."""
    assert extract_key(A1_IKM, A1_SALT) == A1_PRK


def test_expand_matches_rfc_5869_a1() -> None:
    """`expand_key` reproduces the 42 byte OKM of RFC 5869 test case A.1."""
    assert expand_key(A1_PRK, A1_INFO, 42) == A1_OKM


def test_derive_key_is_extract_then_expand_and_nothing_else() -> None:
    """The pair, as one call, is exactly the two halves composed.

    Pinned with an ASCII `info` rather than A.1's own, because `derive_key` takes `info` as
    text and encodes it as UTF-8, and A.1's info is high bytes that are not UTF-8 at all. The
    published vector is pinned on `extract_key` and `expand_key` above, which is where the
    bytes are the interface.
    """
    assert derive_key(A1_IKM, "acme.v1:one", 42, salt=A1_SALT) == expand_key(
        extract_key(A1_IKM, A1_SALT), b"acme.v1:one", 42
    )


def test_an_empty_salt_is_the_rfc_zero_filled_one() -> None:
    """The default salt hashes as `HASH_LENGTH` zero bytes, which is what RFC 5869 says."""
    assert extract_key(A1_IKM) == extract_key(A1_IKM, bytes(HASH_LENGTH))


def test_a_derivation_is_reproducible() -> None:
    """The same master and info give the same key, which is what an unsalted derive is for."""
    master = b"a" * 32
    assert derive_key(master, "acme.v1:one") == derive_key(master, "acme.v1:one")


def test_different_info_gives_independent_keys() -> None:
    """Two contexts under one master do not collide, which is the whole point of `info`."""
    master = b"a" * 32
    assert derive_key(master, "acme.v1:one") != derive_key(master, "acme.v1:two")


def test_different_masters_give_different_keys() -> None:
    """One context under two masters does not collide either."""
    assert derive_key(b"a" * 32, "acme.v1:one") != derive_key(b"b" * 32, "acme.v1:one")


def test_a_salt_changes_the_derivation() -> None:
    """A salt is part of the derivation, so a sealed secret cannot reuse another's key."""
    master = b"a" * 32
    assert derive_key(master, "acme.v1:one", salt=b"s1") != derive_key(master, "acme.v1:one", salt=b"s2")


def test_the_default_length_is_an_aes_256_key() -> None:
    """32 bytes by default, which is an AES-256 or an HMAC-SHA256 key."""
    assert len(derive_key(b"a" * 32, "acme.v1:one")) == 32


@pytest.mark.parametrize("length", [0, 1, 31, 32, 33, 64, 255 * 32])
def test_any_allowed_length_comes_back_exactly(length: int) -> None:
    """Every length up to the ceiling returns exactly that many bytes."""
    assert len(derive_key(b"a" * 32, "acme.v1:one", length)) == length


def test_a_shorter_key_is_a_prefix_of_a_longer_one() -> None:
    """HKDF is a stream, so a 16 byte key is the first 16 bytes of the 32 byte one."""
    master = b"a" * 32
    assert derive_key(master, "acme.v1:one", 16) == derive_key(master, "acme.v1:one", 32)[:16]


def test_over_the_block_ceiling_is_refused() -> None:
    """Past 255 blocks the counter wraps and the output would repeat, so it raises."""
    with pytest.raises(ValueError, match="cannot produce more than"):
        derive_key(b"a" * 32, "acme.v1:one", 255 * HASH_LENGTH + 1)


def test_a_negative_length_is_refused() -> None:
    """A negative length is a caller bug, not an empty key."""
    with pytest.raises(ValueError, match="cannot be"):
        derive_key(b"a" * 32, "acme.v1:one", -1)


def test_info_is_encoded_as_utf_8() -> None:
    """A non-ASCII context is UTF-8, so the same string derives the same key everywhere."""
    master = b"a" * 32
    assert derive_key(master, "acme.v1:café") == expand_key(extract_key(master), "acme.v1:café".encode(), 32)


def test_an_empty_master_still_derives() -> None:
    """Extract accepts any length of input keying material, including none."""
    assert len(derive_key(b"", "acme.v1:one")) == 32


def test_expand_only_matches_a_hand_rolled_product_shim() -> None:
    """The expand half alone reproduces what a product that skipped extract already stores.

    A product whose master key is already high-entropy random commonly hashed it and expanded
    from that, with no extract step. Such a key must keep deriving the same bytes across the
    swap to this module, so `expand_key` is public and is the call that migration uses.
    """
    master = "super-master-key"
    info = b"standupless.webhook.v1:wh_123:s4lt"
    prk = hashlib.sha256(master.encode()).digest()

    output = b""
    block = b""
    counter = 1
    while len(output) < 32:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        output += block
        counter += 1

    assert expand_key(prk, info, 32) == output[:32]


def test_the_totp_cipher_derives_through_the_shared_primitive() -> None:
    """`SecretMasterKeyCipher` opens what it seals, now that it derives through this module."""
    from webbpulse.identity.crypto import SecretMasterKeyCipher

    cipher = SecretMasterKeyCipher(b"m" * 32)
    sealed = cipher.seal(b"JBSWY3DPEHPK3PXP", user_id="u-1")
    assert cipher.open(sealed, user_id="u-1") == b"JBSWY3DPEHPK3PXP"


def test_the_totp_cipher_still_matches_the_cryptography_hkdf() -> None:
    """The refactor is byte for byte: no stored TOTP seed needs rewrapping.

    Derives the same key the `cryptography` HKDF produced for one salt and info, so a seed
    sealed before this change opens after it.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    master = b"m" * 32
    salt = b"s" * 16
    info = b"webbpulse-totp-seed-v1\x00purpose=totp\x00user_id=u-1"
    expected = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(master)

    assert expand_key(extract_key(master, salt), info, 32) == expected
