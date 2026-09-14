"""`LocalSigner`: an in-process stand-in for the KMS signing client, for local stacks.

It implements the same two-method `KmsClient` protocol the token service signs through, with
real RSA PKCS #1 v1.5 SHA-256, so a token it mints verifies against the JWKS built from the
same key. The key is derived from a seed string rather than generated, so `kid` survives a
restart and a browser holding a token from the previous process is not signed out. Needs
`cryptography`, which the `identity` extra brings in.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any, Final, cast

if TYPE_CHECKING:  # pragma: no cover
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

    from webbpulse.identity.settings import IdentitySettings
    from webbpulse.identity.tokens import KmsClient

__all__ = ["DEFAULT_LOCAL_SEED", "LOCAL_KEY_BITS", "LocalSigner", "LocalSignerRefused", "signing_client"]

DEFAULT_LOCAL_SEED: Final = "webbpulse-local-identity"

LOCAL_KEY_BITS: Final = 2048

_REFUSED_ENVIRONMENTS: Final[frozenset[str]] = frozenset({"production", "prod"})


class LocalSignerRefused(RuntimeError):
    """The local signer was asked for in an environment that must never hold key material.

    A distinct type so a composition root can tell this apart from a configuration typo, and
    named for the condition rather than for the switch that requested it.
    """


def _refuse_production(environment: str) -> None:
    """Raise when `environment` names production, whatever the switch says.

    Mirrors `mint_test_token`: a signer whose private half lives in the process is not a
    thing one editing mistake should be able to put in front of real users.
    """
    if environment.strip().lower() in _REFUSED_ENVIRONMENTS:
        raise LocalSignerRefused(
            f"The local identity signer is refused in environment {environment!r}. Its "
            "private key lives in the process and is derived from a seed, so anybody "
            "holding the seed can mint tokens for every user."
        )


def derive_rsa_key(seed: str, *, key_id: str = "") -> RSAPrivateKey:
    """Derive one RSA private key deterministically from `seed` and `key_id`.

    Deterministic so `kid`, which is a hash of the public half, is the same across restarts
    and across the processes of one local stack. Generation is seeded from a SHAKE-256
    stream over the two inputs, so two key ids under one seed are different keys.
    """
    material = hashlib.shake_256(f"{seed}\x00{key_id}".encode()).digest(32)
    state = int.from_bytes(material, "big")

    class _SeededRandom:
        """A deterministic byte source standing in for the system CSPRNG."""

        def __init__(self, start: int) -> None:
            """Hold the counter the stream is expanded from."""
            self._counter = start

        def read(self, size: int) -> bytes:
            """Return `size` deterministic bytes, advancing the counter."""
            out = bytearray()
            while len(out) < size:
                self._counter += 1
                out += hashlib.sha512(self._counter.to_bytes(64, "big")).digest()
            return bytes(out[:size])

    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers

    source = _SeededRandom(state)
    p = _derive_prime(source)
    q = _derive_prime(source)
    while p == q:
        q = _derive_prime(source)
    if p < q:
        p, q = q, p
    e = 65537
    n = p * q
    d = pow(e, -1, (p - 1) * (q - 1))
    numbers = RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=d % (p - 1),
        dmq1=d % (q - 1),
        iqmp=pow(q, -1, p),
        public_numbers=RSAPublicNumbers(e=e, n=n),
    )
    return numbers.private_key()


_SMALL_PRIMES: Final = (
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
    53,
    59,
    61,
    67,
    71,
    73,
    79,
    83,
    89,
    97,
)

_MILLER_RABIN_BASES: Final = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def _is_probable_prime(candidate: int) -> bool:
    """Deterministic Miller-Rabin over the first twelve prime bases.

    Those bases are a proof of primality below 3.3e24 and an overwhelming probabilistic
    test above it, which is the same standard every RSA key generator applies.
    """
    if candidate < 2:
        return False
    for prime in _SMALL_PRIMES:
        if candidate == prime:
            return True
        if candidate % prime == 0:
            return False
    remainder = candidate - 1
    exponent = 0
    while remainder % 2 == 0:
        remainder //= 2
        exponent += 1
    for base in _MILLER_RABIN_BASES:
        witness = pow(base, remainder, candidate)
        if witness in (1, candidate - 1):
            continue
        for _ in range(exponent - 1):
            witness = pow(witness, 2, candidate)
            if witness == candidate - 1:
                break
        else:
            return False
    return True


def _derive_prime(source: Any) -> int:
    """Draw candidates from `source` until one is a probable prime of half the key size."""
    bits = LOCAL_KEY_BITS // 2
    while True:
        candidate = int.from_bytes(source.read(bits // 8), "big")
        candidate |= (1 << (bits - 1)) | 1
        if candidate % 65537 != 0 and _is_probable_prime(candidate):
            return candidate


class LocalSigner:
    """An in-process KMS stand-in implementing `sign` and `get_public_key`.

    One key per key id, derived from the seed, so `KmsSigner` and `public_jwk_from_kms` work
    against it unchanged and a rotation across two key ids is two distinct keys. It refuses
    to exist in production.
    """

    def __init__(self, *, seed: str = DEFAULT_LOCAL_SEED, environment: str = "local") -> None:
        """Bind the signer to a seed, refusing a production environment outright."""
        _refuse_production(environment)
        self._seed = seed
        self._keys: dict[str, RSAPrivateKey] = {}

    @property
    def seed(self) -> str:
        """The seed every key of this signer is derived from."""
        return self._seed

    def _key_for(self, key_id: str) -> RSAPrivateKey:
        """The private key for `key_id`, derived once and held for the process."""
        key = self._keys.get(key_id)
        if key is None:
            key = derive_rsa_key(self._seed, key_id=key_id)
            self._keys[key_id] = key
        return key

    def der_for(self, key_id: str) -> bytes:
        """The DER SubjectPublicKeyInfo for `key_id`, which `kid_for_der` hashes."""
        from cryptography.hazmat.primitives import serialization

        public_bytes: bytes = (
            self._key_for(key_id)
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        return public_bytes

    def get_public_key(self, *, KeyId: str) -> dict[str, Any]:
        """Answer the `kms:GetPublicKey` shape for `KeyId`, DER bytes included."""
        from webbpulse.identity.tokens import KMS_KEY_SPEC, KMS_SIGNING_ALGORITHM

        return {
            "KeyId": KeyId,
            "PublicKey": self.der_for(KeyId),
            "KeySpec": KMS_KEY_SPEC,
            "KeyUsage": "SIGN_VERIFY",
            "SigningAlgorithms": [KMS_SIGNING_ALGORITHM],
        }

    def sign(self, *, KeyId: str, Message: bytes, MessageType: str, SigningAlgorithm: str) -> dict[str, Any]:
        """Sign a prehashed message the way KMS would, returning the raw PKCS #1 signature.

        `MessageType` and `SigningAlgorithm` are checked rather than ignored, so a caller
        that would have been rejected by KMS is rejected here too.
        """
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, utils

        from webbpulse.identity.tokens import DIGEST_MESSAGE_TYPE, KMS_SIGNING_ALGORITHM

        if MessageType != DIGEST_MESSAGE_TYPE:
            raise ValueError(f"LocalSigner signs prehashed digests only, got MessageType {MessageType!r}.")
        if SigningAlgorithm != KMS_SIGNING_ALGORITHM:
            raise ValueError(
                f"LocalSigner signs with {KMS_SIGNING_ALGORITHM!r} only, got {SigningAlgorithm!r}. "
                "The HTTP API JWT authorizer supports only RSA-based algorithms."
            )
        signature = self._key_for(KeyId).sign(Message, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
        return {"KeyId": KeyId, "Signature": signature, "SigningAlgorithm": SigningAlgorithm}


def signing_client(settings: IdentitySettings) -> KmsClient:
    """The signing client this deployment's `signer` setting selects.

    `kms` builds a boto3 KMS client, which is what every deployed environment uses; `local`
    builds a `LocalSigner` over `local_signer_seed`, which is refused in production by both
    the settings validator and the signer itself.
    """
    if settings.signer == "local":
        return LocalSigner(seed=settings.local_signer_seed_value, environment=settings.environment)
    import boto3

    return cast("KmsClient", boto3.client("kms"))
