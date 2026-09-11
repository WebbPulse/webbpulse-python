"""KMS envelope encryption for the one identity secret that cannot be hashed.

A TOTP seed is a symmetric shared secret, so it cannot be hashed. It is sealed under a
per-secret KMS data key with AES-256-GCM, bound to the user by the encryption context.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, Protocol

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Mapping

__all__ = [
    "AES_KEY_BYTES",
    "GCM_NONCE_BYTES",
    "TOTP_ENCRYPTION_PURPOSE",
    "EnvelopeCipher",
    "EnvelopeDecryptionFailed",
    "KmsDataKeyClient",
    "SealedSecret",
    "encryption_context",
]

AES_KEY_BYTES: Final = 32

GCM_NONCE_BYTES: Final = 12

TOTP_ENCRYPTION_PURPOSE: Final = "totp"


class EnvelopeDecryptionFailed(Exception):
    """A sealed secret would not open.

    One type for every cause, so a caller cannot tell a wrong encryption context from a
    failed tag. `reason` carries the detail for a log and must not be returned to a caller.
    """

    def __init__(self, reason: str) -> None:
        """Record the log-only reason this envelope would not open."""
        super().__init__(reason)
        self.reason = reason


class KmsDataKeyClient(Protocol):
    """The two KMS calls the envelope needs, typed structurally.

    Signatures are boto3's, PascalCase keywords included, so a real client satisfies the
    protocol with no adapter and a test can pass a two-method fake.
    """

    def generate_data_key(
        self,
        *,
        KeyId: str,
        NumberOfBytes: int,
        EncryptionContext: Mapping[str, str],
    ) -> Mapping[str, Any]: ...

    def decrypt(
        self,
        *,
        CiphertextBlob: bytes,
        EncryptionContext: Mapping[str, str],
    ) -> Mapping[str, Any]: ...


def encryption_context(user_id: str, *, purpose: str = TOTP_ENCRYPTION_PURPOSE) -> dict[str, str]:
    """Build the authenticated additional data binding a ciphertext to one user and one use.

    `user_id` stops a ciphertext being moved between rows and `purpose` stops one sealed for
    another feature being replayed as a TOTP seed.
    """
    return {"user_id": user_id, "purpose": purpose}


@dataclass(frozen=True, slots=True)
class SealedSecret:
    """A secret encrypted under a data key that is itself encrypted under a KMS key.

    All three base64 fields are safe to store: none is a secret on its own, and only KMS can
    open the wrapped data key.
    """

    ciphertext: str
    nonce: str
    wrapped_key: str

    def as_item(self) -> dict[str, str]:
        """The three fields under the attribute names the table uses."""
        return {
            "secret_ciphertext": self.ciphertext,
            "secret_nonce": self.nonce,
            "wrapped_data_key": self.wrapped_key,
        }

    @classmethod
    def from_item(cls, item: Mapping[str, Any]) -> SealedSecret | None:
        """Read one back from a stored item, or `None` when any part is missing.

        A half-written row is reported as "no usable factor" rather than raising on the
        login path.
        """
        ciphertext = str(item.get("secret_ciphertext", ""))
        nonce = str(item.get("secret_nonce", ""))
        wrapped = str(item.get("wrapped_data_key", ""))
        if not ciphertext or not nonce or not wrapped:
            return None
        return cls(ciphertext=ciphertext, nonce=nonce, wrapped_key=wrapped)


class EnvelopeCipher:
    """Seals and opens a secret with a KMS data key and local AES-256-GCM.

    Holds no key material between calls: the plaintext data key exists only inside `seal`
    and `open`, and is never returned or stored.
    """

    def __init__(self, key_id: str, client: KmsDataKeyClient) -> None:
        """Bind the cipher to one KMS data key and a client that can call it."""
        if not key_id:
            raise ValueError(
                "EnvelopeCipher needs a KMS key id. Set IdentitySettings.data_key_arn to "
                "the identity-data key for this environment. It must not be the signing "
                "key: a key that can both sign tokens and decrypt seeds makes the blast "
                "radius of either compromise the whole of both."
            )
        self._key_id = key_id
        self._client = client

    @property
    def key_id(self) -> str:
        """The KMS key data keys are generated under."""
        return self._key_id

    def seal(
        self,
        plaintext: bytes,
        *,
        user_id: str,
        purpose: str = TOTP_ENCRYPTION_PURPOSE,
    ) -> SealedSecret:
        """Encrypt `plaintext` under a fresh data key bound to this user.

        One `GenerateDataKey` per call: a data key is never reused across secrets, and the
        plaintext key does not outlive the call.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        context = encryption_context(user_id, purpose=purpose)
        response = self._client.generate_data_key(
            KeyId=self._key_id,
            NumberOfBytes=AES_KEY_BYTES,
            EncryptionContext=context,
        )
        data_key = bytes(response["Plaintext"])
        wrapped = bytes(response["CiphertextBlob"])

        nonce = os.urandom(GCM_NONCE_BYTES)
        ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, None)
        return SealedSecret(
            ciphertext=_b64(ciphertext),
            nonce=_b64(nonce),
            wrapped_key=_b64(wrapped),
        )

    def open(
        self, sealed: SealedSecret, *, user_id: str, purpose: str = TOTP_ENCRYPTION_PURPOSE
    ) -> bytes:
        """Decrypt a sealed secret, or raise `EnvelopeDecryptionFailed`.

        The encryption context is rebuilt from the caller's `user_id`, never from the row, so
        a ciphertext moved to another user's row fails to open. Every failure is one type.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        context = encryption_context(user_id, purpose=purpose)
        try:
            wrapped = _unb64(sealed.wrapped_key)
            nonce = _unb64(sealed.nonce)
            ciphertext = _unb64(sealed.ciphertext)
        except Exception as exc:
            raise EnvelopeDecryptionFailed(f"stored envelope is not valid base64: {exc}") from exc

        try:
            response = self._client.decrypt(CiphertextBlob=wrapped, EncryptionContext=context)
            data_key = bytes(response["Plaintext"])
        except Exception as exc:
            raise EnvelopeDecryptionFailed(f"KMS refused the wrapped data key: {exc}") from exc

        try:
            return AESGCM(data_key).decrypt(nonce, ciphertext, None)
        except Exception as exc:
            raise EnvelopeDecryptionFailed(f"the ciphertext did not authenticate: {exc}") from exc


def _b64(raw: bytes) -> str:
    """Encode bytes as an ASCII base64 string."""
    return base64.b64encode(raw).decode("ascii")


def _unb64(value: str) -> bytes:
    """Decode a strict ASCII base64 string back to bytes."""
    return base64.b64decode(value.encode("ascii"), validate=True)
