"""KMS envelope encryption for the one identity secret that cannot be hashed.

A TOTP seed is a **symmetric shared secret**. Unlike a password it cannot be hashed, because
the server has to reproduce the code to check it, and unlike a passkey there is no public
half. So a read of the seed table is a complete compromise of the second factor for every
user, and surviving a compromise of the first factor is the entire reason the second one
exists. Section 4.4 of `docs/identity-standard.md` is about closing that.

## What this protects against, and what it does not

DynamoDB encrypts at rest by default under an AWS-owned key. That protects against physical
media loss and against nothing else an attacker of this system would actually do. The
realistic threat is an application path or an IAM principal that can call `Query` on the
table, and an AWS-owned key is transparent to every one of those.

Encrypting the seed under a **separate** KMS key means reading a usable seed needs
`dynamodb:GetItem` **and** `kms:Decrypt` on that key, with the right encryption context. A
leaked read-only Dynamo path yields ciphertext, every decrypt is a CloudTrail event that can
be alarmed on, and the data key is a different key from the signing key, so the blast radius
of either one is bounded.

It does not protect a seed from an attacker who already has the identity function's own
role. Nothing can: that role has to be able to decrypt, or the second factor cannot be
checked. What it buys is that the seed is no longer readable by anything *less* than that
role, which is most of what goes wrong.

## Envelope, not direct Encrypt

Section 4.4 argued for direct `kms:Encrypt`/`Decrypt` on the grounds that a seed is about
twenty bytes and "there is nothing to gain from a data key". M4 uses **envelope encryption**
anyway, and the standard's M4 decision block records the reversal. The reasoning:

- **The ciphertext stops being opaque to us.** A KMS ciphertext blob is a KMS-internal
  format whose layout is not documented and not ours. An envelope keeps the AES-GCM
  ciphertext, its nonce and its tag in fields this package wrote and can reason about, and
  the only thing KMS holds is the wrapped data key.
- **It is the shape every other secret will want.** M5's passkey material and anything later
  that is longer than the 4096-byte direct-`Encrypt` limit needs an envelope regardless.
  Having one implementation rather than two is worth more than the round trip it saves.
- **The per-verify cost is identical.** Both designs make exactly one KMS call on the verify
  path, `Decrypt`. Envelope adds a call on the **enrol** path only, which happens once per
  user per authenticator.

What is genuinely given up is that the data key is per-secret rather than shared, so there
is no caching win here, and none is attempted: caching a decrypted data key across requests
would put plaintext key material in a process that outlives the request, which is the thing
the design is trying to avoid.

## The encryption context is the load-bearing part

`{"user_id": "<id>", "purpose": "totp"}`, passed to both `GenerateDataKey` and `Decrypt`.

KMS binds the context into the wrapped key as authenticated additional data, so a ciphertext
copied into another user's row **fails to decrypt** rather than silently authenticating the
wrong person. That is not a nicety: without it, an attacker with a single write to the table
promotes their own seed onto a victim's account, and every code they generate is accepted.
The same context is also what an IAM policy condition keys on, which is how one function can
be allowed to decrypt only its own users' seeds.

The context is rebuilt from the row's own `user_id` on decrypt rather than stored alongside
the ciphertext. Storing it would mean an attacker who can write the row can write the context
too, which gives back exactly what the context was protecting.

## The local half

AES-256-GCM from `cryptography`, which is already a dependency through `PyJWT[crypto]`. A
fresh 96-bit nonce per encryption from `os.urandom`, never reused, because GCM's failure mode
on nonce reuse is catastrophic rather than gradual: two messages under one nonce leak the
XOR of the plaintexts and, worse, the authentication subkey.

The nonce is stored with the ciphertext. A nonce is not a secret, it only has to be unique.

## No boto3 here

`KmsDataKeyClient` is a `Protocol`, matching what `KmsClient` in `tokens` already does and
for the same reason: the `identity` extra deliberately does not carry boto3, so this module
takes a client rather than building one, and a test passes a fake or moto's.

Unlike KMS asymmetric signing, **moto is faithful for this one**. M1 decision 8 found moto's
`get_public_key` unusable for RS256, and the natural inference is that moto cannot be trusted
for KMS at all. Measured against moto 5.2.3 that inference is wrong for the symmetric path:
`GenerateDataKey` and `Decrypt` round-trip correctly, the encryption context is enforced as
AAD, and a tampered ciphertext blob is rejected. The M4 suite therefore tests this module
against moto as well as against a hand fake.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, Protocol

if TYPE_CHECKING:  # pragma: no cover - typing only
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

#: Bytes of data key requested from KMS. 32 is AES-256, which is what `AESGCM` selects from
#: the key length it is handed. Asking for 16 would be AES-128 and is not worth the saving.
AES_KEY_BYTES: Final = 32

#: Bytes of GCM nonce. 96 bits is the size GCM is specified and optimised for; any other
#: length sends the implementation through an extra derivation step for no benefit.
GCM_NONCE_BYTES: Final = 12

#: The `purpose` half of the encryption context. A constant rather than a caller's string,
#: because a typo in it produces a ciphertext that decrypts nowhere and the symptom is a
#: user whose second factor stopped working with no error anybody sees until they try.
TOTP_ENCRYPTION_PURPOSE: Final = "totp"


class EnvelopeDecryptionFailed(Exception):
    """A sealed secret would not open.

    One type for every cause: the wrong encryption context, a tampered ciphertext, a
    tampered nonce, a wrapped key from a different KMS key, or a KMS refusal. They are one
    type on purpose. The distinction is not something a caller can act on differently, and
    the difference between "KMS said no" and "the tag did not verify" is information about
    how far an attacker's forgery got.

    The `reason` attribute carries the detail for a log. It is not safe to return to a
    caller, for the reason above.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class KmsDataKeyClient(Protocol):
    """The two KMS calls the envelope needs, typed structurally.

    Deliberately narrower than boto3's KMS client. This module needs `GenerateDataKey` and
    `Decrypt` and nothing else, so that is what it asks for, and a fake in a test implements
    two methods rather than being a mock of a client with three hundred.

    The signatures are boto3's, PascalCase keywords included, so a real client satisfies the
    protocol with no adapter. `KmsClient` in `tokens` makes the same trade.
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
    """The authenticated additional data binding a ciphertext to one user and one use.

    Section 4.4 fixes the shape. Both halves matter and for different reasons: `user_id`
    stops a ciphertext being moved between rows, and `purpose` stops one encrypted under
    this key for some later feature being replayed as a TOTP seed.
    """
    return {"user_id": user_id, "purpose": purpose}


@dataclass(frozen=True, slots=True)
class SealedSecret:
    """A secret encrypted under a data key that is itself encrypted under a KMS key.

    Three fields, all safe to store: the AES-GCM ciphertext with its tag appended, the nonce
    that ciphertext was produced under, and the KMS-wrapped data key. Nothing here is a
    secret on its own, which is the property that makes the row safe to read.

    Stored base64 rather than as DynamoDB binary. `Repository` round-trips a `bytes` as a
    `Binary` and the value comes back wrapped, so every reader would have to unwrap it and
    one that forgot would store the wrapper's repr. A string has one representation.
    """

    #: AES-256-GCM ciphertext with the 16 byte tag appended, base64.
    ciphertext: str
    #: The 96 bit nonce, base64. Not a secret; only ever used once.
    nonce: str
    #: The data key as KMS wrapped it, base64. Opaque, and the only part KMS can open.
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

        `None` rather than a partial object or a `KeyError`. A row missing one of the three
        cannot be decrypted whatever the caller does, and returning `None` lets the caller
        treat it as "no usable factor" rather than turning a half-written row into a 500 on
        the login path.
        """
        ciphertext = str(item.get("secret_ciphertext", ""))
        nonce = str(item.get("secret_nonce", ""))
        wrapped = str(item.get("wrapped_data_key", ""))
        if not ciphertext or not nonce or not wrapped:
            return None
        return cls(ciphertext=ciphertext, nonce=nonce, wrapped_key=wrapped)


class EnvelopeCipher:
    """Seals and opens a secret with a KMS data key and local AES-256-GCM.

    Build one per execution environment from the settings' `data_key_arn` and a KMS client.
    Holds no key material between calls: the plaintext data key exists only inside `seal`
    and `open`, and neither returns it or stores it anywhere.

    ::

        cipher = EnvelopeCipher(settings.data_key_arn, kms_client)
        sealed = cipher.seal(b"the totp seed", user_id="user-1")
        seed = cipher.open(sealed, user_id="user-1")
    """

    def __init__(self, key_id: str, client: KmsDataKeyClient) -> None:
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

        One `GenerateDataKey` per call, and no data key is ever reused across secrets. A
        shared data key would mean one `Decrypt` opens every seed in the table, which is
        most of the property the envelope exists to provide.

        The plaintext data key is used and then dropped. Python gives no way to wipe it from
        memory, and pretending otherwise with a `bytearray` overwrite would be theatre: the
        interpreter has already copied it. What is real is that it does not outlive the call
        and is never written anywhere.
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

        The encryption context is rebuilt from the `user_id` the **caller** looked the row up
        by, never from anything stored in the row. That is what makes moving a ciphertext to
        another user's row fail: the context KMS is asked for will not match the one the key
        was wrapped under, and KMS refuses.

        Every failure below is one exception. A caller on the login path turns it into the
        same refusal it gives a wrong code, because the difference between "this seed is
        corrupt" and "this code is wrong" is not the user's business and telling them apart
        is a probe an attacker can run.
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
            # Covers the wrong encryption context, a wrapped key from another KMS key, a
            # disabled key, and a denied call. All of them mean the same thing to a caller.
            raise EnvelopeDecryptionFailed(f"KMS refused the wrapped data key: {exc}") from exc

        try:
            return AESGCM(data_key).decrypt(nonce, ciphertext, None)
        except Exception as exc:
            # The GCM tag did not verify: the ciphertext or the nonce was altered after it
            # was written. Distinct from the KMS branch above in the log and nowhere else.
            raise EnvelopeDecryptionFailed(f"the ciphertext did not authenticate: {exc}") from exc


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)
