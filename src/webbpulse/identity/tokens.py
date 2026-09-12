"""KMS-backed RS256 token signing, plus the JWKS and OIDC discovery documents.

RS256 is forced: the API Gateway HTTP API JWT authorizer supports only RSA-based
algorithms. The signer holds no key material and derives `kid` from the public key.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, Final, Protocol

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import APIRouter

__all__ = [
    "DIGEST_MESSAGE_TYPE",
    "JWS_ALGORITHM",
    "KMS_KEY_SPEC",
    "KMS_SIGNING_ALGORITHM",
    "KmsSigner",
    "TokenMintingDisabled",
    "build_discovery_document",
    "build_jwks",
    "identity_router",
    "mint_test_token",
    "public_jwk_from_kms",
]

JWS_ALGORITHM: Final = "RS256"

KMS_SIGNING_ALGORITHM: Final = "RSASSA_PKCS1_V1_5_SHA_256"

DIGEST_MESSAGE_TYPE: Final = "DIGEST"

KMS_KEY_SPEC: Final = "RSA_2048"

_REFUSED_ENVIRONMENTS: Final = frozenset({"production", "prod"})

DISCOVERY_PATH: Final = "/.well-known/openid-configuration"

JWKS_PATH: Final = "/.well-known/jwks.json"


def _b64u(raw: bytes) -> str:
    """Encode bytes as unpadded base64url, which every JWS and JWK field uses."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_json(value: Mapping[str, Any]) -> str:
    """Encode one JWS header or payload segment.

    No canonicalisation: JWS signs the exact bytes of the segment, and the same string is
    used for signing and sending.
    """
    return _b64u(json.dumps(value, separators=(",", ":")).encode("utf-8"))


class TokenMintingDisabled(RuntimeError):
    """`mint_test_token` was called without being explicitly enabled.

    A distinct type so a service can 404 this while still turning a genuine internal error
    into a 500. Named for the condition, since a `Test` prefix would be collected by pytest.
    """


class KmsClient(Protocol):
    """The two KMS calls this module makes, typed structurally.

    A protocol rather than boto3's client, so the base install does not depend on boto3 and a
    test can pass a fake without a stubber.
    """

    def sign(
        self,
        *,
        KeyId: str,
        Message: bytes,
        MessageType: str,
        SigningAlgorithm: str,
    ) -> Mapping[str, Any]:
        """Sign a message with the KMS private half and return the signature."""
        ...

    def get_public_key(self, *, KeyId: str) -> Mapping[str, Any]:
        """Fetch the public half, used to derive `kid` and serve the JWKS."""
        ...


class KmsSigner:
    """Signs a JWS with a KMS asymmetric key, holding no key material.

    The private half never leaves KMS. `kid` is derived from the public key rather than
    passed in, so the token header and the JWKS cannot disagree.
    """

    def __init__(self, client: KmsClient, key_id: str) -> None:
        """Bind the signer to one KMS key id and a client, deferring the `kid` lookup."""
        self._client = client
        self._key_id = key_id
        self._kid: str | None = None

    @property
    def key_id(self) -> str:
        """The KMS key id this signer signs with."""
        return self._key_id

    @property
    def kid(self) -> str:
        """The `kid` for this key, computed once and held.

        A pure function of key material, which cannot change under one KMS key id because
        signing keys are rotated by adding a second key rather than in place.
        """
        if self._kid is None:
            self._kid = kid_for_der(self._der_public_key())
        return self._kid

    def _der_public_key(self) -> bytes:
        """Fetch the DER SubjectPublicKeyInfo, insisting on bytes rather than base64.

        Hashing a base64 string instead would yield a `kid` nothing else computes.
        """
        response = self._client.get_public_key(KeyId=self._key_id)
        der = response["PublicKey"]
        if not isinstance(der, bytes):  # pragma: no cover
            raise TypeError(
                "kms:GetPublicKey returned a non-bytes PublicKey; expected the DER SubjectPublicKeyInfo as bytes."
            )
        return der

    def sign(self, signing_input: bytes) -> bytes:
        """The raw signature over `signing_input`, hashed here and sent as a digest."""
        digest = hashlib.sha256(signing_input).digest()
        response = self._client.sign(
            KeyId=self._key_id,
            Message=digest,
            MessageType=DIGEST_MESSAGE_TYPE,
            SigningAlgorithm=KMS_SIGNING_ALGORITHM,
        )
        signature = response["Signature"]
        if not isinstance(signature, bytes):  # pragma: no cover
            raise TypeError("kms:Sign returned a non-bytes Signature; expected the raw PKCS #1 signature as bytes.")
        return signature

    def encode(self, claims: Mapping[str, Any]) -> str:
        """Build a complete compact-serialised JWS for `claims`.

        Encoded here rather than through PyJWT, which signs with an algorithm object holding
        a key this signer cannot hold. The output is an ordinary RS256 JWS.
        """
        header = {"alg": JWS_ALGORITHM, "typ": "JWT", "kid": self.kid}
        signing_input = f"{_b64u_json(header)}.{_b64u_json(claims)}".encode("ascii")
        return f"{signing_input.decode('ascii')}.{_b64u(self.sign(signing_input))}"


def kid_for_der(der_spki: bytes) -> str:
    """Compute the `kid` for a DER SubjectPublicKeyInfo: base64url of its SHA-256.

    Separate from `KmsSigner` so a verifier holding only the public key computes the same
    value without a KMS client.
    """
    return _b64u(hashlib.sha256(der_spki).digest())


def _int_to_b64u(value: int) -> str:
    """Encode a JWK integer field: big-endian, minimum length, unpadded base64url.

    RFC 7518 requires the minimum-length octet sequence with no leading zero, so the DER
    encoding's padding byte must not be carried into `n`.
    """
    length = max(1, (value.bit_length() + 7) // 8)
    return _b64u(value.to_bytes(length, "big"))


def public_jwk_from_kms(client: KmsClient, key_id: str) -> dict[str, str]:
    """Build the public JWK for a KMS RSA signing key, as it appears in the JWKS.

    The key spec is checked rather than trusted, so a key of the wrong spec fails loudly
    instead of producing a JWK claiming `RS256` that verifies nothing.
    """
    response = client.get_public_key(KeyId=key_id)
    spec = response.get("KeySpec")
    if spec is not None and spec != KMS_KEY_SPEC:
        raise ValueError(
            f"Signing key {key_id} has KeySpec {spec!r}, but the identity standard "
            f"requires {KMS_KEY_SPEC!r}: the HTTP API JWT authorizer supports only "
            "RSA-based algorithms."
        )
    der = response["PublicKey"]
    modulus, exponent = _rsa_numbers_from_spki(der)
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": JWS_ALGORITHM,
        "kid": kid_for_der(der),
        "n": _int_to_b64u(modulus),
        "e": _int_to_b64u(exponent),
    }


def _rsa_numbers_from_spki(der: bytes) -> tuple[int, int]:
    """Read `(n, e)` from a DER SubjectPublicKeyInfo, via `cryptography`.

    `cryptography` already arrives with `PyJWT[crypto]`, so no hand-rolled DER walk over
    attacker-adjacent input is needed.
    """
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    key = load_der_public_key(der)
    if not isinstance(key, RSAPublicKey):
        raise ValueError(
            "kms:GetPublicKey returned a non-RSA public key. The identity standard "
            "requires RSA_2048, because the HTTP API JWT authorizer supports only "
            "RSA-based algorithms."
        )
    numbers = key.public_numbers()
    return numbers.n, numbers.e


def build_jwks(jwks: Sequence[Mapping[str, str]]) -> dict[str, Any]:
    """Build the JWKS document body: a `keys` array, per RFC 7517.

    Takes a sequence because rotation serves two keys at once; order is convention only,
    since a verifier selects by `kid`.
    """
    return {"keys": list(jwks)}


def build_discovery_document(issuer: str) -> dict[str, Any]:
    """Build the OIDC discovery document body.

    `issuer` is normalised here because it must be byte-identical to the `iss` claim and to
    the authorizer's configured issuer; a stray trailing slash denies every request.
    """
    normalised = issuer.rstrip("/")
    return {
        "issuer": normalised,
        "jwks_uri": f"{normalised}{JWKS_PATH}",
        "response_types_supported": ["token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [JWS_ALGORITHM],
    }


def mint_test_token(
    signer: KmsSigner,
    *,
    enabled: bool,
    environment: str,
    issuer: str,
    audience: str,
    subject: str,
    expires_in: int = 600,
    extra_claims: Mapping[str, Any] | None = None,
    now: int | None = None,
) -> str:
    """Mint a signed access token without a login, for exercising an authorizer.

    Not a login, and it must never be reachable in production: `enabled` has no default and
    `environment` is refused independently, so one editing mistake is not sufficient. `typ`
    is always `"access"`, so this can never be presented as a ticket or a reset link.
    """
    if not enabled:
        raise TokenMintingDisabled(
            "mint_test_token is disabled. It mints a signed access token without "
            "authenticating anybody and must be enabled explicitly, per environment."
        )
    if environment.lower() in _REFUSED_ENVIRONMENTS:
        raise TokenMintingDisabled(
            f"mint_test_token is refused in environment {environment!r}, whatever the enable flag says."
        )
    issued_at = int(time.time()) if now is None else now
    claims: dict[str, Any] = {
        "typ": "access",
        "sub": subject,
        "iss": issuer.rstrip("/"),
        "aud": audience,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": issued_at + expires_in,
        "jti": uuid.uuid4().hex,
    }
    if extra_claims:
        claims = {**dict(extra_claims), **claims}
    return signer.encode(claims)


def identity_router(
    *,
    issuer: str,
    jwks: object,
) -> APIRouter:
    """Build the mountable router serving the two documents a relying party fetches.

    `jwks` is a zero-argument callable, so the caller owns the caching. Both routes must be
    reachable with no authorizer and no access gate, or API Gateway cannot fetch the key and
    every authorized route fails closed. The paths are absolute and take no prefix.
    """
    from fastapi import APIRouter

    if not callable(jwks):
        raise TypeError("jwks must be a zero-argument callable returning a list of JWKs.")

    router = APIRouter(tags=["identity"])
    discovery = build_discovery_document(issuer)

    @router.get(JWKS_PATH, include_in_schema=False)
    async def jwks_document() -> dict[str, Any]:
        """Serve the current JWKS."""
        return build_jwks(jwks())

    @router.get(DISCOVERY_PATH, include_in_schema=False)
    async def discovery_document() -> dict[str, Any]:
        """Serve the discovery document, built once at router construction."""
        return discovery

    return router
