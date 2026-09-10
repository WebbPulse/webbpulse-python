"""KMS-backed RS256 token signing, plus the JWKS and OIDC discovery documents.

This is the M0 slice of `docs/identity-standard.md`: enough of the identity standard to
prove that an API Gateway HTTP API JWT authorizer verifies a token this package signed,
against a JWKS this package served. It is deliberately not the whole standard. There is no
user model here, no password flow, no session, no refresh rotation, and no storage of any
kind. Those land in 0.7.0 and later, per section 9.1 of the standard.

What is here is the part every later milestone rests on, so it is the part worth proving
first: a signer that never holds key material, a JWK derived from the public half of that
key, and the two documents an OIDC relying party fetches to find it.

## RS256, and why there was no choice

The API Gateway documentation for HTTP API JWT authorizers says, in the token validation
workflow, "Check the token's algorithm and signature by using the public key that is
fetched from the issuer's `jwks_uri`. Currently, only RSA-based algorithms are supported."
ES256 is ECDSA, so it is excluded, and the standard's preference for it cannot be
exercised while the built-in authorizer does the verifying.

So RS256, KMS key spec `RSA_2048`, signing algorithm `RSASSA_PKCS1_V1_5_SHA_256`.

**PKCS1 v1.5 and not PSS**, even though the KMS `Sign` documentation says "When signing
with RSA key pairs, RSASSA-PSS algorithms are preferred. We include RSASSA-PKCS1-v1_5
algorithms for compatibility with existing applications." That preference is about signing
in general. Here the wire format is fixed by JWA, which defines `RS256` as RSASSA-PKCS1-v1_5
with SHA-256 and `PS256` as the PSS variant. Signing with PSS and labelling the header
`RS256` produces a token that nothing will verify, and the failure is a 401 with no
explanation of why.

## Signing a digest, not a message

`KmsSigner` computes the SHA-256 of the JWS signing input itself and calls `kms:Sign` with
`MessageType="DIGEST"`. The KMS documentation is explicit that this is what the parameter
is for: "use `DIGEST` for message digests, which are already hashed ... When the value is
`DIGEST`, AWS KMS skips the hashing step in the signing algorithm."

A `Message` may be 0 to 4096 bytes, and a JWT with these claims is far under that, so this
is not working around a limit that is being hit today. It is removing the limit from
consideration permanently: a claims set that grows past 4096 bytes would otherwise turn
into a runtime failure on a request path, and there is no reason to leave that edge live
when sending 32 bytes costs nothing. KMS skips only the hashing step, not the padding, so
`SigningAlgorithm` stays `RSASSA_PKCS1_V1_5_SHA_256` either way.

The returned signature needs no reshaping. For RSA, the documentation says "the encoding of
this value is defined by PKCS #1 in RFC 8017", which is the raw signature octet string that
JWS wants, so it is base64url-encoded as-is. (ECDSA would have needed care here: KMS returns
those DER-encoded while JWS wants the fixed-width r||s concatenation. One more way the
forced choice of RS256 costs nothing.)

## `kid` is derived from the key material

`kid` is the base64url of the SHA-256 of the DER SubjectPublicKeyInfo that `kms:GetPublicKey`
returns. That makes it a pure function of the public key: stable across redeploys, identical
in every process that computes it, and impossible to collide between two different keys.

It is deliberately not the KMS key id or ARN. Those are account identifiers, and a JWKS is a
public document, so serving one would publish an AWS account number for no benefit. They
also do not change when the key material does, which is precisely the property a `kid` needs.

## Nothing here caches, and that is the caller's job

`public_jwk_from_kms` calls `kms:GetPublicKey` every time. A service should call it once and
hold the result in module state for the life of the execution environment, which is safe
because it is a read of a public key. The caching policy is left to the caller because the
right lifetime depends on the rotation procedure, and baking a TTL in here would make the
package the thing that has to change when the procedure does.

## `mint_test_token` is off unless something turns it on

The helper that mints a token without a login exists so M0 can be exercised end to end with
a curl. It takes an explicit `enabled` argument with no default, so there is no way to call
it that reads as harmless, and it refuses outright when `environment` is `production`. Both
checks are there on purpose: a settings flag can be set by mistake, and the environment
check is what makes that mistake survivable.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, Final, Protocol

if TYPE_CHECKING:  # pragma: no cover - typing only
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

#: The JWS `alg` header value, and the `alg` on every JWK this module emits. RSASSA-PKCS1-v1_5
#: with SHA-256, per RFC 7518. The API Gateway JWT authorizer supports only RSA-based
#: algorithms, so this is the whole of the algorithm choice.
JWS_ALGORITHM: Final = "RS256"

#: The KMS `SigningAlgorithm` that produces an RS256 signature. Not a PSS variant: JWA binds
#: `RS256` to PKCS1 v1.5, and a PSS signature under an `RS256` header verifies nowhere.
KMS_SIGNING_ALGORITHM: Final = "RSASSA_PKCS1_V1_5_SHA_256"

#: The KMS `MessageType` for a pre-hashed input. The signing input is hashed here and the
#: 32-byte digest is what crosses the wire.
DIGEST_MESSAGE_TYPE: Final = "DIGEST"

#: The KMS key spec the signing key must be created with. Checked against `GetPublicKey`'s
#: answer rather than assumed, so a key created with the wrong spec fails loudly at the
#: first JWKS request instead of producing tokens nothing can verify.
KMS_KEY_SPEC: Final = "RSA_2048"

#: Environments where `mint_test_token` is refused whatever the enable flag says.
_REFUSED_ENVIRONMENTS: Final = frozenset({"production", "prod"})

#: OIDC discovery path, relative to the issuer. RFC 8414 and OpenID Connect Discovery 1.0.
DISCOVERY_PATH: Final = "/.well-known/openid-configuration"

#: JWKS path, relative to the issuer.
JWKS_PATH: Final = "/.well-known/jwks.json"


def _b64u(raw: bytes) -> str:
    """base64url, unpadded, which is what every field in a JWS and a JWK uses."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_json(value: Mapping[str, Any]) -> str:
    """A JWS header or payload segment.

    Separators are tight and keys are left in insertion order rather than sorted. JSON
    canonicalisation is not required anywhere in JWS: the signature covers the exact bytes
    of the encoded segment, so what matters is that the bytes signed are the bytes sent,
    which they are because the same string is used for both.
    """
    return _b64u(json.dumps(value, separators=(",", ":")).encode("utf-8"))


class TokenMintingDisabled(RuntimeError):
    """`mint_test_token` was called without being explicitly enabled.

    A distinct type rather than a bare `RuntimeError` so a service can let this one 404
    while still turning a genuine internal error into a 500.

    Named for the condition rather than for the helper. `TestTokenDisabled` would read
    better next to `mint_test_token`, but pytest collects any class whose name starts with
    `Test`, so importing it into a test module makes the suite fail at collection with
    `PytestCollectionWarning: cannot collect test class`. That would land on every consumer
    that tests this path, and renaming the exception is cheaper than every consumer adding
    a `python_classes` override.
    """


class KmsClient(Protocol):
    """The two KMS calls this module makes.

    Typed as a protocol rather than as `boto3`'s client so the package's base install does
    not depend on boto3, and so a test can pass a fake without a stubber. `webbpulse` puts
    boto3 behind the `dynamodb` extra and this module follows that: it imports nothing from
    boto3 at all, and the caller supplies the client.
    """

    def sign(
        self,
        *,
        KeyId: str,
        Message: bytes,
        MessageType: str,
        SigningAlgorithm: str,
    ) -> Mapping[str, Any]: ...

    def get_public_key(self, *, KeyId: str) -> Mapping[str, Any]: ...


class KmsSigner:
    """Signs a JWS with a KMS asymmetric key, holding no key material.

    The private half never leaves KMS, so there is no secret to load, rotate in an
    environment variable, or leak in a stack trace. What this class holds is a key id and a
    client.

    `kid` is not passed in. It is derived from the public key so that the value in the token
    header and the value in the JWKS cannot disagree, which is the failure that presents as
    every request being denied with nothing in the logs to say why. Deriving it costs one
    `kms:GetPublicKey` per signer instance; a long-lived signer in module state pays it once
    per execution environment.
    """

    def __init__(self, client: KmsClient, key_id: str) -> None:
        self._client = client
        self._key_id = key_id
        self._kid: str | None = None

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def kid(self) -> str:
        """The `kid` for this key, computed once and held.

        Held on the instance rather than recomputed because it is a pure function of key
        material that cannot change under a single KMS key id: KMS automatic rotation is
        not used for signing keys (section 3.5 of the standard), and rotation is by adding a
        second key with its own id.
        """
        if self._kid is None:
            self._kid = kid_for_der(self._der_public_key())
        return self._kid

    def _der_public_key(self) -> bytes:
        response = self._client.get_public_key(KeyId=self._key_id)
        der = response["PublicKey"]
        # botocore hands back bytes for a blob member. A `str` here would mean someone has
        # passed a fake that returns the base64 the HTTP API uses, and hashing the base64
        # would give a kid that nothing else computes.
        if not isinstance(der, bytes):  # pragma: no cover - defensive
            raise TypeError(
                "kms:GetPublicKey returned a non-bytes PublicKey; expected the DER "
                "SubjectPublicKeyInfo as bytes."
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
        if not isinstance(signature, bytes):  # pragma: no cover - defensive
            raise TypeError(
                "kms:Sign returned a non-bytes Signature; expected the raw PKCS #1 "
                "signature as bytes."
            )
        return signature

    def encode(self, claims: Mapping[str, Any]) -> str:
        """A complete compact-serialised JWS for `claims`.

        The header and payload are encoded here rather than through PyJWT, because PyJWT
        signs with an algorithm object holding a key, and this key cannot be held. Registering
        a custom algorithm class that calls KMS is the alternative, and it is more moving
        parts for the same three base64url segments joined by dots. The output is an ordinary
        RS256 JWS either way, and `tests/test_identity.py` proves that by verifying a
        signature of the same construction with PyJWT against the JWK this module emits.
        """
        header = {"alg": JWS_ALGORITHM, "typ": "JWT", "kid": self.kid}
        signing_input = f"{_b64u_json(header)}.{_b64u_json(claims)}".encode("ascii")
        return f"{signing_input.decode('ascii')}.{_b64u(self.sign(signing_input))}"


def kid_for_der(der_spki: bytes) -> str:
    """`kid` for a DER SubjectPublicKeyInfo: base64url of its SHA-256.

    Exposed separately from `KmsSigner` so a verifier holding only the public key can
    compute the same value without a KMS client, which is what a contract test needs.
    """
    return _b64u(hashlib.sha256(der_spki).digest())


def _int_to_b64u(value: int) -> str:
    """A JWK integer field: big-endian, minimum length, unpadded base64url.

    RFC 7518 section 6.3.1.1 requires the octet sequence to be the minimum length able to
    represent the value, with no leading zero octets. `int.bit_length()` rounded up to whole
    bytes gives exactly that, and it is why this cannot just reuse whatever length the DER
    encoding happened to use: DER prepends a zero octet to keep a high-bit-set integer
    positive, and carrying that zero into `n` produces a JWK that some verifiers reject and
    others accept, which is the worst of the two.
    """
    length = max(1, (value.bit_length() + 7) // 8)
    return _b64u(value.to_bytes(length, "big"))


def public_jwk_from_kms(client: KmsClient, key_id: str) -> dict[str, str]:
    """The public JWK for a KMS RSA signing key, as it appears in the JWKS.

    Parses the DER SubjectPublicKeyInfo that `kms:GetPublicKey` returns and pulls the
    modulus and exponent out of it. The key spec is checked against `KMS_KEY_SPEC` rather
    than trusted, because a key created as `RSA_4096`, or as an ECC key, would otherwise
    produce a JWK claiming `RS256` that no token this service signs would verify against.
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
    """`(n, e)` from a DER SubjectPublicKeyInfo, via `cryptography`.

    `cryptography` is not a new dependency: PyJWT's `crypto` extra already brings it, and
    the `identity` extra depends on `PyJWT[crypto]` for exactly this reason. Hand-rolling a
    DER walk here was the alternative and it is the wrong trade: the parser would be about
    forty lines of index arithmetic on attacker-adjacent input for a saving of nothing,
    since the dependency is present regardless.
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
    """The JWKS document body: a `keys` array, per RFC 7517.

    Takes a sequence rather than a single JWK because rotation serves two keys at once. The
    active signer's JWK goes first by convention, though nothing in JWKS resolution depends
    on order: a verifier selects by `kid`.
    """
    return {"keys": list(jwks)}


def build_discovery_document(issuer: str) -> dict[str, Any]:
    """The OIDC discovery document body.

    `issuer` must be byte-identical to the `iss` claim this service signs and to the
    `issuer` configured on the API Gateway authorizer. A trailing slash on one and not the
    others is the classic failure here, and it presents as every request being denied with
    no useful message, so the value is normalised once at the edge of this function rather
    than trusted to match by hand at three call sites.

    The five members are the ones OpenID Connect Discovery 1.0 requires of a provider that
    only signs. There is no `authorization_endpoint` or `token_endpoint` because this
    service is not an OAuth authorization server: it signs its own access tokens through its
    own login routes, and advertising endpoints that do not exist would be worse than
    omitting them.
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
    """A signed access token minted without a login, for exercising an authorizer.

    This exists for M0 and for contract tests. It is not a login, it authenticates nobody,
    and it must never be reachable in production.

    Two independent gates, because one is not enough. `enabled` has no default, so every
    call site states its intent and there is no accidental invocation. `environment` is
    checked against a refusal list on top of that, so a settings flag left true in the wrong
    place is still refused. A single flag would make one editing mistake sufficient.

    The claims are the M0 subset of section 3.2: `typ`, `sub`, `iss`, `aud`, `exp`, `iat`,
    `jti`. `nbf` is set to `iat` as well, because the authorizer validates `nbf` when it is
    present and omitting it would leave one of its documented checks unexercised by the
    spike. The claims the full standard adds (`sid`, `amr`, `roles`, `scope`, `email`) are
    session and product concerns that M0 has nothing to say about, and `extra_claims` is the
    seam for adding one without changing this signature.

    `typ` is `"access"` and is not optional. One signing key covers several token purposes
    in the full design, and every verifier is expected to assert the value it wants, so a
    token minted here can never be presented as an MFA ticket or a reset link.
    """
    if not enabled:
        raise TokenMintingDisabled(
            "mint_test_token is disabled. It mints a signed access token without "
            "authenticating anybody and must be enabled explicitly, per environment."
        )
    if environment.lower() in _REFUSED_ENVIRONMENTS:
        raise TokenMintingDisabled(
            f"mint_test_token is refused in environment {environment!r}, whatever the "
            "enable flag says."
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
        # Under the reserved claims, not over them. A caller cannot rewrite `iss` or `exp`
        # through this seam, which would turn a debugging helper into a way to mint a token
        # for another issuer.
        claims = {**dict(extra_claims), **claims}
    return signer.encode(claims)


def identity_router(
    *,
    issuer: str,
    jwks: object,
) -> APIRouter:
    """The two documents an OIDC relying party fetches, as a mountable router.

    `jwks` is a zero-argument callable returning the list of public JWKs. A callable rather
    than a list so the caller owns the caching: a service resolves the JWK once per
    execution environment and hands this router a closure over it, and a rotation that adds
    a second key changes what the closure returns without rebuilding the router.

    **Both routes must be reachable without any authorizer**, including without a staging
    access gate. API Gateway fetches them itself, from outside any browser session, holding
    no cookies. A gate in front of either one means the JWT authorizer cannot retrieve the
    key and every authorized route fails closed, which is section 2.5 of the standard and is
    the single most likely way to get this wrong.

    The paths are absolute, so this router is mounted with no prefix even in a service whose
    other routers sit under `/api/v1`. `.well-known` paths are defined relative to an origin
    by RFC 8615 and cannot be moved under a prefix without ceasing to be discoverable.
    """
    from fastapi import APIRouter

    if not callable(jwks):
        raise TypeError("jwks must be a zero-argument callable returning a list of JWKs.")

    router = APIRouter(tags=["identity"])
    discovery = build_discovery_document(issuer)

    @router.get(JWKS_PATH, include_in_schema=False)
    async def jwks_document() -> dict[str, Any]:
        return build_jwks(jwks())

    @router.get(DISCOVERY_PATH, include_in_schema=False)
    async def discovery_document() -> dict[str, Any]:
        # Built once at router construction: it is a pure function of the issuer, and
        # rebuilding it per request would only add a chance for the two to diverge.
        return discovery

    return router
