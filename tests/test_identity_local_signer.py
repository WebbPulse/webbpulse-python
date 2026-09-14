"""`LocalSigner`, the `signer` settings switch, and the client `signing_client` picks."""

from __future__ import annotations

from typing import Any

import jwt
import pytest
from pytest import MonkeyPatch

from webbpulse.identity import (
    DEFAULT_LOCAL_SEED,
    LOCAL_KEY_BITS,
    IdentitySettings,
    KmsSigner,
    LocalSigner,
    LocalSignerRefused,
    TokenService,
    kid_for_der,
    public_jwk_from_kms,
    signing_client,
)
from webbpulse.identity.tokens import DIGEST_MESSAGE_TYPE, KMS_KEY_SPEC, KMS_SIGNING_ALGORITHM

KEY_A = "local-key-a"

KEY_B = "local-key-b"


def settings(**overrides: Any) -> IdentitySettings:
    """An `IdentitySettings` for a local stack, with the fields a test varies overridden."""
    base: dict[str, Any] = {
        "environment": "local",
        "issuer": "http://127.0.0.1:8000/api/auth",
        "audience": "webbpulse-local-api",
        "signing_key_arns": [KEY_A],
        "signer": "local",
    }
    return IdentitySettings(**{**base, **overrides})


@pytest.fixture(scope="module")
def signer() -> LocalSigner:
    """One `LocalSigner` for the module: deriving a key is not free."""
    return LocalSigner()


def test_get_public_key_answers_the_kms_shape(signer: LocalSigner) -> None:
    """The response carries DER bytes and the spec the token service checks."""
    response = signer.get_public_key(KeyId=KEY_A)
    assert response["KeyId"] == KEY_A
    assert isinstance(response["PublicKey"], bytes)
    assert response["KeySpec"] == KMS_KEY_SPEC
    assert response["SigningAlgorithms"] == [KMS_SIGNING_ALGORITHM]


def test_the_key_is_stable_across_instances() -> None:
    """A restart derives the same key, so `kid` does not change under a live token."""
    first = LocalSigner().der_for(KEY_A)
    second = LocalSigner().der_for(KEY_A)
    assert first == second


def test_a_different_seed_is_a_different_key() -> None:
    """Two stacks under different seeds do not share a signing key."""
    assert LocalSigner(seed="one").der_for(KEY_A) != LocalSigner(seed="two").der_for(KEY_A)


def test_a_different_key_id_is_a_different_key(signer: LocalSigner) -> None:
    """A rotation across two key ids is two keys, as it is in KMS."""
    assert signer.der_for(KEY_A) != signer.der_for(KEY_B)


def test_the_key_is_rsa_2048(signer: LocalSigner) -> None:
    """The authorizer supports only RSA, and the standard pins the size."""
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    key = load_der_public_key(signer.der_for(KEY_A))
    assert isinstance(key, RSAPublicKey)
    assert key.key_size == LOCAL_KEY_BITS == 2048


def test_a_token_verifies_against_the_jwk(signer: LocalSigner) -> None:
    """The whole chain: sign through `KmsSigner`, verify against the published JWK."""
    token = KmsSigner(signer, KEY_A).encode({"sub": "u1", "aud": "webbpulse-local-api"})
    jwk = public_jwk_from_kms(signer, KEY_A)
    claims = jwt.decode(token, jwt.PyJWK(jwk).key, algorithms=["RS256"], audience="webbpulse-local-api")
    assert claims["sub"] == "u1"


def test_kid_is_the_hash_of_the_der(signer: LocalSigner) -> None:
    """`kid` in the header is what a verifier computes from the published key."""
    assert KmsSigner(signer, KEY_A).kid == kid_for_der(signer.der_for(KEY_A))


def test_the_token_service_signs_and_publishes_the_same_key(signer: LocalSigner) -> None:
    """A local stack's JWKS verifies its own access tokens with no KMS grant."""
    resolved = settings()
    service = TokenService(resolved, signer)
    token = service.mint_access_token("u1")
    keys = service.jwks()["keys"]
    assert [key["kid"] for key in keys] == [service.active_kid]
    claims = jwt.decode(
        token,
        jwt.PyJWK(keys[0]).key,
        algorithms=["RS256"],
        audience=resolved.audience,
        issuer=resolved.issuer,
    )
    assert claims["sub"] == "u1"


def test_sign_refuses_a_raw_message(signer: LocalSigner) -> None:
    """KMS would reject a RAW message here, so the local signer does too."""
    with pytest.raises(ValueError, match="prehashed digests only"):
        signer.sign(KeyId=KEY_A, Message=b"x" * 32, MessageType="RAW", SigningAlgorithm=KMS_SIGNING_ALGORITHM)


def test_sign_refuses_another_algorithm(signer: LocalSigner) -> None:
    """Only the algorithm the HTTP API JWT authorizer supports is signed with."""
    with pytest.raises(ValueError, match="RSASSA_PKCS1_V1_5_SHA_256"):
        signer.sign(
            KeyId=KEY_A, Message=b"x" * 32, MessageType=DIGEST_MESSAGE_TYPE, SigningAlgorithm="RSASSA_PSS_SHA_256"
        )


@pytest.mark.parametrize("environment", ["production", "Production", " PROD "])
def test_the_signer_refuses_production(environment: str) -> None:
    """The private half lives in the process, so production is refused outright."""
    with pytest.raises(LocalSignerRefused):
        LocalSigner(environment=environment)


@pytest.mark.parametrize("environment", ["production", "prod", "Production"])
def test_settings_refuse_the_local_signer_in_production(environment: str) -> None:
    """The refusal is at settings validation too, mirroring `mint_test_token`."""
    with pytest.raises(ValueError, match="refused in environment"):
        settings(environment=environment, issuer="https://example.com/api/auth")


def test_settings_allow_kms_in_production() -> None:
    """The switch only refuses `local`; production on KMS validates as it always did."""
    resolved = settings(environment="production", issuer="https://example.com/api/auth", signer="kms")
    assert resolved.signer == "kms"


def test_the_default_signer_is_kms() -> None:
    """An unset switch means KMS, so no deployment picks the local signer by omission."""
    assert IdentitySettings(issuer="https://example.com/api/auth", audience="a", signing_key_arns=["k"]).signer == "kms"


def test_the_seed_defaults_when_unset() -> None:
    """An empty `local_signer_seed` takes the package default rather than an empty seed."""
    assert settings().local_signer_seed_value == DEFAULT_LOCAL_SEED
    assert settings(local_signer_seed="mine").local_signer_seed_value == "mine"


def test_signing_client_builds_the_local_signer() -> None:
    """`local` gets a `LocalSigner` over the configured seed and no boto3 call."""
    client = signing_client(settings(local_signer_seed="mine"))
    assert isinstance(client, LocalSigner)
    assert client.seed == "mine"


def test_signing_client_builds_a_kms_client(monkeypatch: MonkeyPatch) -> None:
    """`kms` goes to boto3, which is what every deployed environment does."""
    import boto3

    built: list[str] = []

    def fake_client(name: str) -> object:
        """Record the service asked for instead of reaching AWS."""
        built.append(name)
        return object()

    monkeypatch.setattr(boto3, "client", fake_client)
    signing_client(settings(environment="staging", issuer="https://example.com/api/auth", signer="kms"))
    assert built == ["kms"]


def test_signing_client_reads_the_environment(monkeypatch: MonkeyPatch) -> None:
    """The switch is an ordinary `IDENTITY_`-prefixed variable."""
    monkeypatch.setenv("IDENTITY_SIGNER", "local")
    monkeypatch.setenv("IDENTITY_ENVIRONMENT", "local")
    monkeypatch.setenv("IDENTITY_ISSUER", "http://127.0.0.1:8000/api/auth")
    monkeypatch.setenv("IDENTITY_AUDIENCE", "webbpulse-local-api")
    monkeypatch.setenv("IDENTITY_SIGNING_KEY_ARNS", '["local"]')
    assert isinstance(signing_client(IdentitySettings()), LocalSigner)  # type: ignore[call-arg]
