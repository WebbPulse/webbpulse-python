"""Tests for `JwksVerifier`: RS256 verification against a stubbed JWKS, and its cache."""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from typing import Any

import pytest
from starlette.requests import Request

from webbpulse.identity import (
    InvalidToken,
    JwksVerifier,
    KmsSigner,
    build_jwks,
    cached_verifier,
    clear_verifier_cache,
    discovery_jwks_uri,
    mint_test_token,
    public_jwk_from_kms,
    verified_bearer_subject,
)
from webbpulse.testing import FakeKms

pytest.importorskip("cryptography")

KEY_ID = "arn:aws:kms:us-west-2:111122223333:key/11111111-2222-3333-4444-555555555555"
ISSUER = "https://api.staging.example.com/api/auth"
AUDIENCE = "webbpulse-staging"


class StubJwkClient:
    """A `PyJWKClient` stand-in over an in-process JWKS, counting its fetches.

    Mirrors the one method the verifier calls and raises the same way on an unknown `kid`,
    so a test asserts on the verifier's own behaviour rather than on the network.
    """

    def __init__(self, jwks: dict[str, Any]) -> None:
        """Hold the key set this client serves and start the fetch count at zero."""
        self.jwks = jwks
        self.fetches = 0

    def get_signing_key_from_jwt(self, token: str) -> Any:
        """The signing key for the token's `kid`, or raise for an unknown one."""
        import jwt

        self.fetches += 1
        kid = jwt.get_unverified_header(token)["kid"]
        for entry in self.jwks["keys"]:
            if entry["kid"] == kid:
                return jwt.PyJWK(dict(entry), algorithm="RS256")
        raise jwt.exceptions.PyJWKClientError(f"unable to find a signing key that matches {kid!r}")


@pytest.fixture
def signer(fake_kms: FakeKms) -> KmsSigner:
    """A signer over the module's shared RSA key."""
    return KmsSigner(fake_kms, KEY_ID)


@pytest.fixture
def client(fake_kms: FakeKms) -> StubJwkClient:
    """A stub JWKS client serving the one key the signer signs with."""
    return StubJwkClient(build_jwks([public_jwk_from_kms(fake_kms, KEY_ID)]))


@pytest.fixture
def verifier(client: StubJwkClient) -> JwksVerifier:
    """A verifier bound to the stub client, so no fetch leaves the process."""
    return JwksVerifier(issuer=ISSUER, audience=AUDIENCE, client=client)


def token(signer: KmsSigner, **overrides: Any) -> str:
    """An access token for `subject`, signed for real by the shared key."""
    params: dict[str, Any] = {
        "enabled": True,
        "environment": "staging",
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "subject": "01234567-89ab-7def-8123-456789abcdef",
    }
    params.update(overrides)
    return mint_test_token(signer, **params)


def test_a_valid_token_verifies_and_returns_its_claims(verifier: JwksVerifier, signer: KmsSigner) -> None:
    """A token signed by a key in the JWKS verifies and yields its subject."""
    claims = verifier.verify(token(signer))
    assert claims["sub"] == "01234567-89ab-7def-8123-456789abcdef"
    assert claims["iss"] == ISSUER
    assert claims["typ"] == "access"


def test_a_token_from_another_issuer_is_refused(verifier: JwksVerifier, signer: KmsSigner) -> None:
    """A token whose `iss` is not the configured issuer is refused."""
    with pytest.raises(InvalidToken):
        verifier.verify(token(signer, issuer="https://evil.example.com"))


def test_a_token_for_another_audience_is_refused(verifier: JwksVerifier, signer: KmsSigner) -> None:
    """A token whose `aud` is not the configured audience is refused."""
    with pytest.raises(InvalidToken):
        verifier.verify(token(signer, audience="someone-elses-api"))


def test_an_expired_token_is_refused(verifier: JwksVerifier, signer: KmsSigner) -> None:
    """A token whose `exp` is in the past is refused, beyond the leeway."""
    with pytest.raises(InvalidToken):
        verifier.verify(token(signer, now=int(time.time()) - 4000, expires_in=600))


def test_a_token_not_yet_valid_is_refused(verifier: JwksVerifier, signer: KmsSigner) -> None:
    """A token whose `nbf` is in the future is refused.

    Signed through the signer directly: `mint_test_token` stamps its own `nbf` last, so
    `extra_claims` cannot move it.
    """
    now = int(time.time())
    not_yet = signer.encode(
        {
            "sub": "01234567-89ab-7def-8123-456789abcdef",
            "iss": ISSUER,
            "aud": AUDIENCE,
            "typ": "access",
            "iat": now,
            "nbf": now + 3600,
            "exp": now + 7200,
        }
    )
    with pytest.raises(InvalidToken):
        verifier.verify(not_yet)


def test_a_tampered_payload_is_refused(verifier: JwksVerifier, signer: KmsSigner) -> None:
    """A token whose payload was edited after signing fails the signature check."""
    import base64

    header, payload, signature = token(signer).split(".")
    decoded = json.loads(base64.urlsafe_b64decode(payload + "=="))
    decoded["sub"] = "00000000-0000-7000-8000-000000000000"
    forged = base64.urlsafe_b64encode(json.dumps(decoded).encode()).rstrip(b"=").decode()
    with pytest.raises(InvalidToken):
        verifier.verify(f"{header}.{forged}.{signature}")


def test_a_token_signed_by_an_unknown_key_is_refused(verifier: JwksVerifier) -> None:
    """A token whose `kid` is in no served key is refused rather than trusted."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    stranger = KmsSigner(FakeKms(rsa.generate_private_key(public_exponent=65537, key_size=2048)), KEY_ID)
    with pytest.raises(InvalidToken):
        verifier.verify(token(stranger))


def test_an_unsigned_token_is_refused(verifier: JwksVerifier) -> None:
    """An `alg: none` token is refused before any key is fetched."""
    import jwt

    unsigned = jwt.encode({"sub": "x", "iss": ISSUER, "aud": AUDIENCE}, key="", algorithm="none")
    with pytest.raises(InvalidToken):
        verifier.verify(unsigned)


def test_an_hs256_token_is_refused(verifier: JwksVerifier) -> None:
    """An HS256 token is refused: only RS256 is accepted."""
    import jwt

    symmetric = jwt.encode({"sub": "x", "iss": ISSUER, "aud": AUDIENCE}, key="s" * 64, algorithm="HS256")
    with pytest.raises(InvalidToken):
        verifier.verify(symmetric)


def test_a_malformed_token_is_refused(verifier: JwksVerifier) -> None:
    """A string that is not a JWT is refused rather than raising something else."""
    with pytest.raises(InvalidToken):
        verifier.verify("not-a-token")


def test_a_non_access_token_is_refused(verifier: JwksVerifier, signer: KmsSigner) -> None:
    """A token minted for another purpose is refused when a `typ` is expected."""
    with pytest.raises(InvalidToken):
        verifier.verify(token(signer), expected_type="mfa_ticket")


def test_the_key_set_is_reused_across_verifications(
    verifier: JwksVerifier, signer: KmsSigner, client: StubJwkClient
) -> None:
    """Repeated verification reuses the client rather than rebuilding the verifier's state."""
    for _ in range(3):
        verifier.verify(token(signer))
    assert client.fetches == 3


def test_a_missing_issuer_or_audience_is_refused(client: StubJwkClient) -> None:
    """A verifier cannot be built without both an issuer and an audience."""
    with pytest.raises(ValueError):
        JwksVerifier(issuer="", audience=AUDIENCE, client=client)
    with pytest.raises(ValueError):
        JwksVerifier(issuer=ISSUER, audience="", client=client)


def test_the_jwks_uri_defaults_to_the_issuer_path(client: StubJwkClient) -> None:
    """Given no URI and no discovery, the JWKS URL is the issuer's well-known path."""
    built = JwksVerifier(issuer=f"{ISSUER}/", audience=AUDIENCE, jwks_uri=f"{ISSUER}/.well-known/jwks.json")
    assert built.jwks_uri == f"{ISSUER}/.well-known/jwks.json"


def test_discovery_refuses_a_foreign_jwks_uri(monkeypatch: pytest.MonkeyPatch) -> None:
    """A discovery document pointing at another origin's keys is refused."""

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *exc: Any) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps({"jwks_uri": "https://evil.example.com/jwks.json"}).encode()

    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: Response())
    with pytest.raises(InvalidToken):
        discovery_jwks_uri(ISSUER)


def _bearer_request(authorization: str | None) -> Request:
    """A bare request carrying `authorization`, or no Authorization header at all."""
    headers = [] if authorization is None else [(b"authorization", authorization.encode())]
    return Request({"type": "http", "method": "GET", "path": "/", "headers": headers})


@pytest.fixture
def fresh_cache() -> Iterator[None]:
    """Start and end each cache test with no verifiers built."""
    clear_verifier_cache()
    yield
    clear_verifier_cache()


@pytest.mark.usefixtures("fresh_cache")
def test_cached_verifier_returns_one_instance_per_key() -> None:
    """The same issuer, audience and URI share an instance, and its key set cache."""
    first = cached_verifier(ISSUER, AUDIENCE)
    assert first is not None
    assert cached_verifier(f" {ISSUER}/ ", [AUDIENCE, " "]) is first
    assert cached_verifier(ISSUER, [AUDIENCE, f"{ISSUER}/device"]) is not first
    assert cached_verifier(ISSUER, AUDIENCE, jwks_uri=f"{ISSUER}/keys") is not first


@pytest.mark.usefixtures("fresh_cache")
def test_cached_verifier_honours_an_explicit_jwks_uri() -> None:
    """A blank URI means the issuer default, and a set one is used as given."""
    default = cached_verifier(ISSUER, AUDIENCE, jwks_uri="  ")
    assert default is not None
    assert default.jwks_uri == f"{ISSUER}/.well-known/jwks.json"
    explicit = cached_verifier(ISSUER, AUDIENCE, jwks_uri=f"{ISSUER}/keys")
    assert explicit is not None
    assert explicit.jwks_uri == f"{ISSUER}/keys"


@pytest.mark.usefixtures("fresh_cache")
@pytest.mark.parametrize(("issuer", "audience"), [("", AUDIENCE), ("  ", AUDIENCE), (ISSUER, ""), (ISSUER, [" ", ""])])
def test_cached_verifier_is_none_without_an_issuer_and_audience(issuer: str, audience: str | list[str]) -> None:
    """A function without the identity environment gets no verifier rather than an error."""
    assert cached_verifier(issuer, audience) is None


@pytest.mark.usefixtures("fresh_cache")
def test_clear_verifier_cache_drops_the_instances() -> None:
    """After a clear the next call builds a new verifier."""
    first = cached_verifier(ISSUER, AUDIENCE)
    clear_verifier_cache()
    assert cached_verifier(ISSUER, AUDIENCE) is not first


def test_verified_bearer_subject_reads_a_verified_token(verifier: JwksVerifier, signer: KmsSigner) -> None:
    """A valid Bearer token yields its `sub`, whatever the scheme's case."""
    presented = token(signer)
    assert verified_bearer_subject(_bearer_request(f"Bearer {presented}"), verifier) == (
        "01234567-89ab-7def-8123-456789abcdef"
    )
    assert verified_bearer_subject(_bearer_request(f"bearer {presented}"), verifier) == (
        "01234567-89ab-7def-8123-456789abcdef"
    )


def test_verified_bearer_subject_accepts_a_plain_callable() -> None:
    """Any claims callable works, such as `TokenService.verify_access_token`."""
    seen: list[str] = []

    def verify(presented: str) -> dict[str, Any]:
        seen.append(presented)
        return {"sub": "user-1"}

    assert verified_bearer_subject(_bearer_request("Bearer abc"), verify) == "user-1"
    assert seen == ["abc"]


def test_verified_bearer_subject_is_empty_for_a_bad_token(verifier: JwksVerifier, signer: KmsSigner) -> None:
    """An expired, foreign or garbled token reads as anonymous rather than raising."""
    expired = token(signer, now=int(time.time()) - 4000, expires_in=600)
    assert verified_bearer_subject(_bearer_request(f"Bearer {expired}"), verifier) == ""
    foreign = token(signer, audience="someone-elses-api")
    assert verified_bearer_subject(_bearer_request(f"Bearer {foreign}"), verifier) == ""
    assert verified_bearer_subject(_bearer_request("Bearer not-a-jwt"), verifier) == ""


@pytest.mark.parametrize("authorization", [None, "", "Basic dXNlcjpwYXNz", "Bearer ", "Bearer   "])
def test_verified_bearer_subject_is_empty_without_a_bearer(authorization: str | None) -> None:
    """No credential means no verification call at all."""

    def verify(presented: str) -> dict[str, Any]:
        raise AssertionError("must not be called")

    assert verified_bearer_subject(_bearer_request(authorization), verify) == ""


def test_verified_bearer_subject_is_empty_without_a_verifier() -> None:
    """A function that could not build a verifier treats every caller as anonymous."""
    assert verified_bearer_subject(_bearer_request("Bearer abc"), None) == ""


def test_verified_bearer_subject_ignores_a_non_string_subject() -> None:
    """A `sub` that is not a string is no subject."""
    assert verified_bearer_subject(_bearer_request("Bearer abc"), lambda _: {"sub": 42}) == ""
