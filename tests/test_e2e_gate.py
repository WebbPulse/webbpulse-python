"""Tests for the staging gate cookie signer.

The policy this signs has to be byte identical to the one the gate's login Lambda issues,
because the CloudFront viewer function reads the expiry back out of the decoded text with a
regular expression rather than by parsing it. A stray space, a reordered key, or standard
base64 instead of CloudFront's safe alphabet all produce a cookie the function refuses and
a suite that reads as a broken deploy.

Nothing here asserts against a real key or prints a signed value; the fixture key is
generated in-process and the assertions verify the signature with its public half.
"""

from __future__ import annotations

import base64
import json
import re

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from webbpulse.e2e.gate import (
    COOKIE_NAMES,
    GateCookies,
    cloudfront_safe_base64,
    gate_policy,
    mint_gate_cookies,
    sign_gate_policy,
)

DOMAIN = "staging.example.invalid"
EXPIRES = 1758000000
EXPECTED_POLICY = (
    '{"Statement":[{"Resource":"https://*staging.example.invalid/*",'
    '"Condition":{"DateLessThan":{"AWS:EpochTime":1758000000}}}]}'
)
GATE_EPOCH_PATTERN = re.compile(r'"AWS:EpochTime":\s*(\d+)')


@pytest.fixture(scope="module")
def signing_key() -> rsa.RSAPrivateKey:
    """One RSA 2048 key for the module, matching the key size the gate parameter holds."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def signing_pem(signing_key: rsa.RSAPrivateKey) -> str:
    """The fixture key as an unencrypted PKCS8 PEM, which is the parameter's own shape."""
    return signing_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def decode_safe_base64(value: str) -> bytes:
    """Decode CloudFront's safe alphabet back to bytes, the way the gate function does."""
    return base64.b64decode(value.replace("-", "+").replace("_", "=").replace("~", "/"))


class TestPolicyShape:
    """Tests for the exact policy text the CloudFront function regex-matches."""

    def test_the_policy_is_byte_identical_to_the_login_lambdas(self) -> None:
        """The known vector, character for character, including the wildcard before the domain."""
        assert gate_policy(DOMAIN, EXPIRES) == EXPECTED_POLICY

    def test_the_policy_carries_no_whitespace(self) -> None:
        """`json.dumps` defaults put a space after every separator, which is refused here."""
        policy = gate_policy(DOMAIN, EXPIRES)
        assert " " not in policy
        assert "\n" not in policy

    def test_the_key_order_is_the_one_the_gate_function_reads(self) -> None:
        """Statement, Resource, Condition, DateLessThan, AWS:EpochTime, in that order."""
        policy = gate_policy(DOMAIN, EXPIRES)
        positions = [
            policy.index(key) for key in ("Statement", "Resource", "Condition", "DateLessThan", "AWS:EpochTime")
        ]
        assert positions == sorted(positions)

    def test_the_resource_keeps_the_wildcard_host(self) -> None:
        """The login Lambda writes `https://*<domain>/*`, with no dot before the wildcard."""
        assert json.loads(gate_policy(DOMAIN, EXPIRES))["Statement"][0]["Resource"] == f"https://*{DOMAIN}/*"

    def test_the_expiry_is_an_integer_not_a_float(self) -> None:
        """A float would serialise as `1758000000.0`, which the function's regex misses."""
        assert '"AWS:EpochTime":1758000000}' in gate_policy(DOMAIN, float(EXPIRES))

    def test_the_gate_functions_regex_finds_the_expiry(self) -> None:
        """The exact pattern `gate.js` runs against the decoded policy matches this text."""
        match = GATE_EPOCH_PATTERN.search(gate_policy(DOMAIN, EXPIRES))
        assert match is not None
        assert int(match.group(1)) == EXPIRES


class TestSafeBase64:
    """Tests for CloudFront's own base64 alphabet."""

    def test_every_substitution_is_applied(self) -> None:
        """`+` becomes `-`, `=` becomes `_` and `/` becomes `~`, and nothing else changes."""
        payload = bytes(range(256))
        standard = base64.b64encode(payload).decode("ascii")
        assert cloudfront_safe_base64(payload) == standard.replace("+", "-").replace("=", "_").replace("/", "~")

    def test_none_of_the_replaced_characters_survive(self) -> None:
        """A `+`, `=` or `/` left in the cookie value is what a browser or the gate rejects."""
        encoded = cloudfront_safe_base64(bytes(range(256)))
        assert "+" not in encoded
        assert "=" not in encoded
        assert "/" not in encoded

    def test_the_padding_becomes_underscores(self) -> None:
        """One byte of payload pads to two `=`, which must both become `_`."""
        assert cloudfront_safe_base64(b"a").endswith("__")

    def test_it_round_trips_through_the_gate_functions_decoder(self) -> None:
        """The decoder in `gate.js` reverses this exactly, which is what the gate relies on."""
        payload = bytes(range(256))
        assert decode_safe_base64(cloudfront_safe_base64(payload)) == payload


class TestSignature:
    """Tests for the RSA-SHA1 PKCS1 v1.5 signature CloudFront verifies."""

    def test_the_signature_verifies_with_the_public_half(
        self, signing_pem: str, signing_key: rsa.RSAPrivateKey
    ) -> None:
        """The only scheme CloudFront signed cookies accept, checked the way it checks."""
        policy, signature = sign_gate_policy(signing_pem, DOMAIN, EXPIRES)
        signing_key.public_key().verify(
            decode_safe_base64(signature),
            decode_safe_base64(policy),
            padding.PKCS1v15(),
            hashes.SHA1(),
        )

    def test_the_signed_bytes_are_the_policy_itself(self, signing_pem: str) -> None:
        """What is signed is the policy text, not a hash of it or a re-serialised copy."""
        policy, _ = sign_gate_policy(signing_pem, DOMAIN, EXPIRES)
        assert decode_safe_base64(policy).decode("utf-8") == EXPECTED_POLICY

    def test_both_halves_use_the_safe_alphabet(self, signing_pem: str) -> None:
        """Policy and signature are both encoded for CloudFront, not only the policy."""
        for value in sign_gate_policy(signing_pem, DOMAIN, EXPIRES):
            assert not set(value) & {"+", "=", "/"}

    def test_a_different_expiry_changes_the_signature(self, signing_pem: str) -> None:
        """The expiry is inside the signed bytes, so it cannot be edited in the cookie."""
        first = sign_gate_policy(signing_pem, DOMAIN, EXPIRES)
        second = sign_gate_policy(signing_pem, DOMAIN, EXPIRES + 1)
        assert first[1] != second[1]

    def test_a_non_rsa_key_is_refused_without_naming_the_key(self) -> None:
        """An EC key cannot sign a CloudFront cookie, and the refusal quotes no key material."""
        from cryptography.hazmat.primitives.asymmetric import ec

        pem = (
            ec.generate_private_key(ec.SECP256R1())
            .private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            .decode("ascii")
        )
        with pytest.raises(TypeError) as error:
            sign_gate_policy(pem, DOMAIN, EXPIRES)
        assert "BEGIN" not in str(error.value)


class TestGateCookies:
    """Tests for the shapes the two clients take."""

    def test_the_three_cookie_names_are_the_gates_own(self) -> None:
        """The viewer function checks exactly these three names and no others."""
        cookies = GateCookies(policy="p", signature="s", key_pair_id="K1", domain=DOMAIN, expires=EXPIRES)
        assert tuple(cookies.values) == COOKIE_NAMES

    def test_httpx_cookies_are_a_plain_name_to_value_mapping(self) -> None:
        """`httpx.Client(cookies=...)` takes exactly this."""
        cookies = GateCookies(policy="p", signature="s", key_pair_id="K1", domain=DOMAIN, expires=EXPIRES)
        assert cookies.as_httpx_cookies() == {
            "CloudFront-Policy": "p",
            "CloudFront-Signature": "s",
            "CloudFront-Key-Pair-Id": "K1",
        }

    def test_playwright_cookies_are_scoped_to_the_apex(self) -> None:
        """A leading dot so every host under the staging apex sends them, as `Domain=` does."""
        cookies = GateCookies(policy="p", signature="s", key_pair_id="K1", domain=DOMAIN, expires=EXPIRES)
        entries = cookies.as_playwright_cookies()
        assert len(entries) == 3
        for entry in entries:
            assert entry["domain"] == f".{DOMAIN}"
            assert entry["path"] == "/"
            assert entry["secure"] is True
            assert entry["sameSite"] == "Lax"

    def test_an_already_dotted_domain_is_not_dotted_twice(self) -> None:
        """A product that writes the apex with a leading dot gets the same cookies."""
        cookies = GateCookies(policy="p", signature="s", key_pair_id="K1", domain=f".{DOMAIN}", expires=EXPIRES)
        assert all(entry["domain"] == f".{DOMAIN}" for entry in cookies.as_playwright_cookies())

    def test_neither_value_reaches_the_repr(self) -> None:
        """A dataclass repr lands in a pytest failure report, so both signed halves are out."""
        cookies = GateCookies(
            policy="policy-value-here",
            signature="signature-value-here",
            key_pair_id="K1",
            domain=DOMAIN,
            expires=EXPIRES,
        )
        text = repr(cookies)
        assert "policy-value-here" not in text
        assert "signature-value-here" not in text


class FakeSsm:
    """An SSM client that answers one parameter, recording how it was asked for."""

    def __init__(self, value: str) -> None:
        """Hold the value this fake returns and a place to record the call."""
        self.value = value
        self.calls: list[dict[str, object]] = []

    def get_parameter(self, **kwargs: object) -> dict[str, dict[str, str]]:
        """Answer the parameter, recording the arguments so the test can assert on them."""
        self.calls.append(kwargs)
        return {"Parameter": {"Value": self.value}}


class TestMinting:
    """Tests for reading the key and minting a session."""

    def test_it_reads_the_parameter_with_decryption(self, signing_pem: str) -> None:
        """A SecureString read without decryption yields ciphertext that signs nothing."""
        ssm = FakeSsm(signing_pem)
        mint_gate_cookies(
            ssm_client=ssm,
            parameter_name="/example/access-gate/signing-private-key",
            key_pair_id="K1",
            domain=DOMAIN,
            environment="staging",
        )
        assert ssm.calls == [{"Name": "/example/access-gate/signing-private-key", "WithDecryption": True}]

    def test_the_minted_session_expires_in_the_future(self, signing_pem: str) -> None:
        """The gate admits a session only while its expiry is over thirty seconds away."""
        cookies = mint_gate_cookies(
            ssm_client=FakeSsm(signing_pem),
            parameter_name="/p",
            key_pair_id="K1",
            domain=DOMAIN,
            environment="staging",
            session_seconds=3600,
            now=EXPIRES,
        )
        assert cookies.expires == EXPIRES + 3600

    def test_the_minted_signature_verifies(self, signing_pem: str, signing_key: rsa.RSAPrivateKey) -> None:
        """End to end: what the fixture hands a browser is what CloudFront accepts."""
        cookies = mint_gate_cookies(
            ssm_client=FakeSsm(signing_pem),
            parameter_name="/p",
            key_pair_id="K1",
            domain=DOMAIN,
            environment="staging",
            now=EXPIRES,
        )
        signing_key.public_key().verify(
            decode_safe_base64(cookies.signature),
            decode_safe_base64(cookies.policy),
            padding.PKCS1v15(),
            hashes.SHA1(),
        )

    def test_production_is_refused(self, signing_pem: str) -> None:
        """Production has no web gate, so a signing key there is a key that should not exist."""
        with pytest.raises(RuntimeError, match="production"):
            mint_gate_cookies(
                ssm_client=FakeSsm(signing_pem),
                parameter_name="/p",
                key_pair_id="K1",
                domain=DOMAIN,
                environment="Production",
            )

    def test_production_is_refused_before_the_parameter_is_read(self, signing_pem: str) -> None:
        """The refusal comes first, so a production run never even asks SSM for the key."""
        ssm = FakeSsm(signing_pem)
        with pytest.raises(RuntimeError):
            mint_gate_cookies(
                ssm_client=ssm,
                parameter_name="/p",
                key_pair_id="K1",
                domain=DOMAIN,
                environment="production",
            )
        assert ssm.calls == []

    def test_no_pem_reaches_the_returned_object(self, signing_pem: str) -> None:
        """The key is read, used and dropped; nothing carrying it is returned or reprd."""
        cookies = mint_gate_cookies(
            ssm_client=FakeSsm(signing_pem),
            parameter_name="/p",
            key_pair_id="K1",
            domain=DOMAIN,
            environment="staging",
        )
        assert "PRIVATE KEY" not in repr(cookies)
        assert "PRIVATE KEY" not in "".join(cookies.values.values())
