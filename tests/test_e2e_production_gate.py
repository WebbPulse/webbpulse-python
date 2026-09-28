"""Tests for `E2E_PRODUCTION_GATED`, the opt-in that mints gate cookies in production.

A production behind the web gate needs the signed cookies for its browser smoke, but the
refusal that keeps a production run from reading a signing key must stay for every
production that has not declared the gate. The opt-in must also unlock the cookie mint
alone: a production run stays the anonymous read-only smoke, with no sign in, no write and
no ephemeral user.
"""

from __future__ import annotations

import base64
from collections.abc import Iterator
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from webbpulse.e2e import (
    PRODUCTION_GATED,
    E2EEnvironment,
    MissingEnvironment,
    admin_mint_token,
)
from webbpulse.e2e.gate import GateCookies, gate_cookies, mint_gate_cookies

pytest_plugins = ["pytester"]

PRODUCTION_REFUSAL = (
    "mint_gate_cookies refuses production. Production has no web gate, so there is "
    "no session to mint and no signing key that should be readable there."
)

WEB_GATE = {
    "E2E_GATE_SIGNING_KEY_SSM_PARAMETER": "/example/access-gate/signing-private-key",
    "E2E_GATE_KEY_PAIR_ID": "K1EXAMPLE",
    "E2E_GATE_COOKIE_DOMAIN": "example.invalid",
}

PRODUCTION = {
    "E2E_ENVIRONMENT": "production",
    "E2E_API_BASE_URL": "https://api.example.invalid",
    "E2E_WEB_BASE_URL": "https://www.example.invalid",
    "E2E_AWS_REGION": "us-west-2",
    "E2E_API_ID": "prod123",
    "E2E_ACCESS_LOG_GROUP": "/aws/apigateway/example-production-api",
    "E2E_RUN_ID": "1234567890",
    "E2E_READ_ONLY": "true",
}

GATED_PRODUCTION = {**PRODUCTION, **WEB_GATE, PRODUCTION_GATED: "true"}


@pytest.fixture(scope="module")
def signing_key() -> rsa.RSAPrivateKey:
    """One RSA 2048 key for the module, the size the gate parameter holds."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def signing_pem(signing_key: rsa.RSAPrivateKey) -> str:
    """The fixture key as an unencrypted PKCS8 PEM, the parameter's own shape."""
    return signing_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def decode_safe_base64(value: str) -> bytes:
    """Decode CloudFront's safe alphabet back to bytes."""
    return base64.b64decode(value.replace("-", "+").replace("_", "=").replace("~", "/"))


class FakeSsm:
    """An SSM client answering one parameter and recording each read."""

    def __init__(self, value: str) -> None:
        """Hold the value returned and the calls made."""
        self.value = value
        self.calls: list[dict[str, object]] = []

    def get_parameter(self, **kwargs: object) -> dict[str, dict[str, str]]:
        """Answer the parameter, recording the arguments."""
        self.calls.append(kwargs)
        return {"Parameter": {"Value": self.value}}


class FakeSession:
    """A boto3 session stand-in handing out one SSM client and recording what was asked for."""

    def __init__(self, ssm: Any) -> None:
        """Hold the SSM client and the services asked for."""
        self.ssm = ssm
        self.asked: list[str] = []

    def client(self, name: str) -> Any:
        """Record the service and hand back the SSM fake."""
        self.asked.append(name)
        return self.ssm


class FakeRequest:
    """A `pytest.FixtureRequest` stand-in handing out one lazily requested session."""

    def __init__(self, session: Any) -> None:
        """Hold the session and the fixture names asked for."""
        self.session = session
        self.asked: list[str] = []

    def getfixturevalue(self, name: str) -> Any:
        """Record the fixture asked for and hand back the session."""
        self.asked.append(name)
        return self.session


def run_gate_fixture(env: E2EEnvironment, request: FakeRequest) -> GateCookies | None:
    """Call the `gate_cookies` fixture function the way pytest would, returning its value."""
    generator: Iterator[GateCookies | None] = gate_cookies.__wrapped__(env, request)  # type: ignore[attr-defined]
    return next(generator)


class TestParsing:
    """Tests for how the environment parse reads the opt-in."""

    def test_the_variable_name_is_the_documented_one(self) -> None:
        """Consumers set it by name as a GitHub Environment variable, so it is contract."""
        assert PRODUCTION_GATED == "E2E_PRODUCTION_GATED"

    def test_a_gated_read_only_production_is_accepted(self) -> None:
        """The whole opt-in: production, read-only, the three gate variables and the flag."""
        env = E2EEnvironment.from_environ(GATED_PRODUCTION)
        assert env.production_gated
        assert env.has_web_gate
        assert env.read_only
        assert not env.signs_in

    def test_production_without_the_flag_is_not_gated(self) -> None:
        """Absent the declaration, production parses exactly as it always has."""
        assert not E2EEnvironment.from_environ({**PRODUCTION, **WEB_GATE}).production_gated

    def test_the_flag_needs_read_only(self) -> None:
        """Declaring the gate must never turn a production run into a signed-in one."""
        writable = {**GATED_PRODUCTION, "E2E_READ_ONLY": "false", "E2E_USER_EMAIL": "u@x", "E2E_USER_PASSWORD": "p"}
        with pytest.raises(MissingEnvironment, match="E2E_READ_ONLY=true"):
            E2EEnvironment.from_environ(writable)

    def test_the_flag_needs_the_gate_variables(self) -> None:
        """A gated production with nothing to sign with would meet the gate's redirect."""
        bare = {**PRODUCTION, PRODUCTION_GATED: "true"}
        with pytest.raises(MissingEnvironment, match="E2E_GATE_SIGNING_KEY_SSM_PARAMETER"):
            E2EEnvironment.from_environ(bare)

    def test_the_flag_means_nothing_outside_production(self) -> None:
        """Staging mints whenever the gate variables are set, so the flag changes nothing."""
        staging = {
            **GATED_PRODUCTION,
            "E2E_ENVIRONMENT": "staging",
            "E2E_READ_ONLY": "",
            "E2E_USER_EMAIL": "u@x",
            "E2E_USER_PASSWORD": "p",
        }
        env = E2EEnvironment.from_environ(staging)
        assert not env.production_gated
        assert env.has_web_gate


class TestSigner:
    """Tests for `mint_gate_cookies` in production."""

    def test_production_is_still_refused_without_the_opt_in(self, signing_pem: str) -> None:
        """The refusal and its exact message stand, and SSM is never asked."""
        ssm = FakeSsm(signing_pem)
        with pytest.raises(RuntimeError) as caught:
            mint_gate_cookies(
                ssm_client=ssm,
                parameter_name="/p",
                key_pair_id="K1",
                domain="example.invalid",
                environment="production",
            )
        assert str(caught.value) == PRODUCTION_REFUSAL
        assert ssm.calls == []

    def test_a_gated_production_mints_a_verifying_session(
        self, signing_pem: str, signing_key: rsa.RSAPrivateKey
    ) -> None:
        """The same signer staging uses, lifted for a production declared gated."""
        cookies = mint_gate_cookies(
            ssm_client=FakeSsm(signing_pem),
            parameter_name="/p",
            key_pair_id="K1",
            domain="example.invalid",
            environment="production",
            production_gated=True,
            now=1758000000,
        )
        assert b"https://*example.invalid/*" in decode_safe_base64(cookies.policy)
        signing_key.public_key().verify(
            decode_safe_base64(cookies.signature),
            decode_safe_base64(cookies.policy),
            padding.PKCS1v15(),
            hashes.SHA1(),
        )


class TestFixture:
    """Tests for the `gate_cookies` fixture in production."""

    def test_a_gated_production_mints_cookies(self, signing_pem: str) -> None:
        """The opt-in reaches the signer and the browser gets its three cookies."""
        ssm = FakeSsm(signing_pem)
        request = FakeRequest(FakeSession(ssm))
        cookies = run_gate_fixture(E2EEnvironment.from_environ(GATED_PRODUCTION), request)
        assert cookies is not None
        assert cookies.key_pair_id == "K1EXAMPLE"
        assert ssm.calls == [{"Name": WEB_GATE["E2E_GATE_SIGNING_KEY_SSM_PARAMETER"], "WithDecryption": True}]

    def test_an_undeclared_production_with_gate_variables_is_still_refused(self, signing_pem: str) -> None:
        """Without the flag a production run refuses as before, before reading any key."""
        ssm = FakeSsm(signing_pem)
        request = FakeRequest(FakeSession(ssm))
        with pytest.raises(RuntimeError) as caught:
            run_gate_fixture(E2EEnvironment.from_environ({**PRODUCTION, **WEB_GATE}), request)
        assert str(caught.value) == PRODUCTION_REFUSAL
        assert ssm.calls == []

    def test_a_writable_production_is_refused_even_when_built_by_hand(self, signing_pem: str) -> None:
        """The fixture lifts the refusal only on a read-only run, whatever the dataclass says."""
        env = E2EEnvironment.from_environ(GATED_PRODUCTION)
        writable = E2EEnvironment(**{**env.__dict__, "read_only": False})
        ssm = FakeSsm(signing_pem)
        with pytest.raises(RuntimeError, match="refuses production"):
            run_gate_fixture(writable, FakeRequest(FakeSession(ssm)))
        assert ssm.calls == []


class TestStaysReadOnly:
    """Tests that the opt-in unlocks nothing but the cookie mint."""

    def test_the_admin_token_is_never_minted(self) -> None:
        """No admin token means no ephemeral user, even with the KMS variables forwarded."""
        env = E2EEnvironment.from_environ(
            {
                **GATED_PRODUCTION,
                "E2E_MINT_ENABLED": "true",
                "E2E_KMS_KEY_ID": "key",
                "E2E_ISSUER": "https://issuer.invalid",
                "E2E_AUDIENCE": "api",
            }
        )
        request = FakeRequest(FakeSession(None))
        assert admin_mint_token.__wrapped__(env, request) == ""  # type: ignore[attr-defined]
        assert request.asked == []

    def test_marked_cases_are_skipped_in_a_gated_production(self, pytester: pytest.Pytester) -> None:
        """The collection hook skips every `e2e_writes` case with the opt-in on."""
        assignments = "\n".join(f"os.environ[{name!r}] = {value!r}" for name, value in GATED_PRODUCTION.items())
        pytester.makeconftest(
            'pytest_plugins = ["webbpulse.e2e"]\n'
            "import os\n"
            f"{assignments}\n"
            'for _name in ("E2E_USER_EMAIL", "E2E_USER_PASSWORD"):\n'
            "    os.environ.pop(_name, None)\n"
        )
        pytester.makepyfile(
            test_cases=(
                "import pytest\n\n\n"
                "@pytest.mark.e2e_writes\n"
                "def test_it_writes():\n"
                "    assert True\n\n\n"
                "def test_it_only_reads():\n"
                "    assert True\n"
            )
        )
        result = pytester.runpytest_inprocess("-p", "no:cacheprovider")
        result.assert_outcomes(passed=1, skipped=1)
