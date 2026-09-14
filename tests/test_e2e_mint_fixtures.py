"""Tests for the `minted_subject` and `minted_token` fixtures.

The subject a token is minted for is the one claim every other mint case depends on. The
application maps `sub` to a stored user, so a synthetic subject is refused at that step
whatever the claim under test says, and a wrong-audience case would then pass for the wrong
reason. These call the fixture functions directly through `__wrapped__`, which is what pytest
would call, so what is asserted is the fixture's own logic rather than a session's plumbing.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from _pytest.outcomes import Skipped

from webbpulse.e2e import E2EEnvironment, admin_mint_token, minted_subject, minted_token
from webbpulse.e2e.identity import IdentitySession

DURABLE_SUBJECT = "2f6c1a7e-6b5f-4a1f-9a8e-0d2b3c4d5e6f"


def segment(payload: dict[str, Any]) -> str:
    """One base64url JWT segment with its padding stripped, the way a real token carries it."""
    raw = json.dumps(payload).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def access_token(subject: str) -> str:
    """An unsigned RS256-shaped token carrying one `sub` claim."""
    header = segment({"alg": "RS256", "typ": "JWT"})
    claims = segment({"sub": subject, "iss": "https://issuer.invalid", "aud": "api"})
    return f"{header}.{claims}.signature"


def session(subject: str) -> IdentitySession:
    """A signed-in durable user whose access token names `subject`."""
    from webbpulse.e2e.identity import decode_claims

    token = access_token(subject)
    header, claims = decode_claims(token)
    return IdentitySession(
        client=None,  # type: ignore[arg-type]
        access_token=token,
        claims=claims,
        header=header,
        refresh_token="",
        refresh_cookies={},
        user_id=str(claims.get("sub", "")),
    )


def environment(**overrides: Any) -> E2EEnvironment:
    """A staging environment with minting enabled."""
    fields: dict[str, Any] = {
        "environment": "staging",
        "api_base_url": "https://api.example.invalid",
        "web_base_url": "https://www.example.invalid",
        "aws_region": "us-west-2",
        "api_id": "api123",
        "access_log_group": "/aws/apigateway/example",
        "user_email": "e2e@example.invalid",
        "user_password": "unused",
        "run_id": "34801932369",
        "mint_enabled": True,
        "kms_key_id": "arn:aws:kms:us-west-2:1:key/abc",
        "issuer": "https://issuer.invalid",
        "audience": "api",
    }
    fields.update(overrides)
    return E2EEnvironment(**fields)


class RecordingKms:
    """A boto3 session stand-in whose `kms` client records nothing but is handed through."""

    def __init__(self) -> None:
        """Hold the one client the fixture asks for."""
        self.asked: list[str] = []

    def client(self, name: str) -> Any:
        """Record the service asked for and hand back a placeholder client."""
        self.asked.append(name)
        return object()


class RecordingConfig:
    """A `pytest.Config` stand-in collecting the warnings a fixture issues."""

    def __init__(self) -> None:
        """Hold the warnings issued."""
        self.warnings: list[Warning] = []

    def issue_config_time_warning(self, warning: Warning, stacklevel: int = 1) -> None:
        """Record one warning instead of emitting it."""
        self.warnings.append(warning)


class RecordingRequest:
    """A `pytest.FixtureRequest` stand-in that hands out one lazily requested fixture.

    The mint fixtures pull `boto3_session` through `getfixturevalue` rather than as a
    parameter, so a run that cannot mint never builds one, and this records which fixtures
    were asked for so a test can assert that nothing was.
    """

    def __init__(self) -> None:
        """Hold the names asked for, the session handed back and a config recording warnings."""
        self.asked: list[str] = []
        self.session = RecordingKms()
        self.config = RecordingConfig()

    def getfixturevalue(self, name: str) -> Any:
        """Record the fixture asked for and hand back the recording session."""
        self.asked.append(name)
        return self.session


def subject_fixture(user_session: IdentitySession) -> str:
    """Call the `minted_subject` fixture function the way pytest would."""
    return minted_subject.__wrapped__(user_session)  # type: ignore[attr-defined,no-any-return]


@pytest.fixture
def recorded_mints(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Replace the plugin's `mint` with a recorder, so no test reaches KMS."""
    minted: list[dict[str, Any]] = []

    def fake_mint(**kwargs: Any) -> str:
        """Record the mint arguments instead of signing anything."""
        minted.append(kwargs)
        return "minted.token.value"

    monkeypatch.setattr("webbpulse.e2e.mint", fake_mint)
    return minted


def token_fixture(env: E2EEnvironment, subject: str) -> Any:
    """Call the `minted_token` fixture function the way pytest would."""
    return minted_token.__wrapped__(env, RecordingRequest(), subject)  # type: ignore[attr-defined]


class TestMintedSubject:
    """Tests for the default subject a minted token names."""

    def test_it_is_the_sub_claim_of_the_session_token(self) -> None:
        """The real subject, which is what the application resolves to a stored user."""
        assert subject_fixture(session(DURABLE_SUBJECT)) == DURABLE_SUBJECT

    def test_it_is_not_a_synthetic_prefix_string(self) -> None:
        """The defect this replaces: `e2e-<run id>-mint` names no stored user."""
        subject = subject_fixture(session(DURABLE_SUBJECT))
        assert not subject.startswith("e2e-")
        assert not subject.endswith("-mint")

    def test_a_session_with_no_sub_skips(self) -> None:
        """A token naming no subject makes every mint case fail for the wrong reason."""
        with pytest.raises(Skipped, match="no `sub` claim"):
            subject_fixture(session(""))


class TestMintedToken:
    """Tests for the token factory the identity cases call."""

    def test_the_default_subject_comes_from_the_session(self, recorded_mints: list[dict[str, Any]]) -> None:
        """No caller passes a subject, so the session's own is what gets signed."""
        token_fixture(environment(), DURABLE_SUBJECT)({"roles": ["admin"]})
        assert recorded_mints[0]["subject"] == DURABLE_SUBJECT

    def test_an_explicit_subject_still_wins(self, recorded_mints: list[dict[str, Any]]) -> None:
        """The override the rejection cases would use for a subject-specific probe."""
        token_fixture(environment(), DURABLE_SUBJECT)(subject="someone-else")
        assert recorded_mints[0]["subject"] == "someone-else"

    def test_the_audience_override_keeps_the_default_subject(self, recorded_mints: list[dict[str, Any]]) -> None:
        """The wrong-audience case must differ from a good token in `aud` alone."""
        token_fixture(environment(), DURABLE_SUBJECT)(audience="https://e2e.invalid/not-this-audience")
        assert recorded_mints[0]["subject"] == DURABLE_SUBJECT
        assert recorded_mints[0]["audience"] == "https://e2e.invalid/not-this-audience"

    def test_the_expiry_override_keeps_the_default_subject(self, recorded_mints: list[dict[str, Any]]) -> None:
        """The expired case must differ from a good token in `exp` alone."""
        token_fixture(environment(), DURABLE_SUBJECT)(expires_in=1, now=0)
        assert recorded_mints[0]["subject"] == DURABLE_SUBJECT
        assert recorded_mints[0]["expires_in"] == 1

    def test_the_environments_audience_is_the_default(self, recorded_mints: list[dict[str, Any]]) -> None:
        """A token with no override carries this environment's own audience."""
        token_fixture(environment(), DURABLE_SUBJECT)()
        assert recorded_mints[0]["audience"] == "api"

    def test_minting_disabled_skips(self) -> None:
        """Every environment but staging, where the fixture must never reach KMS."""
        with pytest.raises(Skipped, match="E2E_MINT_ENABLED"):
            token_fixture(environment(mint_enabled=False), DURABLE_SUBJECT)


class TestAdminMintToken:
    """The admin token the ephemeral routes are authorised with, and its fallback."""

    def test_it_returns_the_minted_token(self, recorded_mints: list[dict[str, Any]]) -> None:
        """The ordinary staging path, where minting is on and the key answers."""
        request = RecordingRequest()
        assert admin_mint_token.__wrapped__(environment(), request) == "minted.token.value"  # type: ignore[attr-defined]
        assert recorded_mints[0]["extra_claims"] == {"roles": ["admin"]}

    def test_minting_off_needs_no_aws_client(self) -> None:
        """A local stack has no KMS key, so the fixture must not build a session at all."""
        request = RecordingRequest()
        assert admin_mint_token.__wrapped__(environment(mint_enabled=False), request) == ""  # type: ignore[attr-defined]
        assert request.asked == []
        assert request.config.warnings == []

    def test_a_read_only_run_mints_nothing_and_warns_about_nothing(self) -> None:
        """Read-only signs in as nobody, so the absent token is expected rather than broken."""
        request = RecordingRequest()
        assert admin_mint_token.__wrapped__(environment(read_only=True), request) == ""  # type: ignore[attr-defined]
        assert request.config.warnings == []

    def test_a_failed_mint_warns_before_falling_back(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A silent fallback made a broken key look like an ordinary durable-user run."""

        def failing_mint(**kwargs: Any) -> str:
            """Fail the way a denied KMS call does."""
            raise RuntimeError("AccessDeniedException on Sign")

        monkeypatch.setattr("webbpulse.e2e.mint", failing_mint)
        request = RecordingRequest()
        assert admin_mint_token.__wrapped__(environment(), request) == ""  # type: ignore[attr-defined]
        assert len(request.config.warnings) == 1
        message = str(request.config.warnings[0])
        assert "RuntimeError" in message
        assert "AccessDeniedException on Sign" in message

    def test_a_failed_mint_warning_carries_no_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The warning lands in CI output, which is not a place for credential material."""

        def failing_mint(**kwargs: Any) -> str:
            """Fail with a message that must not be mistaken for a reason to log a token."""
            raise RuntimeError("boom")

        monkeypatch.setattr("webbpulse.e2e.mint", failing_mint)
        request = RecordingRequest()
        admin_mint_token.__wrapped__(environment(), request)  # type: ignore[attr-defined]
        assert "minted.token.value" not in str(request.config.warnings[0])
