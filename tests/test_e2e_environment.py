"""Tests for reading `E2EEnvironment` out of the `E2E_*` variables.

A suite that starts with a missing base URL fails every test with a connection error and
buries the one line that explains it, so the parse refuses up front and names every missing
variable at once.
"""

from __future__ import annotations

import re

import pytest

from webbpulse.e2e import E2EEnvironment, MissingEnvironment

COMPLETE = {
    "E2E_ENVIRONMENT": "staging",
    "E2E_API_BASE_URL": "https://api.staging.example.invalid/",
    "E2E_WEB_BASE_URL": "https://www.staging.example.invalid/",
    "E2E_AWS_REGION": "us-west-2",
    "E2E_API_ID": "abc123",
    "E2E_ACCESS_LOG_GROUP": "/aws/apigateway/example-staging-api",
    "E2E_USER_EMAIL": "e2e@example.invalid",
    "E2E_USER_PASSWORD": "not-a-real-password",
    "E2E_RUN_ID": "1234567890",
}


class TestParsing:
    """Tests for a well-formed environment."""

    def test_reads_every_required_variable(self) -> None:
        """Each required variable lands on the matching field."""
        env = E2EEnvironment.from_environ(COMPLETE)
        assert env.environment == "staging"
        assert env.api_id == "abc123"
        assert env.user_email == "e2e@example.invalid"
        assert env.run_id == "1234567890"

    def test_base_urls_lose_their_trailing_slash(self) -> None:
        """Both base URLs are normalised, so a path is always joined with exactly one slash."""
        env = E2EEnvironment.from_environ(COMPLETE)
        assert env.api_base_url == "https://api.staging.example.invalid"
        assert env.web_base_url == "https://www.staging.example.invalid"

    def test_legacy_route_names_split_on_commas(self) -> None:
        """The legacy name list is comma separated, and blanks are dropped."""
        env = E2EEnvironment.from_environ({**COMPLETE, "E2E_LEGACY_ROUTE_NAMES": "/api/auth/token, /api/auth/2fa ,"})
        assert env.legacy_route_names == ("/api/auth/token", "/api/auth/2fa")

    def test_an_absent_legacy_list_is_empty(self) -> None:
        """No legacy list means nothing to sweep for, not a failure."""
        assert E2EEnvironment.from_environ(COMPLETE).legacy_route_names == ()

    def test_production_is_recognised(self) -> None:
        """Production is the environment with no gate and no minting."""
        env = E2EEnvironment.from_environ({**COMPLETE, "E2E_ENVIRONMENT": "production"})
        assert env.is_production

    def test_the_resource_prefix_carries_the_marker_and_the_run_id(self) -> None:
        """The prefix is what the start-of-session sweep finds leftovers by."""
        env = E2EEnvironment.from_environ(COMPLETE)
        assert env.resource_prefix == "e2e-1234567890-"

    def test_the_password_is_kept_out_of_the_repr(self) -> None:
        """A dataclass repr reaches a pytest failure report, so the password is excluded."""
        assert "not-a-real-password" not in repr(E2EEnvironment.from_environ(COMPLETE))

    @pytest.mark.parametrize("flag", ["1", "true", "TRUE", "yes", "on"])
    def test_mint_enabled_accepts_the_usual_spellings(self, flag: str) -> None:
        """The mint flag is read the way a workflow boolean input is spelled."""
        env = E2EEnvironment.from_environ(
            {
                **COMPLETE,
                "E2E_MINT_ENABLED": flag,
                "E2E_KMS_KEY_ID": "key",
                "E2E_ISSUER": "https://api.staging.example.invalid/",
                "E2E_AUDIENCE": "aud",
            }
        )
        assert env.mint_enabled
        assert env.issuer == "https://api.staging.example.invalid"

    @pytest.mark.parametrize("flag", ["", "0", "false", "no"])
    def test_mint_disabled_needs_no_mint_variables(self, flag: str) -> None:
        """With minting off, the KMS variables are not required."""
        env = E2EEnvironment.from_environ({**COMPLETE, "E2E_MINT_ENABLED": flag})
        assert not env.mint_enabled


class TestMissingVariables:
    """Tests for the refusal when the workflow is wired wrong."""

    def test_a_missing_variable_is_named(self) -> None:
        """The error names the variable, not just that something is unset."""
        incomplete = {key: value for key, value in COMPLETE.items() if key != "E2E_API_ID"}
        with pytest.raises(MissingEnvironment, match="E2E_API_ID"):
            E2EEnvironment.from_environ(incomplete)

    def test_every_missing_variable_is_named_at_once(self) -> None:
        """A workflow wired wrong is usually wrong in more than one place, so all are listed."""
        incomplete = {key: value for key, value in COMPLETE.items() if key not in ("E2E_API_ID", "E2E_RUN_ID")}
        with pytest.raises(MissingEnvironment) as error:
            E2EEnvironment.from_environ(incomplete)
        assert "E2E_API_ID" in str(error.value)
        assert "E2E_RUN_ID" in str(error.value)

    def test_a_blank_variable_counts_as_missing(self) -> None:
        """An empty string from an unset workflow input is missing, not a valid value."""
        with pytest.raises(MissingEnvironment, match="E2E_API_BASE_URL"):
            E2EEnvironment.from_environ({**COMPLETE, "E2E_API_BASE_URL": "   "})

    def test_enabling_minting_requires_the_kms_variables(self) -> None:
        """Turning minting on without a key or an issuer is refused at parse time."""
        with pytest.raises(MissingEnvironment) as error:
            E2EEnvironment.from_environ({**COMPLETE, "E2E_MINT_ENABLED": "true"})
        assert "E2E_KMS_KEY_ID" in str(error.value)
        assert "E2E_ISSUER" in str(error.value)
        assert "E2E_AUDIENCE" in str(error.value)

    def test_the_error_points_at_the_documentation(self) -> None:
        """The message says where the variables come from, so the fix is one read away."""
        with pytest.raises(MissingEnvironment, match=re.escape("docs/e2e.md")):
            E2EEnvironment.from_environ({})
