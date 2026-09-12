"""`IdentitySettings`: the whole configuration surface of the identity application.

A `BaseSettings` with the `IDENTITY_` prefix, validating the issuer, signing keys,
cookie attributes and token lifetimes. Secrets are never fields here.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Final, Literal
from urllib.parse import urlparse

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = ["MAX_ACCESS_TOKEN_TTL", "MAX_SIGNING_KEYS", "IdentitySettings", "OAuthProvider"]

OAuthProvider = Literal["google", "github"]

_DEFAULT_OAUTH_PROVIDERS: Final[list[OAuthProvider]] = ["google", "github"]

MAX_ACCESS_TOKEN_TTL: Final = timedelta(hours=1)

MAX_SIGNING_KEYS: Final = 4

_PLAINTEXT_ISSUER_ENVIRONMENTS: Final[frozenset[str]] = frozenset({"local", "test"})


class IdentitySettings(BaseSettings):
    """Configuration for one product's identity application.

    Built by the product's composition root or read from `IDENTITY_`-prefixed environment
    variables. List fields accept a JSON array only, never bare CSV.
    """

    model_config = SettingsConfigDict(
        env_prefix="IDENTITY_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    environment: str = Field(
        default="local",
        description=(
            "Which deployment this is. Gates the `http://` issuer allowance and the "
            "local-development fallbacks, and nothing else."
        ),
    )
    issuer: str = Field(
        description=(
            "The `iss` claim, the discovery document's `issuer`, and the authorizer's "
            "configured issuer. All three must be this exact string."
        ),
    )
    audience: str = Field(
        description="The `aud` claim, matched by the authorizer. For example 'carmodpicker-api'.",
    )
    signing_key_arns: list[str] = Field(
        default_factory=list,
        description="KMS RSA_2048 signing keys, active signer first. More than one is a rotation.",
    )
    data_key_arn: str = Field(
        default="",
        description=("Symmetric KMS key for TOTP seed envelope encryption. Unused until M4 and optional until then."),
    )

    passwords_enabled: bool = True
    registration_enabled: bool = True
    email_verification_required: bool = True
    totp_enabled: bool = True
    passkeys_enabled: bool = True
    passkeys_passwordless: bool = True
    oauth_providers: list[OAuthProvider] = Field(default_factory=lambda: _DEFAULT_OAUTH_PROVIDERS.copy())
    password_breach_check: bool = Field(
        default=False,
        description=(
            "Check new passwords against a breach corpus (section 5.2). Off by default: the "
            "2026-09-09 decision was no breach corpus check, so a product opts in explicitly."
        ),
    )
    mfa_required_for_roles: list[str] = Field(default_factory=list)

    access_token_ttl: timedelta = Field(
        default=timedelta(minutes=10),
        description="Section 3.2: ten minutes. Short, because logout cannot revoke one.",
    )
    refresh_token_ttl: timedelta = Field(
        default=timedelta(days=30),
        description="Rolling refresh window, reset on each rotation.",
    )
    refresh_absolute_ttl: timedelta = Field(
        default=timedelta(days=90),
        description="Hard cap after which a full login is required regardless of activity.",
    )
    refresh_reuse_grace: timedelta = Field(
        default=timedelta(seconds=10),
        description=(
            "How long a consumed refresh token replays to the same successor rather than "
            "revoking the family. Zero takes the stricter behaviour."
        ),
    )
    mfa_ticket_ttl: timedelta = Field(default=timedelta(minutes=5))
    email_verification_ttl: timedelta = Field(default=timedelta(hours=24))
    password_reset_ttl: timedelta = Field(default=timedelta(hours=1))
    clock_skew_leeway: timedelta = Field(
        default=timedelta(seconds=30),
        description="Tolerance when verifying `exp` and `nbf` locally, for clock skew.",
    )

    cookie_name: str = Field(default="wp_refresh")
    cookie_domain: str = Field(
        default="",
        description=(
            "The registrable domain, so `www.` and the API host share the cookie. Empty "
            "makes it a host-only cookie, which is correct locally."
        ),
    )
    cookie_path: str = Field(
        default="",
        description=(
            "Scoped so no other domain's function ever receives the refresh cookie. Empty "
            "derives it from the issuer's path, which is where the router mounts, so the "
            "cookie is sent to exactly the routes that spend it. Set it explicitly to "
            "override."
        ),
    )
    cookie_samesite: Literal["lax", "strict", "none"] = Field(default="lax")
    cookie_secure: bool = Field(default=True)

    rp_id: str = Field(
        default="",
        description=(
            "The WebAuthn Relying Party ID, normally the registrable domain. Hashed into "
            "every credential and immutable for that credential's life."
        ),
    )
    rp_name: str = Field(default="")
    webauthn_origins: list[str] = Field(default_factory=list)

    email_from: str = Field(default="")
    ses_configuration_set: str | None = Field(default=None)
    frontend_base_url: str = Field(default="")
    product_name: str = Field(default="")
    support_email: str = Field(default="")
    logo_url: str | None = Field(default=None)

    google_client_id: str = Field(default="")
    github_client_id: str = Field(default="")

    oauth_redirect_uris: list[str] = Field(
        default_factory=list,
        description=(
            "Absolute redirect URIs an OAuth start may ask the provider to call back. "
            "Empty means the single default, `<issuer>/oauth/callback`."
        ),
    )
    """The allow-list an OAuth `redirect_uri` is checked against, by exact string equality.

    Exact equality never a prefix, since a prefix check admits an attacker-registrable
    sibling domain. Empty means the single default, `<issuer>/oauth/callback`.
    """

    @field_validator("issuer", "frontend_base_url", mode="before")
    @classmethod
    def _strip_trailing_slash(cls, value: object) -> object:
        """Strip trailing slashes so `iss`, discovery and the authorizer agree."""
        return value.rstrip("/") if isinstance(value, str) else value

    @model_validator(mode="after")
    def _check_issuer_scheme(self) -> IdentitySettings:
        """Require an absolute http(s) issuer, allowing plaintext only locally."""
        parsed = urlparse(self.issuer)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(
                f"issuer must be an absolute http(s) URL, got {self.issuer!r}. API Gateway "
                "builds the discovery URL by appending "
                "'/.well-known/openid-configuration' to it."
            )
        if parsed.scheme == "http" and self.environment.strip().lower() not in (_PLAINTEXT_ISSUER_ENVIRONMENTS):
            raise ValueError(
                f"issuer {self.issuer!r} is plaintext http in environment "
                f"{self.environment!r}. The JWKS served under this issuer is the trust "
                "anchor for every token this product issues, and over http it is whatever "
                "the network says it is."
            )
        if parsed.query or parsed.fragment:
            raise ValueError(f"issuer must have no query string or fragment, got {self.issuer!r}.")
        return self

    @field_validator("signing_key_arns")
    @classmethod
    def _check_signing_keys(cls, value: list[str]) -> list[str]:
        """Require at least one signing key, capped and free of duplicates."""
        cleaned = [arn.strip() for arn in value if arn.strip()]
        if not cleaned:
            raise ValueError(
                "signing_key_arns must name at least one KMS key. The first entry is the "
                "active signer; a second is a rotation in progress."
            )
        if len(cleaned) > MAX_SIGNING_KEYS:
            raise ValueError(
                f"signing_key_arns lists {len(cleaned)} keys, more than the "
                f"{MAX_SIGNING_KEYS} a rotation needs. Every key in the list is trusted to "
                "verify a token, so a retired key left here is still a live signer's key."
            )
        if len(set(cleaned)) != len(cleaned):
            raise ValueError(
                "signing_key_arns contains a duplicate. Two entries for one key serve the "
                "same `kid` twice in the JWKS, which some verifiers reject."
            )
        return cleaned

    @model_validator(mode="after")
    def _default_cookie_path_to_issuer_path(self) -> IdentitySettings:
        """Derive `cookie_path` from the issuer when it was not set explicitly.

        Scopes the refresh cookie to where the router mounts, so the two cannot drift.
        Runs before `_check_cookie`, which validates the derived value.
        """
        if not self.cookie_path:
            self.cookie_path = urlparse(self.issuer).path.rstrip("/") or "/"
        return self

    @model_validator(mode="after")
    def _check_cookie(self) -> IdentitySettings:
        """Reject cookie attributes a browser would silently drop the cookie over."""
        if self.cookie_samesite == "none" and not self.cookie_secure:
            raise ValueError(
                "cookie_samesite='none' requires cookie_secure=True. Browsers reject a "
                "SameSite=None cookie without Secure outright, and the symptom is a login "
                "that appears to succeed and never persists."
            )
        if self.cookie_domain:
            domain = self.cookie_domain.strip()
            if domain.startswith("."):
                raise ValueError(
                    f"cookie_domain {self.cookie_domain!r} has a leading dot. The leading "
                    "dot form is obsolete and RFC 6265 gives the bare domain the same "
                    "subdomain-including meaning."
                )
            if "." not in domain and domain != "localhost":
                raise ValueError(
                    f"cookie_domain {self.cookie_domain!r} is a single label. A cookie "
                    "scoped to a public suffix is rejected by every browser."
                )
        if not self.cookie_path.startswith("/"):
            raise ValueError(f"cookie_path must be absolute, got {self.cookie_path!r}.")
        return self

    @model_validator(mode="after")
    def _check_lifetimes(self) -> IdentitySettings:
        """Keep the access token short and the refresh windows mutually consistent."""
        if self.access_token_ttl <= timedelta(0):
            raise ValueError("access_token_ttl must be positive.")
        if self.access_token_ttl > MAX_ACCESS_TOKEN_TTL:
            raise ValueError(
                f"access_token_ttl of {self.access_token_ttl} exceeds the "
                f"{MAX_ACCESS_TOKEN_TTL} cap. A logout cannot revoke an already-issued "
                "access token, and a short lifetime is the whole of the answer to that."
            )
        if self.refresh_absolute_ttl < self.refresh_token_ttl:
            raise ValueError(
                f"refresh_absolute_ttl ({self.refresh_absolute_ttl}) is shorter than "
                f"refresh_token_ttl ({self.refresh_token_ttl}), so the rolling window can "
                "never apply and every session dies at the cap."
            )
        if self.refresh_reuse_grace < timedelta(0):
            raise ValueError("refresh_reuse_grace cannot be negative; zero disables the grace.")
        return self

    @property
    def active_signing_key_arn(self) -> str:
        """The key new tokens are signed with: the first entry, by the standard's rule."""
        return self.signing_key_arns[0]

    @property
    def previous_signing_key_arns(self) -> list[str]:
        """Keys still served in the JWKS and no longer signing anything."""
        return self.signing_key_arns[1:]

    @property
    def discovery_url(self) -> str:
        """The exact URL API Gateway builds from the issuer at `CreateAuthorizer` time."""
        from webbpulse.identity.tokens import DISCOVERY_PATH

        return f"{self.issuer}{DISCOVERY_PATH}"

    @property
    def jwks_url(self) -> str:
        """The `jwks_uri` the discovery document advertises."""
        from webbpulse.identity.tokens import JWKS_PATH

        return f"{self.issuer}{JWKS_PATH}"

    def cookie_kwargs(self) -> dict[str, Any]:
        """The keyword arguments for `Response.set_cookie`, minus name and value.

        `httponly` is always `True`: it is what keeps the refresh token out of reach of a
        script on the page, so it is a control rather than a setting.
        """
        kwargs: dict[str, Any] = {
            "httponly": True,
            "secure": self.cookie_secure,
            "samesite": self.cookie_samesite,
            "path": self.cookie_path,
            "max_age": int(self.refresh_token_ttl.total_seconds()),
        }
        if self.cookie_domain:
            kwargs["domain"] = self.cookie_domain
        return kwargs
