"""`IdentitySettings`: the whole configuration surface of the identity application.

Section 6.1 of `docs/identity-standard.md` specifies the fields; this is that specification
made executable, with the validation the document describes in prose. A product builds one
of these and passes it to `build_identity_router`. It does not compose routes and it does
not subclass anything.

## A `BaseSettings`, not a plain `BaseModel`

The standard writes `IdentitySettings(BaseModel)` and this is a `BaseSettings` subclass
instead, for one reason: every other settings object in this package is one, and a product
that wants to build this from environment variables should not have to write the reading
itself. Nothing is lost by the change. A `BaseSettings` constructed with explicit keyword
arguments behaves exactly as a `BaseModel` does, which is how section 6.2's example builds
it, and the environment source is there for the product that would rather set
`IDENTITY_ISSUER` in Terraform than thread a field through a composition root.

The prefix is `IDENTITY_`, so `IDENTITY_AUDIENCE` and `IDENTITY_COOKIE_DOMAIN` do not
collide with a service's own `BaseServiceSettings` fields when both read the same
environment.

## Secrets are not fields, and that is load-bearing

There is no `google_client_secret` here, no `github_client_secret`, and above all no signing
secret. Client secrets arrive from `webbpulse.config.load_json_secret` at request time,
which is what `Domain.requires_secrets` exists for in the composition descriptor. The
signing secret does not exist at all: the private half of the signing key never leaves KMS,
which is the largest secret-management win of the whole design and would be given straight
back by a `signing_secret: str` field here.

## What is validated, and why each check is here rather than in a product

Every one of these is a failure that presents as "every request is denied" with nothing
useful in a log, which is the class of bug worth spending validation on:

- **`issuer` must be an absolute `https://` URL**, and its trailing slash is stripped. A
  trailing-slash mismatch between the `iss` claim, the discovery document and the
  authorizer's configured issuer is the classic failure of this design. Normalising once
  here means the three cannot disagree. `http://` is allowed only when `environment` is
  local or test, because a JWKS fetched over plaintext is not a trust anchor.
- **`signing_key_arns` must be non-empty**, and the first entry is the active signer. More
  than one entry is a rotation in progress (section 3.5), and the list is capped at four:
  a rotation needs two, three is a rotation caught mid-flight by another, and four means
  somebody has stopped removing old keys, which is the state where a compromised retired
  key is still trusted.
- **Cookie `samesite="none"` requires `secure`**, which browsers enforce themselves by
  rejecting the cookie outright. Catching it here turns a silently dropped cookie into a
  refused deploy.
- **`access_token_ttl` is capped at an hour.** The design's whole answer to "logout cannot
  revoke an already-issued access token" is that the token is short-lived. A product that
  sets eight hours has quietly removed that answer, and the cap is where it gets told.
- **`refresh_absolute_ttl` must be at least `refresh_token_ttl`.** An absolute cap shorter
  than the rolling window means the rolling window never applies and every session dies at
  the cap, which is confusing rather than dangerous, and cheap to reject.
- **`cookie_domain` may not be a bare public suffix**, checked only in the obvious cases:
  an empty string, a domain with no dot, and a leading dot. A cookie scoped to `com` is
  rejected by every browser and the symptom is a login that appears to work and never
  persists.

The capability flags default **on**, as section 6.1 says: the mandatory baseline is
mandatory, and the flags exist to stage a rollout and to turn a flow off in local
development rather than to let a product opt out permanently. M1 implements no flows, so in
0.9.0 the flags are carried and validated and nothing reads them yet. They are here rather
than in M2 because a product's Terraform and composition root are written once, and adding
a required field to a settings object every consumer already constructs is the change that
costs the most across the estate.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Final, Literal
from urllib.parse import urlparse

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = ["MAX_ACCESS_TOKEN_TTL", "MAX_SIGNING_KEYS", "IdentitySettings", "OAuthProvider"]

#: The providers the standard's mandatory baseline names. A `Literal` rather than a free
#: string, so a typo in a Terraform-rendered environment variable fails at construction
#: rather than producing a provider route that answers 404 in staging.
OAuthProvider = Literal["google", "github"]

#: The longest access token lifetime this settings object will accept. See the module
#: docstring: the shortness of the access token is what makes a non-revoking logout
#: tolerable, so an unbounded lifetime here quietly removes a control the threat model
#: depends on.
#: Both providers on by default. A product turns one off by setting the environment
#: variable, rather than by having to list the one it wants.
_DEFAULT_OAUTH_PROVIDERS: Final[list[OAuthProvider]] = ["google", "github"]

MAX_ACCESS_TOKEN_TTL: Final = timedelta(hours=1)

#: The most signing keys that may be listed at once. Two is a rotation; more than four is
#: a retired key that nobody removed and is still trusted.
MAX_SIGNING_KEYS: Final = 4

#: Environments where an `http://` issuer is tolerated. Anywhere else it is refused: the
#: JWKS is the trust anchor for every token in the product, and fetching it over plaintext
#: makes it whatever the network says it is.
_PLAINTEXT_ISSUER_ENVIRONMENTS: Final[frozenset[str]] = frozenset({"local", "test"})


class IdentitySettings(BaseSettings):
    """Configuration for one product's identity application.

    Built by the product's composition root, as section 6.2 of the standard shows::

        IdentitySettings(
            issuer=f"https://{s.api_host}/api/auth",
            audience="carmodpicker-api",
            signing_key_arns=s.identity_signing_key_arns,
            cookie_domain=s.registrable_domain,
            rp_id=s.registrable_domain,
            rp_name="CarModPicker",
            product_name="CarModPicker",
            support_email="support@carmodpicker.com",
            frontend_base_url="https://carmodpicker.com",
            email_from="no-reply@carmodpicker.com",
        )

    Or from the environment, where `IDENTITY_ISSUER`, `IDENTITY_AUDIENCE` and the rest are
    set by Terraform. List fields accept a JSON array; unlike `BaseServiceSettings` they do
    not accept bare CSV, because the values here (ARNs, origins) are ones where a stray
    comma should be an error rather than a silently split entry.
    """

    model_config = SettingsConfigDict(
        env_prefix="IDENTITY_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ------------------------------------------------------------------
    # Identity of the issuer
    # ------------------------------------------------------------------

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
        description=(
            "Symmetric KMS key for TOTP seed envelope encryption. Unused until M4 and "
            "optional until then."
        ),
    )

    # ------------------------------------------------------------------
    # Capabilities. All default on: the baseline is mandatory (section 6.1).
    # ------------------------------------------------------------------

    passwords_enabled: bool = True
    registration_enabled: bool = True
    email_verification_required: bool = True
    totp_enabled: bool = True
    passkeys_enabled: bool = True
    passkeys_passwordless: bool = True
    oauth_providers: list[OAuthProvider] = Field(
        default_factory=lambda: _DEFAULT_OAUTH_PROVIDERS.copy()
    )
    password_breach_check: bool = Field(
        default=False,
        description=(
            "Check new passwords against a breach corpus (section 5.2). Off by default: the "
            "2026-09-09 decision was no breach corpus check, so a product opts in explicitly."
        ),
    )
    mfa_required_for_roles: list[str] = Field(default_factory=list)

    # ------------------------------------------------------------------
    # Lifetimes
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Refresh cookie
    # ------------------------------------------------------------------

    cookie_name: str = Field(default="wp_refresh")
    cookie_domain: str = Field(
        default="",
        description=(
            "The registrable domain, so `www.` and the API host share the cookie. Empty "
            "makes it a host-only cookie, which is correct locally."
        ),
    )
    cookie_path: str = Field(
        default="/api/auth",
        description="Scoped so no other domain's function ever receives the refresh cookie.",
    )
    cookie_samesite: Literal["lax", "strict", "none"] = Field(default="lax")
    cookie_secure: bool = Field(default=True)

    # ------------------------------------------------------------------
    # WebAuthn
    # ------------------------------------------------------------------

    rp_id: str = Field(
        default="",
        description=(
            "The WebAuthn Relying Party ID, normally the registrable domain. Hashed into "
            "every credential and immutable for that credential's life."
        ),
    )
    rp_name: str = Field(default="")
    webauthn_origins: list[str] = Field(default_factory=list)

    # ------------------------------------------------------------------
    # Email and branding
    # ------------------------------------------------------------------

    email_from: str = Field(default="")
    ses_configuration_set: str | None = Field(default=None)
    frontend_base_url: str = Field(default="")
    product_name: str = Field(default="")
    support_email: str = Field(default="")
    logo_url: str | None = Field(default=None)

    # ------------------------------------------------------------------
    # OAuth client ids. Secrets come from the app secret, never from here.
    # ------------------------------------------------------------------

    google_client_id: str = Field(default="")
    github_client_id: str = Field(default="")

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @field_validator("issuer", "frontend_base_url", mode="before")
    @classmethod
    def _strip_trailing_slash(cls, value: object) -> object:
        """Normalise once, so `iss`, the discovery document and the authorizer agree.

        `rstrip` rather than removing a single character: `https://host//` is as wrong as
        `https://host/`, and both normalise to the same string here.
        """
        return value.rstrip("/") if isinstance(value, str) else value

    @model_validator(mode="after")
    def _check_issuer_scheme(self) -> IdentitySettings:
        parsed = urlparse(self.issuer)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(
                f"issuer must be an absolute http(s) URL, got {self.issuer!r}. API Gateway "
                "builds the discovery URL by appending "
                "'/.well-known/openid-configuration' to it."
            )
        if parsed.scheme == "http" and self.environment.strip().lower() not in (
            _PLAINTEXT_ISSUER_ENVIRONMENTS
        ):
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
    def _check_cookie(self) -> IdentitySettings:
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

    # ------------------------------------------------------------------
    # Derived values
    # ------------------------------------------------------------------

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

        Here rather than in the session router M2 adds, because the attributes are a
        security control rather than a flow detail: `httponly` is what keeps the refresh
        token out of reach of a script on the page, and it is not a setting because there
        is no correct value other than `True`.
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
