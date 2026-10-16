"""Per-tenant single sign-on: connections, the login resolver, and the SSO service.

Protocol-neutral: OIDC and SAML connections share one state table, one link table and one
session issuance. The OIDC leg lives in `sso_oidc.py`, the SAML leg in `sso_saml.py` and the
routes in `sso_routes.py`. Synchronous and free of FastAPI, and importable without the `sso`
or `saml` extras.
"""

from __future__ import annotations

import logging
import re
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final, Literal, Protocol
from urllib.parse import urlsplit

from webbpulse.dynamodb import now_iso, ttl_in
from webbpulse.identity.oauth import (
    OAUTH_STATE_TTL_SECONDS,
    OAuthLinkRecord,
    OAuthRejected,
    OAuthStateRecord,
    _b64url,
    new_pkce_verifier,
    pkce_challenge,
    provider_account_key,
)
from webbpulse.identity.storage import constant_time_equals

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Mapping, Sequence

    from webbpulse.identity.crypto import SealedSecret, TotpCipher
    from webbpulse.identity.hooks import IdentityHooks
    from webbpulse.identity.oauth import HttpClient, OAuthLinkStore, OAuthStateStore
    from webbpulse.identity.settings import IdentitySettings
    from webbpulse.identity.sso_oidc import OidcSsoClient, UrlGuard
    from webbpulse.identity.sso_saml import SamlSsoClient

__all__ = [
    "AMR_SSO",
    "SAML_DEFAULT_EMAIL_ATTRIBUTES",
    "SAML_DEFAULT_NAME_ATTRIBUTES",
    "SSO_CONNECTION_AMR_PREFIX",
    "SSO_CONNECTION_CLAIM",
    "SSO_LINK_PROVIDER_PREFIX",
    "SSO_PROTOCOL_OIDC",
    "SSO_PROTOCOL_SAML",
    "AssertionReplayStore",
    "OidcConnectionConfig",
    "SamlConnectionConfig",
    "SsoAuthorization",
    "SsoConnection",
    "SsoHooks",
    "SsoIdentity",
    "SsoLoginOutcome",
    "SsoProtocol",
    "SsoRejected",
    "SsoService",
    "sso_connection_from_amr",
    "sso_link_provider",
    "sso_session_amr",
    "strip_sso_markers",
    "valid_connection_id",
]

_log = logging.getLogger(__name__)

AMR_SSO: Final = "sso"
"""The `amr` value every single sign-on session carries, beside its protocol."""

SSO_PROTOCOL_OIDC: Final = "oidc"
SSO_PROTOCOL_SAML: Final = "saml"

type SsoProtocol = Literal["oidc", "saml"]

type SsoLoginOutcome = Literal["linked", "auto_linked", "provisioned"]

SSO_CONNECTION_AMR_PREFIX: Final = "sso_conn:"
"""Marks the connection inside a session family's stored `amr`.

Riding in the stored `amr` means refresh, step-up, the MFA ticket and the desktop handoff
carry the connection with no change of their own. `access_token_amr` drops it, and
`IdentityFlows` emits it as `SSO_CONNECTION_CLAIM` instead.
"""

SSO_CONNECTION_CLAIM: Final = "sso_connection"
"""The access token claim naming the connection a single sign-on session came through."""

SSO_LINK_PROVIDER_PREFIX: Final = "sso:"
"""The `oauth-links` and `oauth-states` provider for a connection: `sso:<connection_id>`."""

_CONNECTION_ID_PATTERN: Final = re.compile(r"[A-Za-z0-9_-]{1,64}")


def valid_connection_id(connection_id: str) -> bool:
    """Whether a connection id is safe in a URL path, a link key and an `amr` marker."""
    return bool(_CONNECTION_ID_PATTERN.fullmatch(connection_id))


def sso_link_provider(connection_id: str) -> str:
    """The provider name a connection's links and states are stored under."""
    return f"{SSO_LINK_PROVIDER_PREFIX}{connection_id}"


def sso_session_amr(protocol: str, connection_id: str) -> tuple[str, ...]:
    """The stored `amr` of a single sign-on session: `sso`, the protocol, the connection marker."""
    return (AMR_SSO, protocol, f"{SSO_CONNECTION_AMR_PREFIX}{connection_id}")


def sso_connection_from_amr(amr: Sequence[str]) -> str:
    """The connection id a stored `amr` names, or an empty string for a non-SSO session."""
    for method in amr:
        if method.startswith(SSO_CONNECTION_AMR_PREFIX):
            return method[len(SSO_CONNECTION_AMR_PREFIX) :]
    return ""


def strip_sso_markers(amr: Sequence[str]) -> tuple[str, ...]:
    """The `amr` with every connection marker removed, which is what a token may show."""
    return tuple(method for method in amr if not method.startswith(SSO_CONNECTION_AMR_PREFIX))


class SsoRejected(OAuthRejected):
    """A single sign-on start or callback was refused.

    A subclass of `OAuthRejected`, so every renderer of that refusal renders this one too.
    """

    def __init__(self, message: str, *, error_code: str = "SSO_FAILED", status_code: int = 400) -> None:
        """Record the refusal message, its error code and the status to answer with."""
        super().__init__(message, error_code=error_code, status_code=status_code)


@dataclass(frozen=True, slots=True)
class OidcConnectionConfig:
    """What an OIDC connection needs of its identity provider.

    The client secret is only ever held sealed. `seal_oidc_client_secret` in `sso_oidc.py`
    seals one, bound to the connection id, so a sealed value cannot move between connections.
    """

    issuer: str
    client_id: str
    sealed_client_secret: SealedSecret
    scopes: tuple[str, ...] = ("openid", "email", "profile")
    token_endpoint_auth_method: Literal["client_secret_basic", "client_secret_post"] = "client_secret_basic"
    extra_authorize_params: Mapping[str, str] = field(default_factory=dict)


SAML_DEFAULT_EMAIL_ATTRIBUTES: Final[tuple[str, ...]] = (
    "email",
    "mail",
    "emailAddress",
    "urn:oid:0.9.2342.19200300.100.1.3",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
)

SAML_DEFAULT_NAME_ATTRIBUTES: Final[tuple[str, ...]] = (
    "name",
    "displayName",
    "urn:oid:2.16.840.1.113730.3.1.241",
    "http://schemas.microsoft.com/identity/claims/displayname",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
)


@dataclass(frozen=True, slots=True)
class SamlConnectionConfig:
    """What a SAML connection needs of its identity provider.

    `idp_certificates` are the PEM or bare base64 signing certificates; more than one lets a
    tenant rotate without downtime. `sp_entity_id` defaults to the connection's metadata URL.
    `subject_attribute` names an attribute to use as the durable subject instead of the
    NameID, which a transient NameID requires. `parse_saml_idp_metadata` in `sso_saml.py`
    builds one from the provider's metadata.
    """

    idp_entity_id: str
    idp_sso_url: str
    idp_certificates: tuple[str, ...]
    sp_entity_id: str = ""
    name_id_format: str = ""
    subject_attribute: str = ""
    email_attributes: tuple[str, ...] = SAML_DEFAULT_EMAIL_ATTRIBUTES
    name_attributes: tuple[str, ...] = SAML_DEFAULT_NAME_ATTRIBUTES


class AssertionReplayStore(Protocol):
    """The one-shot claim that stops a SAML assertion being used twice.

    `webbpulse.dynamodb.IdempotencyStore` and `webbpulse.testing.FakeIdempotencyStore` both
    satisfy it, so this module never imports the `dynamodb` extra.
    """

    def claim(self, key: str, ttl_seconds: float) -> bool:
        """Claim `key` for `ttl_seconds`, answering whether this caller won."""
        ...


@dataclass(frozen=True, slots=True)
class SsoConnection:
    """One tenant's identity provider connection, loaded through `SsoHooks`.

    `verified_domains` are the domains the tenant has proven it owns with
    `webbpulse.identity.domain_verification`. Only an address on one of them is trusted, so it
    alone decides whether a sign-in may attach to or create an account.
    """

    connection_id: str
    tenant_id: str
    protocol: SsoProtocol
    verified_domains: tuple[str, ...] = ()
    enabled: bool = True
    jit_provisioning: bool = True
    display_name: str = ""
    oidc: OidcConnectionConfig | None = None
    saml: SamlConnectionConfig | None = None

    def trusts_email(self, email: str) -> bool:
        """Whether an address the provider asserted is on one of this tenant's verified domains."""
        _, at, domain = email.strip().lower().rpartition("@")
        if not at or not domain:
            return False
        return domain.rstrip(".") in {item.strip().lower().rstrip(".") for item in self.verified_domains}


@dataclass(frozen=True, slots=True)
class SsoIdentity:
    """What the identity provider asserted about the person who just signed in.

    Protocol-neutral: an OIDC ID token and a SAML assertion both reduce to this. `attributes`
    holds the raw verified claims or assertion attributes, for a product's JIT role mapping.
    """

    connection_id: str
    protocol: SsoProtocol
    subject: str
    email: str
    email_verified: bool = False
    name: str = ""
    attributes: Mapping[str, Any] = field(default_factory=dict)

    @property
    def account_key(self) -> str:
        """The `oauth-links` key for this identity: `sso:<connection_id>#<subject>`."""
        return provider_account_key(sso_link_provider(self.connection_id), self.subject)


@dataclass(frozen=True, slots=True)
class SsoAuthorization:
    """The redirect a `start` produces, the state it wrote, and the connection it chose."""

    authorization_url: str
    state: str
    connection_id: str
    protocol: SsoProtocol = "oidc"


class SsoHooks(ABC):
    """What a product supplies for single sign-on: where connections live and what a login means.

    Kept apart from `IdentityHooks`, so a product without SSO implements nothing new.
    """

    @abstractmethod
    def load_connection(self, connection_id: str) -> SsoConnection | None:
        """The connection with this id, or `None`."""

    def find_connection(self, *, email: str = "", tenant_hint: str = "") -> SsoConnection | None:
        """The connection a sign-in should use, from an email address or a tenant slug.

        The default finds none, which makes the start route answer 404 for every lookup.
        """
        return None

    def on_sso_login(
        self,
        user: Mapping[str, Any],
        connection: SsoConnection,
        identity: SsoIdentity,
        *,
        outcome: SsoLoginOutcome,
    ) -> None:
        """Run after the account is resolved and before tokens are issued.

        Where a product adds tenant membership or maps roles from `identity.attributes`. Raise
        `SsoRejected` to refuse the sign-in. The default does nothing.
        """
        return None


class SsoService:
    """Single sign-on start, callback and login resolution, with no FastAPI in sight.

    Built once per execution environment. Client secrets are opened from their sealed form
    only for the token exchange and are never logged or kept.
    """

    def __init__(
        self,
        settings: IdentitySettings,
        hooks: IdentityHooks,
        sso_hooks: SsoHooks,
        *,
        states: OAuthStateStore,
        links: OAuthLinkStore,
        cipher: TotpCipher,
        http_client: HttpClient | None = None,
        url_guard: UrlGuard | None = None,
        oidc_client: OidcSsoClient | None = None,
        saml_replay: AssertionReplayStore | None = None,
        saml_client: SamlSsoClient | None = None,
    ) -> None:
        """Hold the settings, both hook surfaces, the stores, the cipher and the protocol clients.

        `url_guard` checks every provider URL this service fetches; the default refuses
        anything but HTTPS to a public address. SAML is enabled by `saml_replay`, the store
        that remembers spent assertion ids, or by a ready `saml_client`; it needs the `saml`
        extra only when a response is verified.
        """
        self._settings = settings
        self._hooks = hooks
        self._sso_hooks = sso_hooks
        self._states = states
        self._links = links
        if oidc_client is None:
            from webbpulse.identity.sso_oidc import OidcSsoClient as _OidcSsoClient

            oidc_client = _OidcSsoClient(
                cipher=cipher,
                http_client=http_client,
                url_guard=url_guard,
                leeway=settings.clock_skew_leeway,
            )
        self._oidc = oidc_client
        if saml_client is None and saml_replay is not None:
            from webbpulse.identity.sso_saml import SamlSsoClient as _SamlSsoClient

            saml_client = _SamlSsoClient(replay=saml_replay, leeway=settings.clock_skew_leeway)
        self._saml = saml_client

    @property
    def saml_enabled(self) -> bool:
        """Whether this service verifies SAML responses, which mounts the SAML routes."""
        return self._saml is not None

    def callback_url(self, connection: SsoConnection) -> str:
        """The redirect URI registered with the provider: one per connection and protocol.

        For SAML it is the assertion consumer service URL.
        """
        if connection.protocol == SSO_PROTOCOL_SAML:
            return self.acs_url(connection)
        return f"{self._settings.issuer}/sso/{connection.protocol}/{connection.connection_id}/callback"

    def acs_url(self, connection: SsoConnection) -> str:
        """The SAML assertion consumer service URL, which takes the HTTP-POST binding."""
        return f"{self._settings.issuer}/sso/saml/{connection.connection_id}/acs"

    def saml_metadata_url(self, connection: SsoConnection) -> str:
        """Where the connection's SAML service provider metadata is served."""
        return f"{self._settings.issuer}/sso/saml/{connection.connection_id}/metadata"

    def sp_entity_id(self, connection: SsoConnection) -> str:
        """The service provider entity id: the configured one, or the metadata URL."""
        if connection.saml is not None and connection.saml.sp_entity_id:
            return connection.saml.sp_entity_id
        return self.saml_metadata_url(connection)

    def connection(self, connection_id: str) -> SsoConnection:
        """An enabled connection by id, refusing an unknown, malformed or disabled one alike."""
        found = self._sso_hooks.load_connection(connection_id) if valid_connection_id(connection_id) else None
        return self._require_usable(found)

    def _require_usable(self, connection: SsoConnection | None) -> SsoConnection:
        """The connection when it can sign someone in, or the one not-found refusal."""
        if connection is None or not connection.enabled or not valid_connection_id(connection.connection_id):
            raise SsoRejected(
                "Single sign-on is not set up for that account.",
                error_code="SSO_CONNECTION_NOT_FOUND",
                status_code=404,
            )
        return connection

    def start(
        self,
        *,
        email: str = "",
        tenant_hint: str = "",
        connection_id: str = "",
        return_to: str = "",
        binding: str = "",
    ) -> SsoAuthorization:
        """Choose the connection, write a state, and build the URL to send the browser to.

        The connection comes from `connection_id` when given, and otherwise from the
        product's `find_connection` for the email or tenant slug. `binding` is the digest
        from `new_link_binding`, tying the state to the browser that started it.
        """
        if connection_id:
            connection = self.connection(connection_id)
        else:
            connection = self._require_usable(
                self._sso_hooks.find_connection(email=email.strip().lower(), tenant_hint=tenant_hint.strip())
            )

        if connection.protocol == SSO_PROTOCOL_SAML:
            return self._start_saml(connection, return_to=return_to, binding=binding)
        if connection.protocol != SSO_PROTOCOL_OIDC or connection.oidc is None:
            raise _unsupported()

        state = _b64url(secrets.token_bytes(32))
        verifier = new_pkce_verifier()
        nonce = _b64url(secrets.token_bytes(16))
        redirect_uri = self.callback_url(connection)
        authorization_url = self._oidc.authorization_url(
            connection,
            redirect_uri=redirect_uri,
            state=state,
            nonce=nonce,
            code_challenge=pkce_challenge(verifier),
            login_hint=email.strip(),
        )

        self._states.put(
            OAuthStateRecord(
                state=state,
                provider=sso_link_provider(connection.connection_id),
                mode="login",
                created_at=now_iso(),
                expires_at=ttl_in(OAUTH_STATE_TTL_SECONDS),
                pkce_verifier=verifier,
                nonce=nonce,
                return_to=_resolve_return_to(self._settings.frontend_base_url, return_to),
                redirect_uri=redirect_uri,
                binding=binding,
            )
        )
        _log.info(
            "SSO authorization started.",
            extra={
                "event": "sso.start",
                "connection_id": connection.connection_id,
                "tenant_id": connection.tenant_id,
                "protocol": connection.protocol,
            },
        )
        return SsoAuthorization(
            authorization_url=authorization_url,
            state=state,
            connection_id=connection.connection_id,
        )

    def _start_saml(self, connection: SsoConnection, *, return_to: str, binding: str) -> SsoAuthorization:
        """Write a state holding a fresh AuthnRequest id, and build the HTTP-Redirect URL.

        The state rides back as `RelayState`; the request id is stored in the state's `nonce`
        and must come back as the response's `InResponseTo`.
        """
        saml = self._require_saml(connection)
        state = _b64url(secrets.token_bytes(32))
        request_id = f"_{secrets.token_hex(20)}"
        acs = self.acs_url(connection)
        authorization_url = saml.authn_request_url(
            connection,
            request_id=request_id,
            acs_url=acs,
            sp_entity_id=self.sp_entity_id(connection),
            relay_state=state,
        )
        self._states.put(
            OAuthStateRecord(
                state=state,
                provider=sso_link_provider(connection.connection_id),
                mode="login",
                created_at=now_iso(),
                expires_at=ttl_in(OAUTH_STATE_TTL_SECONDS),
                nonce=request_id,
                return_to=_resolve_return_to(self._settings.frontend_base_url, return_to),
                redirect_uri=acs,
                binding=binding,
            )
        )
        _log.info(
            "SSO authorization started.",
            extra={
                "event": "sso.start",
                "connection_id": connection.connection_id,
                "tenant_id": connection.tenant_id,
                "protocol": connection.protocol,
            },
        )
        return SsoAuthorization(
            authorization_url=authorization_url,
            state=state,
            connection_id=connection.connection_id,
            protocol=SSO_PROTOCOL_SAML,
        )

    def _require_saml(self, connection: SsoConnection) -> SamlSsoClient:
        """The SAML client, when this service has one and the connection is configured."""
        if self._saml is None or connection.protocol != SSO_PROTOCOL_SAML or connection.saml is None:
            raise _unsupported()
        return self._saml

    def saml_metadata(self, connection: SsoConnection) -> str:
        """The connection's SAML service provider metadata document."""
        return self._require_saml(connection).sp_metadata(
            connection,
            sp_entity_id=self.sp_entity_id(connection),
            acs_url=self.acs_url(connection),
        )

    def identity_from_saml_response(
        self,
        connection: SsoConnection,
        *,
        saml_response: str,
        state_record: OAuthStateRecord,
    ) -> SsoIdentity:
        """Verify a posted `SAMLResponse` against the spent state, returning what it asserted."""
        return self._require_saml(connection).identity_from_response(
            connection,
            saml_response=saml_response,
            request_id=state_record.nonce,
            acs_url=state_record.redirect_uri or self.acs_url(connection),
            sp_entity_id=self.sp_entity_id(connection),
        )

    def consume_state(self, state: str, *, connection_id: str) -> OAuthStateRecord:
        """Spend a state exactly once, refusing one that belongs to another connection.

        The check stops a state minted for one tenant's provider from finishing at another
        tenant's callback. Every failure answers identically.
        """
        record = self._states.consume(state) if state else None
        if record is None or not constant_time_equals(record.provider, sso_link_provider(connection_id)):
            raise SsoRejected(
                "That sign-in attempt is no longer valid. Start again.",
                error_code="SSO_STATE_INVALID",
            )
        return record

    def identity_from_oidc_callback(
        self,
        connection: SsoConnection,
        *,
        code: str,
        issuer: str,
        state_record: OAuthStateRecord,
    ) -> SsoIdentity:
        """Exchange the code and verify the ID token, returning what the provider asserted.

        `issuer` is the callback's RFC 9207 `iss` parameter, or an empty string when the
        provider sent none.
        """
        if connection.oidc is None:
            raise _unsupported()
        return self._oidc.identity_from_callback(
            connection,
            code=code,
            issuer=issuer,
            redirect_uri=state_record.redirect_uri,
            code_verifier=state_record.pkce_verifier,
            nonce=state_record.nonce,
        )

    def resolve_login(
        self, connection: SsoConnection, identity: SsoIdentity
    ) -> tuple[Mapping[str, Any], SsoLoginOutcome]:
        """Turn a verified identity into a local user, then let the product act on it.

        The durable link is `(connection, subject)`, never the email. A first sign-in may
        attach to an existing account or provision one only for an address on a verified
        domain. `on_sso_login` runs last and may refuse.
        """
        if identity.connection_id != connection.connection_id:
            raise SsoRejected(
                "That sign-in could not be completed. Try again.",
                error_code="SSO_CONNECTION_MISMATCH",
            )

        user, outcome = self._resolve_user(connection, identity)
        self._sso_hooks.on_sso_login(user, connection, identity, outcome=outcome)
        _log.info(
            "SSO sign-in resolved.",
            extra={
                "event": "sso.login",
                "connection_id": connection.connection_id,
                "tenant_id": connection.tenant_id,
                "user_id": _user_id(user),
                "outcome": outcome,
            },
        )
        return user, outcome

    def _resolve_user(
        self, connection: SsoConnection, identity: SsoIdentity
    ) -> tuple[Mapping[str, Any], SsoLoginOutcome]:
        """Find the user by link, by verified-domain email, or provision one."""
        existing = self._links.get(identity.account_key)
        if existing is not None:
            user = self._hooks.load_user_by_id(existing.user_id)
            if user is None:
                self._links.delete(identity.account_key)
                raise SsoRejected(
                    "That account is no longer available.",
                    error_code="SSO_ACCOUNT_MISSING",
                    status_code=401,
                )
            self._touch(existing, identity)
            return user, "linked"

        if not identity.email:
            raise SsoRejected(
                "Your identity provider did not share an email address. Ask your administrator to release it.",
                error_code="SSO_EMAIL_MISSING",
            )
        if not connection.trusts_email(identity.email):
            _log.warning(
                "SSO sign-in refused: the address is not on a verified domain.",
                extra={"event": "sso.domain_unverified", "connection_id": connection.connection_id},
            )
            raise SsoRejected(
                "Your email address is not on a domain this organisation has verified.",
                error_code="SSO_DOMAIN_NOT_VERIFIED",
                status_code=403,
            )

        matched = self._hooks.load_user_by_email(identity.email)
        if matched is not None:
            if not bool(matched.get("email_verified", False)):
                raise SsoRejected(
                    "An account already exists for that email address. Sign in to it and verify "
                    "the address first, then use single sign-on.",
                    error_code="SSO_EMAIL_UNVERIFIED",
                    status_code=409,
                )
            self._claim(identity, _user_id(matched))
            return matched, "auto_linked"

        if not connection.jit_provisioning:
            raise SsoRejected(
                "Your organisation has not given you an account yet. Ask your administrator for an invite.",
                error_code="SSO_PROVISIONING_DISABLED",
                status_code=403,
            )
        user = self._hooks.create_user(
            email=identity.email,
            attributes={"email_verified": True, "name": identity.name},
        )
        self._claim(identity, _user_id(user))
        self._hooks.on_user_created(user, AMR_SSO)
        return user, "provisioned"

    def _claim(self, identity: SsoIdentity, user_id: str) -> None:
        """Write the link for a first sign-in, refusing when another one won the race."""
        moment = now_iso()
        record = OAuthLinkRecord(
            provider_subject=identity.account_key,
            provider=sso_link_provider(identity.connection_id),
            subject=identity.subject,
            user_id=user_id,
            linked_at=moment,
            provider_email=identity.email,
            provider_email_verified=True,
            last_login_at=moment,
        )
        if not self._links.claim(record):
            raise SsoRejected(
                "That identity is already linked to another account.",
                error_code="SSO_ALREADY_LINKED",
                status_code=409,
            )

    def _touch(self, record: OAuthLinkRecord, identity: SsoIdentity) -> None:
        """Record this sign-in on the link. Best effort, so a write failure never fails it."""
        try:
            self._links.put(
                OAuthLinkRecord(
                    provider_subject=record.provider_subject,
                    provider=record.provider,
                    subject=record.subject,
                    user_id=record.user_id,
                    linked_at=record.linked_at,
                    provider_email=identity.email or record.provider_email,
                    provider_email_verified=record.provider_email_verified,
                    last_login_at=now_iso(),
                    provider_login=record.provider_login,
                )
            )
        except Exception:
            _log.warning(
                "Could not record an SSO sign-in on its link.",
                extra={"event": "sso.touch_failed", "connection_id": identity.connection_id},
            )


def _unsupported() -> SsoRejected:
    """The refusal for a connection whose protocol this deployment cannot run."""
    return SsoRejected(
        "That single sign-on connection is not available.",
        error_code="SSO_PROTOCOL_UNSUPPORTED",
        status_code=501,
    )


def _resolve_return_to(base: str, requested: str) -> str:
    """Where the frontend is sent after the callback, constrained to the frontend's origin."""
    if not requested:
        return base
    if requested.startswith("/") and not requested.startswith("//"):
        return f"{base}{requested}"
    if base:
        base_parts = urlsplit(base)
        parts = urlsplit(requested)
        if (parts.scheme, parts.netloc) == (base_parts.scheme, base_parts.netloc):
            return requested
    return base


def _user_id(user: Mapping[str, Any]) -> str:
    """The immutable id from a product's user mapping."""
    value = user.get("id") or user.get("user_id") or ""
    if not value:
        raise SsoRejected(
            "The product's user record has no id, so no token can be minted for it.",
            error_code="USER_ID_MISSING",
            status_code=500,
        )
    return str(value)
