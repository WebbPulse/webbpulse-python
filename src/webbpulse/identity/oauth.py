"""OAuth sign-in and account linking: providers, the state store, and the link service.

Synchronous and free of FastAPI; the routes live in `oauth_routes.py`. Auto-link attaches an
identity to an existing account only when both emails are verified.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final, Literal, Protocol
from urllib.parse import urlencode, urlsplit

from webbpulse.dynamodb import now_iso, ttl_in
from webbpulse.identity.storage import constant_time_equals, is_expired

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Mapping

    from webbpulse.dynamodb import Repository
    from webbpulse.identity.hooks import IdentityHooks
    from webbpulse.identity.settings import IdentitySettings
    from webbpulse.identity.storage import CredentialStore

__all__ = [
    "GITHUB_PROVIDER",
    "GOOGLE_PROVIDER",
    "OAUTH_LINKS_TABLE",
    "OAUTH_LINK_USER_INDEX",
    "OAUTH_STATES_TABLE",
    "OAUTH_STATE_TTL_SECONDS",
    "PROVIDERS",
    "DynamoOAuthLinkStore",
    "DynamoOAuthStateStore",
    "HttpClient",
    "HttpResponse",
    "HttpxClient",
    "InMemoryOAuthLinkStore",
    "InMemoryOAuthStateStore",
    "OAuthAuthorization",
    "OAuthIdentity",
    "OAuthLinkRecord",
    "OAuthLinkStore",
    "OAuthMode",
    "OAuthProviderConfig",
    "OAuthRejected",
    "OAuthService",
    "OAuthStateRecord",
    "OAuthStateStore",
    "provider_account_key",
]

_log = logging.getLogger(__name__)

OAUTH_STATES_TABLE: Final = "oauth-states"
OAUTH_LINKS_TABLE: Final = "oauth-links"

OAUTH_LINK_USER_INDEX: Final = "user_id-index"

OAUTH_STATE_TTL_SECONDS: Final = 600

GOOGLE_PROVIDER: Final = "google"
GITHUB_PROVIDER: Final = "github"

type OAuthMode = Literal["login", "link"]

AMR_OAUTH: Final = "oauth"


class OAuthRejected(Exception):
    """An OAuth start, callback, link or unlink was refused.

    Same shape as `LoginRejected` and `MfaRejected` so the router renders all three alike.
    """

    def __init__(
        self,
        message: str,
        *,
        error_code: str = "OAUTH_FAILED",
        status_code: int = 400,
    ) -> None:
        """Record the refusal message, its error code and the status to answer with."""
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """Just enough of a response for this module: the status and the parsed JSON body.

    Deliberately not a wrapper around `httpx.Response`, so a test can build one directly.
    """

    status_code: int
    json_body: Any

    @property
    def ok(self) -> bool:
        """Whether the status is a 2xx."""
        return 200 <= self.status_code < 300


class HttpClient(Protocol):
    """The two calls this module makes against a provider.

    A Protocol, so `HttpxClient` and a test double satisfy it without inheritance.
    """

    def post_form(
        self, url: str, *, data: Mapping[str, str], headers: Mapping[str, str]
    ) -> HttpResponse:
        """Post an `application/x-www-form-urlencoded` body. The token exchange."""
        ...

    def get_json(self, url: str, *, headers: Mapping[str, str]) -> HttpResponse:
        """Fetch a JSON document. Userinfo, the GitHub emails list, and a JWKS."""
        ...


class HttpxClient:
    """`HttpClient` over `httpx`, built once and reused.

    Sets an explicit timeout on every call, and builds the client lazily so importing this
    module needs no `httpx`.
    """

    def __init__(self, *, timeout: float = 10.0, client: Any = None) -> None:
        """Hold the per-call timeout, and an already-built client when one is supplied."""
        self._timeout = timeout
        self._client = client

    def _require(self) -> Any:
        """Build the `httpx` client on first use, and return it thereafter."""
        if self._client is None:
            import httpx

            self._client = httpx.Client(timeout=self._timeout, follow_redirects=False)
        return self._client

    def post_form(
        self, url: str, *, data: Mapping[str, str], headers: Mapping[str, str]
    ) -> HttpResponse:
        """Post an `application/x-www-form-urlencoded` body."""
        response = self._require().post(url, data=dict(data), headers=dict(headers))
        return _response_from(response)

    def get_json(self, url: str, *, headers: Mapping[str, str]) -> HttpResponse:
        """Fetch a JSON document."""
        response = self._require().get(url, headers=dict(headers))
        return _response_from(response)


def _response_from(response: Any) -> HttpResponse:
    """Read a client library's response into this module's own shape.

    A body that is not JSON becomes `None` rather than raising.
    """
    try:
        body = response.json()
    except Exception:
        body = None
    return HttpResponse(status_code=int(response.status_code), json_body=body)


@dataclass(frozen=True, slots=True)
class OAuthProviderConfig:
    """Everything that differs between one provider and the next, in one place.

    A table rather than a branch per step, so a third provider is a new entry.
    """

    name: str
    authorize_url: str
    token_url: str
    display_name: str = ""
    userinfo_url: str = ""
    emails_url: str = ""
    jwks_url: str = ""
    id_token_issuers: tuple[str, ...] = ()
    scope: str = ""
    supports_pkce: bool = False
    returns_id_token: bool = False
    extra_authorize_params: Mapping[str, str] = field(default_factory=dict)


PROVIDERS: Final[Mapping[str, OAuthProviderConfig]] = {
    GOOGLE_PROVIDER: OAuthProviderConfig(
        name=GOOGLE_PROVIDER,
        display_name="Google",
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        jwks_url="https://www.googleapis.com/oauth2/v3/certs",
        id_token_issuers=("https://accounts.google.com", "accounts.google.com"),
        scope="openid email profile",
        supports_pkce=True,
        returns_id_token=True,
        extra_authorize_params={"prompt": "select_account"},
    ),
    GITHUB_PROVIDER: OAuthProviderConfig(
        name=GITHUB_PROVIDER,
        display_name="GitHub",
        authorize_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",
        userinfo_url="https://api.github.com/user",
        emails_url="https://api.github.com/user/emails",
        scope="read:user user:email",
        supports_pkce=False,
        returns_id_token=False,
    ),
}


def provider_account_key(provider: str, subject: str) -> str:
    """The `oauth-links` partition key: `"<provider>#<subject>"`.

    The provider is part of the key because a subject is only unique within its provider.
    """
    return f"{provider}#{subject}"


@dataclass(frozen=True, slots=True)
class OAuthStateRecord:
    """One in-flight authorization, written before the redirect and spent by the callback.

    Holds the PKCE verifier and the nonce, which never reach the browser. `return_to` is
    validated against the allow-list when it is stored, so a stored row is safe to use.
    """

    state: str
    provider: str
    mode: OAuthMode
    created_at: str
    expires_at: int
    pkce_verifier: str = ""
    nonce: str = ""
    return_to: str = ""
    user_id: str = ""
    redirect_uri: str = ""


@dataclass(frozen=True, slots=True)
class OAuthLinkRecord:
    """One provider identity attached to one local user.

    No provider tokens are stored: a provider is consumed as an identity source only.
    """

    provider_subject: str
    provider: str
    subject: str
    user_id: str
    linked_at: str
    provider_email: str = ""
    provider_email_verified: bool = False
    last_login_at: str = ""


@dataclass(frozen=True, slots=True)
class OAuthIdentity:
    """What a provider said about the person who just authenticated.

    Normalised across providers. `email_verified` is `False` unless the provider positively
    asserted otherwise, and the auto-link decision turns on it.
    """

    provider: str
    subject: str
    email: str
    email_verified: bool
    name: str = ""

    @property
    def account_key(self) -> str:
        """The `oauth-links` partition key for this identity."""
        return provider_account_key(self.provider, self.subject)


@dataclass(frozen=True, slots=True)
class OAuthAuthorization:
    """The redirect a `start` produces: where to send the browser, and the state it spent."""

    authorization_url: str
    state: str


class OAuthStateStore(ABC):
    """The `oauth-states` table: hash `state`, TTL `expires_at`, ten minutes.

    Single use is enforced by `consume`, which must be one conditional operation.
    """

    @abstractmethod
    def put(self, record: OAuthStateRecord) -> None:
        """Write a fresh state. Called once, immediately before the redirect."""

    @abstractmethod
    def consume(self, state: str) -> OAuthStateRecord | None:
        """Atomically spend a state and return it, or `None` if unknown or expired.

        Expiry is checked here as well as by the table TTL, which is storage reclamation
        rather than an access control.
        """


class OAuthLinkStore(ABC):
    """The `oauth-links` table: hash `provider_subject`, GSI `user_id-index`, no TTL ever.

    Never a TTL: a sign-in method that expires on a schedule locks a user out.
    """

    @abstractmethod
    def get(self, provider_subject: str) -> OAuthLinkRecord | None:
        """The link for a `"<provider>#<subject>"` key, or `None`.

        Must be a strongly consistent read of the base table, since it gates a sign-in.
        """

    @abstractmethod
    def put(self, record: OAuthLinkRecord) -> None:
        """Write or replace a link."""

    @abstractmethod
    def list_for_user(self, user_id: str) -> list[OAuthLinkRecord]:
        """Every link for a user. Backed by the GSI, so it may be slightly stale."""

    @abstractmethod
    def delete(self, provider_subject: str) -> None:
        """Remove a link. Idempotent: removing an absent one is not an error."""

    @abstractmethod
    def claim(self, record: OAuthLinkRecord) -> bool:
        """Write a link only if that provider identity is not already attached to somebody.

        The condition is the security control: two concurrent callbacks for one identity
        must not both succeed. Returns `False` when the key already exists.
        """


class InMemoryOAuthStateStore(OAuthStateStore):
    """Dict-backed `OAuthStateStore`, with the same single-use and expiry semantics."""

    def __init__(self) -> None:
        """Start with an empty state table."""
        self._items: dict[str, OAuthStateRecord] = {}

    def put(self, record: OAuthStateRecord) -> None:
        """Write a fresh state."""
        self._items[record.state] = record

    def consume(self, state: str) -> OAuthStateRecord | None:
        """Spend a state, returning `None` when it is unknown or expired."""
        record = self._items.pop(state, None)
        if record is None or is_expired(record.expires_at):
            return None
        return record


class InMemoryOAuthLinkStore(OAuthLinkStore):
    """Dict-backed `OAuthLinkStore`, keyed as the table is."""

    def __init__(self) -> None:
        """Start with an empty link table."""
        self._items: dict[str, OAuthLinkRecord] = {}

    def get(self, provider_subject: str) -> OAuthLinkRecord | None:
        """The link for a provider-subject key, or `None`."""
        return self._items.get(provider_subject)

    def put(self, record: OAuthLinkRecord) -> None:
        """Write or replace a link."""
        self._items[record.provider_subject] = record

    def list_for_user(self, user_id: str) -> list[OAuthLinkRecord]:
        """Every link for a user."""
        return [record for record in self._items.values() if record.user_id == user_id]

    def delete(self, provider_subject: str) -> None:
        """Remove a link, tolerating an absent one."""
        self._items.pop(provider_subject, None)

    def claim(self, record: OAuthLinkRecord) -> bool:
        """Write a link only if that provider identity is not already attached."""
        if record.provider_subject in self._items:
            return False
        self._items[record.provider_subject] = record
        return True


class DynamoOAuthStateStore(OAuthStateStore):
    """`OAuthStateStore` over a `webbpulse.dynamodb.Repository`.

    Takes the repository rather than building one, so the caller owns the table name.
    """

    def __init__(self, repository: Repository) -> None:
        """Hold the repository the state rows are read from and written to."""
        self._repo = repository

    def put(self, record: OAuthStateRecord) -> None:
        """Write a fresh state row."""
        self._repo.put(
            {
                "state": record.state,
                "provider": record.provider,
                "mode": record.mode,
                "created_at": record.created_at,
                "expires_at": record.expires_at,
                "pkce_verifier": record.pkce_verifier,
                "nonce": record.nonce,
                "return_to": record.return_to,
                "user_id": record.user_id,
                "redirect_uri": record.redirect_uri,
            }
        )

    def consume(self, state: str) -> OAuthStateRecord | None:
        """Spend the row with a conditional delete that returns what it deleted.

        `ReturnValues=ALL_OLD` makes this one operation, so a second callback carrying the
        same state finds nothing.
        """
        from botocore.exceptions import ClientError

        try:
            response = self._repo.table.delete_item(
                Key={"state": state},
                ConditionExpression="attribute_exists(#s)",
                ExpressionAttributeNames={"#s": "state"},
                ReturnValues="ALL_OLD",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return None
            raise
        item = response.get("Attributes")
        if not item:
            return None
        record = _state_from_item(item)
        return None if is_expired(record.expires_at) else record


class DynamoOAuthLinkStore(OAuthLinkStore):
    """`OAuthLinkStore` over a `webbpulse.dynamodb.Repository`, with the `user_id-index` GSI."""

    def __init__(self, repository: Repository) -> None:
        """Hold the repository the link rows are read from and written to."""
        self._repo = repository

    def get(self, provider_subject: str) -> OAuthLinkRecord | None:
        """The link for a provider-subject key, read consistently from the base table."""
        item = self._repo.get({"provider_subject": provider_subject}, consistent=True)
        return _link_from_item(item) if item is not None else None

    def put(self, record: OAuthLinkRecord) -> None:
        """Write or replace a link."""
        self._repo.put(_link_to_item(record))

    def list_for_user(self, user_id: str) -> list[OAuthLinkRecord]:
        """Every link for a user, from the GSI, so it may be slightly stale."""
        from boto3.dynamodb.conditions import Key as KeyCondition

        return [
            _link_from_item(item)
            for item in self._repo.iter_query(
                KeyCondition("user_id").eq(user_id), index_name=OAUTH_LINK_USER_INDEX
            )
        ]

    def delete(self, provider_subject: str) -> None:
        """Remove a link, tolerating an absent one."""
        self._repo.delete({"provider_subject": provider_subject})

    def claim(self, record: OAuthLinkRecord) -> bool:
        """Conditionally write a link, returning `False` when the key already exists."""
        from boto3.dynamodb.conditions import Attr
        from botocore.exceptions import ClientError

        try:
            self._repo.put(
                _link_to_item(record),
                condition=Attr("provider_subject").not_exists(),
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return False
            raise
        return True


def _link_to_item(record: OAuthLinkRecord) -> dict[str, Any]:
    """Render a link record as the item shape the table stores."""
    return {
        "provider_subject": record.provider_subject,
        "provider": record.provider,
        "subject": record.subject,
        "user_id": record.user_id,
        "linked_at": record.linked_at,
        "provider_email": record.provider_email,
        "provider_email_verified": record.provider_email_verified,
        "last_login_at": record.last_login_at,
    }


def _state_from_item(item: Mapping[str, Any]) -> OAuthStateRecord:
    """Read a state row defensively, so a row written by an older version still loads."""
    mode = str(item.get("mode", "login"))
    return OAuthStateRecord(
        state=str(item["state"]),
        provider=str(item.get("provider", "")),
        mode="link" if mode == "link" else "login",
        created_at=str(item.get("created_at", "")),
        expires_at=int(item.get("expires_at", 0)),
        pkce_verifier=str(item.get("pkce_verifier", "")),
        nonce=str(item.get("nonce", "")),
        return_to=str(item.get("return_to", "")),
        user_id=str(item.get("user_id", "")),
        redirect_uri=str(item.get("redirect_uri", "")),
    )


def _link_from_item(item: Mapping[str, Any]) -> OAuthLinkRecord:
    """Read a link row into an `OAuthLinkRecord`."""
    return OAuthLinkRecord(
        provider_subject=str(item["provider_subject"]),
        provider=str(item.get("provider", "")),
        subject=str(item.get("subject", "")),
        user_id=str(item.get("user_id", "")),
        linked_at=str(item.get("linked_at", "")),
        provider_email=str(item.get("provider_email", "")),
        provider_email_verified=bool(item.get("provider_email_verified", False)),
        last_login_at=str(item.get("last_login_at", "")),
    )


def _b64url(raw: bytes) -> str:
    """base64url with no padding, which is what RFC 7636 and JWS both want."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def new_pkce_verifier() -> str:
    """A fresh RFC 7636 code verifier: 32 bytes base64url, the RFC's minimum length."""
    return _b64url(secrets.token_bytes(32))


def pkce_challenge(verifier: str) -> str:
    """The `S256` challenge for a verifier: base64url of its SHA-256, never `plain`."""
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


class OAuthService:
    """Provider start, callback, link, list and unlink, with no FastAPI in sight.

    Built once per execution environment and holds no request state. `client_secrets` is
    kept out of settings so a secret never reaches a `repr` or a log line.
    """

    def __init__(
        self,
        settings: IdentitySettings,
        hooks: IdentityHooks,
        *,
        states: OAuthStateStore,
        links: OAuthLinkStore,
        credentials: CredentialStore | None = None,
        client_secrets: Mapping[str, str] | None = None,
        http_client: HttpClient | None = None,
    ) -> None:
        """Hold the settings, hooks, stores, client secrets and HTTP client to use."""
        self._settings = settings
        self._hooks = hooks
        self._states = states
        self._links = links
        self._credentials = credentials
        self._secrets = dict(client_secrets or {})
        self._http = http_client if http_client is not None else HttpxClient()

    def enabled_providers(self) -> list[str]:
        """The providers this product has both switched on and given a client id.

        This is what decides whether the routes mount at all.
        """
        return [name for name in self._settings.oauth_providers if self._client_id(name)]

    def available_providers(self) -> list[OAuthProviderConfig]:
        """The providers a sign-in button should actually be drawn for.

        Stricter than `enabled_providers`: a provider also needs a client secret to complete
        a sign-in. Returned in the order `PROVIDERS` defines, so the layout is stable.
        """
        return [
            config
            for name, config in PROVIDERS.items()
            if name in self._settings.oauth_providers
            and self._client_id(name)
            and self._has_secret(name)
        ]

    def _has_secret(self, provider: str) -> bool:
        """Whether a client secret is configured, without raising or logging."""
        return bool(self._secrets.get(provider, ""))

    def _provider(self, provider: str) -> OAuthProviderConfig:
        """The config for an enabled provider, refusing an unknown or disabled one."""
        config = PROVIDERS.get(provider)
        if config is None or provider not in self.enabled_providers():
            raise OAuthRejected(
                "That sign-in provider is not available.",
                error_code="OAUTH_PROVIDER_UNKNOWN",
                status_code=404,
            )
        return config

    def _client_id(self, provider: str) -> str:
        """The configured client id for a provider, or an empty string."""
        if provider == GOOGLE_PROVIDER:
            return self._settings.google_client_id
        if provider == GITHUB_PROVIDER:
            return self._settings.github_client_id
        return ""

    def _client_secret(self, provider: str) -> str:
        """The client secret for a provider, refusing with a 503 when none is configured.

        The refusal deliberately says nothing about how the service is configured; the
        detail goes to the log line instead.
        """
        secret = self._secrets.get(provider, "")
        if not secret:
            _log.error(
                "No OAuth client secret configured.",
                extra={"event": "oauth.misconfigured", "provider": provider},
            )
            raise OAuthRejected(
                "That sign-in provider is not available.",
                error_code="OAUTH_PROVIDER_UNAVAILABLE",
                status_code=503,
            )
        return secret

    def start(
        self,
        provider: str,
        *,
        mode: OAuthMode = "login",
        user_id: str = "",
        return_to: str = "",
        redirect_uri: str = "",
    ) -> OAuthAuthorization:
        """Mint a state, write it, and build the URL the browser is redirected to.

        The row is written first and `redirect_uri` is checked against the allow-list here,
        so the callback can trust the stored value. A missing client secret refuses up front.
        """
        config = self._provider(provider)
        self._client_secret(provider)
        if mode == "link" and not user_id:
            raise OAuthRejected("Sign in first.", error_code="NOT_AUTHENTICATED", status_code=401)

        resolved_redirect = self._resolve_redirect_uri(redirect_uri)
        resolved_return = self._resolve_return_to(return_to)

        state = _b64url(secrets.token_bytes(32))
        verifier = new_pkce_verifier() if config.supports_pkce else ""
        nonce = _b64url(secrets.token_bytes(16)) if config.returns_id_token else ""

        self._states.put(
            OAuthStateRecord(
                state=state,
                provider=provider,
                mode=mode,
                created_at=now_iso(),
                expires_at=ttl_in(OAUTH_STATE_TTL_SECONDS),
                pkce_verifier=verifier,
                nonce=nonce,
                return_to=resolved_return,
                user_id=user_id if mode == "link" else "",
                redirect_uri=resolved_redirect,
            )
        )

        params: dict[str, str] = {
            "client_id": self._client_id(provider),
            "redirect_uri": resolved_redirect,
            "response_type": "code",
            "scope": config.scope,
            "state": state,
            **dict(config.extra_authorize_params),
        }
        if verifier:
            params["code_challenge"] = pkce_challenge(verifier)
            params["code_challenge_method"] = "S256"
        if nonce:
            params["nonce"] = nonce

        _log.info(
            "OAuth authorization started.",
            extra={"event": "oauth.start", "provider": provider, "mode": mode},
        )
        return OAuthAuthorization(
            authorization_url=f"{config.authorize_url}?{urlencode(params)}",
            state=state,
        )

    def _resolve_redirect_uri(self, requested: str) -> str:
        """The redirect URI to send, checked against the allow-list.

        Empty means the issuer plus the callback path. A non-empty value must appear in
        `oauth_redirect_uris` exactly, by string equality and never a prefix match.
        """
        default = f"{self._settings.issuer}/oauth/callback"
        allowed = list(self._settings.oauth_redirect_uris)
        if not requested:
            return allowed[0] if allowed else default
        if requested in allowed or (not allowed and requested == default):
            return requested
        raise OAuthRejected(
            "That redirect URI is not allowed.",
            error_code="OAUTH_REDIRECT_NOT_ALLOWED",
            status_code=400,
        )

    def _resolve_return_to(self, requested: str) -> str:
        """Where the frontend is sent after the callback, constrained to the frontend.

        Accepts a path resolved against `frontend_base_url`, or an absolute URL on that same
        origin. Anything else, a scheme-relative `//host` included, falls back to the root.
        """
        base = self._settings.frontend_base_url
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

    def consume_state(self, state: str, *, provider: str = "") -> OAuthStateRecord:
        """Spend a state exactly once, and return what it recorded.

        The row is the authority on which provider the flow belongs to, so `provider` is
        optional and only cross-checked when given. Every failure answers identically.
        """
        if not state:
            raise OAuthRejected(
                "That sign-in attempt is no longer valid. Start again.",
                error_code="OAUTH_STATE_INVALID",
            )
        record = self._states.consume(state)
        if record is None:
            raise OAuthRejected(
                "That sign-in attempt is no longer valid. Start again.",
                error_code="OAUTH_STATE_INVALID",
            )
        if provider and not constant_time_equals(record.provider, provider):
            raise OAuthRejected(
                "That sign-in attempt is no longer valid. Start again.",
                error_code="OAUTH_STATE_INVALID",
            )
        return record

    def identity_from_callback(
        self, provider: str, *, code: str, state_record: OAuthStateRecord
    ) -> OAuthIdentity:
        """Exchange the code and turn the provider's answer into an `OAuthIdentity`.

        One method, so a caller need not know whether the identity comes from a verified ID
        token or from authenticated userinfo calls.
        """
        config = self._provider(provider)
        token_body = self._token_body(provider, code=code, state_record=state_record)

        if config.returns_id_token:
            id_token = _require_str(token_body, "id_token", provider)
            return self._identity_from_id_token(config, id_token, nonce=state_record.nonce)

        access_token = _require_str(token_body, "access_token", provider)
        return self._identity_from_userinfo(config, access_token)

    def _token_body(
        self, provider: str, *, code: str, state_record: OAuthStateRecord
    ) -> Mapping[str, Any]:
        """Trade the authorization code for the provider's whole token response body."""
        config = self._provider(provider)
        if not code:
            raise OAuthRejected(
                "The sign-in provider returned no authorization code.",
                error_code="OAUTH_CODE_MISSING",
            )
        data: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self._client_id(provider),
            "client_secret": self._client_secret(provider),
            "redirect_uri": state_record.redirect_uri,
        }
        if state_record.pkce_verifier:
            data["code_verifier"] = state_record.pkce_verifier

        response = self._http.post_form(
            config.token_url, data=data, headers={"Accept": "application/json"}
        )
        body = response.json_body if isinstance(response.json_body, dict) else {}
        if not response.ok or body.get("error"):
            _log.warning(
                "OAuth token exchange failed.",
                extra={
                    "event": "oauth.exchange_failed",
                    "provider": provider,
                    "status": response.status_code,
                    "error": str(body.get("error", ""))[:64],
                },
            )
            raise OAuthRejected(
                "That sign-in could not be completed. Try again.",
                error_code="OAUTH_EXCHANGE_FAILED",
            )
        return body

    def _signing_key_for(self, config: OAuthProviderConfig, id_token: str) -> Any:
        """Find the provider's public key for this token, fetching the JWKS ourselves.

        Fetched through `self._http` so the call carries a timeout, and per verification so a
        key rotation needs no invalidation. An unpublished `kid` is refused.
        """
        import jwt

        header = jwt.get_unverified_header(id_token)
        kid = str(header.get("kid", ""))

        response = self._http.get_json(config.jwks_url, headers={"accept": "application/json"})
        if not response.ok or not isinstance(response.json_body, dict):
            raise OAuthRejected(
                "That sign-in could not be completed. Try again.",
                error_code="OAUTH_ID_TOKEN_INVALID",
            )

        keys = response.json_body.get("keys")
        if not isinstance(keys, list):
            raise OAuthRejected(
                "That sign-in could not be completed. Try again.",
                error_code="OAUTH_ID_TOKEN_INVALID",
            )

        for entry in keys:
            if isinstance(entry, dict) and str(entry.get("kid", "")) == kid:
                return jwt.PyJWK.from_dict(dict(entry)).key

        raise OAuthRejected(
            "That sign-in could not be completed. Try again.",
            error_code="OAUTH_ID_TOKEN_INVALID",
        )

    def _identity_from_id_token(
        self, config: OAuthProviderConfig, id_token: str, *, nonce: str
    ) -> OAuthIdentity:
        """Verify an OIDC ID token, then read the identity out of its claims.

        Checks the signature against the published JWKS, then `iss`, `aud`, `exp` and, after
        the signature and never before, the `nonce` this flow generated.
        """
        import jwt

        audience = self._client_id(config.name)
        try:
            signing_key = self._signing_key_for(config, id_token)
            claims = jwt.decode(
                id_token,
                signing_key,
                algorithms=["RS256"],
                audience=audience,
                issuer=list(config.id_token_issuers),
                leeway=self._settings.clock_skew_leeway,
                options={"require": ["exp", "iat", "sub", "aud", "iss"]},
            )
        except Exception as exc:
            _log.warning(
                "OAuth ID token verification failed.",
                extra={
                    "event": "oauth.id_token_invalid",
                    "provider": config.name,
                    "reason": type(exc).__name__,
                },
            )
            raise OAuthRejected(
                "That sign-in could not be completed. Try again.",
                error_code="OAUTH_ID_TOKEN_INVALID",
            ) from exc

        presented = str(claims.get("nonce", ""))
        if nonce and not constant_time_equals(presented, nonce):
            _log.warning(
                "OAuth ID token nonce mismatch.",
                extra={"event": "oauth.nonce_mismatch", "provider": config.name},
            )
            raise OAuthRejected(
                "That sign-in could not be completed. Try again.",
                error_code="OAUTH_NONCE_MISMATCH",
            )

        return OAuthIdentity(
            provider=config.name,
            subject=str(claims.get("sub", "")),
            email=str(claims.get("email", "")).strip().lower(),
            email_verified=_as_bool(claims.get("email_verified")),
            name=str(claims.get("name", "")),
        )

    def _identity_from_userinfo(
        self, config: OAuthProviderConfig, access_token: str
    ) -> OAuthIdentity:
        """GitHub's identity: the account from `/user`, the address from `/user/emails`.

        Both calls are needed: `/user` gives the immutable subject, and only `/user/emails`
        says which address GitHub has actually confirmed.
        """
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        profile = self._http.get_json(config.userinfo_url, headers=headers)
        if not profile.ok or not isinstance(profile.json_body, dict):
            raise OAuthRejected(
                "That sign-in could not be completed. Try again.",
                error_code="OAUTH_USERINFO_FAILED",
            )
        body = profile.json_body
        subject = str(body.get("id", ""))
        if not subject:
            raise OAuthRejected(
                "That sign-in could not be completed. Try again.",
                error_code="OAUTH_USERINFO_FAILED",
            )

        email, verified = self._github_primary_email(config, headers)
        return OAuthIdentity(
            provider=config.name,
            subject=subject,
            email=email,
            email_verified=verified,
            name=str(body.get("name", "") or body.get("login", "")),
        )

    def _github_primary_email(
        self, config: OAuthProviderConfig, headers: Mapping[str, str]
    ) -> tuple[str, bool]:
        """The verified primary address, or the best available with `verified` false.

        Prefers the verified primary, then any verified address, then the primary whatever
        its state. A failed call yields an empty address rather than raising.
        """
        response = self._http.get_json(config.emails_url, headers=headers)
        entries = response.json_body if response.ok else None
        if not isinstance(entries, list):
            return "", False

        primary_unverified = ""
        first_verified = ""
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            address = str(entry.get("email", "")).strip().lower()
            if not address:
                continue
            verified = _as_bool(entry.get("verified"))
            primary = _as_bool(entry.get("primary"))
            if verified and primary:
                return address, True
            if verified and not first_verified:
                first_verified = address
            if primary and not primary_unverified:
                primary_unverified = address
        if first_verified:
            return first_verified, True
        return primary_unverified, False

    def resolve_login(self, identity: OAuthIdentity) -> tuple[Mapping[str, Any], str]:
        """Turn a provider identity into a local user, by link, email match or registration.

        Returns the user and how it was reached: `"linked"` for an existing link,
        `"auto_linked"` for the verified-email attach, `"registered"` for a new account.
        """
        existing = self._links.get(identity.account_key)
        if existing is not None:
            user = self._hooks.load_user_by_id(existing.user_id)
            if user is None:
                self._links.delete(identity.account_key)
                raise OAuthRejected(
                    "That account is no longer available.",
                    error_code="OAUTH_ACCOUNT_MISSING",
                    status_code=401,
                )
            self._touch(existing, identity)
            return user, "linked"

        if not identity.email:
            raise OAuthRejected(
                "That sign-in provider did not share an email address. Add one to your "
                "provider account, or sign in with a password.",
                error_code="OAUTH_EMAIL_MISSING",
            )

        matched = self._hooks.load_user_by_email(identity.email)
        if matched is not None:
            self._require_auto_link_allowed(identity, matched)
            record = self._new_link(identity, _user_id(matched))
            if not self._links.claim(record):
                raise OAuthRejected(
                    "That provider account is already linked.",
                    error_code="OAUTH_ALREADY_LINKED",
                    status_code=409,
                )
            _log.info(
                "OAuth identity auto-linked on a verified email.",
                extra={
                    "event": "oauth.linked",
                    "provider": identity.provider,
                    "user_id": _user_id(matched),
                    "auto": True,
                },
            )
            return matched, "auto_linked"

        return self._register(identity), "registered"

    def _require_auto_link_allowed(self, identity: OAuthIdentity, user: Mapping[str, Any]) -> None:
        """Refuse the auto-link unless both the provider and the local email are verified.

        Both failures answer with the same code and message, so neither confirms whether an
        account exists for that address.
        """
        local_verified = bool(user.get("email_verified", False))
        if identity.email_verified and local_verified:
            return
        _log.warning(
            "OAuth auto-link refused: an unverified email on one side.",
            extra={
                "event": "oauth.autolink_refused",
                "provider": identity.provider,
                "provider_verified": identity.email_verified,
                "local_verified": local_verified,
            },
        )
        raise OAuthRejected(
            "An account already exists for that email address. Sign in with your password "
            "first, then link this provider from your account settings.",
            error_code="OAUTH_EMAIL_UNVERIFIED",
            status_code=409,
        )

    def _register(self, identity: OAuthIdentity) -> Mapping[str, Any]:
        """Create a local account for a provider identity nobody has seen before.

        Goes through the same `create_user` hook password registration uses, and passes
        `email_verified` through from the provider rather than forcing it true.
        """
        if not self._settings.registration_enabled:
            raise OAuthRejected(
                "This service is not accepting new accounts.",
                error_code="REGISTRATION_DISABLED",
                status_code=403,
            )
        user = self._hooks.create_user(
            email=identity.email,
            attributes={
                "email_verified": identity.email_verified,
                "name": identity.name,
            },
        )
        user_id = _user_id(user)
        record = self._new_link(identity, user_id)
        if not self._links.claim(record):
            raise OAuthRejected(
                "That provider account is already linked.",
                error_code="OAUTH_ALREADY_LINKED",
                status_code=409,
            )
        self._hooks.on_user_created(user, identity.provider)
        _log.info(
            "OAuth registration created an account.",
            extra={
                "event": "oauth.linked",
                "provider": identity.provider,
                "user_id": user_id,
                "registered": True,
            },
        )
        return user

    def link(self, identity: OAuthIdentity, *, user_id: str) -> OAuthLinkRecord:
        """Attach a provider identity to the authenticated account that asked for it.

        Needs no email check, since the caller proved they hold both accounts. An identity
        already attached is refused with the same message whoever holds it.
        """
        existing = self._links.get(identity.account_key)
        if existing is not None:
            raise OAuthRejected(
                "That provider account is already linked.",
                error_code="OAUTH_ALREADY_LINKED",
                status_code=409,
            )
        record = self._new_link(identity, user_id)
        if not self._links.claim(record):
            raise OAuthRejected(
                "That provider account is already linked.",
                error_code="OAUTH_ALREADY_LINKED",
                status_code=409,
            )
        _log.info(
            "OAuth identity linked.",
            extra={
                "event": "oauth.linked",
                "provider": identity.provider,
                "user_id": user_id,
                "auto": False,
            },
        )
        return record

    def list_links(self, user_id: str) -> list[OAuthLinkRecord]:
        """Every provider linked to this account, for the settings page."""
        return sorted(self._links.list_for_user(user_id), key=lambda record: record.provider)

    def unlink(self, *, user_id: str, provider: str) -> None:
        """Detach a provider, unless doing so would leave the account with no way in.

        What would remain is counted first: another OAuth link, a password, or anything the
        `has_other_sign_in_method` hook reports. Only a non-empty answer permits the delete.
        """
        target = provider_account_key(provider, "")
        links = [
            record
            for record in self._links.list_for_user(user_id)
            if record.provider == provider or record.provider_subject.startswith(target)
        ]
        if not links:
            raise OAuthRejected(
                "That provider is not linked to this account.",
                error_code="OAUTH_NOT_LINKED",
                status_code=404,
            )

        removing = {record.provider_subject for record in links}
        remaining = self._other_sign_in_methods(user_id, removing=removing)
        if not remaining:
            raise OAuthRejected(
                "That is the only way to sign in to this account. Set a password or add "
                "another sign-in method first.",
                error_code="OAUTH_LAST_SIGN_IN_METHOD",
                status_code=409,
            )

        for record in links:
            self._links.delete(record.provider_subject)
        _log.info(
            "OAuth identity unlinked.",
            extra={"event": "oauth.unlinked", "provider": provider, "user_id": user_id},
        )

    def _other_sign_in_methods(self, user_id: str, *, removing: set[str]) -> bool:
        """Whether anything would still sign this user in after `removing` goes away.

        Each GSI hit is re-read from the base table, since the index may be stale and
        over-counting here is the direction that loses an account.
        """
        for record in self._links.list_for_user(user_id):
            if record.provider_subject in removing:
                continue
            confirmed = self._links.get(record.provider_subject)
            if confirmed is not None and confirmed.user_id == user_id:
                return True

        if self._credentials is not None:
            from webbpulse.identity.flows import PASSWORD_CREDENTIAL_TYPE

            password = self._credentials.get(user_id, PASSWORD_CREDENTIAL_TYPE)
            if password is not None and password.secret:
                return True

        return bool(self._hooks.has_other_sign_in_method(user_id))

    def _new_link(self, identity: OAuthIdentity, user_id: str) -> OAuthLinkRecord:
        """Build a link record attaching this identity to a user, stamped with the time."""
        moment = now_iso()
        return OAuthLinkRecord(
            provider_subject=identity.account_key,
            provider=identity.provider,
            subject=identity.subject,
            user_id=user_id,
            linked_at=moment,
            provider_email=identity.email,
            provider_email_verified=identity.email_verified,
            last_login_at=moment,
        )

    def _touch(self, record: OAuthLinkRecord, identity: OAuthIdentity) -> None:
        """Record this login on the link, and refresh what the provider now says.

        Best effort: a write failure here must not fail a sign-in that already succeeded.
        """
        try:
            self._links.put(
                OAuthLinkRecord(
                    provider_subject=record.provider_subject,
                    provider=record.provider,
                    subject=record.subject,
                    user_id=record.user_id,
                    linked_at=record.linked_at,
                    provider_email=identity.email or record.provider_email,
                    provider_email_verified=identity.email_verified,
                    last_login_at=now_iso(),
                )
            )
        except Exception:
            _log.warning(
                "Could not record an OAuth login on its link.",
                extra={"event": "oauth.touch_failed", "provider": record.provider},
            )


def _as_bool(value: object) -> bool:
    """Read a provider's boolean, which may be a real one or the string spelling of one."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return False


def _require_str(body: Mapping[str, Any], key: str, provider: str) -> str:
    """Read a required non-empty string from a token response, refusing when it is absent."""
    value = body.get(key)
    if not isinstance(value, str) or not value:
        _log.warning(
            "OAuth token response was missing a required field.",
            extra={"event": "oauth.token_incomplete", "provider": provider, "field": key},
        )
        raise OAuthRejected(
            "That sign-in could not be completed. Try again.",
            error_code="OAUTH_EXCHANGE_FAILED",
        )
    return value


def _user_id(user: Mapping[str, Any]) -> str:
    """The immutable id from a product's user mapping, as `flows._user_id` reads it."""
    value = user.get("id") or user.get("user_id") or ""
    if not value:
        raise OAuthRejected(
            "The product's user record has no id, so no token can be minted for it.",
            error_code="USER_ID_MISSING",
            status_code=500,
        )
    return str(value)
