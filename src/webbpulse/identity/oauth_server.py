"""An OAuth 2.1 authorization server, so a product can host a remote MCP server.

Implements the MCP authorization spec (2025-06-18) over RFC 8414, 9728, 7591, 7636 and
8707: discovery, protected resource metadata, an authorization code grant with PKCE S256
required, dynamic client registration for public clients, and revocation. The tokens are
the same RS256 access tokens `TokenService` already mints, so an existing JWT authorizer
and `coerce_claims` handle them unchanged.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from webbpulse.identity.oauth import pkce_challenge
from webbpulse.identity.oauth_server_storage import (
    AuthorizationCodeRecord,
    ConsentRecord,
    OAuthClientRecord,
    OAuthServerStores,
)
from webbpulse.identity.storage import constant_time_equals, hash_token
from webbpulse.identity.tokens import JWKS_PATH

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Callable

    from fastapi import APIRouter, Request
    from fastapi.responses import JSONResponse

    from webbpulse.identity.flows import IdentityFlows
    from webbpulse.identity.service import TokenService
    from webbpulse.identity.settings import IdentitySettings

__all__ = [
    "AUTHORIZATION_SERVER_METADATA_PATH",
    "AUTHORIZE_PATH",
    "CODE_CHALLENGE_METHODS",
    "GRANT_TYPES_SUPPORTED",
    "OAUTH_SERVER_ROUTE_RESPONSES",
    "PROTECTED_RESOURCE_METADATA_PATH",
    "REGISTER_CLIENT_IP_LIMIT",
    "REGISTER_CLIENT_PATH",
    "RESPONSE_TYPES_SUPPORTED",
    "REVOKE_PATH",
    "TOKEN_ENDPOINT_AUTH_METHODS",
    "TOKEN_PATH",
    "AuthorizationRequest",
    "ConsentContext",
    "ConsentRenderer",
    "OAuthServerError",
    "OAuthServerService",
    "TenantChoice",
    "build_authorization_server_metadata",
    "build_oauth_server_router",
    "build_protected_resource_metadata",
    "default_consent_renderer",
    "extend_discovery_document",
]

AUTHORIZATION_SERVER_METADATA_PATH: Final = "/.well-known/oauth-authorization-server"
PROTECTED_RESOURCE_METADATA_PATH: Final = "/.well-known/oauth-protected-resource"
AUTHORIZE_PATH: Final = "/authorize"
TOKEN_PATH: Final = "/token"
REGISTER_CLIENT_PATH: Final = "/register-client"
REVOKE_PATH: Final = "/revoke"
CONSENT_PATH: Final = "/authorize/consent"

CODE_CHALLENGE_METHODS: Final[tuple[str, ...]] = ("S256",)
"""Only `S256`. RFC 7636 also defines `plain`, which is no proof at all: the verifier and
the challenge are the same string, so an attacker holding the intercepted challenge holds
the verifier. OAuth 2.1 forbids it and so does the MCP spec."""

GRANT_TYPES_SUPPORTED: Final[tuple[str, ...]] = ("authorization_code", "refresh_token")

RESPONSE_TYPES_SUPPORTED: Final[tuple[str, ...]] = ("code",)
"""Only `code`. The implicit grant returns a token in a URL fragment, where it lands in
browser history, `Referer` headers and server logs, and it has no client authentication
step at all. OAuth 2.1 removes it."""

TOKEN_ENDPOINT_AUTH_METHODS: Final[tuple[str, ...]] = ("none",)

REGISTER_CLIENT_IP_LIMIT: Final = (10, 3600)
"""Ten registrations per address per hour. Registration is unauthenticated by design, so
this is the only thing between an open endpoint and a table filled from one host."""

AUTHORIZE_IP_LIMIT: Final = (60, 900)
TOKEN_IP_LIMIT: Final = (120, 900)

CODE_BYTES: Final = 32

MAX_REDIRECT_URIS: Final = 10

MAX_CLIENT_NAME_LENGTH: Final = 200

_LOOPBACK_HOSTS: Final[frozenset[str]] = frozenset({"127.0.0.1", "::1", "localhost"})

_log = logging.getLogger(__name__)

_FastAPIRequest: Any = None

if not TYPE_CHECKING:
    JSONResponse = None
    """Bound by `_bind_fastapi_request`. A runtime global as well as a `TYPE_CHECKING`
    import because every route here is annotated `-> JSONResponse` under postponed
    annotations, and FastAPI resolves that annotation against these globals when it builds
    the OpenAPI document. Type checkers read the import instead, so the annotation keeps
    its real type."""

    Request = None
    """Bound by `_bind_fastapi_request` for the same reason: FastAPI resolves a route's
    `request: Request` annotation against this module's globals, and a name visible only
    under `TYPE_CHECKING` leaves it unresolvable."""


def _bind_fastapi_request() -> None:
    """Put `fastapi.Request` and `JSONResponse` in this module's globals.

    FastAPI resolves a route's string annotations against the defining module's globals, so
    a name visible only under `TYPE_CHECKING` leaves the return annotation unresolvable and
    `app.openapi()` raises `PydanticUserError`.
    """
    global _FastAPIRequest, JSONResponse, Request
    if _FastAPIRequest is None:
        from fastapi import Request as _Request

        _FastAPIRequest = _Request
        Request = _Request  # type: ignore[misc]
    if JSONResponse is None:
        from fastapi.responses import JSONResponse as _Response

        JSONResponse = _Response  # type: ignore[misc]


class OAuthServerError(Exception):
    """One refusal from the authorization server, carrying its RFC 6749 error code.

    The code is the machine-readable one a client branches on; `description` is safe to
    show a developer and never names which half of a comparison failed, because that would
    tell an attacker which value to work on next.
    """

    def __init__(self, error: str, description: str, *, status: int = 400) -> None:
        """Record the error code, its description and the HTTP status to answer with."""
        super().__init__(f"{error}: {description}")
        self.error = error
        self.description = description
        self.status = status


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    """A parsed and validated `/authorize` request, before the user has consented.

    Every field has been checked against the registered client by the time one of these
    exists, so the consent step and the code it produces need re-validate nothing.
    """

    client: OAuthClientRecord
    redirect_uri: str
    resource: str
    scopes: tuple[str, ...]
    code_challenge: str
    state: str = ""
    code_challenge_method: str = "S256"


@dataclass(frozen=True, slots=True)
class TenantChoice:
    """One tenant the signed-in user may bind this authorization to.

    `id` goes into the token's tenant claim; `name` is what the consent screen shows. A
    product supplies these from its own membership model, which this package cannot see.
    """

    id: str
    name: str = ""


@dataclass(frozen=True, slots=True)
class ConsentContext:
    """Everything a consent screen needs to render, and nothing it does not.

    Passed to the `ConsentRenderer` a product supplies. The `form_action` and
    `form_fields` are what a replacement UI must post back unchanged, so a restyled screen
    cannot accidentally drop the binding between the consent and the request it approves.
    """

    request: AuthorizationRequest
    user_id: str
    tenants: tuple[TenantChoice, ...]
    form_action: str
    form_fields: Mapping[str, str]


type ConsentRenderer = Callable[[ConsentContext], Any]
"""What a product supplies to restyle the consent step.

Returns any Starlette response. The default renders a minimal self-contained form, so a
product that supplies nothing still has a working, if plain, authorization screen.
"""

type TenantResolver = Callable[[str], Sequence[TenantChoice]]
"""Maps a signed-in user id to the tenants they may bind a token to.

A product's own membership model. Returning one tenant still shows the consent screen: the
user is approving a client's access, not only choosing where it applies.
"""


def build_authorization_server_metadata(settings: IdentitySettings) -> dict[str, Any]:
    """The RFC 8414 authorization server metadata document.

    Advertises only what this server will actually honour: one response type, S256 alone,
    and `none` as the only client authentication method. Advertising anything else invites
    a client to try it and be refused for reasons it cannot see.
    """
    issuer = settings.issuer.rstrip("/")
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}{AUTHORIZE_PATH}",
        "token_endpoint": f"{issuer}{TOKEN_PATH}",
        "registration_endpoint": f"{issuer}{REGISTER_CLIENT_PATH}",
        "revocation_endpoint": f"{issuer}{REVOKE_PATH}",
        "jwks_uri": f"{issuer}{JWKS_PATH}",
        "scopes_supported": list(settings.mcp_scopes_supported),
        "response_types_supported": list(RESPONSE_TYPES_SUPPORTED),
        "grant_types_supported": list(GRANT_TYPES_SUPPORTED),
        "code_challenge_methods_supported": list(CODE_CHALLENGE_METHODS),
        "token_endpoint_auth_methods_supported": list(TOKEN_ENDPOINT_AUTH_METHODS),
        "resource_indicators_supported": True,
    }


def build_protected_resource_metadata(settings: IdentitySettings) -> dict[str, Any]:
    """The RFC 9728 protected resource metadata document.

    This is what an MCP client reads first, from the `WWW-Authenticate` header of the
    resource's own 401, to discover which authorization server to go to. `resource` is the
    canonical URL a token must be bound to, and the one this server puts in `aud`.
    """
    issuer = settings.issuer.rstrip("/")
    return {
        "resource": settings.mcp_resource_url,
        "authorization_servers": [issuer],
        "scopes_supported": list(settings.mcp_scopes_supported),
        "bearer_methods_supported": ["header"],
        "resource_documentation": issuer,
    }


def extend_discovery_document(document: Mapping[str, Any], settings: IdentitySettings) -> dict[str, Any]:
    """Add the authorization server's endpoints to the existing OIDC discovery document.

    A copy rather than a mutation, so `TokenService`'s precomputed document is not changed
    for a product that mounts identity without the flag. Only called when the flag is on.
    """
    issuer = settings.issuer.rstrip("/")
    extended = dict(document)
    extended.update(
        {
            "authorization_endpoint": f"{issuer}{AUTHORIZE_PATH}",
            "token_endpoint": f"{issuer}{TOKEN_PATH}",
            "registration_endpoint": f"{issuer}{REGISTER_CLIENT_PATH}",
            "code_challenge_methods_supported": list(CODE_CHALLENGE_METHODS),
            "scopes_supported": list(settings.mcp_scopes_supported),
            "response_types_supported": list(RESPONSE_TYPES_SUPPORTED),
            "grant_types_supported": list(GRANT_TYPES_SUPPORTED),
        }
    )
    return extended


def _is_loopback(parsed: Any) -> bool:
    """Whether a parsed redirect URI is a loopback address on any port.

    A native MCP client listens on an ephemeral port it cannot know in advance, so the port
    is deliberately not compared. The host is, because only the loopback interface is
    unreachable from the network.
    """
    return parsed.hostname in _LOOPBACK_HOSTS


def validate_redirect_uri(value: str) -> str:
    """Check one redirect URI and return it, or raise `OAuthServerError`.

    `https` anywhere, or plaintext `http` only on loopback, which never crosses a network.
    A fragment is refused outright: RFC 6749 forbids one, and an authorization code appended
    to a URI that already has a fragment would be delivered somewhere unintended.
    """
    parsed = urlsplit(value)
    if parsed.fragment:
        raise OAuthServerError(
            "invalid_redirect_uri",
            "A redirect URI must carry no fragment.",
        )
    if not parsed.hostname:
        raise OAuthServerError("invalid_redirect_uri", "A redirect URI must be absolute and name a host.")
    if parsed.scheme == "https":
        return value
    if parsed.scheme == "http" and _is_loopback(parsed):
        return value
    raise OAuthServerError(
        "invalid_redirect_uri",
        "A redirect URI must use https, or http on a 127.0.0.1, ::1 or localhost loopback address.",
    )


async def _form_params(request: Request) -> dict[str, str]:
    """Read an `application/x-www-form-urlencoded` body into a plain mapping.

    Decoded here rather than through `request.form()`, which reaches for `python-multipart`
    the moment it is called and would add a dependency to the package for a content type
    OAuth never uses: RFC 6749 specifies urlencoded bodies, not multipart ones.
    """
    body = await request.body()
    return dict(parse_qsl(body.decode("utf-8", errors="replace"), keep_blank_values=True))


def _redirect_with(target: str, params: Mapping[str, str]) -> str:
    """Append query parameters to a redirect URI, keeping any it already carries.

    Built by parsing rather than string concatenation, so a registered URI that already has
    a query string does not end up with two `?` separators and an unparseable tail.
    """
    parsed = urlsplit(target)
    existing = parse_qsl(parsed.query, keep_blank_values=True)
    merged = existing + [(key, value) for key, value in params.items() if value]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(merged), parsed.fragment))


class OAuthServerService:
    """The authorization server's decisions, with no FastAPI in sight.

    Built once per execution environment and holds no request state. Every method takes the
    values already parsed from a request, so the routes stay a thin translation layer and
    the rules are testable without a client.
    """

    def __init__(
        self,
        settings: IdentitySettings,
        stores: OAuthServerStores,
        tokens: TokenService,
        *,
        flows: IdentityFlows | None = None,
    ) -> None:
        """Bind the service to its settings, stores and token service.

        `flows` is optional and only used to issue the refresh family behind a granted
        token, so a product mounting the server without the password flows still works.
        """
        self._settings = settings
        self._stores = stores
        self._tokens = tokens
        self._flows = flows
        self._seed_first_party_clients()

    def _seed_first_party_clients(self) -> None:
        """Write the settings-declared clients into the store, marked first party.

        Written rather than consulted separately, so `/authorize` has one lookup path and a
        pre-registered client cannot diverge from a dynamic one in how it is validated.
        """
        for entry in self._settings.mcp_clients:
            client_id = str(entry.get("client_id", ""))
            redirect_uris = tuple(str(value) for value in entry.get("redirect_uris", []))
            for uri in redirect_uris:
                validate_redirect_uri(uri)
            self._stores.clients.put(
                OAuthClientRecord(
                    client_id=client_id,
                    redirect_uris=redirect_uris,
                    client_name=str(entry.get("client_name", "")),
                    first_party=True,
                    scopes=tuple(str(value) for value in entry.get("scopes", [])),
                )
            )

    @property
    def settings(self) -> IdentitySettings:
        """The identity settings this service was built from."""
        return self._settings

    def register_client(self, request: Mapping[str, Any], *, now: int | None = None) -> dict[str, Any]:
        """Register a public client per RFC 7591 and return the registration response.

        Refuses anything but a public PKCE client: a `token_endpoint_auth_method` other than
        `none` would mean issuing a secret, and a secret shipped inside a desktop MCP client
        is a published credential. No `client_secret` appears in the response for that reason.
        """
        moment = int(time.time()) if now is None else now
        method = str(request.get("token_endpoint_auth_method", "none"))
        if method != "none":
            raise OAuthServerError(
                "invalid_client_metadata",
                "This server registers public clients only, so token_endpoint_auth_method must be 'none'.",
            )
        raw_uris = request.get("redirect_uris")
        if not isinstance(raw_uris, (list, tuple)) or not raw_uris:
            raise OAuthServerError("invalid_redirect_uri", "At least one redirect_uri is required.")
        if len(raw_uris) > MAX_REDIRECT_URIS:
            raise OAuthServerError(
                "invalid_redirect_uri",
                f"At most {MAX_REDIRECT_URIS} redirect URIs may be registered.",
            )
        redirect_uris = tuple(validate_redirect_uri(str(value)) for value in raw_uris)

        grant_types = request.get("grant_types") or list(GRANT_TYPES_SUPPORTED)
        unsupported = set(str(value) for value in grant_types) - set(GRANT_TYPES_SUPPORTED)
        if unsupported:
            raise OAuthServerError(
                "invalid_client_metadata",
                f"Unsupported grant types: {', '.join(sorted(unsupported))}.",
            )
        response_types = request.get("response_types") or list(RESPONSE_TYPES_SUPPORTED)
        if set(str(value) for value in response_types) - set(RESPONSE_TYPES_SUPPORTED):
            raise OAuthServerError(
                "invalid_client_metadata",
                "The only supported response_type is 'code'; the implicit grant is not offered.",
            )

        client_name = str(request.get("client_name", ""))[:MAX_CLIENT_NAME_LENGTH]
        scopes = self._validate_scopes(str(request.get("scope", "")).split())
        record = OAuthClientRecord(
            client_id=f"mcp_{uuid.uuid4().hex}",
            redirect_uris=redirect_uris,
            client_name=client_name,
            created_at=_iso(moment),
            expires_at=moment + int(self._settings.mcp_client_ttl.total_seconds()),
            first_party=False,
            scopes=scopes,
        )
        self._stores.clients.put(record)
        _log.info("oauth_server_client_registered client_id=%s redirect_uris=%d", record.client_id, len(redirect_uris))
        return {
            "client_id": record.client_id,
            "client_id_issued_at": moment,
            "redirect_uris": list(record.redirect_uris),
            "client_name": record.client_name,
            "grant_types": list(GRANT_TYPES_SUPPORTED),
            "response_types": list(RESPONSE_TYPES_SUPPORTED),
            "token_endpoint_auth_method": "none",
            "scope": " ".join(record.scopes) if record.scopes else " ".join(self._settings.mcp_scopes_supported),
        }

    def _validate_scopes(self, requested: Sequence[str]) -> tuple[str, ...]:
        """Check requested scopes against `scopes_supported`, refusing rather than narrowing.

        Silently dropping an unknown scope would leave a client believing it holds access it
        does not, and it would discover that only at the first refused call, far from here.
        """
        if not requested:
            return tuple(self._settings.mcp_scopes_supported)
        supported = set(self._settings.mcp_scopes_supported)
        unknown = [scope for scope in requested if scope not in supported]
        if unknown:
            raise OAuthServerError(
                "invalid_scope",
                f"Unsupported scope: {', '.join(sorted(unknown))}.",
            )
        return tuple(requested)

    def parse_authorization_request(self, params: Mapping[str, str]) -> AuthorizationRequest:
        """Validate an `/authorize` query and return the request, or raise.

        Order matters: the client and redirect URI are checked first, because every later
        refusal is delivered by redirecting to that URI, and redirecting to an unvalidated
        one would make this endpoint an open redirect that also carries an error message.
        """
        client_id = params.get("client_id", "")
        if not client_id:
            raise OAuthServerError("invalid_request", "client_id is required.")
        client = self._stores.clients.get(client_id)
        if client is None:
            raise OAuthServerError("invalid_client", "Unknown client_id.", status=401)

        redirect_uri = params.get("redirect_uri", "")
        if not redirect_uri:
            raise OAuthServerError("invalid_request", "redirect_uri is required.")
        if not client.allows(redirect_uri):
            raise OAuthServerError(
                "invalid_request",
                "redirect_uri does not exactly match one registered for this client.",
            )

        if params.get("response_type", "") != "code":
            raise OAuthServerError("unsupported_response_type", "The only supported response_type is 'code'.")

        method = params.get("code_challenge_method", "")
        challenge = params.get("code_challenge", "")
        if not challenge:
            raise OAuthServerError("invalid_request", "code_challenge is required; this server requires PKCE.")
        if method not in CODE_CHALLENGE_METHODS:
            raise OAuthServerError(
                "invalid_request",
                "code_challenge_method must be 'S256'; 'plain' is not a proof of possession.",
            )

        resource = params.get("resource", "")
        if not resource:
            raise OAuthServerError(
                "invalid_target",
                "resource is required, so the token this produces is bound to one audience.",
            )
        if resource.rstrip("/") != self._settings.mcp_resource_url.rstrip("/"):
            raise OAuthServerError("invalid_target", "resource does not name a resource this server protects.")

        scopes = self._validate_scopes(params.get("scope", "").split())
        return AuthorizationRequest(
            client=client,
            redirect_uri=redirect_uri,
            resource=self._settings.mcp_resource_url,
            scopes=scopes,
            code_challenge=challenge,
            code_challenge_method=method,
            state=params.get("state", ""),
        )

    def issue_code(
        self,
        request: AuthorizationRequest,
        *,
        user_id: str,
        tenant_id: str,
        now: int | None = None,
    ) -> str:
        """Mint an authorization code for a consented request and return the plaintext.

        Only the hash is stored, exactly as refresh and verification tokens are, so a read
        of the table yields nothing exchangeable. The tenant is written into the record
        rather than accepted again at the token endpoint, where the client could change it.
        """
        moment = int(time.time()) if now is None else now
        code = secrets.token_urlsafe(CODE_BYTES)
        ttl = int(self._settings.mcp_authorization_code_ttl.total_seconds())
        self._stores.codes.put(
            AuthorizationCodeRecord(
                code_hash=hash_token(code),
                client_id=request.client.client_id,
                user_id=user_id,
                redirect_uri=request.redirect_uri,
                code_challenge=request.code_challenge,
                code_challenge_method=request.code_challenge_method,
                resource=request.resource,
                tenant_id=tenant_id,
                scopes=request.scopes,
                created_at=_iso(moment),
                expires_at=moment + ttl,
            )
        )
        return code

    def record_consent(
        self,
        request: AuthorizationRequest,
        *,
        user_id: str,
        tenant_id: str,
        now: int | None = None,
    ) -> ConsentRecord:
        """Write the standing grant this authorization established, and return it."""
        moment = int(time.time()) if now is None else now
        record = ConsentRecord(
            consent_id=uuid.uuid4().hex,
            user_id=user_id,
            client_id=request.client.client_id,
            tenant_id=tenant_id,
            resource=request.resource,
            scopes=request.scopes,
            granted_at=_iso(moment),
            updated_at=_iso(moment),
        )
        self._stores.consents.put(record)
        return record

    def exchange_code(self, params: Mapping[str, str], *, now: int | None = None) -> dict[str, Any]:
        """Exchange an authorization code for an access token, or raise `OAuthServerError`.

        The code is spent first, before anything else is checked, so a failed PKCE or
        redirect comparison still burns it: a code that survived a wrong guess would let an
        attacker holding an intercepted code retry until their own verifier was accepted.
        """
        moment = int(time.time()) if now is None else now
        code = params.get("code", "")
        if not code:
            raise OAuthServerError("invalid_request", "code is required.")

        record = self._stores.codes.consume(hash_token(code))
        if record is None:
            raise OAuthServerError("invalid_grant", "The authorization code is unknown, expired or already used.")
        if record.expires_at <= moment:
            raise OAuthServerError("invalid_grant", "The authorization code is unknown, expired or already used.")

        client_id = params.get("client_id", "")
        if not constant_time_equals(client_id, record.client_id):
            raise OAuthServerError("invalid_grant", "This code was not issued to this client.")

        redirect_uri = params.get("redirect_uri", "")
        if not constant_time_equals(redirect_uri, record.redirect_uri):
            raise OAuthServerError("invalid_grant", "redirect_uri does not match the one this code was issued for.")

        verifier = params.get("code_verifier", "")
        if not verifier:
            raise OAuthServerError("invalid_request", "code_verifier is required; this server requires PKCE.")
        if not constant_time_equals(pkce_challenge(verifier), record.code_challenge):
            raise OAuthServerError("invalid_grant", "The code_verifier does not match the code_challenge.")

        resource = params.get("resource", "")
        if resource and resource.rstrip("/") != record.resource.rstrip("/"):
            raise OAuthServerError("invalid_target", "resource does not match the one this code was issued for.")

        client = self._stores.clients.get(record.client_id)
        if client is None:
            raise OAuthServerError("invalid_client", "The client this code was issued to no longer exists.", status=401)
        if not client.first_party:
            self._stores.clients.touch(
                client.client_id,
                expires_at=moment + int(self._settings.mcp_client_ttl.total_seconds()),
            )

        return self._issue_tokens(record, now=moment)

    def _issue_tokens(self, record: AuthorizationCodeRecord, *, now: int) -> dict[str, Any]:
        """Mint the access token, and a rotating refresh token where a store exists.

        The refresh half reuses the existing family model unchanged: rotation with reuse
        detection is the same problem here as for a browser session, and a parallel
        implementation would be a second thing to get right.
        """
        access = self._tokens.mint_access_token(
            record.user_id,
            claims={
                "scope": " ".join(record.scopes),
                "client_id": record.client_id,
                self._settings.mcp_tenant_claim: record.tenant_id,
            },
            audience=record.resource,
            now=now,
        )
        body: dict[str, Any] = {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": int(self._settings.access_token_ttl.total_seconds()),
            "scope": " ".join(record.scopes),
        }
        refresh = self._start_refresh_family(record)
        if refresh is not None:
            body["refresh_token"] = refresh
        return body

    def _start_refresh_family(self, record: AuthorizationCodeRecord) -> str | None:
        """Begin a refresh family for this grant, or `None` when no store is configured."""
        if self._flows is None:
            return None
        issued = self._flows.sessions.start_family(record.user_id, device=f"mcp:{record.client_id}")
        return issued.token

    def refresh(self, params: Mapping[str, str], *, now: int | None = None) -> dict[str, Any]:
        """Rotate a refresh token and mint a new access token for the same grant.

        Rotation and reuse detection are the existing `SessionService`'s, so a replayed
        token revokes its whole family here exactly as it does for a browser session.
        """
        moment = int(time.time()) if now is None else now
        token = params.get("refresh_token", "")
        if not token:
            raise OAuthServerError("invalid_request", "refresh_token is required.")
        if self._flows is None:
            raise OAuthServerError(
                "unsupported_grant_type",
                "This deployment mounts no refresh token store, so refresh_token is not offered.",
            )
        scopes = self._validate_scopes(params.get("scope", "").split())
        resource = params.get("resource", "") or self._settings.mcp_resource_url
        if resource.rstrip("/") != self._settings.mcp_resource_url.rstrip("/"):
            raise OAuthServerError("invalid_target", "resource does not name a resource this server protects.")

        outcome = self._flows.sessions.rotate(token)
        if outcome.issued is None:
            raise OAuthServerError("invalid_grant", "The refresh token is unknown, expired, spent or revoked.")

        tenant = self._tenant_for_refresh(outcome.user_id, params.get("client_id", ""))
        access = self._tokens.mint_access_token(
            outcome.user_id,
            claims={
                "scope": " ".join(scopes),
                "client_id": params.get("client_id", ""),
                self._settings.mcp_tenant_claim: tenant,
            },
            audience=self._settings.mcp_resource_url,
            now=moment,
        )
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": int(self._settings.access_token_ttl.total_seconds()),
            "refresh_token": outcome.issued.token,
            "scope": " ".join(scopes),
        }

    def _tenant_for_refresh(self, user_id: str, client_id: str) -> str:
        """The tenant a refreshed token is bound to: the one the user consented to.

        Read back from the consent record rather than taken from the request, so a refresh
        cannot quietly move a long-lived grant to a tenant the user never approved.
        """
        for consent in self._stores.consents.list_for_user(user_id):
            if consent.client_id == client_id:
                return consent.tenant_id
        return ""

    def revoke(self, params: Mapping[str, str]) -> None:
        """Revoke a refresh token per RFC 7009, answering 200 whatever happened.

        A revocation endpoint that distinguished an unknown token from a revoked one would
        be a token oracle, so an unknown value is accepted silently. The RFC requires this.
        """
        token = params.get("token", "")
        if not token or self._flows is None:
            return
        try:
            self._flows.sessions.revoke_presented(token)
        except Exception:
            _log.warning("oauth_server_revoke_failed", exc_info=True)


def _iso(moment: int) -> str:
    """An RFC 3339 timestamp for an epoch second, matching the other identity records."""
    from datetime import UTC, datetime

    return datetime.fromtimestamp(moment, UTC).isoformat().replace("+00:00", "Z")


def _consent_signature(settings: IdentitySettings, payload: Mapping[str, str]) -> str:
    """An HMAC binding a consent form to the request it approves.

    The form carries the authorization parameters through the user's browser, so without
    this a user could be induced to post a form whose scopes or tenant differ from the ones
    they were shown. Keyed on the signing material the deployment already holds.
    """
    import hmac

    material = "|".join(f"{key}={payload.get(key, '')}" for key in sorted(payload))
    key = (settings.totp_master_key or settings.issuer).encode("utf-8")
    return hmac.new(key, material.encode("utf-8"), hashlib.sha256).hexdigest()


def default_consent_renderer(context: ConsentContext) -> Any:
    """Render the built-in consent screen: one plain self-contained HTML form.

    Deliberately minimal and unstyled. It exists so a product has a working authorization
    screen on day one, not so it ships this one; `consent_renderer` replaces it wholesale.
    """
    from fastapi.responses import HTMLResponse

    request = context.request
    client_name = request.client.client_name or request.client.client_id
    scopes = "".join(f"<li><code>{_escape(scope)}</code></li>" for scope in request.scopes)
    if context.tenants:
        options = "".join(
            f'<option value="{_escape(tenant.id)}">{_escape(tenant.name or tenant.id)}</option>'
            for tenant in context.tenants
        )
        tenant_field = f'<label>Workspace<select name="tenant_id" required>{options}</select></label>'
    else:
        tenant_field = "<p>No workspace is available for this account.</p>"
    hidden = "".join(
        f'<input type="hidden" name="{_escape(key)}" value="{_escape(value)}">'
        for key, value in context.form_fields.items()
    )
    body = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Authorize {_escape(client_name)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body>
<h1>Authorize {_escape(client_name)}</h1>
<p><strong>{_escape(client_name)}</strong> is asking to access your account.</p>
<p>It will be able to:</p>
<ul>{scopes}</ul>
<form method="post" action="{_escape(context.form_action)}">
{hidden}
{tenant_field}
<button type="submit" name="decision" value="allow">Allow</button>
<button type="submit" name="decision" value="deny">Deny</button>
</form>
</body></html>"""
    return HTMLResponse(body, headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY"})


def _escape(value: str) -> str:
    """HTML-escape a value bound for the consent page, quotes included.

    Every value on that page is attacker-influenced: a client name comes from an open
    registration endpoint, and the form fields echo query parameters back.
    """
    import html

    return html.escape(value, quote=True)


def build_oauth_server_router(
    settings: IdentitySettings,
    flows: IdentityFlows | None,
    stores: OAuthServerStores,
    *,
    tokens: TokenService,
    prefix: str = "",
    consent_renderer: ConsentRenderer | None = None,
    tenant_resolver: TenantResolver | None = None,
    limits: Callable[..., list[Any]] | None = None,
    subject_resolver: Callable[[Request], str] | None = None,
) -> APIRouter:
    """The OAuth 2.1 authorization server router, mounted behind `mcp_oauth_enabled`.

    Mounted by `build_identity_router` at the issuer's prefix, so every endpoint sits under
    the same issuer the discovery documents advertise. The two `.well-known` documents must
    be reachable with no authorizer, exactly as the OIDC ones are.
    """
    from fastapi import APIRouter
    from fastapi.responses import JSONResponse, RedirectResponse

    _bind_fastapi_request()

    service = OAuthServerService(settings, stores, tokens, flows=flows)
    render = consent_renderer or default_consent_renderer
    metadata = build_authorization_server_metadata(settings)
    resource_metadata = build_protected_resource_metadata(settings)

    router = APIRouter(tags=["identity", "oauth-server"])

    def route_limits(*specs: tuple[str, tuple[int, int], str]) -> list[Any]:
        """The rate limit dependencies for one route, or none when the product supplied no builder."""
        return limits(*specs) if limits is not None else []

    def subject_of(request: Request) -> str:
        """The signed-in user for this request, or an empty string.

        Delegates to the resolver `build_identity_router` passes, which is the same bearer
        and authorizer-context path every other authenticated identity route uses.
        """
        return subject_resolver(request) if subject_resolver is not None else ""

    def error_response(exc: OAuthServerError) -> JSONResponse:
        """The RFC 6749 error body, which is a flat object rather than this package's envelope.

        A client library parses `error` and `error_description` from the top level, so the
        shared envelope would be unreadable to every MCP client that is not this product's.
        """
        return JSONResponse(
            {"error": exc.error, "error_description": exc.description},
            status_code=exc.status,
            headers={"Cache-Control": "no-store"},
        )

    @router.get(f"{prefix}{AUTHORIZATION_SERVER_METADATA_PATH}", include_in_schema=False)
    async def authorization_server_metadata() -> JSONResponse:
        """Serve the RFC 8414 authorization server metadata, anonymously and cached."""
        return JSONResponse(metadata, headers={"Cache-Control": "public, max-age=3600"})

    @router.get(f"{prefix}{PROTECTED_RESOURCE_METADATA_PATH}", include_in_schema=False)
    async def protected_resource_metadata() -> JSONResponse:
        """Serve the RFC 9728 protected resource metadata, anonymously and cached."""
        return JSONResponse(resource_metadata, headers={"Cache-Control": "public, max-age=3600"})

    @router.get(
        f"{prefix}{AUTHORIZE_PATH}",
        include_in_schema=False,
        dependencies=route_limits(("oauth_authorize", AUTHORIZE_IP_LIMIT, "ip")),
    )
    async def authorize(request: Request) -> Any:
        """Validate an authorization request and render the consent screen.

        A refusal before the client and redirect URI are known is answered as JSON rather
        than a redirect: there is no validated place to send the user, and redirecting to an
        unvalidated URI is the open redirect this check exists to prevent.
        """
        try:
            parsed = service.parse_authorization_request(dict(request.query_params))
        except OAuthServerError as exc:
            return error_response(exc)

        user_id = subject_of(request)
        if not user_id:
            return JSONResponse(
                {
                    "error": "login_required",
                    "error_description": "Sign in to this product, then retry the authorization request.",
                },
                status_code=401,
                headers={"Cache-Control": "no-store"},
            )

        tenants = tuple(tenant_resolver(user_id)) if tenant_resolver is not None else ()
        fields = {
            "response_type": "code",
            "client_id": parsed.client.client_id,
            "redirect_uri": parsed.redirect_uri,
            "resource": parsed.resource,
            "scope": " ".join(parsed.scopes),
            "state": parsed.state,
            "code_challenge": parsed.code_challenge,
            "code_challenge_method": parsed.code_challenge_method,
        }
        fields["signature"] = _consent_signature(settings, fields)
        return render(
            ConsentContext(
                request=parsed,
                user_id=user_id,
                tenants=tenants,
                form_action=f"{prefix}{CONSENT_PATH}",
                form_fields=fields,
            )
        )

    @router.post(
        f"{prefix}{CONSENT_PATH}",
        include_in_schema=False,
        dependencies=route_limits(("oauth_authorize", AUTHORIZE_IP_LIMIT, "ip")),
    )
    async def consent(request: Request) -> Any:
        """Act on the consent decision and redirect back to the client with a code.

        The form's parameters are re-validated from scratch and their HMAC re-checked, so a
        form posted from elsewhere, or one whose scope or tenant was edited in the browser,
        cannot mint a code for something the user was never shown.
        """
        params = await _form_params(request)
        signature = params.pop("signature", "")
        decision = params.pop("decision", "")
        tenant_id = params.pop("tenant_id", "")

        expected = _consent_signature(settings, params)
        if not constant_time_equals(signature, expected):
            return error_response(
                OAuthServerError("invalid_request", "The consent form did not match the request it approves.")
            )

        try:
            parsed = service.parse_authorization_request(params)
        except OAuthServerError as exc:
            return error_response(exc)

        user_id = subject_of(request)
        if not user_id:
            return JSONResponse(
                {"error": "login_required", "error_description": "Sign in and retry the authorization request."},
                status_code=401,
                headers={"Cache-Control": "no-store"},
            )

        if decision != "allow":
            return RedirectResponse(
                _redirect_with(
                    parsed.redirect_uri,
                    {"error": "access_denied", "error_description": "The user declined.", "state": parsed.state},
                ),
                status_code=303,
            )

        if tenant_resolver is not None:
            allowed = {tenant.id for tenant in tenant_resolver(user_id)}
            if tenant_id not in allowed:
                return error_response(
                    OAuthServerError("invalid_request", "That workspace is not one this account may grant access to.")
                )

        service.record_consent(parsed, user_id=user_id, tenant_id=tenant_id)
        code = service.issue_code(parsed, user_id=user_id, tenant_id=tenant_id)
        return RedirectResponse(
            _redirect_with(parsed.redirect_uri, {"code": code, "state": parsed.state}),
            status_code=303,
        )

    @router.post(
        f"{prefix}{TOKEN_PATH}",
        include_in_schema=False,
        dependencies=route_limits(("oauth_token", TOKEN_IP_LIMIT, "ip")),
    )
    async def token(request: Request) -> JSONResponse:
        """Exchange an authorization code, or rotate a refresh token.

        `application/x-www-form-urlencoded` as RFC 6749 requires, never JSON: every OAuth
        client library posts a form here, and accepting JSON as well would be a second
        parsing path into the most security-sensitive endpoint on the server.
        """
        params = await _form_params(request)
        grant_type = params.get("grant_type", "")
        try:
            if grant_type == "authorization_code":
                body = service.exchange_code(params)
            elif grant_type == "refresh_token":
                body = service.refresh(params)
            else:
                raise OAuthServerError(
                    "unsupported_grant_type",
                    "grant_type must be 'authorization_code' or 'refresh_token'.",
                )
        except OAuthServerError as exc:
            return error_response(exc)
        return JSONResponse(body, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})

    @router.post(
        f"{prefix}{REGISTER_CLIENT_PATH}",
        include_in_schema=False,
        dependencies=route_limits(("oauth_register_client", REGISTER_CLIENT_IP_LIMIT, "ip")),
    )
    async def register_client(request: Request) -> JSONResponse:
        """Register a public PKCE client per RFC 7591.

        Open by design: an MCP client that cannot register cannot connect, and there is no
        human in the loop to pre-provision one. The rate limit and the client TTL are what
        keep an open endpoint from becoming an unbounded table.
        """
        if not settings.mcp_registration_enabled:
            return error_response(
                OAuthServerError(
                    "invalid_request",
                    "Dynamic client registration is closed on this deployment.",
                    status=403,
                )
            )
        try:
            payload = await request.json()
        except Exception:
            return error_response(OAuthServerError("invalid_client_metadata", "The request body must be JSON."))
        if not isinstance(payload, dict):
            return error_response(
                OAuthServerError("invalid_client_metadata", "The request body must be a JSON object.")
            )
        try:
            body = service.register_client(payload)
        except OAuthServerError as exc:
            return error_response(exc)
        return JSONResponse(body, status_code=201, headers={"Cache-Control": "no-store"})

    @router.post(
        f"{prefix}{REVOKE_PATH}",
        include_in_schema=False,
        dependencies=route_limits(("oauth_token", TOKEN_IP_LIMIT, "ip")),
    )
    async def revoke(request: Request) -> JSONResponse:
        """Revoke a refresh token per RFC 7009, always answering 200.

        An unknown token is accepted silently, because distinguishing it from a live one
        would turn this endpoint into an oracle for guessing tokens.
        """
        service.revoke(await _form_params(request))
        return JSONResponse({}, headers={"Cache-Control": "no-store"})

    _ = (
        authorization_server_metadata,
        protected_resource_metadata,
        authorize,
        consent,
        token,
        register_client,
        revoke,
    )
    return router


OAUTH_SERVER_ROUTE_RESPONSES: Final[dict[tuple[str, str], dict[int, str]]] = {
    ("GET", AUTHORIZE_PATH): {
        200: "The consent screen is rendered",
        303: "The browser is redirected back to the client with a code or an error",
        400: "The authorization request is malformed, or its PKCE, scope or resource is refused",
        401: "The user is not signed in, or the client is unknown",
    },
    ("POST", TOKEN_PATH): {
        200: "An access token, and a refresh token where one is offered",
        400: "The grant is refused: a spent code, a PKCE mismatch or a resource mismatch",
        401: "The client is unknown",
    },
    ("POST", REGISTER_CLIENT_PATH): {
        201: "The client is registered and its client_id returned",
        400: "The client metadata is refused",
        403: "Dynamic client registration is closed on this deployment",
        429: "Too many registrations from this address",
    },
    ("POST", REVOKE_PATH): {200: "Accepted, whether or not the token existed"},
}
