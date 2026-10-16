"""The OIDC leg of single sign-on: discovery, the authorization URL, and ID token verification.

Every provider URL is checked by a `UrlGuard` before it is fetched, so a tenant cannot
point its connection at an address inside the network. Needs the `sso` extra at call time.
"""

from __future__ import annotations

import base64
import ipaddress
import logging
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Final, Protocol
from urllib.parse import quote, urlencode, urlsplit

from webbpulse.identity.oauth import HttpxClient, _as_bool
from webbpulse.identity.sso import SSO_PROTOCOL_OIDC, SsoIdentity, SsoRejected
from webbpulse.identity.storage import constant_time_equals

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Iterable, Mapping

    from webbpulse.identity.crypto import SealedSecret, TotpCipher
    from webbpulse.identity.oauth import HttpClient
    from webbpulse.identity.sso import OidcConnectionConfig, SsoConnection

__all__ = [
    "OIDC_CLIENT_SECRET_PURPOSE",
    "OIDC_DISCOVERY_PATH",
    "OIDC_METADATA_TTL_SECONDS",
    "SUPPORTED_ID_TOKEN_ALGORITHMS",
    "OidcProviderMetadata",
    "OidcSsoClient",
    "PublicUrlGuard",
    "UrlGuard",
    "open_oidc_client_secret",
    "seal_oidc_client_secret",
]

_log = logging.getLogger(__name__)

OIDC_DISCOVERY_PATH: Final = "/.well-known/openid-configuration"

OIDC_CLIENT_SECRET_PURPOSE: Final = "sso-oidc-client-secret"
"""The cipher purpose a connection's client secret is sealed under, bound to its connection id."""

OIDC_METADATA_TTL_SECONDS: Final = 3600

SUPPORTED_ID_TOKEN_ALGORITHMS: Final[tuple[str, ...]] = (
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
)
"""Asymmetric algorithms only: `none` and the HMAC family are never accepted."""

_RESERVED_CLAIMS: Final = frozenset({"nonce", "at_hash", "c_hash", "s_hash", "sid", "auth_time", "acr", "amr"})

type Resolver = Callable[[str], Iterable[str]]


def seal_oidc_client_secret(cipher: TotpCipher, *, connection_id: str, client_secret: str) -> SealedSecret:
    """Seal a connection's client secret for storage, bound to that connection id."""
    return cipher.seal(client_secret.encode("utf-8"), user_id=connection_id, purpose=OIDC_CLIENT_SECRET_PURPOSE)


def open_oidc_client_secret(cipher: TotpCipher, *, connection_id: str, sealed: SealedSecret) -> str:
    """Open a sealed client secret, refusing with a 503 when it does not authenticate."""
    try:
        return cipher.open(sealed, user_id=connection_id, purpose=OIDC_CLIENT_SECRET_PURPOSE).decode("utf-8")
    except Exception as exc:
        _log.error(
            "An SSO client secret could not be opened.",
            extra={"event": "sso.secret_unreadable", "connection_id": connection_id, "reason": type(exc).__name__},
        )
        raise SsoRejected(
            "That single sign-on connection is not available.",
            error_code="SSO_CONNECTION_UNAVAILABLE",
            status_code=503,
        ) from exc


class UrlGuard(Protocol):
    """Decides whether a provider URL may be fetched, raising `SsoRejected` when not."""

    def __call__(self, url: str) -> None:
        """Return when `url` is safe to fetch, or raise `SsoRejected`."""
        ...


def _system_resolver(host: str) -> list[str]:
    """Every address the system resolver gives for a host."""
    return [str(info[4][0]) for info in socket.getaddrinfo(host, None)]


class PublicUrlGuard:
    """The default guard: HTTPS only, and every resolved address must be public.

    Refuses loopback, private, link-local, reserved and multicast addresses, so a tenant's
    issuer cannot reach the instance metadata service or anything else inside the network.
    `trusted_hosts` skips both checks for named hosts, for a local test provider.
    """

    def __init__(self, *, trusted_hosts: Iterable[str] = (), resolver: Resolver | None = None) -> None:
        """Hold the trusted host names and the resolver used to look addresses up."""
        self._trusted = frozenset(host.lower() for host in trusted_hosts)
        self._resolver: Resolver = resolver if resolver is not None else _system_resolver

    def __call__(self, url: str) -> None:
        """Return when `url` is HTTPS to a public address, or raise `SsoRejected`."""
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if host and host in self._trusted:
            return
        if parts.scheme != "https" or not host or parts.username or parts.password:
            raise _unsafe_url(url, "scheme")
        try:
            addresses = [ipaddress.ip_address(address.split("%", 1)[0]) for address in self._resolver(host)]
        except (OSError, ValueError) as exc:
            raise _unsafe_url(url, "unresolvable") from exc
        if not addresses:
            raise _unsafe_url(url, "unresolvable")
        for address in addresses:
            if not address.is_global or address.is_multicast:
                raise _unsafe_url(url, "private")


def _unsafe_url(url: str, reason: str) -> SsoRejected:
    """The refusal for a provider URL the guard will not fetch, logged with its host only."""
    _log.warning(
        "SSO provider URL refused.",
        extra={"event": "sso.url_refused", "host": urlsplit(url).hostname or "", "reason": reason},
    )
    return SsoRejected(
        "That single sign-on connection is not available.",
        error_code="SSO_PROVIDER_URL_REFUSED",
        status_code=502,
    )


@dataclass(frozen=True, slots=True)
class OidcProviderMetadata:
    """The parts of a provider's discovery document this module uses."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str = ""
    id_token_signing_alg_values_supported: tuple[str, ...] = ("RS256",)
    authorization_response_iss_parameter_supported: bool = False


class OidcSsoClient:
    """Discovery, the authorization URL, and the code exchange for OIDC connections.

    Discovery documents are cached per issuer for `metadata_ttl` seconds. JWKS are fetched
    per verification, so a key rotation needs no invalidation.
    """

    def __init__(
        self,
        *,
        cipher: TotpCipher,
        http_client: HttpClient | None = None,
        url_guard: UrlGuard | None = None,
        leeway: timedelta | float = 0,
        metadata_ttl: int = OIDC_METADATA_TTL_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """Hold the cipher, the HTTP client, the URL guard, the clock leeway and the cache TTL."""
        self._cipher = cipher
        self._http = http_client if http_client is not None else HttpxClient()
        self._guard: UrlGuard = url_guard if url_guard is not None else PublicUrlGuard()
        self._leeway = leeway.total_seconds() if isinstance(leeway, timedelta) else float(leeway)
        self._metadata_ttl = metadata_ttl
        self._clock = clock
        self._metadata: dict[str, tuple[float, OidcProviderMetadata]] = {}

    def metadata(self, config: OidcConnectionConfig) -> OidcProviderMetadata:
        """The provider's discovery document, fetched through the guard and cached.

        The document's `issuer` must equal the configured issuer exactly, and every endpoint
        it names is checked by the guard as well.
        """
        issuer = config.issuer.rstrip("/")
        cached = self._metadata.get(issuer)
        now = self._clock()
        if cached is not None and cached[0] > now:
            return cached[1]

        url = f"{issuer}{OIDC_DISCOVERY_PATH}"
        self._guard(url)
        response = self._http.get_json(url, headers={"accept": "application/json"})
        body = response.json_body if response.ok and isinstance(response.json_body, dict) else None
        if body is None or str(body.get("issuer", "")).rstrip("/") != issuer:
            _log.warning(
                "SSO discovery failed.",
                extra={"event": "sso.discovery_failed", "status": response.status_code},
            )
            raise SsoRejected(
                "That single sign-on connection is not available.",
                error_code="SSO_DISCOVERY_FAILED",
                status_code=502,
            )

        metadata = OidcProviderMetadata(
            issuer=str(body["issuer"]),
            authorization_endpoint=_required_url(body, "authorization_endpoint"),
            token_endpoint=_required_url(body, "token_endpoint"),
            jwks_uri=_required_url(body, "jwks_uri"),
            userinfo_endpoint=str(body.get("userinfo_endpoint", "") or ""),
            id_token_signing_alg_values_supported=tuple(
                str(value) for value in body.get("id_token_signing_alg_values_supported") or ("RS256",)
            ),
            authorization_response_iss_parameter_supported=_as_bool(
                body.get("authorization_response_iss_parameter_supported")
            ),
        )
        for endpoint in (metadata.token_endpoint, metadata.jwks_uri):
            self._guard(endpoint)
        if metadata.userinfo_endpoint:
            self._guard(metadata.userinfo_endpoint)
        if urlsplit(metadata.authorization_endpoint).scheme not in {"https", urlsplit(issuer).scheme}:
            raise _unsafe_url(metadata.authorization_endpoint, "scheme")
        self._metadata[issuer] = (now + self._metadata_ttl, metadata)
        return metadata

    def authorization_url(
        self,
        connection: SsoConnection,
        *,
        redirect_uri: str,
        state: str,
        nonce: str,
        code_challenge: str,
        login_hint: str = "",
    ) -> str:
        """The provider URL that starts the code flow, with PKCE `S256` and a nonce."""
        config = _oidc_config(connection)
        metadata = self.metadata(config)
        params: dict[str, str] = {
            "client_id": config.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(config.scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            **dict(config.extra_authorize_params),
        }
        if login_hint:
            params["login_hint"] = login_hint
        separator = "&" if "?" in metadata.authorization_endpoint else "?"
        return f"{metadata.authorization_endpoint}{separator}{urlencode(params)}"

    def identity_from_callback(
        self,
        connection: SsoConnection,
        *,
        code: str,
        issuer: str,
        redirect_uri: str,
        code_verifier: str,
        nonce: str,
    ) -> SsoIdentity:
        """Check the callback's `iss`, exchange the code, and verify the ID token.

        `iss` must match the connection's issuer whenever it is present, and must be present
        when the provider advertises RFC 9207 support, which stops a mix-up between tenants.
        """
        config = _oidc_config(connection)
        metadata = self.metadata(config)
        if issuer:
            if not constant_time_equals(issuer.rstrip("/"), metadata.issuer.rstrip("/")):
                raise _invalid("SSO_ISSUER_MISMATCH", connection, "iss parameter mismatch")
        elif metadata.authorization_response_iss_parameter_supported:
            raise _invalid("SSO_ISSUER_MISMATCH", connection, "iss parameter missing")
        if not code:
            raise SsoRejected("The identity provider returned no authorization code.", error_code="SSO_CODE_MISSING")

        token_body = self._exchange(
            connection, metadata, code=code, redirect_uri=redirect_uri, code_verifier=code_verifier
        )
        id_token = token_body.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            raise _invalid("SSO_EXCHANGE_FAILED", connection, "no id_token")
        claims = self._verify_id_token(connection, metadata, id_token, nonce=nonce)

        email = str(claims.get("email", "") or "").strip().lower()
        email_verified = _as_bool(claims.get("email_verified"))
        name = str(claims.get("name", "") or "")
        access_token = token_body.get("access_token")
        if not email and metadata.userinfo_endpoint and isinstance(access_token, str) and access_token:
            email, email_verified, name = self._userinfo(
                connection, metadata, access_token, subject=str(claims["sub"]), name=name
            )

        return SsoIdentity(
            connection_id=connection.connection_id,
            protocol=SSO_PROTOCOL_OIDC,
            subject=str(claims["sub"]),
            email=email,
            email_verified=email_verified,
            name=name,
            attributes={key: value for key, value in claims.items() if key not in _RESERVED_CLAIMS},
        )

    def _exchange(
        self,
        connection: SsoConnection,
        metadata: OidcProviderMetadata,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> Mapping[str, Any]:
        """Trade the code for the token response, authenticating as the connection's client."""
        config = _oidc_config(connection)
        secret = open_oidc_client_secret(
            self._cipher, connection_id=connection.connection_id, sealed=config.sealed_client_secret
        )
        data: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        }
        headers: dict[str, str] = {"Accept": "application/json"}
        if config.token_endpoint_auth_method == "client_secret_post":
            data["client_id"] = config.client_id
            data["client_secret"] = secret
        else:
            pair = f"{quote(config.client_id, safe='')}:{quote(secret, safe='')}".encode()
            headers["Authorization"] = f"Basic {base64.b64encode(pair).decode('ascii')}"

        self._guard(metadata.token_endpoint)
        response = self._http.post_form(metadata.token_endpoint, data=data, headers=headers)
        body = response.json_body if isinstance(response.json_body, dict) else {}
        if not response.ok or body.get("error"):
            _log.warning(
                "SSO token exchange failed.",
                extra={
                    "event": "sso.exchange_failed",
                    "connection_id": connection.connection_id,
                    "status": response.status_code,
                    "error": str(body.get("error", ""))[:64],
                },
            )
            raise SsoRejected("That sign-in could not be completed. Try again.", error_code="SSO_EXCHANGE_FAILED")
        return body

    def _verify_id_token(
        self,
        connection: SsoConnection,
        metadata: OidcProviderMetadata,
        id_token: str,
        *,
        nonce: str,
    ) -> Mapping[str, Any]:
        """Verify the ID token's signature, `iss`, `aud`, `azp`, `exp` and nonce.

        The algorithm must be asymmetric, advertised by the provider, and match the key. The
        nonce is compared after the signature and never before.
        """
        import jwt

        config = _oidc_config(connection)
        try:
            header = jwt.get_unverified_header(id_token)
            algorithm = str(header.get("alg", ""))
            allowed = set(SUPPORTED_ID_TOKEN_ALGORITHMS) & set(metadata.id_token_signing_alg_values_supported)
            if algorithm not in allowed:
                raise ValueError("unsupported algorithm")
            key = self._signing_key(metadata, str(header.get("kid", "")), algorithm)
            claims = jwt.decode(
                id_token,
                key,
                algorithms=[algorithm],
                audience=config.client_id,
                issuer=metadata.issuer,
                leeway=self._leeway,
                options={"require": ["exp", "iat", "sub", "aud", "iss"]},
            )
        except SsoRejected:
            raise
        except Exception as exc:
            raise _invalid("SSO_ID_TOKEN_INVALID", connection, type(exc).__name__) from exc

        audience = claims.get("aud")
        if isinstance(audience, list) and len(audience) > 1 and claims.get("azp") != config.client_id:
            raise _invalid("SSO_ID_TOKEN_INVALID", connection, "azp mismatch")
        if not str(claims.get("sub", "")):
            raise _invalid("SSO_ID_TOKEN_INVALID", connection, "empty sub")
        if not constant_time_equals(str(claims.get("nonce", "")), nonce):
            raise _invalid("SSO_NONCE_MISMATCH", connection, "nonce mismatch")
        return claims

    def _signing_key(self, metadata: OidcProviderMetadata, kid: str, algorithm: str) -> Any:
        """The provider's public key for `kid`, fetched from its JWKS through the guard.

        A JWKS with a single key accepts a token with no `kid`. A key whose own `alg`
        disagrees with the token's is refused.
        """
        import jwt

        self._guard(metadata.jwks_uri)
        response = self._http.get_json(metadata.jwks_uri, headers={"accept": "application/json"})
        keys = response.json_body.get("keys") if response.ok and isinstance(response.json_body, dict) else None
        if not isinstance(keys, list):
            raise ValueError("unreadable jwks")
        candidates = [entry for entry in keys if isinstance(entry, dict) and entry.get("use", "sig") == "sig"]
        if kid:
            candidates = [entry for entry in candidates if str(entry.get("kid", "")) == kid]
        if len(candidates) != 1:
            raise ValueError("no unique signing key")
        entry = candidates[0]
        if entry.get("alg") and str(entry["alg"]) != algorithm:
            raise ValueError("key algorithm mismatch")
        return jwt.PyJWK.from_dict(dict(entry), algorithm=algorithm).key

    def _userinfo(
        self,
        connection: SsoConnection,
        metadata: OidcProviderMetadata,
        access_token: str,
        *,
        subject: str,
        name: str,
    ) -> tuple[str, bool, str]:
        """The email from userinfo, for a provider that leaves it out of the ID token.

        The userinfo `sub` must equal the ID token's, or the answer is ignored.
        """
        self._guard(metadata.userinfo_endpoint)
        response = self._http.get_json(
            metadata.userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}", "accept": "application/json"},
        )
        body = response.json_body if response.ok and isinstance(response.json_body, dict) else {}
        if str(body.get("sub", "")) != subject:
            return "", False, name
        return (
            str(body.get("email", "") or "").strip().lower(),
            _as_bool(body.get("email_verified")),
            name or str(body.get("name", "") or ""),
        )


def _oidc_config(connection: SsoConnection) -> OidcConnectionConfig:
    """The connection's OIDC settings, refusing a connection that has none."""
    if connection.oidc is None:
        raise SsoRejected(
            "That single sign-on connection is not available.",
            error_code="SSO_PROTOCOL_UNSUPPORTED",
            status_code=501,
        )
    return connection.oidc


def _required_url(body: Mapping[str, Any], key: str) -> str:
    """A required endpoint from a discovery document, refusing when it is absent."""
    value = body.get(key)
    if not isinstance(value, str) or not value:
        raise SsoRejected(
            "That single sign-on connection is not available.",
            error_code="SSO_DISCOVERY_FAILED",
            status_code=502,
        )
    return value


def _invalid(error_code: str, connection: SsoConnection, reason: str) -> SsoRejected:
    """The generic refusal for a callback that did not verify, with the reason logged only."""
    _log.warning(
        "SSO callback verification failed.",
        extra={"event": "sso.callback_invalid", "connection_id": connection.connection_id, "reason": reason},
    )
    return SsoRejected("That sign-in could not be completed. Try again.", error_code=error_code)
