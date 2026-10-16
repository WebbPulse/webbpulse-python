"""The single sign-on HTTP routes, mounted onto the identity router when an `SsoService` is given.

Kept apart from `sso.py` so the service stays importable without FastAPI. The callback
path carries the protocol: the OIDC callback and the SAML assertion consumer mount side by
side, and both finish in the same session issuance.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Callable

    from fastapi import APIRouter
    from fastapi.responses import JSONResponse
    from starlette.requests import Request

    from webbpulse.identity.oauth import OAuthStateRecord
    from webbpulse.identity.settings import IdentitySettings
    from webbpulse.identity.sso import SsoConnection, SsoIdentity, SsoService

__all__ = [
    "SSO_OIDC_CALLBACK_PATH",
    "SSO_ROUTE_RESPONSES",
    "SSO_SAML_ACS_MAX_BODY_BYTES",
    "SSO_SAML_ACS_PATH",
    "SSO_SAML_METADATA_PATH",
    "SSO_START_IP_LIMIT",
    "SSO_START_PATH",
    "register_sso_routes",
]

SSO_START_PATH: Final = "/sso/start"
SSO_OIDC_CALLBACK_PATH: Final = "/sso/oidc/{connection_id}/callback"
SSO_SAML_ACS_PATH: Final = "/sso/saml/{connection_id}/acs"
SSO_SAML_METADATA_PATH: Final = "/sso/saml/{connection_id}/metadata"

SSO_SAML_ACS_MAX_BODY_BYTES: Final = 512 * 1024
"""The largest form body the assertion consumer reads before refusing it."""

SSO_START_IP_LIMIT: Final = (20, 900)

_FastAPIRequest: Any = None


def _bind_fastapi_request() -> None:
    """Put `fastapi.Request` in this module's globals, so FastAPI can resolve the annotation."""
    global _FastAPIRequest
    if _FastAPIRequest is None:
        from fastapi import Request as _Request

        _FastAPIRequest = _Request


def register_sso_routes(
    router: APIRouter,
    *,
    prefix: str,
    settings: IdentitySettings,
    sso: SsoService,
    flows: Any,
    limits: Callable[..., list[Any]],
    context: Callable[[Request], tuple[str, str]],
) -> None:
    """Add `POST <prefix>/sso/start`, the OIDC callback, and the SAML routes when SAML is enabled.

    The start answers JSON because a sign-in page calls it over `fetch` once the user has
    typed an address; it also sets the cookie binding the state to this browser. The
    callback and the assertion consumer always answer a 303 back to the frontend.
    """
    from fastapi import Body
    from fastapi.responses import JSONResponse, RedirectResponse

    from webbpulse.identity.flows import LoginRejected, MfaChallengeRequired
    from webbpulse.identity.oauth import (
        OAUTH_LINK_BINDING_COOKIE,
        OAUTH_STATE_TTL_SECONDS,
        OAuthRejected,
        link_binding_matches,
        new_link_binding,
    )
    from webbpulse.identity.oauth_routes import _with_flag, _with_fragment
    from webbpulse.identity.sso import SSO_PROTOCOL_OIDC, SSO_PROTOCOL_SAML, SsoRejected

    _bind_fastapi_request()

    binding_samesite = "none" if settings.cookie_samesite == "none" else "lax"

    def binding_cookie_kwargs() -> dict[str, Any]:
        """The refresh cookie's path and domain, so the callback under the prefix sees it."""
        kwargs: dict[str, Any] = {"path": settings.cookie_path}
        if settings.cookie_domain:
            kwargs["domain"] = settings.cookie_domain
        return kwargs

    def set_binding_cookie(response: Any, secret: str, *, protocol: str = SSO_PROTOCOL_OIDC) -> Any:
        """Hand the browser the secret that proves it started this sign-in.

        A SAML response arrives as a cross-site POST, which a `Lax` cookie never rides, so a
        SAML start sets it `SameSite=None` whenever the cookie is `Secure`.
        """
        samesite = "none" if protocol == SSO_PROTOCOL_SAML and settings.cookie_secure else binding_samesite
        response.set_cookie(
            OAUTH_LINK_BINDING_COOKIE,
            secret,
            max_age=OAUTH_STATE_TTL_SECONDS,
            httponly=True,
            secure=settings.cookie_secure,
            samesite=samesite,
            **binding_cookie_kwargs(),
        )
        return response

    def clear_binding_cookie(response: Any) -> Any:
        """Drop the binding cookie once its state is spent."""
        response.delete_cookie(
            OAUTH_LINK_BINDING_COOKIE,
            secure=settings.cookie_secure,
            httponly=True,
            samesite=binding_samesite,
            **binding_cookie_kwargs(),
        )
        return response

    def refused(request: Request, exc: OAuthRejected) -> JSONResponse:
        """Render a start refusal in the shared error envelope."""
        from webbpulse.http import error_body

        return JSONResponse(
            error_body(exc.status_code, exc.message, request, error_code=exc.error_code),
            status_code=exc.status_code,
        )

    def error_redirect(exc: OAuthRejected, return_to: str = "") -> Any:
        """Send a failed callback back to the frontend with `sso_error=<code>` and nothing else.

        Only this package's own error codes reach the URL, never a provider string.
        """
        target = return_to or settings.frontend_base_url or "/"
        return clear_binding_cookie(RedirectResponse(_with_flag(target, "sso_error", exc.error_code), status_code=303))

    @router.post(
        f"{prefix}{SSO_START_PATH}",
        dependencies=limits(("sso-start", SSO_START_IP_LIMIT, "ip")),
    )
    async def sso_start(request: _FastAPIRequest, payload: dict[str, Any] = Body(default={})) -> Any:
        """Choose a connection from `email`, `tenant` or `connection_id`, and return its URL.

        Answers `{"authorization_url", "connection_id"}`. A lookup that finds no enabled
        connection answers 404 `SSO_CONNECTION_NOT_FOUND`, which the sign-in page reads as
        "use your password".
        """
        from webbpulse.identity.router import run_sync

        secret, digest = new_link_binding()
        try:
            authorization = await run_sync(
                lambda: sso.start(
                    email=str(payload.get("email", "") or ""),
                    tenant_hint=str(payload.get("tenant", "") or ""),
                    connection_id=str(payload.get("connection_id", "") or ""),
                    return_to=str(payload.get("return_to", "") or ""),
                    binding=digest,
                )
            )
        except OAuthRejected as exc:
            return refused(request, exc)
        response = JSONResponse(
            {
                "authorization_url": authorization.authorization_url,
                "connection_id": authorization.connection_id,
            }
        )
        return set_binding_cookie(response, secret, protocol=authorization.protocol)

    async def complete(
        request: Request,
        record: OAuthStateRecord,
        connection_id: str,
        protocol: str,
        verify: Callable[[SsoConnection], SsoIdentity],
    ) -> Any:
        """Verify the provider's answer, resolve the account and issue the session.

        Shared by every protocol once its state is spent and its binding checked. Success
        sets the refresh cookie and redirects with `sso=1`; an MFA challenge puts its ticket
        in the URL fragment.
        """
        from webbpulse.identity.router import run_sync

        ip, user_agent = context(request)
        try:
            connection = await run_sync(lambda: sso.connection(connection_id))
            identity = await run_sync(lambda: verify(connection))
            user, _outcome = await run_sync(lambda: sso.resolve_login(connection, identity))
            result = await run_sync(
                lambda: flows.issue_for_sso(
                    user,
                    connection_id=connection.connection_id,
                    protocol=protocol,
                    ip=ip,
                    user_agent=user_agent,
                )
            )
        except MfaChallengeRequired as challenge:
            body = challenge.challenge.as_body()
            return clear_binding_cookie(
                RedirectResponse(
                    _with_fragment(
                        record.return_to or settings.frontend_base_url,
                        "mfa_ticket",
                        str(body.get("mfa_ticket", "")),
                    ),
                    status_code=303,
                )
            )
        except OAuthRejected as exc:
            return error_redirect(exc, record.return_to)
        except LoginRejected as exc:
            return error_redirect(
                SsoRejected(exc.message, error_code=exc.error_code, status_code=exc.status_code),
                record.return_to,
            )

        redirect = RedirectResponse(
            _with_flag(record.return_to or settings.frontend_base_url, "sso", "1"),
            status_code=303,
        )
        redirect.set_cookie(settings.cookie_name, result.refresh_token, **settings.cookie_kwargs())
        return clear_binding_cookie(redirect)

    @router.get(f"{prefix}{SSO_OIDC_CALLBACK_PATH}")
    async def sso_oidc_callback(request: _FastAPIRequest, connection_id: str) -> Any:
        """Finish an OIDC sign-in: spend the state, verify the identity, issue the session.

        The state is spent before any provider call, must belong to this connection and must
        come back to the browser that started it. Success sets the refresh cookie and
        redirects with `sso=1`; an MFA challenge puts its ticket in the URL fragment.
        """
        from webbpulse.identity.router import run_sync

        state = request.query_params.get("state", "")
        try:
            record = await run_sync(lambda: sso.consume_state(state, connection_id=connection_id))
        except OAuthRejected as exc:
            return error_redirect(exc)

        if not record.binding or not link_binding_matches(record, request.cookies.get(OAUTH_LINK_BINDING_COOKIE, "")):
            return error_redirect(
                SsoRejected("That sign-in attempt is no longer valid. Start again.", error_code="SSO_STATE_INVALID"),
                record.return_to,
            )

        if request.query_params.get("error", ""):
            return error_redirect(SsoRejected("Sign-in was cancelled.", error_code="SSO_CANCELLED"), record.return_to)

        code = request.query_params.get("code", "")
        issuer = request.query_params.get("iss", "")
        return await complete(
            request,
            record,
            connection_id,
            SSO_PROTOCOL_OIDC,
            lambda connection: sso.identity_from_oidc_callback(
                connection, code=code, issuer=issuer, state_record=record
            ),
        )

    _ = (sso_start, sso_oidc_callback)
    if sso.saml_enabled:
        _register_saml_routes(
            router,
            prefix=prefix,
            sso=sso,
            refused=refused,
            error_redirect=error_redirect,
            complete=complete,
        )


def _register_saml_routes(
    router: APIRouter,
    *,
    prefix: str,
    sso: SsoService,
    refused: Callable[[Request, Any], JSONResponse],
    error_redirect: Callable[..., Any],
    complete: Callable[..., Any],
) -> None:
    """Add the SAML metadata and assertion consumer routes.

    The assertion consumer reads the raw form body itself, so no multipart parser is
    needed, and refuses one that is not URL-encoded or is over the size limit.
    """
    from urllib.parse import parse_qs

    from fastapi.responses import Response

    from webbpulse.identity.oauth import OAUTH_LINK_BINDING_COOKIE, OAuthRejected, link_binding_matches
    from webbpulse.identity.sso import SsoRejected

    def malformed() -> SsoRejected:
        """The refusal for a post that is not a SAML HTTP-POST binding form."""
        return SsoRejected("That sign-in could not be completed. Try again.", error_code="SSO_SAML_INVALID")

    @router.get(f"{prefix}{SSO_SAML_METADATA_PATH}")
    async def sso_saml_metadata(request: _FastAPIRequest, connection_id: str) -> Any:
        """The connection's service provider metadata, for the identity provider to import."""
        from webbpulse.identity.router import run_sync

        try:
            document = await run_sync(lambda: sso.saml_metadata(sso.connection(connection_id)))
        except OAuthRejected as exc:
            return refused(request, exc)
        return Response(document, media_type="application/samlmetadata+xml")

    @router.post(f"{prefix}{SSO_SAML_ACS_PATH}")
    async def sso_saml_acs(request: _FastAPIRequest, connection_id: str) -> Any:
        """Finish a SAML sign-in: spend the `RelayState`, verify the response, issue the session.

        The state is spent before the response is verified, must belong to this connection
        and must come back to the browser that started it.
        """
        from webbpulse.identity.router import run_sync

        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/x-www-form-urlencoded":
            return error_redirect(malformed())
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > SSO_SAML_ACS_MAX_BODY_BYTES:
                return error_redirect(malformed())
        try:
            form = parse_qs(bytes(body).decode("ascii"), keep_blank_values=True, max_num_fields=8)
        except ValueError:
            return error_redirect(malformed())
        responses = form.get("SAMLResponse", [])
        relay_states = form.get("RelayState", [])
        if len(responses) != 1 or len(relay_states) != 1:
            return error_redirect(malformed())
        saml_response = responses[0]

        try:
            record = await run_sync(lambda: sso.consume_state(relay_states[0], connection_id=connection_id))
        except OAuthRejected as exc:
            return error_redirect(exc)

        if not record.binding or not link_binding_matches(record, request.cookies.get(OAUTH_LINK_BINDING_COOKIE, "")):
            return error_redirect(
                SsoRejected("That sign-in attempt is no longer valid. Start again.", error_code="SSO_STATE_INVALID"),
                record.return_to,
            )

        return await complete(
            request,
            record,
            connection_id,
            SSO_PROTOCOL_SAML,
            lambda connection: sso.identity_from_saml_response(
                connection, saml_response=saml_response, state_record=record
            ),
        )

    _ = (sso_saml_metadata, sso_saml_acs)


SSO_ROUTE_RESPONSES: Final[dict[tuple[str, str], dict[int, str]]] = {
    ("POST", SSO_START_PATH): {
        404: "No enabled single sign-on connection matches the email, tenant or connection id",
        429: "Too many single sign-on starts from this address",
        501: "The connection's protocol is not available in this deployment",
        502: "The identity provider's discovery document could not be fetched or was refused",
        503: "The connection's client secret could not be opened",
    },
    ("GET", SSO_OIDC_CALLBACK_PATH): {
        303: "The browser is redirected back to the frontend, on success and on failure alike",
    },
    ("GET", SSO_SAML_METADATA_PATH): {
        404: "No enabled single sign-on connection has that id",
        501: "The connection is not a configured SAML connection",
    },
    ("POST", SSO_SAML_ACS_PATH): {
        303: "The browser is redirected back to the frontend, on success and on failure alike",
    },
}
"""The statuses the single sign-on routes really answer, keyed by method and unprefixed path.

The callback and the assertion consumer never answer 200: success carries `sso=1` and failure `sso_error=<code>`.
"""
