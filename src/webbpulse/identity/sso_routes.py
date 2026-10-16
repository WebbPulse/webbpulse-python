"""The single sign-on HTTP routes, mounted onto the identity router when an `SsoService` is given.

Kept apart from `sso.py` so the service stays importable without FastAPI. The callback
path carries the protocol, so a SAML assertion consumer can mount beside the OIDC one.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Callable

    from fastapi import APIRouter
    from fastapi.responses import JSONResponse
    from starlette.requests import Request

    from webbpulse.identity.settings import IdentitySettings
    from webbpulse.identity.sso import SsoService

__all__ = [
    "SSO_OIDC_CALLBACK_PATH",
    "SSO_ROUTE_RESPONSES",
    "SSO_START_IP_LIMIT",
    "SSO_START_PATH",
    "register_sso_routes",
]

SSO_START_PATH: Final = "/sso/start"
SSO_OIDC_CALLBACK_PATH: Final = "/sso/oidc/{connection_id}/callback"

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
    """Add `POST <prefix>/sso/start` and the OIDC callback.

    The start answers JSON because a sign-in page calls it over `fetch` once the user has
    typed an address; it also sets the cookie binding the state to this browser. The
    callback always answers a 303 back to the frontend.
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
    from webbpulse.identity.sso import SSO_PROTOCOL_OIDC, SsoRejected

    _bind_fastapi_request()

    binding_samesite = "none" if settings.cookie_samesite == "none" else "lax"

    def binding_cookie_kwargs() -> dict[str, Any]:
        """The refresh cookie's path and domain, so the callback under the prefix sees it."""
        kwargs: dict[str, Any] = {"path": settings.cookie_path}
        if settings.cookie_domain:
            kwargs["domain"] = settings.cookie_domain
        return kwargs

    def set_binding_cookie(response: Any, secret: str) -> Any:
        """Hand the browser the secret that proves it started this sign-in."""
        response.set_cookie(
            OAUTH_LINK_BINDING_COOKIE,
            secret,
            max_age=OAUTH_STATE_TTL_SECONDS,
            httponly=True,
            secure=settings.cookie_secure,
            samesite=binding_samesite,
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
        return set_binding_cookie(response, secret)

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

        ip, user_agent = context(request)
        code = request.query_params.get("code", "")
        issuer = request.query_params.get("iss", "")
        try:
            connection = await run_sync(lambda: sso.connection(connection_id))
            identity = await run_sync(
                lambda: sso.identity_from_oidc_callback(connection, code=code, issuer=issuer, state_record=record)
            )
            user, _outcome = await run_sync(lambda: sso.resolve_login(connection, identity))
            result = await run_sync(
                lambda: flows.issue_for_sso(
                    user,
                    connection_id=connection.connection_id,
                    protocol=SSO_PROTOCOL_OIDC,
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

    _ = (sso_start, sso_oidc_callback)


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
}
"""The statuses the single sign-on routes really answer, keyed by method and unprefixed path.

The callback never answers 200: success carries `sso=1` and failure `sso_error=<code>`.
"""
