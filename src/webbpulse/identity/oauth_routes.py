"""The six OAuth HTTP routes, mounted onto the identity router.

Kept apart from `router.py` so each milestone mounts its own routes, and apart from
`oauth.py` so the service stays importable without FastAPI.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Callable

    from fastapi import APIRouter
    from fastapi.responses import JSONResponse
    from starlette.requests import Request

    from webbpulse.identity.oauth import OAuthService
    from webbpulse.identity.service import TokenService
    from webbpulse.identity.settings import IdentitySettings

__all__ = [
    "OAUTH_CALLBACK_PATH",
    "OAUTH_LINKS_PATH",
    "OAUTH_LINK_PATH",
    "OAUTH_PROVIDERS_CACHE_CONTROL",
    "OAUTH_PROVIDERS_PATH",
    "OAUTH_START_IP_LIMIT",
    "OAUTH_START_PATH",
    "register_oauth_provider_discovery",
    "register_oauth_routes",
]

OAUTH_START_PATH: Final = "/oauth/{provider}/start"
OAUTH_CALLBACK_PATH: Final = "/oauth/callback"
OAUTH_LINK_PATH: Final = "/oauth/{provider}/link"
OAUTH_LINKS_PATH: Final = "/oauth/links"
OAUTH_PROVIDERS_PATH: Final = "/oauth/providers"

OAUTH_PROVIDERS_CACHE_CONTROL: Final = "public, max-age=300"

OAUTH_START_IP_LIMIT: Final = (20, 900)

_FastAPIRequest: Any = None


def _bind_fastapi_request() -> None:
    """Put `fastapi.Request` in this module's globals for FastAPI's annotation lookup."""
    global _FastAPIRequest
    if _FastAPIRequest is None:
        from fastapi import Request as _Request

        _FastAPIRequest = _Request


def register_oauth_provider_discovery(
    router: APIRouter,
    *,
    prefix: str,
    oauth: OAuthService | None = None,
) -> None:
    """Add `GET <prefix>/oauth/providers`, the one route that mounts in every deployment.

    Anonymous and unrated, answering an empty list when OAuth is unconfigured so the
    frontend never has to infer availability from a 404 or a probe.
    """
    from fastapi.responses import JSONResponse as _JSONResponse

    @router.get(
        f"{prefix}{OAUTH_PROVIDERS_PATH}",
        tags=["oauth"],
        summary="The OAuth providers this deployment can sign a user in with",
        response_model=None,
    )
    async def oauth_providers() -> Any:
        """The OAuth providers this deployment can actually sign a user in with.

        A provider is listed only when it has both a client id and a client secret.
        Annotated `-> Any` with `response_model=None` so the OpenAPI schema still builds.
        """
        configs = oauth.available_providers() if oauth is not None else []
        return _JSONResponse(
            {
                "providers": [
                    {"id": config.name, "display_name": config.display_name} for config in configs
                ]
            },
            headers={"Cache-Control": OAUTH_PROVIDERS_CACHE_CONTROL},
        )

    _ = oauth_providers


def register_oauth_routes(
    router: APIRouter,
    *,
    prefix: str,
    settings: IdentitySettings,
    oauth: OAuthService,
    flows: Any,
    tokens: TokenService,
    limits: Callable[..., list[Any]],
    context: Callable[[Request], tuple[str, str]],
    rejected: Callable[[Request, Any], JSONResponse],
    success_body: Callable[[Any], dict[str, Any]],
    set_refresh_cookie: Callable[[JSONResponse, str], JSONResponse],
) -> None:
    """Add the five OAuth routes, given the closures `_mount_flows` already built.

    Reusing those closures keeps the cookie attributes and refusal shape identical to the
    password path. Mounted only when at least one provider has a client id.
    """
    from fastapi import Body
    from fastapi.responses import JSONResponse, RedirectResponse

    from webbpulse.identity.flows import LoginRejected, MfaChallengeRequired
    from webbpulse.identity.oauth import OAuthRejected

    _bind_fastapi_request()

    def oauth_refused(request: Request, exc: OAuthRejected) -> JSONResponse:
        """Render an OAuth refusal in the shared error envelope."""
        from webbpulse.http import error_body

        return JSONResponse(
            error_body(exc.status_code, exc.message, request, error_code=exc.error_code),
            status_code=exc.status_code,
        )

    def error_redirect(exc: OAuthRejected, return_to: str = "") -> RedirectResponse:
        """Bounce a failed browser leg back to the frontend carrying an error code.

        Only this module's own error codes reach the URL, never a provider string.
        """
        from urllib.parse import quote

        target = return_to or settings.frontend_base_url or "/"
        separator = "&" if "?" in target else "?"
        return RedirectResponse(
            f"{target}{separator}oauth_error={quote(exc.error_code)}", status_code=303
        )

    def require_subject(request: Request) -> str:
        """Read the verified subject claim off the request, or an empty string."""
        from webbpulse.identity.router import _subject_from_request

        return _subject_from_request(request, tokens)

    @router.get(
        f"{prefix}{OAUTH_START_PATH}",
        dependencies=limits(("oauth-start", OAUTH_START_IP_LIMIT, "ip")),
    )
    async def oauth_start(request: _FastAPIRequest, provider: str) -> Any:
        """Begin an authorization, and redirect the browser to the provider.

        `mode` defaults to `login`; a `link` start requires a bearer token and records the
        verified user id on the state row.
        """
        from webbpulse.identity.router import run_sync

        mode_param = request.query_params.get("mode", "login")
        mode: Any = "link" if mode_param == "link" else "login"
        user_id = require_subject(request) if mode == "link" else ""

        try:
            authorization = await run_sync(
                lambda: oauth.start(
                    provider,
                    mode=mode,
                    user_id=user_id,
                    return_to=request.query_params.get("return_to", ""),
                    redirect_uri=request.query_params.get("redirect_uri", ""),
                )
            )
        except OAuthRejected as exc:
            return oauth_refused(request, exc)

        return RedirectResponse(authorization.authorization_url, status_code=302)

    @router.get(f"{prefix}{OAUTH_CALLBACK_PATH}")
    async def oauth_callback(request: _FastAPIRequest) -> Any:
        """Finish an authorization: spend the state, verify the identity, act on the mode.

        The state is spent first so a replay dies before any provider call, and the mode
        comes from the state row rather than the URL.
        """
        from webbpulse.identity.router import run_sync

        state = request.query_params.get("state", "")
        code = request.query_params.get("code", "")

        provider_error = request.query_params.get("error", "")

        try:
            record = await run_sync(lambda: oauth.consume_state(state))
        except OAuthRejected as exc:
            return error_redirect(exc)

        if provider_error:
            return error_redirect(
                OAuthRejected("Sign-in was cancelled.", error_code="OAUTH_CANCELLED"),
                record.return_to,
            )

        ip, user_agent = context(request)
        try:
            identity = await run_sync(
                lambda: oauth.identity_from_callback(
                    record.provider, code=code, state_record=record
                )
            )

            if record.mode == "link":
                await run_sync(lambda: oauth.link(identity, user_id=record.user_id))
                return RedirectResponse(
                    _with_flag(record.return_to or settings.frontend_base_url, "oauth_linked"),
                    status_code=303,
                )

            user, _outcome = await run_sync(lambda: oauth.resolve_login(identity))
            result = await run_sync(
                lambda: flows.issue_for_oauth(
                    user, provider=record.provider, ip=ip, user_agent=user_agent
                )
            )
        except MfaChallengeRequired as challenge:
            body = challenge.challenge.as_body()
            return RedirectResponse(
                _with_flag(
                    record.return_to or settings.frontend_base_url,
                    "mfa_ticket",
                    str(body.get("mfa_ticket", "")),
                ),
                status_code=303,
            )
        except OAuthRejected as exc:
            return error_redirect(exc, record.return_to)
        except LoginRejected as exc:
            return error_redirect(
                OAuthRejected(exc.message, error_code=exc.error_code, status_code=exc.status_code),
                record.return_to,
            )

        redirect = RedirectResponse(
            _with_flag(record.return_to or settings.frontend_base_url, "oauth", "1"),
            status_code=303,
        )
        redirect.set_cookie(settings.cookie_name, result.refresh_token, **settings.cookie_kwargs())
        return redirect

    @router.post(f"{prefix}{OAUTH_LINK_PATH}")
    async def oauth_link(
        request: _FastAPIRequest, provider: str, payload: dict[str, Any] = Body(default={})
    ) -> JSONResponse:
        """Start a `link` for the authenticated caller, returning the URL to send them to.

        Answers JSON rather than a redirect because the settings page calls it over `fetch`.
        """
        from webbpulse.identity.router import run_sync

        subject = require_subject(request)
        if not subject:
            return rejected(
                request,
                LoginRejected(
                    "Sign in to link a provider.",
                    error_code="NOT_AUTHENTICATED",
                    status_code=401,
                ),
            )
        try:
            authorization = await run_sync(
                lambda: oauth.start(
                    provider,
                    mode="link",
                    user_id=subject,
                    return_to=str(payload.get("return_to", "")),
                    redirect_uri=str(payload.get("redirect_uri", "")),
                )
            )
        except OAuthRejected as exc:
            return oauth_refused(request, exc)
        return JSONResponse({"authorization_url": authorization.authorization_url})

    @router.get(f"{prefix}{OAUTH_LINKS_PATH}")
    async def oauth_links(request: _FastAPIRequest) -> JSONResponse:
        """Every provider linked to the authenticated account.

        The provider `subject` is deliberately omitted from the response.
        """
        from webbpulse.identity.router import run_sync

        subject = require_subject(request)
        if not subject:
            return rejected(
                request,
                LoginRejected(
                    "Sign in to see your linked providers.",
                    error_code="NOT_AUTHENTICATED",
                    status_code=401,
                ),
            )
        records = await run_sync(lambda: oauth.list_links(subject))
        return JSONResponse(
            {
                "links": [
                    {
                        "provider": record.provider,
                        "email": record.provider_email,
                        "email_verified": record.provider_email_verified,
                        "linked_at": record.linked_at,
                        "last_login_at": record.last_login_at,
                    }
                    for record in records
                ]
            }
        )

    @router.delete(f"{prefix}{OAUTH_LINK_PATH}")
    async def oauth_unlink(request: _FastAPIRequest, provider: str) -> JSONResponse:
        """Detach a provider, unless it is the last way into the account.

        The refusal is a 409 carrying `OAUTH_LAST_SIGN_IN_METHOD`.
        """
        from webbpulse.identity.router import run_sync

        subject = require_subject(request)
        if not subject:
            return rejected(
                request,
                LoginRejected(
                    "Sign in to unlink a provider.",
                    error_code="NOT_AUTHENTICATED",
                    status_code=401,
                ),
            )
        try:
            await run_sync(lambda: oauth.unlink(user_id=subject, provider=provider))
        except OAuthRejected as exc:
            return oauth_refused(request, exc)
        return JSONResponse({"unlinked": True})

    _ = (oauth_start, oauth_callback, oauth_link, oauth_links, oauth_unlink)


def _with_flag(target: str, key: str, value: str = "1") -> str:
    """Append a query parameter to a frontend URL that may already have some."""
    from urllib.parse import quote

    base = target or "/"
    separator = "&" if "?" in base else "?"
    return f"{base}{separator}{key}={quote(value)}"
