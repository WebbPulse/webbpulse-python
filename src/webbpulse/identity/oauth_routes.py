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
    "OAUTH_ROUTE_RESPONSES",
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

if not TYPE_CHECKING:
    JSONResponse = None
    """Bound by `_bind_fastapi_request`. A runtime global as well as a `TYPE_CHECKING`
    import because every route here is annotated `-> JSONResponse` under postponed
    annotations, and FastAPI resolves that annotation against these globals when it builds
    the OpenAPI document. Type checkers read the import instead, so the annotation keeps
    its real type."""


def _bind_fastapi_request() -> None:
    """Put `fastapi.Request` and `JSONResponse` in this module's globals.

    FastAPI resolves a route's string annotations against the defining module's globals, so
    a name visible only under `TYPE_CHECKING` leaves the return annotation unresolvable and
    `app.openapi()` raises `PydanticUserError`.
    """
    global _FastAPIRequest, JSONResponse
    if _FastAPIRequest is None:
        from fastapi import Request as _Request

        _FastAPIRequest = _Request
    if JSONResponse is None:
        from fastapi.responses import JSONResponse as _Response

        JSONResponse = _Response  # type: ignore[misc]


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
            {"providers": [{"id": config.name, "display_name": config.display_name} for config in configs]},
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
    from webbpulse.identity.oauth import (
        OAUTH_LINK_BINDING_COOKIE,
        OAUTH_STATE_TTL_SECONDS,
        OAuthRejected,
        link_binding_matches,
        new_link_binding,
    )

    _bind_fastapi_request()

    link_max_age = int(settings.oauth_link_max_auth_age.total_seconds())
    binding_samesite = "none" if settings.cookie_samesite == "none" else "lax"

    def binding_cookie_kwargs() -> dict[str, Any]:
        """Where the binding cookie lives: the refresh cookie's path and domain, `Lax`.

        `Lax` rather than the refresh cookie's own setting, because the callback is a
        top-level navigation back from the provider's site and `Strict` would withhold it.
        """
        kwargs: dict[str, Any] = {"path": settings.cookie_path}
        if settings.cookie_domain:
            kwargs["domain"] = settings.cookie_domain
        return kwargs

    def set_binding_cookie(response: Any, secret: str) -> Any:
        """Hand the browser the secret that proves it started this flow."""
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

    def step_up_refusal(request: Request) -> JSONResponse | None:
        """A 401 `STEP_UP_REQUIRED` when the caller's sign-in is older than the link window.

        Mirrors `require_recent_auth`, but an API key has no sign-in to age and is refused
        like any other undated token, since linking changes how the account is entered.
        """
        if link_max_age <= 0:
            return None
        import time

        from webbpulse.http import error_body
        from webbpulse.identity.router import _claims_from_request
        from webbpulse.identity.scopes import (
            STEP_UP_REQUIRED_ERROR_CODE,
            STEP_UP_REQUIRED_MESSAGE,
            _auth_time,
            step_up_challenge,
        )

        auth_time = _auth_time(_claims_from_request(request, tokens))
        if auth_time is not None and time.time() - auth_time <= link_max_age:
            return None
        return JSONResponse(
            error_body(
                401,
                STEP_UP_REQUIRED_MESSAGE,
                request,
                error_code=STEP_UP_REQUIRED_ERROR_CODE,
                max_age=link_max_age,
            ),
            status_code=401,
            headers={"WWW-Authenticate": step_up_challenge(link_max_age)},
        )

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
        return RedirectResponse(f"{target}{separator}oauth_error={quote(exc.error_code)}", status_code=303)

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
        verified user id on the state row. Either mode binds the state to this browser.
        """
        from webbpulse.identity.router import run_sync

        mode_param = request.query_params.get("mode", "login")
        mode: Any = "link" if mode_param == "link" else "login"
        user_id = require_subject(request) if mode == "link" else ""
        if mode == "link" and user_id:
            refusal = step_up_refusal(request)
            if refusal is not None:
                return refusal
        secret, digest = new_link_binding()

        try:
            authorization = await run_sync(
                lambda: oauth.start(
                    provider,
                    mode=mode,
                    user_id=user_id,
                    return_to=request.query_params.get("return_to", ""),
                    redirect_uri=request.query_params.get("redirect_uri", ""),
                    binding=digest,
                )
            )
        except OAuthRejected as exc:
            return oauth_refused(request, exc)

        redirect = RedirectResponse(authorization.authorization_url, status_code=302)
        return set_binding_cookie(redirect, secret)

    @router.get(f"{prefix}{OAUTH_CALLBACK_PATH}")
    async def oauth_callback(request: _FastAPIRequest) -> Any:
        """Finish an authorization: spend the state, verify the identity, act on the mode.

        The state is spent first so a replay dies before any provider call, and the mode
        comes from the state row rather than the URL. Both modes must come back to the
        browser that started them, and every outcome clears the binding cookie.
        """
        from webbpulse.identity.router import run_sync

        state = request.query_params.get("state", "")
        code = request.query_params.get("code", "")

        provider_error = request.query_params.get("error", "")

        try:
            record = await run_sync(lambda: oauth.consume_state(state))
        except OAuthRejected as exc:
            return error_redirect(exc)

        if not record.binding or not link_binding_matches(record, request.cookies.get(OAUTH_LINK_BINDING_COOKIE, "")):
            return clear_binding_cookie(
                error_redirect(
                    OAuthRejected(
                        "That sign-in attempt is no longer valid. Start again.",
                        error_code="OAUTH_STATE_INVALID",
                    ),
                    record.return_to,
                )
            )

        if provider_error:
            cancelled = error_redirect(
                OAuthRejected("Sign-in was cancelled.", error_code="OAUTH_CANCELLED"),
                record.return_to,
            )
            return clear_binding_cookie(cancelled)

        ip, user_agent = context(request)
        try:
            identity = await run_sync(
                lambda: oauth.identity_from_callback(record.provider, code=code, state_record=record)
            )

            if record.mode == "link":
                await run_sync(lambda: oauth.link(identity, user_id=record.user_id))
                return clear_binding_cookie(
                    RedirectResponse(
                        _with_flag(record.return_to or settings.frontend_base_url, "oauth_linked"),
                        status_code=303,
                    )
                )

            user, _outcome = await run_sync(lambda: oauth.resolve_login(identity))
            result = await run_sync(
                lambda: flows.issue_for_oauth(user, provider=record.provider, ip=ip, user_agent=user_agent)
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
            refused = error_redirect(exc, record.return_to)
            return clear_binding_cookie(refused)
        except LoginRejected as exc:
            return clear_binding_cookie(
                error_redirect(
                    OAuthRejected(exc.message, error_code=exc.error_code, status_code=exc.status_code),
                    record.return_to,
                )
            )

        redirect = RedirectResponse(
            _with_flag(record.return_to or settings.frontend_base_url, "oauth", "1"),
            status_code=303,
        )
        redirect.set_cookie(settings.cookie_name, result.refresh_token, **settings.cookie_kwargs())
        return clear_binding_cookie(redirect)

    @router.post(f"{prefix}{OAUTH_LINK_PATH}")
    async def oauth_link(
        request: _FastAPIRequest, provider: str, payload: dict[str, Any] = Body(default={})
    ) -> JSONResponse:
        """Start a `link` for the authenticated caller, returning the URL to send them to.

        Answers JSON rather than a redirect because the settings page calls it over `fetch`.
        Needs a recent sign-in, and sets the cookie binding the state to this browser.
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
        refusal = step_up_refusal(request)
        if refusal is not None:
            return refusal
        secret, digest = new_link_binding()
        try:
            authorization = await run_sync(
                lambda: oauth.start(
                    provider,
                    mode="link",
                    user_id=subject,
                    return_to=str(payload.get("return_to", "")),
                    redirect_uri=str(payload.get("redirect_uri", "")),
                    binding=digest,
                )
            )
        except OAuthRejected as exc:
            return oauth_refused(request, exc)
        response = JSONResponse({"authorization_url": authorization.authorization_url})
        set_binding_cookie(response, secret)
        return response

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
                        "login": record.provider_login,
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

        The refusal is a 409 carrying `OAUTH_LAST_SIGN_IN_METHOD`. Needs a recent sign-in.
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
        refusal = step_up_refusal(request)
        if refusal is not None:
            return refusal
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


def _with_fragment(target: str, key: str, value: str) -> str:
    """Append a parameter to a frontend URL's fragment, which browsers never send to a server.

    Used for the MFA ticket so it stays out of server logs, proxies and the Referer header.
    The frontend reads it from `location.hash`.
    """
    from urllib.parse import quote

    base, hash_mark, fragment = (target or "/").partition("#")
    pair = f"{key}={quote(value, safe='')}"
    if hash_mark and fragment:
        return f"{base}#{fragment}&{pair}"
    return f"{base}#{pair}"


OAUTH_ROUTE_RESPONSES: Final[dict[tuple[str, str], dict[int, str]]] = {
    ("GET", OAUTH_START_PATH): {
        302: "The browser is redirected to the provider's authorization endpoint",
        400: "The provider is unknown or the redirect target is not allowed",
        401: "A link start was made without a bearer token, or with a sign-in older than the link window",
        429: "Too many authorization starts from this address",
        503: "The provider is configured but its client secret is absent",
    },
    ("GET", OAUTH_CALLBACK_PATH): {
        303: "The browser leg is redirected back to the frontend, on success and on failure alike",
        400: "The state was spent, unknown or malformed",
    },
    ("POST", OAUTH_LINK_PATH): {
        400: "The provider is unknown",
        401: "No bearer token was presented, or the sign-in is older than the link window",
        503: "The provider is configured but its client secret is absent",
    },
    ("DELETE", OAUTH_LINK_PATH): {
        400: "The provider is unknown",
        401: "No bearer token was presented, or the sign-in is older than the link window",
        409: "That provider is the last way into the account",
    },
    ("GET", OAUTH_LINKS_PATH): {401: "No bearer token was presented"},
}
"""The statuses the OAuth routes really answer, keyed by method and unprefixed path.

`GET /oauth/callback` never answers 200: every outcome, success and failure alike, is a 303
back to the frontend carrying a flag. `DELETE /oauth/{provider}/link` answers 409 when the
provider is the only remaining way into the account.
"""
