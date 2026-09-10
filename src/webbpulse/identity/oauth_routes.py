"""The six OAuth HTTP routes, mounted onto the identity router.

Separate from `router.py` for the reason `_mount_mfa` gives for being separate from
`_mount_flows`: each milestone adds its own mount function rather than growing one file past
the point anybody reads it. Separate from `oauth.py` for the stronger reason that
`oauth.py` imports no FastAPI at all, so the service is callable from a test, a CLI or a
queue consumer without a request object, per section 2.1.

## The routes, and why the first two are GETs

| Method | Path | Auth |
| --- | --- | --- |
| `GET` | `/oauth/providers` | none |
| `GET` | `/oauth/{provider}/start` | none |
| `GET` | `/oauth/callback` | none |
| `POST` | `/oauth/{provider}/link` | JWT |
| `GET` | `/oauth/links` | JWT |
| `DELETE` | `/oauth/{provider}/link` | JWT |

`/oauth/providers` is the odd one out and mounts through its own
`register_oauth_provider_discovery`, because it is the only route here that mounts even when
OAuth is switched off entirely, answering an empty list. See that function for why.

`start` and `callback` are `GET` and answer with a `302`, because both are **browser
navigations rather than API calls**. The user clicks "Sign in with Google" and the browser
must end up at Google; Google then navigates the browser back. Neither leg is reachable by
`fetch`, since a cross-origin redirect to a provider cannot be followed by script and the
provider's response is not CORS-readable. Making them JSON endpoints would mean the SPA
reading a URL and assigning `location.href` to it, which is the same navigation with an
extra round trip and an extra place for the URL to leak into a log.

The three link-management routes are ordinary JSON APIs behind the authorizer, and each
reads its subject from the verified claims rather than from the body, for the same reason
`change_password` does: a user id in a body lets anybody modify anybody's account.

## The callback is one route, not one per provider

The provider is recovered from the state row rather than from the path. A registered
redirect URI is a fixed string at the provider, and per-provider callbacks would mean
registering a different one with each, which is more configuration to get wrong for no
gain. It also means the provider on the callback is whatever the *state* said it was, which
is server-side and single use, rather than whatever the URL said, which the caller controls.

## Errors on a browser navigation

A refused callback cannot answer JSON: the user is looking at a browser, and a JSON error
body renders as text on a blank page. So a refusal redirects to the frontend with
`?oauth_error=<code>` and the frontend renders it. The code is one of this module's own
error codes, never a provider string, so nothing attacker-influenced reaches the URL.

The `start` route is the exception: it answers JSON errors, because a misconfigured provider
is an operator problem rather than something to bounce a user through the frontend for.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:  # pragma: no cover - typing only
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

#: Five minutes, matching the JWKS rather than the hour the discovery document gets.
#:
#: The set of providers is configuration, so it changes when a deploy changes it, which is
#: rarer than a key rotation but not never: turning a provider on is exactly the moment
#: somebody is watching to see the button appear. An hour would mean a browser that had
#: loaded the sign-in page before the deploy kept showing the old set for the rest of the
#: hour, with no way to tell it otherwise. Five minutes bounds that while still taking the
#: fetch off the Lambda for the overwhelming majority of sign-in page loads, which is the
#: same trade the JWKS makes and the reason its number is the one copied here.
OAUTH_PROVIDERS_CACHE_CONTROL: Final = "public, max-age=300"

#: Section 5.1: 20 starts per 15 minutes per IP.
#:
#: The limit is on `start` and not on `callback`, deliberately. A start is free to make and
#: writes a row, so an unlimited one is a way to fill the state table. A callback can only be
#: made with a state that a start already issued, so it is limited by construction, and
#: limiting it as well would mean a user behind a shared NAT could be refused on the *second*
#: leg of a sign-in they had already been allowed to begin.
#:
#: Section 5.1 also settles that an OAuth login is **not** subject to the password lockout
#: counter. The two measure different things: lockout counts failed guesses at a password,
#: and no password is guessed here.
OAUTH_START_IP_LIMIT: Final = (20, 900)

#: `fastapi.Request`, bound into this module's globals at first use.
#:
#: The routes below annotate `request: _FastAPIRequest` rather than `request: Request` for
#: the reason `router.py` does, and the comment there has the detail: under
#: `from __future__ import annotations` an annotation is a string, FastAPI resolves it
#: against the defining module's namespace, and a `Request` that only exists under
#: `TYPE_CHECKING` is not in it. FastAPI then cannot tell the parameter is the request
#: object, treats it as a required query parameter, and answers 422 to every route in this
#: file. Same bug, same fix, deliberately spelled the same way so it reads as one idiom.
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

    New in 0.16.0. Answers `{"providers": [{"id": ..., "display_name": ...}, ...]}` for the
    providers that are actually usable, and `{"providers": []}` when OAuth is not configured
    at all, which is why `oauth` is optional: an unconfigured product has no `OAuthService`
    to build, since it may have neither store, and the empty answer needs neither.

    ## Why this exists

    Before it, a frontend had no way to ask which providers were available, so it inferred
    the answer by probing `GET /oauth/{provider}/start` and reading the status code.
    WebbPulse-Portfolio PR 170 did exactly that, and it is wrong twice over. It spends the
    start route's rate limit budget, 20 per 15 minutes per IP, on page loads rather than on
    sign-ins, so a user who reloads a sign-in page enough times is refused the sign-in they
    then attempt. And a probe cannot distinguish "this provider is not configured" from
    "this provider is configured and something is briefly broken": both are a non-200, and a
    frontend that hides a button on a transient failure has turned a blip into a missing
    sign-in method. An explicit list is a different question with an unambiguous answer.

    ## Why it mounts even when OAuth is off

    So that the frontend has one authoritative answer in every deployment. A route that is
    absent when OAuth is unconfigured would mean a 404 that the client has to interpret, and
    a 404 is exactly the ambiguous signal this route exists to replace: it is
    indistinguishable from a routing mistake or an older version of this package. An empty
    list says "no providers, and I am sure" in a way a missing route cannot. It is the same
    reasoning that keeps the `.well-known` documents unconditional.

    ## Anonymous, and rate limited by nothing

    Anonymous because it is read by the sign-in page, which by definition has no token. Not
    rate limited, matching the `.well-known` documents rather than the flow routes: the
    response is a constant derived from configuration, it holds nothing about any user, it
    touches no store and makes no call, and it carries a `Cache-Control` that keeps repeat
    fetches off the function entirely. Rate limiting it would mean a DynamoDB write per
    sign-in page load to protect a handler that reads a dict.
    """
    from fastapi.responses import JSONResponse as _JSONResponse

    @router.get(
        f"{prefix}{OAUTH_PROVIDERS_PATH}",
        # Just "oauth": the router already carries "identity" on every route it holds, and
        # repeating it here puts the tag in the OpenAPI operation twice.
        tags=["oauth"],
        summary="The OAuth providers this deployment can sign a user in with",
        response_model=None,
    )
    async def oauth_providers() -> Any:
        """The OAuth providers this deployment can actually sign a user in with.

        A provider appears only when it has **both** a client id and a client secret. One
        with an id and no secret is a misconfiguration whose symptom, before 0.16.0, was a
        user consenting at the provider and then meeting a 503 on the way back, so it is not
        advertised and `start` refuses it outright.

        Annotated `-> Any` with `response_model=None`, rather than `-> JSONResponse`, and
        that is not cosmetic. Under `from __future__ import annotations` the annotation is
        the *string* `"JSONResponse"`, which FastAPI hands to pydantic as a response model
        and pydantic cannot resolve, so building the OpenAPI schema raises
        `PydanticUserError`. The other routes in this package carry that annotation and each
        one that mounts breaks `app.openapi()` for the whole app; this route mounts in
        **every** deployment, including the documents-only one whose schema builds fine
        today, so it must not be the thing that takes `/docs` away from a product that has
        no OAuth at all.
        """
        configs = oauth.available_providers() if oauth is not None else []
        return _JSONResponse(
            {
                "providers": [
                    {"id": config.name, "display_name": config.display_name}
                    for config in configs
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
    """Add M6's five OAuth routes, given the closures `_mount_flows` already built.

    Takes the same closures `_mount_mfa` takes, and for the same reason: the cookie writer,
    the error renderer and the rate limit builder are bound to settings that only exist
    inside `_mount_flows`, and passing them in keeps one definition of each. An OAuth login
    and a password login therefore set the same cookie with the same attributes and render
    the same refusal shape, which is not something two independent implementations would
    stay agreed on.

    Mounted only when the product configured at least one provider with a client id. A route
    that answers 503 because nobody set `google_client_id` is worse than a route that is not
    in the OpenAPI document at all.
    """
    from fastapi import Body
    from fastapi.responses import JSONResponse, RedirectResponse

    from webbpulse.identity.flows import LoginRejected, MfaChallengeRequired
    from webbpulse.identity.oauth import OAuthRejected

    # Must happen before the first `@router.get` below. See `_FastAPIRequest`.
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

        303 rather than 302: the callback arrives as a `GET` and the frontend route is a
        `GET`, so the distinction is invisible here, but 303 is the status that means "go
        look over there with a GET" and saying so explicitly costs nothing.

        Only this module's own error codes are placed in the URL. A provider's
        `error_description` is attacker-influenced through the `code` parameter and would be
        rendered into a page by the frontend, so it never leaves the log line it was written
        to.
        """
        from urllib.parse import quote

        target = return_to or settings.frontend_base_url or "/"
        separator = "&" if "?" in target else "?"
        return RedirectResponse(
            f"{target}{separator}oauth_error={quote(exc.error_code)}", status_code=303
        )

    def require_subject(request: Request) -> str:
        from webbpulse.identity.router import _subject_from_request

        return _subject_from_request(request, tokens)

    # ---- start ------------------------------------------------------------------------

    @router.get(
        f"{prefix}{OAUTH_START_PATH}",
        dependencies=limits(("oauth-start", OAUTH_START_IP_LIMIT, "ip")),
    )
    async def oauth_start(request: _FastAPIRequest, provider: str) -> Any:
        """Begin an authorization, and redirect the browser to the provider.

        `mode` defaults to `login`. A `link` start requires a bearer token, and the user id
        is taken from the verified claims and written onto the state row, so the callback
        knows which account to attach to without trusting anything the callback carries.
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

    # ---- callback ---------------------------------------------------------------------

    @router.get(f"{prefix}{OAUTH_CALLBACK_PATH}")
    async def oauth_callback(request: _FastAPIRequest) -> Any:
        """Finish an authorization: spend the state, verify the identity, act on the mode.

        The order is fixed and each step depends on the one before it:

        1. **Spend the state.** Single use, so a replayed callback dies here, before any
           provider call is made and before anything is written.
        2. **Exchange the code and verify the identity.** For Google that is an ID token
           checked against the JWKS with its nonce; for GitHub it is two authenticated calls.
        3. **Act on the mode the *state* recorded**, never the mode the URL suggests. A
           `login` state has no user id on it, so a login callback cannot be steered into
           attaching a provider to somebody's account.

        A `login` ends in the same token pair a password login produces, or in the same
        `mfa_required` challenge when the account has a factor enrolled.
        """
        from webbpulse.identity.router import run_sync

        state = request.query_params.get("state", "")
        code = request.query_params.get("code", "")

        # A provider-side refusal, such as the user pressing Cancel on the consent screen.
        # It arrives with `error` and no code, and it is not a failure worth an error page:
        # the user changed their mind. The state, if any, is still spent below so it cannot
        # be reused.
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
            # The account has a second factor. The browser is mid-navigation, so the
            # challenge cannot be answered with a JSON body the way the password path
            # answers it: the frontend has to render a code prompt. The ticket therefore
            # travels in the redirect, and the frontend posts it to `login/totp`, which is
            # the same route and the same ticket the password path uses.
            #
            # The ticket is a bearer value in a URL, which is why `MfaService` gives it a
            # short TTL and single use. It is the same exposure the M3 email links accept
            # and it is bounded the same way.
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

        # The refresh cookie goes on the redirect, exactly as it goes on a login response.
        # `set_refresh_cookie` is the closure `_mount_flows` built, so the attributes cannot
        # drift from the ones the password path sets.
        redirect = RedirectResponse(
            _with_flag(record.return_to or settings.frontend_base_url, "oauth", "1"),
            status_code=303,
        )
        redirect.set_cookie(settings.cookie_name, result.refresh_token, **settings.cookie_kwargs())
        return redirect

    # ---- link, list, unlink -----------------------------------------------------------

    @router.post(f"{prefix}{OAUTH_LINK_PATH}")
    async def oauth_link(
        request: _FastAPIRequest, provider: str, payload: dict[str, Any] = Body(default={})
    ) -> JSONResponse:
        """Start a `link` for the authenticated caller, returning the URL to send them to.

        JSON rather than a redirect, unlike `start`, because this one is called by the
        settings page over `fetch` with an `Authorization` header. A redirect would be
        followed by `fetch` without that header and land somewhere useless.
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

        The response deliberately omits `subject`. It is the provider's stable id for the
        user, it is of no use to a settings page, and echoing an identifier from another
        system into a response body is how it ends up in a log or a bug report.
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

        The refusal is a 409 carrying `OAUTH_LAST_SIGN_IN_METHOD`, which the frontend turns
        into "set a password first" rather than a generic error. See `OAuthService.unlink`
        for what counts as a remaining method.
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

    # Silence the "assigned but never used" reading of the route functions. FastAPI holds
    # them through the decorator, which a linter reading this file alone cannot see.
    _ = (oauth_start, oauth_callback, oauth_link, oauth_links, oauth_unlink)


def _with_flag(target: str, key: str, value: str = "1") -> str:
    """Append a query parameter to a frontend URL that may already have some."""
    from urllib.parse import quote

    base = target or "/"
    separator = "&" if "?" in base else "?"
    return f"{base}{separator}{key}={quote(value)}"
