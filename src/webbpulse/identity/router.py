"""The identity router a product mounts into its identity Lambda.

Mounts the discovery, JWKS and health documents unconditionally, plus the password,
session, email, MFA, passkey and OAuth flows when their collaborators are supplied.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final, Literal
from urllib.parse import urlsplit

from webbpulse.identity.storage import IdentityStores
from webbpulse.identity.tokens import DISCOVERY_PATH, JWKS_PATH

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Callable, Mapping

    from fastapi import APIRouter, Request
    from fastapi.responses import JSONResponse

    from webbpulse.identity.email import EmailSender
    from webbpulse.identity.hooks import IdentityHooks
    from webbpulse.identity.lockout import LoginAttemptStore
    from webbpulse.identity.service import TokenService
    from webbpulse.identity.settings import IdentitySettings
    from webbpulse.identity.tokens import KmsClient

__all__ = [
    "ALLOWED_FETCH_SITES",
    "DISCOVERY_CACHE_CONTROL",
    "HEALTH_PATH",
    "JWKS_CACHE_CONTROL",
    "LOGIN_PATH",
    "LOGIN_TOTP_PATH",
    "LOGOUT_ALL_PATH",
    "LOGOUT_PATH",
    "PASSWORD_PATH",
    "RECOVERY_CODES_PATH",
    "REFRESH_PATH",
    "REGISTER_PATH",
    "RESET_CONFIRM_PATH",
    "RESET_EMAIL_LIMIT",
    "RESET_IP_LIMIT",
    "RESET_REQUESTED_MESSAGE",
    "RESET_REQUEST_PATH",
    "STEP_UP_PATH",
    "TOTP_ACTIVATE_PATH",
    "TOTP_DISABLE_PATH",
    "TOTP_ENROL_IP_LIMIT",
    "TOTP_ENROL_PATH",
    "TOTP_VERIFY_LIMIT",
    "VERIFY_CONFIRM_PATH",
    "VERIFY_EMAIL_LIMIT",
    "VERIFY_IP_LIMIT",
    "VERIFY_REQUEST_PATH",
    "build_identity_router",
    "identity_prefix",
]

DISCOVERY_CACHE_CONTROL = "public, max-age=3600"

JWKS_CACHE_CONTROL = "public, max-age=300"

HEALTH_PATH = "/health"

REGISTER_PATH = "/register"
LOGIN_PATH = "/login"
PASSWORD_PATH = "/password"
REFRESH_PATH = "/refresh"
LOGOUT_PATH = "/logout"
LOGOUT_ALL_PATH = "/logout-all"

VERIFY_REQUEST_PATH = "/verify-email"
VERIFY_CONFIRM_PATH = "/verify-email/confirm"
RESET_REQUEST_PATH = "/reset"
RESET_CONFIRM_PATH = "/reset/confirm"

LOGIN_TOTP_PATH = "/login/totp"
TOTP_ENROL_PATH = "/totp/enrol"
TOTP_ACTIVATE_PATH = "/totp/activate"
TOTP_DISABLE_PATH = "/totp/disable"
RECOVERY_CODES_PATH = "/recovery-codes"
STEP_UP_PATH = "/step-up"

RESET_REQUESTED_MESSAGE: Final = "If that address has an account, a link is on its way."

LOGIN_IP_LIMIT: Final = (20, 900)
LOGIN_EMAIL_LIMIT: Final = (10, 900)
REFRESH_IP_LIMIT: Final = (120, 900)
REGISTER_IP_LIMIT: Final = (5, 3600)

RESET_EMAIL_LIMIT: Final = (3, 3600)
RESET_IP_LIMIT: Final = (10, 3600)
VERIFY_EMAIL_LIMIT: Final = (3, 3600)
VERIFY_IP_LIMIT: Final = (10, 3600)

TOTP_VERIFY_LIMIT: Final = (10, 900)
TOTP_ENROL_IP_LIMIT: Final = (10, 3600)

ALLOWED_FETCH_SITES: Final = frozenset({"same-origin", "same-site", "none"})

_FastAPIRequest: Any = None


def _bind_fastapi_request() -> None:
    """Put `fastapi.Request` in this module's globals for FastAPI's annotation lookup."""
    global _FastAPIRequest
    if _FastAPIRequest is None:
        from fastapi import Request as _Request

        _FastAPIRequest = _Request


def identity_prefix(settings: IdentitySettings) -> str:
    """The path every identity route mounts under, taken from the issuer.

    Returns the issuer's path with any trailing slash removed, so `https://host/api/auth`
    gives `/api/auth` and `https://host` gives an empty string.
    """
    return urlsplit(settings.issuer).path.rstrip("/")


def build_identity_router(
    settings: IdentitySettings,
    hooks: IdentityHooks | None = None,
    stores: IdentityStores | None = None,
    *,
    tokens: TokenService | None = None,
    kms_client: KmsClient | None = None,
    service: str = "identity",
    version: str = "",
    attempts: LoginAttemptStore | None = None,
    email_sender: EmailSender | None = None,
    limiter_enabled: bool = True,
    oauth_client_secrets: Mapping[str, str] | None = None,
) -> APIRouter:
    """The identity router for a product, mounted with no prefix.

    The discovery, JWKS, health, OAuth provider and passkey availability routes always
    mount; the flows mount only when their hooks and stores are supplied.
    """
    from fastapi import APIRouter
    from fastapi.responses import JSONResponse

    if tokens is None:
        if kms_client is None:
            raise ValueError(
                "build_identity_router needs either a TokenService as `tokens` or a KMS "
                "client as `kms_client` to build one from."
            )
        from webbpulse.identity.service import TokenService as _TokenService

        tokens = _TokenService(settings, kms_client)

    resolved_stores = stores if stores is not None else IdentityStores()

    prefix = identity_prefix(settings)

    router = APIRouter(tags=["identity"])

    @router.get(f"{prefix}{DISCOVERY_PATH}", include_in_schema=False)
    async def discovery_document() -> JSONResponse:
        """Serve the OpenID discovery document with its long cache header."""
        return JSONResponse(tokens.discovery(), headers={"Cache-Control": DISCOVERY_CACHE_CONTROL})

    @router.get(f"{prefix}{JWKS_PATH}", include_in_schema=False)
    async def jwks_document() -> JSONResponse:
        """Serve the JWKS with its short cache header, sized for key rotation."""
        return JSONResponse(tokens.jwks(), headers={"Cache-Control": JWKS_CACHE_CONTROL})

    @router.get(f"{prefix}{HEALTH_PATH}", include_in_schema=False)
    async def health() -> dict[str, Any]:
        """Report service health, matching `webbpulse.http.health_router`'s shape."""
        return {
            "status": "healthy",
            "service": service,
            "version": version,
        }

    _mount_oauth_discovery(
        router,
        prefix=prefix,
        settings=settings,
        hooks=hooks,
        stores=resolved_stores,
        oauth_client_secrets=oauth_client_secrets,
    )

    from webbpulse.identity.passkey_routes import register_passkey_availability

    register_passkey_availability(router, prefix=prefix, settings=settings)

    if hooks is not None and resolved_stores.credentials is not None:
        _mount_flows(
            router,
            prefix=prefix,
            settings=settings,
            hooks=hooks,
            stores=resolved_stores,
            tokens=tokens,
            attempts=attempts,
            email_sender=email_sender,
            limiter_enabled=limiter_enabled,
            kms_client=kms_client,
            oauth_client_secrets=oauth_client_secrets,
        )

    return router


def _mount_oauth_discovery(
    router: APIRouter,
    *,
    prefix: str,
    settings: IdentitySettings,
    hooks: IdentityHooks | None,
    stores: IdentityStores,
    oauth_client_secrets: Mapping[str, str] | None,
) -> None:
    """Mount `GET <prefix>/oauth/providers`, with a service behind it where one can exist.

    The route mounts either way; without both OAuth stores and hooks it answers an empty
    provider list.
    """
    from webbpulse.identity.oauth_routes import register_oauth_provider_discovery

    oauth_service = None
    if hooks is not None and stores.oauth_states is not None and stores.oauth_links is not None:
        from webbpulse.identity.oauth import OAuthService

        oauth_service = OAuthService(
            settings,
            hooks,
            states=stores.oauth_states,
            links=stores.oauth_links,
            credentials=stores.credentials,
            client_secrets=oauth_client_secrets,
        )

    register_oauth_provider_discovery(router, prefix=prefix, oauth=oauth_service)


def _mount_flows(
    router: APIRouter,
    *,
    prefix: str,
    settings: IdentitySettings,
    hooks: IdentityHooks,
    stores: IdentityStores,
    tokens: TokenService,
    attempts: LoginAttemptStore | None,
    email_sender: EmailSender | None,
    limiter_enabled: bool,
    kms_client: Any = None,
    oauth_client_secrets: Mapping[str, str] | None = None,
) -> None:
    """Add the M2 flow routes, and M3's four email routes, to an already-built router.

    Also mounts the MFA, OAuth and passkey routes when their collaborators are present.
    Every route returns an explicit `JSONResponse`.
    """
    from fastapi import Body, Depends
    from fastapi.responses import JSONResponse

    from webbpulse.identity.flows import (
        IdentityFlows,
        LoginRejected,
        MfaChallengeRequired,
        RateLimited,
    )
    from webbpulse.identity.passwords import PasswordRejected

    _bind_fastapi_request()

    flows = IdentityFlows(
        settings,
        hooks,
        stores,
        tokens,
        attempts=attempts,
        email_sender=email_sender,
        kms_client=kms_client,
    )

    def limits(*specs: tuple[str, tuple[int, int], str]) -> list[Any]:
        """Build the rate limit dependencies for one route, or none when disabled."""
        if not limiter_enabled:
            return []
        from webbpulse.ratelimit import identity_from_ip, rate_limit

        built: list[Any] = []
        for namespace, (limit, window), key in specs:
            key_fn = identity_from_ip if key == "ip" else _email_key_fn
            built.append(
                Depends(
                    rate_limit(
                        key_fn,
                        limit=limit,
                        window_seconds=window,
                        namespace=namespace,
                    )
                )
            )
        return built

    def set_refresh_cookie(response: JSONResponse, token: str) -> JSONResponse:
        """Attach the refresh cookie with section 5.5's attributes.

        `httponly`, `secure`, `samesite=lax` and a scoped `path` are what keep the token
        out of JavaScript, off plain HTTP and off other routes.
        """
        response.set_cookie(settings.cookie_name, token, **settings.cookie_kwargs())
        return response

    def clear_refresh_cookie(response: JSONResponse) -> JSONResponse:
        """Delete the refresh cookie, with the same attributes it was set with.

        `path` and `domain` must match the `Set-Cookie` that created it, or the browser
        treats the deletion as a different cookie and leaves the original in place.
        """
        kwargs = settings.cookie_kwargs()
        domain = kwargs.get("domain")
        samesite = str(kwargs.get("samesite", "lax"))
        response.delete_cookie(
            settings.cookie_name,
            path=str(kwargs.get("path", "/")),
            domain=str(domain) if domain else None,
            secure=bool(kwargs.get("secure", True)),
            httponly=True,
            samesite=_samesite(samesite),
        )
        return response

    def rejected(request: Request, exc: LoginRejected) -> JSONResponse:
        """Render any flow refusal in the shared error envelope."""
        from webbpulse.http import error_body

        headers = {}
        if isinstance(exc, RateLimited):
            headers["Retry-After"] = str(exc.retry_after)
        return JSONResponse(
            error_body(exc.status_code, exc.message, request, error_code=exc.error_code),
            status_code=exc.status_code,
            headers=headers,
        )

    def policy_rejected(request: Request, exc: PasswordRejected) -> JSONResponse:
        """Render a password policy refusal as a 422 in the shared error envelope."""
        from webbpulse.http import error_body

        return JSONResponse(
            error_body(422, exc.message, request, error_code=exc.error_code),
            status_code=422,
        )

    def context(request: Request) -> tuple[str, str]:
        """The IP and user agent every flow method wants, read once per request."""
        from webbpulse.http import client_ip

        return client_ip(request), request.headers.get("user-agent", "")

    def success_body(result: Any) -> dict[str, Any]:
        """The success envelope for an authentication.

        `access_token` and `expires_in` only, plus whatever the flow added. The refresh
        token is never in the body: it goes in the cookie.
        """
        return {
            "access_token": result.access_token,
            "token_type": "Bearer",
            "expires_in": result.expires_in,
            **dict(result.extra),
        }

    @router.post(
        f"{prefix}{REGISTER_PATH}",
        dependencies=limits(("register", REGISTER_IP_LIMIT, "ip")),
    )
    async def register(
        request: _FastAPIRequest, payload: dict[str, Any] = Body(...)
    ) -> JSONResponse:
        """Register an account, returning tokens unless the address already has one."""
        ip, user_agent = context(request)
        try:
            result = await run_sync(
                lambda: flows.register(
                    email=str(payload.get("email", "")),
                    password=str(payload.get("password", "")),
                    ip=ip,
                    user_agent=user_agent,
                    attributes=payload.get("attributes") or {},
                )
            )
        except PasswordRejected as exc:
            return policy_rejected(request, exc)
        except LoginRejected as exc:
            return rejected(request, exc)

        if result is None:
            return JSONResponse({"registered": True}, status_code=200)

        return set_refresh_cookie(
            JSONResponse({"registered": True, **success_body(result)}, status_code=201),
            result.refresh_token,
        )

    @router.post(
        f"{prefix}{LOGIN_PATH}",
        dependencies=limits(
            ("login-ip", LOGIN_IP_LIMIT, "ip"),
            ("login-email", LOGIN_EMAIL_LIMIT, "email"),
        ),
    )
    async def login(request: _FastAPIRequest, payload: dict[str, Any] = Body(...)) -> JSONResponse:
        """Sign in with a password, or answer an MFA challenge when one is required."""
        ip, user_agent = context(request)
        try:
            result = await run_sync(
                lambda: flows.login(
                    email=str(payload.get("email", "")),
                    password=str(payload.get("password", "")),
                    ip=ip,
                    user_agent=user_agent,
                )
            )
        except MfaChallengeRequired as challenge:
            return JSONResponse(challenge.challenge.as_body())
        except LoginRejected as exc:
            return rejected(request, exc)
        return set_refresh_cookie(JSONResponse(success_body(result)), result.refresh_token)

    @router.post(f"{prefix}{PASSWORD_PATH}")
    async def change_password(
        request: _FastAPIRequest, payload: dict[str, Any] = Body(...)
    ) -> JSONResponse:
        """Change the caller's password, taking the subject from the verified claims."""
        subject = _subject_from_request(request, tokens)
        if not subject:
            return rejected(
                request,
                LoginRejected(
                    "Sign in to change your password.",
                    error_code="NOT_AUTHENTICATED",
                    status_code=401,
                ),
            )
        ip, _ = context(request)
        try:
            await run_sync(
                lambda: flows.change_password(
                    user_id=subject,
                    current_password=str(payload.get("current_password", "")),
                    new_password=str(payload.get("new_password", "")),
                    ip=ip,
                    keep_family_id=_session_from_request(request, tokens),
                )
            )
        except PasswordRejected as exc:
            return policy_rejected(request, exc)
        except LoginRejected as exc:
            return rejected(request, exc)
        return JSONResponse({"changed": True})

    @router.post(
        f"{prefix}{REFRESH_PATH}",
        dependencies=limits(("refresh", REFRESH_IP_LIMIT, "ip")),
    )
    async def refresh(request: _FastAPIRequest) -> JSONResponse:
        """Exchange the refresh cookie for a new access token and a rotated cookie."""
        if not _fetch_site_allowed(request):
            return rejected(
                request,
                LoginRejected(
                    "This request did not come from an allowed origin.",
                    error_code="CROSS_SITE_REQUEST",
                    status_code=403,
                ),
            )
        ip, user_agent = context(request)
        presented = request.cookies.get(settings.cookie_name, "")
        try:
            result = await run_sync(lambda: flows.refresh(presented, ip=ip, user_agent=user_agent))
        except LoginRejected as exc:
            return clear_refresh_cookie(rejected(request, exc))
        return set_refresh_cookie(JSONResponse(success_body(result)), result.refresh_token)

    @router.post(f"{prefix}{LOGOUT_PATH}")
    async def logout(request: _FastAPIRequest) -> JSONResponse:
        """End the presented session and clear the refresh cookie. Always succeeds."""
        if not _fetch_site_allowed(request):
            return rejected(
                request,
                LoginRejected(
                    "This request did not come from an allowed origin.",
                    error_code="CROSS_SITE_REQUEST",
                    status_code=403,
                ),
            )
        ip, _ = context(request)
        presented = request.cookies.get(settings.cookie_name, "")
        await run_sync(lambda: flows.logout(presented, ip=ip))
        return clear_refresh_cookie(JSONResponse({"signed_out": True}))

    @router.post(f"{prefix}{LOGOUT_ALL_PATH}")
    async def logout_all(request: _FastAPIRequest) -> JSONResponse:
        """Revoke every session for the caller and clear the refresh cookie."""
        subject = _subject_from_request(request, tokens)
        if not subject:
            return rejected(
                request,
                LoginRejected(
                    "Sign in to sign out everywhere.",
                    error_code="NOT_AUTHENTICATED",
                    status_code=401,
                ),
            )
        ip, _ = context(request)
        await run_sync(lambda: flows.logout_all(subject, ip=ip))
        return clear_refresh_cookie(JSONResponse({"signed_out": True}))

    if flows.mfa is not None:
        _mount_mfa(
            router,
            prefix=prefix,
            flows=flows,
            tokens=tokens,
            limits=limits,
            context=context,
            rejected=rejected,
            success_body=success_body,
            set_refresh_cookie=set_refresh_cookie,
        )

    if stores.oauth_states is not None and stores.oauth_links is not None:
        from webbpulse.identity.oauth import OAuthService
        from webbpulse.identity.oauth_routes import register_oauth_routes

        oauth_service = OAuthService(
            settings,
            hooks,
            states=stores.oauth_states,
            links=stores.oauth_links,
            credentials=stores.credentials,
            client_secrets=oauth_client_secrets,
        )
        if oauth_service.enabled_providers():
            register_oauth_routes(
                router,
                prefix=prefix,
                settings=settings,
                oauth=oauth_service,
                flows=flows,
                tokens=tokens,
                limits=limits,
                context=context,
                rejected=rejected,
                success_body=success_body,
                set_refresh_cookie=set_refresh_cookie,
            )

    if flows.passkeys is not None:
        from webbpulse.identity.passkey_routes import register_passkey_routes

        register_passkey_routes(
            router,
            prefix=prefix,
            flows=flows,
            tokens=tokens,
            limits=limits,
            context=context,
            rejected=rejected,
            success_body=success_body,
            set_refresh_cookie=set_refresh_cookie,
        )

    if not flows.email_enabled:
        return

    from webbpulse.identity.verification import ConfirmationFailed

    def link_refused(request: Request, exc: ConfirmationFailed) -> JSONResponse:
        """Render a refused verification or reset link.

        `exc.reason` is never rendered: whether a token was unknown, expired or already
        spent is information about somebody else's link.
        """
        from webbpulse.http import error_body

        return JSONResponse(
            error_body(exc.status_code, exc.message, request, error_code=exc.error_code),
            status_code=exc.status_code,
        )

    @router.post(
        f"{prefix}{VERIFY_REQUEST_PATH}",
        dependencies=limits(
            ("verify-email", VERIFY_EMAIL_LIMIT, "email"),
            ("verify-ip", VERIFY_IP_LIMIT, "ip"),
        ),
    )
    async def request_verification(
        request: _FastAPIRequest, payload: dict[str, Any] = Body(...)
    ) -> JSONResponse:
        """Send a verification link, answering the same 200 whatever the address is."""
        ip, _ = context(request)
        try:
            await run_sync(lambda: flows.request_verification(str(payload.get("email", "")), ip=ip))
        except LoginRejected as exc:
            return rejected(request, exc)
        return JSONResponse({"sent": True})

    @router.post(f"{prefix}{VERIFY_CONFIRM_PATH}")
    async def confirm_verification(
        request: _FastAPIRequest, payload: dict[str, Any] = Body(...)
    ) -> JSONResponse:
        """Spend a verification token and mark the address verified."""
        ip, _ = context(request)
        try:
            user_id = await run_sync(
                lambda: flows.confirm_verification(str(payload.get("token", "")), ip=ip)
            )
        except ConfirmationFailed as exc:
            return link_refused(request, exc)
        except LoginRejected as exc:
            return rejected(request, exc)
        return JSONResponse({"verified": True, "user_id": user_id})

    @router.post(
        f"{prefix}{RESET_REQUEST_PATH}",
        dependencies=limits(
            ("reset-email", RESET_EMAIL_LIMIT, "email"),
            ("reset-ip", RESET_IP_LIMIT, "ip"),
        ),
    )
    async def request_password_reset(
        request: _FastAPIRequest, payload: dict[str, Any] = Body(...)
    ) -> JSONResponse:
        """Send a password reset link, answering the same 200 whatever the address is."""
        ip, _ = context(request)
        try:
            await run_sync(
                lambda: flows.request_password_reset(str(payload.get("email", "")), ip=ip)
            )
        except LoginRejected as exc:
            return rejected(request, exc)
        return JSONResponse({"sent": True, "detail": RESET_REQUESTED_MESSAGE})

    @router.post(f"{prefix}{RESET_CONFIRM_PATH}")
    async def confirm_password_reset(
        request: _FastAPIRequest, payload: dict[str, Any] = Body(...)
    ) -> JSONResponse:
        """Spend a reset token, set the new password and clear the refresh cookie."""
        ip, _ = context(request)
        try:
            await run_sync(
                lambda: flows.confirm_password_reset(
                    token=str(payload.get("token", "")),
                    new_password=str(payload.get("new_password", "")),
                    ip=ip,
                    family_ids=_string_list(payload.get("family_ids")),
                )
            )
        except ConfirmationFailed as exc:
            return link_refused(request, exc)
        except PasswordRejected as exc:
            return policy_rejected(request, exc)
        except LoginRejected as exc:
            return rejected(request, exc)
        return clear_refresh_cookie(JSONResponse({"reset": True}))


def _mount_mfa(
    router: APIRouter,
    *,
    prefix: str,
    flows: Any,
    tokens: TokenService,
    limits: Callable[..., list[Any]],
    context: Callable[[Request], tuple[str, str]],
    rejected: Callable[[Request, Any], JSONResponse],
    success_body: Callable[[Any], dict[str, Any]],
    set_refresh_cookie: Callable[[JSONResponse, str], JSONResponse],
) -> None:
    """Add M4's six MFA routes, given the closures `_mount_flows` already built.

    `login/totp` stays outside the gateway authorizer because it carries an MFA ticket
    audienced to `<issuer>/mfa`; the other five sit behind it.
    """
    from fastapi import Body
    from fastapi.responses import JSONResponse

    from webbpulse.identity.flows import LoginRejected
    from webbpulse.identity.mfa import MfaRejected

    def mfa_refused(request: Request, exc: MfaRejected) -> JSONResponse:
        """Render an MFA refusal in the shared envelope."""
        from webbpulse.http import error_body

        return JSONResponse(
            error_body(exc.status_code, exc.message, request, error_code=exc.error_code),
            status_code=exc.status_code,
        )

    def require_subject(request: Request) -> str:
        """The verified subject of the request, or a `LoginRejected` when there is none."""
        subject = _subject_from_request(request, tokens)
        if not subject:
            raise LoginRejected("Sign in first.", error_code="NOT_AUTHENTICATED", status_code=401)
        return subject

    @router.post(
        f"{prefix}{LOGIN_TOTP_PATH}",
        dependencies=limits(("mfa-verify", TOTP_VERIFY_LIMIT, "ip")),
    )
    async def complete_totp_login(
        request: _FastAPIRequest, payload: dict[str, Any] = Body(...)
    ) -> JSONResponse:
        """Complete the second leg of an MFA login using a ticket and a code."""
        ip, user_agent = context(request)
        try:
            result = await run_sync(
                lambda: flows.complete_mfa(
                    ticket=str(payload.get("mfa_ticket", "")),
                    code=str(payload.get("code", "")),
                    ip=ip,
                    user_agent=user_agent,
                )
            )
        except MfaRejected as exc:
            return mfa_refused(request, exc)
        except LoginRejected as exc:
            return rejected(request, exc)
        return set_refresh_cookie(JSONResponse(success_body(result)), result.refresh_token)

    @router.post(
        f"{prefix}{TOTP_ENROL_PATH}",
        dependencies=limits(("totp-enrol", TOTP_ENROL_IP_LIMIT, "ip")),
    )
    async def enrol_totp(request: _FastAPIRequest) -> JSONResponse:
        """Begin TOTP enrolment, returning the seed and provisioning URI exactly once."""
        try:
            subject = require_subject(request)
        except LoginRejected as exc:
            return rejected(request, exc)

        claims = _claims_from_request(request, tokens)
        account = claims.get("email", "") or subject
        try:
            enrolment = await run_sync(
                lambda: flows.mfa.begin_enrolment(subject, account_name=account)
            )
        except MfaRejected as exc:
            return mfa_refused(request, exc)
        return JSONResponse(
            {
                "secret": enrolment.secret,
                "provisioning_uri": enrolment.provisioning_uri,
            }
        )

    @router.post(
        f"{prefix}{TOTP_ACTIVATE_PATH}",
        dependencies=limits(("mfa-verify", TOTP_VERIFY_LIMIT, "ip")),
    )
    async def activate_totp(
        request: _FastAPIRequest, payload: dict[str, Any] = Body(...)
    ) -> JSONResponse:
        """Activate TOTP with a code, returning the recovery codes exactly once."""
        try:
            subject = require_subject(request)
        except LoginRejected as exc:
            return rejected(request, exc)
        try:
            codes = await run_sync(
                lambda: flows.mfa.confirm_enrolment(subject, str(payload.get("code", "")))
            )
        except MfaRejected as exc:
            return mfa_refused(request, exc)
        return JSONResponse({"activated": True, "recovery_codes": codes.codes})

    @router.post(
        f"{prefix}{TOTP_DISABLE_PATH}",
        dependencies=limits(("mfa-verify", TOTP_VERIFY_LIMIT, "ip")),
    )
    async def disable_totp(
        request: _FastAPIRequest, payload: dict[str, Any] = Body(...)
    ) -> JSONResponse:
        """Turn TOTP off, requiring a current code as well as the bearer token."""
        try:
            subject = require_subject(request)
        except LoginRejected as exc:
            return rejected(request, exc)
        code = _required_code(payload)
        try:
            await run_sync(lambda: flows.disable_totp(user_id=subject, code=code))
        except MfaRejected as exc:
            return mfa_refused(request, exc)
        return JSONResponse({"disabled": True})

    @router.post(
        f"{prefix}{RECOVERY_CODES_PATH}",
        dependencies=limits(("mfa-verify", TOTP_VERIFY_LIMIT, "ip")),
    )
    async def regenerate_recovery_codes(
        request: _FastAPIRequest, payload: dict[str, Any] = Body(...)
    ) -> JSONResponse:
        """Issue a fresh set of recovery codes, requiring a current code."""
        try:
            subject = require_subject(request)
        except LoginRejected as exc:
            return rejected(request, exc)
        code = _required_code(payload)
        try:
            codes = await run_sync(
                lambda: flows.regenerate_recovery_codes(user_id=subject, code=code)
            )
        except MfaRejected as exc:
            return mfa_refused(request, exc)
        return JSONResponse({"recovery_codes": codes.codes})

    @router.post(
        f"{prefix}{STEP_UP_PATH}",
        dependencies=limits(("mfa-verify", TOTP_VERIFY_LIMIT, "ip")),
    )
    async def step_up(
        request: _FastAPIRequest, payload: dict[str, Any] = Body(...)
    ) -> JSONResponse:
        """Re-assert the second factor, returning a stepped-up access token and no cookie."""
        try:
            subject = require_subject(request)
        except LoginRejected as exc:
            return rejected(request, exc)
        try:
            result = await run_sync(
                lambda: flows.step_up(
                    user_id=subject,
                    session_id=_session_from_request(request, tokens),
                    code=str(payload.get("code", "")),
                )
            )
        except MfaRejected as exc:
            return mfa_refused(request, exc)
        return JSONResponse(success_body(result))


def _required_code(payload: Mapping[str, Any]) -> str:
    """The `code` field of a re-authentication body, or a 422 saying it is missing.

    Raised as a `RequestValidationError` so a client that omitted the field is told so
    rather than being told its code was wrong. A blank string is the same case.
    """
    from fastapi.exceptions import RequestValidationError

    value = payload.get("code")
    if not isinstance(value, str) or not value.strip():
        raise RequestValidationError(
            [
                {
                    "loc": ("body", "code"),
                    "msg": "Field required",
                    "type": "missing",
                }
            ]
        )
    return value


def _string_list(value: object) -> list[str] | None:
    """A JSON array of strings from a request body, or `None`.

    `None` and an empty list mean different things to `confirm_password_reset`: `None`
    falls through to the store, an empty list revokes exactly nothing.
    """
    if value is None:
        return None
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return None


async def run_sync[T](work: Callable[[], T]) -> T:
    """Run blocking work off the event loop.

    Every flow method is synchronous, and bcrypt and boto3 would otherwise stall the
    worker for the whole call. Uses Starlette's threadpool.
    """
    from starlette.concurrency import run_in_threadpool

    return await run_in_threadpool(work)


async def _email_key_fn(request: _FastAPIRequest) -> str:
    """Rate limit key for the per-email login limit, falling back to the IP.

    Reads the buffered request body, which does not consume the stream the route handler
    later parses. A malformed body is limited by IP under a different namespace.
    """
    import json

    from webbpulse.http import client_ip

    try:
        raw = await request.body()
        payload = json.loads(raw) if raw else {}
        email = str(payload.get("email", "")).strip().lower() if isinstance(payload, dict) else ""
    except (TypeError, ValueError, UnicodeDecodeError):
        email = ""
    return f"email:{email}" if email else f"ip:{client_ip(request)}"


def _samesite(value: str) -> Literal["lax", "strict", "none"]:
    """Narrow a configured `samesite` to the three values Starlette accepts.

    `IdentitySettings` already validates the value, so the fallback is unreachable in
    practice and exists to give the type checker a literal.
    """
    return value if value in {"lax", "strict", "none"} else "lax"  # type: ignore[return-value]


def _fetch_site_allowed(request: Request) -> bool:
    """Whether `Sec-Fetch-Site` allows this state-changing cookie request.

    A `cross-site` value is a forged request, because page JavaScript cannot set the
    header. A missing header is allowed, since non-browser clients send none.
    """
    value = request.headers.get("sec-fetch-site", "")
    return not value or value.lower() in ALLOWED_FETCH_SITES


def _subject_from_request(request: Request, tokens: TokenService) -> str:
    """The `sub` claim of the calling request, or an empty string."""
    return _claims_from_request(request, tokens).get("sub", "")


def _session_from_request(request: Request, tokens: TokenService) -> str:
    """The `sid` session claim of the calling request, or an empty string."""
    return _claims_from_request(request, tokens).get("sid", "")


def _claims_from_request(request: Request, tokens: TokenService) -> dict[str, str]:
    """Verified claims for a route the gateway's JWT authorizer sits in front of.

    Prefers the authorizer context header the gateway has already verified, and falls
    back to verifying the bearer token locally. Empty mapping means not authenticated.
    """
    import json

    context_header = request.headers.get("x-amzn-request-context", "")
    if context_header:
        try:
            parsed = json.loads(context_header)
            claims = parsed["authorizer"]["jwt"]["claims"]
        except (KeyError, TypeError, ValueError):
            claims = None
        if isinstance(claims, dict):
            return {str(k): str(v) for k, v in claims.items()}

    authorization = request.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return {}
    try:
        verified = tokens.verify_access_token(token)
    except Exception:
        return {}
    return {str(k): str(v) for k, v in verified.items()}
