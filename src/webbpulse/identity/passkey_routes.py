"""The seven passkey HTTP routes, plus the unconditional availability route.

The seven mount onto the identity router when both passkey tables exist;
`GET /passkeys/availability` mounts in every deployment through its own function.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from webbpulse.identity.router import (
    _subject_from_request,
    run_sync,
)

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Callable

    from fastapi import APIRouter, Request
    from fastapi.responses import JSONResponse

    from webbpulse.identity.service import TokenService
    from webbpulse.identity.settings import IdentitySettings

_FastAPIRequest: Any = None


def _bind_fastapi_request() -> None:
    """Put `fastapi.Request` in this module's globals for FastAPI's annotation lookup."""
    global _FastAPIRequest
    if _FastAPIRequest is None:
        from fastapi import Request as _Request

        _FastAPIRequest = _Request


__all__ = [
    "LOGIN_PASSKEY_OPTIONS_PATH",
    "LOGIN_PASSKEY_VERIFY_PATH",
    "PASSKEYS_PATH",
    "PASSKEY_AVAILABILITY_CACHE_CONTROL",
    "PASSKEY_AVAILABILITY_PATH",
    "PASSKEY_ITEM_PATH",
    "PASSKEY_LOGIN_LIMIT",
    "PASSKEY_OPTIONS_LIMIT",
    "PASSKEY_REGISTER_LIMIT",
    "PASSKEY_REGISTER_OPTIONS_PATH",
    "PASSKEY_REGISTER_VERIFY_PATH",
    "register_passkey_availability",
    "register_passkey_routes",
]

PASSKEY_REGISTER_OPTIONS_PATH = "/passkeys/register/options"
PASSKEY_REGISTER_VERIFY_PATH = "/passkeys/register/verify"

LOGIN_PASSKEY_OPTIONS_PATH = "/login/passkey/options"
LOGIN_PASSKEY_VERIFY_PATH = "/login/passkey/verify"

PASSKEYS_PATH = "/passkeys"
PASSKEY_ITEM_PATH = "/passkeys/{credential_id}"

PASSKEY_AVAILABILITY_PATH = "/passkeys/availability"

PASSKEY_AVAILABILITY_CACHE_CONTROL = "public, max-age=300"

PASSKEY_OPTIONS_LIMIT = (30, 900)
PASSKEY_LOGIN_LIMIT = (30, 900)
PASSKEY_REGISTER_LIMIT = (10, 3600)


def register_passkey_availability(
    router: APIRouter,
    *,
    prefix: str,
    settings: IdentitySettings,
) -> None:
    """Add `GET <prefix>/passkeys/availability`, the one passkey route that always mounts.

    Anonymous and unrated, answering `{"enabled": ..., "passwordless": ...}` from settings.
    `passwordless` is false whenever `enabled` is false.
    """
    from fastapi.responses import JSONResponse as _JSONResponse

    enabled = bool(settings.passkeys_enabled)
    passwordless = enabled and bool(settings.passkeys_passwordless)

    @router.get(
        f"{prefix}{PASSKEY_AVAILABILITY_PATH}",
        tags=["passkeys"],
        summary="Whether this deployment offers passkeys, and passwordless sign-in",
        response_model=None,
    )
    async def passkey_availability() -> Any:
        """Whether this deployment offers passkeys, and whether they are an entry point.

        Both flags are read back from settings rather than inferred from store presence.
        Annotated `-> Any` with `response_model=None` so the OpenAPI schema still builds.
        """
        return _JSONResponse(
            {"enabled": enabled, "passwordless": passwordless},
            headers={"Cache-Control": PASSKEY_AVAILABILITY_CACHE_CONTROL},
        )

    _ = passkey_availability


def register_passkey_routes(
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
    """Add the seven passkey routes. Call only when `flows.passkeys` is not `None`.

    The caller gates the mount so the OpenAPI document describes only what the deployment
    can actually do.
    """
    from fastapi import Body
    from fastapi.responses import JSONResponse

    _bind_fastapi_request()

    from webbpulse.identity.flows import LoginRejected, MfaChallengeRequired
    from webbpulse.identity.passkeys import (
        PasskeyRejected,
        passkey_summaries,
        passkey_summary,
    )

    def passkey_refused(request: Request, exc: PasskeyRejected) -> JSONResponse:
        """Render a passkey refusal in the shared envelope."""
        from webbpulse.http import error_body

        return JSONResponse(
            error_body(exc.status_code, exc.message, request, error_code=exc.error_code),
            status_code=exc.status_code,
        )

    def require_subject(request: Request) -> str:
        """Return the verified subject claim, raising `LoginRejected` when there is none."""
        subject = _subject_from_request(request, tokens)
        if not subject:
            raise LoginRejected("Sign in first.", error_code="NOT_AUTHENTICATED", status_code=401)
        return subject

    @router.post(
        f"{prefix}{PASSKEY_REGISTER_OPTIONS_PATH}",
        dependencies=limits(("passkey-register", PASSKEY_REGISTER_LIMIT, "ip")),
    )
    async def passkey_register_options(request: _FastAPIRequest) -> JSONResponse:
        """Issue a WebAuthn creation challenge for the signed-in caller."""
        try:
            subject = require_subject(request)
        except LoginRejected as exc:
            return rejected(request, exc)
        try:
            challenge = await run_sync(lambda: flows.begin_passkey_registration(user_id=subject))
        except PasskeyRejected as exc:
            return passkey_refused(request, exc)
        except LoginRejected as exc:
            return rejected(request, exc)
        return JSONResponse(
            {"challenge_id": challenge.challenge_id, "publicKey": challenge.options}
        )

    @router.post(
        f"{prefix}{PASSKEY_REGISTER_VERIFY_PATH}",
        dependencies=limits(("passkey-register", PASSKEY_REGISTER_LIMIT, "ip")),
    )
    async def passkey_register_verify(
        request: _FastAPIRequest, payload: dict[str, Any] = Body(...)
    ) -> JSONResponse:
        """Verify a WebAuthn creation response and store the new passkey."""
        try:
            subject = require_subject(request)
        except LoginRejected as exc:
            return rejected(request, exc)
        credential = payload.get("credential")
        if not isinstance(credential, dict):
            return passkey_refused(
                request,
                PasskeyRejected(
                    "A credential is required.",
                    error_code="CREDENTIAL_REQUIRED",
                    status_code=422,
                ),
            )
        try:
            record = await run_sync(
                lambda: flows.finish_passkey_registration(
                    user_id=subject,
                    challenge_id=str(payload.get("challenge_id", "")),
                    credential=credential,
                    name=str(payload.get("name", "")),
                )
            )
        except PasskeyRejected as exc:
            return passkey_refused(request, exc)
        except LoginRejected as exc:
            return rejected(request, exc)
        return JSONResponse(
            {"registered": True, "passkey": passkey_summary(record)}, status_code=201
        )

    @router.post(
        f"{prefix}{LOGIN_PASSKEY_OPTIONS_PATH}",
        dependencies=limits(("passkey-options", PASSKEY_OPTIONS_LIMIT, "ip")),
    )
    async def passkey_login_options(
        request: _FastAPIRequest, payload: dict[str, Any] = Body(default_factory=dict)
    ) -> JSONResponse:
        """Issue an anonymous WebAuthn assertion challenge; the body is optional."""
        try:
            challenge = await run_sync(
                lambda: flows.begin_passkey_login(email=str(payload.get("email", "")))
            )
        except PasskeyRejected as exc:
            return passkey_refused(request, exc)
        except LoginRejected as exc:
            return rejected(request, exc)
        return JSONResponse(
            {"challenge_id": challenge.challenge_id, "publicKey": challenge.options}
        )

    @router.post(
        f"{prefix}{LOGIN_PASSKEY_VERIFY_PATH}",
        dependencies=limits(("passkey-login", PASSKEY_LOGIN_LIMIT, "ip")),
    )
    async def passkey_login_verify(
        request: _FastAPIRequest, payload: dict[str, Any] = Body(...)
    ) -> JSONResponse:
        """Verify an assertion and issue tokens, or answer an MFA challenge."""
        ip, user_agent = context(request)
        credential = payload.get("credential")
        if not isinstance(credential, dict):
            return passkey_refused(
                request,
                PasskeyRejected(
                    "A credential is required.",
                    error_code="CREDENTIAL_REQUIRED",
                    status_code=422,
                ),
            )
        try:
            result = await run_sync(
                lambda: flows.login_with_passkey(
                    challenge_id=str(payload.get("challenge_id", "")),
                    credential=credential,
                    ip=ip,
                    user_agent=user_agent,
                )
            )
        except MfaChallengeRequired as challenge:
            return JSONResponse(challenge.challenge.as_body())
        except PasskeyRejected as exc:
            return passkey_refused(request, exc)
        except LoginRejected as exc:
            return rejected(request, exc)
        return set_refresh_cookie(JSONResponse(success_body(result)), result.refresh_token)

    @router.get(f"{prefix}{PASSKEYS_PATH}")
    async def list_passkeys(request: _FastAPIRequest) -> JSONResponse:
        """Every passkey enrolled on the authenticated account."""
        try:
            subject = require_subject(request)
        except LoginRejected as exc:
            return rejected(request, exc)
        try:
            records = await run_sync(lambda: flows.list_passkeys(user_id=subject))
        except LoginRejected as exc:
            return rejected(request, exc)
        return JSONResponse({"passkeys": passkey_summaries(records)})

    @router.patch(f"{prefix}{PASSKEY_ITEM_PATH}")
    async def rename_passkey(
        request: _FastAPIRequest,
        credential_id: str,
        payload: dict[str, Any] = Body(...),
    ) -> JSONResponse:
        """Rename one of the caller's own passkeys."""
        try:
            subject = require_subject(request)
        except LoginRejected as exc:
            return rejected(request, exc)
        try:
            record = await run_sync(
                lambda: flows.rename_passkey(
                    user_id=subject,
                    credential_id=credential_id,
                    name=str(payload.get("name", "")),
                )
            )
        except PasskeyRejected as exc:
            return passkey_refused(request, exc)
        except LoginRejected as exc:
            return rejected(request, exc)
        return JSONResponse({"passkey": passkey_summary(record)})

    @router.delete(f"{prefix}{PASSKEY_ITEM_PATH}")
    async def delete_passkey(request: _FastAPIRequest, credential_id: str) -> JSONResponse:
        """Delete one of the caller's own passkeys."""
        try:
            subject = require_subject(request)
        except LoginRejected as exc:
            return rejected(request, exc)
        try:
            await run_sync(
                lambda: flows.delete_passkey(user_id=subject, credential_id=credential_id)
            )
        except PasskeyRejected as exc:
            return passkey_refused(request, exc)
        except LoginRejected as exc:
            return rejected(request, exc)
        return JSONResponse({"deleted": True})
