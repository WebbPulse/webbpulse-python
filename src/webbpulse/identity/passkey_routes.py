"""M5's seven passkey routes, mounted into the identity router when both tables exist.

A separate module rather than more of `router.py`, because `router.py` is already the
longest file in the package and because M5 and M6 are being built at the same time against
the same file. What stays in `router.py` is one path constant block and one four-line call.

`register_passkey_routes` takes the closures `_mount_flows` already built rather than
rebuilding them. The cookie writer, the error renderer, the rate limit builder and the
context reader are all bound to settings that exist only inside that function, and passing
them in is what stops a passkey route rendering a refusal differently from a login route.
That is the same arrangement `_mount_mfa` uses, for the same reason.

## Which of these sit behind the authorizer

The two login routes do **not**. `login/passkey/options` is called by somebody who is not
signed in yet, which is the whole point of a passwordless flow, and `login/passkey/verify`
carries an assertion rather than a bearer token. Both are anonymous and both are rate
limited, which is the substitute.

The five management routes do. Each reads its subject from the verified claims and never
from the body: a `user_id` in a registration body would let anyone enrol a passkey on
anyone's account, which is `change_password`'s reasoning applied to a credential that is
harder to notice and harder to revoke.

## What the bodies look like

The options routes return `{"challenge_id": ..., "publicKey": {...}}`. The inner document is
WebAuthn JSON exactly as the specification defines it, camelCase and all, because it is
passed straight to `navigator.credentials.create` or `.get` and a helpfully renamed field is
a field the browser does not understand. `challenge_id` is snake_case with the rest of this
API, because it is ours.

The verify routes take `{"challenge_id": ..., "credential": {...}}`, where `credential` is
the browser's response serialised by `@simplewebauthn/browser` or equivalent.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from webbpulse.identity.router import (
    _subject_from_request,
    run_sync,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Callable

    from fastapi import APIRouter, Request
    from fastapi.responses import JSONResponse

    from webbpulse.identity.service import TokenService

#: `fastapi.Request`, bound into **this** module's globals at first use.
#:
#: `router.py` carries the same global for the same reason, and importing that one would not
#: work: FastAPI resolves a route's string annotations against the namespace of the module
#: the route function is *defined* in, which for everything below is this one. Binding
#: `router`'s global leaves this module's copy at `None`, and every route here answers 422 to
#: every call with no error logged anywhere. See `router._FastAPIRequest` for the full
#: explanation of why the annotation has to be a module global at all.
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
    "PASSKEY_ITEM_PATH",
    "PASSKEY_LOGIN_LIMIT",
    "PASSKEY_OPTIONS_LIMIT",
    "PASSKEY_REGISTER_LIMIT",
    "PASSKEY_REGISTER_OPTIONS_PATH",
    "PASSKEY_REGISTER_VERIFY_PATH",
    "register_passkey_routes",
]

#: The enrolment ceremony, behind the authorizer.
PASSKEY_REGISTER_OPTIONS_PATH = "/passkeys/register/options"
PASSKEY_REGISTER_VERIFY_PATH = "/passkeys/register/verify"

#: The passwordless login ceremony, anonymous. Under `/login/` rather than `/passkeys/` so
#: it sits beside `/login` and `/login/totp`, which is where a reader of the route table
#: looks for a way into an account.
LOGIN_PASSKEY_OPTIONS_PATH = "/login/passkey/options"
LOGIN_PASSKEY_VERIFY_PATH = "/login/passkey/verify"

#: Management: list at the collection, rename and delete at the item.
PASSKEYS_PATH = "/passkeys"
PASSKEY_ITEM_PATH = "/passkeys/{credential_id}"

#: Per IP, because the login legs are anonymous and there is no account to attribute an
#: attempt to until the assertion has already verified. Looser than the TOTP limit because
#: there is nothing here to guess: an assertion is signed by a private key an attacker does
#: not have, so the limit exists to cap the cost of the challenge writes rather than to make
#: a search space large enough.
PASSKEY_OPTIONS_LIMIT = (30, 900)
PASSKEY_LOGIN_LIMIT = (30, 900)
#: Enrolment is authenticated, so this is a ceiling on a signed-in user filling the table
#: rather than a defence against a stranger.
PASSKEY_REGISTER_LIMIT = (10, 3600)


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
    """Add M5's seven passkey routes. Call only when `flows.passkeys` is not `None`.

    The gate is the caller's, matching `_mount_mfa`: a route that answers 503 because the
    product never created the tables is worse than a route that does not exist, and the
    OpenAPI document should describe what the deployment can actually do.
    """
    from fastapi import Body
    from fastapi.responses import JSONResponse

    # Must happen before the first `@router.post` below. See `_FastAPIRequest`.
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
        subject = _subject_from_request(request, tokens)
        if not subject:
            raise LoginRejected("Sign in first.", error_code="NOT_AUTHENTICATED", status_code=401)
        return subject

    # ---- enrolment, behind the authorizer ------------------------------------------

    @router.post(
        f"{prefix}{PASSKEY_REGISTER_OPTIONS_PATH}",
        dependencies=limits(("passkey-register", PASSKEY_REGISTER_LIMIT, "ip")),
    )
    async def passkey_register_options(request: _FastAPIRequest) -> JSONResponse:
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

    # ---- passwordless login, anonymous ---------------------------------------------

    @router.post(
        f"{prefix}{LOGIN_PASSKEY_OPTIONS_PATH}",
        dependencies=limits(("passkey-options", PASSKEY_OPTIONS_LIMIT, "ip")),
    )
    async def passkey_login_options(
        request: _FastAPIRequest, payload: dict[str, Any] = Body(default_factory=dict)
    ) -> JSONResponse:
        # The body is optional: a discoverable-credential request sends nothing at all, and
        # requiring `{}` would be a 422 for the ordinary case.
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
            # A passkey that reported no user verification is one factor, so the same
            # second-factor challenge a password gets applies. 200 with `mfa_required`, for
            # the reason the password login route gives: an error status here is read as a
            # failed login by every existing client.
            return JSONResponse(challenge.challenge.as_body())
        except PasskeyRejected as exc:
            return passkey_refused(request, exc)
        except LoginRejected as exc:
            return rejected(request, exc)
        return set_refresh_cookie(JSONResponse(success_body(result)), result.refresh_token)

    # ---- management, behind the authorizer -----------------------------------------

    @router.get(f"{prefix}{PASSKEYS_PATH}")
    async def list_passkeys(request: _FastAPIRequest) -> JSONResponse:
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
