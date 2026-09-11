"""M5's seven passkey routes, plus the one unconditional availability route.

The seven mount into the identity router when both tables exist. `GET
/passkeys/availability` mounts in every deployment through its own
`register_passkey_availability`, answering `{"enabled": false, "passwordless": false}` where
passkeys are off. See that function for why it is separate.

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
    from webbpulse.identity.settings import IdentitySettings

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

#: Anonymous discovery, new in 0.17.0, and the one passkey route that is unconditional.
PASSKEY_AVAILABILITY_PATH = "/passkeys/availability"

#: Five minutes, the same number `oauth/providers` and the JWKS carry, and for the same
#: reason.
#:
#: Whether passkeys are on is configuration, so it changes when a deploy changes it, which is
#: rare but is exactly the moment somebody is watching to see the button appear. An hour
#: would mean a browser that had loaded the sign-in page before the deploy kept showing the
#: old answer for the rest of the hour with no way to tell it otherwise. Five minutes bounds
#: that while still taking the fetch off the function for the overwhelming majority of
#: sign-in page loads.
PASSKEY_AVAILABILITY_CACHE_CONTROL = "public, max-age=300"

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


def register_passkey_availability(
    router: APIRouter,
    *,
    prefix: str,
    settings: IdentitySettings,
) -> None:
    """Add `GET <prefix>/passkeys/availability`, the one passkey route that always mounts.

    New in 0.17.0. Answers `{"enabled": <bool>, "passwordless": <bool>}` from
    `passkeys_enabled` and `passkeys_passwordless`, so a sign-in page can decide whether to
    draw a passkey button without calling anything that costs something.

    ## Why this exists

    Before it, a frontend had no way to ask, so it probed
    `POST /api/auth/login/passkey/options` on sign-in page load and read the status code.
    WebbPulse-Portfolio does exactly that today, and it is wrong twice over. A probe spends
    that route's rate limit budget, 30 per 15 minutes per IP, on page loads rather than on
    sign-ins, so a user who reloads the sign-in page enough times is refused the passkey
    sign-in they then attempt. And the probe is not a read: `begin_passkey_login` writes a
    WebAuthn challenge row per call, so every sign-in page load in the estate leaves a row in
    the challenge table to expire, which is a storage cost paid to answer a question about
    configuration. WebbPulse-Portfolio PR 182 added a `sessionStorage` cache as a stopgap and
    asked for this route; a cache in one frontend is not a fix, because the first load of
    every session still pays both costs and every other consumer pays them in full.

    ## Why it mounts even when passkeys are off

    So the frontend has one authoritative answer in every deployment, which is the same
    reasoning `register_oauth_provider_discovery` gives and the same reasoning that keeps the
    `.well-known` documents unconditional. A route that were absent when passkeys are off
    would answer 404, and a 404 is the ambiguous signal this route exists to replace: it is
    indistinguishable from a routing mistake, a gateway misconfiguration, or an older version
    of this package. `{"enabled": false}` says "no passkeys, and I am sure".

    That makes this the deliberate exception to the rule the seven routes follow. Those do
    not mount when they cannot work, because a route that can only answer 503 is worse than
    an absent one. This one can always work: its answer when passkeys are off is not a
    degraded answer, it is the correct one.

    ## `passwordless` is false whenever `enabled` is false

    `passkeys_passwordless` defaults to `True` and is read independently of
    `passkeys_enabled` nowhere else, so a deployment can hold `passwordless=True` alongside
    `enabled=False` and mean nothing by it. Reporting that pair would tell a frontend to draw
    a "Sign in with a passkey" button on a deployment whose login routes do not exist.
    `enabled` gates the field here so the two can never disagree, and a client can read
    `passwordless` alone.

    ## Anonymous, and rate limited by nothing

    Anonymous because the sign-in page reads it and by definition holds no token. Not rate
    limited, matching `oauth/providers` and the `.well-known` documents rather than the flow
    routes: the response is two booleans derived from configuration, it holds nothing about
    any user, it touches no store, it makes no call, and it carries a `Cache-Control` that
    keeps repeat fetches off the function entirely. Rate limiting it would mean a DynamoDB
    write per sign-in page load to protect a handler that reads two attributes, which is the
    cost this route was added to remove.
    """
    from fastapi.responses import JSONResponse as _JSONResponse

    enabled = bool(settings.passkeys_enabled)
    passwordless = enabled and bool(settings.passkeys_passwordless)

    @router.get(
        f"{prefix}{PASSKEY_AVAILABILITY_PATH}",
        # Just "passkeys": the router already carries "identity" on every route it holds, and
        # repeating it here puts the tag in the OpenAPI operation twice.
        tags=["passkeys"],
        summary="Whether this deployment offers passkeys, and passwordless sign-in",
        response_model=None,
    )
    async def passkey_availability() -> Any:
        """Whether this deployment offers passkeys, and whether they are an entry point.

        `enabled` is `passkeys_enabled`: the deployment registers and verifies passkeys at
        all, so an account settings page should offer to add one. `passwordless` is
        additionally `passkeys_passwordless`: a passkey is a way *into* an account, so a
        sign-in page should offer the button. With `enabled` true and `passwordless` false a
        passkey is a managed credential and a second factor but not an entry point, which is
        the distinction `flows.begin_passkey_login` already enforces.

        Reported from settings rather than from the store's presence, deliberately. A
        deployment with the capability switched on but no passkey table is a configuration
        error an operator has to fix, and reporting `enabled: false` for it would hide the
        error behind a frontend that quietly stops offering passkeys. The settings are what
        the operator wrote down, so they are what this route reads back.

        Annotated `-> Any` with `response_model=None`, rather than `-> JSONResponse`, for the
        reason `oauth_providers` gives: under `from __future__ import annotations` the
        annotation is the *string* `"JSONResponse"`, which FastAPI hands to pydantic as a
        response model and pydantic cannot resolve, so building the OpenAPI schema raises
        `PydanticUserError` for the whole app. Every other route in this module carries that
        annotation, and each one that mounts breaks `app.openapi()`; this route mounts in
        **every** deployment, including the documents-only one whose schema builds fine
        today, so it must not be the thing that takes `/docs` away from a product that has no
        passkeys at all.
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
