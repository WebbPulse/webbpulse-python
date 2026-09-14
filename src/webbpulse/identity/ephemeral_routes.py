"""Admin-only routes that create and delete one throwaway login user per e2e run.

Why they exist: the suite's profile, social-link and sign-in journeys all mutate the user
they run as, so a single durable account forces every run to serialise behind a concurrency
group. A run that makes its own user and deletes it at the end can run beside any number of
others.

Why they are gated twice: creating a verified account with a chosen password and no email
round trip is exactly the capability an attacker wants. `ephemeral_users_enabled` is off by
default and set only in staging, and `register_ephemeral_routes` additionally refuses to
mount in production whatever the flag says, so a misconfigured production deployment has no
route to reach rather than a route that answers 403.

The caller must present an access token carrying `admin` in its `roles` claim, which in
staging means a KMS-minted token the e2e workflow alone can produce.

No password ever reaches a log line, a response body or an exception message.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Callable, Mapping

    from fastapi import APIRouter
    from fastapi.responses import JSONResponse
    from starlette.requests import Request

    from webbpulse.identity.flows import IdentityFlows
    from webbpulse.identity.settings import IdentitySettings

__all__ = [
    "ADMIN_ROLE",
    "EPHEMERAL_ROUTE_RESPONSES",
    "EPHEMERAL_USERS_PATH",
    "EPHEMERAL_USER_ITEM_PATH",
    "caller_is_admin",
    "register_ephemeral_routes",
]

EPHEMERAL_USERS_PATH: Final = "/e2e/users"
EPHEMERAL_USER_ITEM_PATH: Final = "/e2e/users/{user_id}"

ADMIN_ROLE: Final = "admin"

_REFUSED_ENVIRONMENTS: Final[frozenset[str]] = frozenset({"production", "prod"})

_FastAPIRequest: Any = None


def _bind_fastapi_request() -> None:
    """Put `fastapi.Request` in this module's globals for FastAPI's annotation lookup.

    With postponed annotations FastAPI resolves a handler's parameter types against the
    module globals, and a `Request` that exists only under `TYPE_CHECKING` resolves to
    nothing, so FastAPI reads the parameter as a required body field named `request` and
    every call answers 422 before the handler runs.
    """
    global _FastAPIRequest
    if _FastAPIRequest is None:
        from fastapi import Request as _Request

        _FastAPIRequest = _Request


EPHEMERAL_ROUTE_RESPONSES: Final[Mapping[tuple[str, str], dict[int, str]]] = {
    ("POST", EPHEMERAL_USERS_PATH): {
        201: "The ephemeral user was created.",
        400: "The request named no email address.",
        401: "No access token, or one carrying no subject.",
        403: "The caller is not an admin, or ephemeral users are disabled here.",
        409: "That address already has an account.",
        422: "The password does not meet the policy.",
    },
    ("DELETE", EPHEMERAL_USER_ITEM_PATH): {
        200: "The ephemeral user was deleted, or was already gone.",
        401: "No access token, or one carrying no subject.",
        403: "The caller is not an admin, or ephemeral users are disabled here.",
    },
}


def caller_is_admin(request: Request) -> bool:
    """Whether this request's verified claims carry the admin role.

    Read through `identity_claims` rather than the router's own claim helper, because that
    one stringifies every value and `roles` is an array claim: a list would arrive as its
    repr and no membership test on it would be meaningful. `identity_claims` coerces the
    array claims back to lists for both the native JWT authorizer and the staging gate.
    """
    from webbpulse.identity.claims import identity_claims

    claims = identity_claims(request)
    if claims is None:
        return False
    roles = claims.get("roles") or []
    if isinstance(roles, str):
        return roles == ADMIN_ROLE
    return ADMIN_ROLE in {str(role) for role in roles}


def register_ephemeral_routes(
    router: APIRouter,
    *,
    prefix: str,
    settings: IdentitySettings,
    flows: IdentityFlows,
    rejected: Callable[[Request, Any], JSONResponse],
) -> None:
    """Mount the ephemeral e2e user routes, unless this environment refuses them.

    Nothing is mounted when `ephemeral_users_enabled` is false or the environment is a
    production one. Absent rather than refusing is the stronger answer: an unmounted route
    cannot be reached by a caller who somehow holds an admin token.
    """
    if not settings.ephemeral_users_enabled:
        return
    if settings.environment.strip().lower() in _REFUSED_ENVIRONMENTS:
        return

    _bind_fastapi_request()

    from fastapi import Body
    from fastapi.responses import JSONResponse as _JSONResponse

    from webbpulse.identity.flows import LoginRejected
    from webbpulse.identity.passwords import PasswordRejected
    from webbpulse.identity.router import run_sync

    def refuse_non_admin(request: Request) -> JSONResponse | None:
        """The refusal for a caller who is not an admin, or None to let the call through.

        A missing subject and a present one without the role are told apart, so a workflow
        that minted a token with no roles reads differently from one that sent none.
        """
        from webbpulse.identity.claims import identity_subject

        if not identity_subject(request):
            return rejected(
                request,
                LoginRejected(
                    "Sign in to manage ephemeral e2e users.",
                    error_code="NOT_AUTHENTICATED",
                    status_code=401,
                ),
            )
        if not caller_is_admin(request):
            return rejected(
                request,
                LoginRejected(
                    "Managing ephemeral e2e users needs the admin role.",
                    error_code="ADMIN_REQUIRED",
                    status_code=403,
                ),
            )
        return None

    @router.post(
        f"{prefix}{EPHEMERAL_USERS_PATH}",
        tags=["identity"],
        summary="Create one throwaway verified user for an e2e run",
        include_in_schema=False,
        response_model=None,
    )
    async def create_ephemeral_user(request: _FastAPIRequest, payload: dict[str, Any] = Body(...)) -> Any:
        """Create one verified account for this run and return its id and email.

        The password arrives in the body, is hashed by the flow and is never echoed back:
        the caller generated it and already holds it.
        """
        refusal = refuse_non_admin(request)
        if refusal is not None:
            return refusal
        try:
            created = await run_sync(
                lambda: flows.create_ephemeral_user(
                    email=str(payload.get("email", "")),
                    password=str(payload.get("password", "")),
                    attributes=payload.get("attributes") or {},
                )
            )
        except PasswordRejected as exc:
            from webbpulse.http import error_body

            return _JSONResponse(
                error_body(422, exc.message, request, error_code=exc.error_code),
                status_code=422,
            )
        except LoginRejected as exc:
            return rejected(request, exc)
        return _JSONResponse(created, status_code=201)

    @router.delete(
        f"{prefix}{EPHEMERAL_USER_ITEM_PATH}",
        tags=["identity"],
        summary="Delete one throwaway e2e user",
        include_in_schema=False,
        response_model=None,
    )
    async def delete_ephemeral_user(request: _FastAPIRequest, user_id: str) -> Any:
        """Delete this run's user, letting the users-table stream purge its identity rows.

        A user that is already gone answers 200 with `deleted` false, so a retried cleanup
        is not an error.
        """
        refusal = refuse_non_admin(request)
        if refusal is not None:
            return refusal
        try:
            deleted = await run_sync(lambda: flows.delete_ephemeral_user(user_id))
        except LoginRejected as exc:
            return rejected(request, exc)
        return _JSONResponse({"user_id": user_id, "deleted": deleted}, status_code=200)

    _ = (create_ephemeral_user, delete_ephemeral_user)
