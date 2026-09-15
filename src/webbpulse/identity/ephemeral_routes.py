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
staging means a KMS-minted token the e2e workflow alone can produce. Verified authorizer
claims are preferred where an authorizer ran, and the bearer token is verified in process
where none did: CarModPicker staging fronts the whole identity surface with one coarse key
behind the access gate and no JWT authorizer, so a valid admin token arrives with no claims
attached to it.

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
    from webbpulse.identity.service import TokenService
    from webbpulse.identity.settings import IdentitySettings

__all__ = [
    "ADMIN_ROLE",
    "EPHEMERAL_ROUTE_RESPONSES",
    "EPHEMERAL_USERS_PATH",
    "EPHEMERAL_USER_ITEM_PATH",
    "caller_is_admin",
    "caller_roles",
    "register_ephemeral_routes",
]

EPHEMERAL_USERS_PATH: Final = "/e2e/users"
EPHEMERAL_USER_ITEM_PATH: Final = "/e2e/users/{user_id}"

ADMIN_ROLE: Final = "admin"

_REFUSED_ENVIRONMENTS: Final[frozenset[str]] = frozenset({"production", "prod"})

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

    With postponed annotations FastAPI resolves a handler's parameter and return types
    against the module globals, and a name that exists only under `TYPE_CHECKING` resolves
    to nothing. For `Request` that makes FastAPI read the parameter as a required body
    field named `request`, so every call answers 422 before the handler runs; for
    `JSONResponse` it leaves the return annotation unresolvable and `app.openapi()` raises
    `PydanticUserError`.
    """
    global _FastAPIRequest, JSONResponse
    if _FastAPIRequest is None:
        from fastapi import Request as _Request

        _FastAPIRequest = _Request
    if JSONResponse is None:
        from fastapi.responses import JSONResponse as _Response

        JSONResponse = _Response  # type: ignore[misc]


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


def caller_roles(claims: Mapping[str, Any]) -> list[str]:
    """The `roles` claim as a list, whichever shape it arrived in.

    An authorizer flattens an array claim, so a single role can arrive as a bare string,
    while a token verified in process carries the native JSON list. Both become a list here
    so membership is tested the same way on either path.
    """
    roles = claims.get("roles") or []
    if isinstance(roles, str):
        return [roles] if roles else []
    if isinstance(roles, (list, tuple, set, frozenset)):
        return [str(role) for role in roles]
    return [str(roles)]


def caller_is_admin(request: Request) -> bool:
    """Whether this request's verified authorizer claims carry the admin role.

    Read through `identity_claims` rather than the router's own claim helper, because that
    one stringifies every value and `roles` is an array claim: a list would arrive as its
    repr and no membership test on it would be meaningful. `identity_claims` coerces the
    array claims back to lists for both the native JWT authorizer and the staging gate.

    Only the authorizer path, kept for callers outside this module. The routes resolve their
    caller through `_resolve_caller`, which also verifies a bearer token in process where no
    authorizer ran.
    """
    from webbpulse.identity.claims import identity_claims

    claims = identity_claims(request)
    if claims is None:
        return False
    return ADMIN_ROLE in set(caller_roles(claims))


def register_ephemeral_routes(
    router: APIRouter,
    *,
    prefix: str,
    settings: IdentitySettings,
    flows: IdentityFlows,
    tokens: TokenService,
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

    def _resolve_caller(request: Request) -> tuple[str, list[str]]:
        """This request's subject and roles, from whichever source could answer.

        Verified authorizer claims win where an authorizer ran. Where none did, the bearer
        token is verified in process, which is what an identity surface fronted by one coarse
        route key behind the staging access gate needs. A token that fails verification
        resolves to no subject, so it reads as not authenticated rather than as a fault.
        """
        from webbpulse.identity.claims import identity_claims

        claims = identity_claims(request)
        if claims is not None:
            return str(claims.get("sub", "") or ""), caller_roles(claims)

        authorization = request.headers.get("authorization", "")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            return "", []
        try:
            verified = tokens.verify_access_token(token.strip())
        except Exception:
            return "", []
        return str(verified.get("sub", "") or ""), caller_roles(verified)

    def refuse_non_admin(request: Request) -> JSONResponse | None:
        """The refusal for a caller who is not an admin, or None to let the call through.

        A missing subject and a present one without the role are told apart, so a workflow
        that minted a token with no roles reads differently from one that sent none.
        """
        subject, roles = _resolve_caller(request)
        if not subject:
            return rejected(
                request,
                LoginRejected(
                    "Sign in to manage ephemeral e2e users.",
                    error_code="NOT_AUTHENTICATED",
                    status_code=401,
                ),
            )
        if ADMIN_ROLE not in set(roles):
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
