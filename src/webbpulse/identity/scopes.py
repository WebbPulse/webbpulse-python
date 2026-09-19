"""Scope enforcement over the authorizer's claims, and the dependency that accepts a key.

Two dependencies. `claims_or_api_key` answers with an `AuthorizerClaims` whichever credential
arrived, a JWT the gateway already verified or one of this package's API keys presented as a
bearer token. `require_scopes` guards a route on what that claims object carries.

Both fail closed. Every path that cannot produce verified claims raises, so no route reached
through here ever runs anonymously, and a fault in the chain reads as 401 rather than as a
caller with no scopes.
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from typing import TYPE_CHECKING, Any, Final

from webbpulse.identity.api_keys import (
    ACTOR_API_KEY,
    ACTOR_CLAIM,
    TENANT_CLAIM,
    ApiKeyRecord,
    ApiKeyStore,
    claims_for_key,
    effective_scopes,
    is_api_key,
    verify,
)
from webbpulse.identity.claims import AuthorizerClaims, ClaimsUnavailable, identity_claims

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import Request

__all__ = [
    "FORBIDDEN_ERROR_CODE",
    "SCOPES_KEY",
    "UNAUTHENTICATED_ERROR_CODE",
    "bearer_credential",
    "claims_or_api_key",
    "claims_scopes",
    "claims_tenant",
    "has_scopes",
    "is_api_key_actor",
    "missing_scopes",
    "require_scopes",
    "require_tenant",
    "tenant_matches",
]

_log = logging.getLogger(__name__)

if not TYPE_CHECKING:
    Request = None
    """Bound by `_bind_fastapi_request`. A runtime global as well as a `TYPE_CHECKING`
    import because the dependencies built here are annotated `request: Request` under
    postponed annotations, and FastAPI resolves that against these globals. Left unbound it
    reads the parameter as a query field and answers 422 instead of running."""


def _bind_fastapi_request() -> None:
    """Put `fastapi.Request` in this module's globals, as `router` does for its routes.

    FastAPI resolves a dependency's string annotations against the defining module's
    globals, so a name visible only under `TYPE_CHECKING` is not there when it builds the
    signature.
    """
    global Request
    if Request is None:
        from fastapi import Request as _Request

        Request = _Request  # type: ignore[misc]


SCOPES_KEY: Final = "scopes"
"""The coerced claim `coerce_claims` splits the space-separated `scope` string into."""

UNAUTHENTICATED_ERROR_CODE: Final = "UNAUTHORIZED"
"""The 401 `error_code`, the same string `webbpulse.http` maps that status to."""

FORBIDDEN_ERROR_CODE: Final = "INSUFFICIENT_SCOPE"
"""The 403 `error_code`, narrower than the status's own `FORBIDDEN`.

A missing scope is its own refusal: a frontend can offer to re-authorize for it, which it
cannot do for the blanket `FORBIDDEN` that `webbpulse.http` gives every other 403.
"""

_BEARER: Final = "bearer "


def bearer_credential(request: Request) -> str:
    """The bearer value on this request, or `""`.

    Case-insensitive on the scheme, as RFC 7235 requires, and empty for every other scheme so
    a `Basic` header is never mistaken for a key.
    """
    header = request.headers.get("authorization", "")
    if not header.lower().startswith(_BEARER):
        return ""
    return header[len(_BEARER) :].strip()


def claims_scopes(claims: Mapping[str, Any]) -> tuple[str, ...]:
    """The scopes a claims object carries, from either spelling.

    Prefers the coerced `scopes` list `coerce_claims` produces and falls back to splitting a
    raw `scope` string, so this works on claims that never went through the coercion.
    """
    coerced = claims.get(SCOPES_KEY)
    if isinstance(coerced, Sequence) and not isinstance(coerced, str):
        return tuple(str(scope) for scope in coerced)
    scope = claims.get("scope")
    if isinstance(scope, str):
        return tuple(scope.split())
    return ()


def claims_tenant(claims: Mapping[str, Any]) -> str:
    """The tenant a credential is bound to, or `""` for one that names none.

    A verified API key always carries it, because `claims_for_key` stamps the record's own
    `tenant_id`. A session JWT normally does not: a person's authority is their membership,
    read fresh in whichever tenant the path names, so an empty answer here is the ordinary
    case and not a fault.
    """
    return str(claims.get(TENANT_CLAIM, "") or "").strip()


def tenant_matches(claims: Mapping[str, Any], tenant_id: str) -> bool:
    """Whether a tenant-bound credential may act inside `tenant_id`.

    True for claims carrying no tenant, which is the session case: an unbound credential is
    not a credential bound to somewhere else. False whenever a bound one names a different
    tenant, which is the check that keeps a key minted in one tenant out of every other.
    """
    bound = claims_tenant(claims)
    return not bound or bound == tenant_id


def missing_scopes(claims: Mapping[str, Any], required: Iterable[str]) -> tuple[str, ...]:
    """Which of `required` the claims do not carry, sorted, for a refusal to name."""
    held = set(claims_scopes(claims))
    return tuple(sorted({scope for scope in required if scope} - held))


def has_scopes(claims: Mapping[str, Any], required: Iterable[str]) -> bool:
    """Whether the claims carry every required scope. Every one, never any one."""
    return not missing_scopes(claims, required)


def _unauthenticated(message: str = "Authentication is required.") -> Any:
    """The 401 every failed path here raises, with the package's envelope fields."""
    from fastapi import HTTPException

    from webbpulse.messages import STATUS_MESSAGES

    return HTTPException(
        status_code=401,
        detail={"message": message or STATUS_MESSAGES[401], "error_code": UNAUTHENTICATED_ERROR_CODE},
        headers={"WWW-Authenticate": "Bearer"},
    )


def claims_or_api_key(
    *,
    store: ApiKeyStore | None = None,
    live_scopes: Callable[[ApiKeyRecord], Iterable[str]]
    | Callable[[ApiKeyRecord], Awaitable[Iterable[str]]]
    | None = None,
    tenant: Callable[[Request], str] | None = None,
) -> Any:
    """Build the dependency returning verified claims from either credential.

    Tries the authorizer first: a route behind a JWT authorizer already has verified claims on
    the request, and those win, so adding this dependency never weakens a route that had one.
    Only when no authorizer ran does it look for a bearer value shaped like an API key, verify
    it, and build the same claims object from it.

    Fails closed everywhere. An unreadable request context, a missing credential, an unknown,
    revoked or expired key, and a `live_scopes` callable that raises all become the same 401
    with the same body, so nothing distinguishes them to a caller.

    Args:
        store: Where keys are verified against. `None` disables the key path entirely, leaving
            an authorizer-only dependency.
        live_scopes: Loads the minter's current membership for a verified key, and the claims
            carry the intersection of that with the key's own set through `effective_scopes`.
            May be `def` or `async def`. **Leaving it `None` means the key's stored scopes are
            trusted as-is**, which is only safe where membership cannot change.
        tenant: Reads the tenant this request is addressed to, normally out of the path, for a
            multi-tenant product. Any credential bound to a different tenant is refused with
            the same 401 as an unknown one, so a key cannot be walked across tenant ids to
            learn which exist. `None` leaves the binding unchecked, which is right only for a
            single-tenant product; a multi-tenant one that leaves it `None` must make the
            check itself against `claims_tenant`.

    Returns:
        An `async def` dependency suitable for `Depends`.
    """
    _bind_fastapi_request()

    async def dependency(request: Request) -> AuthorizerClaims:
        """Return the verified claims for this request, or raise a 401."""
        try:
            claims = identity_claims(request)
        except ClaimsUnavailable as exc:
            _log.warning("Authorizer claims unreadable: %s", exc, exc_info=exc)
            raise _unauthenticated() from exc
        if claims is not None:
            return _tenant_checked(claims, request)

        if store is None:
            raise _unauthenticated()
        presented = bearer_credential(request)
        if not presented or not is_api_key(presented):
            raise _unauthenticated()

        try:
            record = verify(presented, store)
        except Exception as exc:
            _log.warning("API key verification failed: %s", exc, exc_info=exc)
            raise _unauthenticated() from exc
        if record is None:
            raise _unauthenticated()

        if live_scopes is None:
            return _tenant_checked(claims_for_key(record), request)
        try:
            resolved = live_scopes(record)
            if inspect.isawaitable(resolved):
                resolved = await resolved
        except Exception as exc:
            _log.warning("Could not load live scopes for an API key: %s", exc, exc_info=exc)
            raise _unauthenticated() from exc
        return _tenant_checked(claims_for_key(record, scopes=effective_scopes(record.scopes, resolved)), request)

    def _tenant_checked(claims: AuthorizerClaims, request: Request) -> AuthorizerClaims:
        """The claims, once their tenant binding covers the tenant this request addresses.

        A resolver that raises is a 401 rather than an unchecked pass: failing to learn which
        tenant a request is in is exactly the case where a bound credential must not be let
        through.
        """
        if tenant is None:
            return claims
        try:
            wanted = tenant(request)
        except Exception as exc:
            _log.warning("Could not resolve the tenant for a request: %s", exc, exc_info=exc)
            raise _unauthenticated() from exc
        if not tenant_matches(claims, wanted):
            _log.warning("Refusing a credential bound to another tenant.")
            raise _unauthenticated()
        return claims

    dependency.__name__ = "claims_or_api_key"
    dependency.__doc__ = "The verified claims for this request, from the authorizer or a presented API key."
    return dependency


def require_scopes(*required: str, claims_dependency: Any | None = None) -> Any:
    """Build a dependency refusing any caller missing one of `required`.

    Every named scope must be present, not any of them: a route that wants either spelling
    should take the broader one and let the narrower imply it, because an implicit `or` in a
    guard is the kind of thing nobody re-reads.

    The refusal is a 403 carrying `webbpulse.messages.forbidden` and `INSUFFICIENT_SCOPE`, so
    it renders in the same envelope as every other refusal in the estate and a frontend
    branches on the code rather than the prose. The missing scope names are not in the body:
    naming them tells a caller what to go and acquire.

    Args:
        required: The scopes the caller must hold, such as `"issues:write"`.
        claims_dependency: The dependency producing the claims to check, defaulting to
            `claims_or_api_key()` with no store, which is authorizer-only. Pass the one built
            with an `ApiKeyStore` to let keys through.

    Returns:
        An `async def` dependency suitable for `Depends`, returning the claims it checked so a
        route can take it as its claims dependency rather than adding a second one.
    """
    from fastapi import Depends, HTTPException

    from webbpulse.messages import forbidden

    wanted = tuple(scope for scope in required if scope)
    resolver = claims_dependency if claims_dependency is not None else claims_or_api_key()

    async def dependency(claims: AuthorizerClaims = Depends(resolver)) -> AuthorizerClaims:
        """Return the claims when they carry every required scope, or raise a 403."""
        absent = missing_scopes(claims, wanted)
        if absent:
            _log.info(
                "Refusing a caller missing scopes %s (actor=%s).",
                ",".join(absent),
                claims.get(ACTOR_CLAIM, "user"),
            )
            raise HTTPException(
                status_code=403,
                detail={"message": forbidden(), "error_code": FORBIDDEN_ERROR_CODE},
            )
        return claims

    dependency.__name__ = "require_scopes"
    dependency.__doc__ = f"Requires the scopes {', '.join(wanted) or '(none)'} on this request's claims."
    return dependency


def require_tenant(path_param: str = "tenant_id", *, claims_dependency: Any | None = None) -> Any:
    """Build a dependency refusing a credential bound to a tenant other than the one in the path.

    The standalone form of what `claims_or_api_key(tenant=...)` does inline, for a route that
    already has its claims dependency and wants the binding checked without rebuilding it.

    The refusal is the same 401 an unknown credential gets rather than a 403, deliberately: a
    403 would confirm that the tenant in the path exists, which turns a key into a way to
    enumerate tenants.

    Args:
        path_param: The path parameter naming the tenant, such as `"workspace_id"`.
        claims_dependency: The dependency producing the claims to check, defaulting to
            `claims_or_api_key()` with no store.

    Returns:
        An `async def` dependency suitable for `Depends`, returning the claims it checked.
    """
    from fastapi import Depends

    _bind_fastapi_request()
    resolver = claims_dependency if claims_dependency is not None else claims_or_api_key()

    async def dependency(request: Request, claims: AuthorizerClaims = Depends(resolver)) -> AuthorizerClaims:
        """Return the claims when their tenant binding covers the path, or raise a 401."""
        wanted = str(request.path_params.get(path_param, "") or "").strip()
        if not tenant_matches(claims, wanted):
            _log.warning("Refusing a credential bound to another tenant on %s.", path_param)
            raise _unauthenticated()
        return claims

    dependency.__name__ = "require_tenant"
    dependency.__doc__ = f"Requires this request's credential to be bound to the {path_param} in the path."
    return dependency


def is_api_key_actor(claims: Mapping[str, Any]) -> bool:
    """Whether these claims came from an API key rather than a signed-in person.

    For the route that must refuse a key outright, such as changing a password or minting
    another key: a key must never be able to mint its own successor.
    """
    return str(claims.get(ACTOR_CLAIM, "")) == ACTOR_API_KEY
