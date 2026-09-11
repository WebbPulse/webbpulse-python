"""Parser for the API Gateway authorizer's claims, and its FastAPI dependency.

The gateway has already verified the token, so this module only reads the claims and
coerces the gateway's flattened string map back to the JWT specification's types.
"""

from __future__ import annotations

import inspect
import json
import logging
from collections.abc import Awaitable, Callable, Mapping
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import Request

__all__ = [
    "AuthorizerClaims",
    "ClaimsUnavailable",
    "MissingRequestContext",
    "NoClaimsSection",
    "UnparseableRequestContext",
    "authorizer_claims",
    "coerce_claims",
    "read_authorizer_claims",
]

_log = logging.getLogger(__name__)

INTEGER_CLAIMS: Final[frozenset[str]] = frozenset({"exp", "iat", "nbf", "auth_time"})

BOOLEAN_CLAIMS: Final[frozenset[str]] = frozenset({"email_verified"})

ARRAY_CLAIMS: Final[frozenset[str]] = frozenset({"amr", "roles", "groups", "aud"})

SCOPES_KEY: Final = "scopes"

_REFUSED_ENVIRONMENTS: Final[frozenset[str]] = frozenset({"production", "prod"})


class ClaimsUnavailable(Exception):
    """Base class for the three ways the authorizer's claims can fail to arrive.

    None of the three means the caller was anonymous: the gateway rejects an anonymous
    request before the function is invoked at all.
    """


class MissingRequestContext(ClaimsUnavailable):
    """No `x-amzn-request-context` header at all, which is a deployment fault.

    The Lambda Web Adapter always injects this header, so its absence means the function is
    not behind the adapter or is not being reached by API Gateway.
    """


class UnparseableRequestContext(ClaimsUnavailable):
    """The header was present and could not be read as JSON.

    The adapter sends plain JSON, so anything else means something in the chain re-encoded
    it. Raised rather than swallowed, so a parse bug never presents as an authorization
    failure.
    """


class NoClaimsSection(ClaimsUnavailable):
    """The request context parsed and carries no `authorizer.jwt.claims`.

    The matched route key has no JWT authorizer attached, so the token was never checked and
    the request must be refused.
    """


class AuthorizerClaims(Mapping[str, Any]):
    """The verified claims, coerced, with the wire form kept alongside.

    A `Mapping`, so `claims["sub"]` and `claims.get("email")` work directly. `raw` carries
    the string map exactly as API Gateway sent it.
    """

    __slots__ = ("_coerced", "_raw")

    def __init__(self, raw: Mapping[str, Any]) -> None:
        """Store the wire claims and build the coerced view."""
        self._raw = dict(raw)
        self._coerced = coerce_claims(raw)

    @property
    def raw(self) -> dict[str, Any]:
        """The claims exactly as the gateway sent them, before any coercion."""
        return dict(self._raw)

    def __getitem__(self, key: str) -> Any:
        """Return one coerced claim."""
        return self._coerced[key]

    def __iter__(self) -> Any:
        """Iterate the coerced claim names."""
        return iter(self._coerced)

    def __len__(self) -> int:
        """Return the number of coerced claims."""
        return len(self._coerced)

    def __repr__(self) -> str:
        """Render `sub` only, so a log line never spills an email or a scope list."""
        return f"AuthorizerClaims(sub={self._coerced.get('sub')!r})"


def _coerce_int(value: Any) -> Any:
    """Parse a quoted NumericDate claim, leaving a non-integer string exactly as it arrived."""
    if not isinstance(value, str):
        return value
    try:
        return int(value)
    except ValueError:
        return value


def _coerce_bool(value: Any) -> Any:
    """Parse the JSON spellings `"true"` and `"false"`, leaving anything else a string."""
    if not isinstance(value, str):
        return value
    lowered = value.strip().lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    return value


def _coerce_array(value: Any) -> Any:
    """Convert a gateway-encoded array claim to a `list[str]`.

    Handles both spellings the gateway emits, a JSON array and the bracketed comma form. A
    value with no brackets becomes a one-element list.
    """
    if isinstance(value, list):
        return [str(item) for item in value]
    if not isinstance(value, str):
        return value
    stripped = value.strip()
    if not (stripped.startswith("[") and stripped.endswith("]")):
        return [stripped] if stripped else []
    try:
        parsed = json.loads(stripped)
    except ValueError:
        parsed = None
    if isinstance(parsed, list):
        return [str(item) for item in parsed]
    inner = stripped[1:-1].strip()
    if not inner:
        return []
    return [part.strip().strip('"').strip("'") for part in inner.split(",") if part.strip()]


def coerce_claims(claims: Mapping[str, Any]) -> dict[str, Any]:
    """Coerce a gateway claim string map back to the types the JWT specification gives it.

    Only the claims named in `INTEGER_CLAIMS`, `BOOLEAN_CLAIMS`, `ARRAY_CLAIMS` and `scope`
    are touched; everything else passes through unchanged rather than being guessed at.
    """
    coerced: dict[str, Any] = dict(claims)
    for key in INTEGER_CLAIMS & coerced.keys():
        coerced[key] = _coerce_int(coerced[key])
    for key in BOOLEAN_CLAIMS & coerced.keys():
        coerced[key] = _coerce_bool(coerced[key])
    for key in ARRAY_CLAIMS & coerced.keys():
        coerced[key] = _coerce_array(coerced[key])
    scope = coerced.get("scope")
    if isinstance(scope, str):
        coerced[SCOPES_KEY] = scope.split()
    return coerced


def read_authorizer_claims(request: Request) -> AuthorizerClaims:
    """Return the verified claims for this request.

    Raises one of the three `ClaimsUnavailable` types instead of failing closed, so a parse
    fault is never mistaken for an anonymous caller.
    """
    from webbpulse.http import REQUEST_CONTEXT_HEADER

    raw = request.headers.get(REQUEST_CONTEXT_HEADER)
    if raw is None or not raw.strip():
        raise MissingRequestContext(
            f"No {REQUEST_CONTEXT_HEADER} header on this request. Behind API Gateway the "
            "Lambda Web Adapter always injects it, so this is a deployment fault rather "
            "than an anonymous caller."
        )
    try:
        context = json.loads(raw)
    except ValueError as exc:
        raise UnparseableRequestContext(
            f"The {REQUEST_CONTEXT_HEADER} header is not JSON. The Lambda Web Adapter "
            "sends it as a plain JSON string and never base64 encodes it, so this is a "
            "bug in the chain that produced the header rather than a bad token."
        ) from exc
    if not isinstance(context, Mapping):
        raise UnparseableRequestContext(
            f"The {REQUEST_CONTEXT_HEADER} header parsed as {type(context).__name__} "
            "rather than a JSON object."
        )

    authorizer = context.get("authorizer")
    if not isinstance(authorizer, Mapping):
        raise NoClaimsSection(
            "The request context carries no `authorizer` section, so no authorizer ran "
            "for this route. On an HTTP API that means the matched route key has no JWT "
            "authorizer attached."
        )
    jwt_section = authorizer.get("jwt")
    if not isinstance(jwt_section, Mapping):
        raise NoClaimsSection(
            f"The request context has an `authorizer` section with keys "
            f"{sorted(authorizer)}, and no `jwt` among them. A REQUEST authorizer puts "
            "its context under `lambda` instead, and a JWT authorizer is what this "
            "expects."
        )
    claims = jwt_section.get("claims")
    if not isinstance(claims, Mapping):
        raise NoClaimsSection(
            "The request context has `authorizer.jwt` and no `claims` beneath it."
        )
    return AuthorizerClaims(claims)


def authorizer_claims(
    *,
    environment: str = "local",
    local_fallback: Callable[[Request], AuthorizerClaims | Mapping[str, Any] | None]
    | Callable[[Request], Awaitable[AuthorizerClaims | Mapping[str, Any] | None]]
    | None = None,
) -> Any:
    """Build the FastAPI dependency returning this request's verified claims.

    Every `ClaimsUnavailable` becomes a 401 with a fixed detail string; which of the three
    faults it was goes to the log only, never to the caller.

    Args:
        environment: This deployment's name. Only used to refuse `local_fallback` in a
            production environment, and never to change what is parsed.
        local_fallback: A callable taking the `Request` and returning claims some other
            way, for a workstation where there is no API Gateway and therefore no header.
            It may be `def` or `async def`. Returning `None` means "no claims", and the
            request is refused exactly as if there had been no fallback. Refused outright
            when `environment` is production.

    Returns:
        An `async def` dependency suitable for `Depends`.

    Raises:
        ValueError: When `local_fallback` is supplied in a production environment. Raised
            at construction, so it fails at import of the service's router rather than on
            the first request that needed it.
    """
    from fastapi import HTTPException

    if local_fallback is not None and environment.strip().lower() in _REFUSED_ENVIRONMENTS:
        raise ValueError(
            f"local_fallback is refused in environment {environment!r}. A missing "
            "authorizer must fail rather than degrade into in-app verification, because "
            "a service that keeps answering 200 is how a missing authorizer goes "
            "unnoticed."
        )

    async def dependency(request: Request) -> AuthorizerClaims:
        """Return the verified claims, or raise a 401."""
        try:
            return read_authorizer_claims(request)
        except ClaimsUnavailable as exc:
            if local_fallback is None:
                _log.warning("Authorizer claims unavailable: %s", exc, exc_info=exc)
                raise HTTPException(
                    status_code=401,
                    detail="Not authenticated.",
                    headers={"WWW-Authenticate": "Bearer"},
                ) from exc

            resolved = local_fallback(request)
            if inspect.isawaitable(resolved):
                resolved = await resolved
            if resolved is None:
                raise HTTPException(
                    status_code=401,
                    detail="Not authenticated.",
                    headers={"WWW-Authenticate": "Bearer"},
                ) from exc
            return (
                resolved if isinstance(resolved, AuthorizerClaims) else AuthorizerClaims(resolved)
            )

    dependency.__name__ = "authorizer_claims"
    dependency.__doc__ = (
        "The verified JWT claims for this request, read from the API Gateway authorizer."
    )
    return dependency
