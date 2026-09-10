"""The one parser for the API Gateway authorizer's claims, and its FastAPI dependency.

A domain Lambda behind an HTTP API JWT authorizer verifies nothing. The gateway has already
rejected every request that did not carry a valid token, so the claims that arrive are
trustworthy input. What this module owns is reading them, and it owns that alone: section
2.4 of `docs/identity-standard.md` makes "one parser for this header, in the package" a
requirement of M1 rather than a preference.

## Why that is a requirement and not a style note

M0 had two independent readings of `x-amzn-request-context`. `webbpulse.http.client_ip`
parsed it as plain JSON, which is what the Lambda Web Adapter sends and what its own
documentation says it sends. The spike's handler base64-decoded it first. The decode raised,
the handler caught the error and returned an empty mapping, and the empty mapping became a
401 that was indistinguishable from a token the gateway had rejected. A one-line bug cost an
afternoon of suspecting the gateway, the container image and the KMS key in turn.

The lesson generalises past the adapter: **a decoding assumption that fails closed into
"unauthenticated" is indistinguishable from a real authorization failure**. So this module
does the opposite of what the spike did.

- It parses plain JSON, reusing `webbpulse.http.request_context` rather than repeating the
  parse, so there is exactly one implementation of the header's encoding in the package.
- It distinguishes a missing header, an unparseable header and a header with no claims
  section, and says which one it was. Those are a deployment fault, a bug in our own code
  and a routing fault respectively. None of them is an anonymous caller.
- It never swallows a decode error into an empty mapping.

## Every claim value arrives as a string

This is the fact that most reliably surprises a caller, and M0 observed it directly rather
than inferring it. API Gateway flattens the verified claim set into a string map before
putting it in the request context, so a `whoami` handler behind a real authorizer saw::

    {"typ": "access", "sub": "spike-2", "iss": "https://api.staging.webbpulse.com",
     "aud": "webbpulse-staging", "iat": "1788938046", "nbf": "1788938046",
     "exp": "1788938646", "jti": "976037a1ea4847da8a633b3338d61f65"}

`exp`, `iat` and `nbf` are quoted. The JWT specification says they are numbers, so any code
treating them as numbers has to coerce first, and a comparison like `claims["exp"] < now`
against a string raises `TypeError` in Python rather than quietly misbehaving, which is the
one mercy in it.

`authorizer_claims` therefore coerces, and it is explicit about what it touches rather than
guessing per value:

- **`exp`, `iat`, `nbf`, `auth_time`** become `int`. A value that is not an integer string
  is left exactly as it arrived, because a claim this service did not mint is not worth
  raising over on a request the gateway already accepted.
- **`email_verified`** becomes `bool`, from the JSON spellings `"true"` and `"false"`
  case-insensitively. Nothing else is coerced to a bool: a claim named like a flag but
  spelled `"1"` by some other issuer stays a string rather than being guessed at.
- **`scope`** becomes a `list[str]` split on whitespace, per RFC 8693, and is also kept in
  its original spelling under `scope` for a caller that wants the raw string. The split form
  is `scopes`, a name the wire format does not use, so nothing is overwritten.
- **`amr`, `roles`, `groups`, `aud`** become a `list[str]` when they arrive as an encoded
  array. The gateway emits an array claim in one of two spellings and both are handled: a
  JSON array (`'["a","b"]'`) and the bracketed comma form the flattener produces
  (`'[a, b]'`). A bare value with no brackets becomes a one-element list, because a single
  audience is the common case and a caller should not have to branch on it.

Coercion is applied to a copy. The mapping handed back carries the coerced values, and
`raw` on the returned object carries exactly what the gateway sent, so a caller debugging a
claim mismatch can see the wire bytes without a second parse.

## The local development seam

There is no API Gateway on a workstation, so there is no header. `authorizer_claims(...)`
takes `local_fallback`, a callable that produces claims some other way, typically by
verifying a bearer token in-process against the JWKS. That keeps `webbpulse.http.mount_all`
working without a second wiring.

The fallback is **refused outright when `environment` names a production environment**, so a
misconfigured authorizer can never silently degrade into in-app verification in a deployed
environment. That refusal is not a courtesy: without it, the failure mode of a missing
authorizer is a service that keeps answering 200 while verifying tokens with whatever the
fallback happens to trust.
"""

from __future__ import annotations

import inspect
import json
import logging
from collections.abc import Awaitable, Callable, Mapping
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:  # pragma: no cover - typing only
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

#: Claims the JWT specification defines as a NumericDate, which the gateway sends as a
#: quoted integer. `auth_time` is in the list because OIDC defines it the same way and a
#: product's hooks may add it.
INTEGER_CLAIMS: Final[frozenset[str]] = frozenset({"exp", "iat", "nbf", "auth_time"})

#: Claims coerced from `"true"`/`"false"` to a real bool. Deliberately short: a claim that
#: merely looks like a flag is left as the string it arrived as.
BOOLEAN_CLAIMS: Final[frozenset[str]] = frozenset({"email_verified"})

#: Claims that are arrays in the token and arrive encoded as one string.
ARRAY_CLAIMS: Final[frozenset[str]] = frozenset({"amr", "roles", "groups", "aud"})

#: The key the split form of `scope` is published under. Not `scope`, so the raw
#: space-delimited string the OAuth specifications define stays available unchanged.
SCOPES_KEY: Final = "scopes"

#: Environments where `local_fallback` is refused whatever the caller passes. Matches the
#: refusal list in `webbpulse.identity.tokens`, so one environment name means one thing
#: across the module.
_REFUSED_ENVIRONMENTS: Final[frozenset[str]] = frozenset({"production", "prod"})


class ClaimsUnavailable(Exception):
    """Base class for the three ways the authorizer's claims can fail to arrive.

    Caught as one type by a caller that only wants to answer 401, and caught individually by
    a caller that wants to alarm differently on each, which is the point of there being
    three. None of the three means the caller was anonymous: the gateway rejects an
    anonymous request before the function is invoked at all.
    """


class MissingRequestContext(ClaimsUnavailable):
    """No `x-amzn-request-context` header at all.

    A **deployment fault**. In production the Lambda Web Adapter always injects this header,
    so its absence means the function is not behind the adapter, or is being reached by
    something other than API Gateway. Locally it means no fallback was configured.
    """


class UnparseableRequestContext(ClaimsUnavailable):
    """The header was present and could not be read as JSON.

    A **bug in our own code**, or a genuinely corrupt value. The adapter sends plain JSON;
    anything else means something in the chain has re-encoded it. This is the failure M0
    spent an afternoon on, and it is raised rather than swallowed for exactly that reason.
    """


class NoClaimsSection(ClaimsUnavailable):
    """The request context parsed, and carries no `authorizer.jwt.claims`.

    A **routing fault**. The function was invoked without the JWT authorizer having run,
    which on an HTTP API means the route key this request matched has no authorizer attached
    or has a REQUEST authorizer instead. The token was never checked, so the request must be
    refused.
    """


class AuthorizerClaims(Mapping[str, Any]):
    """The verified claims, coerced, with the wire form kept alongside.

    A `Mapping`, so `claims["sub"]` and `claims.get("email")` work and a handler annotating
    the dependency as `Mapping[str, Any]` needs no conversion. `raw` carries the string map
    exactly as API Gateway sent it, which is what a caller debugging a claim mismatch wants
    and what a second coercion pass would otherwise destroy.
    """

    __slots__ = ("_coerced", "_raw")

    def __init__(self, raw: Mapping[str, Any]) -> None:
        self._raw = dict(raw)
        self._coerced = coerce_claims(raw)

    @property
    def raw(self) -> dict[str, Any]:
        """The claims exactly as the gateway sent them, before any coercion."""
        return dict(self._raw)

    def __getitem__(self, key: str) -> Any:
        return self._coerced[key]

    def __iter__(self) -> Any:
        return iter(self._coerced)

    def __len__(self) -> int:
        return len(self._coerced)

    def __repr__(self) -> str:
        # `sub` only. A repr in a log line must not spill an email or a scope list, and the
        # subject is the one claim that is useful for correlation and is already the log
        # context's `user_id`.
        return f"AuthorizerClaims(sub={self._coerced.get('sub')!r})"


def _coerce_int(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return int(value)
    except ValueError:
        # A claim this service did not mint, on a request the gateway already accepted.
        # Leaving it alone beats raising and turning a foreign claim into a 500.
        return value


def _coerce_bool(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    lowered = value.strip().lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    return value


def _coerce_array(value: Any) -> Any:
    """A gateway-encoded array claim to a `list[str]`.

    Two spellings arrive, and which one depends on how the claim was encoded in the token:

    - A JSON array, `'["reader", "writer"]'`, which parses.
    - The bracketed comma form the claim flattener produces for a token array,
      `'[reader, writer]'`, which is not JSON at all and has to be split by hand.

    A value with no brackets is a single audience or a single role, and becomes a
    one-element list so a caller never has to branch on the arity.
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
    # The bracketed comma form. Strip the brackets and split; entries are bare, so a
    # surrounding quote from a mixed encoding is stripped too rather than kept as data.
    inner = stripped[1:-1].strip()
    if not inner:
        return []
    return [part.strip().strip('"').strip("'") for part in inner.split(",") if part.strip()]


def coerce_claims(claims: Mapping[str, Any]) -> dict[str, Any]:
    """Coerce a gateway claim string map back to the types the JWT specification gives it.

    Separate from the request plumbing so a test can drive it with a fixture shaped exactly
    like the gateway's output, and so a caller holding claims from somewhere else (a
    contract test, a replayed access log line) can run the identical conversion.

    The module docstring lists exactly which claims are touched. Everything else passes
    through unchanged, including any claim a product's hooks added, because guessing at a
    type from a value is how `"1"` becomes `True` in one service and stays `"1"` in another.
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
        # RFC 8693: `scope` is a space-delimited string. Published under a second key so the
        # raw spelling survives for anything that re-signs or forwards it.
        coerced[SCOPES_KEY] = scope.split()
    return coerced


def read_authorizer_claims(request: Request) -> AuthorizerClaims:
    """The verified claims for this request, or one of the three `ClaimsUnavailable` types.

    The whole of the parse, with no HTTP concerns. `authorizer_claims` wraps this in a
    dependency that renders the package's error envelope; a caller outside a request path
    (a middleware, a test, a queue consumer replaying a context) uses this directly.
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
        # Never an empty mapping. See the module docstring: swallowing this is what made a
        # parsing bug present as an authorization outcome during M0.
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

    Used the way the standard's section 2.4 writes it::

        from webbpulse.identity import authorizer_claims

        Principal = Annotated[Mapping[str, Any], Depends(authorizer_claims())]

        @router.get("/build-lists")
        async def list_build_lists(principal: Principal) -> list[BuildList]:
            return repos.build_lists.for_user(principal["sub"])

    Every `ClaimsUnavailable` becomes a 401 in the package's own error envelope, through
    `fastapi.HTTPException` so `register_error_handlers` renders it like every other error
    in the service. The message the exception carries goes to the log, and the caller gets
    a fixed string: which of the three faults it was is operational detail and telling an
    unauthenticated caller that the route has no authorizer attached is an invitation.

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
    # Carried so a service's OpenAPI and FastAPI's own error messages name the concept
    # rather than an inner function, matching what `user_id_dependency` does in `http`.
    dependency.__doc__ = (
        "The verified JWT claims for this request, read from the API Gateway authorizer."
    )
    return dependency
