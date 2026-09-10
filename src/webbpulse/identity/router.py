"""`build_identity_router`: the router a product mounts into its identity Lambda.

Always mounts the three anonymous documents:

    GET <prefix>/.well-known/openid-configuration
    GET <prefix>/.well-known/jwks.json
    GET <prefix>/health

and, when the product supplies `hooks` **and** a `stores` carrying the credential and
refresh stores, the M2 password and session flows:

    POST <prefix>/register
    POST <prefix>/login
    POST <prefix>/password
    POST <prefix>/refresh
    POST <prefix>/logout
    POST <prefix>/logout-all

MFA, passkeys and OAuth are M4 to M6, per section 9.1 of `docs/identity-standard.md`.

## Where `<prefix>` comes from, and why you mount with no prefix of your own

`<prefix>` is the issuer's path: `/api/auth` for the standard's
`https://<host>/api/auth`, and empty for an issuer with no path, which gives origin paths.
The router places itself there, so **mount it with no prefix**.

It is the issuer's path because that is where API Gateway and the advertised `jwks_uri`
look. The gateway builds the discovery URL as `issuer + "/.well-known/openid-configuration"`
at `CreateAuthorizer` time, and `settings.jwks_uri` advertises the JWKS the same way.
Neither URL is ours to choose once the issuer is set, so the routes go where they point.

0.9.0 served the documents at the origin regardless of the issuer's path, which was wrong
for the standard's own issuer and is fixed here. See `identity_prefix`.

## Why the flows mount conditionally

A product that runs a JWKS-only function, which is how 0.9.0 shipped, passes no hooks and no
stores. Mounting a login route for it would declare an endpoint that answers 500 on its
first request, because the very first thing it does is call a hook that raises
`HookNotImplemented`. A route that cannot work should not exist: an unmountable flow is a
configuration error worth failing at composition, not at 3am.

So the rule is explicit and checkable: **flows appear exactly when the collaborators they
need are present.** `build_identity_router(settings, kms_client=kms)` is still the three
document routes and nothing else.

## Why these routes must be anonymous

API Gateway fetches both `.well-known` documents **itself**, from outside any browser
session, holding no cookies and presenting no token. Any authorizer or access gate in front
of either one means the JWT authorizer cannot retrieve the signing key, and then every
authorized route in the product fails closed. Section 2.5 names this as the single most
likely way to get the deployment wrong, and it is worth repeating at the place where the
routes are actually declared: **do not put these behind the staging access gate.**

## Caching

Both documents get an explicit `Cache-Control`. The gateway refetches the JWKS on its own
interval and the discovery document at authorizer creation, and both are on the anonymous
hot path, so an unclaimed cache policy means every fetch is a Lambda invocation.

The two get different lifetimes, and the asymmetry is the point:

- **Discovery is `max-age=3600`.** It is a pure function of the issuer and changes only when
  the issuer does, which is never in the life of a deployment.
- **JWKS is `max-age=300`.** Short, because this is the document rotation moves through. A
  long cache here is what turns rotation step 3 into an outage: a verifier holding a
  ten-hour-old JWKS has not seen the new key and rejects every token signed with it. Five
  minutes bounds that window while still absorbing the fetch volume.

Neither carries `no-store`. Neither contains a secret: a JWKS is public key material by
definition, and treating it as sensitive would be cargo cult.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final, Literal
from urllib.parse import urlsplit

from webbpulse.identity.storage import IdentityStores
from webbpulse.identity.tokens import DISCOVERY_PATH, JWKS_PATH

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Callable

    from fastapi import APIRouter, Request

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
    "LOGOUT_ALL_PATH",
    "LOGOUT_PATH",
    "PASSWORD_PATH",
    "REFRESH_PATH",
    "REGISTER_PATH",
    "build_identity_router",
    "identity_prefix",
]

#: One hour. The discovery document changes only when the issuer changes.
DISCOVERY_CACHE_CONTROL = "public, max-age=3600"

#: Five minutes. Short enough that a rotation propagates inside one step's deploy window.
JWKS_CACHE_CONTROL = "public, max-age=300"

#: Matches `webbpulse.http.health_router`, so an identity Lambda answers the same probe
#: path as every other service in the estate.
HEALTH_PATH = "/health"

#: Flow route suffixes, relative to the issuer path the router mounts under.
#:
#: Suffixes rather than absolute paths, because the prefix is not knowable here: it comes
#: from `settings.issuer`, and a product is free to issue from an origin or from a path.
#: `identity_prefix()` computes it and `build_identity_router` joins the two.
REGISTER_PATH = "/register"
LOGIN_PATH = "/login"
PASSWORD_PATH = "/password"
REFRESH_PATH = "/refresh"
LOGOUT_PATH = "/logout"
LOGOUT_ALL_PATH = "/logout-all"

#: Section 5.1's limits, as (limit, window seconds). Named here rather than inline so the
#: table in the standard and the code can be diffed against each other by eye.
LOGIN_IP_LIMIT: Final = (20, 900)
LOGIN_EMAIL_LIMIT: Final = (10, 900)
REFRESH_IP_LIMIT: Final = (120, 900)
REGISTER_IP_LIMIT: Final = (5, 3600)

#: `Sec-Fetch-Site` values a state-changing cookie route accepts. Section 5.5's first CSRF
#: supplement: the header is sent by every current major browser and cannot be set by page
#: JavaScript, so a cross-site value is a forged request. A **missing** header is allowed,
#: because a non-browser client legitimately sends none and refusing those would break every
#: integration test and curl invocation.
ALLOWED_FETCH_SITES: Final = frozenset({"same-origin", "same-site", "none"})

#: `fastapi.Request`, bound into this module's globals at first use.
#:
#: Every route below annotates a parameter `request: _FastAPIRequest`. Under
#: `from __future__ import annotations` an annotation is a **string**, and FastAPI resolves a
#: route's annotations against the defining module's namespace. A `Request` imported inside
#: a function is not in that namespace, so FastAPI could not tell the parameter was the
#: request object and treated it as a required query parameter, answering 422 to every call.
#: `webbpulse.ratelimit` hit the identical problem and solved it the identical way, and the
#: shape of that bug (a whole router answering 422 with no error anywhere) is unpleasant
#: enough to be worth solving the same way twice rather than inventing a second idiom.
_FastAPIRequest: Any = None


def _bind_fastapi_request() -> None:
    """Put `fastapi.Request` in this module's globals for FastAPI's annotation lookup."""
    global _FastAPIRequest
    if _FastAPIRequest is None:
        from fastapi import Request as _Request

        _FastAPIRequest = _Request


def identity_prefix(settings: IdentitySettings) -> str:
    """The path every identity route mounts under, taken from the issuer.

    Returns the issuer's path with any trailing slash removed, so
    `https://host/api/auth` gives `/api/auth` and `https://host` gives `""`. Joining a
    suffix onto the result is always well formed: an empty prefix leaves the suffix's own
    leading slash to do the work.

    **Derived rather than configured, because the issuer already decides it.** API Gateway
    builds the discovery URL as `issuer + "/.well-known/openid-configuration"` at
    `CreateAuthorizer` time, and `settings.jwks_uri` advertises the JWKS the same way. Those
    two URLs are not ours to choose once the issuer is set, so the routes have to be where
    they point. A second setting for the mount path would be a second source of truth for
    one fact, and the failure it invites is silent: the documents serve 200 at a path
    nothing fetches, while the gateway gets a 404 and every authorized route in the product
    fails closed.

    This is a behaviour change from 0.9.0, which served the documents at the origin whatever
    the issuer's path was. That was wrong for the standard's own `https://<host>/api/auth`
    issuer, and the Portfolio pilot hit it: a test that followed the served `jwks_uri` found
    a 404, and the workaround was to mount the router under a hand-written prefix. Deriving
    the prefix here makes that workaround unnecessary, and makes the doubled
    `/api/auth/api/auth` it would now produce impossible.
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
    limiter_enabled: bool = True,
) -> APIRouter:
    """The identity router for a product, mounted with no prefix.

    `settings` is an `IdentitySettings`. Pass `hooks` and a `stores` holding the credential
    and refresh stores to get the M2 flows as well as the three documents; omit either and
    only the documents mount. See the module docstring for why that is conditional.

    `attempts` is the `login-attempts` store backing progressive lockout. Omit it and the
    flows still work, with lockout disabled: it is a hardening measure, and a product that
    has not created the table should still be able to sign its users in.

    `limiter_enabled` turns off the `webbpulse.ratelimit` dependencies. It exists for tests
    and for a local run with no DynamoDB, and production leaves it `True`. The limiter fails
    open on its own when the table is unreachable (section 5.1), so this flag is about not
    building the dependency at all rather than about tolerating a failure.

    `tokens` is a `TokenService`. Pass one to share a single instance, and its JWK cache,
    with the rest of the service. Omit it and one is built from `settings` and `kms_client`,
    which is the ordinary case.

    `service` and `version` are what `/health` reports, matching the arguments
    `webbpulse.http.health_router` takes for the same purpose.

    **Mount this with no prefix**, even in a service whose other routers sit under
    `/api/v1`. The router places itself under the issuer's path, because that is where API
    Gateway and the advertised `jwks_uri` look for it: the gateway builds the discovery URL
    as `issuer + "/.well-known/openid-configuration"`, and `settings.jwks_uri` advertises
    the JWKS the same way. For the standard's `https://<host>/api/auth` issuer every route
    lands under `/api/auth`; for an issuer with no path they land at the origin. Adding a
    prefix of your own puts the documents where nothing will look for them, or doubles the
    issuer path if you mount under it by hand.

    Every route here is anonymous, deliberately. See the module docstring.
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

    # Every route hangs off the issuer's path. See `identity_prefix` for why this is derived
    # rather than configured, and the docstring above for why the caller adds no prefix.
    prefix = identity_prefix(settings)

    router = APIRouter(tags=["identity"])

    # Each returns an explicit `JSONResponse` rather than taking a `response: Response`
    # parameter and mutating its headers. Under `from __future__ import annotations` that
    # parameter's annotation is the *string* "Response", and FastAPI, unable to resolve it
    # to the class from this function's local import, treats it as a required query
    # parameter and answers 422 to every request. Returning the response sidesteps the
    # resolution problem entirely.

    @router.get(f"{prefix}{DISCOVERY_PATH}", include_in_schema=False)
    async def discovery_document() -> JSONResponse:
        return JSONResponse(tokens.discovery(), headers={"Cache-Control": DISCOVERY_CACHE_CONTROL})

    @router.get(f"{prefix}{JWKS_PATH}", include_in_schema=False)
    async def jwks_document() -> JSONResponse:
        return JSONResponse(tokens.jwks(), headers={"Cache-Control": JWKS_CACHE_CONTROL})

    @router.get(f"{prefix}{HEALTH_PATH}", include_in_schema=False)
    async def health() -> dict[str, Any]:
        # Shape matches `webbpulse.http.health_router` so one probe configuration works
        # across every service. Deliberately does not call KMS: a health check that depends
        # on a downstream turns a KMS blip into an unhealthy target and a restart loop,
        # and the JWKS route already fails loudly if KMS is genuinely unreachable.
        return {
            "status": "healthy",
            "service": service,
            "version": version,
        }

    if hooks is not None and resolved_stores.credentials is not None:
        _mount_flows(
            router,
            prefix=prefix,
            settings=settings,
            hooks=hooks,
            stores=resolved_stores,
            tokens=tokens,
            attempts=attempts,
            limiter_enabled=limiter_enabled,
        )

    return router


def _mount_flows(
    router: APIRouter,
    *,
    prefix: str,
    settings: IdentitySettings,
    hooks: IdentityHooks,
    stores: IdentityStores,
    tokens: TokenService,
    attempts: LoginAttemptStore | None,
    limiter_enabled: bool,
) -> None:
    """Add the six M2 flow routes to an already-built router.

    Split out of `build_identity_router` because that function is otherwise readable in one
    screen and this half is three times its length. The split is also the seam M3 to M6 will
    extend: each later milestone adds its own `_mount_*` rather than growing one function
    past the point anybody reads it.

    Every route returns an explicit `JSONResponse`, for the same reason the document routes
    do. Under `from __future__ import annotations` a `response: Response` parameter is the
    unresolvable string `"Response"`, which FastAPI treats as a required query parameter and
    answers 422 to. Returning the response and calling `set_cookie` on it sidesteps that.
    """
    from fastapi import Body, Depends
    from fastapi.responses import JSONResponse

    from webbpulse.identity.flows import IdentityFlows, LoginRejected, RateLimited
    from webbpulse.identity.passwords import PasswordRejected

    # Must happen before the first `@router.post` below. See `_FastAPIRequest`.
    _bind_fastapi_request()

    flows = IdentityFlows(settings, hooks, stores, tokens, attempts=attempts)

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

        `httponly` is what keeps JavaScript from reading it, `secure` keeps it off plain
        HTTP, `samesite=lax` is the primary CSRF defence and is available only because both
        products serve frontend and API under one registrable domain, and `path` keeps it
        off every other domain's routes so the catalog function can never log it.
        """
        response.set_cookie(settings.cookie_name, token, **settings.cookie_kwargs())
        return response

    def clear_refresh_cookie(response: JSONResponse) -> JSONResponse:
        """Delete the cookie, with the same attributes it was set with.

        `path` and `domain` must match the `Set-Cookie` that created it or the browser
        treats the deletion as a different cookie and leaves the original in place, which
        would leave a revoked token sitting in the browser to be sent on every subsequent
        request.
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
        token is **never** in the body: it goes in the cookie, and putting it here as well
        would hand it to any script that can read a fetch response, defeating `httponly`.
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
            # The address already has an account. Section 5.4: the same 200 a real
            # registration gets, with no token, because there is no session to start. The
            # SPA shows "check your email either way", which is true in both branches once
            # M3 sends the notice to the existing address.
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
        except LoginRejected as exc:
            return rejected(request, exc)
        return set_refresh_cookie(JSONResponse(success_body(result)), result.refresh_token)

    @router.post(f"{prefix}{PASSWORD_PATH}")
    async def change_password(
        request: _FastAPIRequest, payload: dict[str, Any] = Body(...)
    ) -> JSONResponse:
        # Behind the gateway's JWT authorizer per section 2.3, so the caller is already
        # authenticated and the subject comes from the verified claims rather than the body.
        # Reading it from the body would let anybody change anybody's password.
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
        if not _fetch_site_allowed(request):
            # The cookie is deliberately **not** cleared here, unlike every other refusal on
            # this route. A cross-site refusal means the request was forged, so the session
            # it names is the victim's and is perfectly good. Clearing it would let any
            # attacker page sign a victim out by causing one refused request, turning the
            # CSRF defence into the denial of service it was meant to prevent.
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
            # The cookie is cleared on every refusal, whatever the cause. A token that has
            # just been refused will never work again, so leaving it in the browser only
            # guarantees the next request repeats the failure.
            return clear_refresh_cookie(rejected(request, exc))
        return set_refresh_cookie(JSONResponse(success_body(result)), result.refresh_token)

    @router.post(f"{prefix}{LOGOUT_PATH}")
    async def logout(request: _FastAPIRequest) -> JSONResponse:
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
        # Always 200. Logout is idempotent and the caller's intent is to end up signed out,
        # so an unknown or expired cookie is a success, not an error. Telling the caller
        # their cookie was already dead is also a signal they should not get.
        return clear_refresh_cookie(JSONResponse({"signed_out": True}))

    @router.post(f"{prefix}{LOGOUT_ALL_PATH}")
    async def logout_all(request: _FastAPIRequest) -> JSONResponse:
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


async def run_sync[T](work: Callable[[], T]) -> T:
    """Run blocking work off the event loop.

    Every flow method is synchronous: bcrypt burns CPU for the better part of a hundred
    milliseconds and boto3 blocks on a socket. Calling either directly from an `async def`
    route stalls the whole worker for that time, so a login would serialise every other
    request the process is serving. Starlette's threadpool is what a plain `def` route would
    have been given anyway.
    """
    from starlette.concurrency import run_in_threadpool

    return await run_in_threadpool(work)


async def _email_key_fn(request: _FastAPIRequest) -> str:
    """Rate limit key for the per-email login limit. Section 5.1.

    Limiting login by both IP and email matters: by IP alone a distributed attacker walks
    past it, and by email alone one attacker can lock out a known user, which is why both
    limits exist rather than either one.

    Reads the request body to find the address. `request.body()` caches on the request, so
    reading it in a dependency does not consume the stream the route handler later parses:
    Starlette returns the same buffered bytes to both. Doing this any other way, such as
    pulling the email from a query parameter, would put a credential-adjacent value in an
    access log.

    Falls back to the IP whenever there is no parseable address, so a malformed body is
    still limited rather than being an unlimited hole in the per-email ceiling. The
    namespaces differ between the two limits, so an IP fallback here does not consume the
    per-IP budget the other dependency is counting.
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
    practice. It exists so that `delete_cookie` is called with a literal the type checker
    can see, rather than with an ignore comment standing where a check should be.
    """
    return value if value in {"lax", "strict", "none"} else "lax"  # type: ignore[return-value]


def _fetch_site_allowed(request: Request) -> bool:
    """Section 5.5's first CSRF supplement.

    `Sec-Fetch-Site` is set by the browser and cannot be set by page JavaScript, so a value
    of `cross-site` on a state-changing cookie route is a forged request whatever the cookie
    says. A missing header is allowed: non-browser clients send none, and refusing those
    would break every server-to-server caller and every curl invocation for no security
    gain, since an attacker's page cannot suppress the header a browser adds.
    """
    value = request.headers.get("sec-fetch-site", "")
    return not value or value.lower() in ALLOWED_FETCH_SITES


def _subject_from_request(request: Request, tokens: TokenService) -> str:
    return _claims_from_request(request, tokens).get("sub", "")


def _session_from_request(request: Request, tokens: TokenService) -> str:
    return _claims_from_request(request, tokens).get("sid", "")


def _claims_from_request(request: Request, tokens: TokenService) -> dict[str, str]:
    """Verified claims for a route the gateway's JWT authorizer sits in front of.

    Two sources, in order:

    1. **The authorizer context**, which API Gateway puts in the Lambda event and the Web
       Adapter forwards as a header. Preferred, because the gateway has already verified the
       signature and this code re-verifying it would be duplicated work on the hot path.
    2. **The `Authorization` header**, verified here through `TokenService`. This is the
       local and test path, and the path for a deployment that has not put the authorizer in
       front of the flow routes.

    Returns an empty mapping rather than raising when there is nothing valid, and the caller
    turns that into a 401. Never trusts an unverified claim from either source.
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
            # The gateway presents every claim as a string, `exp` included. It has already
            # verified the signature, so these are trusted.
            return {str(k): str(v) for k, v in claims.items()}

    authorization = request.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return {}
    try:
        verified = tokens.verify_access_token(token)
    except Exception:
        # Any verification failure is simply "not authenticated". The specific reason is not
        # something to tell the caller, and the token service has already logged it.
        return {}
    return {str(k): str(v) for k, v in verified.items()}
