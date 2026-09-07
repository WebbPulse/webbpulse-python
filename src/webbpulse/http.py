"""FastAPI app factory, request id, error handlers, and the client IP.

`create_app` builds one domain's FastAPI application. `mount_all` composes several of them
into the single app that local development, the test suite and a plain container run, which
is the second composition root: one entrypoint per domain in production, one mounted app
everywhere else, from the same routers.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Iterable, Mapping, Sequence
from typing import TYPE_CHECKING, Any, Final

from fastapi import APIRouter, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

if TYPE_CHECKING:  # pragma: no cover - typing only
    from webbpulse.config import BaseServiceSettings

__all__ = [
    "LAMBDA_CONTEXT_HEADER",
    "REQUEST_CONTEXT_HEADER",
    "REQUEST_ID_HEADER",
    "RequestIdMiddleware",
    "client_ip",
    "create_app",
    "health_router",
    "mount_all",
    "request_id",
]

_log = logging.getLogger(__name__)

#: The header the Lambda Web Adapter injects, carrying the API Gateway request context as a
#: JSON string. Verified against the adapter's own documentation, which describes it as:
#: "API Gateway sends metadata (requestId, requestTime, apiId, identity, authorizer) for
#: each request. This is forwarded in the `x-amzn-request-context` header as a JSON string."
REQUEST_CONTEXT_HEADER: Final = "x-amzn-request-context"

#: The companion header carrying the Lambda invocation context (function name, deadline).
LAMBDA_CONTEXT_HEADER: Final = "x-amzn-lambda-context"

#: Request id, accepted from the caller when present and echoed on every response.
REQUEST_ID_HEADER: Final = "X-Request-ID"

_REQUEST_ID_STATE: Final = "webbpulse_request_id"


def client_ip(request: Request, *, local_fallback: bool = True) -> str:
    """The caller's IP address, taken from the API Gateway request context.

    **Why not X-Forwarded-For.** Behind API Gateway the leftmost `X-Forwarded-For` hop is
    whatever the client sent, and a client can send anything. Rate limiting or blocking on
    it lets a caller mint a fresh identity per request by varying one header, which is worse
    than not limiting at all because it looks like it works. This function never reads it.

    The trustworthy value is the source IP API Gateway itself observed, which arrives in the
    `x-amzn-request-context` header the Web Adapter injects. Two payload shapes exist and
    both are handled:

    - HTTP API, payload format 2.0: `requestContext.http.sourceIp`
    - REST API, payload format 1.0: `requestContext.identity.sourceIp`

    Returns `"unknown"` when there is no request context and no local fallback applies, and
    callers must treat that as a single shared bucket rather than as a distinct identity.

    **Local development fallback.** With `local_fallback=True` (the default) a request that
    carries no API Gateway context at all falls back to `request.client.host`, which is the
    real peer address of the socket. That is correct when uvicorn is reached directly, which
    is exactly the local, test and container case. It is *not* reached in production,
    because in production the header is always present. If a service is ever placed behind a
    proxy that is not API Gateway, pass `local_fallback=False` and give it an explicit
    trusted-proxy implementation rather than trusting the peer address.

    This is the piece that most needs to be shared rather than reimplemented: the previous
    per-app version read `request.scope["aws.event"]`, which Mangum populated and the Web
    Adapter does not, so on migration it silently stopped matching and fell through to the
    spoofable header without anything failing.
    """
    raw = request.headers.get(REQUEST_CONTEXT_HEADER)
    if raw:
        try:
            context = json.loads(raw)
        except (TypeError, ValueError):
            _log.warning("Could not parse %s as JSON; ignoring it.", REQUEST_CONTEXT_HEADER)
            context = None
        if isinstance(context, Mapping):
            # Payload format 2.0 first, since every new HTTP API uses it.
            http_section = context.get("http")
            if isinstance(http_section, Mapping):
                source_ip = http_section.get("sourceIp")
                if isinstance(source_ip, str) and source_ip:
                    return source_ip
            # Payload format 1.0, REST APIs.
            identity = context.get("identity")
            if isinstance(identity, Mapping):
                source_ip = identity.get("sourceIp")
                if isinstance(source_ip, str) and source_ip:
                    return source_ip

    if local_fallback and request.client is not None and request.client.host:
        return request.client.host
    return "unknown"


def request_id(request: Request) -> str:
    """The current request's id, as set by `RequestIdMiddleware`.

    Usable as a FastAPI dependency: `rid: str = Depends(request_id)`.
    """
    value = getattr(request.state, _REQUEST_ID_STATE, None)
    return value if isinstance(value, str) else "-"


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Assign every request an id, expose it on `request.state`, echo it on the response.

    An inbound `X-Request-ID` is honoured so a value set at the edge survives, and a new
    UUID4 is minted otherwise. The id is also attached to the active OpenTelemetry span, so
    a log line, a trace and a support ticket can all be joined on the same string.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        incoming = request.headers.get(REQUEST_ID_HEADER, "").strip()
        # Bound the length so a hostile header cannot inflate every log line downstream.
        rid = incoming[:128] if incoming else str(uuid.uuid4())
        setattr(request.state, _REQUEST_ID_STATE, rid)

        try:
            from opentelemetry import trace

            span = trace.get_current_span()
            if span.get_span_context().is_valid:
                span.set_attribute("webbpulse.request_id", rid)
        except ImportError:  # pragma: no cover - otel extra absent
            pass

        response = await call_next(request)
        response.headers[REQUEST_ID_HEADER] = rid
        return response


def health_router(
    *, service: str, version: str, checks: Mapping[str, Any] | None = None
) -> APIRouter:
    """A router exposing `GET /health`.

    Liveness only, and deliberately so. It always returns 200 and never touches DynamoDB,
    because the Lambda Web Adapter polls this path as its readiness check on every cold
    start: a health route that queries a table adds that query to every cold start and makes
    the function fail to start at all when the table is briefly unavailable. Readiness
    checks that do touch dependencies belong on a separate path that the adapter does not
    poll.
    """
    router = APIRouter(tags=["health"])
    static: dict[str, Any] = dict(checks or {})

    @router.get("/health", include_in_schema=False)
    async def health() -> dict[str, Any]:
        return {"status": "healthy", "service": service, "version": version, **static}

    return router


def _error_body(status_code: int, message: str, request: Request, **extra: Any) -> dict[str, Any]:
    return {
        "success": False,
        "status": status_code,
        "message": message,
        "request_id": request_id(request),
        **extra,
    }


def register_error_handlers(app: FastAPI) -> None:
    """Install handlers that render every error in one JSON envelope.

    Without these, a validation error and an unhandled exception have different shapes and
    the second one leaks a stack trace to the caller in some configurations. All three
    handlers log through the JSON formatter, so an error is visible in CloudWatch with its
    request id whether or not the caller ever reports it.
    """

    @app.exception_handler(StarletteHTTPException)
    async def _http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        # Starlette types `detail` as str, but HTTPException accepts any object and
        # FastAPI routes commonly raise one with a dict detail, so the check stays.
        detail = (
            exc.detail
            if isinstance(exc.detail, str)  # type: ignore[redundant-expr]
            else "Request failed."
        )
        # 5xx raised deliberately is still a server fault worth an ERROR line; 4xx is not.
        if exc.status_code >= 500:
            _log.error(detail, extra={"status": exc.status_code, "path": request.url.path})
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(exc.status_code, detail, request),
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # `exc.errors()` can carry the offending input, which may be a password or token.
        # Only the location and the reason are returned, never the value.
        errors = [
            {
                "loc": list(error.get("loc", ())),
                "msg": error.get("msg", ""),
                "type": error.get("type", ""),
            }
            for error in exc.errors()
        ]
        return JSONResponse(
            status_code=422,
            content=_error_body(422, "Request validation failed.", request, errors=errors),
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        _log.exception(
            "Unhandled exception serving the request.",
            extra={"path": request.url.path, "method": request.method},
        )
        # The message is deliberately generic. The detail is in CloudWatch, joined to this
        # response by the request id, rather than in the response body.
        return JSONResponse(
            status_code=500,
            content=_error_body(500, "Internal server error.", request),
        )


def create_app(
    domain_routers: Iterable[APIRouter] = (),
    *,
    title: str = "WebbPulse service",
    version: str = "0.0.0",
    service_name: str = "webbpulse",
    settings: BaseServiceSettings | None = None,
    cors_allow_origins: Sequence[str] | None = None,
    cors_allow_credentials: bool | None = None,
    router_prefix: str = "",
    include_health: bool = True,
    instrument: bool = True,
    **fastapi_kwargs: Any,
) -> FastAPI:
    """Build one domain's FastAPI application.

    Adds, in the order the request traverses them: CORS, the request id middleware, the
    structured error handlers, and a `GET /health` route.

    CORS origins come from `settings` when given, or from `cors_allow_origins`. When
    credentials are allowed the origin list must be exact, never `"*"`: the CORS
    specification forbids that pair, and browsers reject the response rather than the server
    doing so, which makes it look like a client bug.

    `instrument=True` attaches the OpenTelemetry FastAPI instrumentation when the `otel`
    extra is installed and tracing is enabled. Call `configure_tracing` first so the spans
    reach a real provider.
    """
    origins = (
        list(cors_allow_origins)
        if cors_allow_origins is not None
        else (list(settings.cors_allow_origins) if settings is not None else [])
    )
    allow_credentials = (
        cors_allow_credentials
        if cors_allow_credentials is not None
        else (settings.cors_allow_credentials if settings is not None else True)
    )
    if allow_credentials and "*" in origins:
        raise ValueError(
            "CORS cannot allow credentials with a wildcard origin. List the exact origins."
        )

    app = FastAPI(title=title, version=version, **fastapi_kwargs)

    # Starlette runs middleware in reverse registration order, so registering CORS last puts
    # it outermost. That matters: an error raised deeper must still come back with CORS
    # headers, or the browser reports an opaque CORS failure instead of the real status.
    app.add_middleware(RequestIdMiddleware)
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=allow_credentials,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Accept", "Authorization", "Content-Type", "Origin", REQUEST_ID_HEADER],
            expose_headers=[REQUEST_ID_HEADER, "RateLimit", "RateLimit-Policy", "Retry-After"],
            max_age=86400,
        )

    register_error_handlers(app)

    if include_health:
        app.include_router(health_router(service=service_name, version=version))
    for router in domain_routers:
        app.include_router(router, prefix=router_prefix)

    if instrument:
        from webbpulse.otel import instrument_fastapi

        instrument_fastapi(app)
    return app


def mount_all(
    apps: Mapping[str, FastAPI],
    *,
    title: str = "WebbPulse",
    version: str = "0.0.0",
    service_name: str = "webbpulse",
    **fastapi_kwargs: Any,
) -> FastAPI:
    """Mount several domain apps under one parent. The local and test composition root.

    Production runs one entrypoint per domain, each importing only its own routers, which is
    what makes a cold start cheap and one domain's dependencies invisible to another. Local
    development, the test suite and a plain `docker run` want the whole surface at one port,
    and this builds that from the very same app objects rather than from a second wiring
    that can drift::

        app = mount_all({"/api/v1/posts": posts_app, "/api/v1/skills": skills_app})

    Each mount path must be the same prefix API Gateway routes to that domain's function, so
    a path that works locally works in production. Note that a mounted sub-application keeps
    its own middleware and exception handlers, so each domain app's error envelope and
    request id continue to work; the parent adds its own `/health` for the container itself.
    """
    parent = FastAPI(title=title, version=version, **fastapi_kwargs)
    parent.include_router(health_router(service=service_name, version=version))
    register_error_handlers(parent)

    for path, sub_app in apps.items():
        if not path.startswith("/"):
            raise ValueError(f"Mount path must start with '/', got {path!r}.")
        # Starlette raises on a trailing slash mount, and the resulting 404s are confusing.
        parent.mount(path.rstrip("/") or "/", sub_app)
    return parent
