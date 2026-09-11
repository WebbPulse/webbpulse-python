"""FastAPI app factory, request id, error handlers, and the client IP.

`create_app` builds one domain's application and `mount_all` composes several into the app
local development and tests run. Bind the user id with `user_id_dependency`, never from a
sync dependency, whose context Starlette's threadpool discards.
"""

from __future__ import annotations

import inspect
import json
import logging
import uuid
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from webbpulse.log_context import request_id_var, set_request_id, set_user_id

if TYPE_CHECKING:  # pragma: no cover
    from webbpulse.config import BaseServiceSettings

__all__ = [
    "DYNAMODB_RETRY_AFTER_SECONDS",
    "LAMBDA_CONTEXT_HEADER",
    "REQUEST_CONTEXT_HEADER",
    "REQUEST_ID_HEADER",
    "ErrorSpec",
    "ExceptionMap",
    "RequestIdMiddleware",
    "bind_user_id",
    "client_ip",
    "create_app",
    "error_body",
    "health_router",
    "install_dynamodb_handlers",
    "mount_all",
    "register_error_handlers",
    "request_id",
    "user_id_dependency",
]

_log = logging.getLogger(__name__)

REQUEST_CONTEXT_HEADER: Final = "x-amzn-request-context"

LAMBDA_CONTEXT_HEADER: Final = "x-amzn-lambda-context"

REQUEST_ID_HEADER: Final = "X-Request-ID"

_REQUEST_ID_STATE: Final = "webbpulse_request_id"

_STATUS_ERROR_CODES: Final[Mapping[int, str]] = {
    400: "BAD_REQUEST",
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    409: "CONFLICT",
    422: "VALIDATION_ERROR",
    429: "RATE_LIMITED",
    500: "INTERNAL_ERROR",
    503: "SERVICE_UNAVAILABLE",
}

_ROUTING_DETAILS: Final[Mapping[str, str]] = {
    "Not Found": "The requested resource was not found.",
    "Method Not Allowed": "That method is not allowed on this resource.",
}


def client_ip(request: Request, *, local_fallback: bool = True) -> str:
    """The caller's IP address, read from the API Gateway request context header.

    `X-Forwarded-For` is never read, because a client can forge it. Falls back to the peer
    address when `local_fallback` is set, and returns `"unknown"` otherwise.
    """
    raw = request.headers.get(REQUEST_CONTEXT_HEADER)
    if raw:
        try:
            context = json.loads(raw)
        except (TypeError, ValueError):
            _log.warning("Could not parse %s as JSON; ignoring it.", REQUEST_CONTEXT_HEADER)
            context = None
        if isinstance(context, Mapping):
            http_section = context.get("http")
            if isinstance(http_section, Mapping):
                source_ip = http_section.get("sourceIp")
                if isinstance(source_ip, str) and source_ip:
                    return source_ip
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


async def bind_user_id(user_id: object) -> str:
    """Bind the user id for the rest of the request and return the cleaned string.

    Being a coroutine is the point: it runs in the request's own context, unlike the same
    binding made from a sync dependency. Await it; never call it from a `def` dependency.
    """
    set_user_id(user_id)
    from webbpulse.log_context import user_id_var

    return user_id_var.get()


def user_id_dependency[UserT](
    get_user: Callable[..., UserT | Awaitable[UserT]],
    *,
    attribute: str = "id",
    extract: Callable[[UserT], object] | None = None,
) -> Callable[..., Awaitable[UserT]]:
    """Wrap a user-resolving dependency so the resolved id reaches the log context.

    Returns an `async def` dependency that resolves `get_user`, binds the id read via
    `extract` or `attribute`, and passes the same object through unchanged. A `None` user
    or a missing id binds nothing rather than failing the request.
    """

    async def dependency(resolved: Any = Depends(get_user)) -> UserT:
        """Resolve the wrapped dependency, bind its user id, and return it unchanged."""
        user: UserT = resolved
        if user is not None:
            value = extract(user) if extract is not None else getattr(user, attribute, None)
            if value is not None:
                await bind_user_id(value)
        return user

    dependency.__name__ = getattr(get_user, "__name__", "user_id_dependency")
    dependency.__doc__ = inspect.getdoc(get_user)
    return dependency


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Assign every request an id, expose it everywhere the id is needed, echo it back.

    An inbound `X-Request-ID` is honoured and a UUID4 minted otherwise. The id reaches
    `request.state`, the log context variable, and the active OpenTelemetry span.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Bind the request id for the call, then echo it on the response header."""
        incoming = request.headers.get(REQUEST_ID_HEADER, "").strip()
        rid = incoming[:128] if incoming else str(uuid.uuid4())
        setattr(request.state, _REQUEST_ID_STATE, rid)
        token = set_request_id(rid)

        try:
            from opentelemetry import trace

            span = trace.get_current_span()
            if span.get_span_context().is_valid:
                span.set_attribute("webbpulse.request_id", rid)
        except ImportError:  # pragma: no cover
            pass

        try:
            response = await call_next(request)
        finally:
            request_id_var.reset(token)
        response.headers[REQUEST_ID_HEADER] = rid
        return response


def health_router(
    *, service: str, version: str, checks: Mapping[str, Any] | None = None
) -> APIRouter:
    """A router exposing `GET /health`.

    Liveness only: it always returns 200 and touches no dependency, because the Lambda Web
    Adapter polls this path on every cold start.
    """
    router = APIRouter(tags=["health"])
    static: dict[str, Any] = dict(checks or {})

    @router.get("/health", include_in_schema=False)
    async def health() -> dict[str, Any]:
        """Report the service as live, with its name, version and any static checks."""
        return {"status": "healthy", "service": service, "version": version, **static}

    return router


def error_body(
    status_code: int,
    message: str,
    request: Request,
    *,
    error_code: str | None = None,
    details: Sequence[Any] | Mapping[str, Any] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Build the standard error envelope of `success`, `status`, `message` and `request_id`.

    `error_code` and `details` are omitted when `None`. `details` is echoed verbatim, so it
    must never carry a rejected input value, a credential or an internal identifier.
    """
    body: dict[str, Any] = {
        "success": False,
        "status": status_code,
        "message": message,
        "request_id": request_id(request),
    }
    if error_code is not None:
        body["error_code"] = error_code
    if details is not None:
        body["details"] = list(details) if isinstance(details, Sequence) else dict(details)
    body.update(extra)
    return body


_error_body = error_body


def register_error_handlers(
    app: FastAPI,
    *,
    error_codes: bool = False,
    validation_details: bool = False,
    validation_error_code: str = "VALIDATION_ERROR",
    dynamodb: bool = False,
    exception_map: ExceptionMap | None = None,
) -> None:
    """Install handlers that render every error in one JSON envelope.

    Every option defaults off, so the base body is unchanged: `error_codes` adds a stable
    `error_code`, `validation_details` adds per-field 422 `details`, `dynamodb` installs the
    botocore handlers, and `exception_map` maps the service's own exception types.
    """

    def _code(status_code: int, override: str | None = None) -> str | None:
        """The `error_code` for a response, honouring an explicit override."""
        if override is not None:
            return override
        if not error_codes:
            return None
        fallback = "HTTP_ERROR" if status_code < 500 else "INTERNAL_ERROR"
        return _STATUS_ERROR_CODES.get(status_code, fallback)

    @app.exception_handler(StarletteHTTPException)
    async def _http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        """Render any `HTTPException`, including Starlette's own 404 and 405, as the envelope."""
        override_code: str | None = None
        override_details: Any = None
        raw: Any = exc.detail
        if isinstance(raw, str):
            detail = raw
        elif isinstance(raw, Mapping):
            candidate = raw.get("message")
            detail = candidate if isinstance(candidate, str) else "Request failed."
            candidate_code = raw.get("error_code")
            override_code = candidate_code if isinstance(candidate_code, str) else None
            override_details = raw.get("details")
        else:
            detail = "Request failed."

        if exc.status_code in (404, 405) and detail in _ROUTING_DETAILS:
            detail = _ROUTING_DETAILS[detail]

        if exc.status_code >= 500:
            _log.error(detail, extra={"status": exc.status_code, "path": request.url.path})
            detail = "Internal server error."
            override_details = None

        return JSONResponse(
            status_code=exc.status_code,
            content=error_body(
                exc.status_code,
                detail,
                request,
                error_code=_code(exc.status_code, override_code),
                details=override_details,
            ),
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        """Render a 422, returning only each error's location and reason, never its input."""
        errors = [
            {
                "loc": list(error.get("loc", ())),
                "msg": error.get("msg", ""),
                "type": error.get("type", ""),
            }
            for error in exc.errors()
        ]
        details = (
            [
                {
                    "field": ".".join(str(part) for part in error["loc"][1:]) or "_root",
                    "message": error["msg"],
                    "type": error["type"],
                }
                for error in errors
            ]
            if validation_details
            else None
        )
        return JSONResponse(
            status_code=422,
            content=error_body(
                422,
                "Request validation failed.",
                request,
                error_code=_code(422, validation_error_code if error_codes else None),
                details=details,
                errors=errors,
            ),
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        """Render any unhandled exception as a generic 500, with the detail left in the log."""
        _log.exception(
            "Unhandled exception serving the request.",
            extra={"path": request.url.path, "method": request.method},
        )
        return JSONResponse(
            status_code=500,
            content=error_body(500, "Internal server error.", request, error_code=_code(500)),
        )

    if dynamodb:
        install_dynamodb_handlers(app, error_codes=error_codes, exception_map=exception_map)
    elif exception_map:
        _install_exception_map(
            app, _normalise_exception_map(exception_map), error_codes=error_codes
        )


DYNAMODB_RETRY_AFTER_SECONDS: Final = 1

_DYNAMODB_THROTTLE_CODES: Final = frozenset(
    {
        "ProvisionedThroughputExceededException",
        "ThrottlingException",
        "RequestLimitExceeded",
    }
)


@dataclass(frozen=True, slots=True)
class ErrorSpec:
    """How one caller-supplied exception type renders in the envelope.

    `message` defaults to the wording for that status, `error_code` is honoured only with
    `error_codes=True`, and a status of 500 or above never echoes `message` to the caller.
    """

    status: int
    message: str | None = None
    error_code: str | None = None
    retry_after: int | None = None


type ExceptionMap = Mapping[type[BaseException], int | ErrorSpec]

_STATUS_MESSAGES: Final[Mapping[int, str]] = {
    400: "The request could not be understood.",
    401: "Authentication is required.",
    403: "You do not have access to this resource.",
    404: "The requested resource was not found.",
    405: "That method is not allowed on this resource.",
    409: "The resource was modified by another request. Try again.",
    422: "Request validation failed.",
    429: "Too many requests. Try again shortly.",
    503: "The service is busy. Try again shortly.",
}


def _normalise_exception_map(
    exception_map: ExceptionMap | None,
) -> list[tuple[type[BaseException], ErrorSpec]]:
    """Validate the caller's mapping and turn every value into an `ErrorSpec`.

    Entries come back most derived first, and a bad key or status raises here, at app build
    time, rather than as a 500 at request time.
    """
    if not exception_map:
        return []

    entries: list[tuple[type[BaseException], ErrorSpec]] = []
    raw_items: Iterable[tuple[Any, Any]] = exception_map.items()
    for exc_type, value in raw_items:
        if not isinstance(exc_type, type) or not issubclass(exc_type, BaseException):
            raise TypeError(f"exception_map keys must be exception classes, got {exc_type!r}.")
        spec = ErrorSpec(value) if isinstance(value, int) else value
        if not isinstance(spec, ErrorSpec):
            raise TypeError(
                f"exception_map values must be an int status or an ErrorSpec, "
                f"got {value!r} for {exc_type.__name__}."
            )
        if not 100 <= spec.status <= 599:
            raise ValueError(
                f"exception_map status for {exc_type.__name__} must be a valid HTTP "
                f"status, got {spec.status}."
            )
        entries.append((exc_type, spec))

    entries.sort(key=lambda item: len(item[0].__mro__), reverse=True)
    return entries


def _install_exception_map(
    app: FastAPI,
    entries: Sequence[tuple[type[BaseException], ErrorSpec]],
    *,
    error_codes: bool,
) -> None:
    """Register one handler per caller-supplied exception type.

    Each handler builds the envelope `error_body` builds for every other error.
    """

    def _register(exc_type: type[BaseException], spec: ErrorSpec) -> None:
        """Install the handler rendering one exception type as its `ErrorSpec`."""
        status = spec.status
        is_server_fault = status >= 500
        message = (
            "Internal server error."
            if is_server_fault
            else (spec.message or _STATUS_MESSAGES.get(status) or "Request failed.")
        )
        code: str | None = None
        if error_codes:
            fallback = "HTTP_ERROR" if status < 500 else "INTERNAL_ERROR"
            code = spec.error_code or _STATUS_ERROR_CODES.get(status, fallback)
        headers = {"Retry-After": str(spec.retry_after)} if spec.retry_after is not None else None

        async def _handler(request: Request, exc: BaseException) -> JSONResponse:
            """Log the mapped exception and return its envelope."""
            log_extra = {
                "path": request.url.path,
                "method": request.method,
                "request_id": request_id(request),
                "exception_type": type(exc).__name__,
            }
            if is_server_fault:
                _log.exception("Mapped exception raised a server fault.", extra=log_extra)
            else:
                _log.warning("Mapped exception handled.", extra=log_extra)
            return JSONResponse(
                status_code=status,
                content=error_body(status, message, request, error_code=code),
                headers=headers,
            )

        app.add_exception_handler(exc_type, _handler)  # type: ignore[arg-type]

    for exc_type, spec in entries:
        _register(exc_type, spec)


def install_dynamodb_handlers(
    app: FastAPI,
    *,
    error_codes: bool = False,
    exception_map: ExceptionMap | None = None,
) -> None:
    """Install exception handlers for botocore `ClientError` raised by DynamoDB.

    Maps a failed condition to 409, throttling to 503 with `Retry-After`, a missing table to
    500, and a cancelled transaction to either by its reasons. `exception_map` covers the
    service's own types. Opt in, since it needs the `dynamodb` extra.
    """
    entries = _normalise_exception_map(exception_map)

    from botocore.exceptions import ClientError

    def _code(status_code: int, override: str | None = None) -> str | None:
        """The `error_code` for a response, or `None` when codes are off."""
        if override is not None:
            return override if error_codes else None
        return _STATUS_ERROR_CODES.get(status_code) if error_codes else None

    @app.exception_handler(ClientError)
    async def _dynamodb_client_error(request: Request, exc: ClientError) -> JSONResponse:
        """Render a botocore `ClientError` as the envelope, by its AWS error code."""
        error = exc.response.get("Error", {})
        aws_code = error.get("Code", "")
        log_extra = {
            "path": request.url.path,
            "method": request.method,
            "request_id": request_id(request),
            "aws_error_code": aws_code,
        }

        if aws_code == "ConditionalCheckFailedException":
            _log.warning("DynamoDB conditional check failed.", extra=log_extra)
            return JSONResponse(
                status_code=409,
                content=error_body(
                    409,
                    "The resource was modified by another request. Try again.",
                    request,
                    error_code=_code(409),
                ),
            )

        if aws_code in _DYNAMODB_THROTTLE_CODES:
            _log.warning("DynamoDB throttled the request.", extra=log_extra)
            return JSONResponse(
                status_code=503,
                content=error_body(
                    503,
                    "The service is busy. Try again shortly.",
                    request,
                    error_code=_code(503),
                ),
                headers={"Retry-After": str(DYNAMODB_RETRY_AFTER_SECONDS)},
            )

        if aws_code == "ResourceNotFoundException":
            _log.error("DynamoDB table or index is missing.", extra=log_extra)
            return JSONResponse(
                status_code=500,
                content=error_body(500, "Internal server error.", request, error_code=_code(500)),
            )

        if aws_code == "TransactionCanceledException":
            reasons = exc.response.get("CancellationReasons") or []
            codes = [str(reason.get("Code", "")) for reason in reasons]
            if "ConditionalCheckFailed" in codes:
                _log.warning(
                    "DynamoDB transaction cancelled by a failed condition.",
                    extra={**log_extra, "cancellation_reasons": codes},
                )
                return JSONResponse(
                    status_code=409,
                    content=error_body(
                        409,
                        "The resource was modified by another request. Try again.",
                        request,
                        error_code=_code(409),
                    ),
                )
            _log.error(
                "DynamoDB transaction cancelled.",
                extra={**log_extra, "cancellation_reasons": codes},
            )
            return JSONResponse(
                status_code=500,
                content=error_body(500, "Internal server error.", request, error_code=_code(500)),
            )

        _log.exception("Unhandled DynamoDB client error.", extra=log_extra)
        return JSONResponse(
            status_code=500,
            content=error_body(500, "Internal server error.", request, error_code=_code(500)),
        )

    _install_exception_map(app, entries, error_codes=error_codes)


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
    error_codes: bool = False,
    validation_details: bool = False,
    dynamodb_handlers: bool = False,
    exception_map: ExceptionMap | None = None,
    **fastapi_kwargs: Any,
) -> FastAPI:
    """Build one domain's FastAPI application.

    Adds CORS, the request id middleware, the structured error handlers and `GET /health`.
    CORS origins come from `settings` or `cors_allow_origins`, and must be exact when
    credentials are allowed.
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

    app.add_middleware(RequestIdMiddleware)
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=allow_credentials,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Accept", "Authorization", "Content-Type", "Origin", REQUEST_ID_HEADER],
            expose_headers=[
                REQUEST_ID_HEADER,
                "RateLimit",
                "RateLimit-Policy",
                "Retry-After",
                "X-RateLimit-Limit",
                "X-RateLimit-Remaining",
                "X-RateLimit-Reset",
            ],
            max_age=86400,
        )

    register_error_handlers(
        app,
        error_codes=error_codes,
        validation_details=validation_details,
        dynamodb=dynamodb_handlers,
        exception_map=exception_map,
    )

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

    Each mount path must be the prefix API Gateway routes to that domain's function. A
    mounted app keeps its own middleware and handlers; the parent adds its own `/health`.
    """
    parent = FastAPI(title=title, version=version, **fastapi_kwargs)
    parent.include_router(health_router(service=service_name, version=version))
    register_error_handlers(parent)

    for path, sub_app in apps.items():
        if not path.startswith("/"):
            raise ValueError(f"Mount path must start with '/', got {path!r}.")
        parent.mount(path.rstrip("/") or "/", sub_app)
    return parent
