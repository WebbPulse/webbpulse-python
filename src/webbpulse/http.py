"""FastAPI app factory, request id, error handlers, the client IP, and the wire helpers.

`create_app` builds one domain's application and `mount_all` composes several into the app
local development and tests run. Bind the user id with `user_id_dependency`, never from a
sync dependency, whose context Starlette's threadpool discards.

`verify_hmac_signature` is the receiving half of a signed webhook and `CursorPage` with
`encode_cursor` and `decode_cursor` is the paginated response shape, which carries a
data-layer cursor across the wire without this module knowing what is in it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import inspect
import json
import logging
import time
import uuid
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final

from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from webbpulse.log_context import current_context, request_id_var, set_request_id, set_user_id
from webbpulse.messages import DEFAULT_MESSAGE, STATUS_MESSAGES

if TYPE_CHECKING:  # pragma: no cover
    from webbpulse.config import BaseServiceSettings

__all__ = [
    "DEFAULT_CORS_ALLOW_HEADERS",
    "DEFAULT_ERROR_STATUSES",
    "DYNAMODB_ERROR_MESSAGES",
    "DYNAMODB_RETRY_AFTER_SECONDS",
    "LAMBDA_CONTEXT_HEADER",
    "REQUEST_CONTEXT_HEADER",
    "REQUEST_ID_HEADER",
    "RETRY_ATTEMPT_HEADER",
    "ROUTE_KEY_HEADER",
    "SIGNATURE_ALGORITHMS",
    "CursorPage",
    "DynamoDBErrorHandlerOptions",
    "DynamoDBErrors",
    "ErrorContext",
    "ErrorEnvelope",
    "ErrorRenderer",
    "ErrorResponse",
    "ErrorSpec",
    "ExceptionMap",
    "InvalidCursor",
    "RequestIdMiddleware",
    "RequestLoggingMiddleware",
    "SignatureMismatch",
    "ValidationErrorDetail",
    "bind_user_id",
    "client_ip",
    "create_app",
    "decode_cursor",
    "detailed_error_body",
    "encode_cursor",
    "error_body",
    "error_envelope_responses",
    "health_router",
    "install_dynamodb_error_handlers",
    "install_dynamodb_handlers",
    "mount_all",
    "register_error_handlers",
    "request_context",
    "request_id",
    "resolve_error_envelope",
    "route_key",
    "user_id_dependency",
    "verify_hmac_signature",
]

_log = logging.getLogger(__name__)

REQUEST_CONTEXT_HEADER: Final = "x-amzn-request-context"

LAMBDA_CONTEXT_HEADER: Final = "x-amzn-lambda-context"

REQUEST_ID_HEADER: Final = "X-Request-ID"

RETRY_ATTEMPT_HEADER: Final = "X-Retry-Attempt"

ROUTE_KEY_HEADER: Final = "X-WebbPulse-Route-Key"

DEFAULT_CORS_ALLOW_HEADERS: Final = (
    "Accept",
    "Accept-Language",
    "Authorization",
    "Content-Language",
    "Content-Type",
    "Origin",
    REQUEST_ID_HEADER,
    RETRY_ATTEMPT_HEADER,
)

_REQUEST_ID_STATE: Final = "webbpulse_request_id"

_USER_ID_STATE: Final = "webbpulse_user_id"

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


def request_context(request: Request) -> Mapping[str, Any] | None:
    """The API Gateway request context the Lambda Web Adapter forwards, or None.

    None on a local run, where nothing sets the header, and on a header that is not JSON,
    which is logged once and then ignored rather than failing the request.
    """
    raw = request.headers.get(REQUEST_CONTEXT_HEADER)
    if not raw:
        return None
    try:
        context = json.loads(raw)
    except (TypeError, ValueError):
        _log.warning("Could not parse %s as JSON; ignoring it.", REQUEST_CONTEXT_HEADER)
        return None
    return context if isinstance(context, Mapping) else None


def route_key(request: Request) -> str:
    """The `routeKey` API Gateway matched this request to, or "" when it is not known.

    The access log is the other place that says which route key served a request, and it
    takes half a minute to deliver. This is the same fact on the response itself, so a
    route cut is provable the moment the probe answers.
    """
    context = request_context(request)
    if context is None:
        return ""
    value = context.get("routeKey")
    return value if isinstance(value, str) and value else ""


def client_ip(request: Request, *, local_fallback: bool = True) -> str:
    """The caller's IP address, read from the API Gateway request context header.

    `X-Forwarded-For` is never read, because a client can forge it. Falls back to the peer
    address when `local_fallback` is set, and returns `"unknown"` otherwise.
    """
    context = request_context(request)
    if context is not None:
        for section in ("http", "identity"):
            values = context.get(section)
            if isinstance(values, Mapping):
                source_ip = values.get("sourceIp")
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


async def bind_user_id(user_id: object, request: Request | None = None) -> str:
    """Bind the user id for the rest of the request and return the cleaned string.

    Being a coroutine is the point: it runs in the request's own context, unlike the same
    binding made from a sync dependency. Await it; never call it from a `def` dependency.

    Passing `request` also records the id on the request scope, which is what lets the
    request log report a subject bound inside a route handler.
    """
    set_user_id(user_id)
    from webbpulse.log_context import user_id_var

    cleaned = user_id_var.get()
    if request is not None:
        setattr(request.state, _USER_ID_STATE, cleaned)
    return cleaned


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

    async def dependency(request: Request, resolved: Any = Depends(get_user)) -> UserT:
        """Resolve the wrapped dependency, bind its user id, and return it unchanged."""
        user: UserT = resolved
        if user is not None:
            value = extract(user) if extract is not None else getattr(user, attribute, None)
            if value is not None:
                await bind_user_id(value, request)
        return user

    dependency.__name__ = getattr(get_user, "__name__", "user_id_dependency")
    dependency.__doc__ = inspect.getdoc(get_user)
    return dependency


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Assign every request an id, expose it everywhere the id is needed, echo it back.

    An inbound `X-Request-ID` is honoured and a UUID4 minted otherwise. The id reaches
    `request.state`, the log context variable, and the active OpenTelemetry span.

    It also echoes the gateway's own `routeKey` as `X-WebbPulse-Route-Key`, in every
    environment, so which route served a request is provable from the response rather than
    only from an access log that lags. The header is absent on a local run, where nothing
    forwards a request context.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Bind the request id for the call, then echo it and the route key on the response."""
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
        matched = route_key(request)
        if matched:
            response.headers[ROUTE_KEY_HEADER] = matched
        return response


class RequestLoggingMiddleware:
    """Emit one structured log line per HTTP request, after the response is decided.

    Pure ASGI rather than `BaseHTTPMiddleware` on purpose: `call_next` runs the application
    in a child task, whose context a `BaseHTTPMiddleware` cannot read back, so a user id
    bound by `user_id_dependency` would never reach the line. Only the method, the route
    template or path, the status, the duration and the bound context are logged; a body, a
    header, a token and a query string are never touched.
    """

    def __init__(self, app: Any, *, logger: logging.Logger | None = None) -> None:
        """Wrap `app`, logging to `logger` or to this module's logger."""
        self.app = app
        self._logger = logger if logger is not None else _log

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        """Time the request and log its outcome, whether it returns or raises."""
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        started = time.perf_counter()
        status: dict[str, int | None] = {"code": None}

        async def send_wrapper(message: Any) -> None:
            """Capture the response status as the response starts."""
            if message.get("type") == "http.response.start":
                status["code"] = message.get("status")
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception:
            self._emit(scope, status["code"] or 500, started)
            raise
        else:
            self._emit(scope, status["code"], started)

    def _emit(self, scope: Any, status_code: int | None, started: float) -> None:
        """Write the line, merging the bound request and user ids."""
        extra: dict[str, Any] = {
            "http_method": scope.get("method"),
            "http_path": _route_path(scope),
            "http_status": status_code,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        }
        extra.update(current_context())
        extra.setdefault("request_id", request_id_var.get())
        subject = _scope_user_id(scope)
        if subject is not None:
            extra["user_id"] = subject
        self._logger.info("request", extra=extra)


def _route_path(scope: Mapping[str, Any]) -> str | None:
    """The matched route template, falling back to the raw path.

    The template is preferred so an id in the path does not give every request its own
    distinct value, which would make the lines impossible to aggregate.
    """
    route = scope.get("route")
    template = getattr(route, "path", None)
    if isinstance(template, str) and template:
        root = scope.get("root_path") or ""
        return f"{root}{template}" if isinstance(root, str) else template
    path = scope.get("path")
    return path if isinstance(path, str) else None


def _scope_user_id(scope: Mapping[str, Any]) -> str | None:
    """The subject recorded on the request scope by `bind_user_id`, when there is one."""
    state = scope.get("state")
    if isinstance(state, Mapping):
        value = state.get(_USER_ID_STATE)
        if isinstance(value, str) and value and value != "-":
            return value
    return None


def health_router(*, service: str, version: str, checks: Mapping[str, Any] | None = None) -> APIRouter:
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


def detailed_error_body(
    status_code: int,
    message: str,
    request: Request,
    *,
    error_code: str | None = None,
    details: Sequence[Any] | Mapping[str, Any] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Build the `"detailed"` envelope: the four base fields plus an always-present `error_code`.

    The shape CarModPicker emits today. A 422 carries `details` as a flat
    `[{field, message, type}]` list and no `errors` key, and no shape ever carries Starlette's
    `detail`. `error_code` falls back to the stable code for the status when none is given.
    """
    body: dict[str, Any] = {
        "success": False,
        "status": status_code,
        "message": message,
        "request_id": request_id(request),
        "error_code": error_code or _status_error_code(status_code),
    }
    if details is not None:
        body["details"] = list(details) if isinstance(details, Sequence) else dict(details)
    body.update(extra)
    return body


class ValidationErrorDetail(BaseModel):
    """One offending field in a 422, carrying its location and reason but never its input."""

    field: str = Field(description="Dotted path to the offending field, or `_root` for the body itself.")
    message: str = Field(description="Why the value was rejected.")
    type: str = Field(description="The pydantic error type, such as `missing` or `string_type`.")


class ErrorResponse(BaseModel):
    """The `"detailed"` error envelope every handler renders, and what OpenAPI advertises.

    `details` is present only on a 422, where it holds one entry per offending field.
    """

    success: bool = Field(default=False, description="Always `false` on an error response.")
    status: int = Field(description="The HTTP status code, repeated in the body.")
    message: str = Field(description="A human readable summary safe to surface to a caller.")
    request_id: str = Field(description="The request id, echoed in the `X-Request-ID` header.")
    error_code: str = Field(description="A stable machine readable code, such as `NOT_FOUND`.")
    details: list[ValidationErrorDetail] | None = Field(
        default=None,
        description="Per-field validation failures. Present only on a 422.",
    )


def _status_error_code(status_code: int) -> str:
    """The stable `error_code` string for an HTTP status."""
    fallback = "HTTP_ERROR" if status_code < 500 else "INTERNAL_ERROR"
    return _STATUS_ERROR_CODES.get(status_code, fallback)


@dataclass(frozen=True, slots=True)
class ErrorContext:
    """Everything a renderer needs to turn one error into a response body.

    `validation_errors` is populated only for a 422 and holds one `{loc, msg, type}` entry per
    offending field, never the rejected input. `extra` carries keys a built-in shape adds, such
    as the legacy `errors` list.
    """

    status: int
    message: str
    request: Request
    error_code: str | None = None
    details: Sequence[Any] | Mapping[str, Any] | None = None
    validation_errors: Sequence[Mapping[str, Any]] | None = None
    exception: BaseException | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)


type ErrorRenderer = Callable[[ErrorContext], Mapping[str, Any]]

type ErrorEnvelope = str | ErrorRenderer

_ENVELOPE_SHAPES: Final = ("default", "detailed")


def _render_default(context: ErrorContext) -> Mapping[str, Any]:
    """Render the historical envelope, where `error_code` and `details` are opt in."""
    return error_body(
        context.status,
        context.message,
        context.request,
        error_code=context.error_code,
        details=context.details,
        **dict(context.extra),
    )


def _render_detailed(context: ErrorContext) -> Mapping[str, Any]:
    """Render the `"detailed"` envelope, dropping the legacy `errors` key from a 422."""
    extra = {key: value for key, value in context.extra.items() if key != "errors"}
    return detailed_error_body(
        context.status,
        context.message,
        context.request,
        error_code=context.error_code,
        details=context.details,
        **extra,
    )


def resolve_error_envelope(envelope: ErrorEnvelope | None) -> ErrorRenderer:
    """Turn an `error_envelope` argument into the renderer the handlers call.

    Accepts `None` or `"default"` for the historical shape, `"detailed"` for the shape that
    always carries `error_code`, or any callable taking an `ErrorContext`. An unknown name
    raises `ValueError` here, at app build time, rather than as a 500 under load.
    """
    if envelope is None or envelope == "default":
        return _render_default
    if envelope == "detailed":
        return _render_detailed
    if callable(envelope):
        return envelope
    raise ValueError(f"error_envelope must be one of {_ENVELOPE_SHAPES} or a callable, got {envelope!r}.")


_ENVELOPE_STATUS_DESCRIPTIONS: Final = {
    400: "Bad request.",
    401: "Authentication required.",
    403: "Not permitted.",
    404: "Resource not found.",
    409: "Conflict with the current state.",
    422: "Request validation failed.",
    429: "Rate limit exceeded.",
    500: "Internal server error.",
}

DEFAULT_ERROR_STATUSES: Final = (422,)


def error_envelope_responses(
    statuses: Iterable[int] = DEFAULT_ERROR_STATUSES,
) -> dict[int | str, dict[str, Any]]:
    """Build the OpenAPI `responses` mapping that advertises `ErrorResponse` for each status.

    Passed as `responses` to `FastAPI(...)` so every operation documents the envelope the
    handlers actually render, in place of FastAPI's default `HTTPValidationError`.
    """
    return {
        status_code: {
            "model": ErrorResponse,
            "description": _ENVELOPE_STATUS_DESCRIPTIONS.get(status_code, "Request failed."),
        }
        for status_code in statuses
    }


def _renders_codes(renderer: ErrorRenderer, *, error_codes: bool) -> bool:
    """Whether the resolved renderer should be handed an `error_code` to render.

    The default shape suppresses one unless `error_codes=True`; every other shape decides for
    itself, so a custom renderer always receives the code the handler derived.
    """
    return error_codes or renderer is not _render_default


def register_error_handlers(
    app: FastAPI,
    *,
    error_codes: bool = False,
    validation_details: bool = False,
    validation_error_code: str = "VALIDATION_ERROR",
    error_envelope: ErrorEnvelope | None = None,
    dynamodb: bool = False,
    dynamodb_errors: DynamoDBErrors = False,
    exception_map: ExceptionMap | None = None,
) -> None:
    """Install handlers that render every error in one JSON envelope.

    Every option defaults off, so the base body is unchanged: `error_codes` adds a stable
    `error_code`, `validation_details` adds per-field 422 `details`, `dynamodb` installs the
    botocore handlers, `dynamodb_errors` installs the handlers for this package's own
    `webbpulse.dynamodb` exception types, and `exception_map` maps the service's own types.

    `dynamodb_errors` also accepts a `DynamoDBErrorHandlerOptions`, which installs the same
    handlers with the consumer's own wording instead of the package defaults.

    `error_envelope` chooses the body shape for every handler installed here, including the
    unmatched-route 404. `"detailed"` implies `error_codes` and `validation_details`, so a
    consumer gets the `{"success", "status", "message", "request_id", "error_code"}` shape with
    a flat 422 `details` list and no `errors` key.
    """
    renderer = resolve_error_envelope(error_envelope)
    detailed = renderer is _render_detailed
    if detailed:
        error_codes = True
        validation_details = True
    render_codes = _renders_codes(renderer, error_codes=error_codes)

    def _code(status_code: int, override: str | None = None) -> str | None:
        """The `error_code` for a response, honouring an explicit override."""
        if override is not None:
            return override
        if not render_codes:
            return None
        return _status_error_code(status_code)

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
            content=dict(
                renderer(
                    ErrorContext(
                        status=exc.status_code,
                        message=detail,
                        request=request,
                        error_code=_code(exc.status_code, override_code),
                        details=override_details,
                        exception=exc,
                    )
                )
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
            content=dict(
                renderer(
                    ErrorContext(
                        status=422,
                        message="Request validation failed.",
                        request=request,
                        error_code=_code(422, validation_error_code if render_codes else None),
                        details=details,
                        validation_errors=errors,
                        exception=exc,
                        extra={"errors": errors},
                    )
                )
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
            content=dict(
                renderer(
                    ErrorContext(
                        status=500,
                        message="Internal server error.",
                        request=request,
                        error_code=_code(500),
                        exception=exc,
                    )
                )
            ),
        )

    if dynamodb:
        install_dynamodb_handlers(
            app,
            error_codes=error_codes,
            error_envelope=renderer,
            exception_map=exception_map,
        )
    elif exception_map:
        _install_exception_map(
            app,
            _normalise_exception_map(exception_map),
            error_codes=error_codes,
            renderer=renderer,
        )

    if dynamodb_errors:
        options = (
            dynamodb_errors
            if isinstance(dynamodb_errors, DynamoDBErrorHandlerOptions)
            else DynamoDBErrorHandlerOptions()
        )
        install_dynamodb_error_handlers(
            app,
            error_codes=error_codes,
            error_envelope=renderer,
            not_found_message=options.not_found_message,
            conflict_message=options.conflict_message,
            internal_error_message=options.internal_error_message,
            unprocessed_message=options.unprocessed_message,
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

_STATUS_MESSAGES: Final[Mapping[int, str]] = STATUS_MESSAGES
"""The per-status default wording, owned by `webbpulse.messages` and aliased here."""


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
                f"exception_map values must be an int status or an ErrorSpec, got {value!r} for {exc_type.__name__}."
            )
        if not 100 <= spec.status <= 599:
            raise ValueError(
                f"exception_map status for {exc_type.__name__} must be a valid HTTP status, got {spec.status}."
            )
        entries.append((exc_type, spec))

    entries.sort(key=lambda item: len(item[0].__mro__), reverse=True)
    return entries


def _install_exception_map(
    app: FastAPI,
    entries: Sequence[tuple[type[BaseException], ErrorSpec]],
    *,
    error_codes: bool,
    renderer: ErrorRenderer | None = None,
) -> None:
    """Register one handler per caller-supplied exception type.

    Each handler renders through the same envelope renderer every other error uses.
    """
    render = renderer if renderer is not None else _render_default
    render_codes = _renders_codes(render, error_codes=error_codes)

    def _register(exc_type: type[BaseException], spec: ErrorSpec) -> None:
        """Install the handler rendering one exception type as its `ErrorSpec`."""
        status = spec.status
        is_server_fault = status >= 500
        message = (
            "Internal server error."
            if is_server_fault
            else (spec.message or _STATUS_MESSAGES.get(status) or DEFAULT_MESSAGE)
        )
        code: str | None = None
        if render_codes:
            code = spec.error_code or _status_error_code(status)
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
                content=dict(
                    render(
                        ErrorContext(
                            status=status,
                            message=message,
                            request=request,
                            error_code=code,
                            exception=exc,
                        )
                    )
                ),
                headers=headers,
            )

        app.add_exception_handler(exc_type, _handler)  # type: ignore[arg-type]

    for exc_type, spec in entries:
        _register(exc_type, spec)


def install_dynamodb_handlers(
    app: FastAPI,
    *,
    error_codes: bool = False,
    error_envelope: ErrorEnvelope | None = None,
    exception_map: ExceptionMap | None = None,
) -> None:
    """Install exception handlers for botocore `ClientError` raised by DynamoDB.

    Maps a failed condition to 409, throttling to 503 with `Retry-After`, a missing table to
    500, and a cancelled transaction to either by its reasons. `exception_map` covers the
    service's own types, and `error_envelope` chooses the body shape. Opt in, since it needs
    the `dynamodb` extra.
    """
    entries = _normalise_exception_map(exception_map)
    renderer = resolve_error_envelope(error_envelope)
    if renderer is _render_detailed:
        error_codes = True
    render_codes = _renders_codes(renderer, error_codes=error_codes)

    from botocore.exceptions import ClientError

    def _code(status_code: int, override: str | None = None) -> str | None:
        """The `error_code` for a response, or `None` when codes are off."""
        if override is not None:
            return override if render_codes else None
        return _status_error_code(status_code) if render_codes else None

    def _body(status_code: int, message: str, request: Request, exc: BaseException) -> Any:
        """Render one DynamoDB failure through the configured envelope."""
        return dict(
            renderer(
                ErrorContext(
                    status=status_code,
                    message=message,
                    request=request,
                    error_code=_code(status_code),
                    exception=exc,
                )
            )
        )

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
                content=_body(409, "The resource was modified by another request. Try again.", request, exc),
            )

        if aws_code in _DYNAMODB_THROTTLE_CODES:
            _log.warning("DynamoDB throttled the request.", extra=log_extra)
            return JSONResponse(
                status_code=503,
                content=_body(503, "The service is busy. Try again shortly.", request, exc),
                headers={"Retry-After": str(DYNAMODB_RETRY_AFTER_SECONDS)},
            )

        if aws_code == "ResourceNotFoundException":
            _log.error("DynamoDB table or index is missing.", extra=log_extra)
            return JSONResponse(
                status_code=500,
                content=_body(500, "Internal server error.", request, exc),
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
                    content=_body(
                        409,
                        "The resource was modified by another request. Try again.",
                        request,
                        exc,
                    ),
                )
            _log.error(
                "DynamoDB transaction cancelled.",
                extra={**log_extra, "cancellation_reasons": codes},
            )
            return JSONResponse(
                status_code=500,
                content=_body(500, "Internal server error.", request, exc),
            )

        _log.exception("Unhandled DynamoDB client error.", extra=log_extra)
        return JSONResponse(
            status_code=500,
            content=_body(500, "Internal server error.", request, exc),
        )

    _install_exception_map(app, entries, error_codes=error_codes, renderer=renderer)


DYNAMODB_ERROR_MESSAGES: Final[Mapping[str, str]] = {
    "not_found": "The requested resource was not found.",
    "conflict": "The resource was modified by another request. Try again.",
    "internal": "Internal server error.",
    "unprocessed": "The service is busy. Try again shortly.",
}


@dataclass(frozen=True, slots=True)
class DynamoDBErrorHandlerOptions:
    """The wording `install_dynamodb_error_handlers` renders, for forwarding through a flag.

    Pass one in place of `True` to `register_error_handlers(dynamodb_errors=...)` or
    `create_app(dynamodb_error_handlers=...)`. Every field left `None` keeps the package
    default from `DYNAMODB_ERROR_MESSAGES`.
    """

    not_found_message: str | None = None
    conflict_message: str | None = None
    internal_error_message: str | None = None
    unprocessed_message: str | None = None


type DynamoDBErrors = bool | DynamoDBErrorHandlerOptions


def install_dynamodb_error_handlers(
    app: FastAPI,
    *,
    error_codes: bool = False,
    error_envelope: ErrorEnvelope | None = None,
    not_found_message: str | None = None,
    conflict_message: str | None = None,
    internal_error_message: str | None = None,
    unprocessed_message: str | None = None,
) -> None:
    """Install handlers for `webbpulse.dynamodb`'s own exception types.

    `ItemNotFound` renders as a 404, `ConditionFailed` as a 409, `UnprocessedItems` as a 503
    with `Retry-After`, and `TransactionCanceled` as a 409 when any cancellation reason is a
    failed condition and a 500 otherwise. Opt in, and needs no extra: the types live in
    `webbpulse.dynamodb` and importing them pulls in no botocore. Pair it with
    `install_dynamodb_handlers` when raw `ClientError` can also escape.

    The four message arguments pin a consumer's own wording; each one left `None` keeps the
    package default.
    """
    from webbpulse.dynamodb import ConditionFailed, ItemNotFound, TransactionCanceled, UnprocessedItems

    renderer = resolve_error_envelope(error_envelope)
    if renderer is _render_detailed:
        error_codes = True
    render_codes = _renders_codes(renderer, error_codes=error_codes)
    not_found = not_found_message or DYNAMODB_ERROR_MESSAGES["not_found"]
    conflict = conflict_message or DYNAMODB_ERROR_MESSAGES["conflict"]
    internal = internal_error_message or DYNAMODB_ERROR_MESSAGES["internal"]
    unprocessed = unprocessed_message or DYNAMODB_ERROR_MESSAGES["unprocessed"]

    def _body(status_code: int, message: str, request: Request, exc: BaseException) -> Any:
        """Render one repository failure through the configured envelope."""
        return dict(
            renderer(
                ErrorContext(
                    status=status_code,
                    message=message,
                    request=request,
                    error_code=_status_error_code(status_code) if render_codes else None,
                    exception=exc,
                )
            )
        )

    def _log_extra(request: Request, exc: BaseException) -> dict[str, Any]:
        """The log fields every branch records, none of which reach the response body."""
        return {
            "path": request.url.path,
            "method": request.method,
            "request_id": request_id(request),
            "exception_type": type(exc).__name__,
        }

    @app.exception_handler(ItemNotFound)
    async def _item_not_found(request: Request, exc: ItemNotFound) -> JSONResponse:
        """Render a missing item as a 404, leaving the table and key in the log."""
        _log.warning("DynamoDB item not found.", extra=_log_extra(request, exc))
        return JSONResponse(status_code=404, content=_body(404, not_found, request, exc))

    @app.exception_handler(ConditionFailed)
    async def _condition_failed(request: Request, exc: ConditionFailed) -> JSONResponse:
        """Render a rejected conditional write as a 409, leaving the condition in the log."""
        _log.warning("DynamoDB condition failed.", extra=_log_extra(request, exc))
        return JSONResponse(status_code=409, content=_body(409, conflict, request, exc))

    @app.exception_handler(UnprocessedItems)
    async def _unprocessed_items(request: Request, exc: UnprocessedItems) -> JSONResponse:
        """Render an exhausted batch as a 503 with `Retry-After`, the way throttling renders.

        A batch that still had keys or items outstanding after the retry cap is DynamoDB
        shedding load, which is transient and retryable. A 500 would tell the caller not to
        bother retrying and would page someone for capacity working as designed.
        """
        extra = {**_log_extra(request, exc), "unprocessed_count": exc.count, "attempts": exc.attempts}
        _log.warning("DynamoDB left a batch unprocessed.", extra=extra)
        return JSONResponse(
            status_code=503,
            content=_body(503, unprocessed, request, exc),
            headers={"Retry-After": str(DYNAMODB_RETRY_AFTER_SECONDS)},
        )

    @app.exception_handler(TransactionCanceled)
    async def _transaction_canceled(request: Request, exc: TransactionCanceled) -> JSONResponse:
        """Render a cancelled transaction as a 409 only when a condition failed."""
        codes = [str(reason.get("Code", "")) for reason in exc.reasons]
        extra = {**_log_extra(request, exc), "cancellation_reasons": codes}
        if exc.conditional_check_failed:
            _log.warning("DynamoDB transaction cancelled by a failed condition.", extra=extra)
            return JSONResponse(status_code=409, content=_body(409, conflict, request, exc))
        _log.error("DynamoDB transaction cancelled.", extra=extra, exc_info=True)
        return JSONResponse(status_code=500, content=_body(500, internal, request, exc))


def create_app(
    domain_routers: Iterable[APIRouter] = (),
    *,
    title: str = "WebbPulse service",
    version: str = "0.0.0",
    service_name: str = "webbpulse",
    settings: BaseServiceSettings | None = None,
    cors_allow_origins: Sequence[str] | None = None,
    cors_allow_credentials: bool | None = None,
    cors_allow_headers: Sequence[str] | None = None,
    router_prefix: str = "",
    include_health: bool = True,
    instrument: bool = True,
    request_log: bool = True,
    error_codes: bool = False,
    validation_details: bool = False,
    error_envelope: ErrorEnvelope | None = None,
    dynamodb_handlers: bool = False,
    dynamodb_error_handlers: DynamoDBErrors = False,
    exception_map: ExceptionMap | None = None,
    **fastapi_kwargs: Any,
) -> FastAPI:
    """Build one domain's FastAPI application.

    Adds CORS, the request id middleware, the request log, the structured error handlers
    and `GET /health`. Set `request_log=False` where the API Gateway access log is the only
    per-request record a service wants.
    CORS origins come from `settings` or `cors_allow_origins`, and must be exact when
    credentials are allowed. `cors_allow_headers` replaces `DEFAULT_CORS_ALLOW_HEADERS`,
    which covers the request id and retry attempt headers the API clients send.

    `error_envelope` chooses the error body shape: the default, `"detailed"`, or a callable
    taking an `ErrorContext`. `dynamodb_error_handlers` maps this package's own
    `webbpulse.dynamodb` exception types, and `dynamodb_handlers` the raw botocore ones. Pass a
    `DynamoDBErrorHandlerOptions` in place of `True` to pin the wording those handlers render.
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
        raise ValueError("CORS cannot allow credentials with a wildcard origin. List the exact origins.")

    allow_headers = list(cors_allow_headers) if cors_allow_headers is not None else list(DEFAULT_CORS_ALLOW_HEADERS)

    if resolve_error_envelope(error_envelope) is _render_detailed:
        fastapi_kwargs.setdefault("responses", error_envelope_responses())

    app = FastAPI(title=title, version=version, **fastapi_kwargs)

    if request_log:
        app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(RequestIdMiddleware)
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=allow_credentials,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=allow_headers,
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
        error_envelope=error_envelope,
        dynamodb=dynamodb_handlers,
        dynamodb_errors=dynamodb_error_handlers,
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


SIGNATURE_ALGORITHMS: Final[Mapping[str, str]] = {
    "sha1": "sha1",
    "sha256": "sha256",
    "sha512": "sha512",
}
"""The hash names `verify_hmac_signature` accepts, so a header cannot name an arbitrary one."""


class SignatureMismatch(ValueError):
    """A signed body did not verify under the shared secret.

    A `ValueError`, so a service that maps it renders a 401 and never says which of the
    header's shape, its algorithm or its digest was wrong. Telling a caller that much is a
    verification oracle.
    """


class InvalidCursor(ValueError):
    """An opaque cursor was missing, malformed, or not signed under the caller's key.

    One error for all three, for the same reason: a caller who can tell a tampered cursor
    from a stale one learns something about the signing key.
    """


def verify_hmac_signature(
    body: bytes,
    header_value: str | None,
    secret: str | bytes,
    *,
    algorithm: str = "sha256",
    prefix: str = "sha256=",
) -> bool:
    """Verify a signature header over `body`, in constant time, or raise `SignatureMismatch`.

    This is GitHub's `X-Hub-Signature-256` shape, `sha256=<hex>`, which the defaults match,
    and it is also the shape `webbpulse.events.webhooks` sends. Pass `prefix=""` for a scheme
    that sends a bare hex digest. The comparison runs through `hmac.compare_digest` on the
    digest bytes, so neither the length of the presented value nor how many leading
    characters matched leaks through the time it takes.

    Returns `True` on a match and never returns `False`: a caller that forgets to check a
    boolean is the failure mode this guards against, so a mismatch raises. For a webhook
    signed over a timestamp and the body together, verify
    `webbpulse.events.webhooks.signed_message(timestamp, body)` here rather than `body`, and
    check the timestamp with `within_replay_window` before doing any work.
    """
    digestmod = SIGNATURE_ALGORITHMS.get(algorithm.lower())
    if digestmod is None:
        raise SignatureMismatch("Unsupported signature algorithm.")
    if not header_value:
        raise SignatureMismatch("The signature header is missing.")

    presented = header_value.strip()
    if prefix:
        if not presented.startswith(prefix):
            raise SignatureMismatch("The signature header is not in the expected form.")
        presented = presented[len(prefix) :]

    key = secret.encode() if isinstance(secret, str) else secret
    expected = hmac.new(key, body, getattr(hashlib, digestmod)).digest()
    try:
        presented_bytes = bytes.fromhex(presented)
    except ValueError as exc:
        raise SignatureMismatch("The signature is not hex.") from exc

    if not hmac.compare_digest(expected, presented_bytes):
        raise SignatureMismatch("The signature does not match.")
    return True


def encode_cursor(state: Mapping[str, Any], key: str | bytes) -> str:
    """One opaque, tamper-evident cursor carrying `state` across the wire.

    The state is serialised compactly with sorted keys, so the same state always encodes to
    the same string, then signed with HMAC-SHA256 under `key` and packed as urlsafe base64
    with the padding stripped. The result is opaque and safe in a query string, and a client
    that edits it gets `InvalidCursor` from `decode_cursor` rather than a page of somebody
    else's rows.

    It is signed, not encrypted: a client can decode what is in it, so a cursor carries keys
    and positions, never anything the caller may not already see.
    """
    payload = json.dumps(dict(state), separators=(",", ":"), sort_keys=True).encode()
    signature = hmac.new(_cursor_key(key), payload, hashlib.sha256).digest()[:16]
    return _b64encode(payload + b"." + signature)


def decode_cursor(cursor: str, key: str | bytes) -> dict[str, Any]:
    """Read a cursor `encode_cursor` produced, or raise `InvalidCursor`.

    Every failure, a cursor that is not base64, not JSON, not an object, or not signed under
    `key`, raises the same error with the same message, so nothing about the key is learnable
    by feeding cursors in.
    """
    try:
        raw = _b64decode(cursor)
    except (ValueError, binascii.Error) as exc:
        raise InvalidCursor("The cursor is not valid.") from exc

    payload, separator, signature = raw.rpartition(b".")
    if not separator:
        raise InvalidCursor("The cursor is not valid.")

    expected = hmac.new(_cursor_key(key), payload, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(expected, signature):
        raise InvalidCursor("The cursor is not valid.")

    try:
        state = json.loads(payload)
    except ValueError as exc:
        raise InvalidCursor("The cursor is not valid.") from exc
    if not isinstance(state, dict):
        raise InvalidCursor("The cursor is not valid.")
    return state


def _cursor_key(key: str | bytes) -> bytes:
    """The signing key as bytes, refusing an empty one rather than signing under nothing."""
    material = key.encode() if isinstance(key, str) else key
    if not material:
        raise ValueError("A cursor signing key is required.")
    return material


def _b64encode(raw: bytes) -> str:
    """Urlsafe base64 without padding, which is what keeps a cursor clean in a query string."""
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64decode(value: str) -> bytes:
    """Read unpadded urlsafe base64, restoring the padding the encoder stripped."""
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode())


class CursorPage[ItemT](BaseModel):
    """One page of results and the opaque cursor for the next, as a response body.

    Generic in the item type, so a route returns `CursorPage[PostOut]` and FastAPI documents
    the item schema rather than a bare object. `next_cursor` is `None` exactly when the
    result set is exhausted, and `has_more` is derived from it, so the two can never disagree.

    `from_page` bridges `webbpulse.dynamodb.Page` without this module importing that one:
    it takes the items and the `last_evaluated_key` as arguments, so `http` stays usable in a
    service with no `dynamodb` extra installed and the data layer keeps knowing nothing about
    the wire.
    """

    items: list[ItemT]
    next_cursor: str | None = None

    @property
    def has_more(self) -> bool:
        """Whether another page exists, which is exactly whether a cursor was issued."""
        return self.next_cursor is not None

    @classmethod
    def from_page(
        cls,
        items: Sequence[ItemT],
        last_evaluated_key: Mapping[str, Any] | None,
        key: str | bytes,
    ) -> CursorPage[ItemT]:
        """Build a page from a data-layer result and its raw cursor.

        `last_evaluated_key` is `Page.last_evaluated_key` straight from the repository. It is
        signed into an opaque cursor here, so the key shape never reaches a client and a
        client cannot hand one back that it made up.
        """
        return cls(
            items=list(items),
            next_cursor=encode_cursor(dict(last_evaluated_key), key) if last_evaluated_key else None,
        )
