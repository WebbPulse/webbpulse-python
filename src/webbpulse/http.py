"""FastAPI app factory, request id, error handlers, and the client IP.

`create_app` builds one domain's FastAPI application. `mount_all` composes several of them
into the single app that local development, the test suite and a plain container run, which
is the second composition root: one entrypoint per domain in production, one mounted app
everywhere else, from the same routers.

## The sync dependency trap, and `user_id_dependency`

`webbpulse.log_context.set_user_id` binds a ContextVar, and a ContextVar bound inside a
**sync** (`def`) FastAPI dependency is invisible to the handler and to every log line after
it. This is not a bug in either package. Starlette runs a sync dependency in a threadpool
through `anyio.to_thread.run_sync`, which copies the context into the worker thread; the
copy is what the dependency mutates, and the copy is discarded when the call returns. The
request's own context never sees the value.

Nothing fails. The dependency runs, the principal resolves, the endpoint returns 200, and
every log line for the rest of the request carries `user_id` of `"-"`. WebbPulse-Portfolio
shipped exactly that to production, and the only symptom was a field quietly reading `"-"`
in CloudWatch.

`bind_user_id` and `user_id_dependency` exist so the shape that works is the one that is
easy to reach. `user_id_dependency` wraps a service's own user-resolving dependency in an
`async def`, which runs in the request's context, and binds the id there::

    from webbpulse.http import user_id_dependency

    CurrentUser = user_id_dependency(get_current_user)

    @router.get("/me")
    async def me(user: User = Depends(CurrentUser)) -> UserRead:
        ...

The wrapped dependency may itself be `def` or `async def`: FastAPI resolves it as a
sub-dependency and the binding happens in the async wrapper either way, after the value has
come back across the thread boundary.
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

if TYPE_CHECKING:  # pragma: no cover - typing only
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

#: Stable `error_code` per status, used when `register_error_handlers(error_codes=True)`.
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

#: Starlette's own wording for an unmatched route and a wrong method, rewritten so the
#: envelope reads like the rest of the API rather than like the framework underneath.
_ROUTING_DETAILS: Final[Mapping[str, str]] = {
    "Not Found": "The requested resource was not found.",
    "Method Not Allowed": "That method is not allowed on this resource.",
}


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


async def bind_user_id(user_id: object) -> str:
    """Bind the user id for the rest of the request. **Await this; never call it from a
    `def` dependency.**

    A thin async wrapper over `webbpulse.log_context.set_user_id`, and the whole of the
    difference is the `async`. A coroutine runs in the caller's own context, so the binding
    it makes is visible to the handler and to every log line after it. The same call inside
    a sync (`def`) dependency binds a context that Starlette's threadpool discards on
    return, and nothing anywhere reports that it happened.

    Being a coroutine is what makes the wrong shape hard to write rather than merely
    documented: `bind_user_id(user.id)` in a `def` dependency binds nothing, but it also
    leaves an un-awaited coroutine, which Python warns about at runtime and which this
    package's `-W error` test configuration turns into a failure. `set_user_id` is still
    there and still correct wherever the caller controls the context: a middleware, a
    `task_context` block, a CLI entry point.

    Returns the bound value as the cleaned string, so a caller can log or assert on exactly
    what was bound rather than repeating the coercion.
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

    Returns an `async def` dependency that resolves `get_user` as a FastAPI sub-dependency,
    binds the id from whatever it returned, and returns that same object unchanged. The
    return value is passed straight through, so this is a drop-in replacement at the call
    site: a handler that took `Depends(get_current_user)` takes `Depends(CurrentUser)` and
    receives the identical object.

    ::

        CurrentUser = user_id_dependency(get_current_user)

        @router.get("/me")
        async def me(user: User = Depends(CurrentUser)) -> UserRead:
            ...

    `get_user` may be `def` or `async def`, and it keeps its own dependencies: FastAPI
    inspects its signature through `Depends`, so a resolver taking a `Session`, a token or
    a `Request` works untouched. The threadpool problem does not apply, because the binding
    happens in the async wrapper after the value has come back across the thread boundary.

    Args:
        get_user: The service's existing dependency, returning a user object or `None`.
        attribute: The attribute holding the id, `"id"` by default. A user object with a
            different name for it passes `attribute="user_id"` or `attribute="sub"`.
        extract: A callable taking the resolved object and returning the id, for the case
            where it is not a plain attribute: a dict, a tuple, a nested claim. Takes
            precedence over `attribute` when given.

    Returns:
        An `async def` dependency suitable for `Depends`.

    Notes:
        A `get_user` that returns `None`, which is the shape of an optional-authentication
        dependency, binds nothing and leaves `user_id` at its `"-"` placeholder rather than
        binding the string `"None"`. An object with neither `attribute` nor a usable
        `extract` result binds nothing too: a missing id is a reason to log without one, not
        a reason to fail the request that was otherwise going to succeed.
    """

    async def dependency(resolved: Any = Depends(get_user)) -> UserT:
        user: UserT = resolved
        if user is not None:
            value = extract(user) if extract is not None else getattr(user, attribute, None)
            if value is not None:
                await bind_user_id(value)
        return user

    # Carried across so FastAPI's own error messages and the OpenAPI operation ids name the
    # service's dependency rather than this module's inner function.
    dependency.__name__ = getattr(get_user, "__name__", "user_id_dependency")
    dependency.__doc__ = inspect.getdoc(get_user)
    return dependency


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Assign every request an id, expose it everywhere the id is needed, echo it back.

    An inbound `X-Request-ID` is honoured so a value set at the edge survives, and a new
    UUID4 is minted otherwise. The id then goes to three places, because each reaches
    something the others cannot:

    * `request.state`, which `request_id()` and therefore the error envelope read.
    * `webbpulse.log_context.request_id_var`, which `JsonFormatter` reads, so every log
      record emitted anywhere under this request carries the id without the `Request`
      object having to be threaded down to the code doing the logging.
    * The active OpenTelemetry span, as `webbpulse.request_id`, so a log line and a trace
      join on one string.

    The context variable is reset in a `finally`. Starlette copies the context into the
    request's task, so the binding would die with the task regardless, but resetting keeps
    a `BaseHTTPMiddleware` stack that shares a context across the chain from leaking one
    request's id into the next.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        incoming = request.headers.get(REQUEST_ID_HEADER, "").strip()
        # Bound the length so a hostile header cannot inflate every log line downstream.
        rid = incoming[:128] if incoming else str(uuid.uuid4())
        setattr(request.state, _REQUEST_ID_STATE, rid)
        token = set_request_id(rid)

        try:
            from opentelemetry import trace

            span = trace.get_current_span()
            if span.get_span_context().is_valid:
                span.set_attribute("webbpulse.request_id", rid)
        except ImportError:  # pragma: no cover - otel extra absent
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


def error_body(
    status_code: int,
    message: str,
    request: Request,
    *,
    error_code: str | None = None,
    details: Sequence[Any] | Mapping[str, Any] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Build the standard error envelope.

    The four base fields are always present and always in this order::

        {"success": false, "status": 404, "message": "...", "request_id": "..."}

    `error_code` and `details` are omitted entirely when they are `None`, so a caller that
    sets neither gets exactly the 0.2.0 body. That is the whole point of the option: a
    service that wants a machine readable code or per-field validation detail carries it in
    the shared envelope rather than forking the handlers to add a key.

    `details` is a list for validation errors (one entry per offending field) or a mapping
    for anything structured. It is echoed to the caller verbatim, so never put a rejected
    input value, a credential or an internal identifier in it.
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


# Retained under the old private name: nothing outside this module used it, but keeping the
# alias means a stray import in a consumer's fork does not break on upgrade.
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

    Without these, a validation error and an unhandled exception have different shapes and
    the second one leaks a stack trace to the caller in some configurations. Every handler
    logs through the JSON formatter, so an error is visible in CloudWatch with its request
    id whether or not the caller ever reports it.

    All the options default off, so a 0.2.0 caller gets byte identical bodies after
    upgrading. They exist so a service can adopt richer errors without forking:

    - `error_codes=True` adds a stable `error_code` string to the envelope. Handled statuses
      get a code derived from the status (`NOT_FOUND`, `CONFLICT`, `INTERNAL_ERROR`), and an
      `HTTPException` may override it by carrying its own, see below.
    - `validation_details=True` adds `details` to the 422 body, a list of
      `{"field", "message", "type"}` entries. The existing `errors` key stays exactly as it
      was, because dropping it would break a 0.2.0 caller reading it.
    - `dynamodb=True` also installs the botocore handlers, equivalent to calling
      `install_dynamodb_handlers(app)`. It imports botocore, so it needs the `dynamodb`
      extra; leave it off and the package keeps working without boto3.
    - `exception_map` maps the service's own exception types onto statuses, for the errors a
      repository layer translates before any botocore handler could see them:
      `{ItemNotFound: 404, ConditionFailed: 409}`. Each value is a status or an `ErrorSpec`.
      It needs no extra of its own and works with `dynamodb` either way: passing it without
      `dynamodb=True` installs only these handlers and imports no botocore.

    A route may set a per-response code by raising an `HTTPException` whose `detail` is a
    mapping carrying `message` and optionally `error_code` and `details`::

        raise HTTPException(404, {"message": "No such post.", "error_code": "POST_NOT_FOUND"})

    That works whether or not `error_codes` is on, since it is an explicit choice at the
    raise site rather than a global default.
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
        # Starlette types `detail` as str, but HTTPException accepts any object and
        # FastAPI routes commonly raise one with a dict detail, so the check stays.
        override_code: str | None = None
        override_details: Any = None
        # Typed as str upstream, but HTTPException accepts any object, so widen it
        # explicitly and let the isinstance checks below do the real narrowing.
        raw: Any = exc.detail
        if isinstance(raw, str):
            detail = raw
        elif isinstance(raw, Mapping):
            # The structured raise site: {"message", "error_code", "details"}.
            candidate = raw.get("message")
            detail = candidate if isinstance(candidate, str) else "Request failed."
            candidate_code = raw.get("error_code")
            override_code = candidate_code if isinstance(candidate_code, str) else None
            override_details = raw.get("details")
        else:
            detail = "Request failed."

        # Starlette raises a bare HTTPException for an unmatched route (404) and for a path
        # that matches with the wrong method (405), with detail "Not Found"/"Method Not
        # Allowed". Those reach this handler too, so the envelope covers them rather than
        # the raw {"detail": "Not Found"} Starlette would otherwise return. That is the
        # shape CarModPicker was leaking, and it is why this handler is registered for
        # StarletteHTTPException rather than only FastAPI's subclass.
        if exc.status_code in (404, 405) and detail in _ROUTING_DETAILS:
            detail = _ROUTING_DETAILS[detail]

        # 5xx raised deliberately is still a server fault worth an ERROR line; 4xx is not.
        # The detail goes to CloudWatch but not to the caller: a `raise HTTPException(500,
        # f"...{table_name}...")` is a normal thing to write, and echoing it would leak
        # internals to anyone who can provoke the error. The request id joins the two.
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
        # `details` is the newer, flatter shape: the field path as a dotted string rather
        # than a list, which is what a frontend rendering per-field messages actually wants.
        # `errors` is kept unconditionally alongside it so a 0.2.0 reader is unaffected.
        details = (
            [
                {
                    # Drop the leading "query"/"body" segment: the caller knows where it
                    # sent the value, and "body.email" reads worse than "email".
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
        _log.exception(
            "Unhandled exception serving the request.",
            extra={"path": request.url.path, "method": request.method},
        )
        # The message is deliberately generic. The detail is in CloudWatch, joined to this
        # response by the request id, rather than in the response body.
        return JSONResponse(
            status_code=500,
            content=error_body(500, "Internal server error.", request, error_code=_code(500)),
        )

    if dynamodb:
        # One call, so the botocore branches and the caller's own types are installed
        # together and the mapping is validated the same way either way.
        install_dynamodb_handlers(app, error_codes=error_codes, exception_map=exception_map)
    elif exception_map:
        # No botocore import on this path: the mapping alone needs no AWS SDK.
        _install_exception_map(
            app, _normalise_exception_map(exception_map), error_codes=error_codes
        )


#: How long a throttled caller is told to wait. Short, because DynamoDB on-demand capacity
#: recovers in seconds and a long value turns a brief spike into a long outage for the user.
DYNAMODB_RETRY_AFTER_SECONDS: Final = 1

#: Throttling and capacity errors, all of which are retryable and map to 503.
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

    A repository layer usually translates a botocore `ClientError` into its own class long
    before any handler sees it, so `ItemNotFound` never reaches the `ClientError` handler.
    Passing `{ItemNotFound: 404}` maps the type directly, and this spec is the longer form
    for when the default message or code is not the right one::

        ErrorSpec(404, message="No such post.", error_code="POST_NOT_FOUND")

    `message` defaults to the wording already used for that status, so a bare status is
    usually enough. `error_code` is honoured only when `error_codes=True`, exactly like the
    per-status codes, so turning the option off still yields the 0.3.0 body. `retry_after`
    adds the `Retry-After` header in seconds, which is what a 503 or a 429 wants.

    A status of 500 or above never echoes `message` to the caller. It logs at error and
    returns the generic "Internal server error." instead, because a message written for an
    internal exception is not written for a stranger.
    """

    status: int
    message: str | None = None
    error_code: str | None = None
    retry_after: int | None = None


#: What `exception_map` accepts: an exception type mapped to a status, or to an `ErrorSpec`
#: when the message, the code or a `Retry-After` needs saying explicitly.
type ExceptionMap = Mapping[type[BaseException], int | ErrorSpec]

#: The default `message` per status, used when an `ErrorSpec` names none. The 409 and 503
#: wordings are the ones the botocore handlers already send, so a caller-supplied
#: `ConditionFailed` reads identically to a `ConditionalCheckFailedException`.
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

    Ordering matters: Starlette walks an exception's MRO and picks the handler registered
    for the most derived class it finds, but a caller can pass both a base class and its
    subclass, and each becomes its own registration. Sorting subclasses first is therefore
    belt and braces rather than the mechanism, and it costs nothing.

    Raising here rather than at request time is deliberate. A typo in the mapping is a wiring
    mistake, and finding it when the app is built beats finding it in a 500 under load.
    """
    if not exception_map:
        return []

    entries: list[tuple[type[BaseException], ErrorSpec]] = []
    # Widened deliberately. The annotation promises exception classes and statuses, but a
    # consumer's mapping is often assembled dynamically and untyped, and a wiring mistake
    # should fail loudly here rather than as a 500 at request time.
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

    # Most derived first, so a subclass entry is registered after nothing that shadows it.
    entries.sort(key=lambda item: len(item[0].__mro__), reverse=True)
    return entries


def _install_exception_map(
    app: FastAPI,
    entries: Sequence[tuple[type[BaseException], ErrorSpec]],
    *,
    error_codes: bool,
) -> None:
    """Register one handler per caller-supplied exception type.

    Each handler builds the same envelope `error_body` builds for every other error, so a
    consumer that drops its own thin handlers gets byte identical responses.
    """

    def _register(exc_type: type[BaseException], spec: ErrorSpec) -> None:
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
            log_extra = {
                "path": request.url.path,
                "method": request.method,
                "request_id": request_id(request),
                "exception_type": type(exc).__name__,
            }
            # A mapped 5xx is still a server fault worth a stack trace; a mapped 4xx is the
            # ordinary outcome of a lost race or a missing row and only warrants a warning.
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

    Opt in, and separate from `register_error_handlers`, because it imports botocore: the
    base install has no boto3, so a service that does not touch DynamoDB must not pay for
    it. Install the `dynamodb` extra to use this. `register_error_handlers(dynamodb=True)`
    is the same thing spelled as one call.

    The mapping, which is the part that is easy to get wrong per service:

    - `ConditionalCheckFailedException` is a **409**, not a 500. A conditional write failing
      means someone else got there first, which is a caller visible conflict and the normal
      outcome of an optimistic create or a compare-and-swap.
    - `ProvisionedThroughputExceededException`, `ThrottlingException` and
      `RequestLimitExceeded` are **503** with `Retry-After`. They are transient and
      retryable, and a 500 would tell a client not to bother retrying.
    - `ResourceNotFoundException` is a **500** logged at error. The table is missing, which
      is a deployment fault and never the caller's; returning 404 for it would send an
      operator hunting for a missing record instead of a missing table.
    - `TransactionCanceledException` is inspected rather than assumed. Its
      `CancellationReasons` say why each item in the transaction failed, so it is a **409**
      when any reason is `ConditionalCheckFailed` and a **500** otherwise. Treating the
      whole class as a 409 hides real faults, and treating it as a 500 turns an ordinary
      lost race into a page.

    Every response carries the request id, and every one logs with it, so a caller's report
    joins to the CloudWatch line without the body having to carry the AWS error text.

    **`exception_map`** covers the case those botocore branches cannot reach. A repository
    layer that translates a conditional check failure into its own `ConditionFailed` before
    returning leaves nothing for the `ClientError` handler to see, so each such service grew
    its own thin handlers around `error_body`. Pass the types instead::

        install_dynamodb_handlers(
            app,
            exception_map={ItemNotFound: 404, ConditionFailed: 409, TransactionCanceled: 409},
        )

    A value is either a status or an `ErrorSpec` when the message, the `error_code` or a
    `Retry-After` needs saying. The rendered envelope is the one `error_body` builds, so a
    consumer dropping its own handlers sees no change in the response. A bad key or status
    raises at install time rather than at request time.

    The mapping is validated before botocore is imported, so a wiring mistake surfaces as a
    `TypeError` and not as an `ImportError` from a missing extra.
    """
    entries = _normalise_exception_map(exception_map)

    from botocore.exceptions import ClientError

    def _code(status_code: int, override: str | None = None) -> str | None:
        if override is not None:
            return override if error_codes else None
        return _STATUS_ERROR_CODES.get(status_code) if error_codes else None

    @app.exception_handler(ClientError)
    async def _dynamodb_client_error(request: Request, exc: ClientError) -> JSONResponse:
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
            # A missing table is a deployment fault, so this is loud and it is a 500. The
            # caller is told nothing about tables.
            _log.error("DynamoDB table or index is missing.", extra=log_extra)
            return JSONResponse(
                status_code=500,
                content=error_body(500, "Internal server error.", request, error_code=_code(500)),
            )

        if aws_code == "TransactionCanceledException":
            reasons = exc.response.get("CancellationReasons") or []
            # The stubs type each reason as a mapping; the runtime shape is whatever the
            # API returned, so read defensively but without a check mypy calls redundant.
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

        # Anything else is an unexpected AWS fault: log the whole thing, tell the caller
        # nothing. Falling through to the generic Exception handler would work too, but
        # Starlette picks the most specific registered handler, so this must be explicit.
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

    Adds, in the order the request traverses them: CORS, the request id middleware, the
    structured error handlers, and a `GET /health` route.

    CORS origins come from `settings` when given, or from `cors_allow_origins`. When
    credentials are allowed the origin list must be exact, never `"*"`: the CORS
    specification forbids that pair, and browsers reject the response rather than the server
    doing so, which makes it look like a client bug.

    `instrument=True` attaches the OpenTelemetry FastAPI instrumentation when the `otel`
    extra is installed and tracing is enabled. Call `configure_tracing` first so the spans
    reach a real provider.

    `exception_map` renders the service's own exception types in the same envelope, so a
    repository layer that raises `ItemNotFound` rather than letting a botocore `ClientError`
    escape does not need thin handlers of its own::

        app = create_app([posts_router], exception_map={ItemNotFound: 404, ConditionFailed: 409})
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
            # A header the browser cannot read is a header the limiter did not emit, as
            # far as a fetch() caller is concerned, so the X-RateLimit-* compatibility
            # trio is exposed alongside the structured fields it accompanies.
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
