"""Create and delete one throwaway login user per run, so runs can overlap.

The durable user is a shared mutable resource: the profile, social-link and sign-in
journeys all write to whichever account they run as, so two runs against it race and the
callers had to serialise behind a per-branch concurrency group. A run that makes its own
user needs no such group.

Falls back to the durable user whenever the route is not there, which covers a product that
has not adopted the flag yet and any environment where the flag is off. A read-only run
signs in as nobody and asks for neither. Only the route's own refusal counts as "not here":
a 403 from the HTTP API authorizer in front of it, which a cold start produces, is retried
and then raised, because reading it as a refusal silently ran a whole worker as the shared
durable user.

A run whose teardown delete failed leaves its user behind, so the first worker of every run
asks the sweep route to delete ephemeral users older than `SWEEP_OLDER_THAN_SECONDS`. A
deployment on a `webbpulse` that predates the route answers 404 or 405, and one whose users
table cannot be enumerated answers 501; each is read as "no sweep here" and the run goes on.

The generated password lives in memory for the length of the session and reaches only the
login call and the browser's `fill`. It is never logged, never written to a trace or an
artifact, and `Credentials` keeps it out of its own repr.
"""

from __future__ import annotations

import secrets
import string
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Final, Protocol

__all__ = [
    "BODY_EXCERPT_LIMIT",
    "CREATE_PATH",
    "GATEWAY_RETRY_DELAYS",
    "PASSWORD_LENGTH",
    "RESERVED_EMAIL_DOMAIN",
    "ROUTE_REFUSAL_CODES",
    "SWEEP_OLDER_THAN_SECONDS",
    "SWEEP_PATH",
    "SWEEP_UNOFFERED_STATUSES",
    "Credentials",
    "EphemeralUser",
    "TokenClient",
    "attempt_ephemeral_user",
    "create_ephemeral_user",
    "delete_ephemeral_user",
    "describe_delete_failure",
    "describe_error_body",
    "email_validation_hint",
    "ephemeral_email",
    "generate_password",
    "is_route_refusal",
    "item_path",
    "sweep_ephemeral_users",
]

CREATE_PATH: Final = "/api/auth/e2e/users"

PASSWORD_LENGTH: Final = 32

BODY_EXCERPT_LIMIT: Final = 300

RESERVED_EMAIL_DOMAIN: Final = "e2e.invalid"

SWEEP_PATH: Final = "/api/auth/e2e/users/sweep"

SWEEP_OLDER_THAN_SECONDS: Final = 3 * 60 * 60
"""Three hours: long enough that no run still in progress loses its user to this sweep."""

SWEEP_UNOFFERED_STATUSES: Final = frozenset({403, 404, 405, 501})
"""The answers that mean this deployment offers no sweep, rather than that one failed."""

ROUTE_REFUSAL_CODES: Final = frozenset({"ADMIN_REQUIRED", "EPHEMERAL_USERS_DISABLED"})
"""The `error_code` values the create route's own 403 carries, which mean "not offered here"."""

UNMOUNTED_STATUSES: Final = frozenset({404, 405})

GATEWAY_RETRY_DELAYS: Final[tuple[float, ...]] = (1.0, 2.0, 4.0)
"""Seconds slept before each retry of a 403 that is not the route's own refusal."""

DETAIL_LIMIT: Final = 10

_ALPHABET: Final = string.ascii_letters + string.digits


class TokenClient(Protocol):
    """The slice of `E2EClient` these helpers use: a bearer-scoped client that posts and requests."""

    def with_token(self, token: str | None) -> TokenClient:
        """A client sending `token` as the bearer credential."""
        ...

    def post(self, path: str, *, json: Any = None) -> Any:
        """POST a JSON body and return the response."""
        ...

    def request(self, method: str, path: str, *, json: Any = None) -> Any:
        """Send one request and return the response."""
        ...


def _detail_entry(entry: Any) -> str:
    """One validation detail rendered as `field: message (type)`, from whatever shape it has."""
    if not isinstance(entry, dict):
        return str(entry)
    field_name = entry.get("field")
    if field_name is None:
        location = entry.get("loc")
        if isinstance(location, (list, tuple)):
            field_name = ".".join(str(part) for part in location)
    rendered = str(field_name) if field_name else "?"
    message = entry.get("message") or entry.get("msg")
    if message:
        rendered = f"{rendered}: {message}"
    kind = entry.get("type")
    if kind:
        rendered = f"{rendered} ({kind})"
    return rendered


def _detail_text(details: Any) -> str:
    """A compact rendering of the envelope's `details`, or the empty string when it holds none."""
    if isinstance(details, dict):
        details = [details]
    if not isinstance(details, (list, tuple)) or not details:
        return ""
    shown = [_detail_entry(entry) for entry in list(details)[:DETAIL_LIMIT]]
    text = "; ".join(part for part in shown if part)
    if len(details) > DETAIL_LIMIT:
        text = f"{text}; ... {len(details) - DETAIL_LIMIT} more"
    return text


def describe_error_body(response: Any) -> str:
    """What the failing response said, safe to put in a message a person reads.

    A JSON body is read as the shared error envelope and rendered from its `error_code`,
    `message`, `request_id` and `details`. Anything else is excerpted to at most
    `BODY_EXCERPT_LIMIT` characters. Only the response is read, so no request payload and no
    credential can reach the result.
    """
    try:
        payload = response.json()
    except Exception:
        payload = None
    if isinstance(payload, dict):
        parts = []
        for key in ("error_code", "message", "request_id"):
            value = payload.get(key)
            if value:
                parts.append(f"{key}={value}")
        detail_text = _detail_text(payload.get("details"))
        if detail_text:
            parts.append(f"details=[{detail_text}]")
        if parts:
            return " ".join(parts)
    text = str(getattr(response, "text", "") or "")
    if not text.strip():
        return "the body was empty"
    excerpt = text[:BODY_EXCERPT_LIMIT]
    if len(text) > BODY_EXCERPT_LIMIT:
        excerpt = f"{excerpt}..."
    return f"body={excerpt}"


_EMAIL_VALIDATION_MARKERS: Final = (
    "email",
    "special-use",
    "reserved name",
    "not a valid email",
    "emailstr",
)

_EMAIL_HINT: Final = (
    "Hint: the ephemeral address is on the reserved "
    f"`{RESERVED_EMAIL_DOMAIN}` domain, which RFC 2606 sets aside so no mail can ever leave. "
    "`email-validator`, which Pydantic's `EmailStr` uses, refuses special-use domains and "
    "offers no option that re-admits `.invalid`, so a persisted user record model annotated "
    "`EmailStr` answers 500 here. Keep `EmailStr` on request schemas only and let record "
    "models hold a plain `local@domain` string."
)


def email_validation_hint(status_code: int, body: str, email: str) -> str:
    """The one-line `EmailStr` hint when this failure looks like the reserved-domain trap.

    Offered only for a 500, which is what a record model rejecting the address produces: for
    any address on the reserved ephemeral domain, since that domain is the only reason a
    product's own record model would reject an address the shared identity flow already
    accepted and a production error envelope hides the cause, and for a body that mentions
    email validation whatever the address. The empty string for every other status, so a
    gateway or throttling failure on the same address is not given a misleading explanation.
    """
    if status_code != 500:
        return ""
    on_reserved_domain = email.rsplit("@", 1)[-1].lower() == RESERVED_EMAIL_DOMAIN
    lowered = body.lower()
    mentions_email = any(marker in lowered for marker in _EMAIL_VALIDATION_MARKERS)
    if not on_reserved_domain and not mentions_email:
        return ""
    return _EMAIL_HINT


def item_path(user_id: str, *, create_path: str = CREATE_PATH) -> str:
    """The delete path for one ephemeral user, derived from the create path."""
    return f"{create_path.rstrip('/')}/{user_id}"


def generate_password(length: int = PASSWORD_LENGTH) -> str:
    """A random password strong enough for any product's policy, from `secrets`.

    Mixed case, digits and one punctuation character are forced rather than left to chance,
    because a policy that demands each class would otherwise reject a run at random.
    """
    if length < 8:
        raise ValueError("An ephemeral password must be at least 8 characters.")
    body = "".join(secrets.choice(_ALPHABET) for _ in range(length - 4))
    upper = secrets.choice(string.ascii_uppercase)
    lower = secrets.choice(string.ascii_lowercase)
    digit = secrets.choice(string.digits)
    return f"{upper}{lower}{digit}{body}-"


def ephemeral_email(run_id: str, *, domain: str = RESERVED_EMAIL_DOMAIN) -> str:
    """The address for this run's user, carrying the run id so a leak is traceable.

    `.invalid` is reserved by RFC 2606 and can never be delivered to, so a product that
    mails a new account cannot reach a real inbox with it.
    """
    cleaned = "".join(char for char in run_id.strip().lower() if char.isalnum() or char == "-")
    if not cleaned:
        raise ValueError("An ephemeral email needs a run id, and was given an empty one.")
    return f"e2e-{cleaned}@{domain}"


@dataclass(frozen=True)
class Credentials:
    """One email and password the suite signs in with, whoever they belong to.

    `password` is `repr=False`, so a pytest fixture dump, an assertion rewrite or a logged
    dataclass never renders it.
    """

    email: str
    password: str = field(repr=False)
    user_id: str = ""
    ephemeral: bool = False


@dataclass(frozen=True)
class EphemeralUser:
    """This run's own login user, and what is needed to delete it."""

    credentials: Credentials
    user_id: str
    create_path: str = CREATE_PATH


def is_route_refusal(response: Any) -> bool:
    """Whether this 403 is the create route's own refusal rather than the gateway's.

    The route answers in the shared error envelope with a top-level `error_code` from
    `ROUTE_REFUSAL_CODES`. A `detail` object carrying the code is read too, for a product
    that renders the refusal through a bare `HTTPException`. Anything else, such as the
    authorizer's `{"message": "Forbidden"}`, is not the route speaking.
    """
    try:
        payload = response.json()
    except Exception:
        return False
    if not isinstance(payload, dict):
        return False
    detail = payload.get("detail")
    codes = {payload.get("error_code")}
    if isinstance(detail, dict):
        codes.add(detail.get("error_code"))
    return any(code in ROUTE_REFUSAL_CODES for code in codes)


def create_ephemeral_user(
    client: TokenClient,
    *,
    run_id: str,
    admin_token: str,
    create_path: str = CREATE_PATH,
    password: str | None = None,
    attributes: dict[str, Any] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> EphemeralUser | None:
    """Create this run's login user, or None when the route is not offered here.

    `attempt_ephemeral_user` with the reason for a missing route dropped, for a caller that
    only needs to know whether it got a user.
    """
    result = attempt_ephemeral_user(
        client,
        run_id=run_id,
        admin_token=admin_token,
        create_path=create_path,
        password=password,
        attributes=attributes,
        sleep=sleep,
    )
    return result if isinstance(result, EphemeralUser) else None


def attempt_ephemeral_user(
    client: TokenClient,
    *,
    run_id: str,
    admin_token: str,
    create_path: str = CREATE_PATH,
    password: str | None = None,
    attributes: dict[str, Any] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> EphemeralUser | str:
    """Create this run's login user, or say why this deployment does not offer the route.

    A 404 or 405 means the route is not mounted, and a 403 carrying one of
    `ROUTE_REFUSAL_CODES` is the route refusing; both return the reason so the caller can
    fall back to the durable user and say why. Any other 403 is the gateway in front of the
    route, such as an authorizer timing out on a cold start, and is retried after each delay
    in `GATEWAY_RETRY_DELAYS` before it raises. Every other failure raises at once, because a
    route that exists and is erroring is a finding rather than a reason to quietly mutate the
    shared account.

    Neither the generated password nor the admin token reaches the raised message.
    """
    secret = password if password is not None else generate_password()
    email = ephemeral_email(run_id)
    body = {"email": email, "password": secret, "attributes": dict(attributes or {})}
    response = client.with_token(admin_token).post(create_path, json=body)
    for delay in GATEWAY_RETRY_DELAYS:
        if response.status_code != 403 or is_route_refusal(response):
            break
        sleep(delay)
        response = client.with_token(admin_token).post(create_path, json=body)
    if response.status_code in UNMOUNTED_STATUSES:
        return f"POST {create_path} answered {response.status_code}, so this deployment does not mount the route."
    if response.status_code == 403 and is_route_refusal(response):
        return f"POST {create_path} refused the run. It said: {describe_error_body(response)}"
    if response.status_code == 403:
        raise RuntimeError(
            f"POST {create_path} answered 403 on {len(GATEWAY_RETRY_DELAYS) + 1} attempts with a body "
            "that is not the route's own refusal, so the gateway in front of it, most likely the "
            "HTTP API authorizer, kept refusing the minted admin token. Falling back would run "
            f"this worker as the shared durable user. It said: {describe_error_body(response)}"
        )
    if response.status_code != 201:
        described = describe_error_body(response)
        hint = email_validation_hint(response.status_code, described, email)
        message = (
            f"POST {create_path} answered {response.status_code} rather than creating this "
            "run's ephemeral e2e user. The route is mounted, so this is a real failure "
            f"rather than a deployment that does not offer it. It said: {described}"
        )
        raise RuntimeError(f"{message} {hint}" if hint else message)
    try:
        payload = response.json()
    except ValueError as error:
        raise RuntimeError(f"POST {create_path} answered 201 with a body that is not JSON") from error
    user_id = str(payload.get("user_id", "") or "")
    if not user_id:
        raise RuntimeError(f"POST {create_path} answered 201 with no user_id, so the user could never be deleted.")
    return EphemeralUser(
        credentials=Credentials(
            email=str(payload.get("email", "") or email),
            password=secret,
            user_id=user_id,
            ephemeral=True,
        ),
        user_id=user_id,
        create_path=create_path,
    )


def delete_ephemeral_user(client: TokenClient, user: EphemeralUser, *, admin_token: str) -> bool:
    """Delete this run's user, returning whether the route reported it gone.

    Never raises: cleanup runs at session teardown, where a raise would replace a completed
    run's results with a teardown error. A failure is reported by the return value and the
    caller turns it into a warning.
    """
    return not describe_delete_failure(client, user, admin_token=admin_token)


def describe_delete_failure(client: TokenClient, user: EphemeralUser, *, admin_token: str) -> str:
    """Delete this run's user, returning why it failed or the empty string when it worked.

    The same never-raising contract as `delete_ephemeral_user`, with the reason kept rather
    than discarded so the caller's teardown warning can name it. Only the response and the
    exception are read, so neither the password nor the admin token can reach the result.
    """
    path = item_path(user.user_id, create_path=user.create_path)
    try:
        response = client.with_token(admin_token).request("DELETE", path)
    except Exception as error:
        return f"DELETE {path} raised {type(error).__name__}: {error}"
    if response.status_code == 200:
        return ""
    return f"DELETE {path} answered {response.status_code}. It said: {describe_error_body(response)}"


def sweep_ephemeral_users(
    client: TokenClient,
    *,
    admin_token: str,
    sweep_path: str = SWEEP_PATH,
    older_than_seconds: int = SWEEP_OLDER_THAN_SECONDS,
) -> str:
    """Ask the deployment to delete leftover ephemeral users, returning why it failed or "".

    Never raises, since a sweep that could not run is no reason to lose a run. An answer in
    `SWEEP_UNOFFERED_STATUSES` returns the empty string too: an older backend has no such
    route, and a newer plugin must not break a run against it. Only the response and the
    exception are read, so the admin token cannot reach the result.
    """
    try:
        response = client.with_token(admin_token).post(sweep_path, json={"older_than_seconds": older_than_seconds})
    except Exception as error:
        return f"POST {sweep_path} raised {type(error).__name__}: {error}"
    if response.status_code == 200 or response.status_code in SWEEP_UNOFFERED_STATUSES:
        return ""
    return f"POST {sweep_path} answered {response.status_code}. It said: {describe_error_body(response)}"
