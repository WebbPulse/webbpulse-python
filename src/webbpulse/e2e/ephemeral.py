"""Create and delete one throwaway login user per run, so runs can overlap.

The durable user is a shared mutable resource: the profile, social-link and sign-in
journeys all write to whichever account they run as, so two runs against it race and the
callers had to serialise behind a per-branch concurrency group. A run that makes its own
user needs no such group.

Falls back to the durable user whenever the route is not there, which covers a product that
has not adopted the flag yet and any environment where the flag is off. A read-only run
signs in as nobody and asks for neither.

The generated password lives in memory for the length of the session and reaches only the
login call and the browser's `fill`. It is never logged, never written to a trace or an
artifact, and `Credentials` keeps it out of its own repr.
"""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:  # pragma: no cover
    from .client import E2EClient

__all__ = [
    "CREATE_PATH",
    "PASSWORD_LENGTH",
    "Credentials",
    "EphemeralUser",
    "create_ephemeral_user",
    "delete_ephemeral_user",
    "ephemeral_email",
    "generate_password",
    "item_path",
]

CREATE_PATH: Final = "/api/auth/e2e/users"

PASSWORD_LENGTH: Final = 32

_ALPHABET: Final = string.ascii_letters + string.digits


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


def ephemeral_email(run_id: str, *, domain: str = "e2e.invalid") -> str:
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


def create_ephemeral_user(
    client: E2EClient,
    *,
    run_id: str,
    admin_token: str,
    create_path: str = CREATE_PATH,
    password: str | None = None,
    attributes: dict[str, Any] | None = None,
) -> EphemeralUser | None:
    """Create this run's login user, or None when the route is not offered here.

    A 404 or a 403 is read as "this deployment does not offer ephemeral users" and answered
    with None so the caller falls back to the durable user. Every other failure raises,
    because a route that exists and is erroring is a finding rather than a reason to quietly
    mutate the shared account.

    Neither the generated password nor the admin token reaches the raised message.
    """
    secret = password if password is not None else generate_password()
    email = ephemeral_email(run_id)
    response = client.with_token(admin_token).post(
        create_path,
        json={"email": email, "password": secret, "attributes": dict(attributes or {})},
    )
    if response.status_code in (403, 404, 405):
        return None
    if response.status_code != 201:
        raise RuntimeError(
            f"POST {create_path} answered {response.status_code} rather than creating this "
            "run's ephemeral e2e user. The route is mounted, so this is a real failure "
            "rather than a deployment that does not offer it."
        )
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


def delete_ephemeral_user(client: E2EClient, user: EphemeralUser, *, admin_token: str) -> bool:
    """Delete this run's user, returning whether the route reported it gone.

    Never raises: cleanup runs at session teardown, where a raise would replace a completed
    run's results with a teardown error. A failure is reported by the return value and the
    caller turns it into a warning.
    """
    path = item_path(user.user_id, create_path=user.create_path)
    try:
        response = client.with_token(admin_token).request("DELETE", path)
    except Exception:
        return False
    return response.status_code == 200
