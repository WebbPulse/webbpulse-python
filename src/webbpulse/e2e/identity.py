"""Sign the durable e2e user in through the real login route, and mint a token in staging.

Two identities, for two different questions. The durable user logs in the way a person
does, so it exercises the route, the limiter, the hooks and the cookie or header the
product actually uses; it is the only identity production ever sees. The minted token
exercises the authorizer alone, with no login at all, and `mint_test_token` refuses
production independently of its enable flag, so the mint fixtures skip everywhere else.

Nothing here prints a password or a token.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .client import E2EClient

__all__ = [
    "DEFAULT_LOGIN_PATH",
    "DEFAULT_LOGOUT_PATH",
    "DEFAULT_REFRESH_PATH",
    "JWKS_PATH",
    "IdentitySession",
    "LoginFailed",
    "decode_claims",
    "login",
    "logout",
    "mint",
    "refresh",
]

DEFAULT_LOGIN_PATH = "/api/auth/login"
DEFAULT_REFRESH_PATH = "/api/auth/refresh"
DEFAULT_LOGOUT_PATH = "/api/auth/logout"
JWKS_PATH = "/api/auth/.well-known/jwks.json"


class LoginFailed(RuntimeError):
    """The durable e2e user could not sign in, so every authenticated test would be noise."""


def _pad(value: str) -> str:
    """Restore the base64url padding a JWT segment omits."""
    return value + "=" * (-len(value) % 4)


def decode_claims(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read a JWT's header and claims without verifying it.

    Verification is the gateway's job and it has already happened by the time a call
    succeeds. What this is for is asserting the shape: that the token this environment
    issued is RS256 from this environment's issuer and audience, which is a claim about
    which code path minted it.
    """
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT: fewer than two dot separated segments")
    header = json.loads(base64.urlsafe_b64decode(_pad(parts[0])))
    claims = json.loads(base64.urlsafe_b64decode(_pad(parts[1])))
    return header, claims


@dataclass
class IdentitySession:
    """A signed-in durable e2e user: a client carrying the token, plus the refresh material.

    `refresh_cookies` holds whatever the login response set, so a product that keeps the
    refresh token in a cookie and one that returns it in the body are both served without
    the suite knowing which.
    """

    client: E2EClient
    access_token: str
    claims: Mapping[str, Any]
    header: Mapping[str, Any]
    refresh_token: str
    refresh_cookies: Mapping[str, str]
    user_id: str

    @property
    def algorithm(self) -> str:
        """The `alg` the token header declares."""
        return str(self.header.get("alg", ""))

    @property
    def issuer(self) -> str:
        """The `iss` claim."""
        return str(self.claims.get("iss", ""))

    @property
    def audience(self) -> str:
        """The `aud` claim, flattened when the token carries a list."""
        audience = self.claims.get("aud", "")
        if isinstance(audience, list):
            return str(audience[0]) if audience else ""
        return str(audience)


def _extract_token(payload: Any, *names: str) -> str:
    """The first of `names` present in a response body, or the empty string."""
    if not isinstance(payload, dict):
        return ""
    for name in names:
        value = payload.get(name)
        if isinstance(value, str) and value:
            return value
    data = payload.get("data")
    if isinstance(data, dict):
        return _extract_token(data, *names)
    return ""


def login(
    client: E2EClient,
    email: str,
    password: str,
    *,
    login_path: str = DEFAULT_LOGIN_PATH,
) -> IdentitySession:
    """Sign the durable e2e user in through the real login route.

    Raises rather than returning a broken session: an authenticated suite running against a
    failed login produces a column of 401s that say nothing about the routes under test.
    The password never reaches the message of the raised error.
    """
    response = client.post(login_path, json={"email": email, "password": password})
    if response.status_code != 200:
        raise LoginFailed(
            f"POST {login_path} answered {response.status_code} for the durable e2e user. "
            "Check E2E_USER_EMAIL and the environment secret E2E_USER_PASSWORD, and that "
            "the account exists and is verified in this environment."
        )
    try:
        payload = response.json()
    except ValueError as error:
        raise LoginFailed(f"POST {login_path} answered 200 with a body that is not JSON") from error

    access_token = _extract_token(payload, "access_token", "accessToken", "token")
    if not access_token:
        raise LoginFailed(f"POST {login_path} answered 200 with no access token in the body")

    header, claims = decode_claims(access_token)
    return IdentitySession(
        client=client.with_token(access_token),
        access_token=access_token,
        claims=claims,
        header=header,
        refresh_token=_extract_token(payload, "refresh_token", "refreshToken"),
        refresh_cookies=dict(response.cookies),
        user_id=str(claims.get("sub", "")),
    )


def refresh(
    session: IdentitySession,
    *,
    refresh_path: str = DEFAULT_REFRESH_PATH,
) -> Any:
    """Exchange the refresh material for a new access token, however the product carries it.

    The refresh token is sent in the body when the login response returned one and left to
    the cookie jar otherwise, so this works for both conventions without a product flag.
    """
    body = {"refresh_token": session.refresh_token} if session.refresh_token else None
    headers = {}
    if session.refresh_cookies:
        headers["cookie"] = "; ".join(f"{name}={value}" for name, value in session.refresh_cookies.items())
    return session.client.post(refresh_path, json=body, headers=headers)


def logout(session: IdentitySession, *, logout_path: str = DEFAULT_LOGOUT_PATH) -> Any:
    """End the session through the real logout route."""
    return session.client.post(logout_path, json={})


def mint(
    *,
    kms_client: Any,
    key_id: str,
    environment: str,
    issuer: str,
    audience: str,
    subject: str,
    expires_in: int = 600,
    extra_claims: Mapping[str, Any] | None = None,
    now: int | None = None,
) -> str:
    """Mint a signed access token with `mint_test_token` and a `KmsSigner`.

    A thin wrapper so the suite does not import the identity package's internals, and so
    the refusal in production is the package's own rather than a copy of it that could
    drift. `enabled` is passed true here because the fixture that calls this has already
    skipped when `E2E_MINT_ENABLED` is unset; `environment` is still passed through, so the
    package's independent refusal remains the second check.
    """
    from webbpulse.identity.tokens import KmsSigner, mint_test_token

    signer = KmsSigner(kms_client, key_id)
    return mint_test_token(
        signer,
        enabled=True,
        environment=environment,
        issuer=issuer,
        audience=audience,
        subject=subject,
        expires_in=expires_in,
        extra_claims=extra_claims,
        now=now,
    )
