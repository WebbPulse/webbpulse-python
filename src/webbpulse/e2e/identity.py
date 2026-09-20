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
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .client import E2EClient

__all__ = [
    "DEFAULT_ACCESS_TOKEN_TTL",
    "DEFAULT_LOGIN_PATH",
    "DEFAULT_LOGOUT_PATH",
    "DEFAULT_REFRESH_PATH",
    "DEFAULT_REFRESH_SKEW",
    "JWKS_PATH",
    "IdentitySession",
    "LoginFailed",
    "RefreshFailed",
    "decode_claims",
    "login",
    "logout",
    "mint",
    "refresh",
    "token_expiry",
]

DEFAULT_LOGIN_PATH = "/api/auth/login"
DEFAULT_REFRESH_PATH = "/api/auth/refresh"
DEFAULT_LOGOUT_PATH = "/api/auth/logout"
JWKS_PATH = "/api/auth/.well-known/jwks.json"

DEFAULT_REFRESH_SKEW = 60.0
DEFAULT_ACCESS_TOKEN_TTL = 600.0


class LoginFailed(RuntimeError):
    """The durable e2e user could not sign in, so every authenticated test would be noise."""


class RefreshFailed(RuntimeError):
    """The session's refresh material no longer buys an access token.

    Distinct from a plain HTTP assertion failure because it is terminal for the run: once
    the refresh family is expired or revoked there is no credential left, and every
    subsequent case would fail as a 401 that says nothing about the route it called.
    """


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


def token_expiry(token: str) -> float | None:
    """The `exp` a JWT declares, as a unix timestamp, or None when it carries no readable one.

    Read without verification, the same way `decode_claims` reads the rest: the value is used
    only to decide when to ask for a fresh token, never to decide whether the current one is
    trusted, which is the gateway's job.
    """
    try:
        _, claims = decode_claims(token)
    except Exception:
        return None
    expiry = claims.get("exp")
    if isinstance(expiry, bool) or not isinstance(expiry, (int, float)):
        return None
    return float(expiry)


@dataclass
class IdentitySession:
    """A signed-in durable e2e user: a client carrying the token, plus the refresh material.

    `refresh_cookies` holds whatever the login response set, so a product that keeps the
    refresh token in a cookie and one that returns it in the body are both served without
    the suite knowing which.

    The session, not the client, owns the access token. The client it hands out asks for the
    credential on every request, so a token refreshed here reaches every later call including
    ones made through a clone. The identity access token's TTL is ten minutes by default and
    a full suite runs well past that, so a session that carried the login token for the whole
    run had every call after the tenth minute refused by the authorizer, which reads exactly
    like a broken route.

    Refresh is lazy and happens in two places: before a request when the current token is
    within `refresh_skew` seconds of its `exp`, and once after a refusal that reads as an
    expired credential. Both take `_lock`, so concurrent callers refresh once between them and
    neither loses the rotated refresh token to the other.
    """

    client: E2EClient
    access_token: str
    claims: Mapping[str, Any]
    header: Mapping[str, Any]
    refresh_token: str
    refresh_cookies: Mapping[str, str]
    user_id: str
    refresh_path: str = DEFAULT_REFRESH_PATH
    refresh_skew: float = DEFAULT_REFRESH_SKEW
    access_token_ttl: float = DEFAULT_ACCESS_TOKEN_TTL
    issued_at: float = field(default_factory=time.time)
    clock: Callable[[], float] = time.time
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    refreshes: int = 0

    def __post_init__(self) -> None:
        """Point the session's client back at the session so it asks for a live token.

        Tolerates a session built without a client, which is how the token-shape tests
        construct one: there is nothing to keep current when nothing sends requests.
        """
        if self.client is not None:
            self.client.token_source = self

    @property
    def expires_at(self) -> float:
        """When the current access token stops being accepted, as a unix timestamp.

        The token's own `exp` when it declares one. A token with no readable `exp` falls back
        to the configured TTL measured from when this token was issued, which is the best a
        caller can do without the issuer telling it.
        """
        declared = token_expiry(self.access_token)
        if declared is not None:
            return declared
        return self.issued_at + self.access_token_ttl

    def is_near_expiry(self) -> bool:
        """Whether the current token is inside the skew window and should be replaced first."""
        return self.clock() >= self.expires_at - self.refresh_skew

    def bearer_token(self) -> str:
        """The token to send now, refreshing first when the current one is near its expiry."""
        if self.is_near_expiry():
            with self._lock:
                if self.is_near_expiry():
                    self._refresh_locked()
        return self.access_token

    def refresh_for_retry(self, token: str) -> str:
        """Refresh after a refusal and hand back the token the retry should carry.

        Returns the token another caller already obtained when `token` is no longer the
        session's, so a burst of requests refused together refreshes once rather than once
        each, and the rest simply retry with what that one refresh produced.
        """
        with self._lock:
            if token != self.access_token:
                return self.access_token
            self._refresh_locked()
            return self.access_token

    def _refresh_locked(self) -> None:
        """Exchange the refresh material for a new token and store the rotated material.

        The caller holds `_lock`. The identity refresh endpoint rotates the refresh token on
        every call, so whatever it returns in the body and whatever cookies it sets replace
        what the session held, mirroring how `login` stores them. Keeping the old material
        would send a spent token on the next refresh, which the rotation detection treats as
        a replay and answers by revoking the whole family.
        """
        response = refresh(self, refresh_path=self.refresh_path)
        status = getattr(response, "status_code", 0)
        if status != 200:
            raise RefreshFailed(
                f"POST {self.refresh_path} answered {status} refreshing the session for user "
                f"{self.user_id or '<unknown>'}. The refresh token has expired or the family was "
                "revoked, so this session has no credential left and every later call would be "
                "refused for the same reason."
            )
        try:
            payload = response.json()
        except ValueError as error:
            raise RefreshFailed(
                f"POST {self.refresh_path} answered 200 with a body that is not JSON, so the "
                f"session for user {self.user_id or '<unknown>'} has no new access token."
            ) from error

        access_token = _extract_token(payload, "access_token", "accessToken", "token")
        if not access_token:
            raise RefreshFailed(
                f"POST {self.refresh_path} answered 200 with no access token in the body, so the "
                f"session for user {self.user_id or '<unknown>'} cannot continue."
            )

        header, claims = decode_claims(access_token)
        self.access_token = access_token
        self.header = header
        self.claims = claims
        self.issued_at = self.clock()
        self.refreshes += 1
        rotated = _extract_token(payload, "refresh_token", "refreshToken")
        if rotated:
            self.refresh_token = rotated
        cookies = dict(getattr(response, "cookies", {}) or {})
        if cookies:
            self.refresh_cookies = {**self.refresh_cookies, **cookies}

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
    refresh_path: str = DEFAULT_REFRESH_PATH,
    refresh_skew: float = DEFAULT_REFRESH_SKEW,
    access_token_ttl: float = DEFAULT_ACCESS_TOKEN_TTL,
) -> IdentitySession:
    """Sign the durable e2e user in through the real login route.

    Raises rather than returning a broken session: an authenticated suite running against a
    failed login produces a column of 401s that say nothing about the routes under test.
    The password never reaches the message of the raised error.

    The session returned keeps its own token current: it refreshes through `refresh_path`
    when the token comes within `refresh_skew` seconds of expiring, and `access_token_ttl`
    is the fallback lifetime for a token that declares no readable `exp`.
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
        refresh_path=refresh_path,
        refresh_skew=refresh_skew,
        access_token_ttl=access_token_ttl,
    )


def refresh(
    session: IdentitySession,
    *,
    refresh_path: str = DEFAULT_REFRESH_PATH,
) -> Any:
    """Exchange the refresh material for a new access token, however the product carries it.

    The refresh token is sent in the body when the login response returned one and left to
    the cookie jar otherwise, so this works for both conventions without a product flag.

    Sent through a clone carrying no bearer credential, because the refresh token is the whole
    authorisation here. A clone also carries no token source, which matters twice: asking the
    session for a live token would re-enter the refresh this call may already be inside, and a
    refusal retry would spend the rotated token a second time and have the rotation detection
    revoke the whole family as a replay. The 429 pacing and retry still apply.
    """
    body = {"refresh_token": session.refresh_token} if session.refresh_token else None
    headers = {}
    if session.refresh_cookies:
        headers["cookie"] = "; ".join(f"{name}={value}" for name, value in session.refresh_cookies.items())
    anonymous = session.client.with_token(None)
    return anonymous.post(refresh_path, json=body, headers=headers)


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
