"""Sign a CLI in through the OAuth device authorization grant, keeping its tokens in the OS keyring.

    client = DeviceLoginClient("https://api.example.com/api/auth", "wp-tf", headers=gate_headers)
    client.login(["runs:read"])
    token = client.access_token()
    client.logout()

`login` prints the verification URL and the user code, then polls until the person approves
in a browser. The access and refresh tokens go straight into the OS keyring and are
refreshed there transparently when the access token is about to expire. Neither token is
ever written to stdout, a log line, a command line or an exception message.

A refresh runs under a file lock in the user cache directory, so two commands started
together cannot both spend the same refresh token. A plaintext or failing keyring backend
is refused rather than used, and an access token too large for the platform's credential
store is left out of it and fetched again with the refresh token when next needed.

Needs `webbpulse[device-login]` (httpx and keyring).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sys
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, Final, Protocol
from urllib.parse import urlsplit

if TYPE_CHECKING:  # pragma: no cover
    import httpx

__all__ = [
    "DEFAULT_KEYRING_SERVICE",
    "DEVICE_CODE_GRANT_TYPE",
    "REFRESH_MARGIN_SECONDS",
    "DeviceLoginClient",
    "DeviceLoginError",
    "KeyringBackend",
    "LogoutResult",
    "StoredSession",
]

DEFAULT_KEYRING_SERVICE: Final = "webbpulse-device-login"
DEVICE_CODE_GRANT_TYPE: Final = "urn:ietf:params:oauth:grant-type:device_code"
REFRESH_MARGIN_SECONDS: Final = 60
SLOW_DOWN_STEP: Final = 5
_LOCAL_HOSTS: Final = frozenset({"localhost", "127.0.0.1", "::1"})
KEYRING_ENTRY_BUDGET: Final = 1200
"""The most characters one keyring entry may hold. Windows Credential Manager caps a secret
at 2560 bytes and stores text as UTF-16, so this keeps well inside it on every platform."""
_REFUSED_KEYRINGS: Final = frozenset(
    {
        "keyrings.alt.file.PlaintextKeyring",
        "keyring.backends.fail.Keyring",
    }
)


class DeviceLoginError(Exception):
    """A device login that could not start, finish, refresh or end. Never carries a token."""


class KeyringBackend(Protocol):
    """The three `keyring` module functions this client uses."""

    def get_password(self, service_name: str, username: str) -> str | None:
        """The stored secret, or `None`."""
        ...

    def set_password(self, service_name: str, username: str, password: str) -> None:
        """Store a secret."""
        ...

    def delete_password(self, service_name: str, username: str) -> None:
        """Remove a stored secret."""
        ...


@dataclass(frozen=True, slots=True)
class StoredSession:
    """One device login as the keyring holds it. The tokens stay out of its repr."""

    issuer: str
    client_id: str
    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    expires_at: float
    refresh_expires_at: float
    scope: str = ""

    def to_json(self, *, include_access_token: bool = True) -> str:
        """The keyring form, optionally without the access token."""
        return json.dumps(
            {
                "issuer": self.issuer,
                "client_id": self.client_id,
                "access_token": self.access_token if include_access_token else "",
                "refresh_token": self.refresh_token,
                "expires_at": self.expires_at,
                "refresh_expires_at": self.refresh_expires_at,
                "scope": self.scope,
            }
        )

    @classmethod
    def from_json(cls, text: str) -> StoredSession | None:
        """Read the keyring form, or `None` when it is unreadable."""
        try:
            data = json.loads(text)
            return cls(
                issuer=str(data["issuer"]),
                client_id=str(data["client_id"]),
                access_token=str(data["access_token"]),
                refresh_token=str(data["refresh_token"]),
                expires_at=float(data["expires_at"]),
                refresh_expires_at=float(data["refresh_expires_at"]),
                scope=str(data.get("scope", "")),
            )
        except (ValueError, KeyError, TypeError):
            return None


def _check_issuer(issuer: str) -> str:
    """The issuer without a trailing slash, refusing anything tokens should not travel to in the clear."""
    cleaned = issuer.strip().rstrip("/")
    parts = urlsplit(cleaned)
    local = (parts.hostname or "") in _LOCAL_HOSTS
    if parts.scheme != "https" and not (parts.scheme == "http" and local):
        raise DeviceLoginError("the issuer must be an https URL")
    if not parts.hostname or parts.username or parts.query or parts.fragment:
        raise DeviceLoginError("the issuer must be a plain URL with no credentials, query or fragment")
    return cleaned


def _default_keyring() -> KeyringBackend:
    """The `keyring` module, or a `DeviceLoginError` naming the extra to install or the backend refused.

    A backend that writes secrets to disk in plaintext, or one that fails every call, is
    refused by name rather than used, so tokens never land somewhere unprotected.
    """
    try:
        import keyring
    except ImportError as exc:
        raise DeviceLoginError("device login needs keyring; install webbpulse[device-login]") from exc
    backend = keyring.get_keyring()
    name = f"{type(backend).__module__}.{type(backend).__qualname__}"
    if name in _REFUSED_KEYRINGS:
        raise DeviceLoginError(
            f"the keyring backend {name} is not safe for tokens; configure a system keyring "
            "(macOS Keychain, Windows Credential Manager, or Secret Service on Linux)"
        )
    return keyring


def _default_lock_dir() -> Path:
    """Where refresh lock files live: the user cache directory, never anywhere shared."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "webbpulse" / "locks"
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "webbpulse" / "locks"


@contextlib.contextmanager
def _file_lock(path: Path) -> Iterator[None]:
    """Hold an exclusive lock on `path` for the block, across processes."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("a+b") as handle:
        if sys.platform == "win32":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@dataclass(frozen=True, slots=True)
class LogoutResult:
    """What `logout` did. Truthy when there was a session to end.

    `revoked` is whether the server confirmed the revocation. When it is false the local
    copy is still gone, but the server session may live until it expires.
    """

    had_session: bool
    revoked: bool = False

    def __bool__(self) -> bool:
        """Whether there was a session."""
        return self.had_session


class DeviceLoginClient:
    """Run a device login against one issuer for one client id, and keep its session fresh.

    `headers` are sent on every request, which is where a staging access gate header goes.
    `http`, `keyring_backend`, `clock` and `sleep` are seams for tests.
    """

    def __init__(
        self,
        issuer: str,
        client_id: str,
        *,
        http: httpx.Client | None = None,
        headers: Mapping[str, str] | None = None,
        keyring_backend: KeyringBackend | None = None,
        service: str = DEFAULT_KEYRING_SERVICE,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        out: IO[str] | None = None,
        lock_dir: Path | None = None,
    ) -> None:
        """Bind the client to an issuer, a client id and its seams. Makes no request."""
        if not client_id.strip():
            raise DeviceLoginError("a client id is required")
        self._issuer = _check_issuer(issuer)
        self._client_id = client_id
        self._http = http
        self._headers = {key: value for key, value in (headers or {}).items() if value}
        self._keyring = keyring_backend
        self._service = service
        self._clock = clock
        self._sleep = sleep
        self._out = out
        self._lock_dir = lock_dir

    @property
    def issuer(self) -> str:
        """The issuer this client signs in to."""
        return self._issuer

    @property
    def _username(self) -> str:
        """The keyring entry name for this issuer and client."""
        return f"{self._issuer}|{self._client_id}"

    def _backend(self) -> KeyringBackend:
        """The keyring, resolved on first use."""
        if self._keyring is None:
            self._keyring = _default_keyring()
        return self._keyring

    def stored(self) -> StoredSession | None:
        """The saved session for this issuer and client, or `None`."""
        try:
            text = self._backend().get_password(self._service, self._username)
        except DeviceLoginError:
            raise
        except Exception as exc:
            raise DeviceLoginError(f"could not read the keyring: {type(exc).__name__}") from None
        return StoredSession.from_json(text) if text else None

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        """Hold this issuer and client's refresh lock, so concurrent commands take turns."""
        name = hashlib.sha256(self._username.encode("utf-8")).hexdigest()[:32]
        with _file_lock((self._lock_dir or _default_lock_dir()) / f"{name}.lock"):
            yield

    def _save(self, session: StoredSession) -> None:
        """Write the session to the keyring, leaving the access token out when it would not fit."""
        text = session.to_json()
        if len(text) > KEYRING_ENTRY_BUDGET:
            text = session.to_json(include_access_token=False)
        if len(text) > KEYRING_ENTRY_BUDGET:
            raise DeviceLoginError("the device login is too large for the keyring")
        try:
            self._backend().set_password(self._service, self._username, text)
        except Exception as exc:
            raise DeviceLoginError(f"could not write the keyring: {type(exc).__name__}") from None

    def _forget(self) -> None:
        """Remove the session from the keyring, quietly when there is none."""
        try:
            self._backend().delete_password(self._service, self._username)
        except Exception:
            return

    def _post(self, path: str, form: Mapping[str, str]) -> tuple[int, dict[str, Any]]:
        """POST a form to the issuer, answering the status and the JSON body.

        Transport failures become a `DeviceLoginError` naming only the failure's type, so
        nothing from the request, which may hold a token, reaches the message.
        """
        import httpx

        client = self._http or httpx.Client(timeout=30.0)
        try:
            response = client.post(f"{self._issuer}{path}", data=dict(form), headers=self._headers)
        except httpx.HTTPError as exc:
            raise DeviceLoginError(f"could not reach {self._issuer}: {type(exc).__name__}") from None
        finally:
            if self._http is None:
                client.close()
        try:
            body = response.json()
        except ValueError:
            body = {}
        return response.status_code, body if isinstance(body, dict) else {}

    def _print(self, message: str) -> None:
        """Write a progress line to the output stream, stderr by default."""
        print(message, file=self._out if self._out is not None else sys.stderr, flush=True)

    def login(self, scopes: Iterable[str] = ()) -> StoredSession:
        """Run the device flow: print the URL and code, poll until approved, store the session."""
        status, started = self._post(
            "/device/code", {"client_id": self._client_id, "scope": " ".join(dict.fromkeys(scopes))}
        )
        if status != 200 or not started.get("device_code"):
            raise DeviceLoginError(_describe("could not start a device login", started, status))
        device_code = str(started["device_code"])
        interval = max(int(started.get("interval") or 5), 1)
        deadline = self._clock() + int(started.get("expires_in") or 600)
        uri = str(started.get("verification_uri") or "")
        complete = str(started.get("verification_uri_complete") or "")
        self._print(f"Open {complete or uri} in a browser and confirm the code {started.get('user_code', '')}.")
        if complete and uri:
            self._print(f"Or go to {uri} and enter the code yourself.")
        self._print("Waiting for approval...")
        while True:
            self._sleep(interval)
            if self._clock() >= deadline:
                raise DeviceLoginError("the device code expired before it was approved; run login again")
            status, body = self._post(
                "/device/token",
                {"grant_type": DEVICE_CODE_GRANT_TYPE, "device_code": device_code, "client_id": self._client_id},
            )
            if status == 200 and body.get("access_token"):
                session = self._session_from(body)
                self._save(session)
                return session
            error = str(body.get("error", ""))
            if error == "authorization_pending":
                continue
            if error == "slow_down":
                interval += SLOW_DOWN_STEP
                continue
            if error == "access_denied":
                raise DeviceLoginError("the login was denied in the browser")
            if error == "expired_token":
                raise DeviceLoginError("the device code expired before it was approved; run login again")
            raise DeviceLoginError(_describe("the device login failed", body, status))

    def access_token(self) -> str:
        """A current access token, refreshing and re-storing the session when it is about to expire.

        Raises `DeviceLoginError` when there is no session, or it has ended and needs a new login.
        """
        session = self.stored()
        if session is None:
            raise DeviceLoginError("not signed in; run login first")
        if session.access_token and session.expires_at - REFRESH_MARGIN_SECONDS > self._clock():
            return session.access_token
        with self._locked():
            return self._refresh_locked()

    def _refresh_locked(self) -> str:
        """Re-read the session under the lock and refresh it unless another command just did."""
        session = self.stored()
        if session is None:
            raise DeviceLoginError("not signed in; run login first")
        now = self._clock()
        if session.access_token and session.expires_at - REFRESH_MARGIN_SECONDS > now:
            return session.access_token
        if session.refresh_expires_at <= now:
            self._forget()
            raise DeviceLoginError("the device login has ended; run login again")
        status, body = self._post(
            "/device/token",
            {"grant_type": "refresh_token", "refresh_token": session.refresh_token, "client_id": self._client_id},
        )
        if status != 200 or not body.get("access_token"):
            if body.get("error") == "invalid_grant":
                self._forget()
                raise DeviceLoginError("the device login was revoked or has ended; run login again")
            raise DeviceLoginError(_describe("could not refresh the device login", body, status))
        refreshed = self._session_from(body)
        self._save(refreshed)
        return refreshed.access_token

    def logout(self) -> LogoutResult:
        """Revoke the session on the server and forget it locally, whatever the server says.

        When the revocation is not confirmed, by a non-200 answer or a network failure, the
        local copy still goes and a warning says the server session may still be live.
        """
        with self._locked():
            session = self.stored()
            if session is None:
                return LogoutResult(had_session=False)
            revoked = False
            try:
                status, _ = self._post("/device/revoke", {"token": session.refresh_token, "client_id": self._client_id})
                revoked = status == 200
            except DeviceLoginError:
                revoked = False
            finally:
                self._forget()
        if not revoked:
            self._print(
                "Warning: the server did not confirm the sign-out. The local session is removed, but "
                "the server session may stay live until it expires; revoke it from your account's "
                "device logins to be sure."
            )
        return LogoutResult(had_session=True, revoked=revoked)

    def _session_from(self, body: Mapping[str, Any]) -> StoredSession:
        """A session from a token response."""
        now = self._clock()
        return StoredSession(
            issuer=self._issuer,
            client_id=self._client_id,
            access_token=str(body["access_token"]),
            refresh_token=str(body.get("refresh_token", "")),
            expires_at=now + int(body.get("expires_in") or 0),
            refresh_expires_at=now + int(body.get("refresh_token_expires_in") or body.get("expires_in") or 0),
            scope=str(body.get("scope", "")),
        )


def _describe(prefix: str, body: Mapping[str, Any], status: int) -> str:
    """A readable failure from an OAuth error body: its code and description, never anything else."""
    error = str(body.get("error", "") or "")
    description = str(body.get("error_description", "") or "")
    detail = ": ".join(part for part in (error, description) if part)
    return f"{prefix} ({status}{f', {detail}' if detail else ''})"
