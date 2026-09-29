"""Tests for `webbpulse.device_login`: the CLI side of the device grant, over a scripted issuer."""

from __future__ import annotations

import io
import json
import logging
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest

from webbpulse.device_login import (
    DEFAULT_KEYRING_SERVICE,
    DEVICE_CODE_GRANT_TYPE,
    DeviceLoginClient,
    DeviceLoginError,
    StoredSession,
)

ISSUER = "https://api.example.test/api/auth"
CLIENT = "wp-tf"
ACCESS = "eyJ-access-token-under-test"
REFRESH = "wpdr_grant.refresh-secret-under-test"
ROTATED_ACCESS = "eyJ-rotated-access-token"
ROTATED_REFRESH = "wpdr_grant.rotated-refresh-secret"
DEVICE_CODE = "device-code-under-test"
USER_CODE = "BCDF-GHJK"
GATE = "gate-value-under-test"
SECRETS = (ACCESS, REFRESH, ROTATED_ACCESS, ROTATED_REFRESH, DEVICE_CODE, GATE)


class FakeKeyring:
    """An in-memory stand-in for the `keyring` module."""

    def __init__(self) -> None:
        """Start empty."""
        self.items: dict[tuple[str, str], str] = {}

    def get_password(self, service_name: str, username: str) -> str | None:
        """The stored value, or None."""
        return self.items.get((service_name, username))

    def set_password(self, service_name: str, username: str, password: str) -> None:
        """Store a value."""
        self.items[(service_name, username)] = password

    def delete_password(self, service_name: str, username: str) -> None:
        """Remove a value, raising like keyring does when there is none."""
        if (service_name, username) not in self.items:
            raise KeyError(username)
        del self.items[(service_name, username)]


class Clock:
    """A clock the fake sleep advances."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        """Start at a fixed moment."""
        self.now = start
        self.sleeps: list[float] = []

    def time(self) -> float:
        """The current moment."""
        return self.now

    def sleep(self, seconds: float) -> None:
        """Advance the clock instead of waiting."""
        self.sleeps.append(seconds)
        self.now += seconds


class Issuer:
    """A scripted device grant issuer."""

    def __init__(self, polls: list[dict[str, Any]] | None = None) -> None:
        """Answer the given poll errors in order, then the token pair."""
        self.polls = list(polls or [])
        self.requests: list[httpx.Request] = []
        self.forms: list[dict[str, str]] = []
        self.refresh_answer: tuple[int, dict[str, Any]] = (
            200,
            {
                "access_token": ROTATED_ACCESS,
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": ROTATED_REFRESH,
                "refresh_token_expires_in": 40000,
                "scope": "runs:read",
            },
        )

    def handler(self, request: httpx.Request) -> httpx.Response:
        """Answer one request."""
        self.requests.append(request)
        form = {key: values[0] for key, values in parse_qs(request.content.decode()).items()}
        self.forms.append(form)
        path = request.url.path
        if path == "/api/auth/device/code":
            return httpx.Response(
                200,
                json={
                    "device_code": DEVICE_CODE,
                    "user_code": USER_CODE,
                    "verification_uri": f"{ISSUER}/device",
                    "verification_uri_complete": f"{ISSUER}/device?user_code={USER_CODE}",
                    "expires_in": 600,
                    "interval": 5,
                },
            )
        if path == "/api/auth/device/token" and form.get("grant_type") == DEVICE_CODE_GRANT_TYPE:
            if self.polls:
                return httpx.Response(400, json=self.polls.pop(0))
            return httpx.Response(
                200,
                json={
                    "access_token": ACCESS,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": REFRESH,
                    "refresh_token_expires_in": 43200,
                    "scope": "runs:read runs:plan",
                },
            )
        if path == "/api/auth/device/token" and form.get("grant_type") == "refresh_token":
            status, body = self.refresh_answer
            return httpx.Response(status, json=body)
        if path == "/api/auth/device/revoke":
            return httpx.Response(200)
        return httpx.Response(404, json={"error": "not_found"})


def build(
    issuer: Issuer, *, keyring: FakeKeyring | None = None, clock: Clock | None = None, **kwargs: Any
) -> tuple[DeviceLoginClient, FakeKeyring, Clock, io.StringIO]:
    """A client wired to the scripted issuer, a fake keyring and a fake clock."""
    ring = keyring or FakeKeyring()
    moment = clock or Clock()
    out = io.StringIO()
    client = DeviceLoginClient(
        ISSUER,
        CLIENT,
        http=httpx.Client(transport=httpx.MockTransport(issuer.handler)),
        keyring_backend=ring,
        clock=moment.time,
        sleep=moment.sleep,
        out=out,
        **kwargs,
    )
    return client, ring, moment, out


def _assert_no_secret(*texts: str) -> None:
    """None of the secrets under test appear in any of the texts."""
    for text in texts:
        for secret in SECRETS:
            assert secret not in text


class TestLogin:
    """`login`: print, poll, store."""

    def test_login_prints_the_code_polls_and_stores_the_session(self, capsys: pytest.CaptureFixture[str]) -> None:
        """The URL and code are printed, the session lands in the keyring, and no token is printed."""
        issuer = Issuer([{"error": "authorization_pending"}, {"error": "authorization_pending"}])
        client, ring, clock, out = build(issuer)
        session = client.login(["runs:read", "runs:plan"])
        assert session.scope == "runs:read runs:plan"
        assert USER_CODE in out.getvalue()
        assert f"{ISSUER}/device?user_code={USER_CODE}" in out.getvalue()
        assert clock.sleeps == [5, 5, 5]
        stored = json.loads(ring.items[(DEFAULT_KEYRING_SERVICE, f"{ISSUER}|{CLIENT}")])
        assert stored["access_token"] == ACCESS
        assert stored["refresh_token"] == REFRESH
        assert stored["expires_at"] == clock.now + 3600
        assert issuer.forms[0] == {"client_id": CLIENT, "scope": "runs:read runs:plan"}
        captured = capsys.readouterr()
        _assert_no_secret(out.getvalue(), captured.out, captured.err, repr(session), str(session))

    def test_slow_down_lengthens_the_interval(self) -> None:
        """Each `slow_down` adds five seconds to every later wait."""
        issuer = Issuer([{"error": "slow_down"}, {"error": "authorization_pending"}])
        client, _, clock, _ = build(issuer)
        client.login()
        assert clock.sleeps == [5, 10, 10]

    def test_a_denial_raises_and_stores_nothing(self) -> None:
        """Declining in the browser ends the login with a plain message."""
        client, ring, _, _ = build(Issuer([{"error": "access_denied"}]))
        with pytest.raises(DeviceLoginError, match="denied"):
            client.login()
        assert ring.items == {}

    def test_an_expired_code_raises(self) -> None:
        """The server's `expired_token` ends the login."""
        client, ring, _, _ = build(Issuer([{"error": "expired_token"}]))
        with pytest.raises(DeviceLoginError, match="expired"):
            client.login()
        assert ring.items == {}

    def test_the_client_gives_up_at_the_code_lifetime(self) -> None:
        """A code nobody approves stops polling when it would have expired."""
        client, _, clock, _ = build(Issuer([{"error": "authorization_pending"}] * 500))
        with pytest.raises(DeviceLoginError, match="expired"):
            client.login()
        assert clock.now - 1_000_000.0 <= 610

    def test_a_refused_start_names_the_error_only(self) -> None:
        """A failed start reports the OAuth error code and description, nothing else."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"error": "invalid_client", "error_description": "nope", "extra": GATE})

        client = DeviceLoginClient(
            ISSUER, CLIENT, http=httpx.Client(transport=httpx.MockTransport(handler)), keyring_backend=FakeKeyring()
        )
        with pytest.raises(DeviceLoginError) as caught:
            client.login()
        assert str(caught.value) == "could not start a device login (401, invalid_client: nope)"

    def test_the_gate_header_is_sent_on_every_request(self) -> None:
        """A staging gate value rides on each call, and is never printed."""
        issuer = Issuer()
        client, _, _, out = build(issuer, headers={"X-Origin-Verify": GATE})
        client.login()
        assert all(request.headers["x-origin-verify"] == GATE for request in issuer.requests)
        _assert_no_secret(out.getvalue())


class TestAccessToken:
    """`access_token`: the stored token, refreshed when it is about to expire."""

    def _signed_in(self, issuer: Issuer) -> tuple[DeviceLoginClient, FakeKeyring, Clock]:
        """A client that has completed a login."""
        client, ring, clock, _ = build(issuer)
        client.login()
        return client, ring, clock

    def test_a_fresh_token_is_returned_without_a_request(self) -> None:
        """Nothing is sent while the access token has more than a minute left."""
        issuer = Issuer()
        client, _, _ = self._signed_in(issuer)
        sent = len(issuer.requests)
        assert client.access_token() == ACCESS
        assert len(issuer.requests) == sent

    def test_an_expiring_token_is_refreshed_and_the_rotation_stored(self) -> None:
        """Inside the last minute the session rotates, and the new pair replaces the old."""
        issuer = Issuer()
        client, _ring, clock = self._signed_in(issuer)
        clock.now += 3600 - 30
        assert client.access_token() == ROTATED_ACCESS
        assert issuer.forms[-1] == {"grant_type": "refresh_token", "refresh_token": REFRESH, "client_id": CLIENT}
        stored = client.stored()
        assert stored is not None
        assert stored.refresh_token == ROTATED_REFRESH
        assert client.access_token() == ROTATED_ACCESS

    def test_a_revoked_session_is_forgotten(self) -> None:
        """`invalid_grant` on refresh clears the keyring and asks for a new login."""
        issuer = Issuer()
        client, ring, clock = self._signed_in(issuer)
        issuer.refresh_answer = (400, {"error": "invalid_grant", "error_description": "revoked"})
        clock.now += 3600
        with pytest.raises(DeviceLoginError, match="login again") as caught:
            client.access_token()
        assert ring.items == {}
        _assert_no_secret(str(caught.value))

    def test_a_session_past_its_cap_is_forgotten_without_a_request(self) -> None:
        """Once the refresh token's life is over there is nothing to try."""
        issuer = Issuer()
        client, ring, clock = self._signed_in(issuer)
        sent = len(issuer.requests)
        clock.now += 43200
        with pytest.raises(DeviceLoginError, match="ended"):
            client.access_token()
        assert len(issuer.requests) == sent
        assert ring.items == {}

    def test_a_server_error_keeps_the_session(self) -> None:
        """A transient failure is reported but does not throw the session away."""
        issuer = Issuer()
        client, ring, clock = self._signed_in(issuer)
        issuer.refresh_answer = (503, {})
        clock.now += 3600
        with pytest.raises(DeviceLoginError, match="503"):
            client.access_token()
        assert ring.items

    def test_no_session_raises(self) -> None:
        """Asking for a token before logging in says to log in."""
        client, _, _, _ = build(Issuer())
        with pytest.raises(DeviceLoginError, match="not signed in"):
            client.access_token()


class TestLogout:
    """`logout`: revoke on the server, forget locally."""

    def test_logout_revokes_and_forgets(self) -> None:
        """The refresh token is posted to `/device/revoke` and the keyring entry removed."""
        issuer = Issuer()
        client, ring, _, _ = build(issuer)
        client.login()
        assert client.logout() is True
        assert issuer.requests[-1].url.path == "/api/auth/device/revoke"
        assert issuer.forms[-1] == {"token": REFRESH, "client_id": CLIENT}
        assert ring.items == {}

    def test_logout_without_a_session_is_false(self) -> None:
        """Nothing to sign out of."""
        client, _, _, _ = build(Issuer())
        assert client.logout() is False

    def test_logout_forgets_even_when_the_server_is_down(self) -> None:
        """A failed revoke still clears the local session."""
        ring = FakeKeyring()
        client, _, _, _ = build(Issuer(), keyring=ring)
        client.login()

        def down(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError(f"refused {REFRESH}")

        offline = DeviceLoginClient(
            ISSUER, CLIENT, http=httpx.Client(transport=httpx.MockTransport(down)), keyring_backend=ring
        )
        with pytest.raises(DeviceLoginError) as caught:
            offline.logout()
        assert ring.items == {}
        _assert_no_secret(str(caught.value))


class TestSecrecy:
    """Tokens never reach an exception message, a repr, a log or the output."""

    def test_a_transport_error_names_only_its_type(self, caplog: pytest.LogCaptureFixture) -> None:
        """An httpx error whose text carries the token becomes a message without it."""
        caplog.set_level(logging.DEBUG)
        ring = FakeKeyring()
        client, _, clock, _ = build(Issuer(), keyring=ring)
        client.login()
        clock.now += 3600

        def leaky(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout(f"timed out sending {request.content.decode()}")

        offline = DeviceLoginClient(
            ISSUER,
            CLIENT,
            http=httpx.Client(transport=httpx.MockTransport(leaky)),
            keyring_backend=ring,
            clock=clock.time,
        )
        with pytest.raises(DeviceLoginError) as caught:
            offline.access_token()
        assert "ReadTimeout" in str(caught.value)
        assert caught.value.__cause__ is None
        assert caught.value.__suppress_context__
        _assert_no_secret(str(caught.value), repr(caught.value), caplog.text)

    def test_a_keyring_failure_names_only_its_type(self) -> None:
        """A keyring backend error does not echo what was being written."""

        class Broken(FakeKeyring):
            def set_password(self, service_name: str, username: str, password: str) -> None:
                raise RuntimeError(f"cannot store {password}")

        client, _, _, _ = build(Issuer(), keyring=Broken())
        with pytest.raises(DeviceLoginError) as caught:
            client.login()
        assert str(caught.value) == "could not write the keyring: RuntimeError"
        _assert_no_secret(str(caught.value))

    def test_the_session_repr_hides_the_tokens(self) -> None:
        """A stored session printed by accident shows no token."""
        session = StoredSession(ISSUER, CLIENT, ACCESS, REFRESH, 1.0, 2.0, "runs:read")
        _assert_no_secret(repr(session), str(session))
        assert StoredSession.from_json(session.to_json()) == session

    @pytest.mark.parametrize("text", ["", "not json", "{}", '{"issuer": "x"}', "[]"])
    def test_an_unreadable_session_is_none(self, text: str) -> None:
        """Garbage in the keyring reads as no session."""
        assert StoredSession.from_json(text) is None


class TestIssuer:
    """Where tokens may be sent."""

    @pytest.mark.parametrize(
        "issuer",
        [
            "http://api.example.test/api/auth",
            "ftp://api.example.test",
            "https://user:pw@api.example.test/api/auth",
            "https://api.example.test/api/auth?x=1",
            "https:///api/auth",
        ],
    )
    def test_an_unsafe_issuer_is_refused(self, issuer: str) -> None:
        """Only plain https URLs, or http on this machine."""
        with pytest.raises(DeviceLoginError):
            DeviceLoginClient(issuer, CLIENT, keyring_backend=FakeKeyring())

    @pytest.mark.parametrize("issuer", ["http://localhost:8000/api/auth", "http://127.0.0.1:8000/api/auth/"])
    def test_a_local_issuer_may_be_plain_http(self, issuer: str) -> None:
        """Local development servers are allowed, with the trailing slash trimmed."""
        assert not DeviceLoginClient(issuer, CLIENT, keyring_backend=FakeKeyring()).issuer.endswith("/")

    def test_a_client_id_is_required(self) -> None:
        """An empty client id is refused before any request."""
        with pytest.raises(DeviceLoginError):
            DeviceLoginClient(ISSUER, " ", keyring_backend=FakeKeyring())

    def test_sessions_are_kept_per_issuer(self) -> None:
        """Staging and production logins do not overwrite each other."""
        ring = FakeKeyring()
        build(Issuer(), keyring=ring)[0].login()
        other = DeviceLoginClient("https://api.other.test/api/auth", CLIENT, keyring_backend=ring)
        assert other.stored() is None


def test_the_default_keyring_is_the_keyring_module(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without a backend passed in, the client uses the `keyring` package, here its null backend."""
    client = DeviceLoginClient(ISSUER, CLIENT)
    assert client.stored() is None


def test_a_missing_keyring_package_names_the_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without keyring installed the error says which extra to install."""
    import builtins

    real_import: Callable[..., Any] = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "keyring":
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(DeviceLoginError, match=r"webbpulse\[device-login\]"):
        DeviceLoginClient(ISSUER, CLIENT).stored()
