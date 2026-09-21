"""Tests for the access token an `IdentitySession` keeps current.

The identity access token's TTL is ten minutes and a full suite runs well past it. A session
that carried the login token for the whole run had every later call from that worker refused
by the authorizer, and those refusals read exactly like product bugs, including in the
fixtures that create the resources a case then asserts on. What is under test here is that
the session notices before the gateway does, that it also recovers from a refusal it did not
predict, and that it never retries a refusal a fresh token would not fix.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from webbpulse.e2e.client import E2EClient, is_expired_credential
from webbpulse.e2e.identity import (
    DEFAULT_ACCESS_TOKEN_TTL,
    DEFAULT_REFRESH_PATH,
    DEFAULT_REFRESH_SKEW,
    IdentitySession,
    RefreshFailed,
    decode_claims,
    login,
    token_expiry,
)

SUBJECT = "2f6c1a7e-6b5f-4a1f-9a8e-0d2b3c4d5e6f"
PROTECTED = "/api/things"


def segment(payload: dict[str, Any]) -> str:
    """One base64url JWT segment with its padding stripped, the way a real token carries it."""
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")


def access_token(*, expires_at: float | None, marker: str = "a") -> str:
    """An unsigned RS256-shaped token, carrying `exp` only when one is given.

    `marker` distinguishes one token from the next so a test can assert which credential a
    request carried rather than only that it carried something.
    """
    claims: dict[str, Any] = {"sub": SUBJECT, "iss": "https://issuer.invalid", "aud": "api", "marker": marker}
    if expires_at is not None:
        claims["exp"] = expires_at
    return f"{segment({'alg': 'RS256', 'typ': 'JWT'})}.{segment(claims)}.signature"


class Clock:
    """A wall clock a test drives by hand."""

    def __init__(self, now: float = 1_000_000.0) -> None:
        """Start at `now`."""
        self.now = now

    def __call__(self) -> float:
        """The current time."""
        return self.now

    def advance(self, seconds: float) -> None:
        """Move the clock forward."""
        self.now += seconds


class Recorder:
    """A MockTransport handler that scripts answers and records what each request carried."""

    def __init__(self, handler: Callable[[httpx.Request, int], httpx.Response]) -> None:
        """Answer each request through `handler`, which is given the request and its index."""
        self._handler = handler
        self.requests: list[httpx.Request] = []
        self.tokens: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        """Record one request and return the scripted answer."""
        index = len(self.requests)
        self.requests.append(request)
        self.tokens.append(request.headers.get("authorization", "").removeprefix("Bearer "))
        return self._handler(request, index)

    @property
    def paths(self) -> list[str]:
        """The path of every request, oldest first."""
        return [request.url.path for request in self.requests]

    @property
    def refreshes(self) -> int:
        """How many calls reached the refresh route."""
        return self.paths.count(DEFAULT_REFRESH_PATH)


def client_for(recorder: Recorder) -> E2EClient:
    """An unpaced `E2EClient` over a MockTransport driven by `recorder`."""
    return E2EClient(
        base_url="https://api.example.invalid",
        transport=httpx.MockTransport(recorder),
        per_minute=0,
    )


def refresh_body(marker: str, *, expires_at: float | None, rotated: str = "") -> dict[str, Any]:
    """The body the identity refresh route answers with, rotating the refresh token."""
    body: dict[str, Any] = {"access_token": access_token(expires_at=expires_at, marker=marker)}
    if rotated:
        body["refresh_token"] = rotated
    return body


def session_for(
    recorder: Recorder,
    clock: Clock,
    *,
    expires_at: float | None,
    refresh_token: str = "refresh-1",
    access_token_ttl: float = DEFAULT_ACCESS_TOKEN_TTL,
) -> IdentitySession:
    """A signed-in session over `recorder`, holding a token that expires at `expires_at`."""
    token = access_token(expires_at=expires_at)
    header, claims = decode_claims(token)
    return IdentitySession(
        client=client_for(recorder).with_token(token),
        access_token=token,
        claims=claims,
        header=header,
        refresh_token=refresh_token,
        refresh_cookies={},
        user_id=SUBJECT,
        access_token_ttl=access_token_ttl,
        issued_at=clock(),
        clock=clock,
    )


class TestTokenExpiry:
    """Tests for reading the expiry out of a token without verifying it."""

    def test_exp_is_read(self) -> None:
        """A token declaring `exp` reports it."""
        assert token_expiry(access_token(expires_at=1_234.0)) == 1_234.0

    def test_missing_exp_is_none(self) -> None:
        """A token carrying no `exp` reports none rather than a guess."""
        assert token_expiry(access_token(expires_at=None)) is None

    def test_unreadable_token_is_none(self) -> None:
        """Something that is not a JWT reports none rather than raising."""
        assert token_expiry("not-a-jwt") is None

    def test_non_numeric_exp_is_none(self) -> None:
        """An `exp` that is not a number is no expiry at all."""
        token = f"{segment({'alg': 'RS256'})}.{segment({'exp': 'soon'})}.signature"
        assert token_expiry(token) is None

    def test_ttl_is_the_fallback_when_there_is_no_exp(self) -> None:
        """A token with no readable `exp` expires a TTL after it was issued."""
        clock = Clock()
        session = session_for(Recorder(lambda request, index: httpx.Response(200)), clock, expires_at=None)
        assert session.expires_at == clock() + DEFAULT_ACCESS_TOKEN_TTL


class TestProactiveRefresh:
    """Tests for replacing a token before the gateway refuses it."""

    def test_a_fresh_token_is_sent_as_is(self) -> None:
        """A token nowhere near its expiry is used without a refresh call."""
        clock = Clock()
        recorder = Recorder(lambda request, index: httpx.Response(200, json={"ok": True}))
        session = session_for(recorder, clock, expires_at=clock() + 600)

        assert session.client.get(PROTECTED).status_code == 200
        assert recorder.paths == [PROTECTED]
        assert session.refreshes == 0

    def test_a_token_inside_the_skew_window_is_refreshed_first(self) -> None:
        """A token within the skew of its expiry is replaced before the request is sent."""
        clock = Clock()
        expires_at = clock() + 600
        recorder = Recorder(
            lambda request, index: (
                httpx.Response(200, json=refresh_body("b", expires_at=clock() + 600))
                if request.url.path == DEFAULT_REFRESH_PATH
                else httpx.Response(200, json={"ok": True})
            )
        )
        session = session_for(recorder, clock, expires_at=expires_at)
        clock.advance(600 - DEFAULT_REFRESH_SKEW + 1)

        assert session.client.get(PROTECTED).status_code == 200
        assert recorder.paths == [DEFAULT_REFRESH_PATH, PROTECTED]
        assert recorder.tokens[-1] == session.access_token
        assert session.refreshes == 1

    def test_an_expired_token_is_refreshed_first(self) -> None:
        """A token already past its expiry is replaced rather than sent and refused."""
        clock = Clock()
        recorder = Recorder(
            lambda request, index: (
                httpx.Response(200, json=refresh_body("b", expires_at=clock() + 600))
                if request.url.path == DEFAULT_REFRESH_PATH
                else httpx.Response(200, json={"ok": True})
            )
        )
        session = session_for(recorder, clock, expires_at=clock() + 10)
        clock.advance(120)

        session.client.get(PROTECTED)
        assert recorder.refreshes == 1

    def test_the_ttl_fallback_drives_the_refresh_without_an_exp(self) -> None:
        """A token with no `exp` is refreshed a TTL minus the skew after it was issued."""
        clock = Clock()
        recorder = Recorder(
            lambda request, index: (
                httpx.Response(200, json=refresh_body("b", expires_at=None))
                if request.url.path == DEFAULT_REFRESH_PATH
                else httpx.Response(200, json={"ok": True})
            )
        )
        session = session_for(recorder, clock, expires_at=None, access_token_ttl=300.0)

        session.client.get(PROTECTED)
        assert recorder.refreshes == 0

        clock.advance(300 - DEFAULT_REFRESH_SKEW + 1)
        session.client.get(PROTECTED)
        assert recorder.refreshes == 1


class TestRefreshOnRefusal:
    """Tests for recovering from a refusal the expiry check did not predict."""

    def test_a_401_is_refreshed_and_retried(self) -> None:
        """A 401 on a token believed fresh refreshes once and retries, and the retry answers."""
        clock = Clock()

        def handle(request: httpx.Request, index: int) -> httpx.Response:
            """Refuse the first call, hand out a new token, then answer."""
            if request.url.path == DEFAULT_REFRESH_PATH:
                return httpx.Response(200, json=refresh_body("b", expires_at=clock() + 600))
            if index == 0:
                return httpx.Response(401, json={"message": "Unauthorized"})
            return httpx.Response(200, json={"ok": True})

        recorder = Recorder(handle)
        session = session_for(recorder, clock, expires_at=clock() + 600)

        response = session.client.get(PROTECTED)
        assert response.status_code == 200
        assert recorder.paths == [PROTECTED, DEFAULT_REFRESH_PATH, PROTECTED]
        assert recorder.tokens[0] != recorder.tokens[-1]
        assert recorder.tokens[-1] == session.access_token

    def test_the_gateway_403_shape_is_refreshed_and_retried(self) -> None:
        """The gateway's bare `{"message": "Forbidden"}` is an expired token, so it retries."""
        clock = Clock()

        def handle(request: httpx.Request, index: int) -> httpx.Response:
            """Answer the gateway's refusal shape, then succeed once the token is fresh."""
            if request.url.path == DEFAULT_REFRESH_PATH:
                return httpx.Response(200, json=refresh_body("b", expires_at=clock() + 600))
            if index == 0:
                return httpx.Response(403, json={"message": "Forbidden"})
            return httpx.Response(200, json={"ok": True})

        recorder = Recorder(handle)
        session = session_for(recorder, clock, expires_at=clock() + 600)

        assert session.client.get(PROTECTED).status_code == 200
        assert recorder.paths == [PROTECTED, DEFAULT_REFRESH_PATH, PROTECTED]

    def test_a_product_403_is_not_retried(self) -> None:
        """A 403 carrying an `error_code` is a permission answer, so it stands as it is."""
        clock = Clock()
        envelope = {
            "success": False,
            "status": 403,
            "error_code": "FORBIDDEN",
            "message": "You do not have access to this resource.",
            "request_id": "req-abc123",
        }
        recorder = Recorder(lambda request, index: httpx.Response(403, json=envelope))
        session = session_for(recorder, clock, expires_at=clock() + 600)

        response = session.client.get(PROTECTED)
        assert response.status_code == 403
        assert recorder.paths == [PROTECTED]
        assert session.refreshes == 0

    def test_the_second_refusal_is_surfaced_as_is(self) -> None:
        """One refresh and one retry, then whatever the retry answered is the answer."""
        clock = Clock()

        def handle(request: httpx.Request, index: int) -> httpx.Response:
            """Refuse every protected call, however fresh the token is."""
            if request.url.path == DEFAULT_REFRESH_PATH:
                return httpx.Response(200, json=refresh_body("b", expires_at=clock() + 600))
            return httpx.Response(401, json={"message": "Unauthorized"})

        recorder = Recorder(handle)
        session = session_for(recorder, clock, expires_at=clock() + 600)

        response = session.client.get(PROTECTED)
        assert response.status_code == 401
        assert recorder.paths == [PROTECTED, DEFAULT_REFRESH_PATH, PROTECTED]

    def test_a_client_without_a_token_source_does_not_retry(self) -> None:
        """A `with_token` clone means that one token, so a 401 on it is the finding."""
        recorder = Recorder(lambda request, index: httpx.Response(401, json={"message": "Unauthorized"}))
        clone = client_for(recorder).with_token(access_token(expires_at=None))

        assert clone.get(PROTECTED).status_code == 401
        assert recorder.paths == [PROTECTED]


class TestIsExpiredCredential:
    """Tests for telling an expired credential from a permission refusal."""

    def test_401_always_qualifies(self) -> None:
        """A 401 is about the credential whoever answered it."""
        assert is_expired_credential(httpx.Response(401, json={"error_code": "UNAUTHORIZED"}))

    def test_the_gateway_forbidden_shape_qualifies(self) -> None:
        """The authorizer's bare message is what an expired token looks like from outside."""
        assert is_expired_credential(httpx.Response(403, json={"message": "Forbidden"}))

    def test_a_product_403_does_not_qualify(self) -> None:
        """An envelope with an `error_code` is a permission answer, not a stale token."""
        assert not is_expired_credential(httpx.Response(403, json={"error_code": "FORBIDDEN", "message": "Forbidden"}))

    def test_a_non_json_403_does_not_qualify(self) -> None:
        """A body that is not JSON is not the gateway shape."""
        assert not is_expired_credential(httpx.Response(403, text="Forbidden"))

    def test_other_statuses_do_not_qualify(self) -> None:
        """A 404 or a 500 says nothing about the credential."""
        assert not is_expired_credential(httpx.Response(404, json={"message": "Forbidden"}))


class TestRotation:
    """Tests for storing back what the rotating refresh endpoint hands out."""

    def test_the_rotated_refresh_token_is_stored(self) -> None:
        """The refresh token the endpoint rotated replaces the one the session held."""
        clock = Clock()
        recorder = Recorder(
            lambda request, index: (
                httpx.Response(200, json=refresh_body("b", expires_at=clock() + 600, rotated="refresh-2"))
                if request.url.path == DEFAULT_REFRESH_PATH
                else httpx.Response(200, json={"ok": True})
            )
        )
        session = session_for(recorder, clock, expires_at=clock() + 10)
        clock.advance(120)

        session.client.get(PROTECTED)
        assert session.refresh_token == "refresh-2"

    def test_the_rotated_token_is_what_the_next_refresh_presents(self) -> None:
        """The second refresh sends the token the first one rotated, not the spent one."""
        clock = Clock()
        rotations = iter(["refresh-2", "refresh-3"])
        presented: list[Any] = []

        def handle(request: httpx.Request, index: int) -> httpx.Response:
            """Record the refresh token each refresh presented and rotate it again."""
            if request.url.path == DEFAULT_REFRESH_PATH:
                presented.append(json.loads(request.content)["refresh_token"])
                return httpx.Response(200, json=refresh_body("b", expires_at=clock() + 600, rotated=next(rotations)))
            return httpx.Response(200, json={"ok": True})

        recorder = Recorder(handle)
        session = session_for(recorder, clock, expires_at=clock() + 10)

        clock.advance(120)
        session.client.get(PROTECTED)
        clock.advance(600)
        session.client.get(PROTECTED)

        assert presented == ["refresh-1", "refresh-2"]
        assert session.refresh_token == "refresh-3"

    def test_rotated_cookies_are_stored(self) -> None:
        """A product carrying the refresh token in a cookie has the new cookie kept."""
        clock = Clock()

        def handle(request: httpx.Request, index: int) -> httpx.Response:
            """Set a rotated refresh cookie on the refresh answer."""
            if request.url.path == DEFAULT_REFRESH_PATH:
                return httpx.Response(
                    200,
                    json=refresh_body("b", expires_at=clock() + 600),
                    headers={"set-cookie": "refresh_token=cookie-2; Path=/; HttpOnly"},
                )
            return httpx.Response(200, json={"ok": True})

        recorder = Recorder(handle)
        session = session_for(recorder, clock, expires_at=clock() + 10)
        session.refresh_cookies = {"refresh_token": "cookie-1"}
        clock.advance(120)

        session.client.get(PROTECTED)
        assert session.refresh_cookies["refresh_token"] == "cookie-2"

    def test_the_claims_track_the_new_token(self) -> None:
        """The session's decoded claims and header describe the token it now carries."""
        clock = Clock()
        recorder = Recorder(
            lambda request, index: (
                httpx.Response(200, json=refresh_body("b", expires_at=clock() + 600))
                if request.url.path == DEFAULT_REFRESH_PATH
                else httpx.Response(200, json={"ok": True})
            )
        )
        session = session_for(recorder, clock, expires_at=clock() + 10)
        clock.advance(120)

        session.client.get(PROTECTED)
        assert session.claims["marker"] == "b"
        assert session.algorithm == "RS256"

    def test_the_refresh_call_carries_no_bearer_token(self) -> None:
        """The refresh token is the whole authorisation, so no access token is attached."""
        clock = Clock()
        recorder = Recorder(
            lambda request, index: (
                httpx.Response(200, json=refresh_body("b", expires_at=clock() + 600))
                if request.url.path == DEFAULT_REFRESH_PATH
                else httpx.Response(200, json={"ok": True})
            )
        )
        session = session_for(recorder, clock, expires_at=clock() + 10)
        clock.advance(120)

        session.client.get(PROTECTED)
        assert recorder.tokens[recorder.paths.index(DEFAULT_REFRESH_PATH)] == ""


class TestRefreshFailure:
    """Tests for the error a dead refresh family raises."""

    def test_a_401_from_refresh_names_the_session(self) -> None:
        """A revoked or expired family raises a clear error naming the user, not a 401."""
        clock = Clock()
        recorder = Recorder(
            lambda request, index: (
                httpx.Response(401, json={"error_code": "NO_SESSION"})
                if request.url.path == DEFAULT_REFRESH_PATH
                else httpx.Response(200, json={"ok": True})
            )
        )
        session = session_for(recorder, clock, expires_at=clock() + 10)
        clock.advance(120)

        with pytest.raises(RefreshFailed) as raised:
            session.client.get(PROTECTED)
        message = str(raised.value)
        assert SUBJECT in message
        assert DEFAULT_REFRESH_PATH in message
        assert "401" in message

    def test_a_200_with_no_access_token_is_a_refresh_failure(self) -> None:
        """A refresh that answers 200 with nothing usable is as terminal as a 401."""
        clock = Clock()
        recorder = Recorder(lambda request, index: httpx.Response(200, json={"ok": True}))
        session = session_for(recorder, clock, expires_at=clock() + 10)
        clock.advance(120)

        with pytest.raises(RefreshFailed, match="no access token"):
            session.client.get(PROTECTED)

    def test_a_non_json_refresh_body_is_a_refresh_failure(self) -> None:
        """A 200 whose body is not JSON carries no new token either."""
        clock = Clock()
        recorder = Recorder(
            lambda request, index: (
                httpx.Response(200, text="<html>gateway</html>")
                if request.url.path == DEFAULT_REFRESH_PATH
                else httpx.Response(200, json={"ok": True})
            )
        )
        session = session_for(recorder, clock, expires_at=clock() + 10)
        clock.advance(120)

        with pytest.raises(RefreshFailed, match="not JSON"):
            session.client.get(PROTECTED)


class TestConcurrency:
    """Tests for two callers reaching the expiry window at the same moment."""

    def test_concurrent_requests_refresh_once(self) -> None:
        """Eight threads on an expired token produce one refresh, and all send the new token."""
        clock = Clock()
        barrier = threading.Barrier(8)
        lock = threading.Lock()
        refresh_calls = []

        def handle(request: httpx.Request, index: int) -> httpx.Response:
            """Count the refreshes and answer every protected call."""
            if request.url.path == DEFAULT_REFRESH_PATH:
                with lock:
                    refresh_calls.append(index)
                return httpx.Response(200, json=refresh_body("b", expires_at=clock() + 600, rotated="refresh-2"))
            return httpx.Response(200, json={"ok": True})

        recorder = Recorder(handle)
        session = session_for(recorder, clock, expires_at=clock() + 10)
        clock.advance(120)

        def call() -> None:
            """Wait for every thread, then send one request through the session's client."""
            barrier.wait()
            session.client.get(PROTECTED)

        threads = [threading.Thread(target=call) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(refresh_calls) == 1
        assert session.refreshes == 1
        assert session.refresh_token == "refresh-2"
        sent = [token for path, token in zip(recorder.paths, recorder.tokens, strict=True) if path == PROTECTED]
        assert sent == [session.access_token] * 8

    def test_concurrent_refusals_refresh_once(self) -> None:
        """Threads all refused on the same token refresh once between them and all retry."""
        clock = Clock()
        barrier = threading.Barrier(4)
        lock = threading.Lock()
        refresh_calls = []
        stale = access_token(expires_at=clock() + 600)

        def handle(request: httpx.Request, index: int) -> httpx.Response:
            """Refuse the stale token, answer anything newer, and count the refreshes."""
            if request.url.path == DEFAULT_REFRESH_PATH:
                with lock:
                    refresh_calls.append(index)
                return httpx.Response(200, json=refresh_body("b", expires_at=clock() + 600))
            if request.headers.get("authorization", "").removeprefix("Bearer ") == stale:
                return httpx.Response(401, json={"message": "Unauthorized"})
            return httpx.Response(200, json={"ok": True})

        recorder = Recorder(handle)
        session = session_for(recorder, clock, expires_at=clock() + 600)
        session.access_token = stale
        session.client.token = stale

        results: list[int] = []
        results_lock = threading.Lock()

        def call() -> None:
            """Wait for every thread, then send one request and keep its status.

            The status is appended under its own lock, never the one the handler takes, so a
            request in flight cannot block the handler answering another thread's.
            """
            barrier.wait()
            status = session.client.get(PROTECTED).status_code
            with results_lock:
                results.append(status)

        threads = [threading.Thread(target=call) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(refresh_calls) == 1
        assert results == [200, 200, 200, 200]


class TestLoginWiring:
    """Tests for the session `login` hands back."""

    def test_login_returns_a_session_that_refreshes_itself(self) -> None:
        """The client `login` returns asks the session for its token on every request.

        Times are real here rather than driven by the fake clock, because `login` builds the
        session with the default `time.time`: the token it is handed expires immediately, so
        the first protected call has to refresh before it is sent.
        """
        issued = time.time()

        def handle(request: httpx.Request, index: int) -> httpx.Response:
            """Answer the login with a spent token, then hand out a live one on refresh."""
            if request.url.path == "/api/auth/login":
                return httpx.Response(
                    200,
                    json={"access_token": access_token(expires_at=issued), "refresh_token": "refresh-1"},
                )
            if request.url.path == DEFAULT_REFRESH_PATH:
                return httpx.Response(200, json=refresh_body("b", expires_at=issued + 3600))
            return httpx.Response(200, json={"ok": True})

        recorder = Recorder(handle)
        session = login(client_for(recorder), "e2e@example.invalid", "password")
        assert session.client.token_source is session

        session.client.get(PROTECTED)
        assert recorder.paths == ["/api/auth/login", DEFAULT_REFRESH_PATH, PROTECTED]
        assert session.refreshes == 1
        assert session.refresh_token == "refresh-1"

    def test_the_skew_is_configurable(self) -> None:
        """A wider skew refreshes earlier, which is what a slow product needs."""
        clock = Clock()
        recorder = Recorder(
            lambda request, index: (
                httpx.Response(200, json=refresh_body("b", expires_at=clock() + 600))
                if request.url.path == DEFAULT_REFRESH_PATH
                else httpx.Response(200, json={"ok": True})
            )
        )
        session = session_for(recorder, clock, expires_at=clock() + 120)
        session.refresh_skew = 300.0

        session.client.get(PROTECTED)
        assert recorder.refreshes == 1


class TestRefreshCookieOwnership:
    """Tests that the session, not the client, carries the refresh cookie after `login`.

    The anonymous client is session scoped and the suite probes `POST /api/auth/refresh`
    anonymously. With a cookie jar on the client, that probe presented the login generation's
    refresh cookie and rotated the family, and the session's own later refresh replayed the
    spent token, which revoked the family and failed every later case in that worker.
    """

    def test_login_leaves_no_cookie_on_the_anonymous_client(self) -> None:
        """A later anonymous call must not carry the refresh cookie login was answered with."""

        def handle(request: httpx.Request, index: int) -> httpx.Response:
            """Answer the login setting a refresh cookie, and anything else with 200."""
            if request.url.path == "/api/auth/login":
                return httpx.Response(
                    200,
                    headers={"set-cookie": "refresh_token=cookie-1; Path=/"},
                    json={"access_token": access_token(expires_at=time.time() + 3600), "refresh_token": ""},
                )
            return httpx.Response(200, json={"ok": True})

        recorder = Recorder(handle)
        anon = client_for(recorder)
        session = login(anon, "e2e@example.invalid", "password")

        anon.post(DEFAULT_REFRESH_PATH, json={})
        assert recorder.requests[-1].headers.get("cookie", "") == ""
        assert session.refresh_cookies == {"refresh_token": "cookie-1"}

    def test_the_session_still_sends_the_cookie_when_it_refreshes(self) -> None:
        """The session owns the refresh material, so it passes it as a header of its own."""

        def handle(request: httpx.Request, index: int) -> httpx.Response:
            """Answer the login with a spent token and a cookie, then refresh with a live one."""
            if request.url.path == "/api/auth/login":
                return httpx.Response(
                    200,
                    headers={"set-cookie": "refresh_token=cookie-1; Path=/"},
                    json={"access_token": access_token(expires_at=time.time()), "refresh_token": ""},
                )
            if request.url.path == DEFAULT_REFRESH_PATH:
                return httpx.Response(200, json=refresh_body("b", expires_at=time.time() + 3600))
            return httpx.Response(200, json={"ok": True})

        recorder = Recorder(handle)
        session = login(client_for(recorder), "e2e@example.invalid", "password")

        session.client.get(PROTECTED)
        refresh_request = next(r for r in recorder.requests if r.url.path == DEFAULT_REFRESH_PATH)
        assert refresh_request.headers.get("cookie", "") == "refresh_token=cookie-1"
        assert session.refreshes == 1
