"""Tests for the access token an `IdentitySession` keeps current.

The identity access token's TTL is ten minutes and a full suite runs well past it. A session
that carried the login token for the whole run had every later call from that worker refused
by the authorizer, and those refusals read exactly like product bugs, including in the
fixtures that create the resources a case then asserts on. What is under test here is that
the session notices before the gateway does, that it also recovers from a refusal it did not
predict, and that it never retries a refusal a fresh token would not fix.

That last property is decided by the body rather than the status. A refusal carrying the
shared error envelope's `error_code` came from the function, so the caller was authenticated
and refused anyway and no refresh can help; one carrying no envelope came from the gateway or
an authorizer, which is what an expired token looks like from outside.
"""

from __future__ import annotations

import base64
import itertools
import json
import threading
import time
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from webbpulse.e2e.client import E2EClient, carries_error_envelope, is_expired_credential
from webbpulse.e2e.ephemeral import Credentials
from webbpulse.e2e.identity import (
    DEFAULT_ACCESS_TOKEN_TTL,
    DEFAULT_REFRESH_PATH,
    DEFAULT_REFRESH_SKEW,
    DEFAULT_STEP_UP_PATH,
    IdentitySession,
    RefreshFailed,
    StepUpFailed,
    decode_claims,
    login,
    logout,
    refresh,
    step_up,
    token_expiry,
)
from webbpulse.e2e.suite import TestIdentity as IdentityGroup

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

    def test_a_product_401_is_not_retried(self) -> None:
        """A 401 carrying an `error_code` is the application refusing, so it stands as it is.

        The shape a route that authenticates a machine token inside the function answers a
        user bearer with. Refreshing against it asked the refresh endpoint for a credential
        the route would refuse just the same.
        """
        clock = Clock()
        envelope = {
            "success": False,
            "status": 401,
            "message": "Authentication is required.",
            "request_id": "req-abc123",
            "error_code": "UNAUTHORIZED",
        }
        recorder = Recorder(lambda request, index: httpx.Response(401, json=envelope))
        session = session_for(recorder, clock, expires_at=clock() + 600)

        response = session.client.get(PROTECTED)
        assert response.status_code == 401
        assert recorder.paths == [PROTECTED]
        assert session.refreshes == 0

    def test_a_product_401_leaves_the_session_usable(self) -> None:
        """The case that answered it fails alone rather than poisoning every later one.

        Refreshing against a wrong-principal 401 met a refusal from the refresh endpoint
        too, and `RefreshFailed` is terminal: it turned a correct product answer into a
        suite error and left the session with no credential for the cases that followed.
        """
        clock = Clock()
        runner_route = "/api/v1/runs/run-1/bundle"
        envelope = {
            "success": False,
            "status": 401,
            "message": "Authentication is required.",
            "request_id": "req-abc123",
            "error_code": "UNAUTHORIZED",
        }

        def handle(request: httpx.Request, index: int) -> httpx.Response:
            """Refuse the runner route, refuse any refresh, and answer everything else."""
            if request.url.path == runner_route:
                return httpx.Response(401, json=envelope)
            if request.url.path == DEFAULT_REFRESH_PATH:
                return httpx.Response(401, json={"message": "Unauthorized"})
            return httpx.Response(200, json={"ok": True})

        recorder = Recorder(handle)
        session = session_for(recorder, clock, expires_at=clock() + 600)

        assert session.client.get(runner_route).status_code == 401
        assert session.client.get(PROTECTED).status_code == 200
        assert recorder.paths == [runner_route, PROTECTED]
        assert session.refreshes == 0


class TestIsExpiredCredential:
    """Tests for telling an expired credential from a refusal no refresh can fix."""

    def test_a_bare_401_qualifies(self) -> None:
        """An envelope-less 401 is the authorizer refusing the token itself."""
        assert is_expired_credential(httpx.Response(401, json={"message": "Unauthorized"}))

    def test_an_empty_bodied_401_qualifies(self) -> None:
        """An authorizer denying with its own policy can answer nothing at all."""
        assert is_expired_credential(httpx.Response(401))

    def test_a_non_json_401_qualifies(self) -> None:
        """A parse failure must not silently suppress a refresh a real expiry needs."""
        assert is_expired_credential(httpx.Response(401, text="<html>401</html>"))

    def test_a_json_list_401_qualifies(self) -> None:
        """Valid JSON that is not an object carries no envelope, so it is not the app."""
        assert is_expired_credential(httpx.Response(401, json=["Unauthorized"]))

    def test_a_product_401_does_not_qualify(self) -> None:
        """An `error_code` proves the function authenticated the caller and refused anyway.

        The shape a route that authenticates a machine token inside the Lambda answers a
        user bearer with. The caller is the wrong kind of principal, which no refresh fixes.
        """
        envelope = {
            "success": False,
            "status": 401,
            "message": "Authentication is required.",
            "request_id": "req-abc123",
            "error_code": "UNAUTHORIZED",
        }
        assert not is_expired_credential(httpx.Response(401, json=envelope))

    def test_a_camel_cased_product_401_does_not_qualify(self) -> None:
        """The camel cased spelling is read too, as it already was for a 403."""
        assert not is_expired_credential(httpx.Response(401, json={"errorCode": "UNAUTHORIZED"}))

    def test_the_gateway_forbidden_shape_qualifies(self) -> None:
        """The authorizer's bare message is what an expired token looks like from outside."""
        assert is_expired_credential(httpx.Response(403, json={"message": "Forbidden"}))

    def test_a_product_403_does_not_qualify(self) -> None:
        """An envelope with an `error_code` is a permission answer, not a stale token."""
        assert not is_expired_credential(httpx.Response(403, json={"error_code": "FORBIDDEN", "message": "Forbidden"}))

    def test_a_non_json_403_does_not_qualify(self) -> None:
        """A body that is not JSON is not the gateway shape."""
        assert not is_expired_credential(httpx.Response(403, text="Forbidden"))

    def test_another_bare_403_message_does_not_qualify(self) -> None:
        """Only the gateway's own `Forbidden` is the authorizer shape at this status."""
        assert not is_expired_credential(httpx.Response(403, json={"message": "Nope"}))

    def test_other_statuses_do_not_qualify(self) -> None:
        """A 404 or a 500 says nothing about the credential."""
        assert not is_expired_credential(httpx.Response(404, json={"message": "Forbidden"}))


class TestCarriesErrorEnvelope:
    """Tests for the one question both refusal arms ask, so the two cannot drift apart."""

    def test_an_envelope_code_is_recognised(self) -> None:
        """`error_body` writes `error_code`, and only the application runs it."""
        assert carries_error_envelope(httpx.Response(401, json={"error_code": "UNAUTHORIZED"}))

    def test_the_camel_cased_spelling_is_recognised(self) -> None:
        """A product serialising its envelope in camel case is still the application."""
        assert carries_error_envelope(httpx.Response(403, json={"errorCode": "FORBIDDEN"}))

    def test_a_bare_gateway_message_carries_none(self) -> None:
        """The gateway answers before the function runs, so it writes no code."""
        assert not carries_error_envelope(httpx.Response(401, json={"message": "Unauthorized"}))

    def test_a_blank_code_carries_none(self) -> None:
        """An empty code names no failure, so it is no more the app than an absent one."""
        assert not carries_error_envelope(httpx.Response(401, json={"error_code": ""}))

    def test_a_non_json_body_carries_none(self) -> None:
        """An unreadable refusal is never mistaken for the application answering."""
        assert not carries_error_envelope(httpx.Response(401, text="<html>401</html>"))

    def test_a_json_list_body_carries_none(self) -> None:
        """Valid JSON that is not an object carries no envelope."""
        assert not carries_error_envelope(httpx.Response(401, json=["UNAUTHORIZED"]))


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


def dated_token(auth_time: int, *, marker: str) -> str:
    """An unsigned token carrying `auth_time`, for the step-up helper's checks."""
    claims = {"sub": SUBJECT, "exp": 2_000_000_000, "auth_time": auth_time, "marker": marker}
    return f"{segment({'alg': 'RS256', 'typ': 'JWT'})}.{segment(claims)}.signature"


class TestStepUp:
    """Tests for `step_up`, which re-authenticates a session through the password path."""

    def scripted(self, *, step_status: int = 200, refreshed_auth_time: int = 2_000) -> Recorder:
        """A backend answering step-up with `auth_time` 2000 and refresh with `refreshed_auth_time`."""

        def answer(request: httpx.Request, index: int) -> httpx.Response:
            """Script the step-up and refresh routes."""
            if request.url.path == DEFAULT_STEP_UP_PATH:
                if step_status != 200:
                    return httpx.Response(step_status, json={"success": False, "error_code": "INVALID_CREDENTIALS"})
                return httpx.Response(200, json={"access_token": dated_token(2_000, marker="stepped")})
            return httpx.Response(
                200,
                json={"access_token": dated_token(refreshed_auth_time, marker="refreshed"), "refresh_token": "r-2"},
            )

        return Recorder(answer)

    def test_steps_up_then_refreshes_onto_the_new_auth_time(self) -> None:
        """The password goes to the step-up route, then one refresh adopts a token keeping its `auth_time`."""
        recorder = self.scripted()
        session = session_for(recorder, Clock(), expires_at=2_000_000_000)

        returned = step_up(session, "hunter2")

        assert returned is session
        assert recorder.paths == [DEFAULT_STEP_UP_PATH, DEFAULT_REFRESH_PATH]
        assert json.loads(recorder.requests[0].content) == {"password": "hunter2"}
        assert session.claims["auth_time"] == 2_000
        assert session.claims["marker"] == "refreshed"
        assert session.refresh_token == "r-2"
        assert session.refreshes == 1

    def test_a_refused_step_up_raises_without_the_password(self) -> None:
        """A 401 raises `StepUpFailed`, never retries as an expired token, and hides the password."""
        recorder = self.scripted(step_status=401)
        session = session_for(recorder, Clock(), expires_at=2_000_000_000)

        with pytest.raises(StepUpFailed) as caught:
            step_up(session, "hunter2")

        assert "hunter2" not in str(caught.value)
        assert recorder.paths == [DEFAULT_STEP_UP_PATH]

    def test_a_refresh_that_loses_the_step_up_raises(self) -> None:
        """A refreshed token older than the step-up means the family never recorded it."""
        recorder = self.scripted(refreshed_auth_time=1_000)
        session = session_for(recorder, Clock(), expires_at=2_000_000_000)

        with pytest.raises(StepUpFailed, match="auth_time 1000"):
            step_up(session, "hunter2")


class RotatingIdentity:
    """A fake identity backend with the real refresh contract: rotate on use, revoke on reuse.

    Refresh tokens travel in a cookie, as the identity package sends them. Presenting a
    refresh token that was already rotated away revokes its whole family, and a revoked
    family's access tokens are refused with the gateway's bare 401, which is what turned one
    unsaved rotation into a column of failures on a real run.
    """

    PASSWORD = "correct horse"

    def __init__(self) -> None:
        """Start with no families."""
        self.current: dict[str, str] = {}
        self.family_of: dict[str, str] = {}
        self.access_family: dict[str, str] = {}
        self.auth_time: dict[str, int] = {}
        self.revoked: set[str] = set()
        self.reused: list[str] = []
        self.counter = 0
        self.clock = 1_000

    def _next(self, prefix: str) -> str:
        """A fresh opaque identifier."""
        self.counter += 1
        return f"{prefix}-{self.counter}"

    def _access_for(self, family: str, auth_time: int) -> str:
        """A long lived access token bound to `family`."""
        token = dated_token(auth_time, marker=self._next(family))
        self.access_family[token] = family
        return token

    def _rotate(self, family: str) -> httpx.Response:
        """Issue a new refresh cookie and access token for `family`."""
        refresh_token = self._next(f"{family}-refresh")
        self.current[family] = refresh_token
        self.family_of[refresh_token] = family
        return httpx.Response(
            200,
            json={"access_token": self._access_for(family, self.auth_time[family])},
            headers={"set-cookie": f"refresh_token={refresh_token}; Path=/; HttpOnly"},
        )

    def _presented(self, request: httpx.Request) -> str:
        """The refresh cookie a request carried, or ""."""
        for part in str(request.headers.get("cookie", "")).split(";"):
            name, _, value = part.strip().partition("=")
            if name == "refresh_token":
                return value
        return ""

    def _bearer_family(self, request: httpx.Request) -> str:
        """The live family the request's bearer token belongs to, or ""."""
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        family = self.access_family.get(token, "")
        return "" if family in self.revoked else family

    def __call__(self, request: httpx.Request, index: int) -> httpx.Response:
        """Serve login, refresh, step-up, logout and one protected route."""
        path = request.url.path
        if path == "/api/auth/login":
            family = self._next("family")
            self.auth_time[family] = self.clock
            return self._rotate(family)
        if path == DEFAULT_REFRESH_PATH:
            presented = self._presented(request)
            family = self.family_of.get(presented, "")
            if not family or family in self.revoked:
                return httpx.Response(401, json={"error_code": "NO_SESSION"})
            if presented != self.current[family]:
                self.reused.append(family)
                self.revoked.add(family)
                return httpx.Response(401, json={"error_code": "TOKEN_REUSED"})
            return self._rotate(family)
        if path == DEFAULT_STEP_UP_PATH:
            family = self._bearer_family(request)
            if not family or json.loads(request.content).get("password") != self.PASSWORD:
                return httpx.Response(401, json={"error_code": "INVALID_CREDENTIALS"})
            self.clock += 60
            self.auth_time[family] = self.clock
            return httpx.Response(200, json={"access_token": self._access_for(family, self.clock)})
        if path == "/api/auth/logout":
            family = self.family_of.get(self._presented(request), "")
            if family:
                self.revoked.add(family)
            return httpx.Response(200, json={"signed_out": True})
        if self._bearer_family(request):
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(401, json={"message": "Unauthorized"})


def rotating_backend() -> tuple[RotatingIdentity, E2EClient]:
    """A rotating fake backend and an anonymous client over it."""
    backend = RotatingIdentity()
    return backend, client_for(Recorder(backend))


def signed_in(anon: E2EClient) -> IdentitySession:
    """A session signed in through the real `login` helper against the fake backend."""
    return login(anon, "e2e@example.invalid", RotatingIdentity.PASSWORD)


class TestRefreshHelperKeepsTheRotation:
    """Tests that the public `refresh` helper stores what the route rotated."""

    def test_two_refreshes_then_a_stepped_up_call_all_succeed(self) -> None:
        """The session survives consecutive explicit refreshes and still steps up and calls."""
        backend, anon = rotating_backend()
        session = signed_in(anon)

        assert refresh(session).status_code == 200
        assert refresh(session).status_code == 200
        step_up(session, RotatingIdentity.PASSWORD)

        assert session.client.get(PROTECTED).status_code == 200
        assert backend.reused == []
        assert session.refreshes == 3

    def test_the_rotated_cookie_is_what_the_next_refresh_presents(self) -> None:
        """Each explicit refresh presents the cookie the one before it was handed."""
        backend, anon = rotating_backend()
        session = signed_in(anon)
        first = session.refresh_cookies["refresh_token"]

        refresh(session)
        second = session.refresh_cookies["refresh_token"]
        refresh(session)

        assert first != second != session.refresh_cookies["refresh_token"]
        assert backend.reused == []

    def test_a_body_rotated_token_is_stored(self) -> None:
        """A product returning the refresh token in the body has the rotated one kept."""
        clock = Clock()
        recorder = Recorder(
            lambda request, index: httpx.Response(200, json=refresh_body("b", expires_at=clock() + 600, rotated="r-2"))
        )
        session = session_for(recorder, clock, expires_at=clock() + 600)

        response = refresh(session)

        assert response.status_code == 200
        assert session.refresh_token == "r-2"
        assert session.claims["marker"] == "b"

    def test_a_refused_refresh_leaves_the_session_as_it_was(self) -> None:
        """A non-200 is handed back for the caller to assert on and changes nothing."""
        clock = Clock()
        recorder = Recorder(lambda request, index: httpx.Response(401, json={"error_code": "NO_SESSION"}))
        session = session_for(recorder, clock, expires_at=clock() + 600)
        before = session.access_token

        assert refresh(session).status_code == 401
        assert session.access_token == before
        assert session.refresh_token == "refresh-1"
        assert session.refreshes == 0


class TestLogoutHelper:
    """Tests that `logout` ends the family the session holds."""

    def test_logout_presents_the_refresh_cookie(self) -> None:
        """The client keeps no cookie jar, so the session sends its own cookie."""
        backend, anon = rotating_backend()
        session = signed_in(anon)

        assert logout(session).status_code == 200
        assert len(backend.revoked) == 1
        with pytest.raises(RefreshFailed):
            session.client.get(PROTECTED)


class TestSharedSuiteLeavesTheSessionUsable:
    """The shared identity cases must not spend or end `user_session`, in any order."""

    @staticmethod
    def run_case(name: str, user_session: IdentitySession, anon: E2EClient) -> None:
        """Run one shared suite case, or the `stepped_up_session` fixture's step-up, by name."""
        group = IdentityGroup()
        if name == "refresh":
            group.test_refresh_issues_a_new_token(user_session)
        elif name == "logout":
            group.test_logout_ends_the_session(
                anon,
                SimpleNamespace(signs_in=True),
                Credentials(email="e2e@example.invalid", password=RotatingIdentity.PASSWORD),
            )
        else:
            step_up(user_session, RotatingIdentity.PASSWORD)
            assert user_session.client.get(PROTECTED).status_code == 200

    def test_logout_case_leaves_user_session_usable(self) -> None:
        """The logout case ends a session of its own, never the shared one."""
        backend, anon = rotating_backend()
        user_session = signed_in(anon)

        self.run_case("logout", user_session, anon)

        assert len(backend.revoked) == 1
        assert refresh(user_session).status_code == 200
        assert user_session.client.get(PROTECTED).status_code == 200

    @pytest.mark.parametrize(
        "order",
        list(itertools.permutations(("refresh", "logout", "stepped_up"))),
        ids="-".join,
    )
    def test_order_does_not_matter(self, order: tuple[str, ...]) -> None:
        """Every order of refresh, logout and a stepped-up call leaves the session working."""
        backend, anon = rotating_backend()
        user_session = signed_in(anon)

        for name in order:
            self.run_case(name, user_session, anon)

        assert backend.reused == []
        assert user_session.client.get(PROTECTED).status_code == 200
        step_up(user_session, RotatingIdentity.PASSWORD)
