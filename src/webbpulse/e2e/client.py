"""The HTTP client the suite talks to a deployed environment through.

Three things this wraps that a bare `httpx.Client` does not give, each of which cost an
incident before it was added:

1. **The gate header on every staging request.** Staging sits behind a CloudFront viewer
   function plus a REQUEST authorizer that admits only requests carrying `x-origin-verify`.
   Forgetting it yields a 401 from the gate that reads exactly like a broken route.
2. **The request id off every response.** The access log correlation needs it, and
   capturing it here means no test has to remember to.
3. **Pacing under the per-IP limiter.** Both limiter layers key on source IP alone, so
   every call the suite makes from one runner shares one bucket. A sweep that does not pace
   itself answers 429 to most of its probes, and a suite that treats a 429 as anything but
   "no answer yet" reports the limiter's health as the route's.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator, Mapping, MutableMapping
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

__all__ = [
    "DEFAULT_PER_MINUTE",
    "E2EClient",
    "Pacer",
    "RateLimitExhausted",
    "RequestRecord",
    "TokenSource",
    "carries_error_envelope",
    "is_expired_credential",
    "recorded_path",
    "retry_delay",
]

DEFAULT_PER_MINUTE = 10
MINUTE_WINDOW = 60
PACING_RESERVE = 1
RETRY_ATTEMPTS = 4
RETRY_CAP_SECONDS = 75
GATE_HEADER = "x-origin-verify"
GATEWAY_FORBIDDEN_BODY = "Forbidden"


class TokenSource(Protocol):
    """The slice of a session a client needs to keep its bearer credential current.

    Implemented by `webbpulse.e2e.identity.IdentitySession`. The client holds one of these
    instead of a fixed string so that a token refreshed mid-session reaches every clone the
    session handed out, rather than only the one that happened to trigger the refresh.
    """

    def bearer_token(self) -> str:
        """The token to send now, refreshed first when it is at or near its expiry."""
        ...

    def refresh_for_retry(self, token: str) -> str:
        """Refresh after a refusal and return the new token, or the empty string to give up.

        `token` is the credential the refused request carried, so an implementation can tell
        a genuinely stale token from one another caller has already replaced.
        """
        ...


class RateLimitExhausted(RuntimeError):
    """Every retry answered 429, so the probe never got an answer.

    A failure rather than a skip: the earlier bar of "not 200 and not 5xx" passed on the
    429 the limiter returns, which is evidence about the limiter and none at all about the
    route.
    """


def _header_int(headers: Mapping[str, str], name: str) -> int | None:
    """One header parsed as a non-negative int, or None when absent or unparseable."""
    raw = headers.get(name)
    if raw is None:
        return None
    try:
        value = int(float(str(raw).strip()))
    except (AttributeError, TypeError, ValueError):
        return None
    return value if value >= 0 else None


def retry_delay(headers: Mapping[str, str], attempt: int) -> float:
    """How long to wait before retrying a 429, from `Retry-After` when present.

    The app limiter answers a minute-window rejection with `Retry-After: 60` and an
    hour-window rejection with 3600, so the value is honoured but capped: a suite must not
    block for an hour, it must fail and say the hour bucket is exhausted. Without the header
    this falls back to bounded exponential backoff, which is the path a gateway-level 429
    takes.
    """
    advertised = _header_int(headers, "retry-after")
    if advertised is not None:
        return float(min(advertised, RETRY_CAP_SECONDS))
    return float(min(2**attempt, RETRY_CAP_SECONDS))


class Pacer:
    """Keeps calls under the per-IP minute limit instead of tripping it.

    The `X-RateLimit-Remaining-Minute` header the app sets on every answer it handles is
    the budget, and it is authoritative: the products limit per route class, so a GET
    class allowing 200 a minute and an auth class allowing 10 share no single number the
    suite could guess. Whenever the last answer carried the header, the remaining count it
    advertised decides whether the next call waits, and the local `per_minute` fallback is
    not consulted at all.

    The fallback counts only answers that arrived without the header. Those come from the
    gateway, the access gate or the authorizer, which answer before the application runs
    and so spend none of the app limiter's budget; counting them against it is what made a
    sweep of mostly-401 probes pace itself as if every one had cost a token.

    A `per_minute` of zero means the target does not limit at all, which is the staging
    convention, and then no call ever waits.
    """

    def __init__(
        self,
        per_minute: int = DEFAULT_PER_MINUTE,
        sleeper: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Configure the budget and the sleep and clock functions to pace with."""
        self._per_minute = per_minute
        self._sleep = sleeper
        self._clock = clock
        self._window_start: float | None = None
        self._calls_in_window = 0
        self._remaining: int | None = None
        self.slept_seconds = 0.0
        self.unmetered_calls = 0

    def _wait(self, seconds: float) -> None:
        """Sleep for `seconds` and record it, ignoring a non-positive delay."""
        if seconds <= 0:
            return
        self._sleep(seconds)
        self.slept_seconds += seconds

    def before_call(self) -> None:
        """Block until this instance has budget for one more call.

        The advertised remaining count wins outright when the last metered answer carried
        one. Taking the lower of it and the local count, which is what this did before,
        meant a fallback of ten throttled a route class advertising a hundred and ninety
        left, and no header could ever raise the budget.
        """
        if self._per_minute <= 0:
            return
        now = self._clock()
        if self._window_start is None:
            self._window_start = now
            return

        elapsed = now - self._window_start
        if elapsed >= MINUTE_WINDOW:
            self._start_window(now)
            return

        if self._remaining is not None:
            budget_left = self._remaining - PACING_RESERVE
        else:
            budget_left = self._per_minute - PACING_RESERVE - self._calls_in_window
        if budget_left > 0:
            return

        self._wait(MINUTE_WINDOW - elapsed)
        self._start_window(self._clock())

    def _start_window(self, now: float) -> None:
        """Begin a fresh minute window with the spent budget forgotten."""
        self._window_start = now
        self._calls_in_window = 0
        self._remaining = None

    def after_call(self, headers: Mapping[str, str]) -> None:
        """Record what this answer said about the budget, if it said anything.

        An answer without the header never reached the application, so it spent none of the
        app limiter's budget and is not counted against it. A previously advertised
        remaining count is kept rather than cleared, because an unmetered answer is no
        evidence that the metered budget moved.
        """
        advertised = _header_int(headers, "x-ratelimit-remaining-minute")
        if advertised is None:
            self.unmetered_calls += 1
            return
        self._calls_in_window += 1
        self._remaining = advertised

    def wait_out_429(self, headers: Mapping[str, str], attempt: int) -> float:
        """Sleep off a 429 and reset the window, returning the seconds waited."""
        delay = retry_delay(headers, attempt)
        self._wait(delay)
        self._start_window(self._clock())
        return delay


@dataclass
class RequestRecord:
    """One request the suite made, kept so a failure can be traced to an access log entry.

    `path` is the path alone. The coverage check matches it back against the templated
    routes the deployment serves, and a template never carries a query, so a recorded
    `?limit=10` would match nothing and be reported as a request to a route that is not
    served rather than as coverage of the one it reached.
    """

    method: str
    path: str
    status: int
    request_id: str
    throttled: int = 0


def recorded_path(path: str) -> str:
    """One request path with any query string and fragment removed.

    Callers normally pass `params=` and httpx builds the query, which never reaches the
    path, but a caller may also inline one. Stripping here rather than at each reader means
    every record carries the same shape whichever way the request was spelled.
    """
    for separator in ("?", "#"):
        path = path.split(separator, 1)[0]
    return path


@dataclass
class E2EClient:
    """An httpx wrapper that injects the gate header, paces itself and captures request ids.

    Keeps no cookie jar: a `Set-Cookie` on any answer is dropped rather than replayed on the
    next request from the same client. The refresh cookie belongs to the `IdentitySession`,
    which sends it explicitly when it refreshes, and a jar would hand the session-scoped
    anonymous client the login generation's cookie for every later call it makes. The
    anonymous probe of the refresh route would then rotate the session's family, and the
    session's own refresh would replay a spent token and have the family revoked.

    Never raises on a status: every assertion in the suite is about the status, so a raise
    would turn a finding into a traceback. Transport failures do raise, because a request
    that never reached the API proves nothing.
    """

    base_url: str
    gate_headers: Mapping[str, str] = field(default_factory=dict)
    token: str | None = None
    token_source: TokenSource | None = None
    transport: httpx.BaseTransport | None = None
    timeout: float = 30.0
    per_minute: int = DEFAULT_PER_MINUTE
    sleeper: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic
    user_agent: str = "webbpulse-e2e"
    records: list[RequestRecord] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Build the underlying httpx client and the pacer."""
        self._pacer = Pacer(per_minute=self.per_minute, sleeper=self.sleeper, clock=self.clock)
        self._client = httpx.Client(
            base_url=self.base_url.rstrip("/"),
            timeout=self.timeout,
            transport=self.transport,
            follow_redirects=False,
        )

    @property
    def pacer(self) -> Pacer:
        """The pacer this client shares across every call it makes."""
        return self._pacer

    def close(self) -> None:
        """Close the underlying connection pool."""
        self._client.close()

    def __enter__(self) -> E2EClient:
        """Enter a context that closes the pool on exit."""
        return self

    def __exit__(self, *_: object) -> None:
        """Close the pool."""
        self.close()

    def with_token(self, token: str | None) -> E2EClient:
        """A client sharing this one's transport and pacer but carrying a different token.

        The pacer is shared deliberately: the limiter keys on source IP, so an anonymous
        client and an authenticated one from the same runner spend the same budget.

        The clone carries no token source. A caller asking for one specific token means that
        token, so a refresh that replaced it would defeat the request: the minted-token cases
        assert on what a particular credential is answered.
        """
        clone = E2EClient(
            base_url=self.base_url,
            gate_headers=self.gate_headers,
            token=token,
            transport=self.transport,
            timeout=self.timeout,
            per_minute=self.per_minute,
            sleeper=self.sleeper,
            clock=self.clock,
            user_agent=self.user_agent,
            records=self.records,
        )
        clone._pacer = self._pacer
        return clone

    def _bearer(self) -> str:
        """The bearer credential to send now, asking the token source first when there is one.

        The source is consulted on every request rather than cached, because it is what
        refreshes an access token that is at or near its expiry, and the whole point is that
        a long run sends a live token rather than the one login returned.
        """
        if self.token_source is not None:
            return self.token_source.bearer_token()
        return self.token or ""

    def _headers(
        self,
        extra: Mapping[str, str] | None,
        send_gate_header: bool,
        token: str | None = None,
    ) -> dict[str, str]:
        """The headers for one request, gate header and bearer token included."""
        headers: dict[str, str] = {"user-agent": self.user_agent, "accept": "application/json"}
        if send_gate_header:
            headers.update({key.lower(): value for key, value in self.gate_headers.items()})
        if token:
            headers["authorization"] = f"Bearer {token}"
        if extra:
            headers.update({key.lower(): value for key, value in extra.items()})
        return headers

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        data: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | None = None,
        send_gate_header: bool = True,
        retry_on_429: bool = True,
    ) -> httpx.Response:
        """Send one request, pacing under the limiter and retrying a 429 up to the cap.

        `json` sends a JSON body. `data` sends a form-encoded one, which is what the identity
        OAuth token and consent endpoints require of an RFC 6749 client, and httpx sets the
        `application/x-www-form-urlencoded` content type itself. Passing both is a caller
        error and raises `ValueError` before anything goes out.

        Raises `RateLimitExhausted` when every attempt answered 429, since a probe that
        never got an answer must not be banked as a pass.

        A client holding a token source also retries once on a refusal that reads as an
        expired credential, after refreshing. The retry re-sends `json`, `data` and `params`
        as they were given, which is safe because every caller in this suite passes an
        in-memory body rather than a stream or a file handle: a streamed body would already be
        consumed and the retry would send an empty one. Pass `retry_on_429=False` to send
        exactly once, which also disables the refresh retry.
        """
        if json is not None and data is not None:
            raise ValueError("Pass either json= or data=, not both: a request carries one body.")
        token = self._bearer()
        response, throttled = self._send(method, path, json, data, headers, params, send_gate_header, retry_on_429)

        if retry_on_429 and self.token_source is not None and token and is_expired_credential(response):
            refreshed = self.token_source.refresh_for_retry(token)
            if refreshed:
                retry, retried_throttled = self._send(
                    method, path, json, data, headers, params, send_gate_header, retry_on_429, token=refreshed
                )
                response, throttled = retry, throttled + retried_throttled

        if response.status_code == 429 and retry_on_429:
            raise RateLimitExhausted(
                f"{method} {path} answered 429 on all {RETRY_ATTEMPTS} attempts. Nothing can be "
                "concluded about the route; the per-IP budget is exhausted."
            )
        self.records.append(
            RequestRecord(
                method=method,
                path=recorded_path(path),
                status=response.status_code,
                request_id=request_id_of(response),
                throttled=throttled,
            )
        )
        return response

    def _send(
        self,
        method: str,
        path: str,
        json: Any,
        data: Mapping[str, Any] | None,
        headers: Mapping[str, str] | None,
        params: Mapping[str, Any] | None,
        send_gate_header: bool,
        retry_on_429: bool,
        token: str | None = None,
    ) -> tuple[httpx.Response, int]:
        """One paced attempt with its 429 retries, returning the answer and the throttle count.

        `token` is resolved once by the caller rather than here, so that the credential a
        refusal is attributed to is the one that was actually sent.

        The underlying client's jar is emptied after every attempt, retries included, so a
        cookie an answer set is never sent back. Only what a caller passes as a header goes
        out, which is how the session keeps sole ownership of its refresh material.
        """
        bearer = token if token is not None else self._bearer()
        attempts = RETRY_ATTEMPTS if retry_on_429 else 1
        throttled = 0
        response: httpx.Response | None = None
        for attempt in range(attempts):
            self._pacer.before_call()
            response = self._client.request(
                method,
                path,
                json=json,
                data=data,
                params=params,
                headers=self._headers(headers, send_gate_header, bearer),
            )
            self._client.cookies.clear()
            self._pacer.after_call(response.headers)
            if response.status_code != 429:
                break
            throttled += 1
            if attempt == attempts - 1:
                break
            self._pacer.wait_out_429(response.headers, attempt)

        assert response is not None
        return response, throttled

    def get(self, path: str, **kwargs: Any) -> httpx.Response:
        """Send a GET."""
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> httpx.Response:
        """Send a POST."""
        return self.request("POST", path, **kwargs)

    def put(self, path: str, **kwargs: Any) -> httpx.Response:
        """Send a PUT, for an operation the app declares as a full replacement."""
        return self.request("PUT", path, **kwargs)

    def patch(self, path: str, **kwargs: Any) -> httpx.Response:
        """Send a PATCH, for an operation the app declares as a partial update."""
        return self.request("PATCH", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> httpx.Response:
        """Send a DELETE."""
        return self.request("DELETE", path, **kwargs)

    def options(self, path: str, **kwargs: Any) -> httpx.Response:
        """Send an OPTIONS, which is how the CORS preflight checks are made."""
        return self.request("OPTIONS", path, **kwargs)

    def iter_records(self) -> Iterator[RequestRecord]:
        """Every request this client has made, oldest first."""
        return iter(self.records)


def carries_error_envelope(response: httpx.Response) -> bool:
    """Whether a refusal carries the shared error envelope's `error_code`.

    The one question that separates the two kinds of refusal, asked the same way for a 401
    and for a 403 so the two can never drift apart. Only `webbpulse.http.error_body` writes
    `error_code`, and it runs inside the function, so the field's presence proves the
    application authenticated the caller and then refused the request on its own terms. The
    gateway and its authorizers answer before the function runs and can only produce a bare
    `{"message": ...}` object, an empty body or something that is not JSON at all, none of
    which carry the field.

    A body that cannot be read as a JSON object reads as no envelope, so an unreadable
    refusal is never mistaken for the application answering.
    """
    try:
        payload = response.json()
    except Exception:
        return False
    if not isinstance(payload, dict):
        return False
    return bool(payload.get("error_code") or payload.get("errorCode"))


def is_expired_credential(response: httpx.Response) -> bool:
    """Whether this refusal is the kind a fresher access token could turn into an answer.

    A 401 or a 403 qualifies only when it carries no shared error envelope. A refusal that
    carries an `error_code` came from the application, which means the caller was
    authenticated and then refused anyway: too few permissions for a 403, or the wrong kind
    of principal entirely for a 401, as on a route that authenticates a machine token inside
    the function rather than at the gateway. No refresh can turn either into an answer, and
    retrying one would send a second identical request, double every authorization assertion
    in the suite and report the same refusal a call later.

    A refusal carrying no envelope came from the gateway or an authorizer, which is what an
    expired token looks like from outside, so it is worth one refresh and one retry. The 403
    arm additionally requires the gateway's bare `{"message": "Forbidden"}`, because a 403
    with any other envelope-less body is not a shape the authorizer produces. The 401 arm
    takes any envelope-less body, since an authorizer refusing a token may answer
    `Unauthorized`, an empty body or a non-JSON one, and a genuinely expired session must
    still recover from all of them.
    """
    if response.status_code not in (401, 403):
        return False
    if carries_error_envelope(response):
        return False
    if response.status_code == 401:
        return True
    try:
        payload = response.json()
    except Exception:
        return False
    if not isinstance(payload, dict):
        return False
    return str(payload.get("message", "")) == GATEWAY_FORBIDDEN_BODY


def request_id_of(response: httpx.Response) -> str:
    """The request id a response carries, from whichever header the edge set it on.

    API Gateway sets `apigw-requestid`, the shared middleware sets `x-request-id`, and
    CloudFront sets `x-amz-cf-id`. The gateway's own id is the one the access log keys on,
    so it is preferred.
    """
    headers: MutableMapping[str, str] = response.headers
    for name in ("apigw-requestid", "x-amzn-requestid", "x-request-id", "x-amzn-trace-id"):
        value = headers.get(name)
        if value:
            return str(value)
    return ""
