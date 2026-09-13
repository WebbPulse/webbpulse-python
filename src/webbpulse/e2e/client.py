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
from typing import Any

import httpx

__all__ = [
    "DEFAULT_PER_MINUTE",
    "E2EClient",
    "Pacer",
    "RateLimitExhausted",
    "RequestRecord",
    "retry_delay",
]

DEFAULT_PER_MINUTE = 10
MINUTE_WINDOW = 60
PACING_RESERVE = 1
RETRY_ATTEMPTS = 4
RETRY_CAP_SECONDS = 75
GATE_HEADER = "x-origin-verify"


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

    Pacing is driven by the `X-RateLimit-Remaining-Minute` header the app sets on every
    answer rather than by a fixed sleep. The limiter is in-memory per execution
    environment, so the remaining count is the only honest read on how much budget this
    instance has left; when the header is missing the pacer falls back to its own count of
    calls in the current window.
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

    def _wait(self, seconds: float) -> None:
        """Sleep for `seconds` and record it, ignoring a non-positive delay."""
        if seconds <= 0:
            return
        self._sleep(seconds)
        self.slept_seconds += seconds

    def before_call(self) -> None:
        """Block until this instance has budget for one more call."""
        now = self._clock()
        if self._window_start is None:
            self._window_start = now
            return

        elapsed = now - self._window_start
        if elapsed >= MINUTE_WINDOW:
            self._window_start = now
            self._calls_in_window = 0
            self._remaining = None
            return

        budget_left = self._per_minute - PACING_RESERVE - self._calls_in_window
        if self._remaining is not None:
            budget_left = min(budget_left, self._remaining - PACING_RESERVE)
        if budget_left > 0:
            return

        self._wait(MINUTE_WINDOW - elapsed)
        self._window_start = self._clock()
        self._calls_in_window = 0
        self._remaining = None

    def after_call(self, headers: Mapping[str, str]) -> None:
        """Record one spent call and the quota the response advertised."""
        self._calls_in_window += 1
        self._remaining = _header_int(headers, "x-ratelimit-remaining-minute")

    def wait_out_429(self, headers: Mapping[str, str], attempt: int) -> float:
        """Sleep off a 429 and reset the window, returning the seconds waited."""
        delay = retry_delay(headers, attempt)
        self._wait(delay)
        self._window_start = self._clock()
        self._calls_in_window = 0
        self._remaining = None
        return delay


@dataclass
class RequestRecord:
    """One request the suite made, kept so a failure can be traced to an access log entry."""

    method: str
    path: str
    status: int
    request_id: str
    throttled: int = 0


@dataclass
class E2EClient:
    """An httpx wrapper that injects the gate header, paces itself and captures request ids.

    Never raises on a status: every assertion in the suite is about the status, so a raise
    would turn a finding into a traceback. Transport failures do raise, because a request
    that never reached the API proves nothing.
    """

    base_url: str
    gate_headers: Mapping[str, str] = field(default_factory=dict)
    token: str | None = None
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

    def _headers(self, extra: Mapping[str, str] | None, send_gate_header: bool) -> dict[str, str]:
        """The headers for one request, gate header and bearer token included."""
        headers: dict[str, str] = {"user-agent": self.user_agent, "accept": "application/json"}
        if send_gate_header:
            headers.update({key.lower(): value for key, value in self.gate_headers.items()})
        if self.token:
            headers["authorization"] = f"Bearer {self.token}"
        if extra:
            headers.update({key.lower(): value for key, value in extra.items()})
        return headers

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | None = None,
        send_gate_header: bool = True,
        retry_on_429: bool = True,
    ) -> httpx.Response:
        """Send one request, pacing under the limiter and retrying a 429 up to the cap.

        Raises `RateLimitExhausted` when every attempt answered 429, since a probe that
        never got an answer must not be banked as a pass.
        """
        attempts = RETRY_ATTEMPTS if retry_on_429 else 1
        throttled = 0
        response: httpx.Response | None = None
        for attempt in range(attempts):
            self._pacer.before_call()
            response = self._client.request(
                method,
                path,
                json=json,
                params=params,
                headers=self._headers(headers, send_gate_header),
            )
            self._pacer.after_call(response.headers)
            if response.status_code != 429:
                break
            throttled += 1
            if attempt == attempts - 1:
                break
            self._pacer.wait_out_429(response.headers, attempt)

        assert response is not None
        if response.status_code == 429 and retry_on_429:
            raise RateLimitExhausted(
                f"{method} {path} answered 429 on all {attempts} attempts. Nothing can be "
                "concluded about the route; the per-IP budget is exhausted."
            )
        self.records.append(
            RequestRecord(
                method=method,
                path=path,
                status=response.status_code,
                request_id=request_id_of(response),
                throttled=throttled,
            )
        )
        return response

    def get(self, path: str, **kwargs: Any) -> httpx.Response:
        """Send a GET."""
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> httpx.Response:
        """Send a POST."""
        return self.request("POST", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> httpx.Response:
        """Send a DELETE."""
        return self.request("DELETE", path, **kwargs)

    def options(self, path: str, **kwargs: Any) -> httpx.Response:
        """Send an OPTIONS, which is how the CORS preflight checks are made."""
        return self.request("OPTIONS", path, **kwargs)

    def iter_records(self) -> Iterator[RequestRecord]:
        """Every request this client has made, oldest first."""
        return iter(self.records)


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
