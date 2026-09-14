"""Find the API Gateway access log entry for one request and read what served it.

The routeKey in the access log is the whole verification. A probe that returns 200 proves
something answered; only the log entry says which route key matched and which integration
ran, and that distinction is what separates a landed cut from a request falling through a
`{proxy+}` catch-all.

Delivery is per stream and can lag, so the lookup is a bounded wait rather than a single
read. A miss inside the budget is reported as a miss rather than as a routing failure: the
HTTP probe already proved the request reached the API.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

__all__ = ["AccessLogEntry", "AccessLogLookup", "log_field", "parse_entry"]

UNSET_PLACEHOLDER = "-"

DEFAULT_WAIT_SECONDS = 120.0
DEFAULT_POLL_SECONDS = 5.0
LOOKBACK_MILLISECONDS = 120_000


@dataclass(frozen=True)
class AccessLogEntry:
    """One parsed access log line.

    `integration` is the integration error or target the gateway recorded, which is empty
    on a clean request; `status` is the gateway's own status, which differs from the
    integration's when the gate or the authorizer answered.
    """

    request_id: str
    route_key: str
    path: str
    method: str
    status: int
    integration_status: int
    integration_error: str
    raw: Mapping[str, Any]

    @property
    def matched_a_route(self) -> bool:
        """Whether the gateway matched a declared route rather than answering itself."""
        return bool(self.route_key) and self.route_key != "$default"


def log_field(payload: Mapping[str, Any], *keys: str) -> str:
    """The first non-empty string field among `keys`, with API Gateway's `-` read as empty.

    An access log format names `$context` variables, and the gateway renders one that is
    unset for the request as a literal `-` rather than omitting the field or writing an
    empty string. A healthy request therefore carries `"integrationErrorMessage":"-"`, which
    a plain truthiness check reads as an error message and reports as a failed integration.
    """
    for key in keys:
        value = str(payload.get(key) or "").strip()
        if value and value != UNSET_PLACEHOLDER:
            return value
    return ""


def parse_entry(message: str) -> AccessLogEntry | None:
    """Parse one access log message, or None when it is not the JSON format the stage sets.

    A line that does not parse is skipped rather than raised on, because a stage can carry
    more than one format across a format change and one unreadable line must not lose the
    entry that follows it.
    """
    try:
        payload = json.loads(message)
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None

    def _int(key: str) -> int:
        raw = payload.get(key)
        try:
            return int(str(raw))
        except (TypeError, ValueError):
            return 0

    request_id = log_field(payload, "requestId", "requestid")
    if not request_id:
        return None
    return AccessLogEntry(
        request_id=request_id,
        route_key=log_field(payload, "routeKey"),
        path=log_field(payload, "path", "rawPath"),
        method=log_field(payload, "httpMethod", "method"),
        status=_int("status"),
        integration_status=_int("integrationStatus"),
        integration_error=log_field(payload, "integrationErrorMessage"),
        raw=payload,
    )


class AccessLogLookup:
    """Finds access log entries by request id, with a bounded wait for delivery."""

    def __init__(
        self,
        client: Any,
        log_group: str,
        *,
        wait_seconds: float = DEFAULT_WAIT_SECONDS,
        poll_seconds: float = DEFAULT_POLL_SECONDS,
        sleeper: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        now_ms: Callable[[], int] = lambda: int(time.time() * 1000),
    ) -> None:
        """Bind the lookup to one CloudWatch Logs client and access log group."""
        self._client = client
        self._log_group = log_group
        self._wait_seconds = wait_seconds
        self._poll_seconds = poll_seconds
        self._sleep = sleeper
        self._clock = clock
        self._now_ms = now_ms
        self._cache: dict[str, AccessLogEntry] = {}

    @property
    def log_group(self) -> str:
        """The access log group this looks in."""
        return self._log_group

    def _read_once(self, request_id: str, start_time_ms: int) -> AccessLogEntry | None:
        """One `filter_log_events` pass, caching every entry it can parse."""
        token: str | None = None
        while True:
            kwargs: dict[str, Any] = {
                "logGroupName": self._log_group,
                "startTime": start_time_ms,
                "filterPattern": f'"{request_id}"',
                "limit": 100,
            }
            if token:
                kwargs["nextToken"] = token
            response = self._client.filter_log_events(**kwargs)
            for event in response.get("events", []):
                entry = parse_entry(str(event.get("message", "")))
                if entry is not None:
                    self._cache[entry.request_id] = entry
            token = response.get("nextToken")
            if not token:
                break
        return self._cache.get(request_id)

    def find(self, request_id: str, *, start_time_ms: int | None = None) -> AccessLogEntry | None:
        """The access log entry for one request id, or None once the budget runs out.

        None means "not delivered inside the budget", not "the request did not happen". The
        caller decides whether that is a failure, which it is for a route cut assertion and
        is not for a diagnostic.
        """
        if not request_id:
            return None
        cached = self._cache.get(request_id)
        if cached is not None:
            return cached

        start = start_time_ms if start_time_ms is not None else self._now_ms() - LOOKBACK_MILLISECONDS
        deadline = self._clock() + self._wait_seconds
        while True:
            entry = self._read_once(request_id, start)
            if entry is not None:
                return entry
            remaining = deadline - self._clock()
            if remaining <= 0:
                return None
            self._sleep(min(self._poll_seconds, remaining))
