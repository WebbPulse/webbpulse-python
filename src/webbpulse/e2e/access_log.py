"""Find the API Gateway access log entry for one request and read what served it.

The routeKey in the access log is the whole verification. A probe that returns 200 proves
something answered; only the log entry says which route key matched and which integration
ran, and that distinction is what separates a landed cut from a request falling through a
`{proxy+}` catch-all.

Delivery is per stream and can lag, so the lookup is a bounded wait rather than a single
read. A miss inside the budget is reported as a miss rather than as a routing failure: the
HTTP probe already proved the request reached the API.

The suite probes every live route up front and then asks for all of their entries, so the
lookup reads the whole delivery window in one unfiltered scan and serves every id from that
one cache. One group of 147 routes then pays one delivery lag rather than 147 of them. A
rescan is throttled to one per poll interval across all callers, so a run of misses costs
one CloudWatch read rather than one each.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

__all__ = [
    "DEFAULT_SETTLE_SECONDS",
    "AccessLogEntry",
    "AccessLogLookup",
    "log_field",
    "parse_entry",
]

UNSET_PLACEHOLDER = "-"

DEFAULT_WAIT_SECONDS = 120.0
DEFAULT_POLL_SECONDS = 5.0
DEFAULT_SETTLE_SECONDS = 20.0
LOOKBACK_MILLISECONDS = 120_000
WINDOW_MARGIN_MILLISECONDS = 10_000
SCAN_PAGE_LIMIT = 10_000


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
        settle_seconds: float = DEFAULT_SETTLE_SECONDS,
        sleeper: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        now_ms: Callable[[], int] = lambda: int(time.time() * 1000),
    ) -> None:
        """Bind the lookup to one CloudWatch Logs client and access log group.

        `settle_seconds` is how long a miss is treated as delivery lag. Past it a scan that
        still does not carry the id is taken as evidence the entry is not coming, and the
        lookup gives up rather than spending the rest of `wait_seconds`.
        """
        self._client = client
        self._log_group = log_group
        self._wait_seconds = wait_seconds
        self._poll_seconds = poll_seconds
        self._settle_seconds = settle_seconds
        self._sleep = sleeper
        self._clock = clock
        self._now_ms = now_ms
        self._cache: dict[str, AccessLogEntry] = {}
        self._window_start_ms: int | None = None
        self._last_scan_at: float | None = None
        self._first_missed_at: float | None = None

    @property
    def log_group(self) -> str:
        """The access log group this looks in."""
        return self._log_group

    @property
    def cached_ids(self) -> frozenset[str]:
        """Every request id a scan or a read has already parsed, for a diagnostic."""
        return frozenset(self._cache)

    def open_window(self, first_probe_ms: int) -> None:
        """Declare the delivery window every later lookup scans, from the first probe.

        The suite probes every route before it asks for any entry, so the window is opened
        once with the timestamp of that first probe and each scan reads from there. A
        margin is taken off the front because the gateway timestamps an entry when it
        finishes the request, not when the probe was sent.
        """
        start = first_probe_ms - WINDOW_MARGIN_MILLISECONDS
        if self._window_start_ms is None or start < self._window_start_ms:
            self._window_start_ms = start

    def _window_start(self) -> int:
        """The start of the scan window, falling back to a lookback when none was opened."""
        if self._window_start_ms is not None:
            return self._window_start_ms
        return self._now_ms() - LOOKBACK_MILLISECONDS

    def scan_window(self, *, force: bool = False) -> int:
        """Read the whole delivery window unfiltered and cache every entry it parses.

        Returns how many entries the cache holds afterwards. Throttled to one scan per poll
        interval across every caller unless `force` is set, so 147 lookups that all miss
        cost one CloudWatch read between them rather than one each.
        """
        now = self._clock()
        if not force and self._last_scan_at is not None and now - self._last_scan_at < self._poll_seconds:
            return len(self._cache)
        self._last_scan_at = now
        token: str | None = None
        while True:
            kwargs: dict[str, Any] = {
                "logGroupName": self._log_group,
                "startTime": self._window_start(),
                "limit": SCAN_PAGE_LIMIT,
            }
            if token:
                kwargs["nextToken"] = token
            response = self._client.filter_log_events(**kwargs)
            self._absorb(response.get("events", []))
            token = response.get("nextToken")
            if not token:
                break
        return len(self._cache)

    def _absorb(self, events: Any) -> None:
        """Cache every event in one page that parses as an access log entry."""
        for event in events:
            entry = parse_entry(str(event.get("message", "")))
            if entry is not None:
                self._cache[entry.request_id] = entry

    def read_one(self, request_id: str, *, start_time_ms: int | None = None) -> AccessLogEntry | None:
        """One `filter_log_events` pass filtered to a single request id, caching what it parses.

        The narrow read the window scan replaced for the suite. It stays available as the
        fallback for a single lookup outside the window, where scanning the whole delivery
        window would read a busy stage's log group whole for one id.
        """
        start = start_time_ms if start_time_ms is not None else self._window_start()
        token: str | None = None
        while True:
            kwargs: dict[str, Any] = {
                "logGroupName": self._log_group,
                "startTime": start,
                "filterPattern": f'"{request_id}"',
                "limit": 100,
            }
            if token:
                kwargs["nextToken"] = token
            response = self._client.filter_log_events(**kwargs)
            self._absorb(response.get("events", []))
            token = response.get("nextToken")
            if not token:
                break
        return self._cache.get(request_id)

    def find(self, request_id: str, *, start_time_ms: int | None = None) -> AccessLogEntry | None:
        """The access log entry for one request id, or None once the budget runs out.

        The cache is consulted first, then the delivery window is scanned, and only then
        does the bounded wait begin. A `start_time_ms` names a window this lookup was not
        opened for, so that call takes the per-id filtered read instead of the scan.

        Every iteration forces a real read. The unforced scan is throttled across all
        callers, so a lookup entering the loop while another case had just scanned spent its
        whole budget on no-op reads of a stale cache: it slept the poll interval, scanned
        nothing, and repeated. That is what made two cases cost 61 and 43 seconds while the
        rest cost milliseconds, and why the two differed at all, since where in the throttle
        window a case happened to start decided how much budget it burned.

        The loop also stops as soon as a scan that began after the request can be shown to
        have completed without it. Delivery lag is a reason to wait again; a window already
        read past that point is evidence the entry is not coming, and waiting the rest of
        the budget cannot turn that into a hit.

        None means "not delivered inside the budget", not "the request did not happen". The
        caller decides whether that is a failure, which it is for a route cut assertion and
        is not for a diagnostic.
        """
        if not request_id:
            return None
        cached = self._cache.get(request_id)
        if cached is not None:
            return cached

        deadline = self._clock() + self._wait_seconds
        while True:
            started_at = self._clock()
            entry = self._read(request_id, start_time_ms)
            if entry is not None:
                return entry
            if self._settled_without(request_id, started_at):
                return None
            remaining = deadline - self._clock()
            if remaining <= 0:
                return None
            self._sleep(min(self._poll_seconds, remaining))

    def _settled_without(self, request_id: str, started_at: float) -> bool:
        """Whether a read that began at `started_at` proves this id is not merely late.

        True once a scan begun after the entry's own delivery grace period has finished
        without it. Until that grace has passed a miss is indistinguishable from lag, so the
        loop keeps waiting.
        """
        if self._first_missed_at is None:
            self._first_missed_at = started_at
            return False
        return started_at - self._first_missed_at >= self._settle_seconds

    def _read(self, request_id: str, start_time_ms: int | None) -> AccessLogEntry | None:
        """One attempt at an id, always a real read rather than a throttled no-op.

        The window scan is forced here. Leaving it throttled meant an attempt could return
        the same stale cache it was handed a moment earlier while still costing the caller a
        full poll interval of sleep.
        """
        if start_time_ms is not None:
            return self.read_one(request_id, start_time_ms=start_time_ms)
        self.scan_window(force=True)
        return self._cache.get(request_id)
