"""Tests for parsing access log entries and finding one by request id.

The routeKey in the access log is the whole verification: a 200 proves something answered,
and only the log entry says which route matched. Delivery lags, so the lookup waits within a
budget and reports a miss as a miss rather than as a routing failure.
"""

from __future__ import annotations

import json
import time
from typing import Any

import boto3
import pytest
from moto import mock_aws

from webbpulse.e2e.access_log import WINDOW_MARGIN_MILLISECONDS, AccessLogLookup, parse_entry

REGION = "us-west-2"
LOG_GROUP = "/aws/apigateway/example-staging-api"


def line(**overrides: Any) -> str:
    """One access log message in the JSON format the stage's access log format sets."""
    payload = {
        "requestId": "req-1",
        "routeKey": "POST /api/build-lists",
        "path": "/api/build-lists",
        "httpMethod": "POST",
        "status": "201",
        "integrationStatus": "201",
        "integrationErrorMessage": "",
    }
    payload.update({key: value for key, value in overrides.items()})
    return json.dumps(payload)


class Clock:
    """A monotonic clock a test drives by hand, with a sleeper that advances it."""

    def __init__(self) -> None:
        """Start at zero."""
        self.now = 0.0

    def __call__(self) -> float:
        """The current time."""
        return self.now

    def sleep(self, seconds: float) -> None:
        """Advance the clock instead of waiting."""
        self.now += seconds


class FakeLogs:
    """A CloudWatch Logs stand-in that hands back scripted pages of events."""

    def __init__(self, responses: list[dict[str, Any]]) -> None:
        """Hold one response per `filter_log_events` call, repeating the last."""
        self.responses = responses
        self.calls: list[dict[str, Any]] = []

    def filter_log_events(self, **kwargs: Any) -> dict[str, Any]:
        """Return the next scripted response, recording the call."""
        self.calls.append(kwargs)
        index = min(len(self.calls) - 1, len(self.responses) - 1)
        return self.responses[index]


class TestParseEntry:
    """Tests for reading one access log line."""

    def test_reads_the_fields_the_assertions_use(self) -> None:
        """The request id, route key, path, method and statuses all land."""
        entry = parse_entry(line())
        assert entry is not None
        assert entry.request_id == "req-1"
        assert entry.route_key == "POST /api/build-lists"
        assert entry.path == "/api/build-lists"
        assert entry.method == "POST"
        assert entry.status == 201
        assert entry.integration_status == 201

    def test_an_explicit_route_key_counts_as_matched(self) -> None:
        """A declared route key means the gateway matched a route rather than answering itself."""
        entry = parse_entry(line())
        assert entry is not None
        assert entry.matched_a_route

    def test_the_default_route_key_does_not_count_as_matched(self) -> None:
        """`$default` is the gateway answering, which is the fall-through the cut must not hit."""
        entry = parse_entry(line(routeKey="$default"))
        assert entry is not None
        assert not entry.matched_a_route

    def test_a_catch_all_route_key_is_still_reported_verbatim(self) -> None:
        """A `{proxy+}` key is a real match, and the caller compares it against the expectation."""
        entry = parse_entry(line(routeKey="ANY /api/{proxy+}"))
        assert entry is not None
        assert entry.route_key == "ANY /api/{proxy+}"

    def test_an_integration_error_is_kept(self) -> None:
        """The integration error is what distinguishes a 500 from the gateway's own refusal."""
        entry = parse_entry(line(status="500", integrationErrorMessage="Internal server error"))
        assert entry is not None
        assert entry.integration_error == "Internal server error"

    def test_the_raw_payload_is_kept_for_a_failure_message(self) -> None:
        """A failing assertion prints the whole line, so nothing is lost in the parse."""
        entry = parse_entry(line(authorizerError="Unauthorized"))
        assert entry is not None
        assert entry.raw["authorizerError"] == "Unauthorized"

    @pytest.mark.parametrize("message", ["", "not json", "[]", '"a string"', "null"])
    def test_an_unparseable_line_is_skipped(self, message: str) -> None:
        """A line in another format is skipped, so it cannot lose the entry that follows it."""
        assert parse_entry(message) is None

    def test_a_line_with_no_request_id_is_skipped(self) -> None:
        """Without a request id there is nothing to correlate, so the line is not an entry."""
        assert parse_entry(json.dumps({"routeKey": "GET /api/parts"})) is None

    def test_a_missing_status_reads_as_zero_rather_than_raising(self) -> None:
        """A field the format omits is zero, so one stage's format change is not a crash."""
        entry = parse_entry(json.dumps({"requestId": "req-1"}))
        assert entry is not None
        assert entry.status == 0
        assert entry.route_key == ""


class TestLookupTiming:
    """Tests for the bounded wait around delivery lag."""

    def test_an_entry_present_on_the_first_read_returns_at_once(self) -> None:
        """No sleeping when the entry has already been delivered."""
        clock = Clock()
        lookup = AccessLogLookup(
            FakeLogs([{"events": [{"message": line()}]}]),
            LOG_GROUP,
            wait_seconds=0.0,
            sleeper=clock.sleep,
            clock=clock,
        )
        entry = lookup.find("req-1")
        assert entry is not None
        assert clock.now == 0.0

    def test_it_polls_until_the_entry_arrives(self) -> None:
        """Delivery is per stream and lags, so an empty first read is retried."""
        clock = Clock()
        lookup = AccessLogLookup(
            FakeLogs([{"events": []}, {"events": []}, {"events": [{"message": line()}]}]),
            LOG_GROUP,
            poll_seconds=5.0,
            sleeper=clock.sleep,
            clock=clock,
        )
        entry = lookup.find("req-1")
        assert entry is not None
        assert clock.now == 10.0

    def test_a_miss_inside_the_budget_returns_none(self) -> None:
        """A never-delivered entry is a miss, not an exception and not a routing verdict.

        The HTTP probe already proved the request reached the API, so the caller decides
        whether an undelivered log line is a failure for that particular assertion.
        """
        clock = Clock()
        lookup = AccessLogLookup(
            FakeLogs([{"events": []}]),
            LOG_GROUP,
            wait_seconds=20.0,
            poll_seconds=5.0,
            sleeper=clock.sleep,
            clock=clock,
        )
        assert lookup.find("req-1") is None
        assert clock.now == pytest.approx(20.0)

    def test_an_empty_request_id_never_calls_cloudwatch(self) -> None:
        """A response with no request id header is not worth a two minute wait."""
        client = FakeLogs([{"events": []}])
        lookup = AccessLogLookup(client, LOG_GROUP, wait_seconds=0.0)
        assert lookup.find("") is None
        assert client.calls == []

    def test_a_second_lookup_is_served_from_the_cache(self) -> None:
        """One read can deliver several entries, so the second id costs no extra call."""
        client = FakeLogs([{"events": [{"message": line()}, {"message": line(requestId="req-2")}]}])
        lookup = AccessLogLookup(client, LOG_GROUP, wait_seconds=0.0)
        assert lookup.find("req-1") is not None
        assert lookup.find("req-2") is not None
        assert len(client.calls) == 1

    def test_every_page_of_a_read_is_consumed(self) -> None:
        """A paged response is followed, since the wanted entry can be on the second page."""
        client = FakeLogs(
            [
                {"events": [{"message": line(requestId="other")}], "nextToken": "t1"},
                {"events": [{"message": line()}]},
            ]
        )
        lookup = AccessLogLookup(client, LOG_GROUP, wait_seconds=0.0)
        assert lookup.find("req-1") is not None
        assert client.calls[1]["nextToken"] == "t1"

    def test_the_request_id_is_the_filter_pattern_of_the_fallback(self) -> None:
        """Filtering server side keeps a busy stage's log group from being read whole.

        The fallback read is the one that filters. The group's own lookups scan the window
        the probes opened, which is the read that serves every id at once.
        """
        client = FakeLogs([{"events": [{"message": line()}]}])
        AccessLogLookup(client, LOG_GROUP, wait_seconds=0.0).find("req-1", start_time_ms=1_000)
        assert client.calls[0]["filterPattern"] == '"req-1"'
        assert client.calls[0]["logGroupName"] == LOG_GROUP


class TestAgainstCloudwatch:
    """Tests against moto's CloudWatch Logs backend, so the call shape is the real one."""

    def test_it_finds_an_entry_written_to_a_real_log_group(self) -> None:
        """The lookup works against a genuine `filter_log_events`, filter pattern included.

        The timestamps are current rather than fixed, because CloudWatch refuses events too
        far outside the retention window and a fixed literal would start being dropped once
        it aged past it.
        """
        now_ms = int(time.time() * 1000)
        with mock_aws():
            client = boto3.client("logs", region_name=REGION)
            client.create_log_group(logGroupName=LOG_GROUP)
            client.create_log_stream(logGroupName=LOG_GROUP, logStreamName="stream-1")
            client.put_log_events(
                logGroupName=LOG_GROUP,
                logStreamName="stream-1",
                logEvents=[
                    {"timestamp": now_ms, "message": line(requestId="other")},
                    {"timestamp": now_ms + 1, "message": line()},
                ],
            )
            lookup = AccessLogLookup(client, LOG_GROUP, wait_seconds=0.0)
            entry = lookup.find("req-1", start_time_ms=now_ms - 60_000)
            assert entry is not None
            assert entry.route_key == "POST /api/build-lists"

    def test_a_missing_entry_is_a_miss_not_an_error(self) -> None:
        """An id nothing logged returns None once the budget runs out."""
        clock = Clock()
        now_ms = int(time.time() * 1000)
        with mock_aws():
            client = boto3.client("logs", region_name=REGION)
            client.create_log_group(logGroupName=LOG_GROUP)
            lookup = AccessLogLookup(
                client,
                LOG_GROUP,
                wait_seconds=10.0,
                poll_seconds=5.0,
                sleeper=clock.sleep,
                clock=clock,
            )
            assert lookup.find("req-absent", start_time_ms=now_ms - 60_000) is None


class TestUnsetPlaceholder:
    """API Gateway renders an unset `$context` variable as `-`, which is not a value.

    The access log format names every field it wants, so the gateway always writes every
    field. One that has no value for this request is written as a literal `-`, and a healthy
    request therefore carries `"integrationErrorMessage":"-"`. Reading that as an error
    message fails the route cut assertion on exactly the requests that worked.
    """

    def test_a_dash_integration_error_reads_as_no_error(self) -> None:
        """A successful request logging `-` for its integration error has no error."""
        entry = parse_entry(line(integrationErrorMessage="-", integrationLatency="42"))
        assert entry is not None
        assert entry.integration_error == ""
        assert not entry.integration_error

    def test_a_real_integration_error_survives(self) -> None:
        """A genuine integration error message is still reported."""
        entry = parse_entry(line(integrationErrorMessage="Internal Server Error"))
        assert entry is not None
        assert entry.integration_error == "Internal Server Error"

    def test_a_dash_route_key_reads_as_no_route(self) -> None:
        """A request the gateway answered itself logs `-` for its route key."""
        entry = parse_entry(line(routeKey="-"))
        assert entry is not None
        assert entry.route_key == ""
        assert not entry.matched_a_route

    def test_a_dash_is_empty_for_every_string_field(self) -> None:
        """Path and method read `-` as empty too, not as a one-character value."""
        entry = parse_entry(line(path="-", httpMethod="-"))
        assert entry is not None
        assert entry.path == ""
        assert entry.method == ""

    def test_a_dash_request_id_is_not_an_entry(self) -> None:
        """An entry whose request id is the placeholder is unusable, so it is skipped."""
        assert parse_entry(line(requestId="-")) is None

    def test_a_dash_falls_through_to_the_next_key(self) -> None:
        """A field with alternates takes the first that is neither empty nor the placeholder."""
        entry = parse_entry(line(path="-", rawPath="/api/build-lists"))
        assert entry is not None
        assert entry.path == "/api/build-lists"

    def test_a_path_that_is_only_a_dash_segment_survives(self) -> None:
        """A real path merely containing a dash is untouched."""
        entry = parse_entry(line(path="/api/build-lists/a-b-c"))
        assert entry is not None
        assert entry.path == "/api/build-lists/a-b-c"


class TestWindowScan:
    """Tests for reading the whole delivery window instead of one request id at a time.

    The suite probes every live route up front and then asks for all of their entries, so
    one unfiltered scan of the window serves every id. Before this, 147 routes each waited
    out their own roughly half-minute delivery lag.
    """

    def test_a_scan_caches_every_entry_in_the_window(self) -> None:
        """One unfiltered read serves every id the probes produced."""
        client = FakeLogs(
            [
                {
                    "events": [
                        {"message": line()},
                        {"message": line(requestId="req-2")},
                        {"message": line(requestId="req-3")},
                    ]
                }
            ]
        )
        lookup = AccessLogLookup(client, LOG_GROUP, wait_seconds=0.0)
        assert lookup.scan_window() == 3
        assert len(client.calls) == 1
        assert "filterPattern" not in client.calls[0]

    def test_the_window_starts_before_the_first_probe(self) -> None:
        """The gateway timestamps an entry when it finishes, so the window takes a margin."""
        client = FakeLogs([{"events": []}])
        lookup = AccessLogLookup(client, LOG_GROUP, wait_seconds=0.0)
        lookup.open_window(1_000_000)
        lookup.scan_window()
        assert client.calls[0]["startTime"] == 1_000_000 - WINDOW_MARGIN_MILLISECONDS

    def test_the_earliest_probe_wins_a_second_window(self) -> None:
        """Opening the window twice keeps the earlier start, so no probe falls outside it."""
        client = FakeLogs([{"events": []}])
        lookup = AccessLogLookup(client, LOG_GROUP, wait_seconds=0.0)
        lookup.open_window(2_000_000)
        lookup.open_window(1_000_000)
        lookup.scan_window()
        assert client.calls[0]["startTime"] == 1_000_000 - WINDOW_MARGIN_MILLISECONDS

    def test_every_page_of_a_scan_is_consumed(self) -> None:
        """A window busier than one page is followed to its end."""
        client = FakeLogs(
            [
                {"events": [{"message": line()}], "nextToken": "t1"},
                {"events": [{"message": line(requestId="req-2")}]},
            ]
        )
        lookup = AccessLogLookup(client, LOG_GROUP, wait_seconds=0.0)
        assert lookup.scan_window() == 2
        assert client.calls[1]["nextToken"] == "t1"

    def test_find_scans_the_window_rather_than_filtering(self) -> None:
        """A lookup with no explicit window takes the scan, so the next id costs nothing."""
        client = FakeLogs([{"events": [{"message": line()}, {"message": line(requestId="req-2")}]}])
        lookup = AccessLogLookup(client, LOG_GROUP, wait_seconds=0.0)
        assert lookup.find("req-1") is not None
        assert lookup.find("req-2") is not None
        assert len(client.calls) == 1
        assert "filterPattern" not in client.calls[0]

    def test_one_delivery_lag_is_paid_for_the_whole_group(self) -> None:
        """The first miss waits; the entries that arrive with it are then free.

        This is the whole point of the change. The first id polls until delivery, and every
        id delivered in that same scan is served from the cache with no further wait.
        """
        clock = Clock()
        delivered = {
            "events": [{"message": line()}, {"message": line(requestId="req-2")}, {"message": line(requestId="req-3")}]
        }
        client = FakeLogs([{"events": []}, {"events": []}, delivered])
        lookup = AccessLogLookup(
            client,
            LOG_GROUP,
            poll_seconds=5.0,
            sleeper=clock.sleep,
            clock=clock,
        )
        assert lookup.find("req-1") is not None
        first_wait = clock.now
        assert lookup.find("req-2") is not None
        assert lookup.find("req-3") is not None
        assert clock.now == first_wait


class TestRescanThrottle:
    """Tests for the one-scan-per-poll-interval throttle shared by every caller.

    147 lookups that all miss must cost one CloudWatch read between them rather than one
    each, or batching the probes would just move the cost from sleeping to throttling.
    """

    def test_a_second_scan_inside_the_poll_interval_is_reused(self) -> None:
        """A scan that already ran within the poll interval is not repeated."""
        clock = Clock()
        client = FakeLogs([{"events": []}])
        lookup = AccessLogLookup(client, LOG_GROUP, poll_seconds=5.0, sleeper=clock.sleep, clock=clock)
        lookup.scan_window()
        lookup.scan_window()
        assert len(client.calls) == 1

    def test_a_scan_after_the_poll_interval_reads_again(self) -> None:
        """Past the interval the window is read again, since delivery may have caught up."""
        clock = Clock()
        client = FakeLogs([{"events": []}])
        lookup = AccessLogLookup(client, LOG_GROUP, poll_seconds=5.0, sleeper=clock.sleep, clock=clock)
        lookup.scan_window()
        clock.sleep(5.0)
        lookup.scan_window()
        assert len(client.calls) == 2

    def test_forcing_a_scan_ignores_the_throttle(self) -> None:
        """A caller that needs a fresh read can ask for one."""
        clock = Clock()
        client = FakeLogs([{"events": []}])
        lookup = AccessLogLookup(client, LOG_GROUP, poll_seconds=5.0, sleeper=clock.sleep, clock=clock)
        lookup.scan_window()
        lookup.scan_window(force=True)
        assert len(client.calls) == 2

    def test_a_run_of_misses_costs_one_read_between_them(self) -> None:
        """Several ids missing inside one poll interval share the one scan."""
        clock = Clock()
        client = FakeLogs([{"events": []}])
        lookup = AccessLogLookup(
            client, LOG_GROUP, wait_seconds=0.0, poll_seconds=5.0, sleeper=clock.sleep, clock=clock
        )
        for index in range(10):
            assert lookup.find(f"req-{index}") is None
        assert len(client.calls) == 1

    def test_a_miss_inside_the_budget_is_still_a_miss(self) -> None:
        """The throttle does not turn a never-delivered entry into anything but None."""
        clock = Clock()
        client = FakeLogs([{"events": []}])
        lookup = AccessLogLookup(
            client, LOG_GROUP, wait_seconds=20.0, poll_seconds=5.0, sleeper=clock.sleep, clock=clock
        )
        assert lookup.find("req-1") is None
        assert clock.now == pytest.approx(20.0)


class TestFilteredFallback:
    """Tests for the per-request-id read kept for a lookup outside the window."""

    def test_an_explicit_window_takes_the_filtered_read(self) -> None:
        """A caller naming its own start time is a one-off diagnostic, not the group."""
        client = FakeLogs([{"events": [{"message": line()}]}])
        lookup = AccessLogLookup(client, LOG_GROUP, wait_seconds=0.0)
        assert lookup.find("req-1", start_time_ms=1_000) is not None
        assert client.calls[0]["filterPattern"] == '"req-1"'
        assert client.calls[0]["startTime"] == 1_000

    def test_read_one_can_be_called_directly(self) -> None:
        """The narrow read stays available for a single lookup outside the window."""
        client = FakeLogs([{"events": [{"message": line()}]}])
        lookup = AccessLogLookup(client, LOG_GROUP, wait_seconds=0.0)
        entry = lookup.read_one("req-1")
        assert entry is not None
        assert client.calls[0]["filterPattern"] == '"req-1"'

    def test_the_filtered_read_fills_the_same_cache(self) -> None:
        """An id found by the fallback is not read twice."""
        client = FakeLogs([{"events": [{"message": line()}]}])
        lookup = AccessLogLookup(client, LOG_GROUP, wait_seconds=0.0)
        lookup.read_one("req-1")
        assert lookup.find("req-1") is not None
        assert len(client.calls) == 1

    def test_the_cached_ids_are_reportable(self) -> None:
        """A diagnostic can ask what the window delivered without reading it again."""
        client = FakeLogs([{"events": [{"message": line()}, {"message": line(requestId="req-2")}]}])
        lookup = AccessLogLookup(client, LOG_GROUP, wait_seconds=0.0)
        lookup.scan_window()
        assert lookup.cached_ids == frozenset({"req-1", "req-2"})
