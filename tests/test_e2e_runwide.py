"""Tests for the two whole-run checks reaching the same verdict in both scheduling modes.

The run-wide groups measure the run rather than one request, and there are two ways a run
can hand them the whole run. A serial run orders them last, so the record list is complete
when they read it. A distributed run cannot run them as tests at all, because every other
worker is still sending requests, so each worker writes its records out and the controller
reaches the verdicts once they have all finished.

The property worth protecting is that the two modes cannot drift. Both call the same check
functions, and the tests below assert the messages rather than the mechanism, so a change to
one path that did not reach the other would fail here.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from webbpulse.e2e import RUN_WIDE_GROUPS, runwide
from webbpulse.e2e.access_log import AccessLogEntry
from webbpulse.e2e.client import RequestRecord, recorded_path
from webbpulse.e2e.coverage import measure_coverage

pytest_plugins = ["pytester"]


def record(
    *,
    method: str = "GET",
    path: str = "/api/issues",
    request_id: str = "req-1",
) -> RequestRecord:
    """One recorded request, as a worker's client would hold it."""
    return RequestRecord(method=method, path=path, status=200, request_id=request_id)


def entry(
    *,
    status: int = 200,
    integration_status: int = 200,
    route_key: str = "GET /api/issues",
    method: str = "GET",
    raw: Mapping[str, Any] | None = None,
) -> AccessLogEntry:
    """One access log entry, healthy unless a test says otherwise."""
    return AccessLogEntry(
        request_id="req-1",
        route_key=route_key,
        path="/api/issues",
        method=method,
        status=status,
        integration_status=integration_status,
        integration_error="",
        raw={"integrationErrorMessage": "-"} if raw is None else raw,
    )


class FakeOption:
    """The slice of `config.option` the xdist detection reads."""

    def __init__(self, numprocesses: int | None) -> None:
        """Hold the parsed `-n` value, which is None when it was never passed."""
        self.numprocesses = numprocesses


class FakeConfig:
    """A `pytest.Config` stand-in carrying only what the run-wide plumbing reads."""

    def __init__(
        self,
        *,
        numprocesses: int | None = None,
        workerid: str | None = None,
    ) -> None:
        """Hold the parsed options, and `workerinput` only when this stands for a worker."""
        self.option = FakeOption(numprocesses)
        if workerid is not None:
            self.workerinput = {"workerid": workerid}


class TestWorkerAndControllerAreToldApart:
    """The whole design turns on which process this is, so the test is worth being explicit."""

    def test_a_serial_run_is_neither(self) -> None:
        """No `-n` and no `workerinput` is the serial run that orders the groups last."""
        config = FakeConfig()
        assert runwide.xdist_worker(config) == ""
        assert not runwide.xdist_is_active(config)

    def test_a_worker_is_recognised_by_workerinput(self) -> None:
        """`workerinput` is set on a worker's config and never on the controller's."""
        config = FakeConfig(numprocesses=4, workerid="gw2")
        assert runwide.xdist_worker(config) == "gw2"
        assert runwide.xdist_is_active(config)

    def test_a_controller_has_the_option_but_no_workerinput(self) -> None:
        """The controller is the one process that is distributed and holds no requests."""
        config = FakeConfig(numprocesses=4)
        assert runwide.xdist_worker(config) == ""
        assert runwide.xdist_is_active(config)

    def test_xdist_installed_but_unused_stays_serial(self) -> None:
        """Having xdist importable is not asking for it, and a serial run runs the groups."""
        assert not runwide.xdist_is_active(FakeConfig(numprocesses=0))


class TestTheWorkerFile:
    """Each worker writes its own requests where the controller can read them."""

    def test_a_worker_writes_its_records(self, tmp_path: Path) -> None:
        """The file is named for the worker and holds the three fields the checks read."""
        directory = runwide.run_directory("run-1", base=str(tmp_path))
        written = runwide.write_worker_records(directory, "gw0", [record(path="/api/a")])
        assert written.name == "gw0.json"
        payload = json.loads(written.read_text(encoding="utf-8"))
        assert payload == [{"method": "GET", "path": "/api/a", "request_id": "req-1"}]

    def test_the_directory_is_keyed_on_the_run_id(self, tmp_path: Path) -> None:
        """Two runs on one host never read each other's records."""
        first = runwide.run_directory("run-1", base=str(tmp_path))
        second = runwide.run_directory("run-2", base=str(tmp_path))
        assert first != second
        assert first.name.endswith("run-1")

    def test_every_workers_records_are_read_back(self, tmp_path: Path) -> None:
        """The controller sees the union, which is the whole run and what no worker has."""
        directory = runwide.run_directory("run-1", base=str(tmp_path))
        runwide.write_worker_records(directory, "gw0", [record(path="/api/a")])
        runwide.write_worker_records(directory, "gw1", [record(path="/api/b")])
        paths = [request.path for request in runwide.read_worker_records(directory)]
        assert sorted(paths) == ["/api/a", "/api/b"]

    def test_an_unreadable_file_costs_only_its_own_records(self, tmp_path: Path) -> None:
        """One worker's lost file must not hide every other verdict behind an exception."""
        directory = runwide.run_directory("run-1", base=str(tmp_path))
        runwide.write_worker_records(directory, "gw0", [record(path="/api/a")])
        (directory / "gw1.json").write_text("{not json", encoding="utf-8")
        assert [request.path for request in runwide.read_worker_records(directory)] == ["/api/a"]

    def test_a_missing_directory_reads_as_no_requests(self, tmp_path: Path) -> None:
        """Nothing written is no requests, which the coverage check reports as a broken suite."""
        assert runwide.read_worker_records(runwide.run_directory("gone", base=str(tmp_path))) == ()

    def test_the_run_directory_is_cleaned_up(self, tmp_path: Path) -> None:
        """The controller removes what it has read, so a host does not accumulate runs."""
        directory = runwide.run_directory("run-1", base=str(tmp_path))
        runwide.write_worker_records(directory, "gw0", [record()])
        runwide.remove_run_directory(directory)
        assert not directory.exists()

    def test_cleaning_up_twice_is_harmless(self, tmp_path: Path) -> None:
        """Cleanup never raises, because a tidy-up failure must not fail a run."""
        runwide.remove_run_directory(runwide.run_directory("gone", base=str(tmp_path)))


class TestControllerAggregation:
    """The controller reaches the verdicts from every worker's file at once."""

    def _directory(self, tmp_path: Path) -> Path:
        """Two worker files: one clean, one carrying a request with a failing shape."""
        directory = runwide.run_directory("run-1", base=str(tmp_path))
        runwide.write_worker_records(directory, "gw0", [record(path="/api/issues", request_id="req-1")])
        runwide.write_worker_records(directory, "gw1", [record(path="/api/health", request_id="req-2")])
        return directory

    def test_coverage_is_measured_across_both_workers(self, tmp_path: Path) -> None:
        """Neither worker covers both routes, and together they cover both.

        This is the failure the whole change exists to prevent: run on one worker, the
        coverage check reports the other worker's route as never exercised.
        """
        requests = runwide.read_worker_records(self._directory(tmp_path))
        served = [("GET", "/api/issues"), ("GET", "/api/health")]
        coverage = runwide.coverage_for(served, requests, {})
        assert coverage.uncovered == ()

    def test_one_workers_requests_alone_would_report_a_gap(self, tmp_path: Path) -> None:
        """The same measurement over one worker's share is what the old code did."""
        directory = self._directory(tmp_path)
        (directory / "gw1.json").unlink()
        requests = runwide.read_worker_records(directory)
        served = [("GET", "/api/issues"), ("GET", "/api/health")]
        coverage = runwide.coverage_for(served, requests, {})
        assert coverage.uncovered == (("GET", "/api/health"),)

    def test_a_failing_access_log_shape_is_reported(self, tmp_path: Path) -> None:
        """A 5xx on either worker's requests makes the run-wide verdict fail."""
        requests = runwide.read_worker_records(self._directory(tmp_path))
        served = [("GET", "/api/issues"), ("GET", "/api/health")]
        verdicts = runwide.controller_verdicts(
            requests,
            [entry(), entry(status=502)],
            runwide.coverage_for(served, requests, {}),
            {},
        )
        assert verdicts.failed
        assert any("answered 5xx" in failure for failure in verdicts.failures)

    def test_a_clean_run_reaches_no_failure(self, tmp_path: Path) -> None:
        """Both workers clean and every served route covered is a passing verdict."""
        requests = runwide.read_worker_records(self._directory(tmp_path))
        served = [("GET", "/api/issues"), ("GET", "/api/health")]
        verdicts = runwide.controller_verdicts(
            requests,
            [entry()],
            runwide.coverage_for(served, requests, {}),
            {},
        )
        assert not verdicts.failed
        assert verdicts.failures == ()

    def test_an_unset_log_group_skips_only_the_sweep(self, tmp_path: Path) -> None:
        """Coverage is still measured where there is no access log to read."""
        requests = runwide.read_worker_records(self._directory(tmp_path))
        verdicts = runwide.controller_verdicts(
            requests,
            None,
            runwide.coverage_for([("GET", "/api/issues")], requests, {}),
            {},
            access_log_note="E2E_ACCESS_LOG_GROUP is unset, so the access log sweep was not made.",
        )
        assert not verdicts.failed
        assert any("E2E_ACCESS_LOG_GROUP is unset" in note for note in verdicts.notes)

    def test_an_uncovered_route_fails_the_verdict(self, tmp_path: Path) -> None:
        """A served route nothing reached is the coverage failure, named in the message."""
        requests = runwide.read_worker_records(self._directory(tmp_path))
        served = [("GET", "/api/issues"), ("GET", "/api/health"), ("POST", "/api/issues")]
        verdicts = runwide.controller_verdicts(
            requests,
            [entry()],
            runwide.coverage_for(served, requests, {}),
            {},
        )
        assert verdicts.failed
        assert any("POST /api/issues" in failure for failure in verdicts.failures)

    def test_a_stale_allowlist_entry_fails_the_verdict(self, tmp_path: Path) -> None:
        """The staleness check runs on the controller exactly as it does as a test."""
        requests = runwide.read_worker_records(self._directory(tmp_path))
        allowlist = {("GET", "/api/gone"): "was never built"}
        verdicts = runwide.controller_verdicts(
            requests,
            [entry()],
            runwide.coverage_for([("GET", "/api/issues"), ("GET", "/api/health")], requests, allowlist),
            allowlist,
        )
        assert verdicts.failed
        assert any("does not serve" in failure for failure in verdicts.failures)

    def test_an_allowlist_entry_with_no_reason_fails_the_verdict(self, tmp_path: Path) -> None:
        """The reason check runs on the controller too, so neither mode excuses an entry."""
        requests = runwide.read_worker_records(self._directory(tmp_path))
        allowlist = {("GET", "/api/issues"): "  "}
        verdicts = runwide.controller_verdicts(
            requests,
            [entry()],
            runwide.coverage_for([("GET", "/api/issues"), ("GET", "/api/health")], requests, allowlist),
            allowlist,
        )
        assert verdicts.failed
        assert any("carry no reason" in failure for failure in verdicts.failures)

    def test_an_empty_sweep_fails_on_the_controller(self, tmp_path: Path) -> None:
        """The vacuous-pass guard is the controller's too, not only the test method's."""
        requests = runwide.read_worker_records(self._directory(tmp_path))
        verdicts = runwide.controller_verdicts(
            requests,
            [],
            runwide.coverage_for([("GET", "/api/issues"), ("GET", "/api/health")], requests, {}),
            {},
        )
        assert verdicts.failed
        assert any("none of this run's 2 requests" in failure for failure in verdicts.failures)


class TestTheTwoModesCannotDrift:
    """Every message a test method asserts is the one the controller prints."""

    def test_the_shapes_share_one_message(self) -> None:
        """The check functions are the only place each verdict's words live."""
        assert runwide.no_request_was_answered_with_a_server_error([entry(status=502)]) is not None
        assert runwide.no_request_was_answered_with_a_server_error([entry()]) is None

    def test_a_product_rejection_is_not_the_authorizer(self) -> None:
        """A 401 the function itself returned is the product refusing, in both modes."""
        assert runwide.no_rejection_came_from_a_healthy_integration([entry(status=401, integration_status=401)]) is None
        assert runwide.no_rejection_came_from_a_healthy_integration([entry(status=401)]) is not None

    def test_a_preflight_needs_no_route_key(self) -> None:
        """`OPTIONS` is answered by the CORS configuration, in both modes."""
        assert runwide.every_request_matched_a_declared_route([entry(route_key="", method="OPTIONS")]) is None
        assert runwide.every_request_matched_a_declared_route([entry(route_key="")]) is not None

    def test_the_unset_placeholder_is_not_an_error(self) -> None:
        """The gateway's literal `-` is not an integration error, in both modes."""
        assert runwide.no_integration_reported_an_error([entry(raw={"errorMessage": "-"})]) is None
        assert runwide.no_integration_reported_an_error([entry(raw={"errorMessage": "boom"})]) is not None

    def test_the_suite_methods_call_the_shared_checks(self) -> None:
        """The test methods assert on the same functions, so a message cannot fork."""
        from webbpulse.e2e import suite

        with pytest.raises(AssertionError, match="answered 5xx"):
            suite.TestAccessLogHealth().test_no_request_was_answered_with_a_server_error([entry(status=502)])
        with pytest.raises(AssertionError, match="POST /api/issues"):
            suite.TestRouteCoverage().test_every_served_route_was_exercised_or_is_allowlisted(
                measure_coverage([("POST", "/api/issues")], [])
            )


class TestRecordedPathHasNoQuery:
    """The coverage matcher takes a path, and a template never carries a query."""

    def test_a_query_string_is_stripped(self) -> None:
        """A path recorded with its query would match no served template."""
        assert recorded_path("/api/issues?limit=10") == "/api/issues"

    def test_a_fragment_is_stripped(self) -> None:
        """A fragment never reaches a server and must not reach the matcher either."""
        assert recorded_path("/api/issues#section") == "/api/issues"

    def test_a_plain_path_is_untouched(self) -> None:
        """The common case is unchanged, so no existing record moves."""
        assert recorded_path("/api/issues/123") == "/api/issues/123"

    def test_an_inline_query_still_counts_as_coverage(self) -> None:
        """The whole point: the request covers the route it actually reached."""
        coverage = measure_coverage(
            [("GET", "/api/issues")],
            [("GET", recorded_path("/api/issues?limit=10"))],
        )
        assert coverage.uncovered == ()
        assert coverage.unmatched == ()


RUN_WIDE_CONFTEST = """
import os

for _name, _value in {environment}.items():
    os.environ[_name] = _value

pytest_plugins = ["webbpulse.e2e"]
"""

RUN_WIDE_CASES = """
class TestRouteCut:
    def test_probe_one(self):
        assert True

    def test_probe_two(self):
        assert True


class TestAccessLogHealth:
    def test_the_access_log_carries_this_runs_requests(self):
        assert True

    def test_no_request_was_answered_with_a_server_error(self):
        assert True


class TestRouteCoverage:
    def test_every_served_route_was_exercised_or_is_allowlisted(self):
        assert True


def test_zzz_a_product_case_sorting_after_the_shared_file():
    assert True
"""

STAGING = {
    "E2E_ENVIRONMENT": "staging",
    "E2E_API_BASE_URL": "https://api.example.test",
    "E2E_WEB_BASE_URL": "https://example.test",
    "E2E_AWS_REGION": "us-west-2",
    "E2E_API_ID": "abc123",
    "E2E_ACCESS_LOG_GROUP": "/aws/apigateway/example",
    "E2E_RUN_ID": "run-ordering-1",
    "E2E_READ_ONLY": "1",
    "E2E_GATE_SSM_PARAMETER": "/example/staging/origin-verify",
}


def _run(pytester: pytest.Pytester, *args: str, environment: Mapping[str, str] = STAGING) -> pytest.RunResult:
    """Run one pytester session with the environment applied and the plugin enabled."""
    pytester.makeconftest(RUN_WIDE_CONFTEST.replace("{environment}", repr(dict(environment))))
    pytester.makepyfile(test_aaa_shared=RUN_WIDE_CASES)
    return pytester.runpytest_inprocess("-p", "no:cacheprovider", "-v", *args)


def _order(result: pytest.RunResult) -> Sequence[str]:
    """The case names in the order the run reported them."""
    names = []
    for line in result.outlines:
        if "::" not in line:
            continue
        for outcome in ("PASSED", "SKIPPED", "FAILED"):
            if f" {outcome}" in line:
                names.append(line.split("::")[-1].split(" ")[0])
                break
    return names


class TestSerialOrdering:
    """A serial run moves both groups to the end, so the record list is complete."""

    def test_the_run_wide_groups_run_last(self, pytester: pytest.Pytester) -> None:
        """Every other case, including a product file sorting after the shared one, runs first."""
        order = _order(_run(pytester))
        run_wide = [
            "test_the_access_log_carries_this_runs_requests",
            "test_no_request_was_answered_with_a_server_error",
            "test_every_served_route_was_exercised_or_is_allowlisted",
        ]
        assert order[-3:] == run_wide
        assert "test_zzz_a_product_case_sorting_after_the_shared_file" in order[:-3]

    def test_health_runs_before_coverage(self, pytester: pytest.Pytester) -> None:
        """The order between the two groups is the one the report has always read in."""
        order = _order(_run(pytester))
        assert order.index("test_no_request_was_answered_with_a_server_error") < order.index(
            "test_every_served_route_was_exercised_or_is_allowlisted"
        )

    def test_the_groups_stay_tests(self, pytester: pytest.Pytester) -> None:
        """Reordering, not deselecting: the report still names each case."""
        result = _run(pytester)
        result.assert_outcomes(passed=6)

    def test_the_group_names_are_the_ones_reordered(self) -> None:
        """The constant the ordering reads is the two class names, and nothing else."""
        assert RUN_WIDE_GROUPS == ("TestAccessLogHealth", "TestRouteCoverage")


class TestWorkerSkipping:
    """Under xdist the groups cannot run as tests, so they skip with the reason why."""

    def test_both_groups_skip_on_a_worker(self, pytester: pytest.Pytester) -> None:
        """A real distributed run, so the skip is asserted through xdist's own scheduling."""
        result = _run(pytester, "-n", "2", "--dist", "loadgroup")
        result.assert_outcomes(passed=3, skipped=3)

    def test_the_skip_reason_names_the_controller(self, pytester: pytest.Pytester) -> None:
        """A skip that does not say where the check is made instead reads as a check lost."""
        result = _run(pytester, "-n", "2", "--dist", "loadgroup", "-rs")
        result.stdout.fnmatch_lines(["*run-wide checks are made on the controller*"])

    def test_a_serial_run_skips_neither(self, pytester: pytest.Pytester) -> None:
        """The skip is the distributed mode's alone: serially the groups still run."""
        _run(pytester).assert_outcomes(passed=6)
