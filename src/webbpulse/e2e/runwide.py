"""The whole-run checks, and the two ways a run arrives at them.

`TestAccessLogHealth` and `TestRouteCoverage` ask about the run rather than about one
request, so both need every request the run made. A serial run has them: one process holds
one record list, and the plugin orders these two groups last so the list is complete when
they read it. A distributed run does not. Session fixtures under xdist are per worker, so a
group scheduled onto a worker sees that worker's requests and none of the others', and
`--dist loadgroup` is free to put it anywhere.

Rather than hold the whole run on one worker, which would serialise the part of the suite
xdist exists to spread, each worker writes its own records to a file at `pytest_sessionfinish`
and the controller reads all of them once every worker has finished. The controller is the
only process that ever sees the whole run, so it is where the run-wide verdicts are reached.

Every check is a function here returning a failure message or None, and both paths call the
same ones: the test methods in `suite.py` assert on them, and the controller prints them.
Two modes reaching the same verdict by two copies of the logic is exactly the drift this
module exists to prevent.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol

from .access_log import AccessLogEntry, log_field
from .coverage import RouteCoverage, measure_coverage

__all__ = [
    "RUN_DIRECTORY_PREFIX",
    "WORKER_SKIP_REASON",
    "RecordedRequest",
    "RunWideVerdicts",
    "controller_verdicts",
    "describe_entries",
    "every_request_matched_a_declared_route",
    "every_served_route_was_exercised_or_is_allowlisted",
    "no_integration_reported_an_error",
    "no_rejection_came_from_a_healthy_integration",
    "no_request_was_answered_with_a_server_error",
    "read_worker_records",
    "remove_run_directory",
    "run_directory",
    "the_access_log_carries_this_runs_requests",
    "the_allowlist_carries_reasons",
    "the_allowlist_is_not_stale",
    "the_run_recorded_requests_to_correlate",
    "write_worker_records",
]

RUN_DIRECTORY_PREFIX: Final = "webbpulse-e2e-run-"

WORKER_SKIP_REASON: Final = (
    "the run-wide checks are made on the controller once every worker has finished. Under "
    "xdist this worker holds only its own requests, so a verdict reached here would be "
    "about a fraction of the run. Each worker writes its requests at session finish and the "
    "controller reports the whole run in the terminal summary."
)


class RequestLike(Protocol):
    """The slice of `RequestRecord` the run-wide checks read."""

    @property
    def method(self) -> str:
        """The HTTP method."""
        ...

    @property
    def path(self) -> str:
        """The request path, without a query string."""
        ...

    @property
    def request_id(self) -> str:
        """The gateway request id, empty when the response carried none."""
        ...


@dataclass(frozen=True)
class RecordedRequest:
    """One request read back from a worker's file.

    A worker's `RequestRecord` carries more than the run-wide checks need, and the file is
    the boundary between two processes, so only the three fields both checks read cross it.
    """

    method: str
    path: str
    request_id: str


def run_directory(run_id: str, *, base: str | None = None) -> Path:
    """The directory the workers of one run write their records into.

    Keyed on `E2E_RUN_ID`, which every worker already shares through the environment, so two
    runs on one host never read each other's records. The base is the system temporary
    directory rather than xdist's `basetemp`: `basetemp` is removed between runs and its
    layout is xdist's own, while the run id already makes the name unique and the controller
    removes the directory itself once it has read it.
    """
    root = Path(tempfile.gettempdir()) if base is None else Path(base)
    return root / f"{RUN_DIRECTORY_PREFIX}{run_id}"


def write_worker_records(
    directory: Path,
    worker: str,
    requests: Iterable[RequestLike],
) -> Path:
    """Write one worker's requests to its own file, returning the path written.

    One file per worker rather than one shared file, so no worker ever writes where another
    is writing and the controller needs no lock to read them. Written to a temporary name in
    the same directory and then renamed, so the controller can never read a half-written
    file even though it only reads after every worker has finished.
    """
    directory.mkdir(parents=True, exist_ok=True)
    payload = [
        {"method": request.method, "path": request.path, "request_id": request.request_id} for request in requests
    ]
    target = directory / f"{worker}.json"
    staging = directory / f".{worker}.json.tmp"
    staging.write_text(json.dumps(payload), encoding="utf-8")
    staging.replace(target)
    return target


def read_worker_records(directory: Path) -> tuple[RecordedRequest, ...]:
    """Every request every worker of this run recorded, in worker order.

    A file that is missing, unreadable or not the shape this module writes is skipped rather
    than raising: the controller's job is to report the run, and losing one worker's records
    is better reported as the coverage gap it produces than as an exception that hides every
    other verdict.
    """
    if not directory.is_dir():
        return ()
    records: list[RecordedRequest] = []
    for path in sorted(directory.glob("*.json")):
        records.extend(_records_in(path))
    return tuple(records)


def _records_in(path: Path) -> Iterator[RecordedRequest]:
    """The records one worker file holds, or nothing when it cannot be read."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    if not isinstance(payload, list):
        return
    for item in payload:
        if not isinstance(item, Mapping):
            continue
        yield RecordedRequest(
            method=str(item.get("method", "")),
            path=str(item.get("path", "")),
            request_id=str(item.get("request_id", "")),
        )


def remove_run_directory(directory: Path) -> None:
    """Delete the run directory and everything in it, never raising.

    Called by the controller once it has read every worker file. A failure to clean up is
    not worth failing a run over: the directory carries paths and request ids and nothing
    secret, and the next run writes under a different run id.
    """
    if not directory.is_dir():
        return
    for path in directory.iterdir():
        try:
            path.unlink()
        except OSError:
            continue
    try:
        directory.rmdir()
    except OSError:
        return


def the_access_log_carries_this_runs_requests(
    requests: Sequence[RequestLike],
    entries: Sequence[AccessLogEntry],
) -> str | None:
    """Whether the sweep correlated anything, so the checks below it prove something.

    Returns None when the run recorded no request ids at all, which is no evidence either
    way rather than a failure, and the caller reports that as a skip.
    """
    attempted = [request for request in requests if request.request_id]
    if not attempted:
        return None
    if entries:
        return None
    return (
        f"none of this run's {len(attempted)} requests were found in the access log. "
        "Either the log group is not the one this stage writes to, or delivery is "
        "lagging further than the scan window. The sweep below would pass on an empty "
        "set, so it is reported here as a failure rather than as a clean sweep."
    )


def no_request_was_answered_with_a_server_error(entries: Sequence[AccessLogEntry]) -> str | None:
    """Whether any request this run made was answered 5xx."""
    failures = [entry for entry in entries if entry.status >= 500]
    if not failures:
        return None
    return "requests answered 5xx:\n" + describe_entries(failures)


def no_rejection_came_from_a_healthy_integration(entries: Sequence[AccessLogEntry]) -> str | None:
    """Whether any 401 or 403 was logged against an integration that answered 200."""
    rejected = [entry for entry in entries if entry.status in (401, 403) and entry.integration_status == 200]
    if not rejected:
        return None
    return (
        "requests the authorizer rejected although the integration answered 200:\n"
        + describe_entries(rejected)
        + "\nThe function never saw these. This is the authorizer or the gate refusing, "
        "not the product."
    )


def every_request_matched_a_declared_route(entries: Sequence[AccessLogEntry]) -> str | None:
    """Whether any request fell through without matching a declared route key."""
    unmatched = [entry for entry in entries if not entry.matched_a_route and entry.method.upper() != "OPTIONS"]
    if not unmatched:
        return None
    return (
        "requests that matched no declared route key:\n"
        + describe_entries(unmatched)
        + "\nThe gateway answered these itself, so the path reaches no function at all."
    )


def no_integration_reported_an_error(entries: Sequence[AccessLogEntry]) -> str | None:
    """Whether any entry carries an integration error message."""
    errored = [
        (entry, message)
        for entry in entries
        if (message := log_field(entry.raw, "errorMessage", "integrationErrorMessage"))
    ]
    if not errored:
        return None
    return "requests whose integration reported an error:\n" + "\n".join(
        f"  {entry.method} {entry.path} ({entry.request_id}): {message}" for entry, message in errored
    )


def the_run_recorded_requests_to_correlate(requests: Sequence[RequestLike]) -> str | None:
    """Whether this run made any request at all, so coverage is measured against something."""
    if requests:
        return None
    return (
        "this run recorded no requests at all, so coverage cannot be measured. Every "
        "route would report as uncovered, which would be a broken suite rather than a "
        "real gap."
    )


def every_served_route_was_exercised_or_is_allowlisted(coverage: RouteCoverage) -> str | None:
    """Whether every served operation was either reached or knowingly excused."""
    if not coverage.uncovered:
        return None
    return (
        f"{len(coverage.uncovered)} served routes were never exercised by this run:\n"
        + "\n".join(f"  {method} {path}" for method, path in coverage.uncovered)
        + "\nAdd a case that reaches each, or name it in pytest_e2e_uncovered_routes with "
        "the reason it is not worth covering."
    )


def the_allowlist_is_not_stale(coverage: RouteCoverage) -> str | None:
    """Whether any allowlist entry names a route the deployment no longer serves."""
    if not coverage.stale:
        return None
    return (
        "pytest_e2e_uncovered_routes names routes this deployment does not serve:\n"
        + "\n".join(f"  {method} {path}" for method, path in coverage.stale)
        + "\nRemove them: the gap they excused is gone."
    )


def the_allowlist_carries_reasons(allowlist: Mapping[tuple[str, str], str]) -> str | None:
    """Whether every allowlisted route says why it is excused."""
    unexplained = sorted(pair for pair, reason in allowlist.items() if not str(reason).strip())
    if not unexplained:
        return None
    return (
        "these allowlist entries carry no reason:\n"
        + "\n".join(f"  {method} {path}" for method, path in unexplained)
        + "\nAn exception with no reason cannot be reviewed or retired."
    )


def describe_entries(entries: Sequence[AccessLogEntry]) -> str:
    """One indented line per entry, naming what the gateway logged about it."""
    return "\n".join(
        f"  {entry.method} {entry.path} status={entry.status} "
        f"integration={entry.integration_status} route_key={entry.route_key or '(none)'} "
        f"({entry.request_id})"
        for entry in entries
    )


@dataclass(frozen=True)
class RunWideVerdicts:
    """What the controller concluded about the whole run.

    `failures` is what makes the job red and `notes` is what it says about checks it could
    not make, such as an access log sweep skipped for want of a log group. A note never
    fails the run: the reasons a sweep is skipped are configuration the run already knows
    about, and turning them into failures would make a local or production run red for
    doing exactly what it was asked to do.
    """

    failures: tuple[str, ...]
    notes: tuple[str, ...]

    @property
    def failed(self) -> bool:
        """Whether any run-wide check reached a failing verdict."""
        return bool(self.failures)


def controller_verdicts(
    requests: Sequence[RequestLike],
    entries: Sequence[AccessLogEntry] | None,
    coverage: RouteCoverage,
    allowlist: Mapping[tuple[str, str], str],
    *,
    access_log_note: str = "",
) -> RunWideVerdicts:
    """Every run-wide verdict for the whole run, in the order the test groups make them.

    `entries` is None when the access log was not swept, which is what an unset
    `E2E_ACCESS_LOG_GROUP` produces, and `access_log_note` then says why. The coverage
    verdicts are reached either way, because they need only the requests.
    """
    failures: list[str] = []
    notes: list[str] = []

    if entries is None:
        if access_log_note:
            notes.append(access_log_note)
    else:
        vacuous = the_access_log_carries_this_runs_requests(requests, entries)
        if vacuous is not None:
            failures.append(vacuous)
        elif not any(request.request_id for request in requests):
            notes.append("this run recorded no request ids, so there was nothing to correlate")
        for check in (
            no_request_was_answered_with_a_server_error,
            no_rejection_came_from_a_healthy_integration,
            every_request_matched_a_declared_route,
            no_integration_reported_an_error,
        ):
            message = check(entries)
            if message is not None:
                failures.append(message)

    for coverage_message in (
        the_run_recorded_requests_to_correlate(requests),
        every_served_route_was_exercised_or_is_allowlisted(coverage),
        the_allowlist_is_not_stale(coverage),
        the_allowlist_carries_reasons(allowlist),
    ):
        if coverage_message is not None:
            failures.append(coverage_message)

    return RunWideVerdicts(failures=tuple(failures), notes=tuple(notes))


def coverage_for(
    served: Iterable[tuple[str, str]],
    requests: Sequence[RequestLike],
    allowlist: Mapping[tuple[str, str], str],
) -> RouteCoverage:
    """This run's coverage of the served operations, measured the way the fixture measures it."""
    return measure_coverage(served, [(request.method, request.path) for request in requests], allowlist)


def normalise_allowlist(declared: Any) -> dict[tuple[str, str], str]:
    """A product's declared allowlist with methods uppercased, or empty when it declares none.

    Shared by the `uncovered_routes` fixture and the controller, so a method a product
    spells in lowercase matches a served route in both modes.
    """
    if not declared:
        return {}
    return {(str(method).upper(), str(path)): str(reason) for (method, path), reason in dict(declared).items()}


def xdist_worker(config: Any) -> str:
    """This process's xdist worker id, or empty when it is not a worker.

    A worker is recognised by `workerinput`, which xdist sets on the worker's own config and
    never on the controller's. That is the distinction the run-wide checks turn on: the
    controller of a distributed run has no requests of its own and every worker has only
    part of the run.
    """
    workerinput = getattr(config, "workerinput", None)
    if not isinstance(workerinput, Mapping):
        return ""
    return str(workerinput.get("workerid", "") or "")


def xdist_is_active(config: Any) -> bool:
    """Whether this run is distributed across workers at all.

    Read from the parsed `-n`/`--numprocesses` option rather than from the presence of the
    xdist plugin, because xdist installed and not asked for leaves the run serial, and a
    serial run is the one mode where the groups can run as tests.
    """
    if xdist_worker(config):
        return True
    option = getattr(config, "option", None)
    numprocesses = getattr(option, "numprocesses", None)
    return numprocesses not in (None, 0)


def run_id_from_environ(environ: Mapping[str, str] | None = None) -> str:
    """This run's id, which keys the directory the workers share."""
    source = os.environ if environ is None else environ
    return source.get("E2E_RUN_ID", "").strip()
