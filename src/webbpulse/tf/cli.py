"""`wp-tf`: start a plan-only run from a directory and stream its log, like a remote `terraform plan`.

    terraform login terraform.webbpulse.com
    wp-tf plan -w platform-staging
    wp-tf plan ./infra -w ws-01M3G00GJ5VPVR3QDJV8HNBQX1 --detailed-exitcode
    wp-tf logs run-01M3... --phase plan --follow
    wp-tf status run-01M3...
    wp-tf workspaces

The key is the one `terraform login` stored for the host, or `TF_TOKEN_<host>`, or
`WP_TF_TOKEN`. The host defaults to `terraform.webbpulse.com` and is set with `--host` or
`WP_TF_HOST`; the API origin is read from the host's discovery document, and must be https
on the host or a subdomain, unless `--api-url` or `WP_TF_API_URL` names an https origin.
Staging sits behind an access gate whose value goes in `WP_TF_GATE`. No command confirms,
applies or reads state, and no token is ever printed.

Log lines go to stdout, progress to stderr. Exit codes: 0 when the plan succeeded, 1 on any
failure, 2 under `--detailed-exitcode` when the plan has changes.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, NoReturn

from .archive import ArchiveError, build_tarball
from .credentials import CredentialsError, resolve_token

if TYPE_CHECKING:
    from .client import ControlPlane

PROG = "wp-tf"

DEFAULT_HOST = "terraform.webbpulse.com"

HOST_ENV = "WP_TF_HOST"
API_URL_ENV = "WP_TF_API_URL"
GATE_ENV = "WP_TF_GATE"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CHANGES = 2
EXIT_INTERRUPTED = 130

DEFAULT_MESSAGE = "Triggered via wp-tf"

POLL_SECONDS = 2.0

DRAIN_EMPTY_PAGES = 2
"""Empty log pages read after a run ends before the stream counts as complete, since the
runner's last lines can reach the log group a moment after the status changes."""


class UsageError(Exception):
    """A command line the tool refuses before any request."""


class _Parser(argparse.ArgumentParser):
    """An argument parser whose usage errors exit 1, keeping 2 for a plan with changes."""

    def error(self, message: str) -> NoReturn:
        """Raise instead of exiting 2."""
        raise UsageError(message)


def build_parser() -> argparse.ArgumentParser:
    """The `wp-tf` command line."""
    parser = _Parser(prog=PROG, description="Plan-only runs on the WebbPulse Terraform control plane.")
    parser.add_argument("--host", help=f"control plane host, as used with terraform login (default {DEFAULT_HOST})")
    parser.add_argument("--api-url", help="API origin, when it should not be discovered from the host")
    commands = parser.add_subparsers(dest="command", required=True)

    plan = commands.add_parser("plan", help="upload a directory and stream a plan-only run")
    plan.add_argument("directory", nargs="?", default=".", help="configuration directory (default .)")
    plan.add_argument("-w", "--workspace", required=True, help="workspace name or ws- id")
    plan.add_argument("-m", "--message", default=DEFAULT_MESSAGE, help="run message")
    plan.add_argument("--destroy", action="store_true", help="plan destroying every managed resource")
    plan.add_argument("--detailed-exitcode", action="store_true", help="exit 2 when the plan has changes")
    plan.add_argument("--no-follow", action="store_true", help="print the run id and return without waiting")

    logs = commands.add_parser("logs", help="print a run phase's log")
    logs.add_argument("run_id")
    logs.add_argument("--phase", choices=("plan", "apply"), default="plan")
    logs.add_argument("-f", "--follow", action="store_true", help="keep streaming until the run finishes")

    status = commands.add_parser("status", help="print a run as JSON")
    status.add_argument("run_id")

    commands.add_parser("workspaces", help="list workspaces: id, name, working directory")
    return parser


def _changes_line(run: Mapping[str, Any]) -> str:
    """Terraform's plan summary line for a run's change counts."""
    changes = run.get("changes") or {}
    return (
        f"Plan: {int(changes.get('add', 0))} to add, {int(changes.get('change', 0))} to change, "
        f"{int(changes.get('destroy', 0))} to destroy."
    )


def _has_changes(run: Mapping[str, Any]) -> bool:
    """Whether the run's plan changes anything."""
    changes = run.get("changes") or {}
    return any(int(changes.get(key, 0)) for key in ("add", "change", "destroy"))


def follow_run(
    plane: ControlPlane,
    run_id: str,
    phase: str,
    stdout: IO[str],
    stderr: IO[str],
    *,
    sleep: Callable[[float], None] = time.sleep,
    poll_seconds: float = POLL_SECONDS,
) -> dict[str, Any]:
    """Stream a phase's log until the run ends, then return the final run."""
    from .client import TERMINAL_STATUSES

    after: str | None = None
    last_status = ""
    while True:
        run = plane.get_run(run_id)
        status = str(run.get("status", ""))
        if status != last_status:
            behind = f" (queued behind {run['queued_behind']})" if run.get("queued_behind") else ""
            print(f"{PROG}: {run_id} is {status}{behind}", file=stderr, flush=True)
            last_status = status
        lines, after = plane.logs(run_id, phase, after)
        for line in lines:
            print(line, file=stdout, flush=True)
        if status in TERMINAL_STATUSES:
            empty = 0 if lines else 1
            while empty < DRAIN_EMPTY_PAGES:
                sleep(poll_seconds)
                lines, after = plane.logs(run_id, phase, after)
                for line in lines:
                    print(line, file=stdout, flush=True)
                empty = 0 if lines else empty + 1
            return run
        sleep(poll_seconds)


def _print_all_logs(plane: ControlPlane, run_id: str, phase: str, stdout: IO[str]) -> None:
    """Print every log line the phase has so far."""
    after: str | None = None
    while True:
        lines, next_after = plane.logs(run_id, phase, after)
        for line in lines:
            print(line, file=stdout, flush=True)
        if not lines or next_after == after:
            return
        after = next_after


def _plan(
    args: argparse.Namespace,
    plane: ControlPlane,
    host: str,
    stdout: IO[str],
    stderr: IO[str],
    sleep: Callable[[float], None],
) -> int:
    """Upload the directory, start a plan-only run and stream it."""
    from .client import SUCCESS_STATUSES

    workspace = plane.resolve_workspace(args.workspace)
    workspace_id = str(workspace["workspace_id"])
    tarball = build_tarball(Path(args.directory), str(workspace.get("working_directory") or ""))
    print(f"{PROG}: uploading {len(tarball)} bytes to {workspace.get('name', workspace_id)}", file=stderr, flush=True)
    config_version_id = plane.upload_config(workspace_id, tarball)
    run = plane.create_plan_run(workspace_id, config_version_id, message=args.message, is_destroy=args.destroy)
    run_id = str(run["run_id"])
    print(f"{PROG}: run {run_id} https://{host}/runs/{run_id}", file=stderr, flush=True)
    if args.no_follow:
        print(run_id, file=stdout, flush=True)
        return EXIT_OK
    try:
        final = follow_run(plane, run_id, "plan", stdout, stderr, sleep=sleep)
    except KeyboardInterrupt:
        print(f"{PROG}: interrupted, cancelling {run_id}", file=stderr, flush=True)
        try:
            plane.cancel_run(run_id)
        except Exception as exc:
            print(f"{PROG}: could not cancel {run_id}: {exc}", file=stderr, flush=True)
        return EXIT_INTERRUPTED
    status = str(final.get("status", ""))
    if status not in SUCCESS_STATUSES:
        error = final.get("error")
        print(f"{PROG}: run {run_id} ended {status}{f': {error}' if error else ''}", file=stderr, flush=True)
        return EXIT_ERROR
    print(f"{PROG}: {_changes_line(final)}", file=stderr, flush=True)
    if args.detailed_exitcode and _has_changes(final):
        return EXIT_CHANGES
    return EXIT_OK


def _connect(args: argparse.Namespace, environ: Mapping[str, str], home: Path | None) -> tuple[str, ControlPlane]:
    """The host and an authenticated client for it."""
    import httpx

    from .client import ControlPlane, check_api_url, discover_api_url

    host = (args.host or environ.get(HOST_ENV) or DEFAULT_HOST).strip().lower()
    if "/" in host or not host:
        raise UsageError("--host is a hostname such as terraform.webbpulse.com, with no scheme or path")
    token = resolve_token(host, environ, home)
    api_url = (args.api_url or environ.get(API_URL_ENV) or "").strip()
    if api_url:
        api_url = check_api_url(api_url)
    else:
        with httpx.Client(timeout=30.0) as client:
            api_url = discover_api_url(host, client)
    return host, ControlPlane(api_url, token, gate=environ.get(GATE_ENV, "").strip())


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: IO[str] | None = None,
    stderr: IO[str] | None = None,
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
    connect: Callable[[argparse.Namespace, Mapping[str, str], Path | None], tuple[str, ControlPlane]] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Run the CLI and return its exit code."""
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    env = os.environ if environ is None else environ
    try:
        args = build_parser().parse_args(argv)
    except UsageError as exc:
        print(f"{PROG}: {exc}", file=err)
        return EXIT_ERROR
    try:
        import httpx
    except ImportError:
        print(f"{PROG}: needs httpx; install webbpulse[tf]", file=err)
        return EXIT_ERROR

    from .client import ApiError

    try:
        host, plane = (connect or _connect)(args, env, home)
        with plane:
            if args.command == "plan":
                return _plan(args, plane, host, out, err, sleep)
            if args.command == "logs":
                if args.follow:
                    follow_run(plane, args.run_id, args.phase, out, err, sleep=sleep)
                else:
                    _print_all_logs(plane, args.run_id, args.phase, out)
                return EXIT_OK
            if args.command == "status":
                print(json.dumps(plane.get_run(args.run_id), indent=2, sort_keys=True), file=out)
                return EXIT_OK
            for item in plane.list_workspaces():
                row = (item.get("workspace_id", ""), item.get("name", ""), item.get("working_directory") or "")
                print("\t".join(str(value) for value in row), file=out)
            return EXIT_OK
    except (UsageError, CredentialsError, ArchiveError, ApiError) as exc:
        print(f"{PROG}: {exc}", file=err)
        return EXIT_ERROR
    except httpx.HTTPError as exc:
        print(f"{PROG}: {type(exc).__name__}: {exc}", file=err)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
