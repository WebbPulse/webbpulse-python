"""`wp-tf`: start a plan-only run from a directory and stream its log, like a remote `terraform plan`.

    terraform login terraform.webbpulse.com
    wp-tf plan -w platform-staging
    wp-tf plan ./infra -w ws-01M3G00GJ5VPVR3QDJV8HNBQX1 --detailed-exitcode
    wp-tf logs run-01M3... --phase plan --follow
    wp-tf status run-01M3...
    wp-tf workspaces
    wp-tf login --scope runs:apply
    wp-tf logout

The key is `WP_TF_TOKEN`, or `TF_TOKEN_<host>`, or the session `wp-tf login` keeps in the OS
keyring (refreshed as needed), or the one `terraform login` stored for the host. `wp-tf
login` signs in through the browser with the OAuth device grant against the issuer at
`<api>/api/auth`, or `--issuer` / `WP_TF_ISSUER`. The host defaults to
`terraform.webbpulse.com` and is set with `--host` or `WP_TF_HOST`; the API origin is read
from the host's discovery document, and must be https on the host or a subdomain, unless
`--api-url` or `WP_TF_API_URL` names an https origin.
The access gate value comes from `WP_TF_GATE`, else from the gate's SSM parameter
`/<prefix>/access-gate/origin-verify` when AWS credentials can read it, with the prefix
from `--gate-prefix`, `WP_TF_GATE_PREFIX` or the known host. No command confirms, applies
or reads state, and no token or gate value is ever printed.

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
from .gate import GateError, resolve_gate

if TYPE_CHECKING:
    from webbpulse.device_login import DeviceLoginClient

    from .client import ControlPlane

PROG = "wp-tf"

DEFAULT_HOST = "terraform.webbpulse.com"

HOST_ENV = "WP_TF_HOST"
API_URL_ENV = "WP_TF_API_URL"
ISSUER_ENV = "WP_TF_ISSUER"

DEVICE_CLIENT_ID = "wp-tf"
"""The client id `wp-tf login` presents to the device grant."""

ISSUER_PATH = "/api/auth"
"""Where the identity issuer sits under the API origin."""

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
    parser.add_argument(
        "--gate-prefix",
        help="SSM prefix of the access gate value, /<prefix>/access-gate/origin-verify (default by host)",
    )
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

    login = commands.add_parser("login", help="sign in through the browser and keep the session in the OS keyring")
    login.add_argument(
        "--scope",
        action="append",
        default=[],
        help="a scope to request, repeatable; apply and admin scopes must be named (default: the standard set)",
    )
    login.add_argument("--issuer", help="identity issuer URL (default <api>/api/auth)")

    logout = commands.add_parser("logout", help="revoke and forget the wp-tf login session")
    logout.add_argument("--issuer", help="identity issuer URL (default <api>/api/auth)")
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


def _host(args: argparse.Namespace, environ: Mapping[str, str]) -> str:
    """The Terraform host this command talks to."""
    host = (args.host or environ.get(HOST_ENV) or DEFAULT_HOST).strip().lower()
    if "/" in host or not host:
        raise UsageError("--host is a hostname such as terraform.webbpulse.com, with no scheme or path")
    return host


class _Endpoint:
    """The API origin and access gate for a host, each resolved once and only when first needed."""

    def __init__(self, args: argparse.Namespace, environ: Mapping[str, str], host: str) -> None:
        """Bind to the command line and environment; makes no request."""
        self._args = args
        self._environ = environ
        self.host = host
        self._api_url: str | None = None
        self._gate: str | None = None

    @property
    def api_url(self) -> str:
        """The https API origin, from `--api-url`, `WP_TF_API_URL` or the host's discovery document."""
        if self._api_url is None:
            import httpx

            from .client import check_api_url, discover_api_url

            explicit = (self._args.api_url or self._environ.get(API_URL_ENV) or "").strip()
            if explicit:
                self._api_url = check_api_url(explicit)
            else:
                with httpx.Client(timeout=30.0) as client:
                    self._api_url = discover_api_url(self.host, client)
        return self._api_url

    @property
    def gate(self) -> str:
        """The access gate value to send, or an empty string."""
        if self._gate is None:
            self._gate = resolve_gate(
                self.host,
                self._environ,
                self._args.gate_prefix,
                warn=lambda message: print(f"{PROG}: {message}", file=sys.stderr),
            )
        return self._gate


def _device_client(
    args: argparse.Namespace, environ: Mapping[str, str], api_url: str, gate: str, *, out: IO[str] | None = None
) -> DeviceLoginClient:
    """The device login client for this API origin, sending the gate header when there is one."""
    from webbpulse.device_login import DeviceLoginClient

    from .client import GATE_HEADER

    issuer = (getattr(args, "issuer", None) or environ.get(ISSUER_ENV) or f"{api_url.rstrip('/')}{ISSUER_PATH}").strip()
    return DeviceLoginClient(issuer, DEVICE_CLIENT_ID, headers={GATE_HEADER: gate} if gate else None, out=out)


def _session_token(client: DeviceLoginClient) -> str | None:
    """The stored login's access token, refreshed as needed, or None when there is no usable session.

    A keyring that cannot be read is the same as no session, so a machine without one falls
    through to the credentials file quietly; a session that fails to refresh says why.
    """
    from webbpulse.device_login import DeviceLoginError

    try:
        if client.stored() is None:
            return None
    except DeviceLoginError:
        return None
    try:
        return client.access_token()
    except DeviceLoginError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return None


def _stored_session_token(args: argparse.Namespace, environ: Mapping[str, str], endpoint: _Endpoint) -> str | None:
    """The `wp-tf login` session's token, resolving the gate only when there is a session to refresh."""
    try:
        if _device_client(args, environ, endpoint.api_url, "").stored() is None:
            return None
    except Exception:
        return None
    return _session_token(_device_client(args, environ, endpoint.api_url, endpoint.gate))


def _connect(args: argparse.Namespace, environ: Mapping[str, str], home: Path | None) -> tuple[str, ControlPlane]:
    """The host and an authenticated client for it."""
    from .client import ControlPlane

    endpoint = _Endpoint(args, environ, _host(args, environ))
    token = resolve_token(
        endpoint.host, environ, home, session_token=lambda: _stored_session_token(args, environ, endpoint)
    )
    return endpoint.host, ControlPlane(endpoint.api_url, token, gate=endpoint.gate)


def _login(args: argparse.Namespace, environ: Mapping[str, str], stderr: IO[str]) -> DeviceLoginClient:
    """The device login client for `login` and `logout`, printing its progress to stderr."""
    endpoint = _Endpoint(args, environ, _host(args, environ))
    return _device_client(args, environ, endpoint.api_url, endpoint.gate, out=stderr)


def _session_command(
    args: argparse.Namespace,
    environ: Mapping[str, str],
    stderr: IO[str],
    device: Callable[[argparse.Namespace, Mapping[str, str], IO[str]], DeviceLoginClient] | None,
) -> int:
    """Run `login` or `logout`. Neither prints a token."""
    client = (device or _login)(args, environ, stderr)
    if args.command == "login":
        try:
            session = client.login(args.scope)
        except KeyboardInterrupt:
            print(f"{PROG}: login interrupted", file=stderr, flush=True)
            return EXIT_INTERRUPTED
        granted = f" with {session.scope}" if session.scope else ""
        print(f"{PROG}: signed in{granted}; the session is in the OS keyring", file=stderr, flush=True)
        return EXIT_OK
    if client.logout():
        print(f"{PROG}: signed out", file=stderr, flush=True)
    else:
        print(f"{PROG}: no wp-tf login session to sign out of", file=stderr, flush=True)
    return EXIT_OK


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: IO[str] | None = None,
    stderr: IO[str] | None = None,
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
    connect: Callable[[argparse.Namespace, Mapping[str, str], Path | None], tuple[str, ControlPlane]] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    device: Callable[[argparse.Namespace, Mapping[str, str], IO[str]], DeviceLoginClient] | None = None,
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

    from webbpulse.device_login import DeviceLoginError

    from .client import ApiError

    try:
        if args.command in ("login", "logout"):
            return _session_command(args, env, err, device)
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
    except (UsageError, CredentialsError, GateError, ArchiveError, ApiError, DeviceLoginError) as exc:
        print(f"{PROG}: {exc}", file=err)
        return EXIT_ERROR
    except httpx.HTTPError as exc:
        print(f"{PROG}: {type(exc).__name__}: {exc}", file=err)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
