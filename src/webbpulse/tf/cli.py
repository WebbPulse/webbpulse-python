"""`wp-tf`: plan and apply a directory on the control plane and stream the log, like a remote
`terraform plan` and `terraform apply`.

    terraform login terraform.webbpulse.com
    wp-tf plan -w platform-staging
    wp-tf plan ./infra -w ws-01M3G00GJ5VPVR3QDJV8HNBQX1 --detailed-exitcode
    wp-tf apply ./infra -w platform-staging
    wp-tf apply -w platform-staging --auto-approve
    wp-tf confirm run-01M3...
    wp-tf discard run-01M3...
    wp-tf logs run-01M3... --phase plan --follow
    wp-tf status run-01M3...
    wp-tf workspaces
    wp-tf login --add-scope state:download
    wp-tf logout

The key is `WP_TF_TOKEN`, or `TF_TOKEN_<host>`, or the session `wp-tf login` keeps in the OS
keyring (refreshed as needed), or the one `terraform login` stored for the host. `wp-tf
login` signs in through the browser with the OAuth device grant against the issuer at
`<api>/api/auth`, or `--issuer` / `WP_TF_ISSUER`, which must have exactly the API origin,
since the gate header and the session go to it. The host defaults to
`terraform.webbpulse.com` and is set with `--host` or `WP_TF_HOST`; the API origin is read
from the host's discovery document, and must be https on the host or a subdomain, unless
`--api-url` or `WP_TF_API_URL` names an https origin.
The access gate value comes from `WP_TF_GATE`, else from the gate's SSM parameter
`/<prefix>/access-gate/origin-verify` when AWS credentials can read it, with the prefix
from `--gate-prefix`, `WP_TF_GATE_PREFIX` or the known host. Only `apply` and `confirm`
apply, and `apply` asks first unless `--auto-approve` is given. No command reads state, and
no token or gate value is ever printed.

Log lines go to stdout, progress and the confirmation prompt to stderr. Exit codes: 0 when
the plan or apply succeeded, 1 on any failure or a declined apply, 2 under
`--detailed-exitcode` when the plan has changes, 130 after Ctrl-C.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
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

CONFIRM_ATTEMPTS = 15
"""Confirmations tried while the plane still readies a planned run for a decision, which can
lag the `awaiting_confirmation` status by a moment."""

STANDARD_SCOPES = (
    "workspaces:read",
    "workspaces:write",
    "variables:read",
    "variables:write",
    "configs:read",
    "configs:write",
    "runs:read",
    "runs:write",
    "runs:apply",
    "registry:read",
    "registry:write",
)
"""The scopes `--add-scope` adds to: everything a person needs to plan and apply, without
`state:download` or `admin`."""

LOGIN_DESCRIPTION = f"""Sign in through the browser with the OAuth device grant and keep the session in the
OS keyring for up to 12 hours.

Scopes limit what the session can do, on top of the person's own permissions:
  no scope flag          the control plane's default set
  --add-scope SCOPE      the standard set below plus SCOPE, repeatable
  --scope SCOPE          exactly the scopes named, repeatable, for a narrower session

The standard set is:
{textwrap.fill(" ".join(STANDARD_SCOPES), width=88, initial_indent="  ", subsequent_indent="  ")}

state:download and admin are never granted unless named. Applying needs runs:apply, so
when the plane's default set lacks it, sign in with `wp-tf login --add-scope runs:apply`."""

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
    parser = _Parser(prog=PROG, description="Plan and apply runs on the WebbPulse Terraform control plane.")
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

    apply = commands.add_parser(
        "apply", help="upload a directory, plan, confirm and stream the apply, like terraform apply"
    )
    apply.add_argument("directory", nargs="?", default=".", help="configuration directory (default .)")
    apply.add_argument("-w", "--workspace", required=True, help="workspace name or ws- id")
    apply.add_argument("-m", "--message", default=DEFAULT_MESSAGE, help="run message")
    apply.add_argument("--destroy", action="store_true", help="destroy every managed resource")
    apply.add_argument(
        "--auto-approve",
        action="store_true",
        help="apply without asking; without it, stdin must be a terminal to answer the prompt",
    )

    confirm = commands.add_parser("confirm", help="confirm a run awaiting confirmation and stream its apply")
    confirm.add_argument("run_id")
    confirm.add_argument("--comment", default="", help="a comment kept on the run with the decision")
    confirm.add_argument("--no-follow", action="store_true", help="return once confirmed, without streaming")

    discard = commands.add_parser("discard", help="discard a run's plan without applying it")
    discard.add_argument("run_id")
    discard.add_argument("--comment", default="", help="a comment kept on the run with the decision")

    logs = commands.add_parser("logs", help="print a run phase's log")
    logs.add_argument("run_id")
    logs.add_argument("--phase", choices=("plan", "apply"), default="plan")
    logs.add_argument("-f", "--follow", action="store_true", help="keep streaming until the run finishes")

    status = commands.add_parser("status", help="print a run as JSON")
    status.add_argument("run_id")

    commands.add_parser("workspaces", help="list workspaces: id, name, working directory")

    login = commands.add_parser(
        "login",
        help="sign in through the browser and keep the session in the OS keyring",
        description=LOGIN_DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scopes = login.add_mutually_exclusive_group()
    scopes.add_argument(
        "--add-scope",
        action="append",
        default=[],
        metavar="SCOPE",
        help="request the standard set plus this scope, repeatable",
    )
    scopes.add_argument(
        "--scope",
        action="append",
        default=[],
        metavar="SCOPE",
        help="request exactly the scopes named, repeatable, replacing the defaults",
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
    until: frozenset[str] | None = None,
) -> dict[str, Any]:
    """Stream a phase's log until the run reaches a status in `until`, by default one that ends
    it, then return the run."""
    from .client import TERMINAL_STATUSES

    stop = TERMINAL_STATUSES if until is None else until
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
        if status in stop:
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


def _start_run(
    args: argparse.Namespace,
    plane: ControlPlane,
    host: str,
    stderr: IO[str],
    *,
    plan_only: bool,
) -> tuple[str, str]:
    """Upload the directory and start a run on the workspace; return the run id and workspace name."""
    workspace = plane.resolve_workspace(args.workspace)
    workspace_id = str(workspace["workspace_id"])
    name = str(workspace.get("name") or workspace_id)
    tarball = build_tarball(Path(args.directory), str(workspace.get("working_directory") or ""))
    print(f"{PROG}: uploading {len(tarball)} bytes to {name}", file=stderr, flush=True)
    config_version_id = plane.upload_config(workspace_id, tarball)
    create = plane.create_plan_run if plan_only else plane.create_apply_run
    run = create(workspace_id, config_version_id, message=args.message, is_destroy=args.destroy)
    run_id = str(run["run_id"])
    print(f"{PROG}: run {run_id} https://{host}/runs/{run_id}", file=stderr, flush=True)
    return run_id, name


def _cancel_after_interrupt(plane: ControlPlane, run_id: str, stderr: IO[str]) -> int:
    """Cancel a run whose plan was interrupted and return the interrupted exit code."""
    print(f"{PROG}: interrupted, cancelling {run_id}", file=stderr, flush=True)
    try:
        plane.cancel_run(run_id)
    except Exception as exc:
        print(f"{PROG}: could not cancel {run_id}: {exc}", file=stderr, flush=True)
    return EXIT_INTERRUPTED


def _report_failure(run: Mapping[str, Any], run_id: str, stderr: IO[str]) -> int:
    """Say how a run ended and return the error exit code."""
    status = str(run.get("status", ""))
    error = run.get("error")
    print(f"{PROG}: run {run_id} ended {status}{f': {error}' if error else ''}", file=stderr, flush=True)
    return EXIT_ERROR


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

    run_id, _ = _start_run(args, plane, host, stderr, plan_only=True)
    if args.no_follow:
        print(run_id, file=stdout, flush=True)
        return EXIT_OK
    try:
        final = follow_run(plane, run_id, "plan", stdout, stderr, sleep=sleep)
    except KeyboardInterrupt:
        return _cancel_after_interrupt(plane, run_id, stderr)
    if str(final.get("status", "")) not in SUCCESS_STATUSES:
        return _report_failure(final, run_id, stderr)
    print(f"{PROG}: {_changes_line(final)}", file=stderr, flush=True)
    if args.detailed_exitcode and _has_changes(final):
        return EXIT_CHANGES
    return EXIT_OK


def _interactive(stream: IO[str]) -> bool:
    """Whether the stream is a terminal someone can answer a prompt on."""
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def _approved(workspace: str, destroy: bool, stdin: IO[str], stderr: IO[str]) -> bool:
    """Ask on stderr, as `terraform apply` does, and read the answer from stdin; only `yes` approves."""
    question = (
        f'Do you really want to destroy all resources in workspace "{workspace}"?'
        if destroy
        else f'Do you want to perform these actions in workspace "{workspace}"?'
    )
    print(f"\n{question}\n  Only 'yes' will be accepted to approve.\n", file=stderr, flush=True)
    print("  Enter a value: ", end="", file=stderr, flush=True)
    answer = stdin.readline()
    print("", file=stderr, flush=True)
    return answer.strip() == "yes"


def _discard_declined(plane: ControlPlane, run_id: str, stderr: IO[str]) -> None:
    """Discard a run whose apply was declined, saying so whether or not the plane agreed."""
    try:
        plane.discard_run(run_id, "Declined at the wp-tf prompt")
    except Exception as exc:
        print(f"{PROG}: could not discard {run_id}: {exc}", file=stderr, flush=True)
        return
    print(f"{PROG}: apply discarded; run {run_id} was not applied", file=stderr, flush=True)


def _confirm(
    plane: ControlPlane,
    run_id: str,
    comment: str,
    sleep: Callable[[float], None],
    *,
    poll_seconds: float = POLL_SECONDS,
) -> dict[str, Any]:
    """Confirm a run, retrying while it awaits confirmation but the plane is not ready for it yet.

    Raises:
        ApiError: The plane refused, with a hint about the apply scope on a 403.
    """
    from .client import CONFIRMABLE_STATUSES, ApiError

    attempt = 1
    while True:
        try:
            return plane.confirm_run(run_id, comment)
        except ApiError as exc:
            if exc.status == 403:
                raise ApiError(
                    exc.status,
                    f"{exc.message}; confirming needs the runs:apply scope and a recent sign-in, "
                    "so run `wp-tf login --add-scope runs:apply`",
                    exc.error_code,
                ) from exc
            ready_later = exc.status == 409 and attempt < CONFIRM_ATTEMPTS
            if not ready_later or str(plane.get_run(run_id).get("status", "")) not in CONFIRMABLE_STATUSES:
                raise
        attempt += 1
        sleep(poll_seconds)


def _follow_apply(
    plane: ControlPlane, run_id: str, stdout: IO[str], stderr: IO[str], sleep: Callable[[float], None]
) -> int:
    """Stream a confirmed run's apply and report how it ended. Ctrl-C stops following, not the apply."""
    try:
        final = follow_run(plane, run_id, "apply", stdout, stderr, sleep=sleep)
    except KeyboardInterrupt:
        print(
            f"{PROG}: stopped following; the apply goes on. Resume with: {PROG} logs {run_id} --phase apply -f",
            file=stderr,
            flush=True,
        )
        return EXIT_INTERRUPTED
    if str(final.get("status", "")) != "applied":
        return _report_failure(final, run_id, stderr)
    done = final.get("apply_changes") or final.get("changes") or {}
    print(
        f"{PROG}: Apply complete! Resources: {int(done.get('add', 0))} added, {int(done.get('change', 0))} changed, "
        f"{int(done.get('destroy', 0))} destroyed.",
        file=stderr,
        flush=True,
    )
    return EXIT_OK


def _apply(
    args: argparse.Namespace,
    plane: ControlPlane,
    host: str,
    stdin: IO[str],
    stdout: IO[str],
    stderr: IO[str],
    sleep: Callable[[float], None],
) -> int:
    """Upload the directory, plan, ask for a confirmation unless auto-approved, and stream the apply.

    `main` has already refused a prompt that stdin could not answer.
    """
    from .client import APPLY_STATUSES, CONFIRMABLE_STATUSES, DISCARDABLE_STATUSES, TERMINAL_STATUSES

    run_id, workspace = _start_run(args, plane, host, stderr, plan_only=False)
    try:
        planned = follow_run(
            plane,
            run_id,
            "plan",
            stdout,
            stderr,
            sleep=sleep,
            until=TERMINAL_STATUSES | DISCARDABLE_STATUSES | APPLY_STATUSES,
        )
    except KeyboardInterrupt:
        return _cancel_after_interrupt(plane, run_id, stderr)
    status = str(planned.get("status", ""))
    if status == "planned_and_finished":
        print(f"{PROG}: No changes. Your infrastructure matches the configuration.", file=stderr, flush=True)
        return EXIT_OK
    if status not in CONFIRMABLE_STATUSES | APPLY_STATUSES:
        return _report_failure(planned, run_id, stderr)
    if status in CONFIRMABLE_STATUSES:
        print(f"{PROG}: {_changes_line(planned)}", file=stderr, flush=True)
        if not args.auto_approve:
            try:
                approved = _approved(workspace, args.destroy, stdin, stderr)
            except KeyboardInterrupt:
                _discard_declined(plane, run_id, stderr)
                return EXIT_INTERRUPTED
            if not approved:
                _discard_declined(plane, run_id, stderr)
                return EXIT_ERROR
        _confirm(plane, run_id, "", sleep)
    return _follow_apply(plane, run_id, stdout, stderr, sleep)


def _confirm_command(
    args: argparse.Namespace, plane: ControlPlane, stdout: IO[str], stderr: IO[str], sleep: Callable[[float], None]
) -> int:
    """Confirm an existing run and, unless told not to, stream its apply."""
    run = _confirm(plane, args.run_id, args.comment, sleep)
    print(f"{PROG}: confirmed {args.run_id}; it is {run.get('status', 'applying')}", file=stderr, flush=True)
    if args.no_follow:
        return EXIT_OK
    return _follow_apply(plane, args.run_id, stdout, stderr, sleep)


def _requested_scopes(args: argparse.Namespace) -> list[str]:
    """The scopes `login` asks for: exactly `--scope`, the standard set plus `--add-scope`, or none
    so the plane grants its default set."""
    if args.scope:
        return list(dict.fromkeys(args.scope))
    if args.add_scope:
        return list(dict.fromkeys([*STANDARD_SCOPES, *args.add_scope]))
    return []


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
    if not _issuer_matches_api(issuer, api_url):
        raise UsageError(
            f"the issuer {issuer!r} is not on the API origin {api_url!r}; the session and the gate "
            "header are only sent there"
        )
    return DeviceLoginClient(issuer, DEVICE_CLIENT_ID, headers={GATE_HEADER: gate} if gate else None, out=out)


def _issuer_matches_api(issuer: str, api_url: str) -> bool:
    """Whether the issuer has exactly the API's origin: scheme, host and effective port."""
    from urllib.parse import urlsplit

    defaults = {"https": 443, "http": 80}
    try:
        wanted, api = urlsplit(issuer), urlsplit(api_url)
        wanted_port = wanted.port or defaults.get(wanted.scheme)
        api_port = api.port or defaults.get(api.scheme)
    except ValueError:
        return False
    if not wanted.scheme or wanted.scheme.lower() != api.scheme.lower():
        return False
    if not wanted.hostname or not api.hostname or wanted.username or wanted.password:
        return False
    return wanted.hostname.lower().rstrip(".") == api.hostname.lower().rstrip(".") and wanted_port == api_port


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
            session = client.login(_requested_scopes(args))
        except KeyboardInterrupt:
            print(f"{PROG}: login interrupted", file=stderr, flush=True)
            return EXIT_INTERRUPTED
        granted = f" with {session.scope}" if session.scope else ""
        print(f"{PROG}: signed in{granted}; the session is in the OS keyring", file=stderr, flush=True)
        return EXIT_OK
    result = client.logout()
    if result and result.revoked:
        print(f"{PROG}: signed out", file=stderr, flush=True)
    elif result:
        print(
            f"{PROG}: signed out locally; the server did not confirm, so the session may stay live until it expires",
            file=stderr,
            flush=True,
        )
    else:
        print(f"{PROG}: no wp-tf login session to sign out of", file=stderr, flush=True)
    return EXIT_OK


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: IO[str] | None = None,
    stderr: IO[str] | None = None,
    stdin: IO[str] | None = None,
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
    connect: Callable[[argparse.Namespace, Mapping[str, str], Path | None], tuple[str, ControlPlane]] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    device: Callable[[argparse.Namespace, Mapping[str, str], IO[str]], DeviceLoginClient] | None = None,
) -> int:
    """Run the CLI and return its exit code."""
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    inp = stdin if stdin is not None else sys.stdin
    env = os.environ if environ is None else environ
    try:
        args = build_parser().parse_args(argv)
    except UsageError as exc:
        print(f"{PROG}: {exc}", file=err)
        return EXIT_ERROR
    if args.command == "apply" and not args.auto_approve and not _interactive(inp):
        print(f"{PROG}: stdin is not a terminal, so no one can answer the prompt; pass --auto-approve", file=err)
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
            if args.command == "apply":
                return _apply(args, plane, host, inp, out, err, sleep)
            if args.command == "confirm":
                return _confirm_command(args, plane, out, err, sleep)
            if args.command == "discard":
                plane.discard_run(args.run_id, args.comment)
                print(f"{PROG}: discarded {args.run_id}", file=err, flush=True)
                return EXIT_OK
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
