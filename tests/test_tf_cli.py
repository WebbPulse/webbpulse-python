"""Tests for `webbpulse.tf.client` and `webbpulse.tf.cli` against a fake control plane."""

from __future__ import annotations

import argparse
import io
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import httpx
import pytest

from webbpulse.tf import cli
from webbpulse.tf.client import GATE_HEADER, ApiError, ControlPlane, check_api_url, discover_api_url

API = "https://api.example.test"
WS_ID = "ws-01M3G00GJ5VPVR3QDJV8HNBQX1"
TOKEN = "wpk_unit_test_token"
GATE = "gate-unit-test-value"


class FakePlane:
    """A control plane that plans one run through a scripted sequence of statuses and log pages."""

    def __init__(self, statuses: list[str], changes: Mapping[str, int] | None = None, working_directory: str = ""):
        """Script the statuses `GET /runs/{id}` returns in order and the final change counts."""
        self.statuses = statuses
        self.changes = dict(changes or {"add": 1, "change": 0, "destroy": 0})
        self.working_directory = working_directory
        self.requests: list[httpx.Request] = []
        self.uploaded = b""
        self.run_body: dict[str, Any] = {}
        self.log_pages = [["Terraform will perform the following actions:"], ["Plan: 1 to add."]]
        self.cancelled = False
        self.confirm_bodies: list[bytes] = []
        self.confirm_conflicts = 0
        self.confirm_status = 200
        self.discard_bodies: list[bytes] = []
        self.phases: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        """Answer one request."""
        self.requests.append(request)
        path = request.url.path
        if request.url.host == "uploads.example.test":
            self.uploaded = request.content
            return httpx.Response(200)
        if path == "/api/v1/workspaces":
            item = {"workspace_id": WS_ID, "name": "demo", "working_directory": self.working_directory}
            return httpx.Response(200, json={"items": [item]})
        if path == f"/api/v1/workspaces/{WS_ID}/config-versions":
            return httpx.Response(
                201,
                json={
                    "config_version": {"config_version_id": "cv-1"},
                    "upload_url": "https://uploads.example.test/put",
                    "headers": {"Content-Length": str(json.loads(request.content)["size_bytes"])},
                    "expires_in": 900,
                },
            )
        if path == "/api/v1/runs" and request.method == "POST":
            self.run_body = json.loads(request.content)
            return httpx.Response(201, json={"run_id": "run-1", "status": "pending"})
        if path == "/api/v1/runs/run-1":
            status = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
            return httpx.Response(200, json={"run_id": "run-1", "status": status, "changes": self.changes})
        if path == "/api/v1/runs/run-1/confirm":
            self.confirm_bodies.append(request.content)
            if self.confirm_conflicts:
                self.confirm_conflicts -= 1
                return httpx.Response(409, json={"detail": {"message": "not awaiting", "error_code": "CONFLICT"}})
            if self.confirm_status != 200:
                return httpx.Response(self.confirm_status, json={"message": "Forbidden"})
            return httpx.Response(200, json={"run_id": "run-1", "status": "applying"})
        if path == "/api/v1/runs/run-1/discard":
            self.discard_bodies.append(request.content)
            return httpx.Response(200, json={"run_id": "run-1", "status": "discarded"})
        if path == "/api/v1/runs/run-1/logs":
            self.phases.append(request.url.params.get("phase", ""))
            after = request.url.params.get("after")
            index = int(after) if after else 0
            if index < len(self.log_pages):
                events = [{"timestamp": 0, "message": line} for line in self.log_pages[index]]
                return httpx.Response(200, json={"events": events, "next_after": str(index + 1)})
            return httpx.Response(200, json={"events": [], "next_after": after})
        if path == "/api/v1/runs/run-1/cancel":
            self.cancelled = True
            return httpx.Response(200, json={"run_id": "run-1", "status": "cancelled"})
        return httpx.Response(404, json={"detail": {"message": "not found", "error_code": "NOT_FOUND"}})


class Terminal(io.StringIO):
    """A stdin that claims to be a terminal, holding the typed answer."""

    def isatty(self) -> bool:
        """Always a terminal."""
        return True


def _run(plane: FakePlane, argv: list[str], gate: str = "", stdin: io.StringIO | None = None) -> tuple[int, str, str]:
    """Run the CLI against the fake plane and return the code, stdout and stderr."""

    def connect(args: argparse.Namespace, environ: Mapping[str, str], home: Path | None) -> tuple[str, ControlPlane]:
        return "terraform.example.test", ControlPlane(
            API, TOKEN, gate=gate, transport=httpx.MockTransport(plane.handler)
        )

    out, err = io.StringIO(), io.StringIO()
    code = cli.main(
        argv, stdout=out, stderr=err, stdin=stdin or io.StringIO(), environ={}, connect=connect, sleep=lambda _: None
    )
    return code, out.getvalue(), err.getvalue()


def _config(tmp_path: Path) -> Path:
    """A one-file configuration."""
    (tmp_path / "main.tf").write_text('resource "terraform_data" "x" {}\n')
    return tmp_path


def test_plan_uploads_starts_plan_only_run_and_streams(tmp_path: Path) -> None:
    """`plan` uploads the tarball, starts a plan-only run and prints its log lines."""
    plane = FakePlane(["pending", "planning", "planned_and_finished"])
    code, out, err = _run(plane, ["plan", str(_config(tmp_path)), "-w", "demo"])
    assert code == 0
    assert plane.run_body["plan_only"] is True
    assert plane.run_body["workspace_id"] == WS_ID
    assert plane.run_body["config_version_id"] == "cv-1"
    assert plane.uploaded[:2] == b"\x1f\x8b"
    assert "Terraform will perform the following actions:" in out
    assert "Plan: 1 to add." in out
    assert "https://terraform.example.test/runs/run-1" in err
    assert "Plan: 1 to add, 0 to change, 0 to destroy." in err


def test_token_goes_only_to_the_api(tmp_path: Path) -> None:
    """The bearer and gate are sent to the API and never to the presigned upload or the output."""
    plane = FakePlane(["planned_and_finished"])
    _, out, err = _run(plane, ["plan", str(_config(tmp_path)), "-w", WS_ID], gate=GATE)
    for request in plane.requests:
        if request.url.host == "uploads.example.test":
            assert "authorization" not in request.headers
            assert GATE_HEADER not in request.headers
        else:
            assert request.headers["authorization"] == f"Bearer {TOKEN}"
            assert request.headers[GATE_HEADER] == GATE
    assert TOKEN not in out + err
    assert GATE not in out + err


def test_detailed_exitcode_reports_changes(tmp_path: Path) -> None:
    """`--detailed-exitcode` exits 2 with changes and 0 without."""
    code, _, _ = _run(
        FakePlane(["planned_and_finished"]), ["plan", str(_config(tmp_path)), "-w", "demo", "--detailed-exitcode"]
    )
    assert code == 2
    plane = FakePlane(["planned_and_finished"], changes={"add": 0, "change": 0, "destroy": 0})
    code, _, _ = _run(plane, ["plan", str(_config(tmp_path)), "-w", "demo", "--detailed-exitcode"])
    assert code == 0


def test_errored_run_exits_one(tmp_path: Path) -> None:
    """A run that errors exits 1 and says so."""
    code, _, err = _run(FakePlane(["planning", "errored"]), ["plan", str(_config(tmp_path)), "-w", "demo"])
    assert code == 1
    assert "errored" in err


def test_destroy_and_no_follow(tmp_path: Path) -> None:
    """`--destroy` asks for a destroy plan and `--no-follow` prints the run id and returns."""
    plane = FakePlane(["pending"])
    code, out, _ = _run(plane, ["plan", str(_config(tmp_path)), "-w", "demo", "--destroy", "--no-follow"])
    assert code == 0
    assert out.strip() == "run-1"
    assert plane.run_body["is_destroy"] is True
    assert plane.run_body["plan_only"] is True


def test_working_directory_is_respected(tmp_path: Path) -> None:
    """A directory outside the workspace's working directory is refused before any upload."""
    plane = FakePlane(["planned_and_finished"], working_directory="infra/prod")
    code, _, err = _run(plane, ["plan", str(_config(tmp_path)), "-w", "demo"])
    assert code == 1
    assert "infra/prod" in err
    assert plane.uploaded == b""


def test_unknown_workspace(tmp_path: Path) -> None:
    """An unknown workspace name exits 1."""
    code, _, err = _run(FakePlane(["pending"]), ["plan", str(_config(tmp_path)), "-w", "nope"])
    assert code == 1
    assert "WORKSPACE_NOT_FOUND" in err


def test_interrupt_cancels_the_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ctrl-C while following cancels the run and exits 130."""
    plane = FakePlane(["planning"])

    def interrupt(*_: Any, **__: Any) -> dict[str, Any]:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "follow_run", interrupt)
    code, _, _ = _run(plane, ["plan", str(_config(tmp_path)), "-w", "demo"])
    assert code == 130
    assert plane.cancelled


def test_logs_status_and_workspaces() -> None:
    """`logs`, `status` and `workspaces` print what the API returns."""
    code, out, _ = _run(FakePlane(["planned_and_finished"]), ["logs", "run-1"])
    assert code == 0
    assert out.splitlines() == ["Terraform will perform the following actions:", "Plan: 1 to add."]
    code, out, _ = _run(FakePlane(["planned_and_finished"]), ["logs", "run-1", "--follow"])
    assert code == 0
    assert "Plan: 1 to add." in out
    code, out, _ = _run(FakePlane(["planned"]), ["status", "run-1"])
    assert json.loads(out)["status"] == "planned"
    code, out, _ = _run(FakePlane(["pending"]), ["workspaces"])
    assert out.strip().split("\t")[:2] == [WS_ID, "demo"]


def test_api_errors_carry_code_and_scope_hint() -> None:
    """A refused call exits 1 with the status and code; a bare 403 hints at scope or the gate."""

    def forbidden(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"message": "Forbidden"})

    plane = ControlPlane(API, TOKEN, transport=httpx.MockTransport(forbidden))
    with pytest.raises(ApiError) as caught:
        plane.list_workspaces()
    assert caught.value.status == 403
    assert "gate" in str(caught.value)


def test_usage_errors_exit_one() -> None:
    """A bad command line exits 1, since 2 means a plan with changes."""
    err = io.StringIO()
    assert cli.main(["plan"], stdout=io.StringIO(), stderr=err, environ={}) == 1
    assert "workspace" in err.getvalue()


def test_missing_token_exits_one(tmp_path: Path) -> None:
    """With no key anywhere the default connect says to run terraform login."""
    err = io.StringIO()
    code = cli.main(["--api-url", API, "workspaces"], stdout=io.StringIO(), stderr=err, environ={}, home=tmp_path)
    assert code == 1
    assert "terraform login terraform.webbpulse.com" in err.getvalue()


def test_bad_host_is_refused() -> None:
    """A host with a scheme is refused."""
    err = io.StringIO()
    code = cli.main(["--host", "https://x.test", "workspaces"], stdout=io.StringIO(), stderr=err, environ={})
    assert code == 1


def test_discovery_reads_the_api_origin() -> None:
    """The API origin comes from the discovery document's modules.v1 entry."""

    def discovery(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/.well-known/terraform.json"
        return httpx.Response(200, json={"modules.v1": "https://api.staging.example.test/v1/modules/"})

    with httpx.Client(transport=httpx.MockTransport(discovery)) as client:
        assert discover_api_url("staging.example.test", client) == "https://api.staging.example.test"

    def relative(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"modules.v1": "/v1/modules/"})

    with httpx.Client(transport=httpx.MockTransport(relative)) as client:
        assert discover_api_url("host.test", client) == "https://host.test"

    def missing(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"login.v1": {}})

    with httpx.Client(transport=httpx.MockTransport(missing)) as client, pytest.raises(ApiError):
        discover_api_url("host.test", client)


@pytest.mark.parametrize(
    "service",
    [
        "http://api.staging.example.test/v1/modules/",
        "https://evil.test/v1/modules/",
        "https://staging.example.test.evil.test/v1/modules/",
        "https://api.staging.example.test:8443/v1/modules/",
        "https://user@api.staging.example.test/v1/modules/",
        "//evil.test/v1/modules/",
    ],
)
def test_discovery_refuses_an_untrusted_origin(service: str) -> None:
    """A discovery document pointing the key off https or off the login host is refused."""

    def discovery(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"modules.v1": service})

    with httpx.Client(transport=httpx.MockTransport(discovery)) as client, pytest.raises(ApiError) as caught:
        discover_api_url("staging.example.test", client)
    assert caught.value.error_code == "UNTRUSTED_API_ORIGIN"


def test_untrusted_discovery_sends_no_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Through the default connect, an untrusted discovered origin exits 1 before any API call."""
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json={"modules.v1": "http://evil.test/v1/modules/"})

    real_client = httpx.Client

    def client(**kwargs: Any) -> httpx.Client:
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "Client", client)
    err = io.StringIO()
    code = cli.main(["workspaces"], stdout=io.StringIO(), stderr=err, environ={"WP_TF_TOKEN": TOKEN}, home=tmp_path)
    assert code == 1
    assert "UNTRUSTED_API_ORIGIN" in err.getvalue()
    assert [request.url.path for request in sent] == ["/.well-known/terraform.json"]
    assert all("authorization" not in request.headers for request in sent)


@pytest.mark.parametrize("url", ["http://api.example.test", "ftp://api.example.test", "https://u@api.example.test"])
def test_insecure_api_url_is_refused(url: str) -> None:
    """An explicit API URL must be https, from the flag or the environment."""
    err = io.StringIO()
    assert (
        cli.main(["--api-url", url, "workspaces"], stdout=io.StringIO(), stderr=err, environ={"WP_TF_TOKEN": TOKEN})
        == 1
    )
    assert "INSECURE_API_URL" in err.getvalue()
    err = io.StringIO()
    env = {"WP_TF_TOKEN": TOKEN, "WP_TF_API_URL": url}
    assert cli.main(["workspaces"], stdout=io.StringIO(), stderr=err, environ=env) == 1
    assert "INSECURE_API_URL" in err.getvalue()


def test_local_http_api_url_is_allowed() -> None:
    """Plain http is accepted for a local stack only."""
    assert check_api_url("http://localhost:8000/") == "http://localhost:8000"
    assert check_api_url("http://127.0.0.1:8000") == "http://127.0.0.1:8000"
    assert check_api_url("https://api.example.test/") == "https://api.example.test"


def test_list_workspaces_follows_the_cursor() -> None:
    """Workspaces are read across pages when the API returns a next cursor."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("cursor") == "c2":
            return httpx.Response(200, json={"items": [{"workspace_id": "ws-b"}], "next_cursor": None})
        return httpx.Response(200, json={"items": [{"workspace_id": "ws-a"}], "next_cursor": "c2"})

    with ControlPlane(API, TOKEN, transport=httpx.MockTransport(handler)) as plane:
        assert [item["workspace_id"] for item in plane.list_workspaces()] == ["ws-a", "ws-b"]


class FakeDevice:
    """A stand-in for `DeviceLoginClient`, recording what the CLI asked of it."""

    def __init__(
        self, *, session: bool = True, fail: BaseException | None = None, token: str = TOKEN, revoked: bool = True
    ) -> None:
        """Script whether a session exists, whether the server confirms its revocation, and what login does."""
        from webbpulse.device_login import StoredSession

        self.session = StoredSession("https://api.example.test/api/auth", "wp-tf", token, "wpdr_x.y", 9e9, 9e9, "")
        self.has_session = session
        self.fail = fail
        self.scopes: list[str] | None = None
        self.logged_out = False
        self.revoked = revoked

    def login(self, scopes: list[str]) -> Any:
        """Record the scopes, then succeed or fail as scripted."""
        from webbpulse.device_login import StoredSession

        self.scopes = scopes
        if self.fail is not None:
            raise self.fail
        return StoredSession(
            self.session.issuer, "wp-tf", self.session.access_token, "wpdr_x.y", 9e9, 9e9, " ".join(scopes)
        )

    def logout(self) -> Any:
        """Sign out when there is a session."""
        from webbpulse.device_login import LogoutResult

        self.logged_out = self.has_session
        return LogoutResult(had_session=self.has_session, revoked=self.has_session and self.revoked)

    def stored(self) -> Any:
        """The scripted session."""
        return self.session if self.has_session else None

    def access_token(self) -> str:
        """The scripted token, or the failure."""
        if self.fail is not None:
            raise self.fail
        return self.session.access_token


def _session(argv: list[str], device: FakeDevice) -> tuple[int, str, str]:
    """Run `login` or `logout` against a fake device client."""
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(argv, stdout=out, stderr=err, environ={}, device=lambda args, environ, stderr: device)  # type: ignore[arg-type,return-value]
    return code, out.getvalue(), err.getvalue()


def test_login_requests_the_named_scopes_and_prints_no_token() -> None:
    """`--scope` repeats, and the success line names the scopes, not the token."""
    device = FakeDevice()
    code, out, err = _session(["login", "--scope", "runs:read", "--scope", "runs:apply"], device)
    assert code == 0
    assert device.scopes == ["runs:read", "runs:apply"]
    assert "signed in with runs:read runs:apply" in err
    assert TOKEN not in out + err


def test_add_scope_keeps_the_standard_set() -> None:
    """`--add-scope` asks for the standard set plus the named scope, so the defaults are not dropped."""
    device = FakeDevice()
    assert _session(["login", "--add-scope", "state:download", "--add-scope", "runs:read"], device)[0] == 0
    assert device.scopes == [*cli.STANDARD_SCOPES, "state:download"]
    assert "runs:apply" in cli.STANDARD_SCOPES
    assert "admin" not in cli.STANDARD_SCOPES


def test_scope_and_add_scope_are_exclusive() -> None:
    """Naming both an exact set and an addition is refused."""
    code, _, err = _session(["login", "--scope", "runs:read", "--add-scope", "admin"], FakeDevice())
    assert code == 1
    assert "not allowed with" in err


def test_login_help_explains_scopes(capsys: pytest.CaptureFixture[str]) -> None:
    """`login --help` describes the three ways to choose scopes and the standard set."""
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["login", "--help"])
    help_text = capsys.readouterr().out
    for phrase in ("--add-scope SCOPE", "--scope SCOPE", "no scope flag", "runs:apply", "state:download and admin"):
        assert phrase in help_text


def test_login_without_scopes_asks_for_the_default_set() -> None:
    """No `--scope` sends none, so the server grants its defaults and never apply or admin."""
    device = FakeDevice()
    assert _session(["login"], device)[0] == 0
    assert device.scopes == []


def test_a_failed_login_exits_one_with_the_reason() -> None:
    """A denial is reported on stderr and exits 1."""
    from webbpulse.device_login import DeviceLoginError

    code, _, err = _session(["login"], FakeDevice(fail=DeviceLoginError("the login was denied in the browser")))
    assert code == 1
    assert "denied" in err


def test_an_interrupted_login_exits_130() -> None:
    """Ctrl-C while waiting for approval is an interruption, not a failure."""
    code, _, err = _session(["login"], FakeDevice(fail=KeyboardInterrupt()))
    assert code == 130
    assert "interrupted" in err


def test_logout_signs_out_or_says_there_was_nothing() -> None:
    """`logout` revokes a session, and is quiet success without one."""
    device = FakeDevice()
    code, _, err = _session(["logout"], device)
    assert code == 0
    assert device.logged_out
    assert "signed out" in err
    code, _, err = _session(["logout"], FakeDevice(session=False))
    assert code == 0
    assert "no wp-tf login session" in err


def test_logout_warns_when_the_server_did_not_confirm() -> None:
    """A failed server revoke still clears the local session, and says the server one may live on."""
    device = FakeDevice(revoked=False)
    code, _, err = _session(["logout"], device)
    assert code == 0
    assert device.logged_out
    assert "signed out locally" in err
    assert "may stay live" in err


def test_the_device_client_targets_the_api_issuer_with_the_gate() -> None:
    """The issuer defaults to `<api>/api/auth`, `--issuer` overrides it, and the gate header rides along."""
    args = cli.build_parser().parse_args(["login"])
    client = cli._device_client(args, {}, API, GATE)
    assert client.issuer == f"{API}/api/auth"
    assert client._headers == {GATE_HEADER: GATE}
    args = cli.build_parser().parse_args(["login", "--issuer", "https://API.example.test:443/id"])
    assert cli._device_client(args, {}, API, "").issuer == "https://API.example.test:443/id"
    args = cli.build_parser().parse_args(["logout"])
    assert cli._device_client(args, {"WP_TF_ISSUER": "https://api.example.test/auth"}, API, "").issuer == (
        "https://api.example.test/auth"
    )
    assert cli._device_client(args, {}, API, "")._headers == {}


@pytest.mark.parametrize(
    "issuer",
    [
        "https://id.example.test/api/auth",
        "https://evil.test/auth",
        "http://api.example.test/auth",
        "https://api.example.test:8443/auth",
        "https://test/auth",
        "https://example.test/auth",
        "https://user@api.example.test/auth",
        "https://api.example.test.evil.test/auth",
    ],
)
def test_an_issuer_off_the_api_origin_is_refused(issuer: str) -> None:
    """The session and gate header only go to the API origin itself."""
    args = cli.build_parser().parse_args(["login", "--issuer", issuer])
    with pytest.raises(cli.UsageError, match="not on the API origin"):
        cli._device_client(args, {}, API, GATE)


def test_commands_use_the_login_session_when_no_key_is_set(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With no environment key, `workspaces` sends the stored session's access token."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("authorization", ""))
        return httpx.Response(200, json={"items": []})

    real_client = httpx.Client

    def client(**kwargs: Any) -> httpx.Client:
        kwargs.pop("transport", None)
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "Client", client)
    monkeypatch.setattr(cli, "_device_client", lambda *args, **kwargs: FakeDevice(token="session-access-token"))
    err = io.StringIO()
    code = cli.main(
        ["--api-url", API, "workspaces"], stdout=io.StringIO(), stderr=err, environ={"WP_TF_GATE": GATE}, home=tmp_path
    )
    assert code == 0, err.getvalue()
    assert seen == ["Bearer session-access-token"]
    assert "session-access-token" not in err.getvalue()


def test_an_ended_session_falls_through_with_a_warning(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A session that cannot refresh says why, then the usual missing-key error follows."""
    from webbpulse.device_login import DeviceLoginError

    failing = FakeDevice(fail=DeviceLoginError("the device login was revoked or has ended; run login again"))
    monkeypatch.setattr(cli, "_device_client", lambda *args, **kwargs: failing)
    err = io.StringIO()
    stderr = io.StringIO()
    monkeypatch.setattr("sys.stderr", stderr)
    code = cli.main(
        ["--api-url", API, "workspaces"], stdout=io.StringIO(), stderr=err, environ={"WP_TF_GATE": GATE}, home=tmp_path
    )
    assert code == 1
    assert "run login again" in stderr.getvalue()
    assert "wp-tf login" in err.getvalue()
    assert TOKEN not in err.getvalue() + stderr.getvalue()


def test_an_unreadable_keyring_is_quiet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A machine with no usable keyring falls through to the credentials file without a warning."""
    from webbpulse.device_login import DeviceLoginError

    broken = FakeDevice()
    broken.stored = lambda: (_ for _ in ()).throw(DeviceLoginError("could not read the keyring: NoKeyringError"))  # type: ignore[method-assign]
    stderr = io.StringIO()
    monkeypatch.setattr("sys.stderr", stderr)
    assert cli._session_token(broken) is None  # type: ignore[arg-type]
    assert stderr.getvalue() == ""


APPLY_STATUSES = ["planning", "awaiting_confirmation", "applying", "applied"]


def test_apply_prompts_confirms_and_streams_the_apply(tmp_path: Path) -> None:
    """`apply` starts an applying run, shows the plan, takes `yes`, confirms and streams the apply log."""
    plane = FakePlane(list(APPLY_STATUSES))
    code, out, err = _run(plane, ["apply", str(_config(tmp_path)), "-w", "demo"], stdin=Terminal("yes\n"))
    assert code == 0, err
    assert plane.run_body["plan_only"] is False
    assert plane.run_body["is_destroy"] is False
    assert "Plan: 1 to add, 0 to change, 0 to destroy." in err
    assert 'Do you want to perform these actions in workspace "demo"?' in err
    assert len(plane.confirm_bodies) == 1
    assert plane.discard_bodies == []
    assert "apply" in plane.phases
    assert "Apply complete! Resources: 1 added, 0 changed, 0 destroyed." in err
    assert "Terraform will perform the following actions:" in out


def test_a_declined_apply_discards_the_run(tmp_path: Path) -> None:
    """Anything but `yes` discards the run and exits 1 without confirming."""
    plane = FakePlane(list(APPLY_STATUSES))
    code, _, err = _run(plane, ["apply", str(_config(tmp_path)), "-w", "demo"], stdin=Terminal("no\n"))
    assert code == 1
    assert plane.confirm_bodies == []
    assert len(plane.discard_bodies) == 1
    assert "apply discarded" in err


def test_end_of_input_at_the_prompt_discards(tmp_path: Path) -> None:
    """A terminal closed at the prompt is a decline, not an approval."""
    plane = FakePlane(list(APPLY_STATUSES))
    code, _, _ = _run(plane, ["apply", str(_config(tmp_path)), "-w", "demo"], stdin=Terminal(""))
    assert code == 1
    assert plane.confirm_bodies == []
    assert len(plane.discard_bodies) == 1


def test_apply_refuses_a_non_interactive_stdin(tmp_path: Path) -> None:
    """Without `--auto-approve`, a stdin that is not a terminal is refused before any request."""
    plane = FakePlane(list(APPLY_STATUSES))
    code, _, err = _run(plane, ["apply", str(_config(tmp_path)), "-w", "demo"], stdin=io.StringIO("yes\n"))
    assert code == 1
    assert "--auto-approve" in err
    assert plane.requests == []


def test_auto_approve_skips_the_prompt(tmp_path: Path) -> None:
    """`--auto-approve` confirms without reading stdin, and `--destroy` asks for a destroy run."""
    plane = FakePlane(list(APPLY_STATUSES))
    argv = ["apply", str(_config(tmp_path)), "-w", "demo", "--auto-approve", "--destroy"]
    code, _, err = _run(plane, argv, stdin=io.StringIO())
    assert code == 0, err
    assert plane.run_body["is_destroy"] is True
    assert "Enter a value" not in err
    assert len(plane.confirm_bodies) == 1


def test_apply_with_no_changes_stops_after_the_plan(tmp_path: Path) -> None:
    """A plan with no changes finishes the run, so nothing is asked or confirmed."""
    plane = FakePlane(["planning", "planned_and_finished"], changes={"add": 0, "change": 0, "destroy": 0})
    code, _, err = _run(plane, ["apply", str(_config(tmp_path)), "-w", "demo"], stdin=Terminal("yes\n"))
    assert code == 0
    assert "No changes." in err
    assert plane.confirm_bodies == []


def test_apply_reports_an_errored_plan(tmp_path: Path) -> None:
    """A plan that errors exits 1 without a prompt."""
    plane = FakePlane(["planning", "errored"])
    code, _, err = _run(plane, ["apply", str(_config(tmp_path)), "-w", "demo"], stdin=Terminal("yes\n"))
    assert code == 1
    assert "errored" in err
    assert "Enter a value" not in err


def test_apply_reports_a_failed_apply(tmp_path: Path) -> None:
    """An apply that errors exits 1."""
    plane = FakePlane(["awaiting_confirmation", "applying", "errored"])
    code, _, err = _run(plane, ["apply", str(_config(tmp_path)), "-w", "demo", "--auto-approve"])
    assert code == 1
    assert "ended errored" in err


def test_confirm_retries_while_the_plane_readies_the_run(tmp_path: Path) -> None:
    """A 409 while the run still awaits confirmation is retried; the second confirm lands."""
    plane = FakePlane(["awaiting_confirmation", "awaiting_confirmation", "applying", "applied"])
    plane.confirm_conflicts = 1
    code, _, err = _run(plane, ["apply", str(_config(tmp_path)), "-w", "demo", "--auto-approve"])
    assert code == 0, err
    assert len(plane.confirm_bodies) == 2


def test_a_forbidden_confirm_names_the_apply_scope() -> None:
    """A 403 on confirm says to sign in with runs:apply."""
    plane = FakePlane(["awaiting_confirmation"])
    plane.confirm_status = 403
    code, _, err = _run(plane, ["confirm", "run-1"])
    assert code == 1
    assert "wp-tf login --add-scope runs:apply" in err


def test_confirm_and_discard_act_on_an_existing_run() -> None:
    """`confirm` posts the comment and streams the apply; `discard` posts the comment."""
    plane = FakePlane(["applying", "applied"])
    code, _, err = _run(plane, ["confirm", "run-1", "--comment", "ship it"])
    assert code == 0, err
    assert json.loads(plane.confirm_bodies[0]) == {"comment": "ship it"}
    assert "apply" in plane.phases
    plane = FakePlane(["applying"])
    code, _, _ = _run(plane, ["confirm", "run-1", "--no-follow"])
    assert code == 0
    assert plane.confirm_bodies == [b""]
    assert plane.phases == []
    plane = FakePlane(["awaiting_confirmation"])
    code, _, err = _run(plane, ["discard", "run-1", "--comment", "not today"])
    assert code == 0
    assert json.loads(plane.discard_bodies[0]) == {"comment": "not today"}
    assert "discarded run-1" in err


def test_interrupting_the_apply_stream_leaves_the_apply_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ctrl-C while following the apply stops following and does not cancel the run."""
    plane = FakePlane(["applying"])

    def interrupt(*_: Any, **__: Any) -> dict[str, Any]:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "follow_run", interrupt)
    code, _, err = _run(plane, ["confirm", "run-1"])
    assert code == 130
    assert not plane.cancelled
    assert "the apply goes on" in err
