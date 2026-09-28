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
from webbpulse.tf.client import GATE_HEADER, ApiError, ControlPlane, discover_api_url

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
        if path == "/api/v1/runs/run-1/logs":
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


def _run(plane: FakePlane, argv: list[str], gate: str = "") -> tuple[int, str, str]:
    """Run the CLI against the fake plane and return the code, stdout and stderr."""

    def connect(args: argparse.Namespace, environ: Mapping[str, str], home: Path | None) -> tuple[str, ControlPlane]:
        return "terraform.example.test", ControlPlane(
            API, TOKEN, gate=gate, transport=httpx.MockTransport(plane.handler)
        )

    out, err = io.StringIO(), io.StringIO()
    code = cli.main(argv, stdout=out, stderr=err, environ={}, connect=connect, sleep=lambda _: None)
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
