"""Tests for `wp-tf var` against a fake control plane holding workspace variables."""

from __future__ import annotations

import argparse
import io
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import httpx

from webbpulse.tf import cli
from webbpulse.tf.client import ControlPlane

API = "https://api.example.test"
WS_ID = "ws-01M3G00GJ5VPVR3QDJV8HNBQX1"
TOKEN = "wpk_unit_test_token"
SECRET = "s3cr3t-unit-test-value"
VARIABLES_PATH = f"/api/v1/workspaces/{WS_ID}/variables"


class FakeVariablePlane:
    """A control plane with one workspace and an in-memory variable store that never returns a sensitive value."""

    def __init__(self, variables: list[dict[str, Any]] | None = None) -> None:
        """Seed the store with variables keyed by `key`."""
        self.variables: dict[str, dict[str, Any]] = {str(item["key"]): dict(item) for item in variables or []}
        self.writes: list[dict[str, Any]] = []
        self.deleted: list[str] = []
        self.refuse_writes = False
        self.step_up = False

    def _render(self, item: Mapping[str, Any]) -> dict[str, Any]:
        """A stored variable as the API renders it."""
        rendered = {
            "workspace_id": WS_ID,
            "category": "terraform",
            "sensitive": False,
            "hcl": False,
            "description": "",
            "created_at": "2026-10-07T00:00:00Z",
            **item,
        }
        if rendered["sensitive"]:
            rendered["value"] = None
        return rendered

    def handler(self, request: httpx.Request) -> httpx.Response:
        """Answer one request."""
        path = request.url.path
        if path == "/api/v1/workspaces":
            return httpx.Response(200, json={"items": [{"workspace_id": WS_ID, "name": "demo"}]})
        if path == VARIABLES_PATH:
            return httpx.Response(200, json={"items": [self._render(item) for item in self.variables.values()]})
        if path.startswith(f"{VARIABLES_PATH}/"):
            key = path.rsplit("/", 1)[1]
            if request.method in ("PUT", "DELETE"):
                if self.refuse_writes:
                    return httpx.Response(
                        403, json={"detail": {"message": "Forbidden", "error_code": "INSUFFICIENT_SCOPE"}}
                    )
                if self.step_up:
                    return httpx.Response(
                        401, json={"detail": {"message": "Sign in again", "error_code": "STEP_UP_REQUIRED"}}
                    )
            if request.method == "PUT":
                body = json.loads(request.content)
                self.writes.append(body)
                self.variables[key] = {"key": key, **body}
                return httpx.Response(200, json=self._render(self.variables[key]))
            if key not in self.variables:
                return httpx.Response(404, json={"detail": "No such variable."})
            if request.method == "DELETE":
                del self.variables[key]
                self.deleted.append(key)
                return httpx.Response(204)
            return httpx.Response(200, json=self._render(self.variables[key]))
        return httpx.Response(404, json={"detail": {"message": "not found", "error_code": "NOT_FOUND"}})


def _run(plane: FakeVariablePlane, argv: list[str], stdin: str = "") -> tuple[int, str, str]:
    """Run the CLI against the fake plane and return the code, stdout and stderr."""

    def connect(args: argparse.Namespace, environ: Mapping[str, str], home: Path | None) -> tuple[str, ControlPlane]:
        return "terraform.example.test", ControlPlane(API, TOKEN, transport=httpx.MockTransport(plane.handler))

    out, err = io.StringIO(), io.StringIO()
    code = cli.main(argv, stdout=out, stderr=err, stdin=io.StringIO(stdin), environ={}, connect=connect)
    return code, out.getvalue(), err.getvalue()


def _seeded() -> FakeVariablePlane:
    """A plane with one plain, one HCL and one sensitive variable."""
    return FakeVariablePlane(
        [
            {"key": "region", "value": "us-west-2", "description": "AWS region"},
            {"key": "tags", "value": '{ team = "plat" }', "hcl": True},
            {"key": "api_key", "value": SECRET, "sensitive": True, "category": "env"},
        ]
    )


def test_list_prints_every_variable_with_sensitive_values_redacted() -> None:
    """`var list` prints key, category, flags and value, with a placeholder for a sensitive value."""
    code, out, _ = _run(_seeded(), ["var", "list", "-w", "demo"])
    assert code == 0
    rows = [line.split("\t") for line in out.splitlines()]
    assert ["region", "terraform", "-", "us-west-2"] in rows
    assert ["tags", "terraform", "hcl", '{ team = "plat" }'] in rows
    assert ["api_key", "env", "sensitive", cli.SENSITIVE_PLACEHOLDER] in rows
    assert SECRET not in out


def test_get_prints_the_value() -> None:
    """`var get` prints only the value, for use in a script."""
    code, out, _ = _run(_seeded(), ["var", "get", "region", "-w", WS_ID])
    assert code == 0
    assert out == "us-west-2\n"


def test_get_refuses_a_sensitive_value() -> None:
    """`var get` on a sensitive variable exits 1 and prints nothing to stdout."""
    code, out, err = _run(_seeded(), ["var", "get", "api_key", "-w", "demo"])
    assert code == 1
    assert out == ""
    assert "sensitive" in err
    assert SECRET not in err


def test_get_json_redacts_a_sensitive_value() -> None:
    """`var get --json` prints the attributes with the placeholder for a sensitive value."""
    code, out, _ = _run(_seeded(), ["var", "get", "api_key", "-w", "demo", "--json"])
    assert code == 0
    shown = json.loads(out)
    assert shown["value"] == cli.SENSITIVE_PLACEHOLDER
    assert shown["category"] == "env"


def test_get_of_a_missing_variable_exits_one() -> None:
    """An unknown key exits 1."""
    code, _, err = _run(_seeded(), ["var", "get", "nope", "-w", "demo"])
    assert code == 1
    assert "404" in err


def test_set_creates_with_defaults() -> None:
    """`var set` of a new key writes a plain terraform variable."""
    plane = FakeVariablePlane()
    code, _, err = _run(plane, ["var", "set", "region", "us-east-1", "-w", "demo"])
    assert code == 0
    assert plane.writes == [
        {"value": "us-east-1", "category": "terraform", "hcl": False, "sensitive": False, "description": ""}
    ]
    assert "created region on demo" in err


def test_set_keeps_existing_attributes() -> None:
    """`var set` keeps the stored category, hcl and description when none is given."""
    plane = _seeded()
    code, _, err = _run(plane, ["var", "set", "tags", '{ team = "infra" }', "-w", "demo"])
    assert code == 0
    assert plane.writes[-1]["hcl"] is True
    assert plane.writes[-1]["category"] == "terraform"
    code, _, _ = _run(plane, ["var", "set", "region", "eu-west-1", "-w", "demo"])
    assert code == 0
    assert plane.writes[-1]["description"] == "AWS region"
    assert "updated" in err


def test_set_overrides_attributes_when_given() -> None:
    """`--category`, `--no-hcl` and `--description` replace the stored attributes."""
    plane = _seeded()
    argv = ["var", "set", "tags", "plain", "-w", "demo", "--category", "env", "--no-hcl", "--description", "Tags"]
    code, _, _ = _run(plane, argv)
    assert code == 0
    assert plane.writes[-1] == {
        "value": "plain",
        "category": "env",
        "hcl": False,
        "sensitive": False,
        "description": "Tags",
    }


def test_set_reads_a_sensitive_value_from_stdin_and_never_prints_it() -> None:
    """`--value-stdin --sensitive` writes the stdin value, minus its newline, and keeps it out of the output."""
    plane = FakeVariablePlane()
    argv = ["var", "set", "token", "--value-stdin", "--sensitive", "-w", "demo"]
    code, out, err = _run(plane, argv, stdin=f"{SECRET}\n")
    assert code == 0
    assert plane.writes[-1]["value"] == SECRET
    assert plane.writes[-1]["sensitive"] is True
    assert SECRET not in out + err
    assert "sensitive" in err


def test_set_keeps_a_sensitive_variable_sensitive() -> None:
    """Overwriting a sensitive variable without `--sensitive` stays sensitive, so it never becomes readable."""
    plane = _seeded()
    code, _, _ = _run(plane, ["var", "set", "api_key", "--value-stdin", "-w", "demo"], stdin="rotated")
    assert code == 0
    assert plane.writes[-1]["sensitive"] is True
    assert plane.writes[-1]["category"] == "env"
    assert plane.writes[-1]["value"] == "rotated"


def test_set_needs_exactly_one_value_source() -> None:
    """A value and `--value-stdin` together, or neither, is a usage error before any write."""
    plane = FakeVariablePlane()
    code, _, err = _run(plane, ["var", "set", "region", "-w", "demo"])
    assert code == 1
    assert "--value-stdin" in err
    code, _, _ = _run(plane, ["var", "set", "region", "x", "--value-stdin", "-w", "demo"], stdin="y")
    assert code == 1
    assert plane.writes == []


def test_unset_deletes_the_variable() -> None:
    """`var unset` deletes the key."""
    plane = _seeded()
    code, _, err = _run(plane, ["var", "unset", "region", "-w", "demo"])
    assert code == 0
    assert plane.deleted == ["region"]
    assert "deleted region from demo" in err


def test_a_missing_write_scope_says_how_to_get_one() -> None:
    """A 403 INSUFFICIENT_SCOPE on a write names variables:write and the login that grants it."""
    plane = _seeded()
    plane.refuse_writes = True
    for argv in (["var", "set", "region", "x", "-w", "demo"], ["var", "unset", "region", "-w", "demo"]):
        code, _, err = _run(plane, argv)
        assert code == 1
        assert "variables:write" in err
        assert "wp-tf login --add-scope variables:write" in err
        assert "Traceback" not in err


def test_a_stale_sign_in_for_a_sensitive_change_says_to_sign_in_again() -> None:
    """A 401 STEP_UP_REQUIRED says the change needs a recent sign-in."""
    plane = _seeded()
    plane.step_up = True
    code, _, err = _run(plane, ["var", "set", "api_key", "--value-stdin", "-w", "demo"], stdin="x")
    assert code == 1
    assert "15 minutes" in err
