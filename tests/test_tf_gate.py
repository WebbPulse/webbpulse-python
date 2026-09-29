"""`wp-tf` access gate value: environment first, then the gate's SSM parameter."""

from __future__ import annotations

import argparse
import io
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

import boto3
import httpx
import pytest
from moto import mock_aws
from pytest import MonkeyPatch

from webbpulse.tf import cli
from webbpulse.tf.client import GATE_HEADER
from webbpulse.tf.gate import GateError, gate_parameter_name, resolve_gate

STAGING = "staging.terraform.webbpulse.com"
PROD = "terraform.webbpulse.com"
STAGING_PARAMETER = "/webbpulse-terraform-stg/access-gate/origin-verify"
VALUE = "gate-unit-test-value"
REGION = "us-west-2"


def _strip_aws(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    """Remove every ambient AWS credential and point the SDK at empty files."""
    for name in (
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "credentials"))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")


@pytest.fixture
def aws(monkeypatch: MonkeyPatch, tmp_path: Path) -> Iterator[Any]:
    """Fake credentials under moto, with the staging gate parameter stored; yields the SSM client."""
    _strip_aws(monkeypatch, tmp_path)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    with mock_aws():
        ssm = boto3.client("ssm", region_name=REGION)
        ssm.put_parameter(Name=STAGING_PARAMETER, Value=VALUE, Type="SecureString")
        yield ssm


def test_environment_wins_without_reading_ssm(aws: Any) -> None:
    """A set `WP_TF_GATE` is used as is, even when SSM holds another value."""

    def refuse() -> Any:
        raise AssertionError("SSM was read")

    assert resolve_gate(STAGING, {"WP_TF_GATE": " from-env "}, session_factory=refuse) == "from-env"


def test_blank_environment_falls_through_to_ssm(aws: Any) -> None:
    """A blank `WP_TF_GATE` counts as unset."""
    assert resolve_gate(STAGING, {"WP_TF_GATE": "  "}) == VALUE


def test_known_host_reads_its_parameter(aws: Any) -> None:
    """The staging host maps to the staging gate's parameter, read with decryption."""
    assert resolve_gate(STAGING, {}) == VALUE


def test_flag_prefix_beats_environment_and_host(aws: Any) -> None:
    """`--gate-prefix` wins over `WP_TF_GATE_PREFIX`, which wins over the host."""
    aws.put_parameter(Name="/flag/access-gate/origin-verify", Value="flag-value", Type="SecureString")
    aws.put_parameter(Name="/env/access-gate/origin-verify", Value="env-value", Type="SecureString")
    assert resolve_gate(STAGING, {"WP_TF_GATE_PREFIX": "env"}, "/flag/") == "flag-value"
    assert resolve_gate(STAGING, {"WP_TF_GATE_PREFIX": "env"}) == "env-value"


def test_unknown_host_without_a_prefix_sends_no_gate(aws: Any) -> None:
    """A host the tool does not know, with no prefix named, has no gate."""
    assert resolve_gate("terraform.example.test", {}) == ""


def test_missing_credentials_send_no_gate(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    """With no AWS credentials, a known host quietly goes on without a gate."""
    _strip_aws(monkeypatch, tmp_path)
    warnings: list[str] = []
    assert resolve_gate(STAGING, {}, warn=warnings.append) == ""
    assert warnings == []


def test_missing_credentials_refuse_an_explicit_prefix(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    """A prefix named on purpose that cannot be read is an error, not a silent no gate."""
    _strip_aws(monkeypatch, tmp_path)
    with pytest.raises(GateError, match="no AWS credentials"):
        resolve_gate(STAGING, {}, "webbpulse-terraform-stg")


def test_missing_parameter_warns_for_a_host_default(aws: Any) -> None:
    """A host default whose parameter is absent warns by name and goes on without a gate."""
    warnings: list[str] = []
    assert resolve_gate(PROD, {}, warn=warnings.append) == ""
    assert warnings == [
        "could not read the access gate value from SSM "
        "/webbpulse-terraform-prod/access-gate/origin-verify: ParameterNotFound"
    ]


def test_missing_parameter_refuses_an_explicit_prefix(aws: Any) -> None:
    """An explicit prefix whose parameter is absent raises `GateError`."""
    with pytest.raises(GateError, match="ParameterNotFound"):
        resolve_gate(STAGING, {"WP_TF_GATE_PREFIX": "absent"})


@pytest.mark.parametrize("prefix", ["", "/", "a b", "a//b"])
def test_prefix_is_checked(prefix: str) -> None:
    """A prefix that cannot name a parameter is refused."""
    with pytest.raises(GateError):
        gate_parameter_name(prefix)


def test_cli_sends_the_ssm_gate_and_never_prints_it(
    aws: Any, tmp_path: Path, monkeypatch: MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`wp-tf` reads the gate from SSM for the host, sends it to the API and prints it nowhere."""
    from webbpulse.tf import client as tf_client

    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"items": []})

    real = tf_client.ControlPlane

    def plane(api_url: str, token: str, *, gate: str = "", **_: Any) -> Any:
        return real(api_url, token, gate=gate, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(tf_client, "ControlPlane", plane)
    out, err = io.StringIO(), io.StringIO()
    environ: Mapping[str, str] = {"WP_TF_TOKEN": "wpk_unit", "WP_TF_API_URL": f"https://api.{STAGING}"}
    code = cli.main(["--host", STAGING, "workspaces"], stdout=out, stderr=err, environ=environ, home=tmp_path)
    assert code == 0, err.getvalue()
    assert seen[0].headers[GATE_HEADER] == VALUE
    printed = out.getvalue() + err.getvalue() + "".join(capsys.readouterr())
    assert VALUE not in printed


def test_cli_explicit_prefix_failure_exits_1(aws: Any, tmp_path: Path) -> None:
    """A `--gate-prefix` that cannot be read fails the command before any API call."""
    out, err = io.StringIO(), io.StringIO()
    environ = {"WP_TF_TOKEN": "wpk_unit", "WP_TF_API_URL": f"https://api.{STAGING}"}
    code = cli.main(
        ["--host", STAGING, "--gate-prefix", "absent", "workspaces"],
        stdout=out,
        stderr=err,
        environ=environ,
        home=tmp_path,
    )
    assert code == 1
    assert "/absent/access-gate/origin-verify: ParameterNotFound" in err.getvalue()


def test_parser_takes_gate_prefix() -> None:
    """`--gate-prefix` is a top-level option."""
    args = cli.build_parser().parse_args(["--gate-prefix", "p", "workspaces"])
    assert isinstance(args, argparse.Namespace)
    assert args.gate_prefix == "p"
