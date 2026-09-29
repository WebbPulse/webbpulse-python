"""Where `wp-tf` finds the access gate value: `WP_TF_GATE`, else the gate's own SSM parameter.

The staging access gate module stores the value its CloudFront origin adds as a
SecureString at `/<prefix>/access-gate/origin-verify`. With AWS credentials that can read
it, `wp-tf` needs no gate value by hand. The value is never printed or logged.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

GATE_ENV = "WP_TF_GATE"
"""An explicit gate value, checked before SSM."""

GATE_PREFIX_ENV = "WP_TF_GATE_PREFIX"
"""The gate's parameter prefix, when the host is not one `HOST_GATE_PREFIXES` knows."""

GATE_PARAMETER = "/{prefix}/access-gate/origin-verify"

DEFAULT_REGION = "us-west-2"
"""The region read when neither the environment nor the AWS profile names one."""

HOST_GATE_PREFIXES: Mapping[str, str] = {
    "terraform.webbpulse.com": "webbpulse-terraform-prod",
    "staging.terraform.webbpulse.com": "webbpulse-terraform-stg",
}
"""The gate parameter prefix of each WebbPulse Terraform host."""


class GateError(Exception):
    """An explicitly named gate parameter that could not be read."""


def gate_parameter_name(prefix: str) -> str:
    """The SSM parameter holding the gate value under `prefix`, with or without its slashes."""
    cleaned = prefix.strip().strip("/")
    if not cleaned or any(part in cleaned for part in ("//", " ")):
        raise GateError("--gate-prefix is a parameter prefix such as webbpulse-terraform-stg")
    return GATE_PARAMETER.format(prefix=cleaned)


def resolve_gate(
    host: str,
    environ: Mapping[str, str],
    prefix: str | None = None,
    *,
    session_factory: Callable[[], Any] | None = None,
    warn: Callable[[str], None] | None = None,
) -> str:
    """The gate value for `host`, or an empty string when there is none to send.

    `WP_TF_GATE` wins when set. Otherwise the prefix is `prefix` (the `--gate-prefix` flag),
    then `WP_TF_GATE_PREFIX`, then the host's entry in `HOST_GATE_PREFIXES`, and the value is
    read from SSM with decryption. With no prefix, no boto3 or no AWS credentials the answer
    is empty. A read that fails is raised as `GateError` when the prefix was named
    explicitly, and otherwise passed to `warn` so the call goes on without a gate.
    """
    explicit = environ.get(GATE_ENV, "").strip()
    if explicit:
        return explicit
    named = (prefix or environ.get(GATE_PREFIX_ENV) or "").strip()
    chosen = named or HOST_GATE_PREFIXES.get(host, "")
    if not chosen:
        return ""
    name = gate_parameter_name(chosen)

    def skipped(reason: str) -> str:
        """Refuse an explicit prefix, or warn and go on without a gate."""
        message = f"could not read the access gate value from SSM {name}: {reason}"
        if named:
            raise GateError(message)
        if warn is not None:
            warn(message)
        return ""

    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        return skipped("boto3 is not installed") if named else ""
    try:
        session = session_factory() if session_factory is not None else boto3.session.Session()
        credentials = session.get_credentials()
    except BotoCoreError as exc:
        return skipped(type(exc).__name__)
    if credentials is None:
        return skipped("no AWS credentials") if named else ""
    try:
        client = session.client("ssm", region_name=session.region_name or DEFAULT_REGION)
        response = client.get_parameter(Name=name, WithDecryption=True)
    except ClientError as exc:
        return skipped(str(exc.response.get("Error", {}).get("Code") or "refused"))
    except BotoCoreError as exc:
        return skipped(type(exc).__name__)
    value = response.get("Parameter", {}).get("Value")
    if not isinstance(value, str) or not value:
        return skipped("the parameter is empty")
    return value


__all__ = [
    "DEFAULT_REGION",
    "GATE_ENV",
    "GATE_PARAMETER",
    "GATE_PREFIX_ENV",
    "HOST_GATE_PREFIXES",
    "GateError",
    "gate_parameter_name",
    "resolve_gate",
]
