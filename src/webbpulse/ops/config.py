"""`webbpulse-config`: set an environment's app secret keys and private config from a workstation.

Every product keeps its secrets in one Secrets Manager JSON secret, `<prefix>/app`, and its
private non-secret configuration in one SSM String parameter, `/<prefix>/config`, holding a
JSON object. Terraform creates both and ignores their values, so an operator sets the values
with their own AWS identity through this tool:

    uv run webbpulse-config --profile CarModPicker-Staging/AgentToolkit \\
        --prefix carmodpicker-staging secret set OAUTH_GITHUB_CLIENT_SECRET

A secret value is read from a hidden prompt, or from stdin when stdin is not a terminal, so it
never reaches argv or shell history. No command prints a secret value. Every write merges one
key into the current JSON object, keeps every other key, and re-checks the current version
just before writing so two operators cannot silently overwrite each other.

Diagnostics go to stderr and data to stdout. The exit codes are the `EXIT_*` constants.
"""

from __future__ import annotations

import argparse
import getpass
import json
import re
import sys
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import IO, TYPE_CHECKING, Any

if TYPE_CHECKING:
    from botocore.exceptions import ClientError
    from mypy_boto3_secretsmanager.client import SecretsManagerClient
    from mypy_boto3_ssm.client import SSMClient

PROG = "webbpulse-config"

EXIT_OK = 0
EXIT_AWS_ERROR = 1
EXIT_USAGE = 2
EXIT_MISSING = 3
EXIT_NOT_OBJECT = 4
EXIT_CONFLICT = 5
EXIT_KEY_ABSENT = 6

DEFAULT_RETRIES = 3

_UPPER_SNAKE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_MISSING_CODES = frozenset({"ResourceNotFoundException", "ParameterNotFound"})

JsonObject = dict[str, Any]
Mutation = Callable[[JsonObject], JsonObject]


class ConfigToolError(Exception):
    """A failure the CLI reports as one line on stderr with its own exit code."""

    exit_code = EXIT_AWS_ERROR


class UsageError(ConfigToolError):
    """The command line or the supplied value was refused before any AWS write."""

    exit_code = EXIT_USAGE


class ResourceMissingError(ConfigToolError):
    """The secret or parameter does not exist, usually because terraform has not been applied."""

    exit_code = EXIT_MISSING


class NotJsonObjectError(ConfigToolError):
    """The stored value is not a JSON object, so a key cannot be merged into it safely."""

    exit_code = EXIT_NOT_OBJECT


class ConcurrentChangeError(ConfigToolError):
    """The value kept changing between read and write for every retry."""

    exit_code = EXIT_CONFLICT


class KeyAbsentError(ConfigToolError):
    """`config get` was asked for a key the object does not hold."""

    exit_code = EXIT_KEY_ABSENT


@dataclass(frozen=True)
class Target:
    """The resolved secret id and parameter name one invocation acts on."""

    secret_id: str | None
    parameter_name: str | None


@dataclass(frozen=True)
class WriteResult:
    """The outcome of a merge: whether a new version was written, and the current version."""

    changed: bool
    version: str | None


def resolve_target(prefix: str | None, secret_id: str | None = None, parameter_name: str | None = None) -> Target:
    """Resolve `<prefix>/app` and `/<prefix>/config`, letting explicit overrides win."""
    clean = (prefix or "").strip().strip("/")
    return Target(
        secret_id=secret_id or (f"{clean}/app" if clean else None),
        parameter_name=parameter_name or (f"/{clean}/config" if clean else None),
    )


def validate_key(key: str) -> str:
    """Refuse an empty key or one with surrounding whitespace, and return it unchanged."""
    if not key or not key.strip():
        raise UsageError("refusing an empty key")
    if key != key.strip():
        raise UsageError(f"refusing key {key!r}: it has leading or trailing whitespace")
    return key


def is_upper_snake(key: str) -> bool:
    """Report whether a key follows the UPPER_SNAKE convention secret keys use."""
    return bool(_UPPER_SNAKE.fullmatch(key))


def parse_config_value(raw: str, *, force_string: bool = False) -> Any:
    """Parse a config value as JSON when it parses, otherwise keep it as a string."""
    if force_string:
        return raw
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def encode_object(value: JsonObject) -> str:
    """Encode an object compactly with sorted keys, so successive versions diff cleanly."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def decode_object(raw: str, where: str) -> JsonObject:
    """Decode a stored value that must be a JSON object, naming the source when it is not."""
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        raise NotJsonObjectError(f"{where} does not hold valid JSON; repair it before using {PROG}") from None
    if not isinstance(value, dict):
        raise NotJsonObjectError(
            f"{where} holds JSON {type(value).__name__}, not an object; repair it before using {PROG}"
        )
    return value


def _error_code(exc: ClientError) -> str:
    """Return the AWS error code carried by a `ClientError`."""
    return str(exc.response.get("Error", {}).get("Code", ""))


def _translate(exc: ClientError, where: str) -> ConfigToolError:
    """Turn a `ClientError` into the CLI error that names the resource and the likely fix."""
    code = _error_code(exc)
    if code in _MISSING_CODES:
        return ResourceMissingError(
            f"{where} does not exist; apply terraform first, or check --prefix, --profile and --region"
        )
    message = exc.response.get("Error", {}).get("Message", "")
    return ConfigToolError(f"{where}: {code}: {message}")


def _merge(
    read: Callable[[], tuple[str | None, JsonObject]],
    current_version: Callable[[], str | None],
    write: Callable[[JsonObject], str],
    mutate: Mutation,
    *,
    retries: int,
    where: str,
) -> WriteResult:
    """Read, apply one mutation, re-check the version and write, retrying on a concurrent change."""
    for _ in range(retries + 1):
        version, current = read()
        updated = mutate(dict(current))
        if updated == current:
            return WriteResult(changed=False, version=version)
        if current_version() != version:
            continue
        return WriteResult(changed=True, version=write(updated))
    raise ConcurrentChangeError(
        f"{where} changed between read and write on each of {retries + 1} attempts; nothing written, try again"
    )


def _with_key(key: str, value: Any) -> Mutation:
    """Build a mutation that sets one key."""

    def mutate(current: JsonObject) -> JsonObject:
        current[key] = value
        return current

    return mutate


def _with_keys(values: dict[str, Any]) -> Mutation:
    """Build a mutation that sets several keys in one write."""

    def mutate(current: JsonObject) -> JsonObject:
        current.update(values)
        return current

    return mutate


def _without_key(key: str) -> Mutation:
    """Build a mutation that removes one key if present."""

    def mutate(current: JsonObject) -> JsonObject:
        current.pop(key, None)
        return current

    return mutate


class SecretStore:
    """Key-level access to one Secrets Manager JSON secret, never exposing a value to the caller."""

    def __init__(self, client: SecretsManagerClient, secret_id: str, *, retries: int = DEFAULT_RETRIES) -> None:
        """Bind a client to one secret id."""
        self._client = client
        self.secret_id = secret_id
        self._retries = retries

    @property
    def where(self) -> str:
        """Name the secret for messages."""
        return f"secret {self.secret_id}"

    def current_version(self) -> str | None:
        """Return the version id staged AWSCURRENT, or `None` when the secret has no value yet."""
        from botocore.exceptions import ClientError

        try:
            described = self._client.describe_secret(SecretId=self.secret_id)
        except ClientError as exc:
            raise _translate(exc, self.where) from None
        if "DeletedDate" in described:
            raise ResourceMissingError(f"{self.where} is scheduled for deletion; restore it or apply terraform")
        for version_id, stages in described.get("VersionIdsToStages", {}).items():
            if "AWSCURRENT" in stages:
                return version_id
        return None

    def _read(self) -> tuple[str | None, JsonObject]:
        """Return the current version id and its decoded object, pinned to that exact version."""
        from botocore.exceptions import ClientError

        version = self.current_version()
        if version is None:
            return None, {}
        try:
            response = self._client.get_secret_value(SecretId=self.secret_id, VersionId=version)
        except ClientError as exc:
            raise _translate(exc, self.where) from None
        raw = response.get("SecretString")
        if raw is None:
            raise NotJsonObjectError(f"{self.where} holds a binary value, not a JSON object")
        return version, decode_object(raw, self.where)

    def _write(self, value: JsonObject) -> str:
        """Write a new AWSCURRENT version and return its id."""
        from botocore.exceptions import ClientError

        try:
            response = self._client.put_secret_value(
                SecretId=self.secret_id,
                SecretString=encode_object(value),
                ClientRequestToken=str(uuid.uuid4()),
            )
        except ClientError as exc:
            raise _translate(exc, self.where) from None
        return response["VersionId"]

    def key_names(self) -> list[str]:
        """Return the secret's key names, sorted."""
        return sorted(self._read()[1])

    def set(self, key: str, value: str) -> WriteResult:
        """Merge one key into the secret, keeping every other key."""
        return self._update(_with_key(validate_key(key), value))

    def set_many(self, values: dict[str, str]) -> WriteResult:
        """Merge several keys into the secret as one new version, keeping every other key."""
        if not values:
            raise UsageError("set_many needs at least one key")
        return self._update(_with_keys({validate_key(k): v for k, v in values.items()}))

    def unset(self, key: str) -> WriteResult:
        """Remove one key from the secret, writing nothing when it is already absent."""
        return self._update(_without_key(validate_key(key)))

    def _update(self, mutate: Mutation) -> WriteResult:
        """Apply one mutation under the concurrent change guard."""
        return _merge(self._read, self.current_version, self._write, mutate, retries=self._retries, where=self.where)


class ConfigStore:
    """Key-level access to one SSM String parameter holding a JSON object."""

    def __init__(self, client: SSMClient, parameter_name: str, *, retries: int = DEFAULT_RETRIES) -> None:
        """Bind a client to one parameter name."""
        self._client = client
        self.parameter_name = parameter_name
        self._retries = retries

    @property
    def where(self) -> str:
        """Name the parameter for messages."""
        return f"parameter {self.parameter_name}"

    def _read(self) -> tuple[str | None, JsonObject]:
        """Return the parameter version and its decoded object."""
        from botocore.exceptions import ClientError

        try:
            response = self._client.get_parameter(Name=self.parameter_name)
        except ClientError as exc:
            raise _translate(exc, self.where) from None
        parameter = response["Parameter"]
        if parameter.get("Type") != "String":
            raise NotJsonObjectError(f"{self.where} is a {parameter.get('Type')}, not a String parameter")
        return str(parameter["Version"]), decode_object(parameter.get("Value", ""), self.where)

    def current_version(self) -> str | None:
        """Return the parameter's current version."""
        return self._read()[0]

    def _write(self, value: JsonObject) -> str:
        """Overwrite the parameter value and return the new version."""
        from botocore.exceptions import ClientError

        try:
            response = self._client.put_parameter(
                Name=self.parameter_name, Value=encode_object(value), Type="String", Overwrite=True
            )
        except ClientError as exc:
            raise _translate(exc, self.where) from None
        return str(response["Version"])

    def get(self) -> JsonObject:
        """Return the whole config object."""
        return self._read()[1]

    def set(self, key: str, value: Any) -> WriteResult:
        """Merge one key into the object, keeping every other key."""
        return self._update(_with_key(validate_key(key), value))

    def unset(self, key: str) -> WriteResult:
        """Remove one key from the object, writing nothing when it is already absent."""
        return self._update(_without_key(validate_key(key)))

    def _update(self, mutate: Mutation) -> WriteResult:
        """Apply one mutation under the concurrent change guard."""
        return _merge(self._read, self.current_version, self._write, mutate, retries=self._retries, where=self.where)


def read_secret_value(
    key: str,
    stdin: IO[str],
    *,
    prompt: Callable[[str], str] = getpass.getpass,
) -> str:
    """Read a secret value from a hidden, confirmed prompt on a terminal, otherwise from stdin."""
    if stdin.isatty():
        value = prompt(f"Value for {key}: ")
        if prompt(f"Confirm {key}: ") != value:
            raise UsageError("the two values did not match; nothing written")
    else:
        value = stdin.read()
        if value.endswith("\r\n"):
            value = value[:-2]
        elif value.endswith("\n"):
            value = value[:-1]
    if value == "":
        raise UsageError(f"refusing an empty value; use `{PROG} secret unset {key}` to remove a key")
    return value


def render_config_value(value: Any) -> str:
    """Render one config value: a string raw, anything else as JSON."""
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


def _add_target_options(parser: argparse.ArgumentParser, *, suppress: bool) -> None:
    """Add the target options, suppressing defaults on subcommands so a top-level value survives."""
    default: Any = argparse.SUPPRESS if suppress else None
    group = parser.add_argument_group("target")
    group.add_argument("--prefix", default=default, help="resource prefix, e.g. carmodpicker-staging")
    group.add_argument("--secret-id", default=default, help="secret id or ARN, overriding <prefix>/app")
    group.add_argument("--parameter-name", default=default, help="SSM parameter name, overriding /<prefix>/config")
    group.add_argument("--profile", default=default, help="AWS profile; defaults to AWS_PROFILE or the SDK chain")
    group.add_argument("--region", default=default, help="AWS region; defaults to the SDK chain")


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the `webbpulse-config` command surface."""
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Set an environment's app secret keys and private config. No command prints a secret value.",
        epilog=(
            f"exit codes: {EXIT_OK} ok, {EXIT_AWS_ERROR} AWS error, {EXIT_USAGE} usage, "
            f"{EXIT_MISSING} secret or parameter missing, {EXIT_NOT_OBJECT} stored value not a JSON object, "
            f"{EXIT_CONFLICT} concurrent change, {EXIT_KEY_ABSENT} config key absent"
        ),
    )
    _add_target_options(parser, suppress=False)
    kinds = parser.add_subparsers(dest="kind", required=True, metavar="{secret,config}")

    secret = kinds.add_parser("secret", help="keys of the <prefix>/app Secrets Manager JSON secret")
    secret_actions = secret.add_subparsers(dest="action", required=True, metavar="{set,unset,keys}")
    secret_set = secret_actions.add_parser("set", help="set KEY from a hidden prompt or stdin")
    secret_set.add_argument("key", metavar="KEY")
    secret_unset = secret_actions.add_parser("unset", help="remove KEY")
    secret_unset.add_argument("key", metavar="KEY")
    secret_keys = secret_actions.add_parser("keys", help="list key names, one per line")

    config = kinds.add_parser("config", help="keys of the /<prefix>/config SSM JSON parameter")
    config_actions = config.add_subparsers(dest="action", required=True, metavar="{set,get,unset}")
    config_set = config_actions.add_parser("set", help="set KEY to VALUE, parsed as JSON when it parses")
    config_set.add_argument("key", metavar="KEY")
    config_set.add_argument("value", metavar="VALUE")
    config_set.add_argument("--string", action="store_true", help="store VALUE as a string even if it parses as JSON")
    config_get = config_actions.add_parser("get", help="print KEY, or the whole object without KEY")
    config_get.add_argument("key", metavar="KEY", nargs="?")
    config_unset = config_actions.add_parser("unset", help="remove KEY")
    config_unset.add_argument("key", metavar="KEY")

    for leaf in (secret_set, secret_unset, secret_keys, config_set, config_get, config_unset):
        _add_target_options(leaf, suppress=True)
    return parser


def _session(profile: str | None, region: str | None) -> Any:
    """Open a boto3 session on the operator's profile and resolved region."""
    try:
        import boto3
    except ImportError:
        raise ConfigToolError(f"{PROG} needs boto3; install webbpulse[dynamodb]") from None
    session = boto3.Session(profile_name=profile, region_name=region)
    if not session.region_name:
        raise UsageError("no AWS region resolved; pass --region or set one on the profile or in AWS_REGION")
    return session


def _report(stderr: IO[str], result: WriteResult, done: str, noop: str) -> None:
    """Write the one-line outcome of a merge to stderr."""
    if result.changed:
        print(f"{done} (version {result.version})", file=stderr)
    else:
        print(f"{noop}; nothing written", file=stderr)


def _run_secret(
    args: argparse.Namespace,
    session: Any,
    secret_id: str,
    stdin: IO[str],
    stdout: IO[str],
    stderr: IO[str],
    prompt: Callable[[str], str],
) -> None:
    """Dispatch a `secret` subcommand."""
    store = SecretStore(session.client("secretsmanager"), secret_id)
    where = f"{store.where} ({session.region_name})"
    if args.action == "keys":
        for key in store.key_names():
            print(key, file=stdout)
        return
    key = validate_key(args.key)
    if args.action == "set":
        if not is_upper_snake(key):
            print(f"warning: secret key {key!r} is not UPPER_SNAKE", file=stderr)
        value = read_secret_value(key, stdin, prompt=prompt)
        _report(stderr, store.set(key, value), f"set {key} in {where}", f"{key} already holds that value")
        return
    _report(stderr, store.unset(key), f"removed {key} from {where}", f"{key} is not in {where}")


def _run_config(args: argparse.Namespace, session: Any, parameter_name: str, stdout: IO[str], stderr: IO[str]) -> None:
    """Dispatch a `config` subcommand."""
    store = ConfigStore(session.client("ssm"), parameter_name)
    where = f"{store.where} ({session.region_name})"
    if args.action == "get":
        current = store.get()
        if args.key is None:
            print(json.dumps(current, indent=2, sort_keys=True, ensure_ascii=False), file=stdout)
            return
        key = validate_key(args.key)
        if key not in current:
            raise KeyAbsentError(f"{key} is not in {where}")
        print(render_config_value(current[key]), file=stdout)
        return
    key = validate_key(args.key)
    if args.action == "set":
        value = parse_config_value(args.value, force_string=args.string)
        _report(stderr, store.set(key, value), f"set {key} in {where}", f"{key} already holds that value")
        return
    _report(stderr, store.unset(key), f"removed {key} from {where}", f"{key} is not in {where}")


def main(
    argv: Sequence[str] | None = None,
    *,
    stdin: IO[str] | None = None,
    stdout: IO[str] | None = None,
    stderr: IO[str] | None = None,
    prompt: Callable[[str], str] = getpass.getpass,
) -> int:
    """Run the CLI and return its exit code."""
    stdin = stdin if stdin is not None else sys.stdin
    stdout = stdout if stdout is not None else sys.stdout
    stderr = stderr if stderr is not None else sys.stderr
    args = build_parser().parse_args(argv)
    target = resolve_target(args.prefix, args.secret_id, args.parameter_name)
    try:
        from botocore.exceptions import BotoCoreError
    except ImportError:
        print(f"{PROG}: needs boto3; install webbpulse[dynamodb]", file=stderr)
        return EXIT_AWS_ERROR
    try:
        if args.kind == "secret":
            if target.secret_id is None:
                raise UsageError("pass --prefix or --secret-id")
            _run_secret(args, _session(args.profile, args.region), target.secret_id, stdin, stdout, stderr, prompt)
        else:
            if target.parameter_name is None:
                raise UsageError("pass --prefix or --parameter-name")
            _run_config(args, _session(args.profile, args.region), target.parameter_name, stdout, stderr)
    except ConfigToolError as exc:
        print(f"{PROG}: {exc}", file=stderr)
        return exc.exit_code
    except BotoCoreError as exc:
        print(f"{PROG}: {exc}", file=stderr)
        return EXIT_AWS_ERROR
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
