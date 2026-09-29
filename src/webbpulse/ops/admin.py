"""`webbpulse-admin`: grant, revoke and list product admins from a workstation.

A product admin is a `users` row in the product's identity users table with `is_admin`
set. This tool flips that flag for one user found by email or by id, with the operator's
own named AWS profile and never the default credential chain:

    uv run webbpulse-admin --profile CarModPicker-Staging/AdministratorAccess \\
        --prefix carmodpicker-staging grant --email someone@example.com

Every write is one conditional `UpdateItem`: the row must exist and must not already be in
the requested state, so a repeated grant or revoke writes nothing and reports so. The row
records who made the latest change and when, as `admin_granted_by` and `admin_granted_at`
after a grant or `admin_revoked_by` and `admin_revoked_at` after a revoke, and the actor is
the ARN `sts:GetCallerIdentity` returns for the profile. Each grant or revoke also prints one
JSON audit line on stdout, including a `--dry-run` that writes nothing.

Only masked addresses are ever printed. Diagnostics go to stderr and data to stdout. The
exit codes are the `EXIT_*` constants.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import IO, TYPE_CHECKING, Any, Final

from webbpulse.dynamodb import ConditionFailed, Repository
from webbpulse.dynamodb import table_name as prefixed_table_name
from webbpulse.identity.storage import USERS_TABLE
from webbpulse.identity.users import DynamoUsersRepository, User

if TYPE_CHECKING:
    from botocore.exceptions import ClientError
    from mypy_boto3_dynamodb.service_resource import Table

PROG: Final = "webbpulse-admin"

EXIT_OK: Final = 0
EXIT_AWS_ERROR: Final = 1
EXIT_USAGE: Final = 2
EXIT_USER_MISSING: Final = 3
EXIT_TABLE_MISSING: Final = 4

GRANTED_BY: Final = "admin_granted_by"
GRANTED_AT: Final = "admin_granted_at"
REVOKED_BY: Final = "admin_revoked_by"
REVOKED_AT: Final = "admin_revoked_at"

GRANT: Final = "grant"
REVOKE: Final = "revoke"

AUDIT_EVENTS: Final = {GRANT: "identity.admin_granted", REVOKE: "identity.admin_revoked"}


class AdminToolError(Exception):
    """A failure the CLI reports as one line on stderr with its own exit code."""

    exit_code = EXIT_AWS_ERROR


class UsageError(AdminToolError):
    """The command line was refused before any AWS call."""

    exit_code = EXIT_USAGE


class UserMissingError(AdminToolError):
    """No user row matches the email or id given."""

    exit_code = EXIT_USER_MISSING


class TableMissingError(AdminToolError):
    """The users table does not exist under the resolved name."""

    exit_code = EXIT_TABLE_MISSING


def mask_email(email: str) -> str:
    """Mask an address to its first local and first domain character, keeping the TLD.

    `tyler@gmail.com` becomes `t***@g***.com`. Anything that is not a plain address masks
    whole, so the raw value never leaks through a malformed row.
    """
    local, at, domain = str(email).strip().partition("@")
    host, dot, tld = domain.rpartition(".")
    if not at or not local or not dot or not host or not tld:
        return "***"
    return f"{local[0]}***@{host[0]}***.{tld}"


def _utc_now() -> str:
    """The current UTC time as an ISO 8601 string with seconds precision."""
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass(frozen=True)
class AdminChange:
    """The outcome of one grant or revoke, shaped for the audit line."""

    action: str
    user_id: str
    masked_email: str
    table: str
    actor_arn: str
    at: str
    changed: bool
    dry_run: bool

    def audit_record(self) -> dict[str, Any]:
        """The structured audit line for this change, carrying no raw address."""
        return {
            "event": AUDIT_EVENTS[self.action],
            "action": self.action,
            "user_id": self.user_id,
            "email": self.masked_email,
            "table": self.table,
            "actor_arn": self.actor_arn,
            "at": self.at,
            "changed": self.changed,
            "dry_run": self.dry_run,
        }


class _SessionRepository(Repository):
    """A `Repository` bound to a table from the operator's session, not the process default."""

    def __init__(self, table: Table) -> None:
        """Bind an already built table resource."""
        super().__init__(USERS_TABLE, prefix="")
        self.table_name = table.name
        self._table = table


def resolve_table_name(prefix: str | None, table_name: str | None) -> str:
    """Resolve `<prefix>-users`, letting an explicit table name win."""
    if table_name:
        return table_name
    clean = (prefix or "").strip().strip("-")
    if not clean:
        raise UsageError("pass --prefix or --table-name")
    return prefixed_table_name(USERS_TABLE, clean)


class AdminStore:
    """Grant, revoke and list admins on one users table, recording the acting identity."""

    def __init__(
        self,
        users: DynamoUsersRepository[User],
        *,
        actor_arn: str,
        clock: Callable[[], str] = _utc_now,
    ) -> None:
        """Bind a users repository and the ARN every write is attributed to."""
        self._users = users
        self._actor_arn = actor_arn
        self._clock = clock

    @property
    def table(self) -> str:
        """The physical users table name."""
        return self._users.repository.table_name

    def find(self, *, email: str | None = None, user_id: str | None = None) -> User:
        """Look a user up by id, or by address through the `email_lower` index."""
        if (email is None) == (user_id is None):
            raise UsageError("pass exactly one of --email and --user-id")
        user = self._users.get(user_id) if user_id is not None else self._users.get_by_email(email or "")
        if user is None:
            raise UserMissingError(f"no user matches that {'id' if user_id is not None else 'email'} in {self.table}")
        return user

    def grant(self, user: User, *, dry_run: bool = False) -> AdminChange:
        """Set `is_admin` on the user, writing nothing when it is already set."""
        return self._apply(GRANT, user, dry_run=dry_run)

    def revoke(self, user: User, *, dry_run: bool = False) -> AdminChange:
        """Clear `is_admin` on the user, writing nothing when it is already clear."""
        return self._apply(REVOKE, user, dry_run=dry_run)

    def admins(self) -> list[tuple[str, str]]:
        """Every admin as `(user_id, masked_email)`, sorted by id."""
        from boto3.dynamodb.conditions import Attr

        rows = self._users.repository.iter_scan(filter_expression=Attr("is_admin").eq(True))
        return sorted((str(row.get("id", "")), mask_email(str(row.get("email", "")))) for row in rows)

    def _apply(self, action: str, user: User, *, dry_run: bool) -> AdminChange:
        """Run one conditional flag change, or only report it under `dry_run`."""
        at = self._clock()
        want = action == GRANT
        changed = user.is_admin != want
        if changed and not dry_run:
            changed = self._write(user.id, want=want, at=at)

        return AdminChange(
            action=action,
            user_id=user.id,
            masked_email=mask_email(user.email),
            table=self.table,
            actor_arn=self._actor_arn,
            at=at,
            changed=changed,
            dry_run=dry_run,
        )

    def _write(self, user_id: str, *, want: bool, at: str) -> bool:
        """Write the flag and its audit attributes, returning whether a write landed.

        The condition requires the row and the opposite state, so a lost race with another
        operator making the same change reads back as a no-op and a deleted row as missing.
        """
        from boto3.dynamodb.conditions import Attr

        granted, revoked = (GRANTED_BY, GRANTED_AT), (REVOKED_BY, REVOKED_AT)
        (set_by, set_at), (clear_by, clear_at) = (granted, revoked) if want else (revoked, granted)
        state = (Attr("is_admin").not_exists() | Attr("is_admin").ne(True)) if want else Attr("is_admin").eq(True)
        try:
            self._users.repository.update(
                {"id": user_id},
                update_expression="SET #adm = :adm, #by = :by, #at = :at REMOVE #oby, #oat",
                expression_values={":adm": want, ":by": self._actor_arn, ":at": at},
                expression_names={"#adm": "is_admin", "#by": set_by, "#at": set_at, "#oby": clear_by, "#oat": clear_at},
                condition=Attr("id").exists() & state,
            )
        except ConditionFailed:
            if self._users.get(user_id) is None:
                raise UserMissingError(f"the user was deleted from {self.table} before the write") from None
            return False
        return True


def _error_code(exc: ClientError) -> str:
    """Return the AWS error code carried by a `ClientError`."""
    return str(exc.response.get("Error", {}).get("Code", ""))


def _translate(exc: ClientError, table: str) -> AdminToolError:
    """Turn a `ClientError` into the CLI error naming the table and the likely fix."""
    code = _error_code(exc)
    if code == "ResourceNotFoundException":
        return TableMissingError(f"table {table} does not exist; check --prefix, --table-name, --profile and --region")
    message = exc.response.get("Error", {}).get("Message", "")
    return AdminToolError(f"{table}: {code}: {message}")


def _add_target_options(parser: argparse.ArgumentParser, *, suppress: bool) -> None:
    """Add the target options, suppressing defaults on subcommands so a top-level value survives."""
    default: Any = argparse.SUPPRESS if suppress else None
    group = parser.add_argument_group("target")
    group.add_argument("--prefix", default=default, help="resource prefix, e.g. carmodpicker-staging")
    group.add_argument("--table-name", default=default, help="users table name, overriding <prefix>-users")
    group.add_argument("--profile", default=default, help="AWS profile; required, the default chain is never used")
    group.add_argument("--region", default=default, help="AWS region; defaults to the profile's region")


def _add_user_options(parser: argparse.ArgumentParser) -> None:
    """Add the mutually exclusive user selectors and `--dry-run`."""
    who = parser.add_mutually_exclusive_group(required=True)
    who.add_argument("--email", help="the user's address, matched case-insensitively")
    who.add_argument("--user-id", help="the user's id")
    parser.add_argument("--dry-run", action="store_true", help="report the change without writing")


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the `webbpulse-admin` command surface."""
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Grant, revoke and list admins in a product's identity users table.",
        epilog=(
            f"exit codes: {EXIT_OK} ok, {EXIT_AWS_ERROR} AWS error, {EXIT_USAGE} usage, "
            f"{EXIT_USER_MISSING} user not found, {EXIT_TABLE_MISSING} users table missing"
        ),
    )
    _add_target_options(parser, suppress=False)
    actions = parser.add_subparsers(dest="action", required=True, metavar="{grant,revoke,list}")
    grant = actions.add_parser(GRANT, help="make one user an admin")
    _add_user_options(grant)
    revoke = actions.add_parser(REVOKE, help="remove one user's admin flag")
    _add_user_options(revoke)
    listing = actions.add_parser("list", help="print every admin as user id and masked email")
    for leaf in (grant, revoke, listing):
        _add_target_options(leaf, suppress=True)
    return parser


def _session(profile: str | None, region: str | None) -> Any:
    """Open a boto3 session on the named profile, refusing the default credential chain."""
    if not profile or not profile.strip():
        raise UsageError(f"pass --profile; {PROG} never uses default credentials")
    try:
        import boto3
    except ImportError:
        raise AdminToolError(f"{PROG} needs boto3; install webbpulse[dynamodb]") from None
    session = boto3.Session(profile_name=profile.strip(), region_name=region)
    if not session.region_name:
        raise UsageError("no AWS region resolved; pass --region or set one on the profile")
    return session


def _run(args: argparse.Namespace, session: Any, table: str, stdout: IO[str], stderr: IO[str]) -> None:
    """Resolve the caller, bind the table and dispatch one action."""
    actor_arn = str(session.client("sts").get_caller_identity()["Arn"])
    users: DynamoUsersRepository[User] = DynamoUsersRepository(
        repository=_SessionRepository(session.resource("dynamodb").Table(table))
    )
    store = AdminStore(users, actor_arn=actor_arn)
    if args.action == "list":
        admins = store.admins()
        for user_id, masked in admins:
            print(f"{user_id}\t{masked}", file=stdout)
        print(f"{len(admins)} admin(s) in {table} ({session.region_name})", file=stderr)
        return
    user = store.find(email=args.email, user_id=args.user_id)
    apply = store.grant if args.action == GRANT else store.revoke
    change = apply(user, dry_run=args.dry_run)
    print(json.dumps(change.audit_record(), sort_keys=True), file=stdout)
    verb = "granted admin to" if change.action == GRANT else "revoked admin from"
    subject = f"{change.user_id} ({change.masked_email}) in {table}"
    if not change.changed:
        state = "already an admin" if change.action == GRANT else "not an admin"
        print(f"{subject} is {state}; nothing written", file=stderr)
    elif change.dry_run:
        print(f"dry run: would have {verb} {subject}; nothing written", file=stderr)
    else:
        print(f"{verb} {subject}", file=stderr)


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: IO[str] | None = None,
    stderr: IO[str] | None = None,
) -> int:
    """Run the CLI and return its exit code."""
    stdout = stdout if stdout is not None else sys.stdout
    stderr = stderr if stderr is not None else sys.stderr
    args = build_parser().parse_args(argv)
    try:
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        print(f"{PROG}: needs boto3; install webbpulse[dynamodb]", file=stderr)
        return EXIT_AWS_ERROR
    table = ""
    try:
        table = resolve_table_name(args.prefix, args.table_name)
        _run(args, _session(args.profile, args.region), table, stdout, stderr)
    except AdminToolError as exc:
        print(f"{PROG}: {exc}", file=stderr)
        return exc.exit_code
    except ClientError as exc:
        error = _translate(exc, table)
        print(f"{PROG}: {error}", file=stderr)
        return error.exit_code
    except BotoCoreError as exc:
        print(f"{PROG}: {exc}", file=stderr)
        return EXIT_AWS_ERROR
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
