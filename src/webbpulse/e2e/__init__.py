"""The `webbpulse.e2e` pytest plugin: fixtures for post-deploy tests against a real stage.

Enable it from a product's `e2e/conftest.py`:

    pytest_plugins = ["webbpulse.e2e"]

and re-export the generic suite from `e2e/test_shared.py`:

    from webbpulse.e2e.suite import *  # noqa: F401,F403

The product conftest supplies the two things the plugin cannot know: `openapi_document`,
from its own app factory so the document describes exactly the deployed commit, and
`cors_request_headers`, the header list the shared TypeScript client sends. Everything else
comes from the `E2E_*` environment variables the reusable workflow sets.

Nothing in here prints a gate value, a password or a token.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import pytest

from webbpulse.config import rate_limits_apply

from .access_log import AccessLogLookup
from .client import DEFAULT_PER_MINUTE, E2EClient
from .ephemeral import (
    CREATE_PATH,
    Credentials,
    EphemeralUser,
    create_ephemeral_user,
    describe_delete_failure,
)
from .gate import GateCookies
from .gateway import (
    Authorizer,
    Operation,
    Route,
    fetch_authorizers,
    fetch_routes,
    gate_authorizer_ids,
    operations_from_openapi,
    routes_from_openapi,
)
from .identity import IdentitySession, login, mint
from .journeys import (
    Click,
    ExpectText,
    ExpectUrl,
    ExpectVisible,
    Fill,
    Goto,
    Journey,
    LoginForm,
    Record,
    RouteSpec,
)
from .xdist import SHARED_STATE_GROUP, apply_groups, worker_id

__all__ = [
    "CREATE_PATH",
    "E2E_PREFIX",
    "GATE_HEADER",
    "LOCAL_ACCESS_LOG_REASON",
    "LOCAL_ENVIRONMENT",
    "LOCAL_GATEWAY_REASON",
    "READ_ONLY_REASON",
    "SHARED_STATE_GROUP",
    "WRITES_MARKER",
    "Click",
    "Credentials",
    "E2EEnvironment",
    "EphemeralUser",
    "ExpectText",
    "ExpectUrl",
    "ExpectVisible",
    "Fill",
    "GateCookies",
    "Goto",
    "Journey",
    "LoginForm",
    "MissingEnvironment",
    "Record",
    "RouteSpec",
    "pytest_addhooks",
]

pytest_plugins = ["webbpulse.e2e.gate", "webbpulse.e2e.browser"]

_REQUIRED = (
    "E2E_ENVIRONMENT",
    "E2E_API_BASE_URL",
    "E2E_WEB_BASE_URL",
    "E2E_AWS_REGION",
    "E2E_API_ID",
    "E2E_ACCESS_LOG_GROUP",
    "E2E_RUN_ID",
)

LOCAL_ENVIRONMENT = "local"

_GATEWAY_REQUIRED = ("E2E_API_ID", "E2E_ACCESS_LOG_GROUP")

LOCAL_GATEWAY_REASON = "gateway only, runs post deploy"

LOCAL_ACCESS_LOG_REASON = "the access log is gateway only, runs post deploy"

_USER_REQUIRED = ("E2E_USER_EMAIL", "E2E_USER_PASSWORD")

_MINT_REQUIRED = ("E2E_KMS_KEY_ID", "E2E_ISSUER", "E2E_AUDIENCE")

_WEB_GATE = (
    "E2E_GATE_SIGNING_KEY_SSM_PARAMETER",
    "E2E_GATE_KEY_PAIR_ID",
    "E2E_GATE_COOKIE_DOMAIN",
)

BROWSER_NAMES = ("chromium", "firefox", "webkit")
DEFAULT_BROWSER_TIMEOUT_MS = 15000

GATE_HEADER = "x-origin-verify"
E2E_PREFIX = "e2e-"
STALE_SECONDS = 3600


class MissingEnvironment(RuntimeError):
    """One or more `E2E_*` variables are unset, named individually.

    A suite that starts with a missing base URL fails every test with a connection error and
    buries the one line that explains it, so this refuses at collection and says which
    variables to set.
    """


def _truthy(value: str) -> bool:
    """Whether an environment variable's string means yes."""
    return value.strip().lower() in ("1", "true", "yes", "on")


def _positive_int(value: str, default: int) -> int:
    """One variable read as a positive integer, falling back when absent or unparseable."""
    try:
        parsed = int(value.strip())
    except (AttributeError, ValueError):
        return default
    return parsed if parsed > 0 else default


@dataclass(frozen=True)
class E2EEnvironment:
    """Everything the suite needs about the environment under test, from `E2E_*`.

    `read_only` is set from `E2E_READ_ONLY` and is what a production run uses: production has
    no durable e2e user, so `user_email` and `user_password` are empty there and every case
    that would sign in, write or mutate is skipped with one reason.

    `gate_ssm_parameter` is empty in production, which has no gate. `legacy_route_names` is
    the list of strings that must not appear in the deployed bundle. The three
    `gate_signing_key_ssm_parameter`, `gate_key_pair_id` and `gate_cookie_domain` fields
    describe the staging web gate and are all set together or all empty.

    `rate_limit_per_minute` is only the fallback the pacer uses for answers that carry no
    `X-RateLimit-Remaining-Minute` header, and it is read from `E2E_RATE_LIMIT_PER_MINUTE`.
    It is ignored entirely where the target does not rate limit.
    """

    environment: str
    api_base_url: str
    web_base_url: str
    aws_region: str
    api_id: str
    access_log_group: str
    user_email: str
    user_password: str = field(repr=False)
    run_id: str
    gate_ssm_parameter: str = ""
    gate_signing_key_ssm_parameter: str = ""
    gate_key_pair_id: str = ""
    gate_cookie_domain: str = ""
    browser_name: str = "chromium"
    headless: bool = True
    browser_artifacts_dir: str = ""
    browser_timeout_ms: int = DEFAULT_BROWSER_TIMEOUT_MS
    read_only: bool = False
    mint_enabled: bool = False
    kms_key_id: str = ""
    issuer: str = ""
    audience: str = ""
    legacy_route_names: tuple[str, ...] = ()
    rate_limit_per_minute: int = DEFAULT_PER_MINUTE

    @property
    def signs_in(self) -> bool:
        """Whether this run may sign in as the durable e2e user.

        False in read-only mode, which is what a production run is: production has no e2e
        user, so there is no credential to sign in with and nothing that needs one can run.
        """
        return not self.read_only

    @property
    def is_production(self) -> bool:
        """Whether this is the production stage, which has no gate and refuses minting."""
        return self.environment.lower() == "production"

    @property
    def is_local(self) -> bool:
        """Whether this run drives a stack built from source on the runner, with no AWS.

        A local stack has no API Gateway, no CloudWatch access log, no access gate and no
        KMS key, so `api_id`, `access_log_group`, the gate variables and the mint variables
        are all empty and nothing here may construct an AWS client. What it does have is
        the two base URLs, a run id and a user the product seeds itself.
        """
        return self.environment.lower() == LOCAL_ENVIRONMENT

    @property
    def rate_limited(self) -> bool:
        """Whether the target paces callers, by the same convention the services deploy with.

        Staging is never rate limited, so the suite runs there at full speed; everywhere
        else the client paces itself under the per-IP minute limit.
        """
        return rate_limits_apply(self.environment)

    @property
    def has_web_gate(self) -> bool:
        """Whether this environment sits behind the CloudFront web gate."""
        return bool(self.gate_signing_key_ssm_parameter)

    @property
    def resource_prefix(self) -> str:
        """The name prefix every resource this run creates carries, so leftovers are findable."""
        return f"{E2E_PREFIX}{self.run_id}-"

    @classmethod
    def from_environ(cls, environ: Mapping[str, str] | None = None) -> E2EEnvironment:
        """Build the environment from `E2E_*`, naming every missing variable at once.

        Every missing name is reported together rather than one per run, because a workflow
        that is wired wrong is usually wired wrong in more than one place.
        """
        source = os.environ if environ is None else environ
        read_only = _truthy(source.get("E2E_READ_ONLY", ""))
        is_local = source.get("E2E_ENVIRONMENT", "").strip().lower() == LOCAL_ENVIRONMENT
        required = tuple(name for name in _REQUIRED if not (is_local and name in _GATEWAY_REQUIRED))
        missing = [name for name in required if not source.get(name, "").strip()]
        if not read_only:
            missing.extend(name for name in _USER_REQUIRED if not source.get(name, "").strip())
        mint_enabled = _truthy(source.get("E2E_MINT_ENABLED", "")) and not is_local
        if mint_enabled:
            missing.extend(name for name in _MINT_REQUIRED if not source.get(name, "").strip())
        if missing:
            raise MissingEnvironment(
                "The webbpulse.e2e plugin needs these environment variables and they are "
                f"unset or empty: {', '.join(sorted(set(missing)))}. The reusable e2e.yml "
                "workflow sets them from its inputs; locally, see docs/e2e.md."
            )

        gate_values = {name: source.get(name, "").strip() for name in _WEB_GATE}
        set_names = sorted(name for name, value in gate_values.items() if value)
        if set_names and len(set_names) != len(_WEB_GATE):
            raise MissingEnvironment(
                "The staging web gate variables must be set together or left entirely "
                f"empty. Set: {', '.join(set_names)}. Unset or empty: "
                f"{', '.join(sorted(set(_WEB_GATE) - set(set_names)))}. A partial set mints "
                "no session, so every browser case would be answered by the gate's redirect "
                "to the hosted UI rather than by the app."
            )

        browser_name = source.get("E2E_BROWSER", "").strip().lower() or "chromium"
        if browser_name not in BROWSER_NAMES:
            raise MissingEnvironment(
                f"E2E_BROWSER is {browser_name!r}, which is not one of {', '.join(BROWSER_NAMES)}."
            )

        raw_legacy = source.get("E2E_LEGACY_ROUTE_NAMES", "")
        legacy = tuple(name.strip() for name in raw_legacy.split(",") if name.strip())
        return cls(
            environment=source["E2E_ENVIRONMENT"].strip(),
            api_base_url=source["E2E_API_BASE_URL"].strip().rstrip("/"),
            web_base_url=source["E2E_WEB_BASE_URL"].strip().rstrip("/"),
            aws_region=source["E2E_AWS_REGION"].strip(),
            api_id=source.get("E2E_API_ID", "").strip(),
            access_log_group=source.get("E2E_ACCESS_LOG_GROUP", "").strip(),
            user_email=source.get("E2E_USER_EMAIL", "").strip(),
            user_password=source.get("E2E_USER_PASSWORD", ""),
            run_id=source["E2E_RUN_ID"].strip(),
            gate_ssm_parameter=source.get("E2E_GATE_SSM_PARAMETER", "").strip(),
            gate_signing_key_ssm_parameter=gate_values["E2E_GATE_SIGNING_KEY_SSM_PARAMETER"],
            gate_key_pair_id=gate_values["E2E_GATE_KEY_PAIR_ID"],
            gate_cookie_domain=gate_values["E2E_GATE_COOKIE_DOMAIN"],
            browser_name=browser_name,
            headless=_truthy(source.get("E2E_HEADLESS", "true")),
            browser_artifacts_dir=source.get("E2E_BROWSER_ARTIFACTS_DIR", "").strip(),
            browser_timeout_ms=_positive_int(source.get("E2E_BROWSER_TIMEOUT_MS", ""), DEFAULT_BROWSER_TIMEOUT_MS),
            read_only=read_only,
            mint_enabled=mint_enabled,
            kms_key_id=source.get("E2E_KMS_KEY_ID", "").strip(),
            issuer=source.get("E2E_ISSUER", "").strip().rstrip("/"),
            audience=source.get("E2E_AUDIENCE", "").strip(),
            legacy_route_names=legacy,
            rate_limit_per_minute=_positive_int(source.get("E2E_RATE_LIMIT_PER_MINUTE", ""), DEFAULT_PER_MINUTE),
        )


WRITES_MARKER = "e2e_writes"
READ_ONLY_REASON = (
    "E2E_READ_ONLY is set, so this run is an anonymous read-only smoke. This case signs in "
    "as the durable e2e user, writes, or mutates state, and production has no e2e user."
)


def pytest_addhooks(pluginmanager: Any) -> None:
    """Register this plugin's own hook specifications."""
    from . import hookspecs

    pluginmanager.add_hookspecs(hookspecs)


def pytest_configure(config: pytest.Config) -> None:
    """Register the `e2e_writes` marker, so `--strict-markers` accepts it."""
    config.addinivalue_line(
        "markers",
        f"{WRITES_MARKER}: this case signs in as the e2e user, writes, or mutates state. "
        "Skipped when E2E_READ_ONLY is set.",
    )
    config.addinivalue_line(
        "markers",
        "xdist_group(name): pytest-xdist `--dist loadgroup` scheduling group. Registered "
        "here so `--strict-markers` accepts it whether or not xdist is installed.",
    )


LOCAL_SKIPPED_GROUPS: Mapping[str, str] = {
    "TestRouteCut": (
        "the route cut is a gateway concern: it needs the deployed route table, the "
        f"forwarded request context and the CloudWatch access log. {LOCAL_GATEWAY_REASON}."
    ),
}

LOCAL_SKIPPED_CASES: Mapping[str, str] = {
    "test_authorizer_matches_the_operation": (
        f"a local stack has no gateway authorizers to compare an operation against. {LOCAL_GATEWAY_REASON}."
    ),
}


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Group the shared-state cases for xdist, then skip what this environment cannot run.

    The grouping runs on every collection, distributed or not: an `xdist_group` marker is
    inert without xdist, so one pass serves both.

    One place rather than a conditional in each case, so a product that marks a new mutating
    test gets the production skip for free and cannot accidentally ship one that runs there,
    and a local run skips every gateway case by group name without the case knowing. The
    environment is read directly rather than through the `e2e_env` fixture because
    collection happens before any fixture runs.
    """
    apply_groups(items)
    if _local_from_environ():
        _skip_gateway_only_cases(items)
    if not _read_only_from_environ():
        return
    skip = pytest.mark.skip(reason=READ_ONLY_REASON)
    for item in items:
        if item.get_closest_marker(WRITES_MARKER) is not None:
            item.add_marker(skip)


def _skip_gateway_only_cases(items: Sequence[pytest.Item]) -> None:
    """Skip the cases that only a deployed gateway can answer, by group and by name.

    Matched on the class name and the function name rather than on a marker, because the
    groups are the plugin's own and a product re-exporting them must not have to mark
    anything. A product case of its own is never touched: its class is not one of these.
    """
    for item in items:
        group = _owning_group(item)
        reason = LOCAL_SKIPPED_GROUPS.get(group) if group else None
        if reason is None:
            reason = LOCAL_SKIPPED_CASES.get(item.originalname if isinstance(item, pytest.Function) else item.name)
        if reason is not None:
            item.add_marker(pytest.mark.skip(reason=reason))


def _owning_group(item: pytest.Item) -> str:
    """The name of the suite class a case belongs to, or "" for a module level case."""
    cls = getattr(item, "cls", None)
    return "" if cls is None else str(cls.__name__)


def _read_only_from_environ() -> bool:
    """Whether `E2E_READ_ONLY` is set, readable at collection with no fixture."""
    return _truthy(os.environ.get("E2E_READ_ONLY", ""))


def _local_from_environ() -> bool:
    """Whether `E2E_ENVIRONMENT` is local, readable at collection with no fixture."""
    return os.environ.get("E2E_ENVIRONMENT", "").strip().lower() == LOCAL_ENVIRONMENT


@pytest.fixture(scope="session")
def e2e_env() -> E2EEnvironment:
    """The environment under test, parsed from `E2E_*`."""
    return E2EEnvironment.from_environ()


@pytest.fixture(scope="session")
def boto3_session(e2e_env: E2EEnvironment) -> Any:
    """One boto3 session for the run, pinned to the environment's region."""
    import boto3

    return boto3.session.Session(region_name=e2e_env.aws_region)


@pytest.fixture(scope="session")
def gate_headers(e2e_env: E2EEnvironment, request: pytest.FixtureRequest) -> Mapping[str, str]:
    """The `x-origin-verify` header staging requires, read from SSM and never printed.

    Production and a local stack have no gate and yield an empty mapping without reading
    SSM, so neither builds a boto3 session at all: `boto3_session` is requested only on the
    path that actually calls AWS. A staging run whose parameter is unset fails here rather
    than answering 401 to every probe, which is the failure mode the prior art warns about
    loudest: the gate's 401 reads exactly like a broken route.
    """
    if not e2e_env.gate_ssm_parameter:
        if not e2e_env.is_production and not e2e_env.is_local:
            pytest.fail(
                "E2E_GATE_SSM_PARAMETER is empty in a non-production environment. Staging "
                "sits behind the access gate, so every request below would be answered by "
                "the gate with a 401 rather than by the API, and the whole suite would read "
                "as broken routing that is really a missing credential."
            )
        return {}
    boto3_session = request.getfixturevalue("boto3_session")
    client = boto3_session.client("ssm")
    response = client.get_parameter(Name=e2e_env.gate_ssm_parameter, WithDecryption=True)
    value = str(response["Parameter"]["Value"])
    return {GATE_HEADER: value}


@pytest.fixture(scope="session")
def anon(e2e_env: E2EEnvironment, gate_headers: Mapping[str, str]) -> Iterator[E2EClient]:
    """A client carrying the gate header and no identity."""
    client = E2EClient(
        base_url=e2e_env.api_base_url,
        gate_headers=gate_headers,
        per_minute=e2e_env.rate_limit_per_minute if e2e_env.rate_limited else 0,
    )
    try:
        yield client
    finally:
        client.close()


@pytest.fixture(scope="session")
def admin_mint_token(e2e_env: E2EEnvironment, request: pytest.FixtureRequest) -> str:
    """A minted token carrying the admin role, or empty when this run cannot mint.

    The key that signs it is the staging KMS key the e2e workflow alone may use, so holding
    this token is the whole authorisation for creating and deleting an ephemeral user.
    Returns the empty string rather than skipping, because the caller falls back to the
    durable user instead of failing. That is the local path: a local stack has no KMS key,
    so minting is off, this is empty and the run signs in as the user the product seeded.

    `boto3_session` is requested only once minting is known to be on, so a run that cannot
    mint constructs no AWS client.

    The subject is this run's own id rather than a real user: the ephemeral routes read only
    the `roles` claim, so no subject has to resolve to a stored row.

    A mint that was asked for and failed warns before falling back, naming the exception
    type and message. A silent fallback made a broken key or a missing permission look like
    an ordinary durable-user run. The token itself never reaches the warning.
    """
    if not e2e_env.mint_enabled or e2e_env.read_only:
        return ""
    boto3_session = request.getfixturevalue("boto3_session")
    try:
        return mint(
            kms_client=boto3_session.client("kms"),
            key_id=e2e_env.kms_key_id,
            environment=e2e_env.environment,
            issuer=e2e_env.issuer,
            audience=e2e_env.audience,
            subject=f"{E2E_PREFIX}{e2e_env.run_id}-admin",
            expires_in=3600,
            extra_claims={"roles": ["admin"]},
        )
    except Exception as error:
        request.config.issue_config_time_warning(
            UserWarning(
                f"Minting the admin token failed with {type(error).__name__}: {error}. This run "
                "falls back to the durable user, so it creates no ephemeral user and shares the "
                "account with every other run against this environment."
            ),
            stacklevel=2,
        )
        return ""


@pytest.fixture(scope="session")
def ephemeral_user_attributes() -> Mapping[str, Any]:
    """The attributes this run's ephemeral user is created with, empty by default.

    Override it in a product's `e2e/conftest.py` to have `ephemeral_user` create a user
    whose row already carries what the product's authorisation reads, rather than
    reimplementing the whole fixture to pass one argument:

        @pytest.fixture(scope="session")
        def ephemeral_user_attributes() -> dict[str, object]:
            return {"is_admin": True, "email_verified": True}

    A product that grants write scopes only to an admin or a verified row needs this, since
    a user created with no attributes holds read scopes alone and every write case would be
    refused. The mapping reaches `create_ephemeral_user` as `attributes=` and nothing else
    reads it, so a product may put anything its own create route accepts in it.
    """
    return {}


@pytest.fixture(scope="session")
def ephemeral_user(
    request: pytest.FixtureRequest,
    e2e_env: E2EEnvironment,
    anon: E2EClient,
    admin_mint_token: str,
    ephemeral_user_attributes: Mapping[str, Any],
) -> Iterator[EphemeralUser | None]:
    """This run's own login user, created at session start and deleted at session end.

    None whenever the run cannot have one: a read-only run signs in as nobody, and a run
    that cannot mint holds no admin token to authorise the route with. None is also what a
    deployment that does not offer the route gives back, and every caller then falls back to
    the durable user.

    Under xdist each worker holds its own session, so each creates and deletes a user of its
    own. The run id is suffixed with the worker id to keep the addresses apart; one worker
    per user means a worker that dies takes only its own user with it, and no lock file or
    cross-worker handshake is needed.

    Deletion failures are warnings rather than failures. The account carries the sweepable
    `e2e-` prefix, so the next run's start sweep collects anything left behind.

    The user is created with whatever `ephemeral_user_attributes` yields, so a product that
    needs an admin or verified row overrides that one fixture rather than this whole one.
    """
    if e2e_env.read_only or not admin_mint_token:
        yield None
        return
    run_id = f"{e2e_env.run_id}-{worker_id(request.config)}"
    user = create_ephemeral_user(
        anon,
        run_id=run_id,
        admin_token=admin_mint_token,
        attributes=dict(ephemeral_user_attributes),
    )
    try:
        yield user
    finally:
        failure = describe_delete_failure(anon, user, admin_token=admin_mint_token) if user is not None else ""
        if user is not None and failure:
            request.config.issue_config_time_warning(
                UserWarning(
                    f"The ephemeral e2e user {user.user_id} could not be deleted: {failure} It "
                    "carries the e2e- prefix, so the next run's start sweep will collect it."
                ),
                stacklevel=2,
            )


@pytest.fixture(scope="session")
def credentials(e2e_env: E2EEnvironment, ephemeral_user: EphemeralUser | None) -> Credentials:
    """The credentials this run signs in with: its own user where it has one.

    The single place that decides between the ephemeral user and the durable one, so every
    caller, the API login and the browser form alike, follows the same choice without
    knowing which it got.
    """
    if ephemeral_user is not None:
        return ephemeral_user.credentials
    return Credentials(email=e2e_env.user_email, password=e2e_env.user_password)


@pytest.fixture(scope="session")
def user_session(e2e_env: E2EEnvironment, anon: E2EClient, credentials: Credentials) -> IdentitySession:
    """This run's login user, signed in through the real login route.

    Skips in read-only mode rather than attempting a login with no credential. The marker
    already skips every case the plugin ships that would reach here, so this is the backstop
    that catches a product case which forgot the marker: it can only skip, never sign in.
    """
    if not e2e_env.signs_in:
        pytest.skip(READ_ONLY_REASON)
    return login(anon, credentials.email, credentials.password)


@pytest.fixture(scope="session")
def api(user_session: IdentitySession) -> E2EClient:
    """The authenticated client, sharing the anonymous client's pacer and gate header."""
    return user_session.client


@pytest.fixture(scope="session")
def minted_subject(user_session: IdentitySession) -> str:
    """The durable e2e user's real subject: the `sub` claim of the session's access token.

    A minted token names a subject the application has to resolve to a stored user, so a
    synthetic string is refused at that step whatever the claim under test says. Read from
    the access token rather than from a login response field, because `sub` is what the
    authorizer forwards and what the application maps.

    Skips rather than fails on a session whose token carries no `sub`: a token naming no
    real subject makes every mint case fail for the wrong reason.
    """
    subject = user_session.user_id
    if not subject:
        pytest.skip(
            "the durable e2e user's access token carries no `sub` claim, so a minted token "
            "would name no real subject and the API would reject it before reading any "
            "other claim."
        )
    return subject


@pytest.fixture(scope="session")
def minted_token(
    e2e_env: E2EEnvironment,
    request: pytest.FixtureRequest,
    minted_subject: str,
) -> Callable[..., str]:
    """Mint an access token through KMS without a login, staging only.

    The subject defaults to `minted_subject`, which is the `sub` claim of the durable e2e
    user's own access token, and an explicit `subject=` still overrides it. A made-up
    subject names no real user, so the API rejects the token on subject resolution and every
    mint case passes or fails for a reason that has nothing to do with the claim it was
    testing: a token minted with the wrong audience would be refused even with the right one.

    Skips rather than fails when `E2E_MINT_ENABLED` is unset, which is every environment
    but staging. `mint_test_token` refuses production independently of that flag, so the
    skip and the package's refusal are two separate checks on the same thing. Needing the
    durable user means read-only production skips here as well, which is correct: there is
    no real subject to mint for.
    """
    if not e2e_env.mint_enabled:
        pytest.skip("E2E_MINT_ENABLED is not set, so no token is minted in this environment")
    kms = request.getfixturevalue("boto3_session").client("kms")

    def _mint(
        claims: Mapping[str, Any] | None = None,
        *,
        subject: str | None = None,
        audience: str | None = None,
        expires_in: int = 600,
        now: int | None = None,
    ) -> str:
        """Mint one token, overriding the audience or expiry to exercise a rejection."""
        return mint(
            kms_client=kms,
            key_id=e2e_env.kms_key_id,
            environment=e2e_env.environment,
            issuer=e2e_env.issuer,
            audience=e2e_env.audience if audience is None else audience,
            subject=subject or minted_subject,
            expires_in=expires_in,
            extra_claims=claims,
            now=now,
        )

    return _mint


@pytest.fixture(scope="session")
def gateway_routes(request: pytest.FixtureRequest, e2e_env: E2EEnvironment) -> tuple[Route, ...]:
    """Every live route on the API, with its integration target and authorizer id.

    Reuses the list the suite's collection already read where there is one, so a run makes
    one `get-routes` call rather than two against the same stage. On a local stack the
    cached list was synthesized from the product's own OpenAPI document and no AWS call is
    made here either.
    """
    cached = request.config.pluginmanager.get_plugin("webbpulse-e2e-collection")
    routes = getattr(cached, "routes", None)
    if routes is None:
        if e2e_env.is_local:
            routes = routes_from_openapi(request.getfixturevalue("openapi_document"))
        else:
            routes = fetch_routes(request.getfixturevalue("boto3_session").client("apigatewayv2"), e2e_env.api_id)
    if not routes:
        pytest.fail(
            f"apigatewayv2 get-routes returned no routes for api {e2e_env.api_id}. Every "
            "assertion below is derived from that list, so an empty one would pass "
            "vacuously rather than say the api id is wrong."
        )
    return routes


@pytest.fixture(scope="session")
def gateway_authorizers(e2e_env: E2EEnvironment, request: pytest.FixtureRequest) -> tuple[Authorizer, ...]:
    """Every authorizer declared on the API, which is how the gate is told apart from identity.

    Empty on a local stack, which has no gateway and so no authorizers, and no AWS client
    is constructed to find that out.
    """
    if e2e_env.is_local:
        return ()
    boto3_session = request.getfixturevalue("boto3_session")
    return fetch_authorizers(boto3_session.client("apigatewayv2"), e2e_env.api_id)


@pytest.fixture(scope="session")
def gate_authorizers(gateway_authorizers: Sequence[Authorizer]) -> frozenset[str]:
    """Ids of the access gate authorizers on this API, empty in production.

    The gate authorizer is recognised from the API configuration itself, by REQUEST type
    plus the module's own `-access-gate-origin-verify` naming, so no environment variable
    has to name it.
    """
    return gate_authorizer_ids(gateway_authorizers)


@pytest.fixture(scope="session")
def route_keys(gateway_routes: Sequence[Route]) -> tuple[str, ...]:
    """The live route keys alone, which is what the precedence matcher takes."""
    return tuple(route.route_key for route in gateway_routes)


@pytest.fixture(scope="session")
def access_log(e2e_env: E2EEnvironment, request: pytest.FixtureRequest) -> AccessLogLookup:
    """A lookup that finds an access log entry by request id, with a bounded wait.

    A local stack has no CloudWatch access log, so this skips rather than building a logs
    client against an account the run has no credentials for. Every case that asks for it
    is a gateway case that the local collection hook has already skipped; this is the
    backstop for a product case that asks for it anyway.
    """
    if e2e_env.is_local:
        pytest.skip(LOCAL_ACCESS_LOG_REASON)
    boto3_session = request.getfixturevalue("boto3_session")
    return AccessLogLookup(boto3_session.client("logs"), e2e_env.access_log_group)


@pytest.fixture(scope="session")
def openapi_document() -> Mapping[str, Any]:
    """The deployed commit's OpenAPI document, which the product conftest must override.

    The plugin cannot produce it: only the product's own app factory knows the document,
    and taking it from anywhere else would describe a different commit than the one running.
    """
    pytest.fail(
        "The webbpulse.e2e plugin needs an `openapi_document` fixture from the product's "
        "e2e/conftest.py, built from its own app factory so the document describes exactly "
        "the deployed commit. See docs/e2e.md."
    )


@pytest.fixture(scope="session")
def openapi_operations(openapi_document: Mapping[str, Any]) -> tuple[Operation, ...]:
    """Every operation in the product's OpenAPI document."""
    operations = operations_from_openapi(openapi_document)
    if not operations:
        pytest.fail(
            "The product's openapi_document declares no operations, so the coverage suite would pass vacuously."
        )
    return operations


@pytest.fixture(scope="session")
def cors_request_headers() -> tuple[str, ...]:
    """The header names the shared TypeScript client sends, from the product conftest.

    Defaults to the ones every product sends, so a conftest that does not override it still
    catches the common case; a product whose client sends more must override it.
    """
    return ("authorization", "content-type")


@pytest.fixture(scope="session")
def http(e2e_env: E2EEnvironment, gate_cookies: GateCookies | None) -> Iterator[Any]:
    """A plain httpx client for the web origin, carrying the gate cookies where there are any.

    Without them a staging fetch of the shell follows the gate's 302 to the Cognito hosted
    UI and the shell assertions read as a broken deploy. The cookie values are handed to
    httpx and never printed.
    """
    import httpx

    cookies = dict(gate_cookies.as_httpx_cookies()) if gate_cookies is not None else {}
    client = httpx.Client(timeout=30.0, follow_redirects=True, cookies=cookies)
    try:
        yield client
    finally:
        client.close()


@pytest.fixture(scope="session")
def created_resources() -> list[Any]:
    """Handles for everything this run created, so the session end can delete them.

    A plain list rather than a registry: products append whatever their own cleanup hook
    understands, and the plugin never has to know the shape.
    """
    return []


@pytest.fixture(scope="session", autouse=True)
def e2e_hygiene(
    request: pytest.FixtureRequest,
    e2e_env: E2EEnvironment,
    created_resources: list[Any],
) -> Iterator[None]:
    """Sweep stale `e2e-` resources at session start and this run's at session end.

    Products register their own callables through the `pytest_e2e_cleanup` hook. The start
    pass is given an empty `created` list and is expected to delete anything older than an
    hour whose name carries the `e2e-` prefix; the end pass is given everything this run
    appended to `created_resources`.

    A hook that raises is reported as a warning rather than failing the suite: a leftover is
    worth knowing about and is never a reason to lose the result of the tests that already
    ran.

    In read-only mode the hook is not invoked at all, in either phase. The run creates
    nothing, so there is nothing of its own to delete, and the start sweep deletes resources,
    which is exactly what a read-only run must not do.
    """
    if e2e_env.read_only:
        yield
        return
    hook = request.config.hook.pytest_e2e_cleanup
    _warn_on_leftovers(request, _call_cleanup(hook, e2e_env, "start", []), "start")
    yield
    _warn_on_leftovers(request, _call_cleanup(hook, e2e_env, "end", created_resources), "end")


def _call_cleanup(hook: Any, env: E2EEnvironment, phase: str, created: Sequence[Any]) -> list[Any]:
    """Run every registered cleanup hook, turning a raise into a reportable leftover."""
    try:
        return list(hook(env=env, phase=phase, created=list(created)))
    except Exception as error:
        return [f"{type(error).__name__}: {error}"]


def _warn_on_leftovers(request: pytest.FixtureRequest, results: Sequence[Any], phase: str) -> None:
    """Turn what a cleanup hook reported into warnings, never into test failures."""
    for result in results:
        if not result:
            continue
        request.config.issue_config_time_warning(
            UserWarning(f"pytest_e2e_cleanup reported leftovers at the {phase} of the session: {result}"),
            stacklevel=2,
        )
