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

from .access_log import AccessLogLookup
from .client import DEFAULT_PER_MINUTE, E2EClient
from .gate import GateCookies
from .gateway import (
    Authorizer,
    Operation,
    Route,
    fetch_authorizers,
    fetch_routes,
    gate_authorizer_ids,
    operations_from_openapi,
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

__all__ = [
    "E2E_PREFIX",
    "GATE_HEADER",
    "READ_ONLY_REASON",
    "WRITES_MARKER",
    "Click",
    "E2EEnvironment",
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
        missing = [name for name in _REQUIRED if not source.get(name, "").strip()]
        if not read_only:
            missing.extend(name for name in _USER_REQUIRED if not source.get(name, "").strip())
        mint_enabled = _truthy(source.get("E2E_MINT_ENABLED", ""))
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
            api_id=source["E2E_API_ID"].strip(),
            access_log_group=source["E2E_ACCESS_LOG_GROUP"].strip(),
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


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip every case marked `e2e_writes` when the run is read-only.

    One place rather than a conditional in each case, so a product that marks a new mutating
    test gets the production skip for free and cannot accidentally ship one that runs there.
    The environment is read directly rather than through the `e2e_env` fixture because
    collection happens before any fixture runs.
    """
    if not _read_only_from_environ():
        return
    skip = pytest.mark.skip(reason=READ_ONLY_REASON)
    for item in items:
        if item.get_closest_marker(WRITES_MARKER) is not None:
            item.add_marker(skip)


def _read_only_from_environ() -> bool:
    """Whether `E2E_READ_ONLY` is set, readable at collection with no fixture."""
    return _truthy(os.environ.get("E2E_READ_ONLY", ""))


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
def gate_headers(e2e_env: E2EEnvironment, boto3_session: Any) -> Mapping[str, str]:
    """The `x-origin-verify` header staging requires, read from SSM and never printed.

    Production has no gate and yields an empty mapping. A staging run whose parameter is
    unset fails here rather than answering 401 to every probe, which is the failure mode
    the prior art warns about loudest: the gate's 401 reads exactly like a broken route.
    """
    if not e2e_env.gate_ssm_parameter:
        if not e2e_env.is_production:
            pytest.fail(
                "E2E_GATE_SSM_PARAMETER is empty in a non-production environment. Staging "
                "sits behind the access gate, so every request below would be answered by "
                "the gate with a 401 rather than by the API, and the whole suite would read "
                "as broken routing that is really a missing credential."
            )
        return {}
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
        per_minute=DEFAULT_PER_MINUTE,
    )
    try:
        yield client
    finally:
        client.close()


@pytest.fixture(scope="session")
def user_session(e2e_env: E2EEnvironment, anon: E2EClient) -> IdentitySession:
    """The durable e2e user, signed in through the real login route.

    Skips in read-only mode rather than attempting a login with no credential. The marker
    already skips every case the plugin ships that would reach here, so this is the backstop
    that catches a product case which forgot the marker: it can only skip, never sign in.
    """
    if not e2e_env.signs_in:
        pytest.skip(READ_ONLY_REASON)
    return login(anon, e2e_env.user_email, e2e_env.user_password)


@pytest.fixture(scope="session")
def api(user_session: IdentitySession) -> E2EClient:
    """The authenticated client, sharing the anonymous client's pacer and gate header."""
    return user_session.client


@pytest.fixture(scope="session")
def minted_token(e2e_env: E2EEnvironment, boto3_session: Any) -> Callable[..., str]:
    """Mint an access token through KMS without a login, staging only.

    Skips rather than fails when `E2E_MINT_ENABLED` is unset, which is every environment
    but staging. `mint_test_token` refuses production independently of that flag, so the
    skip and the package's refusal are two separate checks on the same thing.
    """
    if not e2e_env.mint_enabled:
        pytest.skip("E2E_MINT_ENABLED is not set, so no token is minted in this environment")
    kms = boto3_session.client("kms")

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
            subject=subject or f"{e2e_env.resource_prefix}mint",
            expires_in=expires_in,
            extra_claims=claims,
            now=now,
        )

    return _mint


@pytest.fixture(scope="session")
def gateway_routes(request: pytest.FixtureRequest, e2e_env: E2EEnvironment, boto3_session: Any) -> tuple[Route, ...]:
    """Every live route on the API, with its integration target and authorizer id.

    Reuses the list the suite's collection already read where there is one, so a run makes
    one `get-routes` call rather than two against the same stage.
    """
    cached = request.config.pluginmanager.get_plugin("webbpulse-e2e-collection")
    routes = getattr(cached, "routes", None)
    if routes is None:
        routes = fetch_routes(boto3_session.client("apigatewayv2"), e2e_env.api_id)
    if not routes:
        pytest.fail(
            f"apigatewayv2 get-routes returned no routes for api {e2e_env.api_id}. Every "
            "assertion below is derived from that list, so an empty one would pass "
            "vacuously rather than say the api id is wrong."
        )
    return routes


@pytest.fixture(scope="session")
def gateway_authorizers(e2e_env: E2EEnvironment, boto3_session: Any) -> tuple[Authorizer, ...]:
    """Every authorizer declared on the API, which is how the gate is told apart from identity."""
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
def access_log(e2e_env: E2EEnvironment, boto3_session: Any) -> AccessLogLookup:
    """A lookup that finds an access log entry by request id, with a bounded wait."""
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
