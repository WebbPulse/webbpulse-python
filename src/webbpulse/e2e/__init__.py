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
from .gateway import Operation, Route, fetch_routes, operations_from_openapi
from .identity import IdentitySession, login, mint

__all__ = [
    "E2EEnvironment",
    "MissingEnvironment",
    "pytest_addhooks",
]

_REQUIRED = (
    "E2E_ENVIRONMENT",
    "E2E_API_BASE_URL",
    "E2E_WEB_BASE_URL",
    "E2E_AWS_REGION",
    "E2E_API_ID",
    "E2E_ACCESS_LOG_GROUP",
    "E2E_USER_EMAIL",
    "E2E_USER_PASSWORD",
    "E2E_RUN_ID",
)

_MINT_REQUIRED = ("E2E_KMS_KEY_ID", "E2E_ISSUER", "E2E_AUDIENCE")

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


@dataclass(frozen=True)
class E2EEnvironment:
    """Everything the suite needs about the environment under test, from `E2E_*`.

    `gate_ssm_parameter` is empty in production, which has no gate. `legacy_route_names` is
    the list of strings that must not appear in the deployed bundle.
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
    mint_enabled: bool = False
    kms_key_id: str = ""
    issuer: str = ""
    audience: str = ""
    legacy_route_names: tuple[str, ...] = ()

    @property
    def is_production(self) -> bool:
        """Whether this is the production stage, which has no gate and refuses minting."""
        return self.environment.lower() == "production"

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
        missing = [name for name in _REQUIRED if not source.get(name, "").strip()]
        mint_enabled = _truthy(source.get("E2E_MINT_ENABLED", ""))
        if mint_enabled:
            missing.extend(name for name in _MINT_REQUIRED if not source.get(name, "").strip())
        if missing:
            raise MissingEnvironment(
                "The webbpulse.e2e plugin needs these environment variables and they are "
                f"unset or empty: {', '.join(sorted(set(missing)))}. The reusable e2e.yml "
                "workflow sets them from its inputs; locally, see docs/e2e.md."
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
            user_email=source["E2E_USER_EMAIL"].strip(),
            user_password=source["E2E_USER_PASSWORD"],
            run_id=source["E2E_RUN_ID"].strip(),
            gate_ssm_parameter=source.get("E2E_GATE_SSM_PARAMETER", "").strip(),
            mint_enabled=mint_enabled,
            kms_key_id=source.get("E2E_KMS_KEY_ID", "").strip(),
            issuer=source.get("E2E_ISSUER", "").strip().rstrip("/"),
            audience=source.get("E2E_AUDIENCE", "").strip(),
            legacy_route_names=legacy,
        )


def pytest_addhooks(pluginmanager: Any) -> None:
    """Register this plugin's own hook specifications."""
    from . import hookspecs

    pluginmanager.add_hookspecs(hookspecs)


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
    """The durable e2e user, signed in through the real login route."""
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
def http(e2e_env: E2EEnvironment) -> Iterator[Any]:
    """A plain httpx client for the web origin, which carries no API gate header."""
    import httpx

    client = httpx.Client(timeout=30.0, follow_redirects=True)
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
    """
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
