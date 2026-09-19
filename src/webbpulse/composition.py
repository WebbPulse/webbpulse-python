"""The composition layer above `create_app`: a domain registry, one builder, one entrypoint.

A product that deploys one function per domain writes the same layer three times over: a
frozen `Domain` descriptor whose routers load lazily, a `build_domain_app` that turns one
descriptor or many into a `FastAPI`, process-wide logging and tracing, a startup check on
the secrets the served domains name, and a per-domain `entrypoint.py` that is forty lines
of the same four calls. This module is that layer, with the product-specific parts left as
seams.

`Domain` is the descriptor and `DomainRegistry` the ordered map of them, which stays in the
product because its rows name the product's own routers. `build_domain_app` composes the
application: it calls `create_app`, includes each domain's routers under its prefix, and
runs the `configure` hooks a product passes for the middleware and state only it knows
about. `domain_entrypoint` returns the `(build_app, main)` pair a per-domain entrypoint
module binds, so `app/domains/<name>/entrypoint.py` becomes three lines and the Dockerfile
CMD `python -m app.domains.${DOMAIN}.entrypoint` is unchanged.

`configure_tracing` wraps `webbpulse.otel.configure_tracing` behind the
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` gate, without which the exporter defaults to the X-Ray
endpoint and every process retries a 403 in silence. `check_secrets` is the startup check,
and `local_authorizer` stands the gateway's JWT authorizer up in process on a local stack
alone.

`RepositoryScope` with `scope_for` records which repositories an application may reach and
which of them it may only read, which is the shape a product narrows a bundle with.
"""

from __future__ import annotations

import logging
import os
import warnings
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final, Protocol

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import APIRouter, FastAPI

__all__ = [
    "OTLP_ENDPOINT_ENV",
    "AppConfigurer",
    "Domain",
    "DomainRegistry",
    "RepositoryScope",
    "RouterSpec",
    "SecretsChecker",
    "SettingsLike",
    "build_domain_app",
    "check_secrets",
    "configure_logging",
    "configure_tracing",
    "domain_entrypoint",
    "local_authorizer",
    "resolve_domains",
    "scope_for",
]

_log = logging.getLogger(__name__)

OTLP_ENDPOINT_ENV: Final = "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"
"""The variable whose presence decides whether this process exports traces at all."""

type RouterSpec = "APIRouter | tuple[APIRouter, str, tuple[str, ...]]"
"""What a loader may return: a bare router, or one with its own prefix suffix and tags.

A bare router mounts under the domain's `router_prefix` with the domain's `router_tags`. A
triple mounts under `router_prefix` plus its own suffix, with its own tags when it names
any, which is how one domain serves several path families.
"""


class SettingsLike(Protocol):
    """The settings attributes this module reads.

    Structural rather than `BaseServiceSettings`, because the three adopting products each
    carry a settings class with its own extra fields and its own upper case mirrors, and
    only these two are read here.
    """

    @property
    def environment(self) -> str:
        """The deployment environment, lower case."""

    @property
    def log_level(self) -> str:
        """The root logger level."""


@dataclass(frozen=True)
class Domain:
    """One deployable domain: what it serves, what it reaches, what it needs to start.

    Every field but `name` has a default, so a registry row is as short as the domain is
    simple. `load_routers` and `load_unprefixed_routers` are callables rather than router
    objects because importing the registry must import no domain package: that lazy import
    is what keeps one domain's image free of the other domains' code, and it is what the
    `entrypoint_isolation` fixture in `webbpulse.testing` holds.
    """

    name: str
    title: str = ""
    load_routers: Callable[[], Sequence[RouterSpec]] = tuple
    """Returns this domain's routers, each a bare `APIRouter` or a `(router, prefix, tags)`
    triple. Called at build time, never at import."""
    load_unprefixed_routers: Callable[[Any], Sequence[APIRouter]] | None = None
    """Returns routers that mount at the root with no prefix and no tags, because the
    router itself declares its full paths. Called lazily with the resolved settings, for
    the same reason `load_routers` is."""
    router_prefix: str = ""
    router_tags: tuple[str, ...] = ()
    service_name_template: str = "{domain}"
    """How `service_name` is rendered. A product sets one template on every row, which is
    the string its Terraform also sets as `SERVICE_NAME`."""
    requires_secrets: tuple[str, ...] = ()
    """Settings names `check_secrets` turns into a hard startup requirement.

    A domain naming none never calls `require_secrets`, which is what lets it run with no
    Secrets Manager grant at all."""
    repositories: tuple[str, ...] = ()
    """Repositories this domain owns and writes."""
    read_repositories: tuple[str, ...] = ()
    """Repositories this domain only reads, belonging to another domain.

    Held apart from `repositories` because the two become different IAM grants: a domain
    reaching a table it does not own must never gain write on it just by needing a lookup.
    """
    extra: dict[str, Any] = field(default_factory=dict)
    """Extra keyword arguments passed through to `create_app` for this domain."""

    @property
    def service_name(self) -> str:
        """The service name this domain logs and traces under."""
        return self.service_name_template.format(domain=self.name)

    @property
    def app_title(self) -> str:
        """`title` when the row names one, and the domain's own name otherwise."""
        return self.title or self.name

    @property
    def all_repositories(self) -> tuple[str, ...]:
        """Every repository this domain reaches, written and read alike, in order."""
        names = list(self.repositories)
        for name in self.read_repositories:
            if name not in names:
                names.append(name)
        return tuple(names)


class DomainRegistry(Mapping[str, Domain]):
    """An ordered, immutable map of domain name to descriptor.

    A product builds one of these in its own `domains.py` and everything else reads it: both
    composition roots, the entrypoint modules, the isolation test and whatever generates the
    Terraform function map. `entrypoint_module` is the mapping a Dockerfile's `DOMAIN` build
    argument goes through, because a domain named with hyphens is a package named with
    underscores.
    """

    def __init__(self, domains: Iterable[Domain] | Mapping[str, Domain]) -> None:
        """Build a registry from descriptors, or from an existing name-to-domain map.

        Raises `ValueError` on a duplicate name, since a second row would silently shadow
        the first and one domain would deploy the other's routes.
        """
        rows = domains.values() if isinstance(domains, Mapping) else domains
        resolved: dict[str, Domain] = {}
        for domain in rows:
            if domain.name in resolved:
                raise ValueError(f"Duplicate domain name {domain.name!r} in the registry.")
            resolved[domain.name] = domain
        self._domains = resolved

    def __getitem__(self, name: str) -> Domain:
        """The descriptor registered under `name`."""
        return self._domains[name]

    def __iter__(self) -> Iterator[str]:
        """The domain names, in registration order."""
        return iter(self._domains)

    def __len__(self) -> int:
        """How many domains are registered."""
        return len(self._domains)

    def __repr__(self) -> str:
        """The registry's names, for a failing assertion to render usefully."""
        return f"DomainRegistry({', '.join(self._domains)})"

    @property
    def names(self) -> tuple[str, ...]:
        """The domain names, in registration order."""
        return tuple(self._domains)

    def entrypoint_module(self, name: str) -> str:
        """The package name under `app/domains/` that serves the domain called `name`.

        Hyphens become underscores, because `build-lists` is a legal domain name and an
        illegal Python identifier, and the Dockerfile does the same translation on its
        `DOMAIN` build argument.
        """
        return self._domains[name].name.replace("-", "_")

    @property
    def entrypoint_modules(self) -> dict[str, str]:
        """Every domain name mapped to its entrypoint package name."""
        return {name: self.entrypoint_module(name) for name in self._domains}


def resolve_domains(
    domains: Domain | str | Sequence[Domain | str],
    registry: Mapping[str, Domain] | None = None,
) -> list[Domain]:
    """One domain or many, given by descriptor or by name, as a list of descriptors.

    A name needs a `registry` to resolve against; passing one without a registry raises
    `LookupError` rather than failing later with an unhelpful `TypeError`.
    """
    items: Sequence[Domain | str] = [domains] if isinstance(domains, Domain | str) else domains
    resolved: list[Domain] = []
    for item in items:
        if isinstance(item, Domain):
            resolved.append(item)
            continue
        if registry is None:
            raise LookupError(f"Cannot resolve the domain name {item!r} without a registry.")
        resolved.append(registry[item])
    return resolved


def configure_logging(
    settings: SettingsLike,
    *,
    service: str | None = None,
    **logging_kwargs: Any,
) -> None:
    """Install the JSON log format for this process, from the settings' level and environment.

    A thin call into `webbpulse.logging.configure_logging` that saves each product writing
    the same three-argument wrapper. Calling it twice is harmless.
    """
    from webbpulse.logging import configure_logging as _configure_logging

    _configure_logging(
        level=settings.log_level,
        service=service,
        environment=settings.environment,
        **logging_kwargs,
    )


def configure_tracing(
    domain: Domain | str,
    settings: SettingsLike,
    *,
    registry: Mapping[str, Domain] | None = None,
    **tracing_kwargs: Any,
) -> bool:
    """Wire OpenTelemetry for one domain, but only when an OTLP endpoint is set.

    The gate is deliberate and is the whole reason this wrapper exists: with
    `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` unset the exporter falls back to this region's
    X-Ray endpoint, and a function with no X-Ray grant then retries a 403 on every export
    for the life of the process, in silence. Returns whether tracing was configured.

    Call it before the application is built, because the server span middleware can only be
    injected into a middleware stack that has not been built yet.
    """
    if not os.environ.get(OTLP_ENDPOINT_ENV, "").strip():
        _log.debug("Tracing not configured: %s is unset.", OTLP_ENDPOINT_ENV)
        return False

    from webbpulse.otel import configure_tracing as _configure_tracing
    from webbpulse.otel import resolve_sample_ratio

    resolved = resolve_domains(domain, registry)[0]
    tracing_kwargs.setdefault("sample_ratio", resolve_sample_ratio())
    return _configure_tracing(
        resolved.service_name,
        environment=settings.environment,
        **tracing_kwargs,
    )


class SecretsChecker(Protocol):
    """What `check_secrets` calls when it decides a secret is genuinely required."""

    def __call__(self, *names: str) -> Any:
        """Resolve every named secret, raising when one is missing."""


def check_secrets(
    domains: Iterable[Domain],
    settings: Any,
    *,
    require: SecretsChecker | None = None,
    strict: bool | None = None,
    warn_on: Iterable[str] = ("SECRET_KEY",),
) -> tuple[str, ...]:
    """Fail fast at startup on a secret the served domains name but the settings lack.

    The union of every served domain's `requires_secrets` is what is checked, so an
    application serving no domain that names a secret never calls `require` at all, which is
    what lets such a function deploy with no Secrets Manager grant.

    `strict` decides between failing and warning, and defaults to whether the settings
    report a production environment: outside production a missing name in `warn_on` raises a
    `UserWarning` rather than refusing to start, so a workstation can run the stack without
    one. Returns the names that were checked.
    """
    wanted = tuple(sorted({name for domain in domains for name in domain.requires_secrets}))
    if not wanted:
        return ()

    resolved_strict = strict if strict is not None else _is_production(settings)
    if resolved_strict:
        checker = require if require is not None else getattr(settings, "require_secrets", None)
        if checker is None:
            raise LookupError(
                "check_secrets was asked to require "
                f"{', '.join(wanted)} but neither `require` nor `settings.require_secrets` is available."
            )
        checker(*wanted)
        return wanted

    warn_for = set(warn_on)
    for name in wanted:
        if name in warn_for and not getattr(settings, name, None):
            warnings.warn(
                f"{name} is empty. Tokens this service signs itself will be insecure. "
                f"Set the {name} environment variable.",
                UserWarning,
                stacklevel=2,
            )
    return wanted


def _is_production(settings: Any) -> bool:
    """Whether these settings describe a production deployment.

    Reads `is_production` when the settings publish one, since two of the three adopting
    products do, and falls back to the environment string otherwise.
    """
    flag = getattr(settings, "is_production", None)
    if isinstance(flag, bool):
        return flag
    return str(getattr(settings, "environment", "")).strip().lower() == "production"


def local_authorizer(
    app: FastAPI,
    settings: Any,
    *,
    build_identity_settings: Callable[[Any], Any],
    issuer_attribute: str = "IDENTITY_ISSUER",
) -> bool:
    """Stand in for the gateway's JWT authorizer, but only on a local stack.

    Deployed, API Gateway verifies the access token and the Lambda Web Adapter hands the
    function its claims in `x-amzn-request-context`, which is what every authorized route
    reads. A local stack has no gateway, so a valid token arrives carrying no claims and
    each of those routes answers 401. `LocalAuthorizerMiddleware` verifies the bearer token
    in process against the local signer's key set and publishes the result in that shape.

    Returns whether the middleware was added. The application's own environment is checked
    first, and the issuer second, before `build_identity_settings` is called at all: the
    identity settings validate their signing keys on construction, so building them in a
    deployed function that carries none would fail the cold start. The identity settings'
    own environment is then checked as well, because that is the one the middleware refuses
    on and the two are separate variables.

    `build_identity_settings` is a callable rather than an import so that this module never
    reaches a product's identity glue, which would put that glue into every other domain's
    image and break the isolation the split is for.
    """
    from webbpulse.identity import LOCAL_ENVIRONMENT, LocalAuthorizerMiddleware

    if str(getattr(settings, "environment", "")).strip().lower() != LOCAL_ENVIRONMENT:
        return False
    if not getattr(settings, issuer_attribute, ""):
        return False

    identity_settings = build_identity_settings(settings)
    if str(getattr(identity_settings, "environment", "")).strip().lower() != LOCAL_ENVIRONMENT:
        return False

    app.add_middleware(LocalAuthorizerMiddleware, settings=identity_settings)
    return True


@dataclass(frozen=True)
class RepositoryScope:
    """The repositories an application may reach, and which of them it may only read.

    Recorded on `app.state.repository_scope` by `build_domain_app`, so a product's own
    binding can narrow any bundle, a test fixture included, to what the deployed function's
    IAM policy actually allows.
    """

    name: str
    """A label for the scope: the served domain names joined by `+`, or `"none"`."""
    names: tuple[str, ...]
    """Every repository the application may reach, in registration order."""
    read_only: tuple[str, ...]
    """Those of `names` no served domain writes, which refuse writes."""


def scope_for(domains: Sequence[Domain]) -> RepositoryScope:
    """The union of these domains' repository declarations.

    A repository one served domain writes is writable for the whole application, which is
    exactly how a merged local process and a multi-domain function are granted: the scope
    must not be narrower than the IAM policy, or a legitimate write fails in process.
    """
    names: list[str] = []
    writable: set[str] = set()
    for domain in domains:
        writable.update(domain.repositories)
        for repository in domain.all_repositories:
            if repository not in names:
                names.append(repository)
    label = "+".join(domain.name for domain in domains) or "none"
    return RepositoryScope(
        name=label,
        names=tuple(names),
        read_only=tuple(name for name in names if name not in writable),
    )


class AppConfigurer(Protocol):
    """A hook `build_domain_app` runs against the application it built."""

    def __call__(self, app: FastAPI, domains: Sequence[Domain]) -> None:
        """Add whatever this product wires onto every application it composes."""


def build_domain_app(
    domains: Domain | str | Sequence[Domain | str],
    *,
    registry: Mapping[str, Domain] | None = None,
    settings: Any = None,
    title: str | None = None,
    service_name: str | None = None,
    configure: Iterable[AppConfigurer] = (),
    after_routers: Iterable[AppConfigurer] = (),
    instrument: bool = False,
    **create_app_kwargs: Any,
) -> FastAPI:
    """Build one application from one domain or many. The one builder both roots go through.

    Both composition roots calling this is what stops them drifting: a route mounted at the
    wrong prefix in a deployed function would have to be mounted wrongly locally too.
    Composition is `include_router` and never `mount`, which would empty the OpenAPI
    document the route-cut tests read.

    `configure` runs after `create_app` and before any router is included, which is where a
    product adds the middleware it wants inside the CORS and request id middleware
    `create_app` installed, since Starlette runs middleware outermost-first in the order
    added. `after_routers` runs once every router is in, for anything that must see the
    finished route table. `settings` is passed through to `create_app` and handed to each
    `load_unprefixed_routers`, and `app.state.repository_scope` is set from the served
    domains.

    `instrument` is `False` because `configure_tracing` runs in `main` before the app is
    built, and this function instruments the finished application itself, after the product's
    own middleware is on rather than underneath it.
    """
    from webbpulse.http import create_app

    resolved = resolve_domains(domains, registry)
    if not resolved:
        raise ValueError("build_domain_app needs at least one domain.")

    single = resolved[0] if len(resolved) == 1 else None
    create_app_kwargs.setdefault("title", title if title is not None else (single.app_title if single else "WebbPulse"))
    if service_name is not None:
        create_app_kwargs["service_name"] = service_name
    elif single is not None:
        create_app_kwargs.setdefault("service_name", single.service_name)
    if settings is not None:
        create_app_kwargs.setdefault("settings", settings)

    app = create_app(
        instrument=False,
        **{key: value for domain in resolved for key, value in domain.extra.items()},
        **create_app_kwargs,
    )

    app.state.repository_scope = scope_for(resolved)

    for hook in configure:
        hook(app, resolved)

    for domain in resolved:
        for spec in domain.load_routers():
            router, prefix, tags = _unpack_router(spec, domain)
            app.include_router(router, prefix=prefix, tags=list(tags))

    for domain in resolved:
        if domain.load_unprefixed_routers is None:
            continue
        for router in domain.load_unprefixed_routers(settings):
            app.include_router(router)

    for hook in after_routers:
        hook(app, resolved)

    if instrument:
        from webbpulse.otel import instrument_fastapi

        instrument_fastapi(app)

    return app


def _unpack_router(spec: RouterSpec, domain: Domain) -> tuple[APIRouter, str, tuple[str, ...]]:
    """One loader result as `(router, prefix, tags)`, whichever shape it arrived in.

    A bare router takes the domain's own prefix and tags; a triple appends its own prefix
    suffix and uses its own tags when it names any.
    """
    if isinstance(spec, tuple):
        router, suffix, tags = spec
        return router, f"{domain.router_prefix}{suffix}", tuple(tags) or domain.router_tags
    return spec, domain.router_prefix, domain.router_tags


def domain_entrypoint(
    domain: Domain | str,
    *,
    registry: Mapping[str, Domain] | None = None,
    build: Callable[[Domain], FastAPI],
    settings: Callable[[], Any] | Any = None,
    check: Callable[[Domain, Any], Any] | None = None,
    serve: Callable[[FastAPI], None] | None = None,
) -> tuple[Callable[[], FastAPI], Callable[[], None]]:
    """The `(build_app, main)` pair one domain's `entrypoint.py` binds, so it is three lines.

    `build_app` builds this domain's application and nothing else. `main` is what the
    process runs: it configures logging and then tracing, runs the startup check, builds the
    application and serves it with uvicorn until killed. Logging comes first so a
    misconfigured function fails at cold start with the failure already in JSON, and tracing
    precedes the build because the server span middleware can only be injected into an
    unbuilt middleware stack.

    `settings` is a zero-argument factory, resolved inside `main` rather than at import so
    that importing an entrypoint module reads no environment. `check` defaults to
    `check_secrets` over this one domain. `serve` defaults to
    `webbpulse.lambda_entry.run_uvicorn`, and a test passes its own to assert what `main`
    would have served without binding a port.
    """
    resolved = resolve_domains(domain, registry)[0]

    def build_app() -> FastAPI:
        """This domain's routers and the root routes, and nothing else."""
        return build(resolved)

    def main() -> None:
        """Configure logging and tracing process-wide, then serve the application."""
        current = settings() if callable(settings) else settings
        if current is not None:
            configure_logging(current, service=resolved.service_name)
            configure_tracing(resolved, current)
        if check is not None:
            check(resolved, current)
        elif current is not None:
            check_secrets([resolved], current)
        runner = serve if serve is not None else _run_uvicorn
        runner(build_app())

    return build_app, main


def _run_uvicorn(app: FastAPI) -> None:
    """Serve `app` with uvicorn on the port the Lambda Web Adapter expects."""
    from webbpulse.lambda_entry import run_uvicorn

    run_uvicorn(app)
