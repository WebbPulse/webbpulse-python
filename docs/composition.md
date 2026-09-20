# Composition

`webbpulse.composition` is the layer above [`create_app`](http.md): the domain registry a
product declares, the one builder both its composition roots go through, and the
`(build_app, main)` pair a per-domain `entrypoint.py` binds.

It exists because a product deploying one Lambda per domain writes the same layer every
time: a frozen descriptor whose routers load lazily, a builder that turns one descriptor or
many into a `FastAPI`, process-wide logging and tracing, a startup check on the secrets the
served domains name, and one forty-line entrypoint module per domain making the same four
calls. Three products had near-identical copies of it. The parts that genuinely differ,
the registry rows and the product's own middleware and repository binding, stay in the
product as seams.

## The two roots

A product built this way has two composition roots and they must not drift.

**Root A** is every domain on one application, which is what local development and the
test suite run against. **Root B** is one domain on one application, which is what each
deployed function runs. Both call `build_domain_app`, so a route mounted at the wrong
prefix in a function would have to be mounted wrongly locally too, and the route-cut tests
catch it before a deploy does.

Composition is `include_router` throughout and never `mount`, which would empty the
OpenAPI document those tests read.

## The descriptor

```python
from webbpulse.composition import Domain, DomainRegistry


def _posts_routers():
    from app.domains.posts.endpoints import posts

    return [(posts.router, "/posts", ("posts",))]


DOMAINS = DomainRegistry(
    [
        Domain(
            name="posts",
            title="Product posts",
            load_routers=_posts_routers,
            router_prefix="/api/v1",
            service_name_template="product-{domain}",
            repositories=("posts",),
        ),
    ]
)
```

`load_routers` is a callable, not a list of routers, and that is the load-bearing part:
importing the registry must import no domain package. The lazy import is what keeps one
domain's image free of the other domains' code, and
[`assert_entrypoint_isolation`](#the-isolation-check) is what holds it.

A loader returns either a bare `APIRouter`, which mounts under the domain's own
`router_prefix` with its `router_tags`, or a `(router, prefix, tags)` triple, which appends
its own suffix and uses its own tags when it names any. `load_unprefixed_routers` is
called with the resolved settings and returns routers that mount at the root with no
prefix, because the router itself declares its full paths: an identity router carrying
`/api/auth` would otherwise serve `/api/auth/api/auth/...`.

`repositories` and `read_repositories` are held apart because they become different IAM
grants. A domain reaching a table it does not own must never gain write on it just by
needing a lookup.

`extra` is `create_app` keyword arguments and nothing else. Every key is forwarded verbatim,
and anything `create_app` does not name reaches `FastAPI`, which accepts unknown keywords
without complaint: a product fact put here is swallowed in silence rather than refused.
Product metadata goes in `metadata`, a mapping `build_domain_app` ignores entirely, such as
a `seeds` flag deciding which root wires a lifespan hook, an owning team, or a Terraform
memory size.

```python
Domain(
    name="vehicles",
    load_routers=_vehicles_routers,
    extra={"error_envelope": "detailed"},
    metadata={"seeds": True},
)
```

`DomainRegistry` is an ordered, immutable `Mapping`. `entrypoint_module` translates a
domain name to its package name, since `build-lists` is a legal domain name and an illegal
Python identifier, and a Dockerfile's `DOMAIN` build argument does the same translation.

## The builder

```python
from webbpulse.composition import build_domain_app


def add_rate_limiting(app, domains):
    from app.common.api.middleware import rate_limit_middleware

    app.middleware("http")(rate_limit_middleware)


def build(domains, **kwargs):
    return build_domain_app(
        domains,
        registry=DOMAINS,
        settings=get_settings(),
        configure=[add_rate_limiting, bind_repositories],
        after_routers=[add_root_routes],
        error_envelope="detailed",
        **kwargs,
    )
```

`configure` runs after `create_app` and before any domain router is included, which is
where a product adds the middleware it wants *inside* the CORS and request id middleware
`create_app` installed: Starlette runs middleware outermost-first in the order added, so
adding later means running further in. `after_routers` runs once every router is in, for
anything that must see the finished route table.

`build_domain_app` sets `app.state.repository_scope` from the served domains, so a
product's own binding reads the scope rather than recomputing it. It does not instrument
the app itself by default, because `configure_tracing` runs in `main` before the app is
built and a product normally calls `instrument_fastapi` last, after its own middleware is
on rather than underneath it. Pass `instrument=True` to have the builder do it.

## The entrypoint

`domain_entrypoint` returns the `(build_app, main)` pair, so a per-domain entrypoint module
is three lines and the Dockerfile CMD `python -m app.domains.${DOMAIN}.entrypoint` does not
change:

```python
# app/domains/posts/entrypoint.py
"""The posts domain's entrypoint, run as `python -m app.domains.posts.entrypoint`."""

from app.common.composition.wiring import DOMAINS, build

DOMAIN = DOMAINS["posts"]
build_app, main = domain_entrypoint(DOMAIN, build=build, settings=get_settings)

if __name__ == "__main__":
    main()
```

`main` configures logging, then tracing, then runs the startup secrets check, then builds
the application and serves it with uvicorn until killed. That order is load-bearing:
logging first so a misconfigured function fails at cold start with the failure already in
JSON, and tracing before the build because the server span middleware can only be injected
into a middleware stack that has not been built yet.

`settings` is a zero-argument factory rather than a settings object, resolved inside `main`,
so importing an entrypoint module reads no environment. `serve` defaults to
`webbpulse.lambda_entry.run_uvicorn`; a test passes its own to assert what `main` would
have served without binding a port.

`configure_logging` is the logging seam. It takes this domain's service name and defaults to
the package's own `configure_logging` bound to the resolved settings, which is the JSON
format. A product whose log format is not that one, a colorized TTY branch for instance,
passes its own and keeps `settings`, so `main` still runs logging, then tracing, then the
check, then the build:

```python
from app.common.core.logging import configure_app_logging

build_app, main = domain_entrypoint(
    DOMAIN,
    build=build_domain_app,
    settings=lambda: settings,
    configure_logging=lambda service: configure_app_logging(service=service),
)
```

The fallback, for a product that must own the whole startup sequence, is `settings=None`
with a `check` doing all of it: with no settings resolved `main` configures neither logging
nor tracing, so the `check` hook has to run logging, tracing and the secrets check itself,
in that order, before the build. Passing `configure_logging` is the shorter road to the same
place and keeps the order the package's.

## Tracing, behind the gate

```python
from webbpulse.composition import configure_tracing

configure_tracing(DOMAIN, settings)
```

This wraps `webbpulse.otel.configure_tracing` behind `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`
and returns whether tracing was configured. The gate is the whole reason the wrapper
exists: with that variable unset the exporter falls back to this region's X-Ray endpoint,
and a function with no X-Ray grant then retries a 403 on every export for the life of the
process, in silence.

## The startup secrets check

```python
from webbpulse.composition import check_secrets

check_secrets([DOMAIN], settings)
```

The union of every served domain's `requires_secrets` is what is checked, so an application
serving no domain that names a secret never calls the checker at all, which is what lets
such a function deploy with no Secrets Manager grant.

`strict` defaults to whether the settings report production, by `settings.is_production`
when they publish it and by the environment string otherwise. Outside production a missing
name in `warn_on`, which defaults to `("SECRET_KEY",)`, raises a `UserWarning` rather than
refusing to start, so a workstation can run the stack without one. In production it calls
`require`, or `settings.require_secrets` when no `require` is passed.

`requires_secrets` is not the same question as the Terraform grant. It names the settings
fields that must be *present*, and a domain reading an optional key out of the app secret
directly still needs the grant while declaring nothing here.

## The local authorizer

```python
from webbpulse.composition import local_authorizer

local_authorizer(app, settings, build_identity_settings=build_identity_settings)
```

Deployed, API Gateway verifies the access token and the Lambda Web Adapter hands the
function its claims in `x-amzn-request-context`, which every authorized route reads. A
local stack has no gateway, so a valid token arrives carrying no claims and each of those
routes answers 401. `LocalAuthorizerMiddleware` verifies the bearer token in process
against the local signer's key set and publishes the result in that same shape.

The guards run in order and the order matters. The application's own environment is checked
first, then the issuer, and only then is `build_identity_settings` called: the identity
settings validate their signing keys on construction, so building them in a deployed
function that carries none would fail the cold start. The identity settings' own
environment is checked last, because that is the one the middleware refuses on and the two
are separate variables. `build_identity_settings` is a callable rather than an import so
that this module never reaches a product's identity glue, which would put that glue into
every other domain's image.

## Repository scope

```python
from webbpulse.composition import scope_for

scope = scope_for([DOMAIN])
```

`RepositoryScope` records which repositories an application may reach and which of them it
may only read, which is the shape a product narrows a bundle with. A repository one served
domain writes is writable for the whole application: the scope must never be narrower than
the IAM policy, or a legitimate write fails in process while the grant would have allowed
it.

## The isolation check

`webbpulse.testing.assert_entrypoint_isolation` builds every domain's entrypoint in its own
interpreter and asserts each one imports its own domain package and no other:

```python
# tests/entrypoints/test_entrypoint_isolation.py
from pathlib import Path

from webbpulse.testing import assert_entrypoint_isolation

from app.common.composition.domains import DOMAINS

BACKEND = Path(__file__).resolve().parents[2]


def test_each_entrypoint_imports_only_its_own_domain() -> None:
    """The claim that makes N images smaller than N copies of one image."""
    assert_entrypoint_isolation(DOMAINS, cwd=BACKEND)
```

A subprocess, because the suite calling this has already imported every domain and an
in-process check would read the suite's imports rather than the image's. The child runs
with a stripped environment, so an entrypoint that needed credentials to build fails here
rather than in a cold start; pass `env` to add back anything a build legitimately needs.

It returns an `EntrypointImports` per domain, carrying `imported` and `foreign`, so a
caller can assert something further, and it raises an `AssertionError` naming every domain
that reached into another.

`entrypoint_imports` is the single-domain form, for a product wanting one case per domain
rather than one over the registry. It takes the same `package_root` default of
`"app.domains."`.

`allowed_foreign` is the exception list, for a foreign module every domain legitimately
imports. A product whose shared middleware is built from one domain's glue, an authorizer
every domain mounts built from the identity domain's `package_glue` for instance, names that
module here and the check still refuses everything else:

```python
assert_entrypoint_isolation(
    DOMAINS,
    cwd=BACKEND,
    allowed_foreign=["app.domains.identity.package_glue"],
)
```

A collection applies to every domain; a mapping of domain name to collection applies per
domain, and a domain the mapping does not name allows none. A listed module covers its own
submodules, and the packages between it and `package_root` are allowed exactly, since Python
cannot import `app.domains.identity.package_glue` without importing `app.domains.identity`.
Naming one module of a domain therefore never opens the rest of that domain: the glue lands
in every image and that domain's endpoints must not follow it there. Keep the list to what
shared wiring genuinely needs, for the same reason.

## Migration for adopters

A product keeps its `domains.py` rows and its settings. `wiring.py` loses everything this
module now owns and keeps only what is product-specific, passed as hooks.

Before, in `app/common/composition/wiring.py`:

```python
@dataclass(frozen=True)
class Domain:
    name: str
    title: str
    load_routers: Callable[[], Sequence[tuple[APIRouter, str, tuple[str, ...]]]]
    ...


def configure_tracing(domain: Domain) -> bool:
    if not os.environ.get(OTLP_ENDPOINT_ENV, "").strip():
        return False
    ...


def check_signing_key(domains: Iterable[Domain]) -> None: ...
def add_local_authorizer(app: FastAPI) -> bool: ...
def scope_for(domains: Sequence[Domain]) -> RepositoryScope: ...


def build_domain_app(
    domains, *, title=None, include_root_routes=True
) -> FastAPI: ...  # ninety lines of create_app, middleware, binding and include_router
```

After:

```python
from webbpulse.composition import (
    Domain,
    build_domain_app as _build_domain_app,
    check_secrets,
    configure_tracing,
    local_authorizer,
    scope_for,
)

from app.common.core.config import settings

SERVICE_NAME_TEMPLATE = "carmodpicker-{domain}"


def _add_shared_middleware(app, domains):
    """Rate limiting, inside the CORS and request id middleware create_app installed."""
    from app.common.api.middleware import rate_limit_middleware

    app.middleware("http")(rate_limit_middleware)
    local_authorizer(app, settings, build_identity_settings=build_identity_settings)
    bind_repositories(app, bundle_for(domains))


def build_domain_app(domains, **kwargs):
    """Both roots go through here, so they cannot drift."""
    from app.common.composition.domains import DOMAINS

    return _build_domain_app(
        domains,
        registry=DOMAINS,
        settings=settings,
        configure=[_add_shared_middleware],
        after_routers=[_add_root_routes, _instrument],
        version=OPENAPI_VERSION,
        include_health=False,
        openapi_url=f"{settings.API_STR}/openapi.json",
        lifespan=_lifespan(domains),
        **kwargs,
    )
```

### Fields a migrating product must set explicitly

`Domain`'s defaults are the ones a new product wants, not the ones a product's own descriptor
had, and two of them will silently change behaviour if a migrating row leaves them out:

- **`router_prefix`** defaults to `""`. A product whose own descriptor defaulted it to its
  API prefix, `settings.API_STR` say, unprefixes every route of every domain by migrating
  without setting it. Nothing raises: the application builds, the routes serve, and they
  serve at the wrong paths. Set it on every row, or compute it once and stamp it on each.
- **`service_name_template`** defaults to `"{domain}"`. A product whose functions log and
  trace under `product-{domain}` loses that prefix by migrating without setting it, so the
  logs and traces of a deployed function land under a service name its Terraform never used.

Both are per-row rather than per-registry, so the shortest safe migration is one constant
each in the product and both named on every row:

```python
API_PREFIX = settings.API_STR
SERVICE_NAME_TEMPLATE = "carmodpicker-{domain}"

Domain(
    name="vehicles",
    router_prefix=API_PREFIX,
    service_name_template=SERVICE_NAME_TEMPLATE,
    load_routers=_vehicles_routers,
)
```

A route-cut test over the OpenAPI document catches the first of these and a service-name
assertion catches the second. Write both before migrating the rows, not after.

`check_signing_key([domain])` becomes `check_secrets([domain], settings)`.

An `entrypoint.py` goes from forty-odd lines to three. Before:

```python
from app.common.composition.domains import DOMAINS
from app.common.composition.wiring import (
    build_domain_app,
    check_signing_key,
    configure_logging,
    configure_tracing,
)

DOMAIN = DOMAINS["identity"]


def build_app() -> "FastAPI":
    """This domain's routers and the root routes, and nothing else."""
    return build_domain_app(DOMAIN, title=DOMAIN.title)


def main() -> None:
    """Configure logging and tracing process-wide, then serve the application."""
    from webbpulse.lambda_entry import run_uvicorn

    configure_logging(service=DOMAIN.service_name)
    configure_tracing(DOMAIN)
    check_signing_key([DOMAIN])
    run_uvicorn(build_app())


if __name__ == "__main__":
    main()
```

After:

```python
"""The identity domain's entrypoint, run as `python -m app.domains.identity.entrypoint`."""

from webbpulse.composition import domain_entrypoint

from app.common.composition.domains import DOMAINS
from app.common.composition.wiring import build_domain_app
from app.common.core.config import settings

DOMAIN = DOMAINS["identity"]
build_app, main = domain_entrypoint(DOMAIN, build=build_domain_app, settings=lambda: settings)

if __name__ == "__main__":
    main()
```

The Dockerfile CMD does not change, and the isolation test becomes the single call in
[the isolation check](#the-isolation-check) above.

### What each product keeps

CarModPicker keeps its `startup_tasks` seam by passing its own `lifespan`, and its five
root routes and sitemap handlers as an `after_routers` hook. Standupless keeps
`read_repositories` on the rows, which `scope_for` reads. The Terraform control plane keeps
its `TrailingSlashMiddleware` and `DomainHeaderMiddleware` as `configure` hooks, and its
per-domain header by passing a hook that closes over the resolved domains.

In all three, `Domain.tables` and `read_tables` stay in the product, because they resolve
names through the product's own `tables_for`, and so does `bundle_for`, which builds the
product's own bundle type. Both read `scope_for` for the names.
