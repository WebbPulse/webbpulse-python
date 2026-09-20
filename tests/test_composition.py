"""The composition layer: descriptors, the registry, the builder and the entrypoint pair.

The cases mirror what the three adopting products assert about their own copies today, so a
change here that would break one of them fails in this suite instead.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404
import sys
import textwrap
import warnings
from pathlib import Path
from typing import Any

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient

from webbpulse.composition import (
    OTLP_ENDPOINT_ENV,
    Domain,
    DomainRegistry,
    RepositoryScope,
    build_domain_app,
    check_secrets,
    configure_logging,
    configure_tracing,
    domain_entrypoint,
    local_authorizer,
    resolve_domains,
    scope_for,
)


class Settings:
    """The two attributes the composition layer reads off a product's settings."""

    def __init__(self, *, environment: str = "local", log_level: str = "INFO", **extra: Any) -> None:
        """Record the environment, the level and whatever else a case wants to set."""
        self.environment = environment
        self.log_level = log_level
        self.cors_allow_origins: list[str] = []
        self.cors_allow_credentials = True
        for name, value in extra.items():
            setattr(self, name, value)


def posts_router() -> list[APIRouter]:
    """One router serving `GET /posts`."""
    router = APIRouter()

    @router.get("/posts")
    def list_posts() -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
        """A route whose path is what the composition assertions read."""
        return {"ok": "posts"}

    return [router]


def comments_router() -> list[tuple[APIRouter, str, tuple[str, ...]]]:
    """One router given as a triple, so it takes its own suffix and tags."""
    router = APIRouter()

    @router.get("/comments")
    def list_comments() -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
        """A route mounted under the domain prefix plus the triple's own suffix."""
        return {"ok": "comments"}

    return [(router, "/threads", ("discussion",))]


def unprefixed_router(settings: Any) -> list[APIRouter]:
    """A router declaring its own full path, mounted with no prefix at all."""
    router = APIRouter()

    @router.get("/api/auth/whoami")
    def whoami() -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
        """A path a prefix would double, which is why it mounts unprefixed."""
        return {"environment": str(getattr(settings, "environment", ""))}

    return [router]


POSTS = Domain(
    name="posts",
    title="Posts",
    load_routers=posts_router,
    router_prefix="/api/v1",
    router_tags=("posts",),
    service_name_template="product-{domain}",
    repositories=("posts", "authors"),
)

DISCUSSION = Domain(
    name="discussion",
    title="Discussion",
    load_routers=comments_router,
    load_unprefixed_routers=unprefixed_router,
    router_prefix="/api/v1",
    service_name_template="product-{domain}",
    requires_secrets=("SECRET_KEY",),
    repositories=("comments",),
    read_repositories=("posts",),
)

REGISTRY = DomainRegistry([POSTS, DISCUSSION])


def paths_of(app: FastAPI) -> set[str]:
    """Every published path, read after startup rather than off `app.routes`."""
    with TestClient(app) as client:
        return set(client.get("/openapi.json").json()["paths"])


def test_a_domain_renders_its_service_name_from_the_template() -> None:
    """The service name is the template the product set, filled with the domain name."""
    assert POSTS.service_name == "product-posts"
    assert Domain(name="bare").service_name == "bare"


def test_a_domain_titles_itself_when_the_row_names_no_title() -> None:
    """A row with no title falls back to the domain's own name."""
    assert POSTS.app_title == "Posts"
    assert Domain(name="bare").app_title == "bare"


def test_all_repositories_is_written_then_read_with_no_duplicate() -> None:
    """The union keeps registration order and never lists one repository twice."""
    domain = Domain(name="d", repositories=("a", "b"), read_repositories=("b", "c"))
    assert domain.all_repositories == ("a", "b", "c")


def test_the_registry_keeps_registration_order() -> None:
    """Names come back in the order the rows were declared, not sorted."""
    assert REGISTRY.names == ("posts", "discussion")
    assert list(REGISTRY) == ["posts", "discussion"]
    assert len(REGISTRY) == 2
    assert REGISTRY["posts"] is POSTS


def test_the_registry_refuses_a_duplicate_name() -> None:
    """A second row under one name would silently shadow the first, so it raises."""
    with pytest.raises(ValueError, match="Duplicate domain name"):
        DomainRegistry([POSTS, Domain(name="posts")])


def test_the_registry_accepts_an_existing_map() -> None:
    """A product migrating from a plain dict passes it straight in."""
    registry = DomainRegistry({"posts": POSTS})
    assert registry.names == ("posts",)


def test_the_registry_translates_a_hyphenated_name_to_a_package() -> None:
    """`build-lists` is a legal domain name and an illegal Python identifier."""
    registry = DomainRegistry([Domain(name="build-lists"), Domain(name="media")])
    assert registry.entrypoint_module("build-lists") == "build_lists"
    assert registry.entrypoint_modules == {"build-lists": "build_lists", "media": "media"}


def test_the_registry_renders_its_names() -> None:
    """A failing assertion renders the registry usefully rather than as an address."""
    assert repr(REGISTRY) == "DomainRegistry(posts, discussion)"


def test_resolve_domains_takes_a_descriptor_a_name_or_a_sequence() -> None:
    """One domain or many, by descriptor or by name, all come back as descriptors."""
    assert resolve_domains(POSTS) == [POSTS]
    assert resolve_domains("posts", REGISTRY) == [POSTS]
    assert resolve_domains(["posts", DISCUSSION], REGISTRY) == [POSTS, DISCUSSION]


def test_resolve_domains_refuses_a_name_with_no_registry() -> None:
    """A name with nothing to resolve against fails here rather than later."""
    with pytest.raises(LookupError, match="without a registry"):
        resolve_domains("posts")


def test_a_domain_app_serves_its_own_routes_under_its_prefix() -> None:
    """A bare router takes the domain prefix and a triple appends its own suffix."""
    assert paths_of(build_domain_app(POSTS, settings=Settings())) >= {"/api/v1/posts"}
    assert paths_of(build_domain_app(DISCUSSION, settings=Settings())) >= {"/api/v1/threads/comments"}


def test_an_unprefixed_router_mounts_at_the_path_it_declares() -> None:
    """A router carrying its own full path is not prefixed, which would double it."""
    assert "/api/auth/whoami" in paths_of(build_domain_app(DISCUSSION, settings=Settings()))


def test_a_domain_app_serves_only_its_own_routes() -> None:
    """One function carries its domain's routes and not the other's."""
    posts = {path for path in paths_of(build_domain_app(POSTS, settings=Settings())) if path.startswith("/api/v1")}
    discussion = {
        path for path in paths_of(build_domain_app(DISCUSSION, settings=Settings())) if path.startswith("/api/v1")
    }
    assert posts
    assert not posts & discussion


def test_the_whole_surface_is_the_union_of_the_domains() -> None:
    """The every-domain root serves exactly what the domain functions serve together.

    The anti-drift assertion: a route reachable locally but on no function, or the
    reverse, is a deploy-time surprise and fails here instead.
    """
    whole = paths_of(build_domain_app(list(REGISTRY.values()), settings=Settings()))
    union: set[str] = set()
    for name in REGISTRY:
        union |= paths_of(build_domain_app(name, registry=REGISTRY, settings=Settings()))
    assert whole == union


def test_a_single_domain_app_takes_its_title_and_service_name() -> None:
    """One domain names the application, so its OpenAPI title is the domain's."""
    app = build_domain_app(POSTS, settings=Settings())
    assert app.title == "Posts"
    with TestClient(app) as client:
        assert client.get("/health").json()["service"] == "product-posts"


def test_a_title_argument_beats_the_descriptor() -> None:
    """An explicit title wins, which is how the every-domain root names itself."""
    app = build_domain_app([POSTS, DISCUSSION], title="Product API", service_name="product", settings=Settings())
    assert app.title == "Product API"


def test_build_domain_app_refuses_an_empty_sequence() -> None:
    """An application serving no domain is a wiring mistake, not a valid build."""
    with pytest.raises(ValueError, match="at least one domain"):
        build_domain_app([], settings=Settings())


def test_the_extra_mapping_reaches_create_app() -> None:
    """A row's `extra` is passed through, which is how a domain sets its own options."""
    domain = Domain(name="d", load_routers=posts_router, extra={"description": "from extra"})
    assert build_domain_app(domain, settings=Settings()).description == "from extra"


def test_explicit_keyword_arguments_win_over_a_row_extra() -> None:
    """A clash between a row's `extra` and a caller's keyword is not a `TypeError`."""
    domain = Domain(name="d", load_routers=posts_router, extra={"description": "from extra"})
    app = build_domain_app(domain, description="from caller")
    assert app.description == "from caller"


def test_the_metadata_mapping_is_never_read_by_the_builder() -> None:
    """`metadata` carries product facts `create_app` knows nothing about and would reject."""
    domain = Domain(name="d", load_routers=posts_router, metadata={"seeds": True, "team": "platform"})
    app = build_domain_app(domain, settings=Settings())
    assert domain.metadata == {"seeds": True, "team": "platform"}
    assert paths_of(app) == {"/posts"}
    assert not hasattr(app, "seeds")


def test_metadata_defaults_to_an_empty_mapping() -> None:
    """A row naming none carries an empty mapping rather than `None`."""
    assert Domain(name="bare").metadata == {}


def test_the_configure_hooks_run_before_the_routers() -> None:
    """`configure` sees an app with no domain routes and `after_routers` sees them all."""
    seen: list[tuple[str, int]] = []

    def before(app: FastAPI, domains: Any) -> None:
        """Record how many routes exist before any domain router is included."""
        seen.append(("before", len(app.routes)))

    def after(app: FastAPI, domains: Any) -> None:
        """Record how many routes exist once every router is in."""
        seen.append(("after", len(app.routes)))

    build_domain_app(POSTS, settings=Settings(), configure=[before], after_routers=[after])
    assert [name for name, _ in seen] == ["before", "after"]
    assert seen[0][1] < seen[1][1]


def test_a_configure_hook_is_given_the_resolved_domains() -> None:
    """The hook is told which domains it is configuring for, by descriptor."""
    captured: list[Any] = []

    def hook(app: FastAPI, domains: Any) -> None:
        """Record the descriptors the builder resolved."""
        captured.append(list(domains))

    build_domain_app(["posts", "discussion"], registry=REGISTRY, settings=Settings(), configure=[hook])
    assert captured == [[POSTS, DISCUSSION]]


def test_the_repository_scope_is_recorded_on_the_app() -> None:
    """A product's binding reads the scope off state rather than recomputing it."""
    app = build_domain_app([POSTS, DISCUSSION], settings=Settings())
    scope = app.state.repository_scope
    assert isinstance(scope, RepositoryScope)
    assert scope.name == "posts+discussion"


def test_scope_for_unions_the_declarations_and_keeps_order() -> None:
    """Written and read repositories, in registration order, with no duplicate."""
    scope = scope_for([POSTS, DISCUSSION])
    assert scope.names == ("posts", "authors", "comments")
    assert scope.read_only == ()


def test_a_repository_one_domain_writes_is_writable_for_the_application() -> None:
    """`posts` is read-only to discussion alone, and writable once posts is served too.

    The scope must never be narrower than the IAM policy, or a legitimate write fails in
    process while the grant would have allowed it.
    """
    assert scope_for([DISCUSSION]).read_only == ("posts",)
    assert scope_for([POSTS, DISCUSSION]).read_only == ()


def test_an_empty_scope_is_labelled_none() -> None:
    """A label is always a string, so a log line never renders an empty one."""
    assert scope_for([]).name == "none"


def test_check_secrets_returns_nothing_when_no_domain_names_one() -> None:
    """A function serving no secret-naming domain never calls the checker at all.

    This is what lets such a function deploy with no Secrets Manager grant.
    """
    calls: list[tuple[str, ...]] = []
    assert check_secrets([POSTS], Settings(), require=lambda *names: calls.append(names)) == ()
    assert calls == []


def test_check_secrets_requires_every_named_secret_in_production() -> None:
    """The union of the served domains' names is what is required, sorted."""
    calls: list[tuple[str, ...]] = []
    checked = check_secrets(
        [POSTS, DISCUSSION],
        Settings(environment="production"),
        require=lambda *names: calls.append(names),
    )
    assert checked == ("SECRET_KEY",)
    assert calls == [("SECRET_KEY",)]


def test_check_secrets_reads_is_production_off_the_settings() -> None:
    """Two of the three adopting products publish the flag, so it is preferred."""
    calls: list[tuple[str, ...]] = []
    check_secrets(
        [DISCUSSION],
        Settings(environment="local", is_production=True),
        require=lambda *names: calls.append(names),
    )
    assert calls == [("SECRET_KEY",)]


def test_check_secrets_uses_the_settings_own_requirer() -> None:
    """With no `require` passed it calls `settings.require_secrets`, as the products do."""
    calls: list[tuple[str, ...]] = []
    settings = Settings(environment="production", require_secrets=lambda *names: calls.append(names))
    check_secrets([DISCUSSION], settings)
    assert calls == [("SECRET_KEY",)]


def test_check_secrets_refuses_when_it_has_nothing_to_require_with() -> None:
    """A strict check with no checker is a wiring mistake and says so."""
    with pytest.raises(LookupError, match="require_secrets"):
        check_secrets([DISCUSSION], Settings(environment="production"))


def test_check_secrets_only_warns_outside_production() -> None:
    """A workstation runs the stack with an empty key rather than refusing to start."""
    with pytest.warns(UserWarning, match="SECRET_KEY is empty"):
        assert check_secrets([DISCUSSION], Settings(SECRET_KEY="")) == ("SECRET_KEY",)


def test_check_secrets_is_quiet_when_the_key_is_set() -> None:
    """A set key outside production warns about nothing."""
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert check_secrets([DISCUSSION], Settings(SECRET_KEY="set")) == ("SECRET_KEY",)


def test_check_secrets_does_not_warn_for_a_name_outside_warn_on() -> None:
    """Only the names a caller lists warn; anything else is silently optional."""
    domain = Domain(name="d", requires_secrets=("GOOGLE_CLIENT_SECRET",))
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert check_secrets([domain], Settings()) == ("GOOGLE_CLIENT_SECRET",)


def test_tracing_is_skipped_when_the_otlp_endpoint_is_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """The gate the whole wrapper exists for.

    Without it the exporter falls back to the X-Ray endpoint and a function with no X-Ray
    grant retries a 403 on every export, in silence, for the life of the process.
    """
    monkeypatch.delenv(OTLP_ENDPOINT_ENV, raising=False)
    assert configure_tracing(POSTS, Settings()) is False


def test_tracing_is_skipped_when_the_endpoint_is_only_whitespace(monkeypatch: pytest.MonkeyPatch) -> None:
    """A variable set to spaces is unset as far as the gate is concerned."""
    monkeypatch.setenv(OTLP_ENDPOINT_ENV, "   ")
    assert configure_tracing(POSTS, Settings()) is False


def test_tracing_passes_the_service_name_and_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Past the gate, the domain's own service name is what the spans carry."""
    monkeypatch.setenv(OTLP_ENDPOINT_ENV, "http://localhost:4318/v1/traces")
    captured: dict[str, Any] = {}

    def fake(service_name: str, **kwargs: Any) -> bool:
        """Record what the wrapper would have configured tracing with."""
        captured["service_name"] = service_name
        captured.update(kwargs)
        return True

    monkeypatch.setattr("webbpulse.otel.configure_tracing", fake)
    assert configure_tracing("posts", Settings(environment="staging"), registry=REGISTRY) is True
    assert captured["service_name"] == "product-posts"
    assert captured["environment"] == "staging"
    assert "sample_ratio" in captured


def test_configure_logging_reads_the_level_and_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """The wrapper saves each product writing the same three-argument call."""
    captured: dict[str, Any] = {}

    def fake(**kwargs: Any) -> None:
        """Record the logging configuration the wrapper composed."""
        captured.update(kwargs)

    monkeypatch.setattr("webbpulse.logging.configure_logging", fake)
    configure_logging(Settings(log_level="DEBUG", environment="staging"), service="product-posts")
    assert captured == {"level": "DEBUG", "service": "product-posts", "environment": "staging"}


class IdentitySettings:
    """A stand-in for the identity settings a product's glue builds."""

    def __init__(self, environment: str = "local") -> None:
        """Record the environment the middleware would refuse on."""
        self.environment = environment


def test_the_local_authorizer_is_added_on_a_local_stack() -> None:
    """A local stack has no gateway, so the middleware verifies the token in process."""
    app = FastAPI()
    assert local_authorizer(
        app,
        Settings(environment="local", IDENTITY_ISSUER="https://auth.local"),
        build_identity_settings=lambda _: IdentitySettings(),
    )


def test_the_local_authorizer_is_skipped_off_a_local_stack() -> None:
    """Deployed, API Gateway has already verified the token, so nothing is added."""
    built: list[Any] = []
    assert not local_authorizer(
        FastAPI(),
        Settings(environment="staging", IDENTITY_ISSUER="https://auth.example"),
        build_identity_settings=lambda s: built.append(s),
    )
    assert built == [], "the identity settings must not be built in a deployed function"


def test_the_local_authorizer_is_skipped_with_no_issuer() -> None:
    """With no issuer there is no identity route and so no token to verify."""
    built: list[Any] = []
    assert not local_authorizer(
        FastAPI(),
        Settings(environment="local", IDENTITY_ISSUER=""),
        build_identity_settings=lambda s: built.append(s),
    )
    assert built == []


def test_the_local_authorizer_respects_the_identity_settings_environment() -> None:
    """The two environments are separate variables, and the middleware refuses on the second."""
    assert not local_authorizer(
        FastAPI(),
        Settings(environment="local", IDENTITY_ISSUER="https://auth.local"),
        build_identity_settings=lambda _: IdentitySettings(environment="staging"),
    )


def test_the_entrypoint_pair_builds_only_its_own_domain() -> None:
    """`build_app` is this domain's application and nothing else."""
    build_app, _ = domain_entrypoint(
        "posts",
        registry=REGISTRY,
        build=lambda domain: build_domain_app(domain, settings=Settings()),
    )
    assert "/api/v1/posts" in paths_of(build_app())


def test_main_configures_logging_then_tracing_then_serves(monkeypatch: pytest.MonkeyPatch) -> None:
    """The order is load-bearing and this is what holds it.

    Logging first so a misconfigured function fails at cold start with the failure already
    in JSON, and tracing before the build because the server span middleware can only be
    injected into an unbuilt middleware stack.
    """
    order: list[str] = []
    monkeypatch.setattr("webbpulse.composition.configure_logging", lambda *a, **k: order.append("logging"))
    monkeypatch.setattr("webbpulse.composition.configure_tracing", lambda *a, **k: order.append("tracing"))

    def build(domain: Domain) -> FastAPI:
        """Record that the application was built, after the process-wide wiring."""
        order.append("build")
        return build_domain_app(domain, settings=Settings())

    _, main = domain_entrypoint(
        POSTS,
        build=build,
        settings=Settings,
        check=lambda domain, settings: order.append("check"),
        serve=lambda app: order.append("serve"),
    )
    main()
    assert order == ["logging", "tracing", "check", "build", "serve"]


def test_a_product_logging_hook_replaces_the_package_format(monkeypatch: pytest.MonkeyPatch) -> None:
    """The seam a product with its own log format uses, instead of passing `settings=None`.

    The package's `configure_logging` must not also run: a product passing its own is
    replacing the format, not adding to it.
    """
    order: list[str] = []
    monkeypatch.setattr("webbpulse.composition.configure_logging", lambda *a, **k: order.append("package-logging"))
    monkeypatch.setattr("webbpulse.composition.configure_tracing", lambda *a, **k: order.append("tracing"))
    services: list[str] = []

    def product_logging(service: str) -> None:
        """This product's own colorized format, taking the service name and nothing else."""
        services.append(service)
        order.append("product-logging")

    def build(domain: Domain) -> FastAPI:
        """Record that the application was built, after the process-wide wiring."""
        order.append("build")
        return build_domain_app(domain, settings=Settings())

    _, main = domain_entrypoint(
        POSTS,
        build=build,
        settings=Settings,
        check=lambda domain, settings: order.append("check"),
        serve=lambda app: order.append("serve"),
        configure_logging=product_logging,
    )
    main()
    assert order == ["product-logging", "tracing", "check", "build", "serve"]
    assert services == ["product-posts"]


def test_a_logging_hook_keeps_the_settings_and_the_default_secrets_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """Passing a hook does not cost the settings, so `check_secrets` still runs by default."""
    monkeypatch.setattr("webbpulse.composition.configure_tracing", lambda *a, **k: False)
    calls: list[tuple[str, ...]] = []
    _, main = domain_entrypoint(
        DISCUSSION,
        build=lambda domain: build_domain_app(domain, settings=Settings()),
        settings=lambda: Settings(environment="production", require_secrets=lambda *n: calls.append(n)),
        serve=lambda app: None,
        configure_logging=lambda service: None,
    )
    main()
    assert calls == [("SECRET_KEY",)]


def test_the_package_logging_runs_when_no_hook_is_passed(monkeypatch: pytest.MonkeyPatch) -> None:
    """The default is unchanged: the package's own format, bound to the resolved settings."""
    monkeypatch.setattr("webbpulse.composition.configure_tracing", lambda *a, **k: False)
    seen: list[str | None] = []
    monkeypatch.setattr(
        "webbpulse.composition.configure_logging",
        lambda settings, service=None, **k: seen.append(service),
    )
    _, main = domain_entrypoint(
        POSTS,
        build=lambda domain: build_domain_app(domain, settings=Settings()),
        settings=Settings,
        serve=lambda app: None,
    )
    main()
    assert seen == ["product-posts"]


def test_main_checks_the_secrets_its_own_domain_names(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no `check` passed, `check_secrets` runs over this one domain."""
    monkeypatch.setattr("webbpulse.composition.configure_logging", lambda *a, **k: None)
    monkeypatch.setattr("webbpulse.composition.configure_tracing", lambda *a, **k: False)
    calls: list[tuple[str, ...]] = []
    _, main = domain_entrypoint(
        DISCUSSION,
        build=lambda domain: build_domain_app(domain, settings=Settings()),
        settings=lambda: Settings(environment="production", require_secrets=lambda *n: calls.append(n)),
        serve=lambda app: None,
    )
    main()
    assert calls == [("SECRET_KEY",)]


def test_the_settings_factory_is_called_inside_main(monkeypatch: pytest.MonkeyPatch) -> None:
    """Importing an entrypoint module must read no environment, so the factory is deferred."""
    monkeypatch.setattr("webbpulse.composition.configure_logging", lambda *a, **k: None)
    monkeypatch.setattr("webbpulse.composition.configure_tracing", lambda *a, **k: False)
    calls: list[int] = []

    def factory() -> Settings:
        """Record that the settings were built, which must not happen at import."""
        calls.append(1)
        return Settings()

    _, main = domain_entrypoint(
        POSTS,
        build=lambda domain: build_domain_app(domain, settings=Settings()),
        settings=factory,
        serve=lambda app: None,
    )
    assert calls == []
    main()
    assert calls == [1]


def test_main_serves_the_application_it_built(monkeypatch: pytest.MonkeyPatch) -> None:
    """What `main` hands the server is what `build_app` would have returned."""
    monkeypatch.setattr("webbpulse.composition.configure_logging", lambda *a, **k: None)
    monkeypatch.setattr("webbpulse.composition.configure_tracing", lambda *a, **k: False)
    served: list[FastAPI] = []
    _, main = domain_entrypoint(
        POSTS,
        build=lambda domain: build_domain_app(domain, settings=Settings()),
        settings=Settings(),
        serve=served.append,
    )
    main()
    assert len(served) == 1
    assert served[0].title == "Posts"


PRODUCT = {
    "app/__init__.py": "",
    "app/domains/__init__.py": "",
    "app/registry.py": """
        from webbpulse.composition import Domain, DomainRegistry

        def _posts():
            from app.domains.posts.api import router
            return [router]

        def _comments():
            from app.domains.comments.api import router
            return [router]

        DOMAINS = DomainRegistry([
            Domain(name="posts", title="Posts", load_routers=_posts, router_prefix="/api/v1"),
            Domain(name="comments", title="Comments", load_routers=_comments, router_prefix="/api/v1"),
        ])
    """,
    "app/domains/posts/__init__.py": "",
    "app/domains/posts/api.py": """
        from fastapi import APIRouter

        router = APIRouter()

        @router.get("/posts")
        def list_posts():
            return {"ok": True}
    """,
    "app/domains/posts/entrypoint.py": """
        from webbpulse.composition import build_domain_app, domain_entrypoint

        from app.registry import DOMAINS

        DOMAIN = DOMAINS["posts"]
        build_app, main = domain_entrypoint(DOMAIN, build=build_domain_app)

        if __name__ == "__main__":
            main()
    """,
    "app/domains/comments/__init__.py": "",
    "app/domains/comments/api.py": """
        from fastapi import APIRouter

        router = APIRouter()

        @router.get("/comments")
        def list_comments():
            return {"ok": True}
    """,
    "app/domains/comments/entrypoint.py": """
        from webbpulse.composition import build_domain_app, domain_entrypoint

        from app.registry import DOMAINS

        DOMAIN = DOMAINS["comments"]
        build_app, main = domain_entrypoint(DOMAIN, build=build_domain_app)

        if __name__ == "__main__":
            main()
    """,
}


@pytest.fixture(scope="module")
def product(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A two-domain product laid out the way an adopting backend is.

    Written to disk because the isolation check runs each entrypoint in its own interpreter,
    which is the only way to see what an image would import.
    """
    root = tmp_path_factory.mktemp("product")
    for path, source in PRODUCT.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(textwrap.dedent(source).lstrip())
    return root


def test_a_generated_entrypoint_is_three_lines_and_builds_its_domain(product: Path) -> None:
    """The shape a product's `entrypoint.py` becomes, run as the Dockerfile CMD runs it."""
    result = subprocess.run(  # nosec B603
        [
            sys.executable,
            "-c",
            "import app.domains.posts.entrypoint as e;"
            "print(e.DOMAIN.name);"
            "print(sorted(e.build_app().openapi()['paths']))",
        ],
        cwd=product,
        env={**os.environ, "PYTHONPATH": str(product)},
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stderr
    lines = result.stdout.strip().splitlines()
    assert lines[0] == "posts"
    assert "/api/v1/posts" in lines[1]


def test_the_isolation_helper_passes_for_a_clean_product(product: Path) -> None:
    """Every entrypoint imports its own domain package and no other's.

    The claim that makes N images smaller than N copies of one image, and what both
    adopting products assert today.
    """
    from webbpulse.testing import assert_entrypoint_isolation

    registry = DomainRegistry([Domain(name="posts"), Domain(name="comments")])
    results = assert_entrypoint_isolation(registry, cwd=product)
    assert set(results) == {"posts", "comments"}
    assert results["posts"].imported >= {"app.domains.posts.entrypoint", "app.domains.posts.api"}
    assert not results["posts"].foreign
    assert results["posts"]


def test_the_isolation_helper_names_the_domain_that_leaked(product: Path, tmp_path: Path) -> None:
    """A domain reaching into another fails here rather than in a deployed function."""
    from webbpulse.testing import assert_entrypoint_isolation

    leaky = product / "app" / "domains" / "posts" / "leak.py"
    leaky.write_text("from app.domains.comments import api  # noqa: F401\n")
    entrypoint = product / "app" / "domains" / "posts" / "entrypoint.py"
    original = entrypoint.read_text()
    leaking_import = "from app.domains.posts import leak  # noqa: F401\n\nDOMAIN = "
    entrypoint.write_text(original.replace("DOMAIN = ", leaking_import))
    try:
        with pytest.raises(AssertionError, match="the posts image also imported"):
            assert_entrypoint_isolation(DomainRegistry([Domain(name="posts")]), cwd=product)
    finally:
        entrypoint.write_text(original)
        leaky.unlink()


def test_the_isolation_helper_reports_a_failing_build(product: Path) -> None:
    """An entrypoint that cannot build in a stripped environment says so with its stderr."""
    from webbpulse.testing import entrypoint_imports

    with pytest.raises(AssertionError, match="failed"):
        entrypoint_imports(
            "missing",
            module="app.domains.missing.entrypoint",
            package="missing",
            package_root="app.domains.",
            cwd=product,
        )


def test_entrypoint_imports_defaults_the_package_root(product: Path) -> None:
    """The single-domain form takes the same default as the whole-registry form."""
    from webbpulse.testing import entrypoint_imports

    result = entrypoint_imports(
        "posts",
        module="app.domains.posts.entrypoint",
        package="posts",
        cwd=product,
    )
    assert result
    assert "app.domains.posts.entrypoint" in result.imported


def test_an_allowed_foreign_import_is_not_reported(product: Path) -> None:
    """Shared wiring built from one domain's glue is a legitimate import for every domain.

    A product whose local authorizer is built from the identity domain's `package_glue`
    cannot use the check as shipped without this, and narrowing it to the named module is
    what keeps the rest of that domain out of every image.
    """
    from webbpulse.testing import assert_entrypoint_isolation

    glue = product / "app" / "domains" / "comments" / "package_glue.py"
    glue.write_text("SHARED = True\n")
    entrypoint = product / "app" / "domains" / "posts" / "entrypoint.py"
    original = entrypoint.read_text()
    shared_import = "from app.domains.comments import package_glue  # noqa: F401\n\nDOMAIN = "
    entrypoint.write_text(original.replace("DOMAIN = ", shared_import))
    try:
        results = assert_entrypoint_isolation(
            DomainRegistry([Domain(name="posts")]),
            cwd=product,
            allowed_foreign=["app.domains.comments.package_glue"],
        )
        assert not results["posts"].foreign
        assert "app.domains.comments.package_glue" in results["posts"].imported
    finally:
        entrypoint.write_text(original)
        glue.unlink()


def test_a_foreign_import_outside_the_allowance_is_still_refused(product: Path) -> None:
    """The allowance is an exception list, not an opt-out: everything else fails as before.

    Naming one module of a domain does not open the rest of it, which is the whole point:
    the glue lands in every image and the domain's endpoints must not follow it there.
    """
    from webbpulse.testing import assert_entrypoint_isolation

    glue = product / "app" / "domains" / "comments" / "package_glue.py"
    glue.write_text("SHARED = True\n")
    leaky = product / "app" / "domains" / "posts" / "leak.py"
    leaky.write_text("from app.domains.comments import api, package_glue  # noqa: F401\n")
    entrypoint = product / "app" / "domains" / "posts" / "entrypoint.py"
    original = entrypoint.read_text()
    leaking_import = "from app.domains.posts import leak  # noqa: F401\n\nDOMAIN = "
    entrypoint.write_text(original.replace("DOMAIN = ", leaking_import))
    try:
        with pytest.raises(AssertionError, match=r"the posts image also imported.*comments\.api"):
            assert_entrypoint_isolation(
                DomainRegistry([Domain(name="posts")]),
                cwd=product,
                allowed_foreign=["app.domains.comments.package_glue"],
            )
    finally:
        entrypoint.write_text(original)
        leaky.unlink()
        glue.unlink()


def test_an_allowance_mapping_applies_per_domain(product: Path) -> None:
    """A mapping allows a module for the domain it names and for no other."""
    from webbpulse.testing import assert_entrypoint_isolation

    glue = product / "app" / "domains" / "comments" / "package_glue.py"
    glue.write_text("SHARED = True\n")
    entrypoint = product / "app" / "domains" / "posts" / "entrypoint.py"
    original = entrypoint.read_text()
    shared_import = "from app.domains.comments import package_glue  # noqa: F401\n\nDOMAIN = "
    entrypoint.write_text(original.replace("DOMAIN = ", shared_import))
    registry = DomainRegistry([Domain(name="posts")])
    try:
        results = assert_entrypoint_isolation(
            registry,
            cwd=product,
            allowed_foreign={"posts": ["app.domains.comments.package_glue"]},
        )
        assert not results["posts"].foreign
        with pytest.raises(AssertionError, match="the posts image also imported"):
            assert_entrypoint_isolation(
                registry,
                cwd=product,
                allowed_foreign={"comments": ["app.domains.comments.package_glue"]},
            )
    finally:
        entrypoint.write_text(original)
        glue.unlink()
