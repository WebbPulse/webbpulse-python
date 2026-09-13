"""The vocabulary a product declares its browser tests in.

`LoginForm` names the locators for signing in and out, `RouteSpec` declares one route and
who may see it, and a `Journey` is a short list of steps against the real UI. The step
vocabulary is deliberately tiny: a product that needs more than these seven verbs writes
its own test against the `page` fixture rather than growing the shared language.

Nothing here touches a browser, so a product can import and unit test its own declarations
without Playwright installed.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

__all__ = [
    "ACCESS_LEVELS",
    "Click",
    "ExpectText",
    "ExpectUrl",
    "ExpectVisible",
    "Fill",
    "Goto",
    "Journey",
    "LoginForm",
    "Record",
    "RouteSpec",
    "Step",
    "expand",
    "url_matches",
]

ACCESS_LEVELS = ("public", "protected", "guest-only")


def expand(value: str, run_id: str) -> str:
    """Expand `{run_id}` in a declared value, so created names carry the sweepable prefix.

    Only that one placeholder is substituted, so a value carrying other braces, a CSS
    selector for instance, passes through untouched.
    """
    return value.replace("{run_id}", run_id)


@dataclass(frozen=True)
class Goto:
    """Navigate to a path relative to the web base URL."""

    path: str


@dataclass(frozen=True)
class Click:
    """Click the element a locator string resolves to."""

    locator: str


@dataclass(frozen=True)
class Fill:
    """Fill an input with a value, which may carry `{run_id}`."""

    locator: str
    value: str


@dataclass(frozen=True)
class ExpectVisible:
    """Assert an element is visible."""

    locator: str


@dataclass(frozen=True)
class ExpectText:
    """Assert an element contains a piece of text, which may carry `{run_id}`."""

    locator: str
    text: str


@dataclass(frozen=True)
class ExpectUrl:
    """Assert the current URL matches a regular expression, which may carry `{run_id}`."""

    pattern: str


@dataclass(frozen=True)
class Record:
    """Append a handle to `created_resources` so the cleanup hook deletes it.

    `resource` is whatever the product's own `pytest_e2e_cleanup` understands; the plugin
    never inspects its shape beyond expanding `{run_id}` in a string.
    """

    resource: object


Step = Goto | Click | Fill | ExpectVisible | ExpectText | ExpectUrl | Record

_MUTATING_REASON = (
    "declares mutates=True but contains no Record step, so whatever it creates in the "
    "stage would never reach created_resources and the cleanup hook would never delete "
    "it. Add a Record step naming the resource, or set mutates=False."
)


@dataclass(frozen=True)
class LoginForm:
    """The locators for signing in and out through the real UI.

    Playwright locator strings, by convention `[data-testid=login-email]` and friends. The
    two redirect fields are where the app sends a visitor who may not see a route:
    `protected_redirect` is the login path for an anonymous visitor and `guest_redirect`
    is the landing path a signed-in visitor is bounced to off a guest-only route.
    """

    path: str
    email: str = "[data-testid=login-email]"
    password: str = "[data-testid=login-password]"
    submit: str = "[data-testid=login-submit]"
    signed_in_marker: str = "[data-testid=signed-in]"
    sign_out: str = "[data-testid=sign-out]"
    signed_out_marker: str = "[data-testid=login-submit]"
    protected_redirect: str = ""
    guest_redirect: str = "/"

    def __post_init__(self) -> None:
        """Refuse a form with no login path or an empty locator."""
        if not self.path.startswith("/"):
            raise ValueError(f"LoginForm.path must be an absolute path beginning with a slash, got {self.path!r}")
        for name in ("email", "password", "submit", "signed_in_marker", "sign_out", "signed_out_marker"):
            if not str(getattr(self, name)).strip():
                raise ValueError(f"LoginForm.{name} is empty, so the sign-in journey has nothing to act on")

    @property
    def anonymous_redirect(self) -> str:
        """Where an anonymous visitor to a protected route is sent, defaulting to the login path."""
        return self.protected_redirect or self.path


@dataclass(frozen=True)
class RouteSpec:
    """One route the product declares, and who is allowed to see it.

    `access` is `"public"`, `"protected"` or `"guest-only"`. `root_locator` overrides the
    element the render check looks for children under, for an app that does not mount on
    `#root` or `#app`.
    """

    path: str
    access: str = "public"
    root_locator: str = ""
    name: str = ""

    def __post_init__(self) -> None:
        """Refuse an unknown access level or a path that is not absolute."""
        if not self.path.startswith("/"):
            raise ValueError(f"RouteSpec.path must be an absolute path beginning with a slash, got {self.path!r}")
        if self.access not in ACCESS_LEVELS:
            raise ValueError(f"RouteSpec.access must be one of {', '.join(ACCESS_LEVELS)}, got {self.access!r}")

    @property
    def label(self) -> str:
        """A junit-legible id for this route."""
        return self.name or f"{self.access}:{self.path}"


@dataclass(frozen=True)
class Journey:
    """A named sequence of steps against the real UI.

    A journey with `mutates=True` must carry at least one `Record` step, so everything it
    creates reaches `created_resources` and the product's cleanup hook. That is checked at
    construction rather than at run time, so a journey that would leak fails at collection.
    """

    name: str
    steps: Sequence[Step]
    signed_in: bool = True
    mutates: bool = False
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Refuse an unnamed or empty journey, and a mutating one with nothing recorded."""
        if not self.name.strip():
            raise ValueError("Journey.name is empty, so a failure would name no journey")
        if not self.steps:
            raise ValueError(f"Journey {self.name!r} declares no steps, so it would pass vacuously")
        if self.mutates and not self.records:
            raise ValueError(f"Journey {self.name!r} {_MUTATING_REASON}")

    @property
    def records(self) -> tuple[Record, ...]:
        """Every `Record` step in this journey."""
        return tuple(step for step in self.steps if isinstance(step, Record))

    @property
    def label(self) -> str:
        """A junit-legible id for this journey."""
        return self.name


def url_matches(pattern: str, url: str) -> bool:
    """Whether a URL matches an `ExpectUrl` pattern, as a search rather than a full match."""
    return re.search(pattern, url) is not None
