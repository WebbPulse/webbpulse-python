"""The built-in OAuth consent screen, themed by the product that mounts it.

A product passes a `ConsentTheme` to `build_identity_router` and gets a finished,
branded authorization screen without owning any of its markup: its palettes for light
and dark, its logo, its fonts and plain-language labels for its scopes. The page is
self-contained. Fonts and logos are data URIs or absolute https URLs, styles carry a
per-response nonce, no script runs, and the Content-Security-Policy names only those
sources, the form's own origin and the two places the form may redirect to.

`describe_scopes` is the scope-to-sentence mapping on its own, for a product that
replaces the renderer wholesale but still wants the same wording.
"""

from __future__ import annotations

import base64
import html
import re
import secrets
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, fields
from functools import cache
from importlib import resources
from typing import TYPE_CHECKING, Any, Final, Literal
from urllib.parse import urlsplit

if TYPE_CHECKING:  # pragma: no cover
    from webbpulse.identity.oauth_server import ConsentContext

__all__ = [
    "DARK_PALETTE",
    "LIGHT_PALETTE",
    "ConsentPalette",
    "ConsentTheme",
    "FontFace",
    "ScopeGroup",
    "ScopeLabel",
    "ScopeRow",
    "build_consent_renderer",
    "consent_security_policy",
    "describe_scopes",
    "render_consent_page",
]

type ColorScheme = Literal["light", "dark", "system"]
"""Which palette the page paints with; `system` follows `prefers-color-scheme`."""

type ScopeAccess = Literal["read", "write"]
"""Whether a scope only reads, which decides the group it is listed under."""

_COLOR: Final = re.compile(r"^(#[0-9a-fA-F]{3,8}|(rgb|rgba|hsl|hsla|oklch)\([0-9a-zA-Z.,%/ -]{1,60}\)|transparent)$")
_FONT_FAMILY: Final = re.compile(r"^[A-Za-z0-9 ,'\"-]{1,300}$")
_DATA_IMAGE: Final = re.compile(r"^data:image/(png|svg\+xml|webp|jpeg|gif)(;base64)?,[A-Za-z0-9+/=%._~!$&'()*,;:@-]*$")
_DATA_FONT: Final = re.compile(r"^data:font/(woff2|woff|ttf|otf);base64,[A-Za-z0-9+/=]*$")
_HTTPS_URL: Final = re.compile(r"^https://[A-Za-z0-9._~:/?#\[\]@!$&*+,;=%-]+$")
_HOST: Final = re.compile(r"^[A-Za-z0-9.\-]+(:[0-9]{1,5})?$|^\[[0-9A-Fa-f:.]+\](:[0-9]{1,5})?$")
_SCHEME: Final = re.compile(r"^[a-z][a-z0-9+.\-]{0,31}$")

_SYSTEM_FONTS: Final = "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif"


@dataclass(frozen=True, slots=True)
class ConsentPalette:
    """The colour tokens the consent screen paints with, for one colour scheme.

    Every value must be a plain CSS colour (hex, `rgb()`, `hsl()` or `oklch()`), checked on
    construction so a token can never carry anything else into the stylesheet.
    """

    background: str
    surface: str
    raised: str
    line: str
    line_strong: str
    text: str
    text_muted: str
    text_faint: str
    accent: str
    accent_foreground: str
    accent_ring: str
    danger: str

    def __post_init__(self) -> None:
        """Refuse any token that is not a plain colour."""
        for item in fields(self):
            value = getattr(self, item.name)
            if not isinstance(value, str) or not _COLOR.match(value.strip()):
                raise ValueError(f"ConsentPalette.{item.name} must be a CSS colour, got {value!r}.")


LIGHT_PALETTE: Final = ConsentPalette(
    background="#ffffff",
    surface="#f7f7f8",
    raised="#efeff2",
    line="#e5e5ea",
    line_strong="#cfd0d7",
    text="#1b1c20",
    text_muted="#62646f",
    text_faint="#686a74",
    accent="#4b55c8",
    accent_foreground="#ffffff",
    accent_ring="#4b55c866",
    danger="#c42b33",
)
"""The neutral light palette a product that supplies none is shown."""

DARK_PALETTE: Final = ConsentPalette(
    background="#141518",
    surface="#1b1c20",
    raised="#232429",
    line="#2a2b31",
    line_strong="#3a3c44",
    text="#e7e7eb",
    text_muted="#9b9da7",
    text_faint="#8a8d99",
    accent="#8a93ff",
    accent_foreground="#101114",
    accent_ring="#8a93ff80",
    danger="#f0616a",
)
"""The neutral dark palette a product that supplies none is shown."""


@dataclass(frozen=True, slots=True)
class FontFace:
    """One `@font-face` weight: a data URI or an absolute https URL, and its format.

    A URL on another origin must be served with CORS, as every webfont must; a data URI
    avoids that and keeps the page free of third-party requests.
    """

    weight: int
    src: str
    format: str = "woff2"

    def __post_init__(self) -> None:
        """Refuse a weight outside CSS's range, an unknown format or an unusable source."""
        if not 1 <= self.weight <= 1000:
            raise ValueError(f"FontFace.weight must be between 1 and 1000, got {self.weight}.")
        if self.format not in {"woff2", "woff", "truetype", "opentype"}:
            raise ValueError(f"FontFace.format must be woff2, woff, truetype or opentype, got {self.format!r}.")
        _asset_source(self.src, data_pattern=_DATA_FONT, what="FontFace.src")

    @classmethod
    def woff2(cls, weight: int, data: bytes) -> FontFace:
        """A face from raw woff2 bytes, inlined as a data URI."""
        encoded = base64.b64encode(data).decode("ascii")
        return cls(weight=weight, src=f"data:font/woff2;base64,{encoded}")


@dataclass(frozen=True, slots=True)
class ScopeLabel:
    """How one scope reads on the consent screen.

    `label` is the row's sentence, `detail` an optional line under it, and `access`
    whether it only reads, which places it under the read or the write heading.
    """

    label: str
    detail: str = ""
    access: ScopeAccess = "write"


@dataclass(frozen=True, slots=True)
class ScopeRow:
    """One requested scope as the consent screen lists it."""

    scope: str
    label: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ScopeGroup:
    """The requested scopes that share an access level, under one heading."""

    access: ScopeAccess
    title: str
    rows: tuple[ScopeRow, ...]


@dataclass(frozen=True, slots=True)
class ConsentTheme:
    """A product's look for the built-in consent screen.

    `logo_url` is the product mark, and `logo_dark_url` the one shown on the dark palette
    when it differs. Both accept an absolute https URL or a `data:image/...` URI.
    `color_scheme` pins the page to one palette or follows the visitor's system setting.
    `scope_labels` wins over the package's built-in and inferred wording, per scope, and
    `revoke_note` is a sentence in the fine print telling people where to disconnect later.
    """

    light: ConsentPalette = LIGHT_PALETTE
    dark: ConsentPalette = DARK_PALETTE
    color_scheme: ColorScheme = "system"
    logo_url: str = ""
    logo_dark_url: str = ""
    font_family: str = _SYSTEM_FONTS
    font_faces: tuple[FontFace, ...] = ()
    scope_labels: Mapping[str, ScopeLabel] = field(default_factory=dict)
    revoke_note: str = ""

    def __post_init__(self) -> None:
        """Refuse an unknown scheme, an unsafe font family or a logo the page cannot load."""
        if self.color_scheme not in {"light", "dark", "system"}:
            raise ValueError(f"ConsentTheme.color_scheme must be light, dark or system, got {self.color_scheme!r}.")
        if not _FONT_FAMILY.match(self.font_family):
            raise ValueError("ConsentTheme.font_family may hold only names, quotes, commas and spaces.")
        for name in ("logo_url", "logo_dark_url"):
            value = getattr(self, name)
            if value:
                _asset_source(value, data_pattern=_DATA_IMAGE, what=f"ConsentTheme.{name}")


_BUILTIN_LABELS: Final[Mapping[str, ScopeLabel]] = {
    "openid": ScopeLabel("Confirm who you are", access="read"),
    "profile": ScopeLabel("See your name", access="read"),
    "email": ScopeLabel("See your email address", access="read"),
    "offline_access": ScopeLabel(
        "Stay connected", "Keeps access until you revoke it, without asking you to sign in again.", access="read"
    ),
    "mcp:read": ScopeLabel("Read your data", access="read"),
    "mcp:write": ScopeLabel("Make changes on your behalf"),
}

_VERBS: Final[Mapping[str, tuple[str, ScopeAccess]]] = {
    "read": ("Read {}", "read"),
    "list": ("List {}", "read"),
    "write": ("Create and update {}", "write"),
    "create": ("Create {}", "write"),
    "update": ("Update {}", "write"),
    "delete": ("Delete {}", "write"),
    "admin": ("Manage {}", "write"),
    "manage": ("Manage {}", "write"),
}

_GROUP_TITLES: Final[Mapping[ScopeAccess, str]] = {"read": "Read access", "write": "Write access"}


def describe_scopes(scopes: Iterable[str], labels: Mapping[str, ScopeLabel] | None = None) -> tuple[ScopeGroup, ...]:
    """Group requested scopes under read and write headings, in plain language.

    A product's own label wins, then the package's built-in wording, then a sentence
    inferred from the `resource:action` convention, so `comments:write` reads "Create and
    update comments". A scope in no known shape is listed verbatim under write access,
    the side that asks the user to look harder.
    """
    rows: dict[ScopeAccess, list[ScopeRow]] = {"read": [], "write": []}
    for scope in dict.fromkeys(scopes):
        label = (labels or {}).get(scope) or _BUILTIN_LABELS.get(scope) or _infer_label(scope)
        rows[label.access].append(ScopeRow(scope=scope, label=label.label, detail=label.detail))
    return tuple(
        ScopeGroup(access=access, title=_GROUP_TITLES[access], rows=tuple(found))
        for access, found in rows.items()
        if found
    )


def _infer_label(scope: str) -> ScopeLabel:
    """A sentence for a `resource:action` scope, or the scope itself when it has no such shape."""
    resource, _, action = scope.partition(":")
    subject = resource.replace("_", " ").replace("-", " ").strip()
    if not subject or not action:
        return ScopeLabel(scope)
    template, access = _VERBS.get(action.lower(), (f"{action.replace('_', ' ').capitalize()} {{}}", "write"))
    return ScopeLabel(template.format(subject), access=access)


def build_consent_renderer(theme: ConsentTheme | None = None) -> Callable[[ConsentContext], Any]:
    """A `ConsentRenderer` that paints the built-in screen with `theme`."""
    chosen = theme or ConsentTheme()

    def render(context: ConsentContext) -> Any:
        """Render the themed consent screen for one authorization request."""
        return render_consent_page(context, chosen)

    return render


def consent_security_policy(context: ConsentContext, theme: ConsentTheme, nonce: str) -> str:
    """The Content-Security-Policy for one consent page.

    Nothing loads by default. Styles need the response's nonce, images and fonts only the
    theme's own sources, and no script runs at all. `form-action` names this server plus
    the two places a submission may redirect: the client's validated redirect URI and the
    product's sign-in page, since browsers apply the directive across the redirect too.
    When the redirect URI cannot be expressed as a source the directive is left off
    rather than breaking the flow; the signed form is what binds it either way.
    """
    images = sorted({_asset_source(url, data_pattern=_DATA_IMAGE, what="logo") for url in _logos(theme)})
    fonts = sorted({_asset_source(face.src, data_pattern=_DATA_FONT, what="font") for face in theme.font_faces})
    directives = ["default-src 'none'", f"style-src 'nonce-{nonce}'"]
    if images:
        directives.append(f"img-src {' '.join(images)}")
    if fonts:
        directives.append(f"font-src {' '.join(fonts)}")
    targets = [_form_target(context.request.redirect_uri)]
    if context.switch_account_url:
        targets.append(_form_target(context.switch_account_url))
    if all(target is not None for target in targets):
        directives.append(f"form-action 'self' {' '.join(sorted({t for t in targets if t}))}")
    directives += ["frame-ancestors 'none'", "base-uri 'none'"]
    return "; ".join(directives)


def render_consent_page(context: ConsentContext, theme: ConsentTheme) -> Any:
    """Render the consent screen as one self-contained, framing-proof HTML response."""
    from fastapi.responses import HTMLResponse

    nonce = secrets.token_urlsafe(18)
    body = _page(context, theme, nonce)
    return HTMLResponse(
        body,
        headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": consent_security_policy(context, theme, nonce),
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        },
    )


def _logos(theme: ConsentTheme) -> list[str]:
    """The logo URLs the page may load."""
    return [url for url in (theme.logo_url, theme.logo_dark_url) if url]


def _asset_source(url: str, *, data_pattern: re.Pattern[str], what: str) -> str:
    """The CSP source that admits `url`: `data:` for a data URI, the origin for https.

    An https URL may hold only URL-safe characters, never quotes, parentheses, backslashes,
    angle brackets or whitespace, because a font source is written into the stylesheet.
    """
    if url.startswith("data:"):
        if not data_pattern.match(url):
            raise ValueError(f"{what} is not a data URI of an accepted type.")
        return "data:"
    if not _HTTPS_URL.match(url):
        raise ValueError(f"{what} must be an absolute https URL of URL-safe characters or a data URI, got {url!r}.")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.netloc or "@" in parsed.netloc or not _HOST.match(parsed.netloc):
        raise ValueError(f"{what} must be an absolute https URL or a data URI, got {url!r}.")
    return f"https://{parsed.netloc.lower()}"


def _form_target(url: str) -> str | None:
    """The `form-action` source for a redirect target, or None when none can be written safely."""
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme in {"http", "https"}:
        if not parsed.netloc or "@" in parsed.netloc or not _HOST.match(parsed.netloc):
            return None
        return f"{scheme}://{parsed.netloc.lower()}"
    if _SCHEME.match(scheme):
        return f"{scheme}:"
    return None


def _escape(value: str) -> str:
    """HTML-escape a value bound for the page, quotes included."""
    return html.escape(value, quote=True)


def _initial(value: str) -> str:
    """The first letter or digit of a name, upper-cased, for a monogram."""
    for character in value:
        if character.isalnum():
            return character.upper()
    return "?"


def _palette_css(palette: ConsentPalette) -> str:
    """The custom properties for one palette."""
    return (
        f"--bg:{palette.background};--surface:{palette.surface};--raised:{palette.raised};"
        f"--line:{palette.line};--line-strong:{palette.line_strong};--text:{palette.text};"
        f"--text-muted:{palette.text_muted};--text-faint:{palette.text_faint};--accent:{palette.accent};"
        f"--on-accent:{palette.accent_foreground};--ring:{palette.accent_ring};--danger:{palette.danger};"
    )


@cache
def _layout_css() -> str:
    """The theme-independent layout rules, shipped beside this module."""
    return resources.files("webbpulse.identity").joinpath("consent_page.css").read_text(encoding="utf-8")


def _stylesheet(theme: ConsentTheme) -> str:
    """The page's whole stylesheet: font faces, both palettes and the layout."""
    faces = "".join(
        f"@font-face{{font-family:'ConsentBrand';font-style:normal;font-weight:{face.weight};"
        f"font-display:swap;src:url(\"{face.src}\") format('{face.format}');}}"
        for face in theme.font_faces
    )
    family = f"'ConsentBrand', {theme.font_family}" if theme.font_faces else theme.font_family
    light = _palette_css(theme.light)
    dark = _palette_css(theme.dark)
    return (
        f"{faces}:root{{color-scheme:light;--font:{family};{light}}}"
        f":root[data-scheme=dark]{{color-scheme:dark;{dark}}}"
        f"@media (prefers-color-scheme:dark){{:root[data-scheme=system]{{color-scheme:dark;{dark}}}}}"
        f"{_layout_css()}"
    )


_READ_ICON: Final = (
    '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" aria-hidden="true">'
    '<path d="M1.5 8s2.4-4.5 6.5-4.5S14.5 8 14.5 8 12.1 12.5 8 12.5 1.5 8 1.5 8Z"/><circle cx="8" cy="8" r="2"/></svg>'
)
_WRITE_ICON: Final = (
    '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" aria-hidden="true">'
    '<path d="M10.5 2.5l3 3L6 13H3v-3l7.5-7.5Z"/></svg>'
)


def _product_tile(product: str, theme: ConsentTheme) -> str:
    """The product's mark, or its initial when the theme names no logo."""
    if not theme.logo_url:
        return f'<span class="tile"><span class="fallback">{_escape(_initial(product))}</span></span>'
    light = f'<img class="logo-light" src="{_escape(theme.logo_url)}" alt="">'
    if not theme.logo_dark_url:
        return f'<span class="tile">{light}</span>'
    dark = f'<img class="logo-dark" src="{_escape(theme.logo_dark_url)}" alt="">'
    return f'<span class="tile has-dark">{light}{dark}</span>'


def _account(context: ConsentContext) -> str:
    """The signed-in account, with the way to switch it when a sign-in page is configured."""
    email = context.account_email
    name = context.account_name or email or "Your account"
    detail = f'<div class="email">{_escape(email)}</div>' if email and email != name else ""
    switch = (
        f'<a class="switch" href="{_escape(context.switch_account_url)}">Switch account</a>'
        if context.switch_account_url
        else ""
    )
    return (
        '<div class="account">'
        f'<span class="avatar" aria-hidden="true">{_escape(_initial(name))}</span>'
        f'<div class="who"><div class="name">Signed in as {_escape(name)}</div>{detail}</div>'
        f"{switch}</div>"
    )


def _permissions(context: ConsentContext, theme: ConsentTheme, client_name: str) -> str:
    """The requested scopes, grouped and worded for people."""
    groups = describe_scopes(context.request.scopes, theme.scope_labels)
    parts = []
    for group in groups:
        icon = _READ_ICON if group.access == "read" else _WRITE_ICON
        rows = "".join(
            f'<li class="perm">{icon}<div><div class="what">{_escape(row.label)}</div>'
            + (f'<div class="detail">{_escape(row.detail)}</div>' if row.detail else "")
            + "</div></li>"
            for row in group.rows
        )
        parts.append(f'<div class="group"><p class="group-title">{_escape(group.title)}</p><ul>{rows}</ul></div>')
    if not parts:
        parts.append(
            '<div class="group"><ul><li class="perm"><div class="what">Nothing beyond signing in</div></li></ul></div>'
        )
    return (
        f'<section class="section" aria-labelledby="perms-label"><h2 class="label" id="perms-label">'
        f"{_escape(client_name)} will be able to</h2>"
        f'<div class="perms">{"".join(parts)}</div></section>'
    )


def _workspaces(context: ConsentContext) -> tuple[str, bool]:
    """The workspace picker, and whether the user has anything to grant access to."""
    if not context.tenants:
        if not context.tenant_required:
            return "", True
        return (
            '<div class="section"><span class="label">Workspace</span>'
            '<p class="empty">This account is not in a workspace it can grant access to. '
            "Switch to another account, or ask a workspace admin to add you.</p></div>",
            False,
        )
    choices = "".join(
        f'<label class="choice"><input type="radio" name="tenant_id" value="{_escape(tenant.id)}" required'
        f"{' checked' if index == 0 else ''}>"
        f'<span class="ws" aria-hidden="true">{_escape(_initial(tenant.name or tenant.id))}</span>'
        f'<span class="ws-name">{_escape(tenant.name or tenant.id)}</span>'
        '<span class="tick" aria-hidden="true"></span></label>'
        for index, tenant in enumerate(context.tenants)
    )
    return (
        '<fieldset class="section"><legend class="label">Workspace</legend>'
        f'<div class="choices">{choices}</div></fieldset>',
        True,
    )


def _page(context: ConsentContext, theme: ConsentTheme, nonce: str) -> str:
    """The consent page's markup."""
    request = context.request
    client_name = request.client.client_name or request.client.client_id
    product = context.product_name or "this app"
    destination = urlsplit(request.redirect_uri).hostname or request.redirect_uri
    workspace_markup, grantable = _workspaces(context)
    hidden = "".join(
        f'<input type="hidden" name="{_escape(key)}" value="{_escape(value)}">'
        for key, value in context.form_fields.items()
    )
    allow = '<button class="primary" type="submit" name="decision" value="allow"' + (
        ">Allow access</button>" if grantable else " disabled>Allow access</button>"
    )
    title = f"Connect {client_name} to {product}" if context.product_name else f"Authorize {client_name}"
    revoke = f" {_escape(theme.revoke_note)}" if theme.revoke_note else ""
    return f"""<!doctype html>
<html lang="en" data-scheme="{theme.color_scheme}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="color-scheme" content="{"light dark" if theme.color_scheme == "system" else theme.color_scheme}">
<title>{_escape(title)}</title>
<style nonce="{nonce}">{_stylesheet(theme)}</style></head>
<body><main class="shell"><div class="column">
<div class="marks" aria-hidden="true">
<span class="tile client">{_escape(_initial(client_name))}</span>
<span class="connector"><span></span><span></span><span></span></span>
{_product_tile(product, theme)}
</div>
<h1>{_escape(title)}</h1>
<p class="lede"><strong>{_escape(client_name)}</strong> is asking for access to your {_escape(product)} account.</p>
{_account(context)}
<form method="post" action="{_escape(context.form_action)}">
{hidden}
{_permissions(context, theme, client_name)}
{workspace_markup}
<div class="actions">
{allow}
<button class="secondary" type="submit" name="decision" value="deny" formnovalidate>Deny</button>
</div>
<p class="fine">Allowing sends you back to <strong>{_escape(destination)}</strong>.
Only allow access for apps you trust.{revoke}</p>
</form>
</div></main></body></html>"""
