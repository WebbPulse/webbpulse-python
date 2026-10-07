"""A branded email shell that any product renders its messages through.

One table-based layout with inline styles: a header with the product's logo and name, a
card holding the message blocks, an accent-coloured call-to-action button, and a footer
with the product's links and legal line. The same blocks render the plain-text
alternative, so the two parts cannot drift apart. Every value is escaped here, so a caller
passes plain strings and never markup.

Email clients drop SVG, apply `<style>` unevenly and invert colours in dark mode on their
own. The layout therefore keeps every colour inline, declares `color-scheme` for the
clients that honour it, and carries a `prefers-color-scheme` block, plus Outlook's
`data-ogsc` selectors, for the clients that read one. Stdlib only, so it can be imported
without any extra.
"""

from __future__ import annotations

import html
import re
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from typing import Final
from urllib.parse import urlsplit

__all__ = [
    "DEFAULT_ACCENT",
    "BulletList",
    "Button",
    "Code",
    "EmailBlock",
    "EmailBrand",
    "EmailLink",
    "Heading",
    "Inline",
    "ListItem",
    "Paragraph",
    "Quote",
    "RenderedEmail",
    "Strong",
    "normalise_hex",
    "render_email",
]

DEFAULT_ACCENT: Final = "#4b55c8"
"""The accent a product gets when it names none, the same one the consent screen defaults to."""

FONT_STACK: Final = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
MONO_STACK: Final = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"

_LIGHT: Final = {
    "page": "#f4f4f5",
    "card": "#ffffff",
    "line": "#e4e4e7",
    "text": "#18181b",
    "muted": "#71717a",
    "quote": "#f4f4f5",
    "quote_text": "#3f3f46",
}
_DARK: Final = {
    "page": "#0f1012",
    "card": "#18191c",
    "line": "#2a2b31",
    "text": "#e7e7eb",
    "muted": "#9b9da7",
    "quote": "#232429",
    "quote_text": "#c9cad1",
}

_HEX = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
_SAFE_SCHEMES: Final = frozenset({"http", "https", "mailto"})


def normalise_hex(value: str | None) -> str | None:
    """A `#rrggbb` colour in lower case, expanding `#rgb`, or `None` when `value` is not one.

    Lenient on purpose, so a product can pass a stored, user-chosen colour straight through
    `EmailBrand.with_accent` and fall back to its own accent when the value is unusable.
    """
    if not value:
        return None
    candidate = value.strip()
    if not _HEX.match(candidate):
        return None
    digits = candidate[1:].lower()
    if len(digits) == 3:
        digits = "".join(character * 2 for character in digits)
    return f"#{digits}"


def _channels(color: str) -> tuple[int, int, int]:
    """The red, green and blue bytes of a normalised `#rrggbb` colour."""
    return int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16)


def _luminance(color: str) -> float:
    """WCAG relative luminance of a normalised colour."""

    def linear(byte: int) -> float:
        channel = byte / 255
        return channel / 12.92 if channel <= 0.03928 else float(((channel + 0.055) / 1.055) ** 2.4)

    red, green, blue = (linear(byte) for byte in _channels(color))
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def _contrast(first: str, second: str) -> float:
    """WCAG contrast ratio between two normalised colours."""
    lighter, darker = sorted((_luminance(first), _luminance(second)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def _mix(color: str, other: str, weight: float) -> str:
    """`color` moved `weight` of the way towards `other`, as `#rrggbb`."""
    mixed = (
        round(channel + (target - channel) * weight)
        for channel, target in zip(_channels(color), _channels(other), strict=True)
    )
    return "#" + "".join(f"{channel:02x}" for channel in mixed)


def _safe_url(url: str) -> str:
    """Refuse a link whose scheme is not http, https or mailto.

    A `javascript:` or `data:` href in an email is never intended, and refusing it here means
    no template can carry one through a value it did not expect to be a URL.
    """
    scheme = urlsplit(url.strip()).scheme.lower()
    if scheme not in _SAFE_SCHEMES:
        raise ValueError(f"An email link must be http, https or mailto, not {scheme or 'relative'}: {url!r}")
    return url.strip()


def _e(value: str) -> str:
    """Escape one value for an HTML text node or a double-quoted attribute."""
    return html.escape(value, quote=True)


@dataclass(frozen=True, slots=True)
class EmailLink:
    """A labelled link, used inline in a paragraph and in the footer."""

    label: str
    url: str

    def __post_init__(self) -> None:
        """Refuse an unsafe scheme when the link is built rather than when it is mailed."""
        _safe_url(self.url)


@dataclass(frozen=True, slots=True)
class Strong:
    """Bold text inside a paragraph."""

    text: str


Inline = str | EmailLink | Strong
"""What a paragraph is made of: plain text, a link, or bold text."""


class Paragraph:
    """One paragraph of inline parts; `muted` renders it small and grey, for asides."""

    __slots__ = ("muted", "parts")

    def __init__(self, *parts: Inline, muted: bool = False) -> None:
        """Keep the parts in order."""
        self.parts: tuple[Inline, ...] = parts
        self.muted = muted


@dataclass(frozen=True, slots=True)
class Heading:
    """The message's title, rendered once at the top of the card."""

    text: str


@dataclass(frozen=True, slots=True)
class Button:
    """The call to action, in the brand accent.

    `show_url` adds the raw link under the button, for a message whose link must still work
    when a client blocks the button's styling or the reader wants to see where it goes.
    """

    label: str
    url: str
    show_url: bool = False

    def __post_init__(self) -> None:
        """Refuse an unsafe scheme when the button is built."""
        _safe_url(self.url)


@dataclass(frozen=True, slots=True)
class Quote:
    """Quoted text, such as a comment excerpt, with an accent rule on its left."""

    text: str


@dataclass(frozen=True, slots=True)
class Code:
    """A short code the reader types somewhere, set large in a monospaced face."""

    text: str


@dataclass(frozen=True, slots=True)
class ListItem:
    """One bullet: a line and an optional quoted detail under it."""

    text: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class BulletList:
    """A bulleted list of items."""

    items: tuple[ListItem, ...]


EmailBlock = Heading | Paragraph | Button | Quote | Code | BulletList
"""Every block a message body is built from."""


@dataclass(frozen=True, slots=True)
class EmailBrand:
    """Who a message comes from: the product's name, logo, accent and footer.

    `logo_url` is an absolute URL to a PNG or JPEG, since clients drop SVG; empty shows the
    product name alone. `home_url` is where the header links. `footer_links` and
    `legal_line` close every message. An invalid `accent_color` raises, because it is a
    product's own constant; `with_accent` is the lenient path for a stored colour.
    """

    product_name: str = ""
    logo_url: str = ""
    accent_color: str = DEFAULT_ACCENT
    home_url: str = ""
    footer_links: tuple[EmailLink, ...] = ()
    legal_line: str = ""
    logo_size: int = 32
    _accent: str = field(default="", init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate the accent and the URLs once, so rendering never has to."""
        accent = normalise_hex(self.accent_color)
        if accent is None:
            raise ValueError(f"EmailBrand.accent_color must be a #rrggbb colour, not {self.accent_color!r}.")
        object.__setattr__(self, "_accent", accent)
        for url in (self.logo_url, self.home_url):
            if url:
                _safe_url(url)

    @property
    def accent(self) -> str:
        """The accent as a normalised `#rrggbb`."""
        return self._accent

    @property
    def accent_foreground(self) -> str:
        """White or near black, whichever reads better on the accent."""
        return "#ffffff" if _contrast(self._accent, "#ffffff") >= _contrast(self._accent, "#111111") else "#111111"

    @property
    def link_color(self) -> str:
        """The accent for links on the light card, darkened until it reaches 4.5:1 on white."""
        color = self._accent
        for _ in range(10):
            if _contrast(color, _LIGHT["card"]) >= 4.5:
                break
            color = _mix(color, "#000000", 0.12)
        return color

    @property
    def dark_link_color(self) -> str:
        """The accent for links on the dark card, lightened until it reaches 4.5:1."""
        color = self._accent
        for _ in range(10):
            if _contrast(color, _DARK["card"]) >= 4.5:
                break
            color = _mix(color, "#ffffff", 0.15)
        return color

    def with_accent(self, color: str | None) -> EmailBrand:
        """This brand with another accent, or unchanged when `color` is empty or not a colour."""
        accent = normalise_hex(color)
        if accent is None or accent == self._accent:
            return self
        return replace(self, accent_color=accent)


@dataclass(frozen=True, slots=True)
class RenderedEmail:
    """Both parts of one message, rendered from the same blocks."""

    html: str
    text: str


def render_email(
    brand: EmailBrand,
    *,
    subject: str,
    blocks: Sequence[EmailBlock],
    preheader: str = "",
    footer_note: Paragraph | None = None,
    footer_links: Sequence[EmailLink] = (),
) -> RenderedEmail:
    """Render one message through the branded shell, in HTML and plain text.

    `preheader` is the hidden line inbox lists show beside the subject. `footer_note` says
    why the reader got the message, such as which setting turns it off, and `footer_links`
    come before the brand's own links, so a message can lead with its own settings link.
    """
    links = (*footer_links, *brand.footer_links)
    return RenderedEmail(
        html=_render_html(brand, subject=subject, blocks=blocks, preheader=preheader, note=footer_note, links=links),
        text=_render_text(brand, blocks=blocks, note=footer_note, links=links),
    )


def _text_style(size: int, line: int, color: str, *, weight: int = 400, margin: str = "0 0 16px") -> str:
    """The inline style every text element carries, so a client that drops `<style>` still renders it."""
    return (
        f"margin:{margin};font-family:{FONT_STACK};font-size:{size}px;line-height:{line}px;"
        f"font-weight:{weight};color:{color};"
    )


def _inline_html(brand: EmailBrand, parts: Sequence[Inline]) -> str:
    """One paragraph's parts as escaped HTML."""
    out: list[str] = []
    for part in parts:
        if isinstance(part, EmailLink):
            out.append(
                f'<a class="wp-link" href="{_e(part.url)}" target="_blank" '
                f'style="color:{brand.link_color};text-decoration:underline;">{_e(part.label)}</a>'
            )
        elif isinstance(part, Strong):
            out.append(f'<strong style="font-weight:600;">{_e(part.text)}</strong>')
        else:
            out.append(_e(part))
    return "".join(out)


def _block_html(brand: EmailBrand, block: EmailBlock) -> str:
    """One block as table-safe HTML with inline styles."""
    if isinstance(block, Heading):
        return f'<h1 class="wp-text" style="{_text_style(20, 28, _LIGHT["text"], weight=600)}">{_e(block.text)}</h1>\n'
    if isinstance(block, Paragraph):
        if block.muted:
            style = _text_style(13, 20, _LIGHT["muted"])
            return f'<p class="wp-muted" style="{style}">{_inline_html(brand, block.parts)}</p>\n'
        style = _text_style(15, 24, _LIGHT["text"])
        return f'<p class="wp-text" style="{style}">{_inline_html(brand, block.parts)}</p>\n'
    if isinstance(block, Button):
        url = _e(block.url)
        markup = (
            '<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:8px 0 24px;">'
            f'<tr><td align="center" bgcolor="{brand.accent}" '
            f'style="border-radius:8px;background-color:{brand.accent};">'
            f'<a href="{url}" target="_blank" style="display:inline-block;padding:12px 22px;'
            f"font-family:{FONT_STACK};font-size:15px;line-height:20px;font-weight:600;"
            f'color:{brand.accent_foreground};text-decoration:none;border-radius:8px;">{_e(block.label)}</a>'
            "</td></tr></table>\n"
        )
        if block.show_url:
            style = _text_style(13, 20, _LIGHT["muted"], margin="-12px 0 24px")
            markup += (
                f'<p class="wp-muted" style="{style}word-break:break-all;">Or open this link: '
                f'<a class="wp-link" href="{url}" target="_blank" '
                f'style="color:{brand.link_color};text-decoration:underline;">{url}</a></p>\n'
            )
        return markup
    if isinstance(block, Quote):
        return (
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
            'style="margin:0 0 16px;"><tr>'
            f'<td class="wp-quote" style="border-left:3px solid {brand.accent};background-color:{_LIGHT["quote"]};'
            f"padding:12px 16px;border-radius:4px;font-family:{FONT_STACK};font-size:14px;line-height:22px;"
            f'color:{_LIGHT["quote_text"]};">{_e(block.text)}</td></tr></table>\n'
        )
    if isinstance(block, Code):
        return (
            '<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 16px;"><tr>'
            f'<td class="wp-quote" style="background-color:{_LIGHT["quote"]};padding:14px 20px;border-radius:8px;'
            f"font-family:{MONO_STACK};font-size:28px;line-height:34px;font-weight:600;letter-spacing:6px;"
            f'color:{_LIGHT["text"]};">{_e(block.text)}</td></tr></table>\n'
        )
    items: list[str] = []
    for item in block.items:
        detail = ""
        if item.detail:
            detail = (
                f'<div class="wp-quote" style="margin:6px 0 0;padding:8px 12px;border-left:3px solid {brand.accent};'
                f"background-color:{_LIGHT['quote']};border-radius:4px;font-size:14px;line-height:20px;"
                f'color:{_LIGHT["quote_text"]};">{_e(item.detail)}</div>'
            )
        style = _text_style(15, 22, _LIGHT["text"], margin="0 0 8px")
        items.append(f'<li class="wp-text" style="{style}">{_e(item.text)}{detail}</li>')
    return f'<ul style="margin:0 0 16px;padding:0 0 0 20px;">{"".join(items)}</ul>\n'


def _style_block(brand: EmailBrand) -> str:
    """The head styles: dark mode for the clients that honour it, and a narrow-screen padding."""
    dark = _DARK
    rules = [
        f".wp-bg{{background-color:{dark['page']} !important;}}",
        f".wp-card{{background-color:{dark['card']} !important;border-color:{dark['line']} !important;}}",
        f".wp-text{{color:{dark['text']} !important;}}",
        f".wp-muted{{color:{dark['muted']} !important;}}",
        f".wp-link{{color:{brand.dark_link_color} !important;}}",
        f".wp-quote{{background-color:{dark['quote']} !important;color:{dark['quote_text']} !important;}}",
    ]
    outlook = "\n".join(f"[data-ogsc] {rule}" for rule in rules)
    return (
        "<style>\n"
        ":root{color-scheme:light dark;supported-color-schemes:light dark;}\n"
        "body{margin:0;padding:0;}\n"
        "@media (max-width:620px){.wp-container{width:100% !important;}.wp-pad{padding:24px 20px !important;}}\n"
        f"@media (prefers-color-scheme:dark){{{''.join(rules)}}}\n"
        f"{outlook}\n"
        "</style>"
    )


def _header_html(brand: EmailBrand) -> str:
    """The logo and product name row, or nothing when the brand has neither."""
    if not brand.product_name and not brand.logo_url:
        return ""
    cells: list[str] = []
    size = brand.logo_size
    if brand.logo_url:
        image = (
            f'<img src="{_e(brand.logo_url)}" width="{size}" height="{size}" alt="" '
            f'style="display:block;border:0;outline:none;text-decoration:none;width:{size}px;height:{size}px;">'
        )
        if brand.home_url:
            image = f'<a href="{_e(brand.home_url)}" target="_blank" style="text-decoration:none;">{image}</a>'
        cells.append(f'<td style="padding:0 10px 0 0;vertical-align:middle;">{image}</td>')
    if brand.product_name:
        name = _e(brand.product_name)
        if brand.home_url:
            name = (
                f'<a class="wp-text" href="{_e(brand.home_url)}" target="_blank" '
                f'style="color:{_LIGHT["text"]};text-decoration:none;">{name}</a>'
            )
        style = _text_style(17, 24, _LIGHT["text"], weight=600, margin="0")
        cells.append(f'<td class="wp-text" style="vertical-align:middle;{style}">{name}</td>')
    return (
        '<tr><td style="padding:0 4px 20px;">'
        '<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>'
        f"{''.join(cells)}</tr></table></td></tr>\n"
    )


def _footer_html(brand: EmailBrand, note: Paragraph | None, links: Sequence[EmailLink]) -> str:
    """The footer: why the reader got this, the links, and the product and legal line."""
    muted = _text_style(12, 18, _LIGHT["muted"], margin="0 0 8px")
    rows: list[str] = []
    if note is not None:
        rows.append(f'<p class="wp-muted" style="{muted}">{_inline_html(brand, note.parts)}</p>')
    if links:
        joined = " &nbsp;&middot;&nbsp; ".join(
            f'<a class="wp-link" href="{_e(link.url)}" target="_blank" '
            f'style="color:{brand.link_color};text-decoration:underline;">{_e(link.label)}</a>'
            for link in links
        )
        rows.append(f'<p class="wp-muted" style="{muted}">{joined}</p>')
    signature = " &nbsp;&middot;&nbsp; ".join(_e(part) for part in (brand.product_name, brand.legal_line) if part)
    if signature:
        rows.append(f'<p class="wp-muted" style="{muted}">{signature}</p>')
    if not rows:
        return ""
    return f'<tr><td style="padding:20px 4px 0;">{"".join(rows)}</td></tr>\n'


def _render_html(
    brand: EmailBrand,
    *,
    subject: str,
    blocks: Sequence[EmailBlock],
    preheader: str,
    note: Paragraph | None,
    links: Sequence[EmailLink],
) -> str:
    """The whole HTML document."""
    hidden = ""
    if preheader:
        hidden = (
            '<div style="display:none;max-height:0;max-width:0;overflow:hidden;mso-hide:all;'
            f'font-size:1px;line-height:1px;opacity:0;color:transparent;">{_e(preheader)}'
            f"{'&#847;&zwnj;&nbsp;' * 30}</div>\n"
        )
    body = "".join(_block_html(brand, block) for block in blocks)
    page = _LIGHT["page"]
    return (
        "<!doctype html>\n"
        '<html lang="en" xmlns="http://www.w3.org/1999/xhtml">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="x-apple-disable-message-reformatting">\n'
        '<meta name="color-scheme" content="light dark">\n'
        '<meta name="supported-color-schemes" content="light dark">\n'
        f"<title>{_e(subject)}</title>\n"
        f"{_style_block(brand)}\n"
        "</head>\n"
        f'<body class="wp-bg" style="margin:0;padding:0;background-color:{page};">\n'
        f"{hidden}"
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="wp-bg" '
        f'bgcolor="{page}" style="background-color:{page};">\n'
        '<tr><td align="center" style="padding:32px 16px;">\n'
        '<table role="presentation" class="wp-container" width="560" cellpadding="0" cellspacing="0" border="0" '
        'style="width:560px;max-width:560px;">\n'
        f"{_header_html(brand)}"
        f'<tr><td class="wp-card wp-pad" bgcolor="{_LIGHT["card"]}" style="background-color:{_LIGHT["card"]};'
        f'border:1px solid {_LIGHT["line"]};border-radius:12px;padding:32px;">\n'
        f"{body}"
        "</td></tr>\n"
        f"{_footer_html(brand, note, links)}"
        "</table>\n"
        "</td></tr>\n"
        "</table>\n"
        "</body>\n"
        "</html>\n"
    )


def _inline_text(parts: Sequence[Inline]) -> str:
    """One paragraph's parts as plain text, a link reading as its label then its URL."""
    out: list[str] = []
    for part in parts:
        if isinstance(part, EmailLink):
            out.append(part.url if part.label == part.url else f"{part.label} ({part.url})")
        elif isinstance(part, Strong):
            out.append(part.text)
        else:
            out.append(part)
    return "".join(out)


def _block_text(block: EmailBlock) -> str:
    """One block as plain text.

    A button's URL sits alone on its own line, so a reader can copy it and a test can find
    it by the line it starts.
    """
    if isinstance(block, Heading):
        return block.text
    if isinstance(block, Paragraph):
        return _inline_text(block.parts)
    if isinstance(block, Button):
        return f"{block.label}:\n{block.url}"
    if isinstance(block, Quote):
        return "\n".join(f"> {line}" for line in block.text.splitlines() or [""])
    if isinstance(block, Code):
        return f"    {block.text}"
    lines: list[str] = []
    for item in block.items:
        lines.append(f"- {item.text}")
        if item.detail:
            lines.append(f"  > {item.detail}")
    return "\n".join(lines)


def _render_text(
    brand: EmailBrand,
    *,
    blocks: Sequence[EmailBlock],
    note: Paragraph | None,
    links: Sequence[EmailLink],
) -> str:
    """The plain-text alternative: the same blocks, then the footer under a rule."""
    sections = [_block_text(block) for block in blocks]
    footer: list[str] = []
    if note is not None:
        footer.append(_inline_text(note.parts))
    footer.extend(f"{link.label}: {link.url}" for link in links)
    signature = ", ".join(part for part in (brand.product_name, brand.legal_line) if part)
    if signature:
        footer.append(signature)
    text = "\n\n".join(section for section in sections if section)
    if footer:
        text += "\n\n--\n" + "\n".join(footer)
    return text + "\n"
