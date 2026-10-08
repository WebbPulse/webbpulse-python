"""Tests for `webbpulse.email_layout`, the branded email shell."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from webbpulse.email_layout import (
    DEFAULT_ACCENT,
    DEFAULT_LIGHT,
    BulletList,
    Button,
    Code,
    EmailBrand,
    EmailLink,
    EmailPalette,
    EmailTheme,
    Heading,
    ListItem,
    Paragraph,
    Quote,
    Strong,
    normalise_hex,
    render_email,
)

BRAND = EmailBrand(
    product_name="Acme",
    logo_url="https://cdn.example.com/logo.png",
    accent_color="#E8590C",
    home_url="https://acme.example.com",
    footer_links=(EmailLink("Help", "https://acme.example.com/help"),),
    legal_line="Acme Ltd, 1 Main Street",
)


def _render(brand: EmailBrand = BRAND) -> tuple[str, str]:
    """Render a message with every block kind and return its HTML and text parts."""
    rendered = render_email(
        brand,
        subject="Hello <there>",
        preheader="A short preview",
        blocks=[
            Heading("Welcome"),
            Paragraph("Hi ", Strong("Sam"), ", read ", EmailLink("the guide", "https://acme.example.com/guide"), "."),
            Button("Open Acme", "https://acme.example.com/open", show_url=True),
            Quote("A <b>quoted</b> line"),
            Code("123456"),
            BulletList((ListItem("First", "detail"), ListItem("Second"))),
            Paragraph("An aside", muted=True),
        ],
        footer_note=Paragraph("You get this because you signed up."),
        footer_links=[EmailLink("Settings", "https://acme.example.com/settings")],
    )
    return rendered.html, rendered.text


def test_the_html_is_a_table_layout_with_inline_styles_logo_and_accent() -> None:
    """The shell carries the logo, the normalised accent on the button and dark mode rules."""
    html, _ = _render()

    assert html.startswith("<!doctype html>")
    assert 'role="presentation"' in html
    assert 'src="https://cdn.example.com/logo.png"' in html
    assert 'bgcolor="#e8590c"' in html
    assert "prefers-color-scheme:dark" in html
    assert "[data-ogsc]" in html
    assert 'name="color-scheme" content="light dark"' in html
    assert "A short preview" in html


def test_every_value_is_escaped() -> None:
    """Markup in a value is escaped, never rendered."""
    html, _ = _render()

    assert "<b>quoted</b>" not in html
    assert "&lt;b&gt;quoted&lt;/b&gt;" in html
    assert "<title>Hello &lt;there&gt;</title>" in html


def test_the_text_part_carries_the_same_content_and_footer() -> None:
    """The plain-text alternative has the button URL on its own line and the footer links."""
    _, text = _render()

    assert "Welcome" in text
    assert "\nhttps://acme.example.com/open\n" in text
    assert "the guide (https://acme.example.com/guide)" in text
    assert "> A <b>quoted</b> line" in text
    assert "- First\n  > detail" in text
    assert "Settings: https://acme.example.com/settings\nHelp: https://acme.example.com/help" in text
    assert text.rstrip().endswith("Acme, Acme Ltd, 1 Main Street")


def test_a_message_footer_link_comes_before_the_brand_links() -> None:
    """A message's own links lead the footer."""
    html, _ = _render()

    assert html.index("Settings") < html.index(">Help<")


@pytest.mark.parametrize("url", ["javascript:alert(1)", "data:text/html,x", "/relative"])
def test_an_unsafe_link_is_refused(url: str) -> None:
    """Only http, https and mailto links can be built."""
    with pytest.raises(ValueError, match="email link"):
        Button("x", url)
    with pytest.raises(ValueError, match="email link"):
        EmailLink("x", url)


def test_an_invalid_accent_raises_and_with_accent_is_lenient() -> None:
    """A product's constant accent must be valid, while a stored accent falls back quietly."""
    with pytest.raises(ValueError, match="accent_color"):
        EmailBrand(accent_color="orange")

    assert BRAND.with_accent("not a colour") is BRAND
    assert BRAND.with_accent(None) is BRAND
    assert BRAND.with_accent("#3B82F6").accent == "#3b82f6"


def test_normalise_hex() -> None:
    """Short hex expands and case folds; anything else is `None`."""
    assert normalise_hex("#ABC") == "#aabbcc"
    assert normalise_hex(" #A1B2C3 ") == "#a1b2c3"
    assert normalise_hex("red") is None
    assert normalise_hex("") is None


def test_link_colors_reach_contrast_on_both_cards() -> None:
    """A pale accent is darkened for light links and a dark accent lightened for dark ones."""
    pale = EmailBrand(accent_color="#ffe066")
    deep = EmailBrand(accent_color="#1a1a40")

    assert pale.link_color != pale.accent
    assert deep.dark_link_color != deep.accent
    assert pale.accent_foreground == "#111111"
    assert deep.accent_foreground == "#ffffff"


def test_a_bare_brand_renders_without_header_or_footer() -> None:
    """A brand with no name, logo or links still renders, using the default accent."""
    rendered = render_email(EmailBrand(), subject="s", blocks=[Button("Go", "https://x.example.com")])

    assert f'bgcolor="{DEFAULT_ACCENT}"' in rendered.html
    assert "<img" not in rendered.html
    assert "\n--\n" not in rendered.text


APP_LIGHT = EmailPalette(
    page="#f7f7f8",
    card="#ffffff",
    line="#e5e5ea",
    text="#1b1c20",
    muted="#62646f",
    quote="#efeff2",
    quote_text="#1b1c20",
)
APP_DARK = EmailPalette(
    page="#141518",
    card="#1b1c20",
    line="#2a2b31",
    text="#e7e7eb",
    muted="#9b9da7",
    quote="#232429",
    quote_text="#e7e7eb",
)
APP_THEME = EmailTheme(
    light=APP_LIGHT,
    dark=APP_DARK,
    font_stack="Inter, ui-sans-serif, system-ui, sans-serif",
    on_accent_dark="#17120f",
    card_radius=8,
    button_radius=6,
    inline_radius=4,
)


def test_the_default_theme_keeps_the_shell_as_it_was() -> None:
    """A brand that names no theme renders the default palette, system fonts and radii."""
    html, _ = _render()

    assert f"background-color:{DEFAULT_LIGHT.page};" in html
    assert f"border:1px solid {DEFAULT_LIGHT.line};border-radius:12px;" in html
    assert "border-radius:8px;background-color:#e8590c;" in html
    assert "font-family:-apple-system," in html


def test_a_theme_replaces_every_palette_colour_font_and_radius() -> None:
    """The theme's tokens reach the inline styles and the dark-mode rules, and the defaults are gone."""
    brand = EmailBrand(product_name="Acme", accent_color="#b8451a", dark_accent_color="#f2703a", theme=APP_THEME)
    html, _ = _render(brand)

    assert f"background-color:{APP_LIGHT.page};" in html
    assert f"border:1px solid {APP_LIGHT.line};border-radius:8px;" in html
    assert "border-radius:6px;background-color:#b8451a;" in html
    assert "font-family:Inter, ui-sans-serif, system-ui, sans-serif;" in html
    assert f"color:{APP_LIGHT.text};" in html
    assert f".wp-bg{{background-color:{APP_DARK.page} !important;}}" in html
    assert ".wp-button{background-color:#f2703a !important;}" in html
    assert ".wp-button-text{color:#17120f !important;}" in html
    assert ".wp-rule{border-left-color:#f2703a !important;}" in html
    for default in (DEFAULT_LIGHT.page, DEFAULT_LIGHT.line, DEFAULT_LIGHT.text, DEFAULT_LIGHT.muted):
        assert default not in html
    assert "-apple-system" not in html


def test_a_new_accent_replaces_the_dark_accent_too() -> None:
    """A workspace accent shows in both schemes unless a dark one is given with it."""
    brand = EmailBrand(accent_color="#b8451a", dark_accent_color="#f2703a", theme=APP_THEME)

    assert brand.with_accent(None) is brand
    assert brand.with_accent("#1d4ed8").dark_accent == "#1d4ed8"
    assert brand.with_accent("#1d4ed8", "#60a5fa").dark_accent == "#60a5fa"
    assert brand.dark_accent_foreground == "#17120f"
    assert brand.accent_foreground == "#ffffff"


def test_link_colors_reach_contrast_on_the_theme_cards() -> None:
    """Links are clamped against the theme's own cards, not the defaults."""
    default = EmailBrand(accent_color="#6b6b6b")
    pale_card = EmailBrand(accent_color="#6b6b6b", theme=EmailTheme(light=_palette(APP_LIGHT, card="#d4d4d8")))

    assert default.link_color == "#6b6b6b"
    assert pale_card.link_color != "#6b6b6b"


def _palette(base: EmailPalette, **changes: str) -> EmailPalette:
    """`base` with some colours changed."""
    fields = ("page", "card", "line", "text", "muted", "quote", "quote_text")
    values = {name: getattr(base, name) for name in fields}
    values.update(changes)
    return EmailPalette(**values)


@pytest.mark.parametrize(
    "build",
    [
        lambda: EmailPalette("red", "#fff", "#fff", "#fff", "#fff", "#fff", "#fff"),
        lambda: EmailTheme(font_stack="Inter; color:red"),
        lambda: EmailTheme(card_radius=99),
        lambda: EmailTheme(on_accent_dark="black"),
        lambda: EmailBrand(dark_accent_color="navy"),
    ],
)
def test_an_invalid_theme_value_raises(build: Callable[[], object]) -> None:
    """A palette, theme or dark accent that is not email-safe is refused when it is built."""
    with pytest.raises(ValueError):
        build()
