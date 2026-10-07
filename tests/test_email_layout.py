"""Tests for `webbpulse.email_layout`, the branded email shell."""

from __future__ import annotations

import pytest

from webbpulse.email_layout import (
    DEFAULT_ACCENT,
    BulletList,
    Button,
    Code,
    EmailBrand,
    EmailLink,
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
