# Branded email shell

`webbpulse.email_layout` renders every outbound message through one layout: a header with
the product's logo and name, a card holding the message, an accent-coloured button, and a
footer with links and a legal line. The HTML and plain-text parts come from the same blocks,
so they cannot drift. Stdlib only. Back to the [README](../README.md).

```python
from webbpulse.email_layout import Button, EmailBrand, EmailLink, Heading, Paragraph
from webbpulse.identity import render_branded

brand = EmailBrand(
    product_name="Acme",
    logo_url="https://app.acme.example/email/logo.png",
    accent_color="#e8590c",
    home_url="https://app.acme.example",
    footer_links=(EmailLink("Help", "https://app.acme.example/help"),),
)
message = render_branded(
    brand.with_accent(workspace.accent_color),
    to=address,
    subject="You were invited to Acme",
    preheader="Join your team on Acme.",
    blocks=[Heading("Join your team"), Paragraph("Sam invited you."), Button("Accept", link)],
    footer_note=Paragraph("You got this because Sam invited this address."),
    tags={"purpose": "invite"},
)
```

## Themes

`EmailBrand.theme` takes an `EmailTheme` built from the product's own design tokens, so its
emails read like its app. Every value is a hex colour or a plain number, never a CSS variable,
because email clients do not resolve them.

```python
from webbpulse.email_layout import EmailPalette, EmailTheme

theme = EmailTheme(
    light=EmailPalette(page="#f7f7f8", card="#ffffff", line="#e5e5ea", text="#1b1c20",
                       muted="#62646f", quote="#efeff2", quote_text="#1b1c20"),
    dark=EmailPalette(page="#141518", card="#1b1c20", line="#2a2b31", text="#e7e7eb",
                      muted="#9b9da7", quote="#232429", quote_text="#e7e7eb"),
    font_stack="Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif",
    on_accent_dark="#17120f",
    card_radius=8,
    button_radius=6,
)
brand = EmailBrand(accent_color="#b8451a", dark_accent_color="#f2703a", theme=theme)
```

- `light` is inline on every element. `dark` is applied by clients that read
  `prefers-color-scheme` or Outlook's `data-ogsc`.
- `dark_accent_color` repaints the button, its text and the quote rule in dark mode. Empty uses
  the accent. `with_accent(color, dark=None)` replaces both, so a workspace colour shows in each
  scheme.
- Text on the accent is `on_accent_light` or `on_accent_dark`, whichever contrasts more.
- A font stack may not carry quotes, braces, angle brackets or semicolons, and radii are 0 to
  32 pixels. `DEFAULT_THEME` is what a brand gets when it names none.

## Rules the shell enforces

- Every value is escaped. Callers pass plain strings, never markup.
- Links, buttons, the logo and the home URL must be `http`, `https` or `mailto`; anything
  else raises when the block is built.
- `accent_color` on `EmailBrand` must be `#rgb` or `#rrggbb` and raises otherwise, because
  it is a product constant. `with_accent` is the lenient path for a stored, user-chosen
  colour: an unusable value keeps the brand's own accent.
- Button text is white or near black, whichever contrasts better with the accent. Link
  colours are darkened (light card) or lightened (dark card) until they reach 4.5:1.

## Email client constraints

- The logo must be a PNG or JPEG at an absolute URL. Gmail and Outlook drop SVG.
- Layout is nested `role="presentation"` tables, 560px wide, with every colour inline, so a
  client that strips `<style>` still renders the light design.
- Dark mode: `color-scheme` meta tags, a `prefers-color-scheme: dark` block for Apple Mail and
  others, and the same rules under `[data-ogsc]` for Outlook. Gmail applies its own
  inversion, which the inline colours survive.

## Identity emails

The four identity messages use `email_brand(settings)`: `product_name`, `logo_url`,
`email_accent_color`, `frontend_base_url` as the home link, `support_email` as a footer
link, `email_legal_line`, `email_dark_accent_color` and `email_theme` (an `EmailTheme`
passed in code). A product that sets none of them gets its name in the default accent and
theme.
