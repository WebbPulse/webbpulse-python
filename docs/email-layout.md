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

- `scheme="light"`, the default: `light` is inline on every element, and `dark` is applied by
  clients that read `prefers-color-scheme` or Outlook's `data-ogsc` and `data-ogsb`.
- `scheme="dark"`, for a product whose app is dark by default: `dark` and the dark accent are
  inline, `color-scheme` is declared `dark light`, and the same dark rules pin the message
  against a client's own inversion. The message is dark in every client and either system
  mode, and `light` is unused.
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
  client that strips `<style>` still renders the theme's own scheme. The body and the wrapper
  table both carry the page colour as `bgcolor` and inline style.
- Dark mode: `color-scheme` meta tags, a `prefers-color-scheme: dark` block for Apple Mail and
  others, and the same rules under `[data-ogsc]` and `[data-ogsb]` for Outlook.
- Gmail's phone apps ignore `color-scheme` and invert colours themselves, which turns a dark
  message white. A dark-first theme guards against it in two ways. The page and the card
  repeat their fill as `background-image: linear-gradient(<hex>,<hex>)`, because Gmail
  inverts background colours but not background images. The header name, the card content
  and the footer sit in two wrappers, `wp-gmail-screen` and `wp-gmail-difference`, that are
  black only under Gmail's `u + .body` selector (the body carries class `body`). When Gmail
  inverts the wrappers to white and the text to dark, the difference layer turns the text
  light again and the screen layer lays it over the gradient. Where Gmail inverts nothing,
  both layers leave the colours as drawn. Nothing inside a wrapper may be an image or a
  gradient fill, because the difference layer would invert it. That is why the logo stays
  outside them, and why quotes and code keep plain colour fills.
- Gmail's inversion and the difference layer cancel only for greys. A saturated accent comes
  out as its complement, so an orange button would turn light blue. The button, every link
  and every quote rule therefore carry `wp-gmail-keep`, a second `mix-blend-mode:difference`
  under `u + .body` that undoes the wrapper's flip and leaves Gmail's own dark-mode version of
  the accent. A quote's rule is drawn as its own 3px cell, because the quote fill next to it
  needs the plain double inversion. The card's 1px line is an outer cell with a gradient fill
  and 1px of padding instead of a border colour, which Gmail would invert to a light hairline.
  The light scheme renders none of this, byte for byte.

## Identity emails

The four identity messages use `email_brand(settings)`: `product_name`, `logo_url`,
`email_accent_color`, `frontend_base_url` as the home link, `support_email` as a footer
link, `email_legal_line`, `email_dark_accent_color` and `email_theme` (an `EmailTheme`
passed in code). A product that sets none of them gets its name in the default accent and
theme.
