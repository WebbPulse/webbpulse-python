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
link and `email_legal_line`. A product that sets none of them gets its name in the default
accent.
