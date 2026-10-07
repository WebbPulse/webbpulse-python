"""Sending the two emails identity owns: a verification link and a reset link.

An abstract sender with an SES v2 implementation and a recording one, plus
`CappedEmailSender`, which puts any sender behind a `webbpulse.email_cap.EmailSendCap`.
Bodies are built from `webbpulse.email_layout` blocks, which escape every value and render
the HTML and plain-text parts from the same content.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final, Protocol

from webbpulse.email_layout import (
    DEFAULT_ACCENT,
    Button,
    EmailBlock,
    EmailBrand,
    EmailLink,
    Heading,
    Paragraph,
    render_email,
)

if TYPE_CHECKING:  # pragma: no cover
    from webbpulse.email_cap import EmailCapDecision, EmailCategory, EmailSendCap
    from webbpulse.identity.settings import IdentitySettings

__all__ = [
    "TRANSACTIONAL_PURPOSES",
    "CappedEmailSender",
    "EmailCapExceeded",
    "EmailMessage",
    "EmailSendFailed",
    "EmailSendResult",
    "EmailSender",
    "RecordingEmailSender",
    "SesV2Client",
    "SesV2EmailSender",
    "email_brand",
    "render_branded",
    "render_password_changed",
    "render_password_reset",
    "render_registration_notice",
    "render_verification",
]

_log = logging.getLogger(__name__)

CHARSET: Final = "UTF-8"

TRANSACTIONAL_PURPOSES: Final[frozenset[str]] = frozenset(
    {"verify_email", "reset_password", "password_changed", "registration_notice"}
)
"""The `purpose` tags `CappedEmailSender` counts as transactional, besides any `mfa` prefix."""


class EmailSendFailed(Exception):
    """SES refused a message, or the client raised on the way to it.

    A distinct type rather than the underlying `ClientError`, so a flow can decide what a
    send failure means without importing botocore.
    """


@dataclass(frozen=True, slots=True)
class EmailMessage:
    """One rendered message, ready for any sender.

    Rendered before a sender is chosen. `to` is a single address: identity never sends to
    more than one recipient.
    """

    to: str
    subject: str
    text: str
    html: str
    tags: dict[str, str] = field(default_factory=dict)


class EmailSender(ABC):
    """Send one message: the whole seam.

    One method, because identity sends one message at a time and batching belongs to a
    product's own notification path.
    """

    @abstractmethod
    def send(self, message: EmailMessage) -> str:
        """Send one message and return a provider message id.

        Raises `EmailSendFailed` when the provider refuses. The id is for the log line only.
        """


class SesV2Client(Protocol):
    """The one SES v2 call this module makes, as a structural type.

    A protocol rather than a boto3 import, so the `identity` extra does not depend on boto3.
    """

    def send_email(self, **kwargs: Any) -> Any:
        """Send one message through SES v2."""
        ...


class SesV2EmailSender(EmailSender):
    """`EmailSender` over SES v2 `SendEmail`.

    Takes a client rather than building one, so no AWS call happens at import. The
    configuration set is omitted from the call when unset, since a missing one fails a send.
    """

    def __init__(
        self,
        client: SesV2Client,
        *,
        from_address: str,
        configuration_set: str | None = None,
    ) -> None:
        """Bind the sender to a client, a verified from address and an optional config set."""
        if not from_address:
            raise ValueError(
                "SesV2EmailSender needs a from_address. It is `IdentitySettings.email_from`, "
                "and SES refuses a send from an unverified or empty identity."
            )
        self._client = client
        self._from = from_address
        self._configuration_set = configuration_set or None

    @classmethod
    def from_settings(cls, settings: IdentitySettings, client: SesV2Client) -> SesV2EmailSender:
        """Build one from the settings fields that already name the address and config set."""
        return cls(
            client,
            from_address=settings.email_from,
            configuration_set=settings.ses_configuration_set,
        )

    def send(self, message: EmailMessage) -> str:
        """Send one message through SES v2 and return its `MessageId`."""
        request: dict[str, Any] = {
            "FromEmailAddress": self._from,
            "Destination": {"ToAddresses": [message.to]},
            "Content": {
                "Simple": {
                    "Subject": {"Data": message.subject, "Charset": CHARSET},
                    "Body": {
                        "Text": {"Data": message.text, "Charset": CHARSET},
                        "Html": {"Data": message.html, "Charset": CHARSET},
                    },
                }
            },
        }
        if self._configuration_set:
            request["ConfigurationSetName"] = self._configuration_set
        if message.tags:
            request["EmailTags"] = [{"Name": name, "Value": value} for name, value in sorted(message.tags.items())]

        try:
            response = self._client.send_email(**request)
        except Exception as exc:
            raise EmailSendFailed(f"SES refused the message: {exc}") from exc

        message_id = str(response.get("MessageId", "")) if isinstance(response, dict) else ""
        _log.info(
            "Identity email sent.",
            extra={
                "event": "email.sent",
                "purpose": message.tags.get("purpose", "unknown"),
                "message_id": message_id,
            },
        )
        return message_id


class EmailCapExceeded(EmailSendFailed):
    """A send refused by the cap, raised only by a `CappedEmailSender` built with `raise_on_cap`.

    A subclass of `EmailSendFailed`, so identity's flows treat it as any other send failure.
    """

    def __init__(self, decision: EmailCapDecision) -> None:
        """Keep the decision that refused the send."""
        self.decision = decision
        super().__init__(f"Email send cap reached: {', '.join(decision.exceeded) or 'unknown'}.")


@dataclass(frozen=True, slots=True)
class EmailSendResult:
    """What `CappedEmailSender.send_checked` did: `sent`, the provider id, and the decision."""

    sent: bool
    message_id: str
    decision: EmailCapDecision


class CappedEmailSender(EmailSender):
    """An `EmailSender` that checks an `EmailSendCap` before delegating to another sender.

    A capped send is skipped: `send` returns an empty message id and `send_checked` returns
    a result with `sent=False`. Pass `raise_on_cap=True` to raise `EmailCapExceeded`
    instead. A message is transactional when its `purpose` tag is in
    `transactional_purposes` or starts with `mfa`, and counts against the transactional
    limits.
    """

    def __init__(
        self,
        sender: EmailSender,
        cap: EmailSendCap,
        *,
        default_tenant: str = "-",
        raise_on_cap: bool = False,
        transactional_purposes: frozenset[str] = TRANSACTIONAL_PURPOSES,
    ) -> None:
        """Wrap `sender` with `cap`, using `default_tenant` when a send names none."""
        self.sender = sender
        self.cap = cap
        self.default_tenant = default_tenant
        self.raise_on_cap = raise_on_cap
        self.transactional_purposes = transactional_purposes

    def category_of(self, message: EmailMessage) -> EmailCategory:
        """Classify a message by its `purpose` tag."""
        purpose = message.tags.get("purpose", "")
        if purpose in self.transactional_purposes or purpose.startswith("mfa"):
            return "transactional"
        return "standard"

    def send(self, message: EmailMessage) -> str:
        """Send under the cap and return the provider id, or an empty string when capped."""
        return self.send_checked(message).message_id

    def send_checked(
        self,
        message: EmailMessage,
        *,
        tenant: str | None = None,
        transactional: bool | None = None,
        now: float | None = None,
    ) -> EmailSendResult:
        """Check the cap, send when allowed, and report what happened.

        `transactional` overrides the purpose classification. Raises `EmailSendFailed` when
        the wrapped sender does, and `EmailCapExceeded` for a capped send only with
        `raise_on_cap`.
        """
        if transactional is None:
            category = self.category_of(message)
        else:
            category = "transactional" if transactional else "standard"
        decision = self.cap.check(
            message.to,
            tenant=self.default_tenant if tenant is None else tenant,
            category=category,
            purpose=message.tags.get("purpose", "unknown"),
            now=now,
        )
        if not decision.allowed:
            if self.raise_on_cap:
                raise EmailCapExceeded(decision)
            return EmailSendResult(sent=False, message_id="", decision=decision)
        return EmailSendResult(sent=True, message_id=self.sender.send(message), decision=decision)


class RecordingEmailSender(EmailSender):
    """An `EmailSender` that keeps every message in a list instead of sending it.

    The test double, and the right sender for a local run with no SES identity: the link is
    in `sent[-1].text`. Keeps the whole `EmailMessage` so a test can assert on the body.
    """

    def __init__(self, *, fail: bool = False) -> None:
        """Start with no recorded messages; `fail` makes every send raise."""
        self.sent: list[EmailMessage] = []
        self.fail = fail

    def send(self, message: EmailMessage) -> str:
        """Record the message and return a synthetic id, or raise when configured to fail."""
        if self.fail:
            raise EmailSendFailed("RecordingEmailSender is configured to fail.")
        self.sent.append(message)
        return f"recorded-{len(self.sent)}"

    def last_for(self, address: str) -> EmailMessage | None:
        """Return the most recent message sent to one address, or `None`."""
        for message in reversed(self.sent):
            if message.to == address:
                return message
        return None

    def clear(self) -> None:
        """Discard every recorded message."""
        self.sent.clear()


def email_brand(settings: IdentitySettings) -> EmailBrand:
    """The `EmailBrand` the identity emails render with, from the settings that already name it.

    A product that sets none of the branding fields still gets the shell, headed by its
    product name in the default accent, with its support address in the footer.
    """
    links: tuple[EmailLink, ...] = ()
    if settings.support_email:
        links = (EmailLink("Contact support", f"mailto:{settings.support_email}"),)
    home = settings.frontend_base_url
    return EmailBrand(
        product_name=settings.product_name,
        logo_url=settings.logo_url or "",
        accent_color=settings.email_accent_color or DEFAULT_ACCENT,
        home_url=home if home.startswith(("http://", "https://")) else "",
        footer_links=links,
        legal_line=settings.email_legal_line,
    )


def render_branded(
    brand: EmailBrand,
    *,
    to: str,
    subject: str,
    blocks: Sequence[EmailBlock],
    preheader: str = "",
    footer_note: Paragraph | None = None,
    footer_links: Sequence[EmailLink] = (),
    tags: dict[str, str] | None = None,
) -> EmailMessage:
    """Render blocks through `webbpulse.email_layout` into an `EmailMessage` ready for any sender.

    The product-side entry point for every non-identity email, so a product's invites and
    notifications share the identity emails' layout.
    """
    rendered = render_email(
        brand,
        subject=subject,
        blocks=blocks,
        preheader=preheader,
        footer_note=footer_note,
        footer_links=footer_links,
    )
    return EmailMessage(to=to, subject=subject, text=rendered.text, html=rendered.html, tags=dict(tags or {}))


def _product(settings: IdentitySettings) -> str:
    """The product name a sentence uses, with a neutral phrase when none is configured."""
    return settings.product_name or "your account"


def _support(settings: IdentitySettings) -> list[EmailBlock]:
    """The closing line naming the support address, or nothing when there is none."""
    if not settings.support_email:
        return []
    address = settings.support_email
    return [Paragraph("Questions? Write to ", EmailLink(address, f"mailto:{address}"), ".", muted=True)]


def render_verification(settings: IdentitySettings, *, to: str, link: str, expiry: str) -> EmailMessage:
    """Render the email verification message."""
    product = _product(settings)
    return render_branded(
        email_brand(settings),
        to=to,
        subject=f"Confirm your email address for {settings.product_name}".strip(),
        preheader=f"Confirm your address to finish creating your {product} account.",
        blocks=[
            Heading("Confirm your email address"),
            Paragraph(f"Someone created a {product} account with this address. Confirm it to activate the account."),
            Button("Confirm your email address", link, show_url=True),
            Paragraph(f"The link works once and expires in {expiry}."),
            Paragraph("If this was not you, you can ignore this message and no account will be activated.", muted=True),
            *_support(settings),
        ],
        tags={"purpose": "verify_email"},
    )


def render_password_reset(settings: IdentitySettings, *, to: str, link: str, expiry: str) -> EmailMessage:
    """Render the password reset message."""
    product = _product(settings)
    return render_branded(
        email_brand(settings),
        to=to,
        subject=f"Reset your {settings.product_name} password".strip(),
        preheader=f"Choose a new password for your {product} account.",
        blocks=[
            Heading("Reset your password"),
            Paragraph(
                f"Someone asked to reset the password on the {product} account for this address. "
                "Choose a new one with the link below."
            ),
            Button("Reset your password", link, show_url=True),
            Paragraph(f"The link works once and expires in {expiry}."),
            Paragraph(
                "If this was not you, you can ignore this message. Your password has not changed, and "
                "nobody can use this link without opening your mailbox.",
                muted=True,
            ),
            *_support(settings),
        ],
        tags={"purpose": "reset_password"},
    )


def render_registration_notice(settings: IdentitySettings, *, to: str, link: str) -> EmailMessage:
    """Render the notice sent to an address somebody tried to register again.

    Carries a reset link rather than a verification link, because the account already exists.
    """
    product = _product(settings)
    return render_branded(
        email_brand(settings),
        to=to,
        subject=f"Someone tried to create a {settings.product_name} account".strip(),
        preheader="Nothing was created and nothing has changed.",
        blocks=[
            Heading("Someone tried to create an account with your address"),
            Paragraph(f"Your address already has a {product} account, so nothing was created and nothing has changed."),
            Paragraph("If it was you, sign in as usual, or reset your password if you have forgotten it."),
            Button("Reset your password", link),
            Paragraph(
                "If it was not you, no action is needed. Nobody can see that this address has an account, "
                "and no account was created.",
                muted=True,
            ),
            *_support(settings),
        ],
        tags={"purpose": "registration_notice"},
    )


def render_password_changed(settings: IdentitySettings, *, to: str, link: str) -> EmailMessage:
    """Render the notice sent after a password is changed or reset.

    A change notification is the one signal a user has that a takeover happened, and the link
    is the reset link, which is the remedy.
    """
    product = _product(settings)
    return render_branded(
        email_brand(settings),
        to=to,
        subject=f"Your {settings.product_name} password was changed".strip(),
        preheader="Every other signed-in session was ended.",
        blocks=[
            Heading("Your password was changed"),
            Paragraph(
                f"The password on your {product} account was just changed, and every other signed-in session was ended."
            ),
            Paragraph("If this was you, there is nothing to do."),
            Paragraph("If it was not you, reset your password immediately and then contact us."),
            Button("Reset your password", link),
            *_support(settings),
        ],
        tags={"purpose": "password_changed"},
    )
