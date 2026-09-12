"""Sending the two emails identity owns: a verification link and a reset link.

An abstract sender with an SES v2 implementation and a recording one. Bodies are rendered
with `string.Template`, so escaping the HTML part is this module's own job.
"""

from __future__ import annotations

import html
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from string import Template
from typing import TYPE_CHECKING, Any, Final, Protocol

if TYPE_CHECKING:  # pragma: no cover
    from webbpulse.identity.settings import IdentitySettings

__all__ = [
    "EmailMessage",
    "EmailSendFailed",
    "EmailSender",
    "RecordingEmailSender",
    "SesV2Client",
    "SesV2EmailSender",
    "render_password_changed",
    "render_password_reset",
    "render_registration_notice",
    "render_verification",
]

_log = logging.getLogger(__name__)

CHARSET: Final = "UTF-8"


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
            request["EmailTags"] = [
                {"Name": name, "Value": value} for name, value in sorted(message.tags.items())
            ]

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


_VERIFICATION_TEXT = Template(
    """Confirm your email address

Someone created a $product_name account with this address. Open the link below to
confirm it:

$link

The link works once and expires in $expiry.

If this was not you, you can ignore this message and no account will be activated.

Questions? Reply to $support_email.
"""
)

_VERIFICATION_HTML = Template(
    """<p>Someone created a $product_name account with this address. Confirm it here:</p>
<p><a href="$link">Confirm your email address</a></p>
<p>The link works once and expires in $expiry.</p>
<p>If this was not you, you can ignore this message and no account will be activated.</p>
<p>Questions? Reply to <a href="mailto:$support_email">$support_email</a>.</p>
"""
)

_RESET_TEXT = Template(
    """Reset your password

Someone asked to reset the password on the $product_name account for this address.
Open the link below to choose a new one:

$link

The link works once and expires in $expiry.

If this was not you, you can ignore this message. Your password has not changed, and
nobody can use this link without opening your mailbox.

Questions? Reply to $support_email.
"""
)

_RESET_HTML = Template(
    """<p>Someone asked to reset the password on the $product_name account for this
address. Choose a new one here:</p>
<p><a href="$link">Reset your password</a></p>
<p>The link works once and expires in $expiry.</p>
<p>If this was not you, you can ignore this message. Your password has not changed, and
nobody can use this link without opening your mailbox.</p>
<p>Questions? Reply to <a href="mailto:$support_email">$support_email</a>.</p>
"""
)

_REGISTRATION_NOTICE_TEXT = Template(
    """Someone tried to create an account with your address

Your address already has a $product_name account, so nothing was created and nothing
has changed.

If it was you, sign in as usual, or reset your password if you have forgotten it:

$link

If it was not you, no action is needed. Nobody can see that this address has an
account, and no account was created.

Questions? Reply to $support_email.
"""
)

_REGISTRATION_NOTICE_HTML = Template(
    """<p>Your address already has a $product_name account, so nothing was created and
nothing has changed.</p>
<p>If it was you, sign in as usual, or
<a href="$link">reset your password</a> if you have forgotten it.</p>
<p>If it was not you, no action is needed. Nobody can see that this address has an
account, and no account was created.</p>
<p>Questions? Reply to <a href="mailto:$support_email">$support_email</a>.</p>
"""
)

_PASSWORD_CHANGED_TEXT = Template(
    """Your password was changed

The password on your $product_name account was just changed, and every other signed-in
session was ended.

If this was you, there is nothing to do.

If it was not you, reset your password immediately and then contact us:

$link

Questions? Reply to $support_email.
"""
)

_PASSWORD_CHANGED_HTML = Template(
    """<p>The password on your $product_name account was just changed, and every other
signed-in session was ended.</p>
<p>If this was you, there is nothing to do.</p>
<p>If it was not you, <a href="$link">reset your password</a> immediately and then
contact us.</p>
<p>Questions? Reply to <a href="mailto:$support_email">$support_email</a>.</p>
"""
)

_HTML_DOCUMENT = Template(
    """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>$subject</title></head>
<body style="font-family: system-ui, -apple-system, Segoe UI, sans-serif; \
font-size: 15px; line-height: 1.5; color: #1a1a1a;">
$logo$body<p style="color: #666; font-size: 13px;">$product_name</p>
</body>
</html>
"""
)


def render_verification(
    settings: IdentitySettings, *, to: str, link: str, expiry: str
) -> EmailMessage:
    """Render the email verification message."""
    return _render(
        settings,
        to=to,
        subject=f"Confirm your email address for {settings.product_name}".strip(),
        text_template=_VERIFICATION_TEXT,
        html_template=_VERIFICATION_HTML,
        link=link,
        expiry=expiry,
        purpose="verify_email",
    )


def render_password_reset(
    settings: IdentitySettings, *, to: str, link: str, expiry: str
) -> EmailMessage:
    """Render the password reset message."""
    return _render(
        settings,
        to=to,
        subject=f"Reset your {settings.product_name} password".strip(),
        text_template=_RESET_TEXT,
        html_template=_RESET_HTML,
        link=link,
        expiry=expiry,
        purpose="reset_password",
    )


def render_registration_notice(settings: IdentitySettings, *, to: str, link: str) -> EmailMessage:
    """Render the notice sent to an address somebody tried to register again.

    Carries a reset link rather than a verification link, because the account already exists.
    """
    return _render(
        settings,
        to=to,
        subject=f"Someone tried to create a {settings.product_name} account".strip(),
        text_template=_REGISTRATION_NOTICE_TEXT,
        html_template=_REGISTRATION_NOTICE_HTML,
        link=link,
        expiry="",
        purpose="registration_notice",
    )


def render_password_changed(settings: IdentitySettings, *, to: str, link: str) -> EmailMessage:
    """Render the notice sent after a password is changed or reset.

    A change notification is the one signal a user has that a takeover happened, and the link
    is the reset link, which is the remedy.
    """
    return _render(
        settings,
        to=to,
        subject=f"Your {settings.product_name} password was changed".strip(),
        text_template=_PASSWORD_CHANGED_TEXT,
        html_template=_PASSWORD_CHANGED_HTML,
        link=link,
        expiry="",
        purpose="password_changed",
    )


def _render(
    settings: IdentitySettings,
    *,
    to: str,
    subject: str,
    text_template: Template,
    html_template: Template,
    link: str,
    expiry: str,
    purpose: str,
) -> EmailMessage:
    """Render both parts of one message.

    Both parts substitute the same values, the text part raw and the HTML part through
    `html.escape`, in one place so a new template cannot forget the escape.
    """
    values = {
        "product_name": settings.product_name or "your account",
        "support_email": settings.support_email,
        "link": link,
        "expiry": expiry,
        "subject": subject,
    }
    escaped = {key: html.escape(value, quote=True) for key, value in values.items()}

    logo = ""
    if settings.logo_url:
        logo = (
            f'<p><img src="{html.escape(settings.logo_url, quote=True)}" '
            f'alt="{escaped["product_name"]}" height="40"></p>\n'
        )

    return EmailMessage(
        to=to,
        subject=subject,
        text=text_template.substitute(values),
        html=_HTML_DOCUMENT.substitute(
            subject=escaped["subject"],
            product_name=escaped["product_name"],
            logo=logo,
            body=html_template.substitute(escaped),
        ),
        tags={"purpose": purpose},
    )
