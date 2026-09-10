"""Sending the two emails identity owns: a verification link and a reset link.

Section 2.1 of `docs/identity-standard.md` puts `services/mail.py` beside the other flow
services, and section 5.8 grants the identity function `ses:SendEmail` on the identity and
the configuration set. This module is that service, split in the same two-part shape every
storage class in this package already has: an abstract sender with a real implementation
and an in-memory one.

## The seam, and why it is an ABC rather than only a Protocol

`EmailSender` is an ABC with one method. `SesV2EmailSender` is the deployed implementation
and `RecordingEmailSender` is the one every test uses, and the choice between them is a
constructor argument rather than a patch of `boto3.client`.

`IdentityHooks` is a Protocol because a product implements it and the package must not make
a product inherit from it. This is the opposite direction: the package supplies both
implementations, a product supplies none, and a third implementation is an unusual thing to
write rather than the normal case. An ABC makes the one method obligatory at class
definition rather than at the first send, which is where an unimplemented sender would
otherwise be discovered.

## No templating dependency, deliberately

Two emails, each about fifteen lines. Jinja2 would be a new runtime dependency in the
`identity` extra, a template directory to package, and a second place a product would then
want to override. `string.Template` is in the standard library, and `$name` substitution is
all these bodies need.

The consequence is that **escaping is this module's job**, and it is done at the one place
it can be got right: `_render_html` escapes every substitution value with `html.escape`
before substituting, and the plain text part substitutes raw because there is nothing to
escape into. A product name of `Bob & Co` renders as `Bob &amp; Co` in the HTML part and
as `Bob & Co` in the text part, which is correct in both.

The link itself is **not** escaped as a URL: it is built by this package from a token this
package generated, so it carries base64url characters and nothing else. It is still
`html.escape`d in the HTML part, because `&` in a query string is exactly the character
that would otherwise truncate an `href`.

## Both parts, always

Every message carries a text part and an HTML part. Text alone renders badly in clients
that expect HTML, and HTML alone is the shape spam filters score worst and the shape a
plain text client cannot read at all. Building both costs one extra `Template` and removes
a class of deliverability problem worth more than that.

## The copy

Written to the house style: no em dashes, and the product name comes from settings rather
than being hardcoded, because two products mount this and neither is named in the package.
The link is stated as a URL in the text part rather than hidden behind link text, so a
reader can see where it goes before following it, which is the habit an identity email
should encourage rather than train out.

## What is not here

**No bounce or complaint handling.** The configuration set is a settings field and SES
publishes events to it, but reacting to a bounce is a product's decision about its own user
record and belongs behind a hook it has not needed yet. **No retry.** A `SendEmail` failure
raises `EmailSendFailed`, and each flow decides whether that fails the request: verification
on register does not, a resend does.
"""

from __future__ import annotations

import html
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from string import Template
from typing import TYPE_CHECKING, Any, Final, Protocol

if TYPE_CHECKING:  # pragma: no cover - typing only
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

#: The character set every part is sent as. SES takes the charset per part, and every body
#: this module builds is a Python `str`, so there is exactly one right answer.
CHARSET: Final = "UTF-8"


class EmailSendFailed(Exception):
    """SES refused a message, or the client raised on the way to it.

    A distinct type rather than the underlying `ClientError`, so a flow can decide what a
    send failure means without importing botocore. The flows differ: a verification email
    that fails during registration is logged and the account still exists, while a
    deliberate resend answers the caller.
    """


@dataclass(frozen=True, slots=True)
class EmailMessage:
    """One rendered message, ready for any sender.

    Rendered before a sender is chosen, so the template tests never construct a client and
    the sender tests never render a template. `to` is a single address: identity never
    sends to more than one recipient, and a list would invite a caller to try.
    """

    to: str
    subject: str
    text: str
    html: str
    #: Tags SES attaches to the event stream when a configuration set is configured.
    #: `purpose` is what makes a bounce rate on verification separable from one on reset.
    tags: dict[str, str] = field(default_factory=dict)


class EmailSender(ABC):
    """Send one message. The whole seam.

    One method, because identity sends one message at a time and every batching question
    belongs to a product's own notification path rather than to a verification link.
    """

    @abstractmethod
    def send(self, message: EmailMessage) -> str:
        """Send it and return a provider message id.

        Raises `EmailSendFailed` when the provider refuses. The id is for the log line and
        for correlating with an SES event, and no caller stores it.
        """


class SesV2Client(Protocol):
    """The one SES v2 call this module makes, as a structural type.

    Typed here rather than imported from `boto3-stubs`, for the same reason
    `webbpulse.identity.tokens.KmsClient` is: the `identity` extra deliberately does not
    depend on boto3, so that a product serving a JWKS is not made to install it. A
    `boto3.client("sesv2")` satisfies this, and so does a fake in a test.
    """

    def send_email(self, **kwargs: Any) -> Any: ...


class SesV2EmailSender(EmailSender):
    """`EmailSender` over SES v2 `SendEmail`.

    Takes a client rather than building one, matching `TokenService` and every storage class
    here: the module makes no AWS call at import, and a caller that already has a session
    reuses it.

    **v2 rather than v1.** The v1 `SendEmail` is the older API and its account-level
    resources are the ones AWS documents as legacy. The v2 shape is also the one that takes
    `EmailTags` inline, which is what makes a bounce rate on verification separable from one
    on reset without a second configuration set.

    `ses_configuration_set` is optional in settings and omitted from the call when unset. A
    configuration set that does not exist is a hard failure on every send, so defaulting to
    a name would break a product that had not created one, and passing an empty string is
    not the same as omitting the key.
    """

    def __init__(
        self,
        client: SesV2Client,
        *,
        from_address: str,
        configuration_set: str | None = None,
    ) -> None:
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
        """Build one from the settings fields section 6.1 already specifies for it."""
        return cls(
            client,
            from_address=settings.email_from,
            configuration_set=settings.ses_configuration_set,
        )

    def send(self, message: EmailMessage) -> str:
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
            # Deliberately broad. botocore raises `ClientError` for a refusal, but also
            # `EndpointConnectionError`, `ParamValidationError` and a handful of others, and
            # every one of them means the same thing to a caller: the mail did not go. This
            # module does not depend on botocore, so it cannot name those types anyway.
            raise EmailSendFailed(f"SES refused the message: {exc}") from exc

        message_id = str(response.get("MessageId", "")) if isinstance(response, dict) else ""
        _log.info(
            "Identity email sent.",
            # No recipient address and no link. Section 5.7: an audit line carries the user
            # and the outcome, and an address in a log is the personal data a log should not
            # accumulate for thirty days.
            extra={
                "event": "email.sent",
                "purpose": message.tags.get("purpose", "unknown"),
                "message_id": message_id,
            },
        )
        return message_id


class RecordingEmailSender(EmailSender):
    """An `EmailSender` that keeps every message in a list instead of sending it.

    The test double, and also the right sender for a local run with no SES identity: the
    link is in `sent[-1].text` and a software engineer working on the flow can paste it into
    a browser without a mailbox.

    Deliberately keeps the whole `EmailMessage` rather than a summary. A test that asserts
    the link is in the body, or that the subject names the product, needs the rendered
    thing, and a double that stored only "one email went to this address" would push every
    such test back into rendering the template itself.
    """

    def __init__(self, *, fail: bool = False) -> None:
        self.sent: list[EmailMessage] = []
        #: Set to make every send raise, for testing the paths that tolerate a failure.
        self.fail = fail

    def send(self, message: EmailMessage) -> str:
        if self.fail:
            raise EmailSendFailed("RecordingEmailSender is configured to fail.")
        self.sent.append(message)
        return f"recorded-{len(self.sent)}"

    def last_for(self, address: str) -> EmailMessage | None:
        """The most recent message to one address, or `None`."""
        for message in reversed(self.sent):
            if message.to == address:
                return message
        return None

    def clear(self) -> None:
        self.sent.clear()


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------
#
# `string.Template` rather than an f-string, so the body reads as a document with holes in
# it rather than as an expression. `safe_substitute` is not used anywhere: a missing key
# should raise here, in a test, rather than mail a customer a body containing `$link`.

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

# Section 5.4: registration against a taken address answers 200 and mails the existing
# address instead of telling the form the address is taken. This is that message, and it is
# what makes the non-disclosure honest rather than merely silent: the person who owns the
# address finds out somebody tried.
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
    """The email verification message. Section 2.6 and section 5.4."""
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
    """The password reset message. Section 2.6."""
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
    """The notice section 5.4 sends to an address somebody tried to register again.

    Carries a reset link rather than a verification link, because the account already
    exists and the plausible innocent explanation is a person who forgot they had one.
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
    """The notice sent after a password is changed or reset.

    Not required by the standard, and included because a change notification is the one
    signal a user has that a takeover happened: an attacker who changes a password locks
    the owner out silently otherwise. The link is the reset link, which is the remedy.
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

    The two parts substitute the **same** values through different escaping: the text part
    takes them raw, because plain text has no markup to escape into, and the HTML part takes
    them through `html.escape`. Doing it in one function is what keeps the two from
    drifting, and doing it here rather than in each caller is what keeps a new template from
    forgetting the escape.
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
