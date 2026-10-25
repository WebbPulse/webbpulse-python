"""Tests for custom headers on `EmailMessage`: validation, the SES request and the fakes."""

from __future__ import annotations

from typing import Any

import pytest

from webbpulse.email_layout import EmailBrand, Paragraph
from webbpulse.identity import (
    RESERVED_HEADER_NAMES,
    EmailMessage,
    RecordingEmailSender,
    SesV2EmailSender,
    render_branded,
)

EMAIL = "someone@example.com"
UNSUBSCRIBE = {
    "List-Unsubscribe": "<https://example.com/unsubscribe?token=abc>",
    "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
}


class CapturingSesClient:
    """Records the request instead of sending it. For asserting the request shape."""

    def __init__(self) -> None:
        """Start with no recorded requests."""
        self.requests: list[dict[str, Any]] = []

    def send_email(self, **kwargs: Any) -> Any:
        """Record the request and return a fixed message id."""
        self.requests.append(kwargs)
        return {"MessageId": "0100000000000000-aaaa-bbbb-cccc-000000"}


def message(headers: dict[str, str] | None = None) -> EmailMessage:
    """A minimal message, with `headers` when given."""
    if headers is None:
        return EmailMessage(to=EMAIL, subject="s", text="t", html="<p>h</p>")
    return EmailMessage(to=EMAIL, subject="s", text="t", html="<p>h</p>", headers=headers)


def test_headers_default_to_empty() -> None:
    """A message built without headers carries an empty mapping."""
    assert message().headers == {}


def test_headers_are_sent_as_simple_content_headers() -> None:
    """Headers become `Content.Simple.Headers` as a Name and Value list, in insertion order."""
    client = CapturingSesClient()
    SesV2EmailSender(client, from_address="a@b.c").send(message(UNSUBSCRIBE))

    assert client.requests[0]["Content"]["Simple"]["Headers"] == [
        {"Name": "List-Unsubscribe", "Value": "<https://example.com/unsubscribe?token=abc>"},
        {"Name": "List-Unsubscribe-Post", "Value": "List-Unsubscribe=One-Click"},
    ]


def test_the_headers_key_is_omitted_when_there_are_none() -> None:
    """`Headers` is absent from the request, not empty, when the message has none."""
    client = CapturingSesClient()
    SesV2EmailSender(client, from_address="a@b.c").send(message())

    assert "Headers" not in client.requests[0]["Content"]["Simple"]


@pytest.mark.parametrize(
    "name",
    [
        "From",
        "to",
        "CC",
        "Bcc",
        "SUBJECT",
        "Reply-To",
        "return-path",
        "Sender",
        "Message-ID",
        "Date",
        "MIME-Version",
        "content-type",
        " From ",
    ],
)
def test_reserved_names_are_refused_case_insensitively(name: str) -> None:
    """Every reserved name raises `ValueError` at construction, whatever its case."""
    with pytest.raises(ValueError, match="reserved"):
        message({name: "x"})


def test_the_reserved_set_covers_the_documented_names() -> None:
    """The exported set lists the twelve names the sender or SES owns, lowercased."""
    assert RESERVED_HEADER_NAMES == {
        "from",
        "to",
        "cc",
        "bcc",
        "subject",
        "reply-to",
        "return-path",
        "sender",
        "message-id",
        "date",
        "mime-version",
        "content-type",
    }


@pytest.mark.parametrize("name", ["X-Bad\r\nBcc", "X-Bad\nName", "X-Bad\rName", "X-Bad:Name"])
def test_names_with_cr_lf_or_a_colon_are_refused(name: str) -> None:
    """A CR, LF or colon in a name raises `ValueError`."""
    with pytest.raises(ValueError, match="name"):
        message({name: "x"})


@pytest.mark.parametrize("value", ["a\r\nBcc: victim@example.com", "a\nb", "a\rb"])
def test_values_with_cr_or_lf_are_refused(value: str) -> None:
    """A CR or LF in a value raises `ValueError`."""
    with pytest.raises(ValueError, match="CR or LF"):
        message({"X-Custom": value})


@pytest.mark.parametrize("name", ["", "   "])
def test_empty_names_are_refused(name: str) -> None:
    """An empty or blank name raises `ValueError`."""
    with pytest.raises(ValueError, match="non-empty"):
        message({name: "x"})


def test_the_recording_sender_keeps_the_headers() -> None:
    """The recording sender records the headers with the rest of the message."""
    sender = RecordingEmailSender()
    sender.send(message(UNSUBSCRIBE))

    assert sender.sent[-1].headers == UNSUBSCRIBE


def test_render_branded_passes_headers_through() -> None:
    """`render_branded` puts its `headers` on the message, and defaults to none."""
    brand = EmailBrand(product_name="Example")
    with_headers = render_branded(brand, to=EMAIL, subject="s", blocks=[Paragraph("hi")], headers=UNSUBSCRIBE)
    without = render_branded(brand, to=EMAIL, subject="s", blocks=[Paragraph("hi")])

    assert with_headers.headers == UNSUBSCRIBE
    assert without.headers == {}


def test_render_branded_validates_headers() -> None:
    """A reserved header passed to `render_branded` raises `ValueError`."""
    with pytest.raises(ValueError, match="reserved"):
        render_branded(
            EmailBrand(product_name="Example"),
            to=EMAIL,
            subject="s",
            blocks=[Paragraph("hi")],
            headers={"Reply-To": "x@example.com"},
        )


def test_headers_are_accepted_by_a_real_sesv2_client_under_moto() -> None:
    """A real sesv2 client under moto accepts a request carrying `Content.Simple.Headers`."""
    moto = pytest.importorskip("moto")
    boto3 = pytest.importorskip("boto3")

    with moto.mock_aws():
        client = boto3.client("sesv2", region_name="us-west-2")
        client.create_email_identity(EmailIdentity="no-reply@example.com")
        message_id = SesV2EmailSender(client, from_address="no-reply@example.com").send(message(UNSUBSCRIBE))

    assert message_id
