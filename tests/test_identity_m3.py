"""Tests for the M3 identity flows: email verification, password reset, and the SES sender.

Covers the link state machine, enumeration-resistant request routes, template escaping, and
the SES v2 sender against both hand fakes and moto.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

from webbpulse.identity import (
    CONFIRMATION_FAILED_MESSAGE,
    RESET_CONFIRM_PATH,
    RESET_LINK_PATH,
    RESET_REQUEST_PATH,
    RESET_REQUESTED_MESSAGE,
    VERIFY_CONFIRM_PATH,
    VERIFY_LINK_PATH,
    VERIFY_REQUEST_PATH,
    AuthenticationRefused,
    BaseIdentityHooks,
    ConfirmationFailed,
    EmailMessage,
    EmailSendFailed,
    IdentitySettings,
    IdentityStores,
    IdentityTokenRecord,
    InMemoryCredentialStore,
    InMemoryIdentityTokenStore,
    InMemoryLoginAttemptStore,
    InMemoryRefreshTokenStore,
    LinkService,
    RecordingEmailSender,
    SesV2EmailSender,
    TokenService,
    build_identity_router,
    describe_expiry,
    hash_token,
    identity_prefix,
    new_token,
    normalise_password,
    render_password_changed,
    render_password_reset,
    render_registration_notice,
    render_verification,
)
from webbpulse.identity.flows import (
    PASSWORD_CREDENTIAL_TYPE,
    IdentityFlows,
    LoginRejected,
)
from webbpulse.identity.storage import CredentialRecord

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Iterator, Mapping

cryptography = pytest.importorskip("cryptography")
fastapi = pytest.importorskip("fastapi")

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

KEY_A = "arn:aws:kms:us-west-2:111122223333:key/aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa"
ISSUER = "https://api.staging.example.com/api/auth"
AUDIENCE = "webbpulse-staging"
FRONTEND = "https://staging.example.com"

PASSWORD = "correct horse battery staple"
NEW_PASSWORD = "an entirely different passphrase"
EMAIL = "person@example.com"
OTHER_EMAIL = "nobody@example.com"
USER_ID = "user-0001"


class FakeKms:
    """A KMS client signing for real with a local private key. M2's fake, unchanged."""

    def __init__(self, keys: dict[str, rsa.RSAPrivateKey]) -> None:
        """Hold the key id to private key mapping the fake signs with."""
        self._keys = keys

    def get_public_key(self, *, KeyId: str) -> dict[str, Any]:
        """Return the DER public key and signing metadata for a key id."""
        der = (
            self._keys[KeyId]
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        return {
            "KeyId": KeyId,
            "PublicKey": der,
            "KeySpec": "RSA_2048",
            "KeyUsage": "SIGN_VERIFY",
            "SigningAlgorithms": ["RSASSA_PKCS1_V1_5_SHA_256"],
        }

    def sign(
        self, *, KeyId: str, Message: bytes, MessageType: str, SigningAlgorithm: str
    ) -> dict[str, Any]:
        """Sign a prehashed message with the local private key for a key id."""
        signature = self._keys[KeyId].sign(
            Message, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
        )
        return {"KeyId": KeyId, "Signature": signature, "SigningAlgorithm": SigningAlgorithm}


@pytest.fixture(autouse=True)
def cheap_bcrypt(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Pin bcrypt to its minimum cost for the whole module, so hashing does not dominate."""
    import webbpulse.security as security

    real_hash = security.hash_password
    real_needs = security.needs_rehash

    def cheap(password: str, *, rounds: int = 4) -> str:
        """Hash a password at the pinned minimum cost."""
        return real_hash(password, rounds=rounds)

    def needs(hashed: str, *, rounds: int = 4) -> bool:
        """Report whether a hash needs rehashing at the pinned minimum cost."""
        return real_needs(hashed, rounds=rounds)

    monkeypatch.setattr(security, "hash_password", cheap)
    monkeypatch.setattr(security, "needs_rehash", needs)
    import webbpulse.identity.passwords as passwords

    monkeypatch.setattr(passwords, "_DUMMY_HASH", None)
    yield


@pytest.fixture(scope="module")
def module_key() -> rsa.RSAPrivateKey:
    """One 2048-bit key for the module. Generation is slow enough to be worth sharing."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def kms(module_key: rsa.RSAPrivateKey) -> FakeKms:
    """A fake KMS client holding the module key under KEY_A."""
    return FakeKms({KEY_A: module_key})


def make_settings(**overrides: Any) -> IdentitySettings:
    """Identity settings for this suite, with email verification off unless overridden."""
    base: dict[str, Any] = {
        "environment": "test",
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "signing_key_arns": [KEY_A],
        "email_verification_required": False,
        "frontend_base_url": FRONTEND,
        "email_from": "no-reply@example.com",
        "product_name": "Example",
        "support_email": "support@example.com",
    }
    base.update(overrides)
    return IdentitySettings(**base)


class FakeHooks(BaseIdentityHooks):
    """A product's policy, in memory. M2's fake plus `mark_email_verified`."""

    def __init__(self, *, refuse: str = "", verify_raises: bool = False) -> None:
        """Start with no users and empty call and verification logs."""
        self.users: dict[str, dict[str, Any]] = {}
        self.by_email: dict[str, str] = {}
        self.refuse = refuse
        self.verify_raises = verify_raises
        self.calls: list[str] = []
        self.verified: list[str] = []
        self._next = 1

    def add(self, email: str, *, user_id: str = "", **attributes: Any) -> dict[str, Any]:
        """Register a user in the fake store and return it."""
        identifier = user_id or f"user-{self._next:04d}"
        self._next += 1
        user = {"id": identifier, "email": email, **attributes}
        self.users[identifier] = user
        self.by_email[email.lower()] = identifier
        return user

    def load_user_by_id(self, user_id: str) -> Mapping[str, Any] | None:
        """Return the user with this id, or None."""
        self.calls.append("load_user_by_id")
        return self.users.get(user_id)

    def load_user_by_email(self, email: str) -> Mapping[str, Any] | None:
        """Return the user with this address, case insensitively, or None."""
        self.calls.append("load_user_by_email")
        identifier = self.by_email.get(email.lower())
        return self.users.get(identifier) if identifier else None

    def may_authenticate(self, user: Mapping[str, Any]) -> None:
        """Refuse the login when the fake is configured to refuse."""
        self.calls.append("may_authenticate")
        if self.refuse:
            raise AuthenticationRefused(self.refuse, error_code="ACCOUNT_DISABLED")

    def claims_for(self, user: Mapping[str, Any]) -> Mapping[str, Any]:
        """Return no extra claims."""
        self.calls.append("claims_for")
        return {}

    def create_user(self, *, email: str, attributes: Mapping[str, Any]) -> Mapping[str, Any]:
        """Create and record a user from an address and attributes."""
        self.calls.append("create_user")
        return self.add(email, **dict(attributes))

    def on_user_created(self, user: Mapping[str, Any], via: str) -> None:
        """Record that the creation hook ran."""
        self.calls.append("on_user_created")

    def mark_email_verified(self, user_id: str) -> None:
        """Record the verified id, or raise when the fake is set to fail."""
        self.calls.append("mark_email_verified")
        if self.verify_raises:
            raise RuntimeError("the product's users table refused the write")
        self.verified.append(user_id)
        user = self.users.get(user_id)
        if user is not None:
            user["email_verified"] = True


@pytest.fixture
def hooks() -> FakeHooks:
    """A fresh `FakeHooks` per test."""
    return FakeHooks()


@pytest.fixture
def stores() -> IdentityStores:
    """In-memory credential, refresh token and identity token stores."""
    return IdentityStores(
        credentials=InMemoryCredentialStore(),
        refresh_tokens=InMemoryRefreshTokenStore(),
        identity_tokens=InMemoryIdentityTokenStore(),
    )


@pytest.fixture
def attempts() -> InMemoryLoginAttemptStore:
    """An in-memory login attempt store."""
    return InMemoryLoginAttemptStore()


@pytest.fixture
def sender() -> RecordingEmailSender:
    """A recording email sender that keeps every message instead of sending it."""
    return RecordingEmailSender()


@pytest.fixture
def settings() -> IdentitySettings:
    """The default identity settings for this suite."""
    return make_settings()


@pytest.fixture
def links(settings: IdentitySettings, stores: IdentityStores) -> LinkService:
    """A `LinkService` over the suite's settings and identity token store."""
    return LinkService(settings, stores.require_identity_tokens())


@pytest.fixture
def flows(
    kms: FakeKms,
    hooks: FakeHooks,
    stores: IdentityStores,
    attempts: InMemoryLoginAttemptStore,
    sender: RecordingEmailSender,
) -> IdentityFlows:
    """Identity flows wired to the fakes, with the recording email sender attached."""
    settings = make_settings()
    return IdentityFlows(
        settings,
        hooks,
        stores,
        TokenService(settings, kms),
        attempts=attempts,
        email_sender=sender,
    )


def seed_account(
    hooks: FakeHooks,
    stores: IdentityStores,
    *,
    email: str = EMAIL,
    password: str = PASSWORD,
    user_id: str = USER_ID,
    **attributes: Any,
) -> dict[str, Any]:
    """An existing account with a stored bcrypt password, as a login would have left it."""
    from webbpulse.security import hash_password

    user = hooks.add(email, user_id=user_id, **attributes)
    stores.require_credentials().put(
        CredentialRecord(
            user_id=user_id,
            credential_type=PASSWORD_CREDENTIAL_TYPE,
            secret=hash_password(normalise_password(password)),
        )
    )
    return user


def token_from(sender: RecordingEmailSender, address: str = EMAIL) -> str:
    """The token out of the most recent link mailed to an address, read from the message body."""
    message = sender.last_for(address)
    assert message is not None, f"no message was sent to {address}"
    from urllib.parse import parse_qs, urlsplit

    for line in message.text.splitlines():
        if line.startswith("http"):
            query = parse_qs(urlsplit(line).query)
            return query["token"][0]
    raise AssertionError("the message body carried no link")


def test_every_message_carries_both_a_text_and_an_html_part(settings: IdentitySettings) -> None:
    """Every rendered message has a non-empty text part, an HTML part, a subject and a purpose tag."""
    messages = [
        render_verification(settings, to=EMAIL, link="https://x/y?token=t", expiry="24 hours"),
        render_password_reset(settings, to=EMAIL, link="https://x/y?token=t", expiry="1 hour"),
        render_registration_notice(settings, to=EMAIL, link="https://x/y"),
        render_password_changed(settings, to=EMAIL, link="https://x/y"),
    ]
    for message in messages:
        assert message.text.strip()
        assert message.html.strip().startswith("<!doctype html>")
        assert message.to == EMAIL
        assert message.subject
        assert message.tags["purpose"]


def test_markup_in_a_setting_is_escaped_in_the_html_part_and_raw_in_the_text() -> None:
    """A product name containing markup is escaped in the HTML part and left raw in the text part."""
    hostile = 'Example<script>alert("x")</script>'
    settings = make_settings(product_name=hostile)
    message = render_verification(settings, to=EMAIL, link="https://x/y", expiry="24 hours")

    assert "<script>" not in message.html
    assert "&lt;script&gt;" in message.html
    assert "<script>" in message.text


def test_a_link_with_query_characters_survives_both_parts(settings: IdentitySettings) -> None:
    """A link with a query string survives raw in the text part and ampersand-escaped in the HTML."""
    link = "https://staging.example.com/verify-email?token=abc&next=%2Fdash"
    message = render_verification(settings, to=EMAIL, link=link, expiry="24 hours")

    assert link in message.text
    assert "token=abc&amp;next=%2Fdash" in message.html
    assert "token=abc&next" not in message.html


def test_the_logo_is_included_only_when_it_is_configured() -> None:
    """The HTML part carries an `img` tag only when `logo_url` is set."""
    with_logo = make_settings(logo_url="https://cdn.example.com/logo.png")
    without = make_settings()

    assert (
        "<img" in render_verification(with_logo, to=EMAIL, link="https://x", expiry="1 hour").html
    )
    assert (
        "<img" not in render_verification(without, to=EMAIL, link="https://x", expiry="1 hour").html
    )


def test_no_message_uses_an_em_dash_or_the_word_developer(settings: IdentitySettings) -> None:
    """No subject, text or HTML part contains an em dash or the word developer."""
    messages = [
        render_verification(settings, to=EMAIL, link="https://x", expiry="24 hours"),
        render_password_reset(settings, to=EMAIL, link="https://x", expiry="1 hour"),
        render_registration_notice(settings, to=EMAIL, link="https://x"),
        render_password_changed(settings, to=EMAIL, link="https://x"),
    ]
    for message in messages:
        for part in (message.subject, message.text, message.html):
            assert "—" not in part
            assert "developer" not in part.lower()


def test_a_template_with_a_missing_value_raises_rather_than_mailing_a_dollar_sign() -> None:
    """`_render` raises `KeyError` on a missing placeholder rather than mailing the raw template."""
    from string import Template

    from webbpulse.identity.email import _render

    with pytest.raises(KeyError):
        _render(
            make_settings(),
            to=EMAIL,
            subject="s",
            text_template=Template("$nonexistent"),
            html_template=Template("<p>x</p>"),
            link="https://x",
            expiry="1 hour",
            purpose="verify_email",
        )


def test_each_message_carries_a_distinct_purpose_tag(settings: IdentitySettings) -> None:
    """The four templates carry four distinct purpose tags."""
    purposes = {
        render_verification(settings, to=EMAIL, link="https://x", expiry="1 hour").tags["purpose"],
        render_password_reset(settings, to=EMAIL, link="https://x", expiry="1 hour").tags[
            "purpose"
        ],
        render_registration_notice(settings, to=EMAIL, link="https://x").tags["purpose"],
        render_password_changed(settings, to=EMAIL, link="https://x").tags["purpose"],
    }
    assert len(purposes) == 4


class RaisingSesClient:
    """A client that refuses every send, the way botocore does for an unverified identity."""

    def send_email(self, **kwargs: Any) -> Any:
        """Raise a plain `RuntimeError` for every send."""
        raise RuntimeError("MessageRejected: Email address is not verified.")


class CapturingSesClient:
    """Records the request instead of sending it. For asserting the request shape."""

    def __init__(self) -> None:
        """Start with no recorded requests."""
        self.requests: list[dict[str, Any]] = []

    def send_email(self, **kwargs: Any) -> Any:
        """Record the request and return a fixed message id."""
        self.requests.append(kwargs)
        return {"MessageId": "0100000000000000-aaaa-bbbb-cccc-000000"}


def test_the_ses_sender_builds_a_simple_content_with_both_parts() -> None:
    """The SES request carries the from address, destination, subject and both body parts as UTF-8."""
    client = CapturingSesClient()
    sender = SesV2EmailSender(client, from_address="no-reply@example.com")
    message = EmailMessage(to=EMAIL, subject="Subject", text="text body", html="<p>html body</p>")

    message_id = sender.send(message)

    assert message_id == "0100000000000000-aaaa-bbbb-cccc-000000"
    request = client.requests[0]
    assert request["FromEmailAddress"] == "no-reply@example.com"
    assert request["Destination"] == {"ToAddresses": [EMAIL]}
    simple = request["Content"]["Simple"]
    assert simple["Subject"]["Data"] == "Subject"
    assert simple["Body"]["Text"]["Data"] == "text body"
    assert simple["Body"]["Html"]["Data"] == "<p>html body</p>"
    assert simple["Subject"]["Charset"] == "UTF-8"


def test_the_configuration_set_key_is_omitted_when_it_is_unset() -> None:
    """`ConfigurationSetName` is absent, not empty, when unset or set to an empty string."""
    client = CapturingSesClient()
    SesV2EmailSender(client, from_address="a@b.c").send(
        EmailMessage(to=EMAIL, subject="s", text="t", html="<p>h</p>")
    )
    assert "ConfigurationSetName" not in client.requests[0]

    client2 = CapturingSesClient()
    SesV2EmailSender(client2, from_address="a@b.c", configuration_set="").send(
        EmailMessage(to=EMAIL, subject="s", text="t", html="<p>h</p>")
    )
    assert "ConfigurationSetName" not in client2.requests[0]


def test_the_configuration_set_is_sent_when_it_is_configured() -> None:
    """`ConfigurationSetName` is sent when the sender is built with a configuration set."""
    client = CapturingSesClient()
    SesV2EmailSender(client, from_address="a@b.c", configuration_set="identity-events").send(
        EmailMessage(to=EMAIL, subject="s", text="t", html="<p>h</p>")
    )
    assert client.requests[0]["ConfigurationSetName"] == "identity-events"


def test_tags_become_email_tags_and_are_omitted_when_there_are_none() -> None:
    """Message tags become `EmailTags`, and the key is omitted when there are none."""
    client = CapturingSesClient()
    sender = SesV2EmailSender(client, from_address="a@b.c")

    sender.send(EmailMessage(to=EMAIL, subject="s", text="t", html="<p>h</p>"))
    assert "EmailTags" not in client.requests[0]

    sender.send(
        EmailMessage(
            to=EMAIL, subject="s", text="t", html="<p>h</p>", tags={"purpose": "verify_email"}
        )
    )
    assert client.requests[1]["EmailTags"] == [{"Name": "purpose", "Value": "verify_email"}]


def test_from_settings_reads_the_two_fields_section_6_1_specifies() -> None:
    """`from_settings` reads `email_from` and `ses_configuration_set` into the request."""
    settings = make_settings(
        email_from="sender@example.com", ses_configuration_set="identity-events"
    )
    client = CapturingSesClient()
    SesV2EmailSender.from_settings(settings, client).send(
        EmailMessage(to=EMAIL, subject="s", text="t", html="<p>h</p>")
    )
    assert client.requests[0]["FromEmailAddress"] == "sender@example.com"
    assert client.requests[0]["ConfigurationSetName"] == "identity-events"


def test_an_empty_from_address_is_refused_at_construction() -> None:
    """An empty from address raises `ValueError` at construction rather than on every send."""
    with pytest.raises(ValueError, match="from_address"):
        SesV2EmailSender(CapturingSesClient(), from_address="")


def test_any_client_exception_becomes_email_send_failed() -> None:
    """Any exception from the client surfaces as `EmailSendFailed`."""
    sender = SesV2EmailSender(RaisingSesClient(), from_address="a@b.c")
    with pytest.raises(EmailSendFailed):
        sender.send(EmailMessage(to=EMAIL, subject="s", text="t", html="<p>h</p>"))


def test_the_ses_sender_works_against_moto() -> None:
    """A real sesv2 client under moto accepts the request shape the sender builds."""
    moto = pytest.importorskip("moto")
    boto3 = pytest.importorskip("boto3")

    with moto.mock_aws():
        client = boto3.client("sesv2", region_name="us-west-2")
        client.create_email_identity(EmailIdentity="no-reply@example.com")
        sender = SesV2EmailSender(client, from_address="no-reply@example.com")
        message_id = sender.send(
            render_verification(
                make_settings(), to=EMAIL, link=f"{FRONTEND}/verify-email?token=x", expiry="1 hour"
            )
        )

    assert message_id


def test_the_recording_sender_records_and_can_be_made_to_fail() -> None:
    """The recording sender tracks sends per address, clears, and raises when built with `fail=True`."""
    sender = RecordingEmailSender()
    assert sender.last_for(EMAIL) is None

    sender.send(EmailMessage(to=EMAIL, subject="first", text="t", html="<p>h</p>"))
    sender.send(EmailMessage(to=OTHER_EMAIL, subject="other", text="t", html="<p>h</p>"))
    sender.send(EmailMessage(to=EMAIL, subject="second", text="t", html="<p>h</p>"))

    last = sender.last_for(EMAIL)
    assert last is not None
    assert last.subject == "second"
    assert len(sender.sent) == 3

    sender.clear()
    assert sender.sent == []

    failing = RecordingEmailSender(fail=True)
    with pytest.raises(EmailSendFailed):
        failing.send(EmailMessage(to=EMAIL, subject="s", text="t", html="<p>h</p>"))


def test_issuing_a_link_stores_only_the_hash(links: LinkService, stores: IdentityStores) -> None:
    """Issuing stores the token hash, never the token itself, against the user and purpose."""
    issued = links.issue(USER_ID, "verify_email")

    store = stores.require_identity_tokens()
    assert store.get(issued.token) is None
    record = store.get(hash_token(issued.token))
    assert record is not None
    assert record.user_id == USER_ID
    assert record.purpose == "verify_email"
    assert issued.token not in record.token_hash


def test_the_two_purposes_get_the_two_ttls_section_4_3_specifies(links: LinkService) -> None:
    """Verification links live 24 hours and reset links 1 hour."""
    assert links.ttl_for("verify_email") == timedelta(hours=24)
    assert links.ttl_for("reset_password") == timedelta(hours=1)


def test_the_url_points_at_the_frontend_with_the_token_in_the_query(links: LinkService) -> None:
    """The issued URL is the frontend link path for the purpose, with the token in the query."""
    issued = links.issue(USER_ID, "reset_password")
    assert issued.url.startswith(f"{FRONTEND}{RESET_LINK_PATH}?token=")
    assert issued.token in issued.url

    verify = links.issue(USER_ID, "verify_email")
    assert verify.url.startswith(f"{FRONTEND}{VERIFY_LINK_PATH}?token=")


def test_the_bare_page_carries_no_token_and_no_empty_query(links: LinkService) -> None:
    """`page_for` returns the bare frontend path with no token and no query string."""
    page = links.page_for("reset_password")
    assert page == f"{FRONTEND}{RESET_LINK_PATH}"
    assert "?" not in page


def test_two_links_for_one_user_are_both_live(links: LinkService) -> None:
    """Issuing a second link of the same purpose does not revoke the first: both confirm."""
    first = links.issue(USER_ID, "reset_password")
    second = links.issue(USER_ID, "reset_password")

    assert links.confirm(first.token, "reset_password").user_id == USER_ID
    assert links.confirm(second.token, "reset_password").user_id == USER_ID


def test_confirming_a_live_link_returns_the_record_and_marks_it_consumed(
    links: LinkService, stores: IdentityStores
) -> None:
    """Confirming a live link returns its record and stamps `consumed_at` on the stored row."""
    issued = links.issue(USER_ID, "verify_email")
    record = links.confirm(issued.token, "verify_email")

    assert record.user_id == USER_ID
    stored = stores.require_identity_tokens().get(hash_token(issued.token))
    assert stored is not None
    assert stored.consumed_at


def test_confirming_an_unknown_token_is_refused(links: LinkService) -> None:
    """An unknown token is refused with reason `unknown`."""
    with pytest.raises(ConfirmationFailed) as caught:
        links.confirm(new_token(), "verify_email")
    assert caught.value.reason == "unknown"


def test_confirming_an_empty_token_is_refused_without_touching_the_store(
    links: LinkService,
) -> None:
    """An empty token is refused with reason `empty` before any store lookup."""
    with pytest.raises(ConfirmationFailed) as caught:
        links.confirm("", "verify_email")
    assert caught.value.reason == "empty"


def test_confirming_an_expired_link_is_refused(links: LinkService) -> None:
    """Expiry is re-checked in code, so a link issued in the past is refused with reason `expired`."""
    past = datetime.now(UTC) - timedelta(hours=48)
    issued = links.issue(USER_ID, "verify_email", now=past)

    with pytest.raises(ConfirmationFailed) as caught:
        links.confirm(issued.token, "verify_email")
    assert caught.value.reason == "expired"


def test_confirming_a_spent_link_a_second_time_is_refused(links: LinkService) -> None:
    """A second confirmation of the same link is refused with reason `already_consumed`."""
    issued = links.issue(USER_ID, "verify_email")
    links.confirm(issued.token, "verify_email")

    with pytest.raises(ConfirmationFailed) as caught:
        links.confirm(issued.token, "verify_email")
    assert caught.value.reason == "already_consumed"


def test_a_verification_link_presented_to_the_reset_flow_is_refused_unspent(
    links: LinkService,
) -> None:
    """A wrong-purpose confirmation is refused before the consume, leaving the link usable."""
    issued = links.issue(USER_ID, "verify_email")

    with pytest.raises(ConfirmationFailed) as caught:
        links.confirm(issued.token, "reset_password")
    assert caught.value.reason == "wrong_purpose"

    assert links.confirm(issued.token, "verify_email").user_id == USER_ID


def test_a_link_consumed_between_the_read_and_the_write_is_refused(
    settings: IdentitySettings, stores: IdentityStores
) -> None:
    """A `consume` that returns None, as a failed conditional write does, is refused as `consumed_concurrently`."""
    store = stores.require_identity_tokens()
    links = LinkService(settings, store)
    issued = links.issue(USER_ID, "reset_password")

    def already_gone(
        token_hash: str, *, consumed_at: str | None = None
    ) -> IdentityTokenRecord | None:
        """Stand in for a conditional write that lost the race by returning None."""
        return None

    store.consume = already_gone  # type: ignore[method-assign]

    with pytest.raises(ConfirmationFailed) as caught:
        links.confirm(issued.token, "reset_password")
    assert caught.value.reason == "consumed_concurrently"


def test_every_refusal_carries_the_same_message_and_code(links: LinkService) -> None:
    """Every refusal reason shares one message, error code and status, whatever went wrong."""
    expired = links.issue(USER_ID, "verify_email", now=datetime.now(UTC) - timedelta(days=2))
    spent = links.issue(USER_ID, "verify_email")
    links.confirm(spent.token, "verify_email")

    refusals = []
    for token in (new_token(), expired.token, spent.token, ""):
        with pytest.raises(ConfirmationFailed) as caught:
            links.confirm(token, "verify_email")
        refusals.append((caught.value.message, caught.value.error_code, caught.value.status_code))

    assert set(refusals) == {(CONFIRMATION_FAILED_MESSAGE, "INVALID_LINK", 400)}


def test_describe_expiry_reads_like_a_sentence() -> None:
    """`describe_expiry` renders hours and minutes with correct singulars."""
    assert describe_expiry(timedelta(hours=24)) == "24 hours"
    assert describe_expiry(timedelta(hours=1)) == "1 hour"
    assert describe_expiry(timedelta(minutes=30)) == "30 minutes"
    assert describe_expiry(timedelta(minutes=1)) == "1 minute"


def test_the_issued_link_expiry_is_readable_as_a_datetime(links: LinkService) -> None:
    """`expires_at_datetime` returns a timezone-aware moment about an hour out for a reset link."""
    issued = links.issue(USER_ID, "reset_password")
    moment = issued.expires_at_datetime()
    assert moment.tzinfo is not None
    assert timedelta(minutes=59) < moment - datetime.now(UTC) <= timedelta(hours=1)


def test_registering_sends_a_verification_link(
    flows: IdentityFlows, sender: RecordingEmailSender
) -> None:
    """Registering mails a verification link at the frontend verify path."""
    flows.register(email=EMAIL, password=PASSWORD)

    message = sender.last_for(EMAIL)
    assert message is not None
    assert message.tags["purpose"] == "verify_email"
    assert f"{FRONTEND}{VERIFY_LINK_PATH}?token=" in message.text


def test_registering_still_creates_the_account_when_the_send_fails(
    kms: FakeKms,
    hooks: FakeHooks,
    stores: IdentityStores,
    attempts: InMemoryLoginAttemptStore,
) -> None:
    """A failing sender does not fail the registration: the account is still created."""
    settings = make_settings()
    failing = RecordingEmailSender(fail=True)
    flows = IdentityFlows(
        settings,
        hooks,
        stores,
        TokenService(settings, kms),
        attempts=attempts,
        email_sender=failing,
    )

    result = flows.register(email=EMAIL, password=PASSWORD)

    assert result is not None
    assert hooks.by_email[EMAIL]


def test_registering_a_taken_address_mails_the_existing_address_a_notice(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """Registering a taken address returns None and mails the owner a registration notice."""
    seed_account(hooks, stores)
    sender.clear()

    assert flows.register(email=EMAIL, password="a completely different password") is None

    message = sender.last_for(EMAIL)
    assert message is not None
    assert message.tags["purpose"] == "registration_notice"


def test_the_registration_notice_carries_no_live_token(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """The registration notice carries the bare reset page, no token, and writes nothing to the token store."""
    seed_account(hooks, stores)
    sender.clear()
    flows.register(email=EMAIL, password="a completely different password")

    message = sender.last_for(EMAIL)
    assert message is not None
    assert "token=" not in message.text
    assert f"{FRONTEND}{RESET_LINK_PATH}" in message.text
    assert stores.require_identity_tokens().get(hash_token(EMAIL)) is None


def test_requesting_verification_sends_a_link(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """`request_verification` mails a verification link and returns nothing."""
    seed_account(hooks, stores)
    sender.clear()

    flows.request_verification(EMAIL)

    message = sender.last_for(EMAIL)
    assert message is not None
    assert message.tags["purpose"] == "verify_email"


def test_requesting_verification_for_an_unknown_address_returns_none_and_sends_nothing(
    flows: IdentityFlows, sender: RecordingEmailSender
) -> None:
    """An unknown address sends no mail."""
    flows.request_verification(OTHER_EMAIL)
    assert sender.sent == []


def test_requesting_verification_for_an_already_verified_address_sends_nothing(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """An already verified address sends no mail."""
    seed_account(hooks, stores, email_verified=True)
    sender.clear()

    flows.request_verification(EMAIL)
    assert sender.sent == []


def test_requesting_verification_for_a_blank_address_does_nothing(
    flows: IdentityFlows, sender: RecordingEmailSender
) -> None:
    """A blank address sends no mail."""
    flows.request_verification("   ")
    assert sender.sent == []


def test_confirming_verification_marks_the_address_verified(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """Confirming a verification link returns the user id and calls `mark_email_verified`."""
    seed_account(hooks, stores)
    sender.clear()
    flows.request_verification(EMAIL)

    user_id = flows.confirm_verification(token_from(sender))

    assert user_id == USER_ID
    assert hooks.verified == [USER_ID]


def test_the_hook_is_called_after_the_link_is_consumed(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """A raising verification hook still leaves the link spent, proving the consume happens first."""
    seed_account(hooks, stores)
    sender.clear()
    flows.request_verification(EMAIL)
    token = token_from(sender)
    hooks.verify_raises = True

    with pytest.raises(RuntimeError):
        flows.confirm_verification(token)

    record = stores.require_identity_tokens().get(hash_token(token))
    assert record is not None
    assert record.consumed_at


def test_a_verification_link_cannot_be_confirmed_twice(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """A second confirmation of the same verification link raises `ConfirmationFailed`."""
    seed_account(hooks, stores)
    sender.clear()
    flows.request_verification(EMAIL)
    token = token_from(sender)

    flows.confirm_verification(token)
    with pytest.raises(ConfirmationFailed):
        flows.confirm_verification(token)


def test_a_verified_address_can_then_sign_in_under_a_product_that_requires_it(
    kms: FakeKms,
    stores: IdentityStores,
    attempts: InMemoryLoginAttemptStore,
    sender: RecordingEmailSender,
) -> None:
    """A product requiring verification refuses login until the link is confirmed, then admits it."""

    class StrictHooks(FakeHooks):
        """Hooks that refuse authentication until `email_verified` is set."""

        def may_authenticate(self, user: Mapping[str, Any]) -> None:
            """Refuse the login unless the user's address is verified."""
            self.calls.append("may_authenticate")
            if not user.get("email_verified"):
                raise AuthenticationRefused(
                    "Confirm your email address first.", error_code="EMAIL_NOT_VERIFIED"
                )

    hooks = StrictHooks()
    settings = make_settings(email_verification_required=True)
    flows = IdentityFlows(
        settings,
        hooks,
        stores,
        TokenService(settings, kms),
        attempts=attempts,
        email_sender=sender,
    )

    with pytest.raises(LoginRejected) as registered:
        flows.register(email=EMAIL, password=PASSWORD)
    assert registered.value.error_code == "EMAIL_VERIFICATION_REQUIRED"

    with pytest.raises(LoginRejected):
        flows.login(email=EMAIL, password=PASSWORD)

    flows.confirm_verification(token_from(sender))

    result = flows.login(email=EMAIL, password=PASSWORD)
    assert result.access_token


def test_requesting_a_reset_sends_a_link(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """`request_password_reset` mails a reset link quoting the one hour expiry."""
    seed_account(hooks, stores)
    sender.clear()

    flows.request_password_reset(EMAIL)

    message = sender.last_for(EMAIL)
    assert message is not None
    assert message.tags["purpose"] == "reset_password"
    assert "1 hour" in message.text


def test_requesting_a_reset_for_an_unknown_address_returns_none_and_sends_nothing(
    flows: IdentityFlows, sender: RecordingEmailSender
) -> None:
    """An unknown address sends no reset mail."""
    flows.request_password_reset(OTHER_EMAIL)
    assert sender.sent == []


def test_an_unverified_account_can_still_reset(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """An unverified account still gets a reset link, so verification is not a lockout."""
    seed_account(hooks, stores, email_verified=False)
    sender.clear()

    flows.request_password_reset(EMAIL)
    assert sender.last_for(EMAIL) is not None


def test_confirming_a_reset_writes_the_new_password_and_revokes_everything(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """A confirmed reset replaces the password and revokes every refresh family, keeping none."""
    seed_account(hooks, stores)
    first = flows.login(email=EMAIL, password=PASSWORD)
    second = flows.login(email=EMAIL, password=PASSWORD)
    families = [first.family_id, second.family_id]
    sender.clear()

    flows.request_password_reset(EMAIL)
    user_id = flows.confirm_password_reset(
        token=token_from(sender), new_password=NEW_PASSWORD, family_ids=families
    )

    assert user_id == USER_ID
    with pytest.raises(LoginRejected):
        flows.login(email=EMAIL, password=PASSWORD)
    assert flows.login(email=EMAIL, password=NEW_PASSWORD).access_token
    for issued in (first, second):
        with pytest.raises(LoginRejected):
            flows.refresh(issued.refresh_token)


def test_a_reset_marks_the_address_verified(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """A completed reset also marks the address verified, since it proves mailbox control."""
    seed_account(hooks, stores)
    login = flows.login(email=EMAIL, password=PASSWORD)
    sender.clear()

    flows.request_password_reset(EMAIL)
    flows.confirm_password_reset(
        token=token_from(sender), new_password=NEW_PASSWORD, family_ids=[login.family_id]
    )

    assert hooks.verified == [USER_ID]


def test_a_reset_succeeds_even_when_marking_verified_raises(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """A raising `mark_email_verified` does not fail the reset: the new password works."""
    seed_account(hooks, stores)
    login = flows.login(email=EMAIL, password=PASSWORD)
    sender.clear()
    flows.request_password_reset(EMAIL)
    hooks.verify_raises = True

    user_id = flows.confirm_password_reset(
        token=token_from(sender), new_password=NEW_PASSWORD, family_ids=[login.family_id]
    )

    assert user_id == USER_ID
    assert flows.login(email=EMAIL, password=NEW_PASSWORD).access_token


def test_a_reset_sends_the_password_changed_notice(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """A completed reset mails a password changed notice carrying no token."""
    seed_account(hooks, stores)
    sender.clear()
    flows.request_password_reset(EMAIL)
    flows.confirm_password_reset(token=token_from(sender), new_password=NEW_PASSWORD, family_ids=[])

    message = sender.last_for(EMAIL)
    assert message is not None
    assert message.tags["purpose"] == "password_changed"
    assert "token=" not in message.text


def test_changing_a_password_also_sends_the_notice(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """`change_password` mails the same password changed notice."""
    seed_account(hooks, stores)
    login = flows.login(email=EMAIL, password=PASSWORD)
    sender.clear()

    flows.change_password(
        user_id=USER_ID,
        current_password=PASSWORD,
        new_password=NEW_PASSWORD,
        keep_family_id=login.family_id,
    )

    message = sender.last_for(EMAIL)
    assert message is not None
    assert message.tags["purpose"] == "password_changed"


def test_the_link_is_spent_even_when_the_new_password_is_refused(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """A password refused by policy still spends the link, and the old password keeps working."""
    from webbpulse.identity import PasswordRejected

    seed_account(hooks, stores)
    sender.clear()
    flows.request_password_reset(EMAIL)
    token = token_from(sender)

    with pytest.raises(PasswordRejected):
        flows.confirm_password_reset(token=token, new_password="short", family_ids=[])

    with pytest.raises(ConfirmationFailed):
        flows.confirm_password_reset(token=token, new_password=NEW_PASSWORD, family_ids=[])
    assert flows.login(email=EMAIL, password=PASSWORD).access_token


def test_a_reset_link_cannot_be_used_for_verification(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """A reset link refused by the verification flow is left unspent and still resets."""
    seed_account(hooks, stores)
    sender.clear()
    flows.request_password_reset(EMAIL)
    token = token_from(sender)

    with pytest.raises(ConfirmationFailed):
        flows.confirm_verification(token)
    flows.confirm_password_reset(token=token, new_password=NEW_PASSWORD, family_ids=[])


@pytest.fixture
def mailless_flows(
    kms: FakeKms,
    hooks: FakeHooks,
    stores: IdentityStores,
    attempts: InMemoryLoginAttemptStore,
) -> IdentityFlows:
    """Identity flows built with no email sender attached."""
    settings = make_settings()
    return IdentityFlows(settings, hooks, stores, TokenService(settings, kms), attempts=attempts)


def test_email_enabled_needs_both_a_sender_and_a_token_store(
    kms: FakeKms, hooks: FakeHooks, attempts: InMemoryLoginAttemptStore
) -> None:
    """`email_enabled` is true only when both an email sender and an identity token store are wired."""
    settings = make_settings()
    tokens = TokenService(settings, kms)

    no_store = IdentityStores(
        credentials=InMemoryCredentialStore(), refresh_tokens=InMemoryRefreshTokenStore()
    )
    assert not IdentityFlows(
        settings, hooks, no_store, tokens, attempts=attempts, email_sender=RecordingEmailSender()
    ).email_enabled

    with_store = IdentityStores(
        credentials=InMemoryCredentialStore(),
        refresh_tokens=InMemoryRefreshTokenStore(),
        identity_tokens=InMemoryIdentityTokenStore(),
    )
    assert not IdentityFlows(settings, hooks, with_store, tokens, attempts=attempts).email_enabled
    assert IdentityFlows(
        settings, hooks, with_store, tokens, attempts=attempts, email_sender=RecordingEmailSender()
    ).email_enabled


def test_registering_without_email_configured_still_works(
    mailless_flows: IdentityFlows, hooks: FakeHooks
) -> None:
    """Registration succeeds with no email configured; only the email routes check first."""
    assert mailless_flows.register(email=EMAIL, password=PASSWORD) is not None
    assert hooks.by_email[EMAIL]


def test_the_email_flows_refuse_with_503_when_no_sender_is_configured(
    mailless_flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """All four email flows raise a 503 `EMAIL_NOT_CONFIGURED` when no sender is wired."""
    seed_account(hooks, stores)

    for call in (
        lambda: mailless_flows.request_verification(EMAIL),
        lambda: mailless_flows.request_password_reset(EMAIL),
        lambda: mailless_flows.confirm_verification("anything"),
        lambda: mailless_flows.confirm_password_reset(token="x", new_password=NEW_PASSWORD),
    ):
        with pytest.raises(LoginRejected) as caught:
            call()
        assert caught.value.status_code == 503
        assert caught.value.error_code == "EMAIL_NOT_CONFIGURED"


@pytest.fixture
def client(
    kms: FakeKms,
    hooks: FakeHooks,
    stores: IdentityStores,
    attempts: InMemoryLoginAttemptStore,
    sender: RecordingEmailSender,
) -> Iterator[TestClient]:
    """A `TestClient` over an app mounting the identity router with the limiter off."""
    from webbpulse.http import register_error_handlers

    settings = make_settings()
    app = FastAPI()
    register_error_handlers(app, error_codes=True)
    app.include_router(
        build_identity_router(
            settings,
            hooks,
            stores,
            kms_client=kms,
            attempts=attempts,
            email_sender=sender,
            limiter_enabled=False,
        )
    )
    with TestClient(app, base_url="https://api.example.com") as test_client:
        yield test_client


def prefix() -> str:
    """The identity router path prefix for the suite's settings."""
    return identity_prefix(make_settings())


def router_paths(**kwargs: Any) -> set[str]:
    """The paths one built router declares, read off the router rather than off an app."""
    router = build_identity_router(make_settings(), limiter_enabled=False, **kwargs)
    return {route.path for route in router.routes}  # type: ignore[attr-defined]


def test_the_four_routes_are_mounted_when_a_sender_and_a_token_store_are_supplied(
    kms: FakeKms, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """All four email routes are declared when a sender and a token store are supplied."""
    mounted = router_paths(hooks=hooks, stores=stores, kms_client=kms, email_sender=sender)
    for suffix in (
        VERIFY_REQUEST_PATH,
        VERIFY_CONFIRM_PATH,
        RESET_REQUEST_PATH,
        RESET_CONFIRM_PATH,
    ):
        assert f"{prefix()}{suffix}" in mounted


def test_the_four_routes_are_absent_without_a_sender(
    kms: FakeKms, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Without a sender the four email routes are absent, while the M2 login route remains."""
    mounted = router_paths(hooks=hooks, stores=stores, kms_client=kms)

    assert f"{prefix()}{VERIFY_REQUEST_PATH}" not in mounted
    assert f"{prefix()}{RESET_CONFIRM_PATH}" not in mounted
    assert f"{prefix()}/login" in mounted


def test_the_four_routes_are_absent_without_a_token_store(
    kms: FakeKms, hooks: FakeHooks, sender: RecordingEmailSender
) -> None:
    """Without an identity token store the email routes are absent, while login remains."""
    stores = IdentityStores(
        credentials=InMemoryCredentialStore(), refresh_tokens=InMemoryRefreshTokenStore()
    )
    mounted = router_paths(hooks=hooks, stores=stores, kms_client=kms, email_sender=sender)

    assert f"{prefix()}{RESET_REQUEST_PATH}" not in mounted
    assert f"{prefix()}/login" in mounted


def test_the_reset_request_route_answers_identically_for_a_known_and_unknown_address(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """The reset request route returns byte-identical responses for a known and an unknown address."""
    seed_account(hooks, stores)

    known = client.post(f"{prefix()}{RESET_REQUEST_PATH}", json={"email": EMAIL})
    unknown = client.post(f"{prefix()}{RESET_REQUEST_PATH}", json={"email": OTHER_EMAIL})

    assert known.status_code == unknown.status_code == 200
    assert known.content == unknown.content
    assert known.json()["detail"] == RESET_REQUESTED_MESSAGE


def test_the_verification_request_route_answers_identically_in_all_three_cases(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Unknown, already verified, and freshly sent are one response from outside."""
    seed_account(hooks, stores)
    hooks.add("verified@example.com", user_id="user-9999", email_verified=True)

    responses = [
        client.post(f"{prefix()}{VERIFY_REQUEST_PATH}", json={"email": EMAIL}),
        client.post(f"{prefix()}{VERIFY_REQUEST_PATH}", json={"email": OTHER_EMAIL}),
        client.post(f"{prefix()}{VERIFY_REQUEST_PATH}", json={"email": "verified@example.com"}),
    ]

    assert {response.status_code for response in responses} == {200}
    assert len({response.content for response in responses}) == 1


def test_the_verification_confirm_route_returns_the_user_id(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """The verification confirm route returns the user id and marks the address verified."""
    seed_account(hooks, stores)
    sender.clear()
    client.post(f"{prefix()}{VERIFY_REQUEST_PATH}", json={"email": EMAIL})

    response = client.post(f"{prefix()}{VERIFY_CONFIRM_PATH}", json={"token": token_from(sender)})

    assert response.status_code == 200
    assert response.json() == {"verified": True, "user_id": USER_ID}
    assert hooks.verified == [USER_ID]


def test_a_bad_token_is_a_400_in_the_shared_error_envelope(client: TestClient) -> None:
    """A bad token is a 400 carrying `INVALID_LINK` in the shared error envelope."""
    response = client.post(f"{prefix()}{VERIFY_CONFIRM_PATH}", json={"token": new_token()})

    assert response.status_code == 400
    body = response.json()
    assert body["success"] is False
    assert body["status"] == 400
    assert body["error_code"] == "INVALID_LINK"
    assert body["message"] == CONFIRMATION_FAILED_MESSAGE


def test_every_kind_of_bad_token_produces_the_same_body(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """Unknown, spent and wrong-purpose are indistinguishable to the caller."""
    seed_account(hooks, stores)
    sender.clear()
    client.post(f"{prefix()}{VERIFY_REQUEST_PATH}", json={"email": EMAIL})
    spent = token_from(sender)
    client.post(f"{prefix()}{VERIFY_CONFIRM_PATH}", json={"token": spent})
    client.post(f"{prefix()}{RESET_REQUEST_PATH}", json={"email": EMAIL})
    wrong_purpose = token_from(sender)

    bodies = set()
    for token in (new_token(), spent, wrong_purpose, ""):
        response = client.post(f"{prefix()}{VERIFY_CONFIRM_PATH}", json={"token": token})
        assert response.status_code == 400
        bodies.add(response.json()["message"])

    assert bodies == {CONFIRMATION_FAILED_MESSAGE}


def test_the_reset_confirm_route_clears_the_refresh_cookie(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """The reset confirm route clears the refresh cookie and the new password then logs in."""
    seed_account(hooks, stores)
    login = client.post(f"{prefix()}/login", json={"email": EMAIL, "password": PASSWORD})
    assert login.status_code == 200
    sender.clear()

    client.post(f"{prefix()}{RESET_REQUEST_PATH}", json={"email": EMAIL})
    response = client.post(
        f"{prefix()}{RESET_CONFIRM_PATH}",
        json={
            "token": token_from(sender),
            "new_password": NEW_PASSWORD,
            "family_ids": [],
        },
    )

    assert response.status_code == 200
    assert response.json() == {"reset": True}
    assert "wp_refresh=" in response.headers.get("set-cookie", "")
    assert (
        client.post(
            f"{prefix()}/login", json={"email": EMAIL, "password": NEW_PASSWORD}
        ).status_code
        == 200
    )


def test_a_reset_with_a_refused_password_is_a_422(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """A reset whose new password fails policy is a 422 carrying an error code."""
    seed_account(hooks, stores)
    sender.clear()
    client.post(f"{prefix()}{RESET_REQUEST_PATH}", json={"email": EMAIL})

    response = client.post(
        f"{prefix()}{RESET_CONFIRM_PATH}",
        json={"token": token_from(sender), "new_password": "short", "family_ids": []},
    )

    assert response.status_code == 422
    assert response.json()["error_code"]


def test_a_request_with_no_email_field_is_still_a_200(client: TestClient) -> None:
    """A request body with no email field still answers 200, so validation is not an oracle."""
    response = client.post(f"{prefix()}{RESET_REQUEST_PATH}", json={})
    assert response.status_code == 200


def test_the_rate_limits_match_section_5_1() -> None:
    """The reset and verification rate limit constants match the values the standard fixes."""
    from webbpulse.identity import (
        RESET_EMAIL_LIMIT,
        RESET_IP_LIMIT,
        VERIFY_EMAIL_LIMIT,
        VERIFY_IP_LIMIT,
    )

    assert RESET_EMAIL_LIMIT == (3, 3600)
    assert RESET_IP_LIMIT == (10, 3600)
    assert VERIFY_EMAIL_LIMIT == (3, 3600)
    assert VERIFY_IP_LIMIT == (10, 3600)
