"""Tests for the M3 identity flows: email verification, password reset, and the SES sender.

Section 9.4 of `docs/identity-standard.md` sets the strategy. Three of its requirements do
most of the shaping here, and they are different requirements from the ones that shaped the
M2 suite:

- **The link state machine gets a test per state.** Unknown, expired, already consumed,
  wrong purpose, consumed concurrently, and the happy path. Six states, six tests, named
  after the states, because the failure a loose test misses is two states collapsing into
  one and a spent link quietly becoming reusable.
- **Enumeration resistance is tested as an equality.** Both request routes are compared
  against each other for an address that exists and one that does not, byte for byte
  including headers, rather than each being checked against a literal. A test asserting
  that both say `{"sent": true}` still passes when one of them also sets a header the other
  does not.
- **The escaping is tested with a value that would break out.** A product name containing
  markup is rendered into both parts, and the assertion is that the HTML part contains the
  escaped form and not the raw one, while the text part contains the raw form. Testing that
  the HTML "looks right" with a benign value tests nothing.

The SES sender is tested against **moto**, unlike M1's KMS work. moto 5.x implements
`sesv2:SendEmail` faithfully enough to assert the request shape, which M1 decision 8 found
was not true of KMS asymmetric signing. Where moto's behaviour is not the point, the
recording sender stands in, and one test uses a raising fake to prove the failure wrapping.

The KMS fake is M2's, redefined here rather than imported: `tests/` is not a package.
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

if TYPE_CHECKING:  # pragma: no cover - typing only
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
    """A KMS client signing for real with a local private key. M2's fake, unchanged.

    Redefined rather than imported because `tests/` is not a package, and cross-importing
    between test modules couples two suites that should change independently.
    """

    def __init__(self, keys: dict[str, rsa.RSAPrivateKey]) -> None:
        self._keys = keys

    def get_public_key(self, *, KeyId: str) -> dict[str, Any]:
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
        signature = self._keys[KeyId].sign(
            Message, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
        )
        return {"KeyId": KeyId, "Signature": signature, "SigningAlgorithm": SigningAlgorithm}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def cheap_bcrypt(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Pin bcrypt to its minimum cost for the whole module. M2's fixture, unchanged.

    Patching `security.DEFAULT_ROUNDS` alone does nothing: `hash_password`'s default binds
    at definition time. Wrapping the function is the only thing that works.
    """
    import webbpulse.security as security

    real_hash = security.hash_password
    real_needs = security.needs_rehash

    def cheap(password: str, *, rounds: int = 4) -> str:
        return real_hash(password, rounds=rounds)

    def needs(hashed: str, *, rounds: int = 4) -> bool:
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
    return FakeKms({KEY_A: module_key})


def make_settings(**overrides: Any) -> IdentitySettings:
    base: dict[str, Any] = {
        "environment": "test",
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "signing_key_arns": [KEY_A],
        # Off by default here for the same reason M2 turns it off: most tests in this file
        # want a session out of `register`. The tests that are about the refusal turn it on.
        "email_verification_required": False,
        "frontend_base_url": FRONTEND,
        "email_from": "no-reply@example.com",
        "product_name": "Example",
        "support_email": "support@example.com",
    }
    base.update(overrides)
    return IdentitySettings(**base)


class FakeHooks(BaseIdentityHooks):
    """A product's policy, in memory. M2's fake plus `mark_email_verified`.

    `verified` records every id the flow marked, which is what makes the ordering assertion
    in the confirmation tests possible: the hook must be called after the link is consumed,
    and a mock would let a test pass while the order was wrong.
    """

    def __init__(self, *, refuse: str = "", verify_raises: bool = False) -> None:
        self.users: dict[str, dict[str, Any]] = {}
        self.by_email: dict[str, str] = {}
        self.refuse = refuse
        self.verify_raises = verify_raises
        self.calls: list[str] = []
        self.verified: list[str] = []
        self._next = 1

    def add(self, email: str, *, user_id: str = "", **attributes: Any) -> dict[str, Any]:
        identifier = user_id or f"user-{self._next:04d}"
        self._next += 1
        user = {"id": identifier, "email": email, **attributes}
        self.users[identifier] = user
        self.by_email[email.lower()] = identifier
        return user

    def load_user_by_id(self, user_id: str) -> Mapping[str, Any] | None:
        self.calls.append("load_user_by_id")
        return self.users.get(user_id)

    def load_user_by_email(self, email: str) -> Mapping[str, Any] | None:
        self.calls.append("load_user_by_email")
        identifier = self.by_email.get(email.lower())
        return self.users.get(identifier) if identifier else None

    def may_authenticate(self, user: Mapping[str, Any]) -> None:
        self.calls.append("may_authenticate")
        if self.refuse:
            raise AuthenticationRefused(self.refuse, error_code="ACCOUNT_DISABLED")

    def claims_for(self, user: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls.append("claims_for")
        return {}

    def create_user(self, *, email: str, attributes: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls.append("create_user")
        return self.add(email, **dict(attributes))

    def on_user_created(self, user: Mapping[str, Any], via: str) -> None:
        self.calls.append("on_user_created")

    def mark_email_verified(self, user_id: str) -> None:
        self.calls.append("mark_email_verified")
        if self.verify_raises:
            raise RuntimeError("the product's users table refused the write")
        self.verified.append(user_id)
        user = self.users.get(user_id)
        if user is not None:
            user["email_verified"] = True


@pytest.fixture
def hooks() -> FakeHooks:
    return FakeHooks()


@pytest.fixture
def stores() -> IdentityStores:
    return IdentityStores(
        credentials=InMemoryCredentialStore(),
        refresh_tokens=InMemoryRefreshTokenStore(),
        identity_tokens=InMemoryIdentityTokenStore(),
    )


@pytest.fixture
def attempts() -> InMemoryLoginAttemptStore:
    return InMemoryLoginAttemptStore()


@pytest.fixture
def sender() -> RecordingEmailSender:
    return RecordingEmailSender()


@pytest.fixture
def settings() -> IdentitySettings:
    return make_settings()


@pytest.fixture
def links(settings: IdentitySettings, stores: IdentityStores) -> LinkService:
    return LinkService(settings, stores.require_identity_tokens())


@pytest.fixture
def flows(
    kms: FakeKms,
    hooks: FakeHooks,
    stores: IdentityStores,
    attempts: InMemoryLoginAttemptStore,
    sender: RecordingEmailSender,
) -> IdentityFlows:
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
    """The token out of the most recent link mailed to an address.

    Read out of the email rather than returned by the flow on purpose. The flow methods
    return `None` precisely so a caller cannot get at the token, and a test that reached
    around that would be testing a path no route can take.
    """
    message = sender.last_for(address)
    assert message is not None, f"no message was sent to {address}"
    from urllib.parse import parse_qs, urlsplit

    for line in message.text.splitlines():
        if line.startswith("http"):
            query = parse_qs(urlsplit(line).query)
            return query["token"][0]
    raise AssertionError("the message body carried no link")


# ---------------------------------------------------------------------------
# Templates: escaping, both parts, and the copy rules
# ---------------------------------------------------------------------------


def test_every_message_carries_both_a_text_and_an_html_part(settings: IdentitySettings) -> None:
    """A text-only message looks like spam and an HTML-only one is unreadable in mutt."""
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
    """The escaping is the point, so it is tested with a value that would break out.

    A product name is operator-supplied rather than attacker-supplied, so this is defence in
    depth rather than a live hole. It is worth having because the templates are the one
    place in the package that concatenates configuration into markup, and the next value to
    go through `_render` may not be operator-supplied.
    """
    hostile = 'Example<script>alert("x")</script>'
    settings = make_settings(product_name=hostile)
    message = render_verification(settings, to=EMAIL, link="https://x/y", expiry="24 hours")

    assert "<script>" not in message.html
    assert "&lt;script&gt;" in message.html
    # Plain text has no markup to escape into, so the raw value belongs there.
    assert "<script>" in message.text


def test_a_link_with_query_characters_survives_both_parts(settings: IdentitySettings) -> None:
    """`?token=` is an ampersand away from being mangled, and the token is the credential."""
    link = "https://staging.example.com/verify-email?token=abc&next=%2Fdash"
    message = render_verification(settings, to=EMAIL, link=link, expiry="24 hours")

    assert link in message.text
    assert "token=abc&amp;next=%2Fdash" in message.html
    assert "token=abc&next" not in message.html


def test_the_logo_is_included_only_when_it_is_configured() -> None:
    with_logo = make_settings(logo_url="https://cdn.example.com/logo.png")
    without = make_settings()

    assert (
        "<img" in render_verification(with_logo, to=EMAIL, link="https://x", expiry="1 hour").html
    )
    assert (
        "<img" not in render_verification(without, to=EMAIL, link="https://x", expiry="1 hour").html
    )


def test_no_message_uses_an_em_dash_or_the_word_developer(settings: IdentitySettings) -> None:
    """The house copy rules, asserted rather than remembered.

    Cheap to check and easy to reintroduce: the next person to add a template writes the
    dash without thinking about it, and nothing else in the suite would notice.
    """
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
    """`substitute`, not `safe_substitute`. The failure belongs in a test, not a mailbox."""
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
    """The tag is what makes a bounce rate on reset separable from one on verification."""
    purposes = {
        render_verification(settings, to=EMAIL, link="https://x", expiry="1 hour").tags["purpose"],
        render_password_reset(settings, to=EMAIL, link="https://x", expiry="1 hour").tags[
            "purpose"
        ],
        render_registration_notice(settings, to=EMAIL, link="https://x").tags["purpose"],
        render_password_changed(settings, to=EMAIL, link="https://x").tags["purpose"],
    }
    assert len(purposes) == 4


# ---------------------------------------------------------------------------
# The SES v2 sender
# ---------------------------------------------------------------------------


class RaisingSesClient:
    """A client that refuses every send, the way botocore does for an unverified identity.

    Raises a plain `RuntimeError` rather than a `ClientError` on purpose: the sender catches
    `Exception` because it does not depend on botocore, and a test that raised `ClientError`
    would not prove that.
    """

    def send_email(self, **kwargs: Any) -> Any:
        raise RuntimeError("MessageRejected: Email address is not verified.")


class CapturingSesClient:
    """Records the request instead of sending it. For asserting the request shape."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def send_email(self, **kwargs: Any) -> Any:
        self.requests.append(kwargs)
        return {"MessageId": "0100000000000000-aaaa-bbbb-cccc-000000"}


def test_the_ses_sender_builds_a_simple_content_with_both_parts() -> None:
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
    """Omitted, not empty. SES rejects a send naming a configuration set that does not exist,
    and an empty string is a name that does not exist rather than an absence."""
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
    client = CapturingSesClient()
    SesV2EmailSender(client, from_address="a@b.c", configuration_set="identity-events").send(
        EmailMessage(to=EMAIL, subject="s", text="t", html="<p>h</p>")
    )
    assert client.requests[0]["ConfigurationSetName"] == "identity-events"


def test_tags_become_email_tags_and_are_omitted_when_there_are_none() -> None:
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
    """SES would refuse it on every send. Failing at construction fails at deploy instead."""
    with pytest.raises(ValueError, match="from_address"):
        SesV2EmailSender(CapturingSesClient(), from_address="")


def test_any_client_exception_becomes_email_send_failed() -> None:
    """One type for the caller, because every underlying failure means the same thing."""
    sender = SesV2EmailSender(RaisingSesClient(), from_address="a@b.c")
    with pytest.raises(EmailSendFailed):
        sender.send(EmailMessage(to=EMAIL, subject="s", text="t", html="<p>h</p>"))


def test_the_ses_sender_works_against_moto() -> None:
    """The one test that exercises a real SES v2 implementation rather than a hand fake.

    moto 5.x implements `sesv2:SendEmail`, which M1 decision 8 found was **not** true of KMS
    asymmetric signing. The hand fakes above assert the request shape; this asserts that a
    real client with a real serialiser accepts that shape at all, which is the part a hand
    fake cannot tell us.
    """
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


# ---------------------------------------------------------------------------
# The link primitive: issue, and the confirmation state machine
# ---------------------------------------------------------------------------


def test_issuing_a_link_stores_only_the_hash(links: LinkService, stores: IdentityStores) -> None:
    """The token in the email is never at rest. A database dump must not be a set of links."""
    issued = links.issue(USER_ID, "verify_email")

    store = stores.require_identity_tokens()
    assert store.get(issued.token) is None
    record = store.get(hash_token(issued.token))
    assert record is not None
    assert record.user_id == USER_ID
    assert record.purpose == "verify_email"
    assert issued.token not in record.token_hash


def test_the_two_purposes_get_the_two_ttls_section_4_3_specifies(links: LinkService) -> None:
    assert links.ttl_for("verify_email") == timedelta(hours=24)
    assert links.ttl_for("reset_password") == timedelta(hours=1)


def test_the_url_points_at_the_frontend_with_the_token_in_the_query(links: LinkService) -> None:
    issued = links.issue(USER_ID, "reset_password")
    assert issued.url.startswith(f"{FRONTEND}{RESET_LINK_PATH}?token=")
    assert issued.token in issued.url

    verify = links.issue(USER_ID, "verify_email")
    assert verify.url.startswith(f"{FRONTEND}{VERIFY_LINK_PATH}?token=")


def test_the_bare_page_carries_no_token_and_no_empty_query(links: LinkService) -> None:
    """A notification email must not carry a live credential, which is what `page_for` is for."""
    page = links.page_for("reset_password")
    assert page == f"{FRONTEND}{RESET_LINK_PATH}"
    assert "?" not in page


def test_two_links_for_one_user_are_both_live(links: LinkService) -> None:
    """Issuing does not revoke the outstanding link of the same purpose. See the M3 decisions.

    `identity-tokens` carries no user index, so revoking would cost a scan or a write on the
    click path to serve the issue path. What it would close is a link the user asked for,
    which expires on its own inside the hour.
    """
    first = links.issue(USER_ID, "reset_password")
    second = links.issue(USER_ID, "reset_password")

    assert links.confirm(first.token, "reset_password").user_id == USER_ID
    assert links.confirm(second.token, "reset_password").user_id == USER_ID


def test_confirming_a_live_link_returns_the_record_and_marks_it_consumed(
    links: LinkService, stores: IdentityStores
) -> None:
    issued = links.issue(USER_ID, "verify_email")
    record = links.confirm(issued.token, "verify_email")

    assert record.user_id == USER_ID
    stored = stores.require_identity_tokens().get(hash_token(issued.token))
    assert stored is not None
    assert stored.consumed_at


def test_confirming_an_unknown_token_is_refused(links: LinkService) -> None:
    with pytest.raises(ConfirmationFailed) as caught:
        links.confirm(new_token(), "verify_email")
    assert caught.value.reason == "unknown"


def test_confirming_an_empty_token_is_refused_without_touching_the_store(
    links: LinkService,
) -> None:
    """An empty string hashes to a real value, and a store lookup for it is a wasted read."""
    with pytest.raises(ConfirmationFailed) as caught:
        links.confirm("", "verify_email")
    assert caught.value.reason == "empty"


def test_confirming_an_expired_link_is_refused(links: LinkService) -> None:
    """Expiry is re-checked in code. The TTL attribute is storage reclamation, never access
    control: DynamoDB deletes an expired item within days, not seconds."""
    past = datetime.now(UTC) - timedelta(hours=48)
    issued = links.issue(USER_ID, "verify_email", now=past)

    with pytest.raises(ConfirmationFailed) as caught:
        links.confirm(issued.token, "verify_email")
    assert caught.value.reason == "expired"


def test_confirming_a_spent_link_a_second_time_is_refused(links: LinkService) -> None:
    issued = links.issue(USER_ID, "verify_email")
    links.confirm(issued.token, "verify_email")

    with pytest.raises(ConfirmationFailed) as caught:
        links.confirm(issued.token, "verify_email")
    assert caught.value.reason == "already_consumed"


def test_a_verification_link_presented_to_the_reset_flow_is_refused_unspent(
    links: LinkService,
) -> None:
    """The purpose check happens **before** the consume, deliberately.

    A user who pastes their verification link into the reset page has done nothing wrong,
    and burning their only link for it would leave them with neither flow available. The
    check is still a real control: the record's purpose is what is compared, not the
    caller's claim about it.
    """
    issued = links.issue(USER_ID, "verify_email")

    with pytest.raises(ConfirmationFailed) as caught:
        links.confirm(issued.token, "reset_password")
    assert caught.value.reason == "wrong_purpose"

    # Still live for the flow it was issued for.
    assert links.confirm(issued.token, "verify_email").user_id == USER_ID


def test_a_link_consumed_between_the_read_and_the_write_is_refused(
    settings: IdentitySettings, stores: IdentityStores
) -> None:
    """The consume is a conditional write, so two racing clicks cannot both win.

    Simulated by a store whose `consume` returns `None` the way a failed condition does. The
    in-memory store cannot be raced from one thread, and the property under test is what the
    service does with the `None`, not how DynamoDB produces it.
    """
    store = stores.require_identity_tokens()
    links = LinkService(settings, store)
    issued = links.issue(USER_ID, "reset_password")

    def already_gone(
        token_hash: str, *, consumed_at: str | None = None
    ) -> IdentityTokenRecord | None:
        return None

    store.consume = already_gone  # type: ignore[method-assign]

    with pytest.raises(ConfirmationFailed) as caught:
        links.confirm(issued.token, "reset_password")
    assert caught.value.reason == "consumed_concurrently"


def test_every_refusal_carries_the_same_message_and_code(links: LinkService) -> None:
    """The reason is for the log. The caller gets one sentence whatever went wrong.

    Telling a caller who guessed a value that it was "already used" confirms the guess found
    a real token, which is a worse disclosure than the unhelpfulness costs.
    """
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
    assert describe_expiry(timedelta(hours=24)) == "24 hours"
    assert describe_expiry(timedelta(hours=1)) == "1 hour"
    assert describe_expiry(timedelta(minutes=30)) == "30 minutes"
    assert describe_expiry(timedelta(minutes=1)) == "1 minute"


def test_the_issued_link_expiry_is_readable_as_a_datetime(links: LinkService) -> None:
    issued = links.issue(USER_ID, "reset_password")
    moment = issued.expires_at_datetime()
    assert moment.tzinfo is not None
    assert timedelta(minutes=59) < moment - datetime.now(UTC) <= timedelta(hours=1)


# ---------------------------------------------------------------------------
# Verification flow
# ---------------------------------------------------------------------------


def test_registering_sends_a_verification_link(
    flows: IdentityFlows, sender: RecordingEmailSender
) -> None:
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
    """Best effort on the register path, and deliberately so.

    Failing the registration would leave a real account behind a 500 and a user who cannot
    register again, because the address is now taken. The resend route is the remedy.
    """
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
    """Section 5.4: 200 for the form, and the owner of the address finds out."""
    seed_account(hooks, stores)
    sender.clear()

    assert flows.register(email=EMAIL, password="a completely different password") is None

    message = sender.last_for(EMAIL)
    assert message is not None
    assert message.tags["purpose"] == "registration_notice"


def test_the_registration_notice_carries_no_live_token(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """A notice is sent to an address somebody else just typed into a form.

    Putting a live reset link in it would mean anyone who can guess an address can cause a
    working credential to be mailed, which is the reset flow without the rate limit on it.
    """
    seed_account(hooks, stores)
    sender.clear()
    flows.register(email=EMAIL, password="a completely different password")

    message = sender.last_for(EMAIL)
    assert message is not None
    assert "token=" not in message.text
    assert f"{FRONTEND}{RESET_LINK_PATH}" in message.text
    # And nothing was written to the token store.
    assert stores.require_identity_tokens().get(hash_token(EMAIL)) is None


def test_requesting_verification_sends_a_link(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    seed_account(hooks, stores)
    sender.clear()

    # No return value at all, by signature: a router cannot branch on the outcome.
    flows.request_verification(EMAIL)

    message = sender.last_for(EMAIL)
    assert message is not None
    assert message.tags["purpose"] == "verify_email"


def test_requesting_verification_for_an_unknown_address_returns_none_and_sends_nothing(
    flows: IdentityFlows, sender: RecordingEmailSender
) -> None:
    flows.request_verification(OTHER_EMAIL)
    assert sender.sent == []


def test_requesting_verification_for_an_already_verified_address_sends_nothing(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """A verification link is a credential, and one for an account that no longer needs it
    widens the window in which a mailbox compromise is an account compromise for no gain."""
    seed_account(hooks, stores, email_verified=True)
    sender.clear()

    flows.request_verification(EMAIL)
    assert sender.sent == []


def test_requesting_verification_for_a_blank_address_does_nothing(
    flows: IdentityFlows, sender: RecordingEmailSender
) -> None:
    flows.request_verification("   ")
    assert sender.sent == []


def test_confirming_verification_marks_the_address_verified(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    seed_account(hooks, stores)
    sender.clear()
    flows.request_verification(EMAIL)

    user_id = flows.confirm_verification(token_from(sender))

    assert user_id == USER_ID
    assert hooks.verified == [USER_ID]


def test_the_hook_is_called_after_the_link_is_consumed(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """A hook that raises leaves the link spent, which is the documented price of ordering it
    this way. The alternative lets a link be spent twice by racing a slow hook."""
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
    """The end to end property the whole milestone exists for.

    A product that requires verification refuses the login until the link is clicked, and
    admits it afterwards. Asserted with a hooks class that actually reads `email_verified`,
    because that is the seam `mark_email_verified` writes through.
    """

    class StrictHooks(FakeHooks):
        def may_authenticate(self, user: Mapping[str, Any]) -> None:
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


# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------


def test_requesting_a_reset_sends_a_link(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
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
    flows.request_password_reset(OTHER_EMAIL)
    assert sender.sent == []


def test_an_unverified_account_can_still_reset(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """Holding the reset back until verification would need the verification link the user
    also cannot get, which is a lockout with no way out of it."""
    seed_account(hooks, stores, email_verified=False)
    sender.clear()

    flows.request_password_reset(EMAIL)
    assert sender.last_for(EMAIL) is not None


def test_confirming_a_reset_writes_the_new_password_and_revokes_everything(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """Section 2.6: a reset revokes every refresh family, with nothing kept.

    Nothing kept, unlike `change_password`, because the person resetting may not be signed in
    at all and no session is known to be the owner's rather than the attacker's.
    """
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
    # The old password is gone and the new one works.
    with pytest.raises(LoginRejected):
        flows.login(email=EMAIL, password=PASSWORD)
    assert flows.login(email=EMAIL, password=NEW_PASSWORD).access_token
    # Both pre-reset sessions are dead.
    for issued in (first, second):
        with pytest.raises(LoginRejected):
            flows.refresh(issued.refresh_token)


def test_a_reset_marks_the_address_verified(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """A reset proves control of the mailbox, which is what a verification link proves.

    Without this a user who never confirmed their address resets the password they were told
    to reset and is then refused by `may_authenticate` anyway.
    """
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
    """The password is already written and every family is already revoked by then.

    Failing here would tell the user their reset did not work when it did, and send them
    back to a reset flow whose old password no longer exists.
    """
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
    """The one signal a user has that a takeover happened. An attacker who changes a password
    locks the owner out silently otherwise."""
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
    """Consume before the policy check, deliberately.

    Checking first would let a caller with a valid link probe the policy without spending it,
    and would let a user who fails the policy twice still hold a live link. The price is that
    a rejected password costs a new link, which is the cheaper of the two.
    """
    from webbpulse.identity import PasswordRejected

    seed_account(hooks, stores)
    sender.clear()
    flows.request_password_reset(EMAIL)
    token = token_from(sender)

    with pytest.raises(PasswordRejected):
        flows.confirm_password_reset(token=token, new_password="short", family_ids=[])

    with pytest.raises(ConfirmationFailed):
        flows.confirm_password_reset(token=token, new_password=NEW_PASSWORD, family_ids=[])
    # And the original password still works, so nothing half-happened.
    assert flows.login(email=EMAIL, password=PASSWORD).access_token


def test_a_reset_link_cannot_be_used_for_verification(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    seed_account(hooks, stores)
    sender.clear()
    flows.request_password_reset(EMAIL)
    token = token_from(sender)

    with pytest.raises(ConfirmationFailed):
        flows.confirm_verification(token)
    # Unspent, so the reset the user actually asked for still works.
    flows.confirm_password_reset(token=token, new_password=NEW_PASSWORD, family_ids=[])


# ---------------------------------------------------------------------------
# Configuration: the flows without an email sender
# ---------------------------------------------------------------------------


@pytest.fixture
def mailless_flows(
    kms: FakeKms,
    hooks: FakeHooks,
    stores: IdentityStores,
    attempts: InMemoryLoginAttemptStore,
) -> IdentityFlows:
    settings = make_settings()
    return IdentityFlows(settings, hooks, stores, TokenService(settings, kms), attempts=attempts)


def test_email_enabled_needs_both_a_sender_and_a_token_store(
    kms: FakeKms, hooks: FakeHooks, attempts: InMemoryLoginAttemptStore
) -> None:
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
    """The one tolerance. Every route that promises an email checks first."""
    assert mailless_flows.register(email=EMAIL, password=PASSWORD) is not None
    assert hooks.by_email[EMAIL]


def test_the_email_flows_refuse_with_503_when_no_sender_is_configured(
    mailless_flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A misconfiguration, not a client error, so a 5xx rather than a 4xx.

    A caller cannot fix it by changing the request, and answering 200 would promise an email
    that is never going to arrive.
    """
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


# ---------------------------------------------------------------------------
# The routes
# ---------------------------------------------------------------------------


@pytest.fixture
def client(
    kms: FakeKms,
    hooks: FakeHooks,
    stores: IdentityStores,
    attempts: InMemoryLoginAttemptStore,
    sender: RecordingEmailSender,
) -> Iterator[TestClient]:
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
            # The limiter needs DynamoDB, and these tests are about the routes. The limits
            # themselves are asserted separately against the constants.
            limiter_enabled=False,
        )
    )
    with TestClient(app, base_url="https://api.example.com") as test_client:
        yield test_client


def prefix() -> str:
    return identity_prefix(make_settings())


def router_paths(**kwargs: Any) -> set[str]:
    """The paths one built router declares.

    Read off the router rather than off an app, the way the M2 suite does: an app's
    `routes` list holds the include wrapper rather than the routes themselves.
    """
    router = build_identity_router(make_settings(), limiter_enabled=False, **kwargs)
    return {route.path for route in router.routes}  # type: ignore[attr-defined]


def test_the_four_routes_are_mounted_when_a_sender_and_a_token_store_are_supplied(
    kms: FakeKms, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
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
    """A route that cannot work should not exist, rather than answering 503 to its first
    request. Same rule the M2 flow routes follow."""
    mounted = router_paths(hooks=hooks, stores=stores, kms_client=kms)

    assert f"{prefix()}{VERIFY_REQUEST_PATH}" not in mounted
    assert f"{prefix()}{RESET_CONFIRM_PATH}" not in mounted
    # The M2 routes are still there, because their collaborators are.
    assert f"{prefix()}/login" in mounted


def test_the_four_routes_are_absent_without_a_token_store(
    kms: FakeKms, hooks: FakeHooks, sender: RecordingEmailSender
) -> None:
    stores = IdentityStores(
        credentials=InMemoryCredentialStore(), refresh_tokens=InMemoryRefreshTokenStore()
    )
    mounted = router_paths(hooks=hooks, stores=stores, kms_client=kms, email_sender=sender)

    assert f"{prefix()}{RESET_REQUEST_PATH}" not in mounted
    assert f"{prefix()}/login" in mounted


def test_the_reset_request_route_answers_identically_for_a_known_and_unknown_address(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Section 5.4, tested as an equality rather than against a literal.

    Comparing the two responses to each other catches the case a literal check misses: one
    of them gaining a header, a different status, or an extra field.
    """
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
    seed_account(hooks, stores)
    sender.clear()
    client.post(f"{prefix()}{VERIFY_REQUEST_PATH}", json={"email": EMAIL})

    response = client.post(f"{prefix()}{VERIFY_CONFIRM_PATH}", json={"token": token_from(sender)})

    assert response.status_code == 200
    assert response.json() == {"verified": True, "user_id": USER_ID}
    assert hooks.verified == [USER_ID]


def test_a_bad_token_is_a_400_in_the_shared_error_envelope(client: TestClient) -> None:
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
    """Every family is revoked, including whichever one this browser held. Leaving the cookie
    would send a dead token on every request until it expired."""
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
    # And the new password is what works now.
    assert (
        client.post(
            f"{prefix()}/login", json={"email": EMAIL, "password": NEW_PASSWORD}
        ).status_code
        == 200
    )


def test_a_reset_with_a_refused_password_is_a_422(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
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
    """A missing field must not be a different answer from a wrong one, or the 422 boundary
    becomes the oracle the 200 was there to avoid."""
    response = client.post(f"{prefix()}{RESET_REQUEST_PATH}", json={})
    assert response.status_code == 200


def test_the_rate_limits_match_section_5_1() -> None:
    """The table in the standard and the constants, diffed against each other.

    The per-IP verification ceiling is an addition rather than a transcription: section 5.1
    gives reset an IP limit and verification only a per-address one, and an unlimited resend
    route is a free mail relay pointed at addresses an attacker supplies.
    """
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
