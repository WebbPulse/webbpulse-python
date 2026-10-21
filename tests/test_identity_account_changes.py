"""Tests for the self-service account routes: the session list and the sign-in address change.

Covers listing and revoking a user's own refresh families, the email change link state
machine, the recent sign-in gate, the uniqueness checks and the notices both addresses get.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from webbpulse.identity import (
    EMAIL_CHANGE_CONFIRM_PATH,
    EMAIL_CHANGE_LINK_PATH,
    EMAIL_CHANGE_PATH,
    SESSIONS_PATH,
    AuthenticationRefused,
    BaseIdentityHooks,
    ConfirmationFailed,
    EmailChangeHooks,
    IdentitySettings,
    IdentityStores,
    InMemoryCredentialStore,
    InMemoryIdentityTokenStore,
    InMemoryLoginAttemptStore,
    InMemoryRefreshTokenStore,
    RecordingEmailSender,
    TokenService,
    build_identity_router,
    identity_prefix,
    normalise_password,
    render_email_change,
    render_email_changed,
)
from webbpulse.identity.flows import PASSWORD_CREDENTIAL_TYPE, IdentityFlows, LoginRejected
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
EMAIL = "person@example.com"
NEW_EMAIL = "moved@example.org"
TAKEN_EMAIL = "taken@example.com"
USER_ID = "user-0001"
OTHER_ID = "user-0002"


class FakeKms:
    """A KMS client signing for real with a local private key."""

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

    def sign(self, *, KeyId: str, Message: bytes, MessageType: str, SigningAlgorithm: str) -> dict[str, Any]:
        """Sign a prehashed message with the local private key for a key id."""
        signature = self._keys[KeyId].sign(Message, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
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
    """A product's policy, in memory, that can change a user's sign-in address."""

    def __init__(self) -> None:
        """Start with no users and no recorded address changes."""
        self.users: dict[str, dict[str, Any]] = {}
        self.changes: list[tuple[str, str]] = []

    def add(self, email: str, *, user_id: str) -> dict[str, Any]:
        """Register a user in the fake store and return it."""
        user = {"id": user_id, "email": email, "email_verified": True}
        self.users[user_id] = user
        return user

    def load_user_by_id(self, user_id: str) -> Mapping[str, Any] | None:
        """Return the user with this id, or None."""
        return self.users.get(user_id)

    def load_user_by_email(self, email: str) -> Mapping[str, Any] | None:
        """Return the user with this address, case insensitively, or None."""
        for user in self.users.values():
            if str(user["email"]).lower() == email.lower():
                return user
        return None

    def may_authenticate(self, user: Mapping[str, Any]) -> None:
        """Permit every user."""
        if user.get("disabled"):
            raise AuthenticationRefused("This account may not sign in.")

    def claims_for(self, user: Mapping[str, Any]) -> Mapping[str, Any]:
        """Return no extra claims."""
        return {}

    def create_user(self, *, email: str, attributes: Mapping[str, Any]) -> Mapping[str, Any]:
        """Create a user from an address."""
        return self.add(email, user_id=f"user-{len(self.users) + 1:04d}")

    def mark_email_verified(self, user_id: str) -> None:
        """Mark the user verified."""
        self.users[user_id]["email_verified"] = True

    def change_email(self, user_id: str, email: str) -> None:
        """Move the user's address and record the change."""
        self.changes.append((user_id, email))
        self.users[user_id]["email"] = email
        self.users[user_id]["email_verified"] = True


class NoChangeHooks(FakeHooks):
    """Hooks that inherit the base class's refusing `change_email`."""

    change_email = BaseIdentityHooks.change_email


@pytest.fixture
def hooks() -> FakeHooks:
    """A fresh `FakeHooks` per test, holding the suite's user and one other."""
    fake = FakeHooks()
    fake.add(EMAIL, user_id=USER_ID)
    fake.add(TAKEN_EMAIL, user_id=OTHER_ID)
    return fake


@pytest.fixture
def stores() -> IdentityStores:
    """In-memory credential, refresh token and identity token stores, with both passwords set."""
    from webbpulse.security import hash_password

    built = IdentityStores(
        credentials=InMemoryCredentialStore(),
        refresh_tokens=InMemoryRefreshTokenStore(),
        identity_tokens=InMemoryIdentityTokenStore(),
    )
    for user_id in (USER_ID, OTHER_ID):
        built.require_credentials().put(
            CredentialRecord(
                user_id=user_id,
                credential_type=PASSWORD_CREDENTIAL_TYPE,
                secret=hash_password(normalise_password(PASSWORD)),
            )
        )
    return built


@pytest.fixture
def sender() -> RecordingEmailSender:
    """A recording email sender that keeps every message instead of sending it."""
    return RecordingEmailSender()


def build_flows(kms: FakeKms, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender) -> IdentityFlows:
    """Identity flows wired to the fakes, with the recording email sender attached."""
    settings = make_settings()
    return IdentityFlows(
        settings,
        hooks,
        stores,
        TokenService(settings, kms),
        attempts=InMemoryLoginAttemptStore(),
        email_sender=sender,
    )


@pytest.fixture
def flows(kms: FakeKms, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender) -> IdentityFlows:
    """Identity flows over the suite's fakes."""
    return build_flows(kms, hooks, stores, sender)


def token_from(sender: RecordingEmailSender, address: str) -> str:
    """The token out of the most recent link mailed to an address, read from the message body."""
    message = sender.last_for(address)
    assert message is not None, f"no message was sent to {address}"
    from urllib.parse import parse_qs, urlsplit

    for line in message.text.splitlines():
        if line.startswith("http"):
            return parse_qs(urlsplit(line).query)["token"][0]
    raise AssertionError("the message body carried no link")


def test_the_session_list_shows_each_live_sign_in_once(flows: IdentityFlows) -> None:
    """Two sign-ins are two sessions, and a refresh keeps the same session rather than adding one."""
    first = flows.login(email=EMAIL, password=PASSWORD, user_agent="Mozilla/5.0", ip="203.0.113.1")
    second = flows.login(email=EMAIL, password=PASSWORD, user_agent="Mozilla/5.0 (iPhone) Mobile")
    flows.refresh(first.refresh_token)

    sessions = flows.list_sessions(USER_ID)

    assert {session.family_id for session in sessions} == {first.family_id, second.family_id}
    by_id = {session.family_id: session for session in sessions}
    assert by_id[first.family_id].device == "desktop"
    assert by_id[first.family_id].ip == "203.0.113.1"
    assert by_id[second.family_id].device == "mobile"


def test_a_signed_out_session_leaves_the_list(flows: IdentityFlows) -> None:
    """Logging out of one sign-in removes it and leaves the other."""
    first = flows.login(email=EMAIL, password=PASSWORD)
    second = flows.login(email=EMAIL, password=PASSWORD)
    flows.logout(first.refresh_token)

    assert [session.family_id for session in flows.list_sessions(USER_ID)] == [second.family_id]


def test_revoking_a_session_is_scoped_to_its_owner(flows: IdentityFlows) -> None:
    """Another user's session id cannot be revoked and reads as unknown; the owner's own can."""
    mine = flows.login(email=EMAIL, password=PASSWORD)
    theirs = flows.login(email=TAKEN_EMAIL, password=PASSWORD)

    assert flows.revoke_session(USER_ID, theirs.family_id) is False
    assert [session.family_id for session in flows.list_sessions(OTHER_ID)] == [theirs.family_id]
    assert flows.revoke_session(USER_ID, "no-such-family") is False

    assert flows.revoke_session(USER_ID, mine.family_id) is True
    assert flows.list_sessions(USER_ID) == []


def test_a_store_that_cannot_enumerate_lists_nothing(
    kms: FakeKms, hooks: FakeHooks, sender: RecordingEmailSender
) -> None:
    """A refresh store with no user enumeration reports no sessions rather than failing."""

    class NoIndexStore(InMemoryRefreshTokenStore):
        """An in-memory store that refuses to enumerate, like a table with no user index."""

        def latest_by_family_for_user(self, user_id: str) -> list[Any]:
            """Refuse, as a store built with no user index does."""
            raise NotImplementedError

    stores = IdentityStores(
        credentials=InMemoryCredentialStore(),
        refresh_tokens=NoIndexStore(),
        identity_tokens=InMemoryIdentityTokenStore(),
    )
    assert build_flows(kms, hooks, stores, sender).list_sessions(USER_ID) == []


def test_requesting_an_email_change_mails_the_new_address_and_changes_nothing(
    flows: IdentityFlows, hooks: FakeHooks, sender: RecordingEmailSender
) -> None:
    """The link goes to the new address, points at the change page, and the account is untouched."""
    flows.request_email_change(user_id=USER_ID, new_email=" Moved@Example.org ")

    message = sender.last_for(NEW_EMAIL)
    assert message is not None
    assert message.tags["purpose"] == "change_email"
    assert f"{FRONTEND}{EMAIL_CHANGE_LINK_PATH}?token=" in message.text
    assert "1 hour" in message.text
    assert sender.last_for(EMAIL) is None
    assert hooks.users[USER_ID]["email"] == EMAIL
    assert hooks.changes == []


@pytest.mark.parametrize(
    ("address", "code", "status"),
    [
        ("not-an-address", "INVALID_EMAIL", 400),
        ("person@localhost", "INVALID_EMAIL", 400),
        (EMAIL.upper(), "EMAIL_UNCHANGED", 400),
        (TAKEN_EMAIL, "EMAIL_TAKEN", 409),
    ],
)
def test_a_request_for_an_unusable_address_is_refused(
    flows: IdentityFlows, sender: RecordingEmailSender, address: str, code: str, status: int
) -> None:
    """A malformed, unchanged or taken address is refused and nothing is mailed."""
    with pytest.raises(LoginRejected) as caught:
        flows.request_email_change(user_id=USER_ID, new_email=address)
    assert caught.value.error_code == code
    assert caught.value.status_code == status
    assert sender.sent == []


def test_confirming_moves_the_address_ends_other_sessions_and_tells_the_old_address(
    flows: IdentityFlows, hooks: FakeHooks, sender: RecordingEmailSender
) -> None:
    """The change lands on confirm: the requesting session survives, the others end, the old address hears."""
    requesting = flows.login(email=EMAIL, password=PASSWORD)
    other = flows.login(email=EMAIL, password=PASSWORD)
    flows.request_email_change(user_id=USER_ID, new_email=NEW_EMAIL, family_id=requesting.family_id)

    assert flows.confirm_email_change(token_from(sender, NEW_EMAIL)) == USER_ID

    assert hooks.changes == [(USER_ID, NEW_EMAIL)]
    assert hooks.users[USER_ID]["email_verified"] is True
    assert [session.family_id for session in flows.list_sessions(USER_ID)] == [requesting.family_id]
    assert other.family_id != requesting.family_id
    notice = sender.last_for(EMAIL)
    assert notice is not None
    assert notice.tags["purpose"] == "email_changed"
    assert NEW_EMAIL not in notice.text
    assert "m***@e***.org" in notice.text
    assert flows.login(email=NEW_EMAIL, password=PASSWORD).access_token


def test_an_email_change_link_works_once(flows: IdentityFlows, sender: RecordingEmailSender) -> None:
    """A second confirmation of the same link is refused."""
    flows.request_email_change(user_id=USER_ID, new_email=NEW_EMAIL)
    token = token_from(sender, NEW_EMAIL)
    flows.confirm_email_change(token)

    with pytest.raises(ConfirmationFailed):
        flows.confirm_email_change(token)


def test_a_verification_link_is_not_an_email_change_link(
    flows: IdentityFlows, hooks: FakeHooks, sender: RecordingEmailSender
) -> None:
    """A link minted for another purpose is refused by the change flow."""
    hooks.users[USER_ID]["email_verified"] = False
    flows.request_verification(EMAIL)

    with pytest.raises(ConfirmationFailed):
        flows.confirm_email_change(token_from(sender, EMAIL))
    assert hooks.changes == []


def test_an_address_claimed_after_the_request_is_refused_at_confirm(
    flows: IdentityFlows, hooks: FakeHooks, sender: RecordingEmailSender
) -> None:
    """Uniqueness is checked again when the link is confirmed."""
    flows.request_email_change(user_id=USER_ID, new_email=NEW_EMAIL)
    hooks.add(NEW_EMAIL, user_id="user-0003")

    with pytest.raises(LoginRejected) as caught:
        flows.confirm_email_change(token_from(sender, NEW_EMAIL))
    assert caught.value.error_code == "EMAIL_TAKEN"
    assert hooks.changes == []


def test_hooks_without_change_email_refuse_before_mailing(
    kms: FakeKms, stores: IdentityStores, sender: RecordingEmailSender
) -> None:
    """A product whose hooks cannot change an address gets a 501 and no link is mailed."""
    hooks = NoChangeHooks()
    hooks.add(EMAIL, user_id=USER_ID)

    with pytest.raises(LoginRejected) as caught:
        build_flows(kms, hooks, stores, sender).request_email_change(user_id=USER_ID, new_email=NEW_EMAIL)
    assert caught.value.status_code == 501
    assert caught.value.error_code == "EMAIL_CHANGE_UNSUPPORTED"
    assert sender.sent == []
    assert isinstance(FakeHooks(), EmailChangeHooks)


def test_the_two_new_messages_carry_no_em_dash_or_developer() -> None:
    """The change confirmation and the change notice follow the copy rules."""
    settings = make_settings()
    for message in (
        render_email_change(settings, to=NEW_EMAIL, link="https://x", expiry="1 hour"),
        render_email_changed(settings, to=EMAIL, new_address="m***@e***.org"),
    ):
        for part in (message.subject, message.text, message.html):
            assert "—" not in part
            assert "developer" not in part.lower()


@pytest.fixture
def client(
    kms: FakeKms, hooks: FakeHooks, stores: IdentityStores, sender: RecordingEmailSender
) -> Iterator[TestClient]:
    """A `TestClient` over an app mounting the identity router with the limiter off."""
    from webbpulse.http import register_error_handlers

    app = FastAPI()
    register_error_handlers(app, error_codes=True)
    app.include_router(
        build_identity_router(
            make_settings(),
            hooks,
            stores,
            kms_client=kms,
            attempts=InMemoryLoginAttemptStore(),
            email_sender=sender,
            limiter_enabled=False,
        )
    )
    with TestClient(app, base_url="https://api.example.com") as test_client:
        yield test_client


def url(path: str) -> str:
    """The full route path under the suite's identity prefix."""
    return f"{identity_prefix(make_settings())}{path}"


def sign_in(client: TestClient, email: str = EMAIL) -> str:
    """Sign in over HTTP and return the bearer access token."""
    response = client.post(url("/login"), json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return str(response.json()["access_token"])


def bearer(token: str) -> dict[str, str]:
    """The authorization header for an access token."""
    return {"Authorization": f"Bearer {token}"}


def test_the_session_routes_list_and_revoke_with_the_current_one_marked(client: TestClient) -> None:
    """`GET /sessions` marks the calling session, and `DELETE` ends another but refuses the caller's own."""
    other = sign_in(client)
    access = sign_in(client)

    listed = client.get(url(SESSIONS_PATH), headers=bearer(access))
    assert listed.status_code == 200
    sessions = listed.json()["sessions"]
    assert len(sessions) == 2
    current = [session for session in sessions if session["current"]]
    assert len(current) == 1
    others = [session for session in sessions if not session["current"]]

    refused = client.delete(url(f"{SESSIONS_PATH}/{current[0]['id']}"), headers=bearer(access))
    assert refused.status_code == 400
    assert refused.json()["error_code"] == "CURRENT_SESSION"

    revoked = client.delete(url(f"{SESSIONS_PATH}/{others[0]['id']}"), headers=bearer(access))
    assert revoked.status_code == 200
    missing = client.delete(url(f"{SESSIONS_PATH}/{others[0]['id']}"), headers=bearer(access))
    assert missing.status_code == 404
    assert missing.json()["error_code"] == "SESSION_NOT_FOUND"
    assert other


def test_the_session_routes_need_a_bearer(client: TestClient) -> None:
    """Both session routes answer 401 with no token."""
    assert client.get(url(SESSIONS_PATH)).status_code == 401
    assert client.delete(url(f"{SESSIONS_PATH}/anything")).status_code == 401


def test_another_users_session_answers_404_over_http(client: TestClient) -> None:
    """A session id that belongs to someone else reads exactly as an unknown one."""
    theirs = sign_in(client, TAKEN_EMAIL)
    their_id = client.get(url(SESSIONS_PATH), headers=bearer(theirs)).json()["sessions"][0]["id"]
    mine = sign_in(client)

    response = client.delete(url(f"{SESSIONS_PATH}/{their_id}"), headers=bearer(mine))
    assert response.status_code == 404


def test_the_email_change_routes_round_trip(client: TestClient, hooks: FakeHooks, sender: RecordingEmailSender) -> None:
    """Request with a fresh sign-in, confirm with the mailed token, and the address has moved."""
    access = sign_in(client)

    requested = client.post(url(EMAIL_CHANGE_PATH), json={"email": NEW_EMAIL}, headers=bearer(access))
    assert requested.status_code == 200, requested.text
    assert requested.json() == {"sent": True}

    confirmed = client.post(url(EMAIL_CHANGE_CONFIRM_PATH), json={"token": token_from(sender, NEW_EMAIL)})
    assert confirmed.status_code == 200
    assert confirmed.json()["changed"] is True
    assert hooks.users[USER_ID]["email"] == NEW_EMAIL

    reused = client.post(url(EMAIL_CHANGE_CONFIRM_PATH), json={"token": token_from(sender, NEW_EMAIL)})
    assert reused.status_code == 400
    assert reused.json()["error_code"] == "INVALID_LINK"


def test_an_email_change_needs_a_bearer_and_a_recent_sign_in(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, sender: RecordingEmailSender
) -> None:
    """No token is a 401, and a sign-in older than the window is a 401 asking for a step-up."""
    assert client.post(url(EMAIL_CHANGE_PATH), json={"email": NEW_EMAIL}).status_code == 401

    access = sign_in(client)
    import webbpulse.identity.scopes as scopes

    monkeypatch.setattr(scopes, "_auth_time", lambda claims: 1)
    response = client.post(url(EMAIL_CHANGE_PATH), json={"email": NEW_EMAIL}, headers=bearer(access))
    assert response.status_code == 401
    assert response.json()["error_code"] == "STEP_UP_REQUIRED"
    assert sender.last_for(NEW_EMAIL) is None


def test_a_taken_address_is_a_409_over_http(client: TestClient) -> None:
    """Asking for an address another account holds answers 409 `EMAIL_TAKEN`."""
    access = sign_in(client)
    response = client.post(url(EMAIL_CHANGE_PATH), json={"email": TAKEN_EMAIL}, headers=bearer(access))
    assert response.status_code == 409
    assert response.json()["error_code"] == "EMAIL_TAKEN"


def test_a_reset_link_mailed_to_the_old_address_dies_with_the_change(
    flows: IdentityFlows, sender: RecordingEmailSender
) -> None:
    """A reset link issued before the change cannot be spent after it, so the old mailbox cannot take the account."""
    flows.request_password_reset(EMAIL)
    stale_reset = token_from(sender, EMAIL)
    flows.request_email_change(user_id=USER_ID, new_email=NEW_EMAIL)
    flows.confirm_email_change(token_from(sender, NEW_EMAIL))

    with pytest.raises(ConfirmationFailed):
        flows.confirm_password_reset(token=stale_reset, new_password="another long passphrase here")


class NoUserIndexTokenStore(InMemoryIdentityTokenStore):
    """An identity token store that cannot find a user's links, like the DynamoDB table."""

    def revoke_for_user(self, user_id: str, purpose: Any) -> int:
        """Refuse, as a table with no user index does."""
        raise NotImplementedError


def test_the_address_binding_kills_old_links_where_the_store_cannot_revoke(
    kms: FakeKms, hooks: FakeHooks, sender: RecordingEmailSender
) -> None:
    """With no user index, the address each link was mailed to still refuses a stale reset or verification."""
    from webbpulse.security import hash_password

    stores = IdentityStores(
        credentials=InMemoryCredentialStore(),
        refresh_tokens=InMemoryRefreshTokenStore(),
        identity_tokens=NoUserIndexTokenStore(),
    )
    stores.require_credentials().put(
        CredentialRecord(
            user_id=USER_ID,
            credential_type=PASSWORD_CREDENTIAL_TYPE,
            secret=hash_password(normalise_password(PASSWORD)),
        )
    )
    flows = build_flows(kms, hooks, stores, sender)
    flows.request_password_reset(EMAIL)
    stale_reset = token_from(sender, EMAIL)
    hooks.users[USER_ID]["email_verified"] = False
    flows.request_verification(EMAIL)
    stale_verify = token_from(sender, EMAIL)
    hooks.users[USER_ID]["email_verified"] = True

    flows.request_email_change(user_id=USER_ID, new_email=NEW_EMAIL)
    flows.confirm_email_change(token_from(sender, NEW_EMAIL))

    with pytest.raises(ConfirmationFailed):
        flows.confirm_password_reset(token=stale_reset, new_password="another long passphrase here")
    with pytest.raises(ConfirmationFailed):
        flows.confirm_verification(stale_verify)


def test_a_second_change_link_dies_once_the_first_lands(flows: IdentityFlows, sender: RecordingEmailSender) -> None:
    """Two pending changes cannot both land: the second link was bound to the address the first replaced."""
    flows.request_email_change(user_id=USER_ID, new_email=NEW_EMAIL)
    first = token_from(sender, NEW_EMAIL)
    flows.request_email_change(user_id=USER_ID, new_email="third@example.net")
    second = token_from(sender, "third@example.net")
    flows.confirm_email_change(first)

    with pytest.raises(ConfirmationFailed):
        flows.confirm_email_change(second)


def test_a_reset_link_still_works_when_the_address_has_not_moved(
    flows: IdentityFlows, sender: RecordingEmailSender
) -> None:
    """The binding refuses nothing for an account whose address is unchanged."""
    flows.request_password_reset(EMAIL)
    assert flows.confirm_password_reset(token=token_from(sender, EMAIL), new_password="another long passphrase here")
