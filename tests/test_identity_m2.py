"""Tests for the M2 identity flows: passwords, lockout, sessions, and the six routes."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import pytest

from webbpulse.identity import (
    AuthenticationRefused,
    BaseIdentityHooks,
    IdentitySettings,
    IdentityStores,
    InMemoryCredentialStore,
    InMemoryLoginAttemptStore,
    InMemoryRefreshTokenStore,
    LoginAttempt,
    PasswordRejected,
    SessionService,
    TokenService,
    build_identity_router,
    check_password,
    email_key,
    hash_token,
    identity_prefix,
    ip_key,
    lockout_state,
    new_attempt,
    normalise_password,
)
from webbpulse.identity.flows import (
    INVALID_CREDENTIALS_MESSAGE,
    PASSWORD_CREDENTIAL_TYPE,
    IdentityFlows,
    LoginRejected,
    RateLimited,
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


class FakeKms:
    """A KMS client signing for real with a local private key.

    It signs the digest without re-hashing and returns the raw PKCS #1 signature.
    """

    def __init__(self, keys: dict[str, rsa.RSAPrivateKey]) -> None:
        """Hold the private keys by key id."""
        self._keys = keys

    def get_public_key(self, *, KeyId: str) -> dict[str, Any]:
        """Return a `kms:GetPublicKey` shaped response for the named key."""
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
        """Return a real PKCS #1 v1.5 signature over the digest, using the named key."""
        signature = self._keys[KeyId].sign(
            Message, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
        )
        return {"KeyId": KeyId, "Signature": signature, "SigningAlgorithm": SigningAlgorithm}


PASSWORD = "correct horse battery staple"
OTHER_PASSWORD = "a different but equally fine one"
EMAIL = "person@example.com"
USER_ID = "user-0001"


@pytest.fixture(autouse=True)
def cheap_bcrypt(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Pin bcrypt to its minimum cost of 4 rounds for every test in this module."""
    import webbpulse.security as security

    real_hash = security.hash_password
    real_needs = security.needs_rehash

    def cheap(password: str, *, rounds: int = 4) -> str:
        """Hash at the minimum cost, even when a caller passes `rounds` explicitly."""
        return real_hash(password, rounds=rounds)

    def needs(hashed: str, *, rounds: int = 4) -> bool:
        """Report rehash need against the minimum cost rather than the real default."""
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
    """Return a locally signing KMS stand-in holding the module key."""
    return FakeKms({KEY_A: module_key})


def make_settings(**overrides: Any) -> IdentitySettings:
    """Build `IdentitySettings` from this module's defaults with the given overrides."""
    base: dict[str, Any] = {
        "environment": "test",
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "signing_key_arns": [KEY_A],
        "email_verification_required": False,
    }
    base.update(overrides)
    return IdentitySettings(**base)


class FakeHooks(BaseIdentityHooks):
    """A product's identity policy, in memory, recording each hook call in order."""

    def __init__(self, *, refuse: str = "") -> None:
        """Start with no users and an optional refusal message for `may_authenticate`."""
        self.users: dict[str, dict[str, Any]] = {}
        self.by_email: dict[str, str] = {}
        self.refuse = refuse
        self.calls: list[str] = []
        self.created: list[tuple[str, str]] = []
        self._next = 1

    def add(self, email: str, *, user_id: str = "", **attributes: Any) -> dict[str, Any]:
        """Add a user with the given email and attributes, and return it."""
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
        """Return the user with this email, matched case insensitively, or None."""
        self.calls.append("load_user_by_email")
        identifier = self.by_email.get(email.lower())
        return self.users.get(identifier) if identifier else None

    def may_authenticate(self, user: Mapping[str, Any]) -> None:
        """Raise `AuthenticationRefused` when configured to refuse or the user is disabled."""
        self.calls.append("may_authenticate")
        if self.refuse:
            raise AuthenticationRefused(self.refuse, error_code="ACCOUNT_DISABLED")
        if user.get("disabled"):
            raise AuthenticationRefused("This account is disabled.", error_code="DISABLED")

    def claims_for(self, user: Mapping[str, Any]) -> Mapping[str, Any]:
        """Return the user's roles as the product claims."""
        self.calls.append("claims_for")
        return {"roles": user.get("roles", [])}

    def create_user(self, *, email: str, attributes: Mapping[str, Any]) -> Mapping[str, Any]:
        """Create and return a user for this email."""
        self.calls.append("create_user")
        return self.add(email, **dict(attributes))

    def on_user_created(self, user: Mapping[str, Any], via: str) -> None:
        """Record the created user and the mechanism that created it."""
        self.calls.append("on_user_created")
        self.created.append((str(user["id"]), via))


@pytest.fixture
def hooks() -> FakeHooks:
    """Return an empty in-memory hooks implementation."""
    return FakeHooks()


@pytest.fixture
def stores() -> IdentityStores:
    """Return in-memory credential and refresh token stores."""
    return IdentityStores(
        credentials=InMemoryCredentialStore(),
        refresh_tokens=InMemoryRefreshTokenStore(),
    )


@pytest.fixture
def attempts() -> InMemoryLoginAttemptStore:
    """Return an in-memory login attempt store."""
    return InMemoryLoginAttemptStore()


@pytest.fixture
def flows(
    kms: FakeKms,
    hooks: FakeHooks,
    stores: IdentityStores,
    attempts: InMemoryLoginAttemptStore,
) -> IdentityFlows:
    """Return `IdentityFlows` wired to the in-memory hooks, stores and attempt store."""
    settings = make_settings()
    return IdentityFlows(settings, hooks, stores, TokenService(settings, kms), attempts=attempts)


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


def test_minimum_is_eight_characters() -> None:
    """A seven character password is rejected and an eight character one is accepted."""
    with pytest.raises(PasswordRejected) as caught:
        check_password("short12")
    assert caught.value.error_code == "PASSWORD_TOO_SHORT"
    assert check_password("exactly8") == "exactly8"


def test_maximum_is_seventy_two_bytes_not_characters() -> None:
    """The length cap is counted in bytes, not characters, and the message says so."""
    emoji = "\U0001f984" * 20
    assert len(emoji) == 20
    assert len(emoji.encode("utf-8")) == 80

    with pytest.raises(PasswordRejected) as caught:
        check_password(emoji)
    assert caught.value.error_code == "PASSWORD_TOO_LONG"
    assert "byte" in str(caught.value).lower()

    assert check_password("a" * 72) == "a" * 72
    with pytest.raises(PasswordRejected):
        check_password("a" * 73)


def test_no_composition_rules() -> None:
    """No composition rule rejects a password, whatever characters it uses."""
    for candidate in ("alllowercase", "ALLUPPERCASE", "12345678", "        x", "!!!!!!!!"):
        assert check_password(candidate) == candidate


def test_unicode_is_normalised_to_nfkc_and_spaces_survive() -> None:
    """Passwords are NFKC normalised so two spellings match, and spaces are not stripped."""
    composed = "café" + "12345"
    precomposed = "café" + "12345"
    assert composed != precomposed
    assert check_password(composed) == check_password(precomposed)

    padded = "  spaces  here  "
    assert check_password(padded) == padded


def test_breach_check_raises_rather_than_silently_doing_nothing() -> None:
    """`breach_check=True` raises `NotImplementedError` rather than silently doing nothing."""
    with pytest.raises(NotImplementedError, match="flag only"):
        check_password(PASSWORD, breach_check=True)


def attempt_at(outcome: str, moment: datetime) -> LoginAttempt:
    """Build a login attempt for this module's email with the given outcome and time."""
    return LoginAttempt(
        identity_key=email_key(EMAIL),
        attempted_at=moment.isoformat().replace("+00:00", "Z"),
        outcome=outcome,  # type: ignore[arg-type]
    )


def test_four_failures_do_not_lock() -> None:
    """Four failures are counted but leave the account unlocked."""
    now = datetime.now(UTC)
    history = [attempt_at("failure", now - timedelta(seconds=i)) for i in range(4)]
    state = lockout_state(history, now=now)
    assert state.failures == 4
    assert state.locked is False


def test_fifth_failure_starts_a_one_second_delay_that_doubles() -> None:
    """The delay starts at one second on the fifth failure, doubles, and caps at 15 minutes."""
    base = datetime.now(UTC)
    history: list[LoginAttempt] = []
    delays: list[float] = []
    for index in range(1, 12):
        history.insert(0, attempt_at("failure", base))
        state = lockout_state(history, now=base)
        if state.retry_at is not None:
            delays.append((state.retry_at - base).total_seconds())
        assert state.failures == index

    assert delays[0] == pytest.approx(1.0)
    assert delays[1] == pytest.approx(2.0)
    assert delays[2] == pytest.approx(4.0)
    assert max(delays) <= timedelta(minutes=15).total_seconds()


def test_a_success_clears_the_count() -> None:
    """A success resets the failure count rather than decaying it."""
    now = datetime.now(UTC)
    history = [
        attempt_at("failure", now - timedelta(seconds=1)),
        attempt_at("success", now - timedelta(seconds=2)),
        *[attempt_at("failure", now - timedelta(seconds=3 + i)) for i in range(9)],
    ]
    state = lockout_state(history, now=now)
    assert state.failures == 1
    assert state.locked is False


def test_a_locked_attempt_does_not_extend_its_own_lockout() -> None:
    """Attempts made while locked do not raise the failure count or push the retry deadline."""
    now = datetime.now(UTC)
    failures = [attempt_at("failure", now - timedelta(seconds=10 + i)) for i in range(5)]
    locked_state = lockout_state(failures, now=now)

    with_retries = [attempt_at("locked", now - timedelta(seconds=i)) for i in range(5)] + failures
    retried_state = lockout_state(with_retries, now=now)

    assert retried_state.failures == locked_state.failures
    assert retried_state.retry_at == locked_state.retry_at


def test_the_delay_elapses_in_real_time() -> None:
    """The delay is measured from the last failure, so it elapses as real time passes."""
    base = datetime.now(UTC)
    history = [attempt_at("failure", base - timedelta(seconds=30 + i)) for i in range(5)]
    assert lockout_state(history, now=base).locked is False

    assert lockout_state(history, now=base - timedelta(seconds=30)).locked is True


def test_attempts_older_than_the_lookback_are_ignored() -> None:
    """Failures older than the lookback window are not counted."""
    ancient = datetime.now(UTC) - timedelta(days=2)
    history = [attempt_at("failure", ancient - timedelta(seconds=i)) for i in range(20)]
    assert lockout_state(history, now=datetime.now(UTC)).failures == 0


def test_attempt_rows_carry_no_credential() -> None:
    """A login attempt row carries no password and has no password field."""
    attempt = new_attempt(email_key(EMAIL), "failure", user_id=USER_ID, ip="203.0.113.9")
    serialised = repr(attempt)
    assert PASSWORD not in serialised
    assert "password" not in {field for field in LoginAttempt.__dataclass_fields__}


def test_email_and_ip_keys_are_namespaced() -> None:
    """Email and IP attempt keys are namespaced and lowercased so they cannot collide."""
    assert email_key("Person@Example.com") == "email#person@example.com"
    assert ip_key("203.0.113.9") == "ip#203.0.113.9"
    assert email_key("x") != ip_key("x")


def test_register_creates_a_user_a_credential_and_a_session(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Registering creates the user, stores a bcrypt credential and returns a session."""
    result = flows.register(email=EMAIL, password=PASSWORD)
    assert result is not None
    assert result.access_token
    assert result.refresh_token
    assert hooks.created == [(str(result.user["id"]), "password")]

    credential = stores.require_credentials().get(str(result.user["id"]), PASSWORD_CREDENTIAL_TYPE)
    assert credential is not None
    assert credential.secret.startswith("$2")
    assert PASSWORD not in credential.secret


def test_register_with_a_taken_email_is_indistinguishable(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Registering a taken email returns None and leaves the existing credential untouched."""
    seed_account(hooks, stores)
    assert flows.register(email=EMAIL, password=OTHER_PASSWORD) is None
    credential = stores.require_credentials().get(USER_ID, PASSWORD_CREDENTIAL_TYPE)
    assert credential is not None
    from webbpulse.security import verify_password

    assert verify_password(PASSWORD, credential.secret)


def test_register_rejects_a_policy_violation_before_looking_the_email_up(
    flows: IdentityFlows, hooks: FakeHooks
) -> None:
    """A password policy violation is raised before the email is ever looked up."""
    with pytest.raises(PasswordRejected):
        flows.register(email=EMAIL, password="short")
    assert "load_user_by_email" not in hooks.calls


def test_register_refuses_when_registration_is_disabled(
    kms: FakeKms, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Registration with `registration_enabled=False` is a 403 `REGISTRATION_DISABLED`."""
    settings = make_settings(registration_enabled=False)
    disabled = IdentityFlows(settings, hooks, stores, TokenService(settings, kms))
    with pytest.raises(LoginRejected) as caught:
        disabled.register(email=EMAIL, password=PASSWORD)
    assert caught.value.status_code == 403
    assert caught.value.error_code == "REGISTRATION_DISABLED"


def test_register_does_not_sign_in_when_verification_is_required(
    kms: FakeKms, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """With verification required, registering creates the account but issues no session."""
    settings = make_settings(email_verification_required=True)
    strict = IdentityFlows(settings, hooks, stores, TokenService(settings, kms))
    with pytest.raises(LoginRejected) as caught:
        strict.register(email=EMAIL, password=PASSWORD)
    assert caught.value.error_code == "EMAIL_VERIFICATION_REQUIRED"
    assert hooks.by_email[EMAIL] in hooks.users


def test_login_succeeds_and_mints_a_token_bound_to_the_family(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    """A successful login mints an access token whose `sid` is the refresh family id."""
    seed_account(hooks, stores)
    result = flows.login(email=EMAIL, password=PASSWORD)

    settings = make_settings()
    claims = TokenService(settings, kms).verify_access_token(result.access_token)
    assert claims["sub"] == USER_ID
    assert claims["typ"] == "access"
    assert claims["sid"] == result.family_id
    assert claims["aud"] == AUDIENCE


def test_login_is_case_insensitive_on_the_email(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Login matches the account regardless of the email's case."""
    seed_account(hooks, stores)
    assert flows.login(email="PERSON@EXAMPLE.COM", password=PASSWORD).access_token


def test_wrong_password_is_rejected(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A wrong password is a 401 carrying the shared invalid credentials message."""
    seed_account(hooks, stores)
    with pytest.raises(LoginRejected) as caught:
        flows.login(email=EMAIL, password=OTHER_PASSWORD)
    assert caught.value.message == INVALID_CREDENTIALS_MESSAGE
    assert caught.value.status_code == 401


def test_unknown_email_and_wrong_password_are_indistinguishable(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A wrong password and an unknown email produce the same message, status and error code."""
    seed_account(hooks, stores)

    with pytest.raises(LoginRejected) as wrong:
        flows.login(email=EMAIL, password=OTHER_PASSWORD)
    with pytest.raises(LoginRejected) as unknown:
        flows.login(email="nobody@example.com", password=OTHER_PASSWORD)

    assert wrong.value.message == unknown.value.message
    assert wrong.value.status_code == unknown.value.status_code
    assert wrong.value.error_code == unknown.value.error_code


def test_both_login_failure_paths_spend_a_bcrypt_verification(
    flows: IdentityFlows,
    hooks: FakeHooks,
    stores: IdentityStores,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both the wrong password and unknown email paths run one real bcrypt verification."""
    import webbpulse.security as security

    calls: list[str] = []
    real = security.verify_password

    def counted(password: str, hashed: str | None) -> bool:
        """Record the hash each verification is handed, then verify for real."""
        calls.append(hashed or "")
        return real(password, hashed)

    monkeypatch.setattr(security, "verify_password", counted)
    seed_account(hooks, stores)

    with pytest.raises(LoginRejected):
        flows.login(email=EMAIL, password=OTHER_PASSWORD)
    after_wrong_password = len(calls)

    with pytest.raises(LoginRejected):
        flows.login(email="nobody@example.com", password=OTHER_PASSWORD)
    after_unknown_email = len(calls)

    assert after_wrong_password == 1
    assert after_unknown_email == 2
    assert calls[1].startswith("$2")


def test_a_user_with_no_password_credential_still_costs_a_bcrypt_round(
    flows: IdentityFlows, hooks: FakeHooks
) -> None:
    """Logging in to an account with no password credential fails with the shared message."""
    hooks.add(EMAIL, user_id=USER_ID)
    with pytest.raises(LoginRejected) as caught:
        flows.login(email=EMAIL, password=PASSWORD)
    assert caught.value.message == INVALID_CREDENTIALS_MESSAGE


def test_a_disabled_user_is_refused_by_the_hook(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A disabled user is refused by `may_authenticate`, which runs after the user lookup."""
    seed_account(hooks, stores, disabled=True)
    with pytest.raises(LoginRejected) as caught:
        flows.login(email=EMAIL, password=PASSWORD)
    assert caught.value.error_code == "DISABLED"
    assert hooks.calls.index("load_user_by_email") < hooks.calls.index("may_authenticate")


def test_login_records_success_and_failure(
    flows: IdentityFlows,
    hooks: FakeHooks,
    stores: IdentityStores,
    attempts: InMemoryLoginAttemptStore,
) -> None:
    """Each login writes an attempt row under both the email key and the IP key."""
    seed_account(hooks, stores)
    with pytest.raises(LoginRejected):
        flows.login(email=EMAIL, password=OTHER_PASSWORD, ip="203.0.113.9")
    flows.login(email=EMAIL, password=PASSWORD, ip="203.0.113.9")

    by_email = attempts.recent(email_key(EMAIL))
    assert [row.outcome for row in by_email] == ["success", "failure"]
    assert [row.outcome for row in attempts.recent(ip_key("203.0.113.9"))] == [
        "success",
        "failure",
    ]


def test_five_failures_lock_the_account_and_the_sixth_is_a_429(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """After five failures, even a correct password is a 429 with a retry-after."""
    seed_account(hooks, stores)
    for _ in range(5):
        with pytest.raises(LoginRejected):
            flows.login(email=EMAIL, password=OTHER_PASSWORD)

    with pytest.raises(RateLimited) as caught:
        flows.login(email=EMAIL, password=PASSWORD)
    assert caught.value.status_code == 429
    assert caught.value.retry_after >= 1


def test_a_correct_password_works_once_the_delay_has_elapsed(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Once the lockout delay has elapsed, the correct password signs in again."""
    seed_account(hooks, stores)
    for _ in range(5):
        with pytest.raises(LoginRejected):
            flows.login(email=EMAIL, password=OTHER_PASSWORD)

    later = datetime.now(UTC) + timedelta(minutes=20)
    assert flows.login(email=EMAIL, password=PASSWORD, now=later).access_token


def test_login_upgrades_a_weak_cost_factor(
    flows: IdentityFlows,
    hooks: FakeHooks,
    stores: IdentityStores,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A successful login rehashes a stored password whose cost factor is below the policy."""
    import webbpulse.security as security

    user = seed_account(hooks, stores)
    stored = stores.require_credentials().get(str(user["id"]), PASSWORD_CREDENTIAL_TYPE)
    assert stored is not None
    original = stored.secret
    assert original.startswith("$2b$04$")

    real_hash = security.hash_password
    real_needs = security.needs_rehash
    monkeypatch.setattr(
        security, "hash_password", lambda p, *, rounds=5: real_hash(p, rounds=rounds)
    )
    monkeypatch.setattr(
        security, "needs_rehash", lambda h, *, rounds=5: real_needs(h, rounds=rounds)
    )

    flows.login(email=EMAIL, password=PASSWORD)

    upgraded = stores.require_credentials().get(str(user["id"]), PASSWORD_CREDENTIAL_TYPE)
    assert upgraded is not None
    assert upgraded.secret != original
    assert upgraded.secret.startswith("$2b$05$")
    assert security.verify_password(PASSWORD, upgraded.secret)


@pytest.fixture
def sessions(stores: IdentityStores) -> SessionService:
    """Return a `SessionService` over the in-memory refresh token store."""
    return SessionService(make_settings(), stores.require_refresh_tokens())


def test_state_current_rotates(sessions: SessionService) -> None:
    """Rotating a current token issues the next generation in the same family."""
    first = sessions.start_family(USER_ID)
    result = sessions.rotate(first.token)
    assert result.outcome == "rotated"
    assert result.issued is not None
    assert result.issued.generation == first.generation + 1
    assert result.issued.family_id == first.family_id
    assert result.issued.token != first.token


def test_state_consumed_inside_the_grace_window_is_replayed(sessions: SessionService) -> None:
    """A second rotation inside the grace window replays a working token without revoking."""
    first = sessions.start_family(USER_ID)
    winner = sessions.rotate(first.token)
    assert winner.issued is not None

    loser = sessions.rotate(first.token)
    assert loser.outcome == "replayed"
    assert loser.issued is not None
    assert loser.issued.family_id == first.family_id
    assert sessions.rotate(winner.issued.token).outcome == "rotated"


def test_state_consumed_outside_the_grace_window_revokes_the_family(
    sessions: SessionService, stores: IdentityStores
) -> None:
    """Reusing a consumed token outside the grace window revokes the whole family."""
    first = sessions.start_family(USER_ID)
    winner = sessions.rotate(first.token)
    assert winner.issued is not None

    beyond = datetime.now(UTC) + timedelta(seconds=60)
    reuse = sessions.rotate(first.token, now=beyond)
    assert reuse.outcome == "reuse"
    assert reuse.revoked >= 2

    assert sessions.rotate(winner.issued.token, now=beyond).outcome == "revoked"


def test_state_revoked_is_refused_without_re_revoking(
    sessions: SessionService, stores: IdentityStores
) -> None:
    """Rotating a token from an already revoked family is refused without revoking again."""
    first = sessions.start_family(USER_ID)
    sessions.revoke_family(first.family_id)

    result = sessions.rotate(first.token)
    assert result.outcome == "revoked"
    assert result.revoked == 0


def test_state_expired_is_refused_and_the_family_is_revoked(sessions: SessionService) -> None:
    """Rotating an expired token is refused and revokes the family."""
    first = sessions.start_family(USER_ID)
    settings = make_settings()
    beyond = datetime.now(UTC) + settings.refresh_token_ttl + timedelta(seconds=1)

    result = sessions.rotate(first.token, now=beyond)
    assert result.outcome == "expired"
    assert result.revoked >= 1


def test_state_unknown_is_refused_and_creates_nothing(
    sessions: SessionService, stores: IdentityStores
) -> None:
    """Rotating an unknown token is refused, issues nothing and writes no row."""
    result = sessions.rotate("not a token anybody issued")
    assert result.outcome == "unknown"
    assert result.issued is None
    assert stores.require_refresh_tokens().get(hash_token("not a token anybody issued")) is None


def test_the_absolute_cap_ends_a_family_however_active_it_has_been(
    sessions: SessionService,
) -> None:
    """Steady rotation still ends at the family's absolute TTL, not just the rolling one."""
    settings = make_settings()
    start = datetime.now(UTC)
    issued = sessions.start_family(USER_ID, now=start)

    moment = start
    step = settings.refresh_token_ttl / 2
    token = issued.token
    for _ in range(20):
        moment += step
        result = sessions.rotate(token, now=moment)
        if result.outcome != "rotated":
            break
        assert result.issued is not None
        token = result.issued.token

    assert moment - start >= settings.refresh_absolute_ttl
    assert result.outcome == "expired"


def test_a_token_never_outlives_the_family_cap(sessions: SessionService) -> None:
    """Every rotated token expires no later than the family's absolute deadline."""
    settings = make_settings()
    start = datetime.now(UTC)
    issued = sessions.start_family(USER_ID, now=start)
    cap = start + settings.refresh_absolute_ttl

    moment = start
    token = issued.token
    step = settings.refresh_token_ttl / 2
    while moment + step < cap:
        moment += step
        result = sessions.rotate(token, now=moment)
        assert result.issued is not None
        token = result.issued.token
        assert result.issued.expires_at <= int(cap.timestamp())

    final = sessions.rotate(token, now=moment)
    assert final.issued is not None
    assert final.issued.expires_at <= int(cap.timestamp())


def test_a_zero_grace_window_makes_every_replay_reuse(stores: IdentityStores) -> None:
    """With `refresh_reuse_grace=0`, any replay of a consumed token is reuse."""
    settings = make_settings(refresh_reuse_grace=0)
    strict = SessionService(settings, stores.require_refresh_tokens())
    first = strict.start_family(USER_ID)
    strict.rotate(first.token)
    assert strict.rotate(first.token).outcome == "reuse"


def test_only_the_hash_is_stored(sessions: SessionService, stores: IdentityStores) -> None:
    """A refresh token record stores only the token's hash, never the token itself."""
    issued = sessions.start_family(USER_ID)
    record = stores.require_refresh_tokens().get(hash_token(issued.token))
    assert record is not None
    assert issued.token not in repr(record)
    assert record.token_hash == hash_token(issued.token)


def test_logout_revokes_the_whole_family(sessions: SessionService) -> None:
    """Revoking the presented token revokes every generation in its family."""
    first = sessions.start_family(USER_ID)
    rotated = sessions.rotate(first.token)
    assert rotated.issued is not None

    result = sessions.revoke_presented(rotated.issued.token)
    assert result.revoked == 2
    assert sessions.rotate(rotated.issued.token).outcome == "revoked"


def test_logout_all_revokes_every_family_for_a_user(sessions: SessionService) -> None:
    """Revoking all families for a user leaves another user's session untouched."""
    families = [sessions.start_family(USER_ID) for _ in range(3)]
    other = sessions.start_family("someone-else")

    revoked = sessions.revoke_all_for_user(USER_ID)
    assert revoked == 3
    for issued in families:
        assert sessions.rotate(issued.token).outcome == "revoked"
    assert sessions.rotate(other.token).outcome == "rotated"


def test_logout_all_by_family_id_is_the_path_dynamodb_can_take(
    sessions: SessionService,
) -> None:
    """Revoking all families for a user works when the caller supplies the family ids."""
    families = [sessions.start_family(USER_ID) for _ in range(2)]
    revoked = sessions.revoke_all_for_user(
        USER_ID, family_ids=[issued.family_id for issued in families]
    )
    assert revoked == 2


def test_refresh_mints_a_new_access_token_and_rotates_the_cookie(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Refreshing mints a new access token and a new refresh token in the same family."""
    seed_account(hooks, stores)
    login = flows.login(email=EMAIL, password=PASSWORD)
    refreshed = flows.refresh(login.refresh_token)

    assert refreshed.access_token
    assert refreshed.refresh_token != login.refresh_token
    assert refreshed.family_id == login.family_id


def test_refresh_reuse_is_the_same_401_as_every_other_refusal(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A reused refresh token and an unknown one both give the same 401."""
    seed_account(hooks, stores)
    login = flows.login(email=EMAIL, password=PASSWORD)
    flows.refresh(login.refresh_token)

    with pytest.raises(LoginRejected) as reuse:
        flows.refresh(login.refresh_token, now=datetime.now(UTC) + timedelta(seconds=60))
    with pytest.raises(LoginRejected) as unknown:
        flows.refresh("never issued")

    assert reuse.value.message == unknown.value.message
    assert reuse.value.status_code == unknown.value.status_code == 401


def test_refresh_re_checks_may_authenticate_and_revokes_on_refusal(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Refresh re-runs `may_authenticate` and revokes the family when it refuses."""
    user = seed_account(hooks, stores)
    login = flows.login(email=EMAIL, password=PASSWORD)

    hooks.users[str(user["id"])]["disabled"] = True
    with pytest.raises(LoginRejected) as caught:
        flows.refresh(login.refresh_token)
    assert caught.value.error_code == "DISABLED"

    hooks.users[str(user["id"])]["disabled"] = False
    with pytest.raises(LoginRejected):
        flows.refresh(login.refresh_token)


def test_refresh_revokes_a_family_whose_user_has_gone(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Refreshing after the user has been deleted is refused."""
    user = seed_account(hooks, stores)
    login = flows.login(email=EMAIL, password=PASSWORD)
    del hooks.users[str(user["id"])]

    with pytest.raises(LoginRejected):
        flows.refresh(login.refresh_token)


def test_change_password_requires_the_current_one(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Changing a password with the wrong current password is refused."""
    seed_account(hooks, stores)
    with pytest.raises(LoginRejected):
        flows.change_password(
            user_id=USER_ID, current_password=OTHER_PASSWORD, new_password="a new one entirely"
        )


def test_change_password_applies_the_policy_to_the_new_password(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """The password policy applies to the new password on change."""
    seed_account(hooks, stores)
    with pytest.raises(PasswordRejected):
        flows.change_password(user_id=USER_ID, current_password=PASSWORD, new_password="short")


def test_change_password_revokes_other_sessions_but_keeps_the_callers(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A password change revokes other families, keeps `keep_family_id`, and swaps the password."""
    seed_account(hooks, stores)
    elsewhere = flows.login(email=EMAIL, password=PASSWORD)
    here = flows.login(email=EMAIL, password=PASSWORD)

    flows.change_password(
        user_id=USER_ID,
        current_password=PASSWORD,
        new_password=OTHER_PASSWORD,
        keep_family_id=here.family_id,
    )

    with pytest.raises(LoginRejected):
        flows.refresh(elsewhere.refresh_token)
    assert flows.refresh(here.refresh_token).access_token

    assert flows.login(email=EMAIL, password=OTHER_PASSWORD).access_token
    with pytest.raises(LoginRejected):
        flows.login(email=EMAIL, password=PASSWORD)


def test_change_password_on_an_account_with_no_credential_still_costs_a_bcrypt_round(
    flows: IdentityFlows, hooks: FakeHooks
) -> None:
    """Changing the password on an account with no credential is refused."""
    hooks.add(EMAIL, user_id=USER_ID)
    with pytest.raises(LoginRejected):
        flows.change_password(
            user_id=USER_ID, current_password=PASSWORD, new_password=OTHER_PASSWORD
        )


@pytest.fixture
def client(
    kms: FakeKms,
    hooks: FakeHooks,
    stores: IdentityStores,
    attempts: InMemoryLoginAttemptStore,
) -> Iterator[TestClient]:
    """Return a test client over an app mounting the identity router, with the limiter off."""
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
            limiter_enabled=False,
        )
    )
    with TestClient(app, base_url="https://api.example.com") as test_client:
        yield test_client


def test_the_documents_alone_mount_without_hooks_or_stores(kms: FakeKms) -> None:
    """Without hooks or stores, only the document, health and availability routes mount."""
    router = build_identity_router(make_settings(), kms_client=kms)
    paths = {route.path for route in router.routes}  # type: ignore[attr-defined]
    assert paths == {
        "/api/auth/.well-known/openid-configuration",
        "/api/auth/.well-known/jwks.json",
        "/api/auth/health",
        "/api/auth/oauth/providers",
        "/api/auth/passkeys/availability",
    }


def test_the_flows_mount_when_hooks_and_stores_are_supplied(
    kms: FakeKms, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Supplying hooks and stores mounts the six flow routes alongside the documents."""
    router = build_identity_router(make_settings(), hooks, stores, kms_client=kms)
    paths = {route.path for route in router.routes}  # type: ignore[attr-defined]
    assert paths == {
        "/api/auth/.well-known/openid-configuration",
        "/api/auth/.well-known/jwks.json",
        "/api/auth/health",
        "/api/auth/oauth/providers",
        "/api/auth/passkeys/availability",
        "/api/auth/register",
        "/api/auth/login",
        "/api/auth/password",
        "/api/auth/refresh",
        "/api/auth/logout",
        "/api/auth/logout-all",
    }


def test_an_origin_issuer_mounts_every_route_at_the_origin(
    kms: FakeKms, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """An issuer with no path mounts every route at the origin."""
    settings = make_settings(issuer="https://identity.example.com")
    router = build_identity_router(settings, hooks, stores, kms_client=kms)
    paths = {route.path for route in router.routes}  # type: ignore[attr-defined]
    assert paths == {
        "/.well-known/openid-configuration",
        "/.well-known/jwks.json",
        "/health",
        "/oauth/providers",
        "/passkeys/availability",
        "/register",
        "/login",
        "/password",
        "/refresh",
        "/logout",
        "/logout-all",
    }


@pytest.mark.parametrize(
    "issuer",
    ["https://api.staging.example.com/api/auth", "https://identity.example.com"],
)
def test_the_advertised_jwks_uri_resolves_to_the_served_jwks(issuer: str, kms: FakeKms) -> None:
    """The `jwks_uri` the served discovery document advertises resolves to a served JWKS."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from webbpulse.identity.tokens import DISCOVERY_PATH

    settings = make_settings(issuer=issuer)
    app = FastAPI()
    app.include_router(build_identity_router(settings, kms_client=kms))

    origin = urlsplit(issuer)
    base_url = f"{origin.scheme}://{origin.netloc}"
    client = TestClient(app, base_url=base_url)

    discovery = client.get(f"{settings.issuer}{DISCOVERY_PATH}")
    assert discovery.status_code == 200
    assert discovery.json()["issuer"] == settings.issuer

    advertised = discovery.json()["jwks_uri"]
    assert advertised == settings.jwks_url
    jwks = client.get(advertised)
    assert jwks.status_code == 200
    assert jwks.json()["keys"]


@pytest.mark.parametrize(
    ("issuer", "prefix"),
    [
        ("https://api.staging.example.com/api/auth", "/api/auth"),
        ("https://identity.example.com", ""),
    ],
)
def test_the_flow_routes_sit_under_the_same_prefix_as_the_documents(
    issuer: str, prefix: str, kms: FakeKms, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Flow routes and document routes share the prefix derived from the issuer."""
    settings = make_settings(issuer=issuer)
    router = build_identity_router(settings, hooks, stores, kms_client=kms)
    paths = {route.path for route in router.routes}  # type: ignore[attr-defined]

    assert identity_prefix(settings) == prefix
    assert f"{prefix}/login" in paths
    assert f"{prefix}/refresh" in paths
    assert f"{prefix}/.well-known/jwks.json" in paths
    assert all(path.startswith(prefix) for path in paths)


def test_the_flow_prefix_matches_the_cookie_path() -> None:
    """The mount prefix equals `cookie_path`, so the refresh route sits under the cookie scope."""
    from webbpulse.identity.router import REFRESH_PATH, identity_prefix

    settings = make_settings()
    prefix = identity_prefix(settings)
    assert prefix == "/api/auth"
    assert settings.cookie_path == prefix
    assert f"{prefix}{REFRESH_PATH}".startswith(settings.cookie_path)


def test_an_origin_issuer_scopes_the_cookie_to_the_root() -> None:
    """A path-less issuer gives an empty mount prefix and a cookie path of `/`."""
    settings = make_settings(issuer="https://identity.example.com")
    assert identity_prefix(settings) == ""
    assert settings.cookie_path == "/"


def test_an_explicit_cookie_path_overrides_the_issuer() -> None:
    """An explicitly configured `cookie_path` is kept, whatever the issuer's path is."""
    settings = make_settings(cookie_path="/")
    assert identity_prefix(settings) == "/api/auth"
    assert settings.cookie_path == "/"


def test_login_sets_an_httponly_secure_samesite_lax_cookie(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Login returns a bearer body with no refresh token and sets a scoped secure cookie."""
    seed_account(hooks, stores)
    response = client.post("/api/auth/login", json={"email": EMAIL, "password": PASSWORD})

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 600
    assert "refresh_token" not in body

    header = response.headers["set-cookie"]
    assert "wp_refresh=" in header
    assert "HttpOnly" in header
    assert "Secure" in header
    assert "SameSite=lax" in header
    assert "Path=/api/auth" in header


def test_login_failure_uses_the_shared_error_envelope(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A failed login answers 401 in the shared error envelope and sets no cookie."""
    seed_account(hooks, stores)
    response = client.post("/api/auth/login", json={"email": EMAIL, "password": OTHER_PASSWORD})
    assert response.status_code == 401
    body = response.json()
    assert body["success"] is False
    assert body["status"] == 401
    assert body["message"] == INVALID_CREDENTIALS_MESSAGE
    assert body["error_code"] == "INVALID_CREDENTIALS"
    assert "request_id" in body
    assert "set-cookie" not in response.headers


def test_unknown_email_and_wrong_password_are_byte_identical_over_http(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Over HTTP, a wrong password and an unknown email match in status, headers and body."""
    seed_account(hooks, stores)
    wrong = client.post("/api/auth/login", json={"email": EMAIL, "password": OTHER_PASSWORD})
    unknown = client.post(
        "/api/auth/login", json={"email": "nobody@example.com", "password": OTHER_PASSWORD}
    )

    assert wrong.status_code == unknown.status_code
    left = {k: v for k, v in wrong.json().items() if k != "request_id"}
    right = {k: v for k, v in unknown.json().items() if k != "request_id"}
    assert left == right

    volatile = {"date", "content-length", "x-request-id"}
    assert {k.lower() for k in wrong.headers} - volatile == {
        k.lower() for k in unknown.headers
    } - volatile


def test_register_returns_the_same_shape_for_a_taken_address(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Registering a taken address answers the ordinary success shape with no session."""
    fresh = client.post("/api/auth/register", json={"email": EMAIL, "password": PASSWORD})
    assert fresh.status_code == 201
    assert fresh.json()["registered"] is True

    again = client.post("/api/auth/register", json={"email": EMAIL, "password": OTHER_PASSWORD})
    assert again.status_code == 200
    assert again.json() == {"registered": True}
    assert "set-cookie" not in again.headers


def test_a_short_password_is_a_422_with_a_specific_reason(client: TestClient) -> None:
    """A short password on register is a 422 with the `PASSWORD_TOO_SHORT` error code."""
    response = client.post("/api/auth/register", json={"email": EMAIL, "password": "short"})
    assert response.status_code == 422
    assert response.json()["error_code"] == "PASSWORD_TOO_SHORT"


def test_refresh_rotates_the_cookie_over_http(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Refreshing over HTTP returns a new access token and replaces the refresh cookie."""
    seed_account(hooks, stores)
    login = client.post("/api/auth/login", json={"email": EMAIL, "password": PASSWORD})
    first_cookie = client.cookies["wp_refresh"]

    refreshed = client.post("/api/auth/refresh")
    assert refreshed.status_code == 200
    assert refreshed.json()["access_token"] != login.json()["access_token"]
    assert client.cookies["wp_refresh"] != first_cookie


def test_refresh_clears_the_cookie_on_every_refusal(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A refused refresh answers 401 and clears the refresh cookie."""
    seed_account(hooks, stores)
    client.post("/api/auth/login", json={"email": EMAIL, "password": PASSWORD})
    client.cookies.set("wp_refresh", "not a token anybody issued", path="/api/auth")

    response = client.post("/api/auth/refresh")
    assert response.status_code == 401
    assert (
        'wp_refresh=""' in response.headers["set-cookie"]
        or "wp_refresh=;" in (response.headers["set-cookie"])
    )


def test_refresh_with_no_cookie_is_a_401(client: TestClient) -> None:
    """Refreshing with no cookie is a 401 `NO_SESSION`."""
    response = client.post("/api/auth/refresh")
    assert response.status_code == 401
    assert response.json()["error_code"] == "NO_SESSION"


def test_a_cross_site_fetch_is_refused_on_refresh_and_logout(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A `Sec-Fetch-Site: cross-site` refresh or logout is a 403 and leaves the session alive."""
    seed_account(hooks, stores)
    client.post("/api/auth/login", json={"email": EMAIL, "password": PASSWORD})

    for path in ("/api/auth/refresh", "/api/auth/logout"):
        response = client.post(path, headers={"Sec-Fetch-Site": "cross-site"})
        assert response.status_code == 403
        assert response.json()["error_code"] == "CROSS_SITE_REQUEST"

    assert client.post("/api/auth/refresh").status_code == 200


def test_a_missing_sec_fetch_site_header_is_allowed(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A request with no `Sec-Fetch-Site` header is allowed through."""
    seed_account(hooks, stores)
    client.post("/api/auth/login", json={"email": EMAIL, "password": PASSWORD})
    assert client.post("/api/auth/refresh").status_code == 200


def test_same_site_and_same_origin_are_allowed(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """`Sec-Fetch-Site` values of `same-origin` and `same-site` are both allowed."""
    seed_account(hooks, stores)
    client.post("/api/auth/login", json={"email": EMAIL, "password": PASSWORD})
    for value in ("same-origin", "same-site"):
        assert (
            client.post("/api/auth/refresh", headers={"Sec-Fetch-Site": value}).status_code == 200
        )


def test_logout_is_idempotent_and_always_succeeds(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Logout answers 200 every time, and the revoked family cannot be refreshed afterwards."""
    seed_account(hooks, stores)
    client.post("/api/auth/login", json={"email": EMAIL, "password": PASSWORD})

    first = client.post("/api/auth/logout")
    assert first.status_code == 200
    assert first.json() == {"signed_out": True}

    second = client.post("/api/auth/logout")
    assert second.status_code == 200

    assert client.post("/api/auth/refresh").status_code == 401


def test_logout_all_needs_a_verified_token(client: TestClient) -> None:
    """Logout-all and change-password are 401 without a bearer token."""
    assert client.post("/api/auth/logout-all").status_code == 401
    assert client.post("/api/auth/password", json={}).status_code == 401


def test_change_password_and_logout_all_read_the_subject_from_the_token(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Change-password takes its subject from the verified access token, not the body."""
    seed_account(hooks, stores)
    login = client.post("/api/auth/login", json={"email": EMAIL, "password": PASSWORD})
    access = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {access}"}

    changed = client.post(
        "/api/auth/password",
        json={"current_password": PASSWORD, "new_password": OTHER_PASSWORD},
        headers=headers,
    )
    assert changed.status_code == 200
    assert changed.json() == {"changed": True}

    assert (
        client.post(
            "/api/auth/login", json={"email": EMAIL, "password": OTHER_PASSWORD}
        ).status_code
        == 200
    )


def test_a_forged_bearer_token_is_not_accepted(client: TestClient) -> None:
    """A forged bearer token is a 401 `NOT_AUTHENTICATED`."""
    response = client.post("/api/auth/logout-all", headers={"Authorization": "Bearer not.a.token"})
    assert response.status_code == 401
    assert response.json()["error_code"] == "NOT_AUTHENTICATED"


def test_the_rate_limits_match_the_table_in_section_five_one() -> None:
    """The login, refresh and register rate limit constants hold their expected values."""
    from webbpulse.identity.router import (
        LOGIN_EMAIL_LIMIT,
        LOGIN_IP_LIMIT,
        REFRESH_IP_LIMIT,
        REGISTER_IP_LIMIT,
    )

    assert LOGIN_IP_LIMIT == (20, 900)
    assert LOGIN_EMAIL_LIMIT == (10, 900)
    assert REFRESH_IP_LIMIT == (120, 900)
    assert REGISTER_IP_LIMIT == (5, 3600)


def test_a_rate_limited_login_answers_429_with_retry_after(
    kms: FakeKms, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """The login route carries the limiter dependency, answering 429 with `Retry-After`."""
    from webbpulse.http import register_error_handlers
    from webbpulse.ratelimit import RateLimitDecision

    class AlwaysLimited:
        """A rate limiter that refuses every request."""

        def check(self, identity: str, *, limit: int, window_seconds: int) -> RateLimitDecision:
            """Return a decision refusing the request with a 42 second reset."""
            return RateLimitDecision(
                allowed=False,
                limit=limit,
                remaining=0,
                reset_after=42,
                window_seconds=window_seconds,
                failed_open=False,
            )

    settings = make_settings()
    app = FastAPI()
    register_error_handlers(app, error_codes=True)

    import webbpulse.ratelimit as ratelimit

    original = ratelimit.RateLimiter
    ratelimit.RateLimiter = lambda **_: AlwaysLimited()  # type: ignore[assignment, misc]
    try:
        app.include_router(build_identity_router(settings, hooks, stores, kms_client=kms))
    finally:
        ratelimit.RateLimiter = original  # type: ignore[misc]

    with TestClient(app, base_url="https://api.example.com") as limited:
        response = limited.post("/api/auth/login", json={"email": EMAIL, "password": PASSWORD})
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "42"


def test_the_documents_still_answer_when_the_flows_are_mounted(
    client: TestClient,
) -> None:
    """The document and health routes still answer anonymously with the flows mounted."""
    assert client.get("/api/auth/.well-known/jwks.json").status_code == 200
    assert client.get("/api/auth/.well-known/openid-configuration").status_code == 200
    assert client.get("/api/auth/health").json()["status"] == "healthy"
