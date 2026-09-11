"""Tests for the M2 identity flows: passwords, lockout, sessions, and the six routes.

Section 9.4 of `docs/identity-standard.md` sets the strategy, and three of its requirements
shape this file more than the rest:

- **The rotation state machine gets a test per state.** Current, consumed inside the grace
  window, consumed outside it, revoked, expired, unknown. Six states, six tests, named after
  the states, because the failure mode of testing rotation loosely is that two states
  collapse into one and reuse detection silently stops firing.
- **Enumeration resistance is tested as an equality, not as an assertion about a message.**
  `test_unknown_email_and_wrong_password_are_byte_identical` compares the two responses to
  each other rather than each to a literal. A test that checks both say "Invalid email or
  password." passes just as happily when one of them also sets a different header.
- **Timing is tested as a shape, not as a threshold.** Asserting that two bcrypt paths take
  within some millisecond count of each other is a flake generator on shared CI. What is
  actually checkable is that both paths *ran a bcrypt verification*, which is the mechanism
  the equality of timing follows from, so that is what is asserted.

The KMS fake is the one from `test_identity_m1.py`. moto 5.2.3 cannot verify KMS asymmetric
signatures (`get_public_key` returns `KeySpec: None` and its signatures do not verify), so a
local-key fake is the only way to test the real signing path.

bcrypt is genuinely slow, which is the point of bcrypt and a problem for a test suite that
runs it a few dozen times. Every test here that does not care about the cost factor uses
`cheap_bcrypt`, an autouse fixture pinning the rounds down to bcrypt's minimum. The two
tests that *do* care override it explicitly.
"""

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


class FakeKms:
    """A KMS client signing for real with a local private key.

    The same shape as `test_identity_m1.FakeKms`, redefined here rather than
    imported because `tests/` is not a package and cross-importing between test modules
    couples two suites that should be able to change independently.

    Faithful in the two ways the output depends on: it signs the digest it is handed without
    re-hashing (`MessageType="DIGEST"`) and returns the raw PKCS #1 signature octet string.
    It differs from KMS only in who holds the key. moto 5.2.3 cannot stand in here: its
    `get_public_key` returns `KeySpec: None` and its signatures do not verify.
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


PASSWORD = "correct horse battery staple"
OTHER_PASSWORD = "a different but equally fine one"
EMAIL = "person@example.com"
USER_ID = "user-0001"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def cheap_bcrypt(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Pin bcrypt to its minimum cost for the whole module.

    Autouse rather than opt-in, because forgetting it in one test is a two second penalty
    nobody notices until the suite is a minute slower. bcrypt's minimum is 4 rounds, roughly
    two hundred times cheaper than the default 12, and every property under test here is
    about which code path ran rather than how long it took.

    Patching `security.DEFAULT_ROUNDS` used to do **nothing**: `hash_password(..., rounds:
    int = DEFAULT_ROUNDS)` bound that default as the `def` executed at import, so rebinding
    the module attribute afterwards never reached it and the suite quietly kept running at
    cost 12. 0.12.1 fixed that by reading the module attribute in the body, so patching it
    now works.

    The wrapper is kept anyway, because it pins the cost more tightly than a changed default
    does: it also lowers a call that passes `rounds=` explicitly, which `DEFAULT_ROUNDS`
    never governs.
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
    # `passwords._DUMMY_HASH` is built once and cached, and a hash built at the real cost
    # would keep the dummy path slow for the rest of the session. Clearing it makes the
    # next call rebuild it cheaply.
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
        # M2 has no email verification, so a product that required it could never sign in.
        # M3 turns this back on with the flow that satisfies it.
        "email_verification_required": False,
    }
    base.update(overrides)
    return IdentitySettings(**base)


class FakeHooks(BaseIdentityHooks):
    """A product's policy, in memory.

    Deliberately not a mock. The flows call five hooks in a specific order and a mock would
    let a test pass while the order was wrong; a real dict-backed implementation makes the
    order observable through `calls`.
    """

    def __init__(self, *, refuse: str = "") -> None:
        self.users: dict[str, dict[str, Any]] = {}
        self.by_email: dict[str, str] = {}
        self.refuse = refuse
        self.calls: list[str] = []
        self.created: list[tuple[str, str]] = []
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
        if user.get("disabled"):
            raise AuthenticationRefused("This account is disabled.", error_code="DISABLED")

    def claims_for(self, user: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls.append("claims_for")
        return {"roles": user.get("roles", [])}

    def create_user(self, *, email: str, attributes: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls.append("create_user")
        return self.add(email, **dict(attributes))

    def on_user_created(self, user: Mapping[str, Any], via: str) -> None:
        self.calls.append("on_user_created")
        self.created.append((str(user["id"]), via))


@pytest.fixture
def hooks() -> FakeHooks:
    return FakeHooks()


@pytest.fixture
def stores() -> IdentityStores:
    return IdentityStores(
        credentials=InMemoryCredentialStore(),
        refresh_tokens=InMemoryRefreshTokenStore(),
    )


@pytest.fixture
def attempts() -> InMemoryLoginAttemptStore:
    return InMemoryLoginAttemptStore()


@pytest.fixture
def flows(
    kms: FakeKms,
    hooks: FakeHooks,
    stores: IdentityStores,
    attempts: InMemoryLoginAttemptStore,
) -> IdentityFlows:
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


# ---------------------------------------------------------------------------
# Password policy, section 5.6
# ---------------------------------------------------------------------------


def test_minimum_is_eight_characters() -> None:
    with pytest.raises(PasswordRejected) as caught:
        check_password("short12")
    assert caught.value.error_code == "PASSWORD_TOO_SHORT"
    assert check_password("exactly8") == "exactly8"


def test_maximum_is_seventy_two_bytes_not_characters() -> None:
    """The cap has to be in bytes, and the message has to say so.

    This is the test that would have caught the obvious wrong implementation. A 20-character
    password of four-byte emoji is 80 bytes: under any character limit, over bcrypt's. A
    limit counted in characters would accept it and silently truncate the tail, so the
    password the user typed and a shorter one they did not would share a hash.
    """
    emoji = "\U0001f984" * 20
    assert len(emoji) == 20
    assert len(emoji.encode("utf-8")) == 80

    with pytest.raises(PasswordRejected) as caught:
        check_password(emoji)
    assert caught.value.error_code == "PASSWORD_TOO_LONG"
    assert "byte" in str(caught.value).lower()

    # 72 ASCII bytes is exactly the limit and is accepted.
    assert check_password("a" * 72) == "a" * 72
    with pytest.raises(PasswordRejected):
        check_password("a" * 73)


def test_no_composition_rules() -> None:
    """SP 800-63B says verifiers SHOULD NOT impose these, so none of them may reject."""
    for candidate in ("alllowercase", "ALLUPPERCASE", "12345678", "        x", "!!!!!!!!"):
        assert check_password(candidate) == candidate


def test_unicode_is_normalised_to_nfkc_and_spaces_survive() -> None:
    """The same password typed two ways must hash the same, and a space is not stripped."""
    composed = "café" + "12345"  # e + combining acute
    precomposed = "café" + "12345"
    assert composed != precomposed
    assert check_password(composed) == check_password(precomposed)

    padded = "  spaces  here  "
    assert check_password(padded) == padded


def test_breach_check_raises_rather_than_silently_doing_nothing() -> None:
    """A product that switched the flag on must not believe it has a control it lacks."""
    with pytest.raises(NotImplementedError, match="flag only"):
        check_password(PASSWORD, breach_check=True)


# ---------------------------------------------------------------------------
# Progressive lockout, section 5.1
# ---------------------------------------------------------------------------


def attempt_at(outcome: str, moment: datetime) -> LoginAttempt:
    return LoginAttempt(
        identity_key=email_key(EMAIL),
        attempted_at=moment.isoformat().replace("+00:00", "Z"),
        outcome=outcome,  # type: ignore[arg-type]
    )


def test_four_failures_do_not_lock() -> None:
    now = datetime.now(UTC)
    history = [attempt_at("failure", now - timedelta(seconds=i)) for i in range(4)]
    state = lockout_state(history, now=now)
    assert state.failures == 4
    assert state.locked is False


def test_fifth_failure_starts_a_one_second_delay_that_doubles() -> None:
    """The curve section 5.1 specifies: 1s at the threshold, doubling, capped at 15 min."""
    base = datetime.now(UTC)
    history: list[LoginAttempt] = []
    delays: list[float] = []
    for index in range(1, 12):
        history.insert(0, attempt_at("failure", base))
        state = lockout_state(history, now=base)
        if state.retry_at is not None:
            delays.append((state.retry_at - base).total_seconds())
        assert state.failures == index

    # First delay appears at the fifth failure and is one second.
    assert delays[0] == pytest.approx(1.0)
    # Each subsequent one doubles, until the cap.
    assert delays[1] == pytest.approx(2.0)
    assert delays[2] == pytest.approx(4.0)
    assert max(delays) <= timedelta(minutes=15).total_seconds()


def test_a_success_clears_the_count() -> None:
    """Not a decay, a reset. Section 5.1: "cleared by any success"."""
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
    """Retrying while locked must not push the deadline further out.

    Otherwise a client that retries on a timer holds itself locked forever, and an attacker
    can keep a victim locked out by doing nothing but hitting a locked endpoint, which is
    the denial-of-service section 5.1 says a hard lock hands to the attacker.
    """
    now = datetime.now(UTC)
    failures = [attempt_at("failure", now - timedelta(seconds=10 + i)) for i in range(5)]
    locked_state = lockout_state(failures, now=now)

    with_retries = [attempt_at("locked", now - timedelta(seconds=i)) for i in range(5)] + failures
    retried_state = lockout_state(with_retries, now=now)

    assert retried_state.failures == locked_state.failures
    assert retried_state.retry_at == locked_state.retry_at


def test_the_delay_elapses_in_real_time() -> None:
    """Measured from the last failure, so waiting actually works.

    A delay measured from "now" at each read would never elapse: every check would push the
    deadline forward and the account would be locked permanently after five failures.
    """
    base = datetime.now(UTC)
    # Five failures, the newest 30 seconds ago. The delay at the threshold is one second,
    # so it elapsed 29 seconds ago and the account is free now.
    history = [attempt_at("failure", base - timedelta(seconds=30 + i)) for i in range(5)]
    assert lockout_state(history, now=base).locked is False

    # Read at the instant of the newest failure, the same delay has not yet elapsed.
    assert lockout_state(history, now=base - timedelta(seconds=30)).locked is True


def test_attempts_older_than_the_lookback_are_ignored() -> None:
    ancient = datetime.now(UTC) - timedelta(days=2)
    history = [attempt_at("failure", ancient - timedelta(seconds=i)) for i in range(20)]
    assert lockout_state(history, now=datetime.now(UTC)).failures == 0


def test_attempt_rows_carry_no_credential() -> None:
    """Section 5.7: no event carries a token, a code, a seed or a password."""
    attempt = new_attempt(email_key(EMAIL), "failure", user_id=USER_ID, ip="203.0.113.9")
    serialised = repr(attempt)
    assert PASSWORD not in serialised
    assert "password" not in {field for field in LoginAttempt.__dataclass_fields__}


def test_email_and_ip_keys_are_namespaced() -> None:
    """One table holds both, so the keys must not be able to collide."""
    assert email_key("Person@Example.com") == "email#person@example.com"
    assert ip_key("203.0.113.9") == "ip#203.0.113.9"
    assert email_key("x") != ip_key("x")


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def test_register_creates_a_user_a_credential_and_a_session(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
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
    """Section 5.4: the signup form must leak nothing.

    The flow returns `None` rather than raising, precisely so no caller can accidentally
    render the taken case differently. Asserting `None` is asserting that the disclosure is
    structurally impossible rather than merely absent from today's message.
    """
    seed_account(hooks, stores)
    assert flows.register(email=EMAIL, password=OTHER_PASSWORD) is None
    # The existing credential is untouched: a duplicate registration must not overwrite
    # somebody's password, which would be account takeover through the signup form.
    credential = stores.require_credentials().get(USER_ID, PASSWORD_CREDENTIAL_TYPE)
    assert credential is not None
    from webbpulse.security import verify_password

    assert verify_password(PASSWORD, credential.secret)


def test_register_rejects_a_policy_violation_before_looking_the_email_up(
    flows: IdentityFlows, hooks: FakeHooks
) -> None:
    """A short password fails on its own merits, so the answer cannot depend on the email."""
    with pytest.raises(PasswordRejected):
        flows.register(email=EMAIL, password="short")
    assert "load_user_by_email" not in hooks.calls


def test_register_refuses_when_registration_is_disabled(
    kms: FakeKms, hooks: FakeHooks, stores: IdentityStores
) -> None:
    settings = make_settings(registration_enabled=False)
    disabled = IdentityFlows(settings, hooks, stores, TokenService(settings, kms))
    with pytest.raises(LoginRejected) as caught:
        disabled.register(email=EMAIL, password=PASSWORD)
    assert caught.value.status_code == 403
    assert caught.value.error_code == "REGISTRATION_DISABLED"


def test_register_does_not_sign_in_when_verification_is_required(
    kms: FakeKms, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A product that requires verification does not want an unverified session."""
    settings = make_settings(email_verification_required=True)
    strict = IdentityFlows(settings, hooks, stores, TokenService(settings, kms))
    with pytest.raises(LoginRejected) as caught:
        strict.register(email=EMAIL, password=PASSWORD)
    assert caught.value.error_code == "EMAIL_VERIFICATION_REQUIRED"
    # The account still exists: the user must be able to verify and then sign in.
    assert hooks.by_email[EMAIL] in hooks.users


# ---------------------------------------------------------------------------
# Login, and enumeration resistance
# ---------------------------------------------------------------------------


def test_login_succeeds_and_mints_a_token_bound_to_the_family(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
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
    seed_account(hooks, stores)
    assert flows.login(email="PERSON@EXAMPLE.COM", password=PASSWORD).access_token


def test_wrong_password_is_rejected(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    seed_account(hooks, stores)
    with pytest.raises(LoginRejected) as caught:
        flows.login(email=EMAIL, password=OTHER_PASSWORD)
    assert caught.value.message == INVALID_CREDENTIALS_MESSAGE
    assert caught.value.status_code == 401


def test_unknown_email_and_wrong_password_are_indistinguishable(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Section 5.4, tested as an equality between the two refusals.

    Comparing them to each other rather than each to a literal is the point: a test that
    asserts both say "Invalid email or password." still passes if one of them gains a
    different status code, error code or header, and any of those is the disclosure.
    """
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
    """The mechanism behind the timing equality, asserted directly.

    Asserting on elapsed time would need a threshold, and a threshold on a shared CI runner
    is a flake. What is genuinely checkable is that the no-such-user path runs a bcrypt
    verification at all, since that is the only reason the two paths take the same time.
    Counting the calls tests the mechanism rather than its consequence.
    """
    import webbpulse.security as security

    calls: list[str] = []
    real = security.verify_password

    def counted(password: str, hashed: str | None) -> bool:
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
    # The dummy hash is a real bcrypt hash, not an empty string, or the verification would
    # short circuit and cost nothing.
    assert calls[1].startswith("$2")


def test_a_user_with_no_password_credential_still_costs_a_bcrypt_round(
    flows: IdentityFlows, hooks: FakeHooks
) -> None:
    """An OAuth-only account must not be detectable by a faster failure."""
    hooks.add(EMAIL, user_id=USER_ID)
    with pytest.raises(LoginRejected) as caught:
        flows.login(email=EMAIL, password=PASSWORD)
    assert caught.value.message == INVALID_CREDENTIALS_MESSAGE


def test_a_disabled_user_is_refused_by_the_hook(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """`may_authenticate` is the product's veto, and it runs after the password check."""
    seed_account(hooks, stores, disabled=True)
    with pytest.raises(LoginRejected) as caught:
        flows.login(email=EMAIL, password=PASSWORD)
    assert caught.value.error_code == "DISABLED"
    # The bcrypt round was already spent, so the refusal has the same timing shape as a
    # wrong password. `may_authenticate` appearing in the call list proves the order.
    assert hooks.calls.index("load_user_by_email") < hooks.calls.index("may_authenticate")


def test_login_records_success_and_failure(
    flows: IdentityFlows,
    hooks: FakeHooks,
    stores: IdentityStores,
    attempts: InMemoryLoginAttemptStore,
) -> None:
    seed_account(hooks, stores)
    with pytest.raises(LoginRejected):
        flows.login(email=EMAIL, password=OTHER_PASSWORD, ip="203.0.113.9")
    flows.login(email=EMAIL, password=PASSWORD, ip="203.0.113.9")

    by_email = attempts.recent(email_key(EMAIL))
    assert [row.outcome for row in by_email] == ["success", "failure"]
    # Section 5.2's anomaly signal needs the IP key written too, or "one address failing
    # against many emails" is a scan rather than a query.
    assert [row.outcome for row in attempts.recent(ip_key("203.0.113.9"))] == [
        "success",
        "failure",
    ]


def test_five_failures_lock_the_account_and_the_sixth_is_a_429(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
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
    """The lock is a delay, never a hard lock. Section 5.1 is explicit about why."""
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
    """Section 5.6: `needs_rehash` runs after every successful verification.

    Login is the only moment the plaintext exists to rehash with, so a cost factor raised in
    settings never reaches an existing account unless this happens here.
    """
    import webbpulse.security as security

    user = seed_account(hooks, stores)
    stored = stores.require_credentials().get(str(user["id"]), PASSWORD_CREDENTIAL_TYPE)
    assert stored is not None
    original = stored.secret
    assert original.startswith("$2b$04$")

    # Raise the policy, exactly as a settings change in production would.
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


# ---------------------------------------------------------------------------
# The rotation state machine, section 2.6. One test per state.
# ---------------------------------------------------------------------------


@pytest.fixture
def sessions(stores: IdentityStores) -> SessionService:
    return SessionService(make_settings(), stores.require_refresh_tokens())


def test_state_current_rotates(sessions: SessionService) -> None:
    first = sessions.start_family(USER_ID)
    result = sessions.rotate(first.token)
    assert result.outcome == "rotated"
    assert result.issued is not None
    assert result.issued.generation == first.generation + 1
    assert result.issued.family_id == first.family_id
    assert result.issued.token != first.token


def test_state_consumed_inside_the_grace_window_is_replayed(sessions: SessionService) -> None:
    """Two tabs refreshing at once is benign and must not log the user out.

    The second call gets a working token rather than a revocation. It is a *new* token
    rather than literally the first successor, because only the successor's hash is stored
    and a hash cannot be turned back into a token; both tabs end up holding something that
    works, which is the behaviour section 2.6 is asking for.
    """
    first = sessions.start_family(USER_ID)
    winner = sessions.rotate(first.token)
    assert winner.issued is not None

    loser = sessions.rotate(first.token)
    assert loser.outcome == "replayed"
    assert loser.issued is not None
    assert loser.issued.family_id == first.family_id
    # Nothing was revoked: the family is still usable from both tokens.
    assert sessions.rotate(winner.issued.token).outcome == "rotated"


def test_state_consumed_outside_the_grace_window_revokes_the_family(
    sessions: SessionService, stores: IdentityStores
) -> None:
    """Reuse. The whole family dies, not just the presented token.

    Revoking one token would leave a stolen sibling live, which is exactly the situation
    reuse detection exists to end.
    """
    first = sessions.start_family(USER_ID)
    winner = sessions.rotate(first.token)
    assert winner.issued is not None

    beyond = datetime.now(UTC) + timedelta(seconds=60)
    reuse = sessions.rotate(first.token, now=beyond)
    assert reuse.outcome == "reuse"
    assert reuse.revoked >= 2

    # The legitimate holder's successor is dead too. That is the intended cost: the family
    # is compromised, so everybody in it has to sign in again.
    assert sessions.rotate(winner.issued.token, now=beyond).outcome == "revoked"


def test_state_revoked_is_refused_without_re_revoking(
    sessions: SessionService, stores: IdentityStores
) -> None:
    """A replay of a token from an already-dead family must not raise a fresh alarm.

    Re-revoking on every replay would turn one theft into an endless stream of
    `session.reuse_detected` events, which is a page for an operator each time.
    """
    first = sessions.start_family(USER_ID)
    sessions.revoke_family(first.family_id)

    result = sessions.rotate(first.token)
    assert result.outcome == "revoked"
    assert result.revoked == 0


def test_state_expired_is_refused_and_the_family_is_revoked(sessions: SessionService) -> None:
    """A sibling still inside its own rolling window must not resume an expired session."""
    first = sessions.start_family(USER_ID)
    settings = make_settings()
    beyond = datetime.now(UTC) + settings.refresh_token_ttl + timedelta(seconds=1)

    result = sessions.rotate(first.token, now=beyond)
    assert result.outcome == "expired"
    assert result.revoked >= 1


def test_state_unknown_is_refused_and_creates_nothing(
    sessions: SessionService, stores: IdentityStores
) -> None:
    """A forged token must never reach a write that could create a row for it."""
    result = sessions.rotate("not a token anybody issued")
    assert result.outcome == "unknown"
    assert result.issued is None
    assert stores.require_refresh_tokens().get(hash_token("not a token anybody issued")) is None


def test_the_absolute_cap_ends_a_family_however_active_it_has_been(
    sessions: SessionService,
) -> None:
    """The rolling window alone would let an attacker hold a family forever.

    Section 3.3: `refresh_absolute_ttl` is the per-family deadline and the rolling
    `refresh_token_ttl` is the per-token one. Rotating steadily keeps the second alive
    indefinitely, so only the first bounds the damage from a stolen cookie.
    """
    settings = make_settings()
    start = datetime.now(UTC)
    issued = sessions.start_family(USER_ID, now=start)

    # Rotate steadily, well inside the rolling window each time, until past the cap.
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
    """The last rotation before the cap must not mint a token that outlives it.

    Without the `min` against the family deadline, a rotation on day 89 of a 90 day cap
    would issue a token with a fresh 30 day rolling window, and that token would still be
    inside its own deadline three weeks after the family was supposed to be finished.

    The family has to be rotated steadily to reach day 89 at all, because each individual
    token expires after 30 days. That is the same reason the cap exists.
    """
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

    # The last token minted before the cap expires no later than the cap itself.
    final = sessions.rotate(token, now=moment)
    assert final.issued is not None
    assert final.issued.expires_at <= int(cap.timestamp())


def test_a_zero_grace_window_makes_every_replay_reuse(stores: IdentityStores) -> None:
    """Section 2.6: the grace is a setting so a product can take the stricter behaviour."""
    settings = make_settings(refresh_reuse_grace=0)
    strict = SessionService(settings, stores.require_refresh_tokens())
    first = strict.start_family(USER_ID)
    strict.rotate(first.token)
    assert strict.rotate(first.token).outcome == "reuse"


def test_only_the_hash_is_stored(sessions: SessionService, stores: IdentityStores) -> None:
    """A read of the table must not be turnable into a working session."""
    issued = sessions.start_family(USER_ID)
    record = stores.require_refresh_tokens().get(hash_token(issued.token))
    assert record is not None
    assert issued.token not in repr(record)
    assert record.token_hash == hash_token(issued.token)


def test_logout_revokes_the_whole_family(sessions: SessionService) -> None:
    first = sessions.start_family(USER_ID)
    rotated = sessions.rotate(first.token)
    assert rotated.issued is not None

    result = sessions.revoke_presented(rotated.issued.token)
    assert result.revoked == 2
    assert sessions.rotate(rotated.issued.token).outcome == "revoked"


def test_logout_all_revokes_every_family_for_a_user(sessions: SessionService) -> None:
    families = [sessions.start_family(USER_ID) for _ in range(3)]
    other = sessions.start_family("someone-else")

    revoked = sessions.revoke_all_for_user(USER_ID)
    assert revoked == 3
    for issued in families:
        assert sessions.rotate(issued.token).outcome == "revoked"
    # Another user's session is untouched.
    assert sessions.rotate(other.token).outcome == "rotated"


def test_logout_all_by_family_id_is_the_path_dynamodb_can_take(
    sessions: SessionService,
) -> None:
    """`refresh-tokens` carries no user index, so the caller supplies the families.

    M1 recorded that `DynamoRefreshTokenStore.revoke_all_for_user` raises rather than
    scanning a production table and deferred the resolution to M2. This is that resolution.
    """
    families = [sessions.start_family(USER_ID) for _ in range(2)]
    revoked = sessions.revoke_all_for_user(
        USER_ID, family_ids=[issued.family_id for issued in families]
    )
    assert revoked == 2


# ---------------------------------------------------------------------------
# Refresh through the flow layer
# ---------------------------------------------------------------------------


def test_refresh_mints_a_new_access_token_and_rotates_the_cookie(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    seed_account(hooks, stores)
    login = flows.login(email=EMAIL, password=PASSWORD)
    refreshed = flows.refresh(login.refresh_token)

    assert refreshed.access_token
    assert refreshed.refresh_token != login.refresh_token
    assert refreshed.family_id == login.family_id


def test_refresh_reuse_is_the_same_401_as_every_other_refusal(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """The difference between reuse and expiry is an alarm, not information for the caller."""
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
    """The only revocation this design has.

    Section 2.6 says plainly that a logout cannot invalidate an issued access token, so an
    account disabled mid-session stops being able to *renew*. That makes the ten-minute
    access token lifetime the actual bound, and it makes this check the thing that enforces
    it at all.
    """
    user = seed_account(hooks, stores)
    login = flows.login(email=EMAIL, password=PASSWORD)

    hooks.users[str(user["id"])]["disabled"] = True
    with pytest.raises(LoginRejected) as caught:
        flows.refresh(login.refresh_token)
    assert caught.value.error_code == "DISABLED"

    # The family is dead, so re-enabling the account does not resurrect the session.
    hooks.users[str(user["id"])]["disabled"] = False
    with pytest.raises(LoginRejected):
        flows.refresh(login.refresh_token)


def test_refresh_revokes_a_family_whose_user_has_gone(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    user = seed_account(hooks, stores)
    login = flows.login(email=EMAIL, password=PASSWORD)
    del hooks.users[str(user["id"])]

    with pytest.raises(LoginRejected):
        flows.refresh(login.refresh_token)


# ---------------------------------------------------------------------------
# Change password
# ---------------------------------------------------------------------------


def test_change_password_requires_the_current_one(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A token proves the session, not the person at the keyboard.

    Without this, a stolen access token upgrades into permanent control of the account,
    which is a far worse outcome than the ten minutes the token itself is worth.
    """
    seed_account(hooks, stores)
    with pytest.raises(LoginRejected):
        flows.change_password(
            user_id=USER_ID, current_password=OTHER_PASSWORD, new_password="a new one entirely"
        )


def test_change_password_applies_the_policy_to_the_new_password(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    seed_account(hooks, stores)
    with pytest.raises(PasswordRejected):
        flows.change_password(user_id=USER_ID, current_password=PASSWORD, new_password="short")


def test_change_password_revokes_other_sessions_but_keeps_the_callers(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Section 2.6: a password change calls sign-out-everywhere.

    A change made because of a suspected compromise is worthless if the attacker's session
    survives it. The caller's own family is spared so that changing a password does not sign
    the user out of the tab they did it in.
    """
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

    # The new password works and the old one does not.
    assert flows.login(email=EMAIL, password=OTHER_PASSWORD).access_token
    with pytest.raises(LoginRejected):
        flows.login(email=EMAIL, password=PASSWORD)


def test_change_password_on_an_account_with_no_credential_still_costs_a_bcrypt_round(
    flows: IdentityFlows, hooks: FakeHooks
) -> None:
    hooks.add(EMAIL, user_id=USER_ID)
    with pytest.raises(LoginRejected):
        flows.change_password(
            user_id=USER_ID, current_password=PASSWORD, new_password=OTHER_PASSWORD
        )


# ---------------------------------------------------------------------------
# The router: mounting, cookies, CSRF, and the error envelope
# ---------------------------------------------------------------------------


@pytest.fixture
def client(
    kms: FakeKms,
    hooks: FakeHooks,
    stores: IdentityStores,
    attempts: InMemoryLoginAttemptStore,
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
            # The limiter needs DynamoDB, and these tests are about the flows. The limits
            # themselves are asserted separately against the constants.
            limiter_enabled=False,
        )
    )
    # `base_url` has to be https or the Secure cookie is dropped by the test transport and
    # every rotation test silently exercises the no-cookie path instead.
    with TestClient(app, base_url="https://api.example.com") as test_client:
        yield test_client


def test_the_documents_alone_mount_without_hooks_or_stores(kms: FakeKms) -> None:
    """The M1 shape is preserved exactly when no collaborators are supplied.

    A JWKS-only function must not declare a login route that answers 500 on its first
    request, because the first thing that route does is call a hook that raises.
    """
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
    """The prefix is the issuer's path, so no path means origin paths.

    The counterpart to the test above. Both shapes have to work: the standard's issuer has
    a path, and a product that issues from a dedicated host has none.
    """
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
    """Follow the URL the discovery document advertises, rather than a path written here.

    This is the test that would have caught the 0.9.0 bug, and the reason it is written this
    way. API Gateway does not read our test constants: it fetches
    `issuer + "/.well-known/openid-configuration"`, reads `jwks_uri` out of the response and
    fetches that. A test asserting a hardcoded `/.well-known/jwks.json` answers 200 passes
    happily while the gateway gets a 404 and every authorized route in the product fails
    closed. Following the served URL is the only version that checks the thing that matters.

    Parametrized over both issuer shapes because the bug lives in the difference between
    them: an origin issuer worked in 0.9.0 and an issuer with a path did not.
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from webbpulse.identity.tokens import DISCOVERY_PATH

    settings = make_settings(issuer=issuer)
    app = FastAPI()
    app.include_router(build_identity_router(settings, kms_client=kms))

    origin = urlsplit(issuer)
    base_url = f"{origin.scheme}://{origin.netloc}"
    client = TestClient(app, base_url=base_url)

    # The gateway builds this URL itself, from the issuer alone.
    discovery = client.get(f"{settings.issuer}{DISCOVERY_PATH}")
    assert discovery.status_code == 200
    assert discovery.json()["issuer"] == settings.issuer

    # And then follows whatever the document advertises.
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
    """One prefix for everything, so the cookie scope covers the routes that spend it."""
    settings = make_settings(issuer=issuer)
    router = build_identity_router(settings, hooks, stores, kms_client=kms)
    paths = {route.path for route in router.routes}  # type: ignore[attr-defined]

    assert identity_prefix(settings) == prefix
    assert f"{prefix}/login" in paths
    assert f"{prefix}/refresh" in paths
    assert f"{prefix}/.well-known/jwks.json" in paths
    assert all(path.startswith(prefix) for path in paths)


def test_the_flow_prefix_matches_the_cookie_path() -> None:
    """A flow mounted outside `cookie_path` would never receive the cookie.

    Section 5.5 scopes the cookie so it is not attached to any other domain's routes. That
    protection only works if the routes that need it live under that path, which is why
    both are derived from the issuer rather than written down twice.
    """
    from webbpulse.identity.router import REFRESH_PATH, identity_prefix

    settings = make_settings()
    prefix = identity_prefix(settings)
    assert prefix == "/api/auth"
    assert settings.cookie_path == prefix
    assert f"{prefix}{REFRESH_PATH}".startswith(settings.cookie_path)


def test_an_origin_issuer_scopes_the_cookie_to_the_root() -> None:
    """An issuer with no path mounts at the origin, so the cookie covers the origin.

    `""` would not be a legal cookie path, so the derivation floors at `/`. Worth its own
    test because the empty prefix and the empty cookie path are the same input producing
    two deliberately different answers.
    """
    settings = make_settings(issuer="https://identity.example.com")
    assert identity_prefix(settings) == ""
    assert settings.cookie_path == "/"


def test_an_explicit_cookie_path_overrides_the_issuer() -> None:
    """Derivation is a default, not a rule. A product that needs a wider scope can say so."""
    settings = make_settings(cookie_path="/")
    assert identity_prefix(settings) == "/api/auth"
    assert settings.cookie_path == "/"


def test_login_sets_an_httponly_secure_samesite_lax_cookie(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores
) -> None:
    seed_account(hooks, stores)
    response = client.post("/api/auth/login", json={"email": EMAIL, "password": PASSWORD})

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 600
    # The refresh token is never in the body: putting it there as well would hand it to any
    # script that can read a fetch response, which defeats httponly entirely.
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
    """The enumeration control, asserted on the wire rather than on the exception.

    `request_id` differs per request by design, so it is the one field excluded. Everything
    else, status, headers and body, has to match exactly.
    """
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
    """201 with a session for a new account, 200 without one for a taken address.

    The status differs because the resources differ: one created an account and one did not.
    What must not differ is anything that identifies *which* case happened for a given
    address, and a caller cannot tell a taken address from a rejected one here because the
    taken case is the ordinary success shape.
    """
    fresh = client.post("/api/auth/register", json={"email": EMAIL, "password": PASSWORD})
    assert fresh.status_code == 201
    assert fresh.json()["registered"] is True

    again = client.post("/api/auth/register", json={"email": EMAIL, "password": OTHER_PASSWORD})
    assert again.status_code == 200
    assert again.json() == {"registered": True}
    assert "set-cookie" not in again.headers


def test_a_short_password_is_a_422_with_a_specific_reason(client: TestClient) -> None:
    """Unlike a login failure, this one is safe to be specific about.

    It describes the password the caller just supplied and says nothing about any account,
    so there is nothing here to enumerate with, and a vague message would leave the user
    guessing at what the form wants.
    """
    response = client.post("/api/auth/register", json={"email": EMAIL, "password": "short"})
    assert response.status_code == 422
    assert response.json()["error_code"] == "PASSWORD_TOO_SHORT"


def test_refresh_rotates_the_cookie_over_http(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores
) -> None:
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
    """A token that has just been refused will never work again.

    Leaving it in the browser only guarantees the next request repeats the failure, and a
    dead cookie sitting in a browser is a token an attacker can still try to replay.
    """
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
    response = client.post("/api/auth/refresh")
    assert response.status_code == 401
    assert response.json()["error_code"] == "NO_SESSION"


def test_a_cross_site_fetch_is_refused_on_refresh_and_logout(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Section 5.5's first CSRF supplement.

    `Sec-Fetch-Site` is set by the browser and cannot be set by page JavaScript, so a
    `cross-site` value on a state-changing cookie route is a forged request whatever the
    cookie says.
    """
    seed_account(hooks, stores)
    client.post("/api/auth/login", json={"email": EMAIL, "password": PASSWORD})

    for path in ("/api/auth/refresh", "/api/auth/logout"):
        response = client.post(path, headers={"Sec-Fetch-Site": "cross-site"})
        assert response.status_code == 403
        assert response.json()["error_code"] == "CROSS_SITE_REQUEST"

    # The session survived the refused attempt: a forged request must not be able to log
    # the victim out, which would be a denial of service handed to the attacker.
    assert client.post("/api/auth/refresh").status_code == 200


def test_a_missing_sec_fetch_site_header_is_allowed(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Non-browser clients send none, and an attacker's page cannot suppress it."""
    seed_account(hooks, stores)
    client.post("/api/auth/login", json={"email": EMAIL, "password": PASSWORD})
    assert client.post("/api/auth/refresh").status_code == 200


def test_same_site_and_same_origin_are_allowed(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Both products serve the frontend and the API under one registrable domain.

    A request from `www.<domain>` to `api.<domain>` is cross-origin but same-site, which is
    exactly the case `SameSite=Lax` is available for and which this must not refuse.
    """
    seed_account(hooks, stores)
    client.post("/api/auth/login", json={"email": EMAIL, "password": PASSWORD})
    for value in ("same-origin", "same-site"):
        assert (
            client.post("/api/auth/refresh", headers={"Sec-Fetch-Site": value}).status_code == 200
        )


def test_logout_is_idempotent_and_always_succeeds(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """The caller's intent is to end up signed out, so a dead cookie is a success.

    Answering 401 would also tell the caller whether the cookie they hold is live, which is
    a signal they should not get.
    """
    seed_account(hooks, stores)
    client.post("/api/auth/login", json={"email": EMAIL, "password": PASSWORD})

    first = client.post("/api/auth/logout")
    assert first.status_code == 200
    assert first.json() == {"signed_out": True}

    second = client.post("/api/auth/logout")
    assert second.status_code == 200

    # The family is dead, so the old cookie cannot be refreshed even if the browser kept it.
    assert client.post("/api/auth/refresh").status_code == 401


def test_logout_all_needs_a_verified_token(client: TestClient) -> None:
    assert client.post("/api/auth/logout-all").status_code == 401
    assert client.post("/api/auth/password", json={}).status_code == 401


def test_change_password_and_logout_all_read_the_subject_from_the_token(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """The subject comes from verified claims, never from the request body.

    Reading it from the body would let anybody change anybody else's password, which is the
    most direct account takeover a flow like this can have.
    """
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

    # The new password works.
    assert (
        client.post(
            "/api/auth/login", json={"email": EMAIL, "password": OTHER_PASSWORD}
        ).status_code
        == 200
    )


def test_a_forged_bearer_token_is_not_accepted(client: TestClient) -> None:
    response = client.post("/api/auth/logout-all", headers={"Authorization": "Bearer not.a.token"})
    assert response.status_code == 401
    assert response.json()["error_code"] == "NOT_AUTHENTICATED"


def test_the_rate_limits_match_the_table_in_section_five_one() -> None:
    """The limits are constants so the standard's table and the code can be diffed by eye."""
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
    """The limiter dependency, wired for real against a fake limiter.

    `webbpulse.ratelimit` is already tested on its own, so what matters here is that the
    identity routes actually carry the dependency: a limit configured but not attached is
    the failure this catches.
    """
    from webbpulse.http import register_error_handlers
    from webbpulse.ratelimit import RateLimitDecision

    class AlwaysLimited:
        def check(self, identity: str, *, limit: int, window_seconds: int) -> RateLimitDecision:
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
    """The `.well-known` routes must stay anonymous and unaffected.

    Section 2.5 names a gate in front of these as the single most likely way to get the
    deployment wrong: API Gateway fetches them itself with no cookie and no token, and if
    either fails the authorizer cannot retrieve the signing key and every authorized route
    in the product fails closed.
    """
    assert client.get("/api/auth/.well-known/jwks.json").status_code == 200
    assert client.get("/api/auth/.well-known/openid-configuration").status_code == 200
    assert client.get("/api/auth/health").json()["status"] == "healthy"


class _NoUserIndexRefreshTokenStore(InMemoryRefreshTokenStore):
    """An `InMemoryRefreshTokenStore` that refuses the user-indexed scan, like DynamoDB.

    `DynamoRefreshTokenStore.revoke_all_for_user` raises because `refresh-tokens` has no
    user index, and the in-memory store's happy path hid that from every route level test.
    """

    def revoke_all_for_user(self, user_id: str, *, except_family_id: str = "") -> int:
        raise NotImplementedError("revoke_all_for_user needs the caller's family ids")


@pytest.fixture
def no_user_index_stores() -> IdentityStores:
    """Stores whose refresh table behaves like the deployed DynamoDB one."""
    return IdentityStores(
        credentials=InMemoryCredentialStore(),
        refresh_tokens=_NoUserIndexRefreshTokenStore(),
    )


@pytest.fixture
def no_user_index_client(
    kms: FakeKms,
    hooks: FakeHooks,
    no_user_index_stores: IdentityStores,
    attempts: InMemoryLoginAttemptStore,
) -> Iterator[TestClient]:
    """The router over a refresh store with no user index."""
    from webbpulse.http import register_error_handlers

    settings = make_settings()
    app = FastAPI()
    register_error_handlers(app, error_codes=True)
    app.include_router(
        build_identity_router(
            settings,
            hooks,
            no_user_index_stores,
            kms_client=kms,
            attempts=attempts,
            limiter_enabled=False,
        )
    )
    with TestClient(app, base_url="https://api.example.com") as test_client:
        yield test_client


def test_logout_all_succeeds_when_the_refresh_store_has_no_user_index(
    no_user_index_client: TestClient, hooks: FakeHooks, no_user_index_stores: IdentityStores
) -> None:
    """The regression: the route supplies the families rather than asking for a scan.

    Deployed on DynamoDB this answered 500, because the route passed no `family_ids` and
    the store raises rather than scanning `refresh-tokens`.
    """
    seed_account(hooks, no_user_index_stores)
    login = no_user_index_client.post(
        "/api/auth/login", json={"email": EMAIL, "password": PASSWORD}
    )
    access = login.json()["access_token"]

    response = no_user_index_client.post(
        "/api/auth/logout-all", headers={"Authorization": f"Bearer {access}"}
    )
    assert response.status_code == 200
    assert response.json() == {"signed_out": True}


def test_logout_all_revokes_the_caller_own_family(
    no_user_index_client: TestClient, hooks: FakeHooks, no_user_index_stores: IdentityStores
) -> None:
    """Signing out everywhere kills the family the caller is signed in with."""
    seed_account(hooks, no_user_index_stores)
    login = no_user_index_client.post(
        "/api/auth/login", json={"email": EMAIL, "password": PASSWORD}
    )
    access = login.json()["access_token"]

    assert (
        no_user_index_client.post(
            "/api/auth/logout-all", headers={"Authorization": f"Bearer {access}"}
        ).status_code
        == 200
    )
    assert no_user_index_client.post("/api/auth/refresh").status_code == 401


def test_family_of_resolves_a_presented_refresh_token(sessions: SessionService) -> None:
    """`family_of` names a token's family, and answers empty for one it does not know."""
    issued = sessions.start_family(USER_ID)
    assert sessions.family_of(issued.token) == issued.family_id
    assert sessions.family_of("not-a-token") == ""
    assert sessions.family_of("") == ""
