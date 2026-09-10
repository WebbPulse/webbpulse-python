"""Tests for the M4 identity work: TOTP, recovery codes, the MFA ticket, step-up and `amr`.

Section 9.4 of `docs/identity-standard.md` sets the strategy, and four of its requirements
shape this file in ways the M2 and M3 suites did not need:

- **TOTP is checked against the RFC, not against itself.** RFC 6238 Appendix B publishes
  code and timestamp pairs for a known seed. A generator tested only against its own
  verifier passes while both are wrong in the same direction, and the user finds out when
  their authenticator app disagrees. The vectors are the only test that can catch that.
- **Single use is tested by using twice.** Every single-use thing here gets a test that
  spends it and then spends it again: the TOTP step, the recovery code, the MFA ticket. A
  test that only walks the happy path passes against an implementation with no replay
  defence at all.
- **The wire shape is asserted against the frontend's contract.** `@webbpulse/auth` 0.4.0
  branches on `mfa_required` in a **200** body and posts `{mfa_ticket, code}` to
  `/login/totp`. Those exact names and that exact status are asserted, because the failure
  they guard against is a rename that type-checks perfectly and breaks every sign-in.
- **The two token types are separated in both directions.** An MFA ticket must not be
  accepted as an access token and an access token must not be accepted as a ticket. One
  direction passing is not evidence for the other.

The envelope is tested against **moto** as well as a hand fake. M1 decision 8 found moto
unusable for KMS *asymmetric* signing, and the natural inference is that KMS is off limits
for tests generally. That inference is wrong: moto 5.x implements symmetric
`GenerateDataKey` and `Decrypt` faithfully, encryption context included, and rejects a
tampered blob and a mismatched context the way KMS does. So the properties the design rests
on are asserted against a real implementation rather than against a fake that could not have
disagreed. The hand fake carries the rest, where moto's behaviour is not the point.

The KMS signing fake is M2's, redefined here rather than imported: `tests/` is not a package.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

import pytest

from webbpulse.identity import (
    LOGIN_PATH,
    LOGIN_TOTP_PATH,
    RECOVERY_CODES_PATH,
    STEP_UP_PATH,
    TOTP_ACTIVATE_PATH,
    TOTP_DISABLE_PATH,
    TOTP_ENROL_PATH,
    TOTP_VERIFY_LIMIT,
    AuthenticationRefused,
    BaseIdentityHooks,
    CredentialRecord,
    EnvelopeCipher,
    EnvelopeDecryptionFailed,
    IdentitySettings,
    IdentityStores,
    InMemoryCredentialStore,
    InMemoryIdentityTokenStore,
    InMemoryLoginAttemptStore,
    InMemoryRecoveryCodeStore,
    InMemoryRefreshTokenStore,
    InMemoryTotpFactorStore,
    RecoveryCodeRecord,
    SealedSecret,
    TokenService,
    TotpFactorRecord,
    build_identity_router,
    encryption_context,
    identity_prefix,
    normalise_password,
)
from webbpulse.identity import totp as totp_module
from webbpulse.identity.flows import (
    PASSWORD_CREDENTIAL_TYPE,
    IdentityFlows,
    MfaChallengeRequired,
)
from webbpulse.identity.mfa import (
    AMR_MFA,
    AMR_OTP,
    AMR_PASSWORD,
    AMR_RECOVERY,
    RECOVERY_CODE_COUNT,
    TOTP_FACTOR,
    MfaRejected,
    MfaService,
    hash_recovery_code,
    normalise_recovery_code,
)
from webbpulse.identity.service import ACCESS_TOKEN_TYPE, MFA_TICKET_TYPE, InvalidToken

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from fastapi import FastAPI
from fastapi.testclient import TestClient

KEY_A = "arn:aws:kms:us-west-2:111122223333:key/aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa"
DATA_KEY = "arn:aws:kms:us-west-2:111122223333:key/dddddddd-4444-4444-4444-dddddddddddd"
ISSUER = "https://api.staging.example.com/api/auth"
AUDIENCE = "webbpulse-staging"
FRONTEND = "https://staging.example.com"

PASSWORD = "correct horse battery staple"
EMAIL = "person@example.com"
USER_ID = "user-0001"


class FakeKms:
    """Signing with a local private key plus a local stand-in for the two envelope calls.

    One object, because `IdentityFlows` takes one `kms_client` and hands the same one to the
    token service and the MFA service. That is the production shape too: one boto3 client
    serves both key ids.

    The envelope half wraps a data key by base64-ing it with its encryption context appended,
    which is not encryption and is not pretending to be. What it does faithfully is the one
    behaviour the design depends on: a `decrypt` under a context other than the one the key
    was generated with fails. The moto test below covers the parts a fake cannot vouch for.
    """

    def __init__(self, keys: dict[str, rsa.RSAPrivateKey]) -> None:
        self._keys = keys
        self.data_key_calls: list[dict[str, Any]] = []

    # ---- signing (M2's fake, unchanged) --------------------------------------------

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

    # ---- the envelope ----------------------------------------------------------------

    def generate_data_key(
        self, *, KeyId: str, NumberOfBytes: int, EncryptionContext: Mapping[str, str]
    ) -> dict[str, Any]:
        self.data_key_calls.append(
            {
                "KeyId": KeyId,
                "NumberOfBytes": NumberOfBytes,
                "EncryptionContext": dict(EncryptionContext),
            }
        )
        import secrets

        plaintext = secrets.token_bytes(NumberOfBytes)
        blob = base64.b64encode(plaintext) + b"|" + _context_bytes(EncryptionContext)
        return {"KeyId": KeyId, "Plaintext": plaintext, "CiphertextBlob": blob}

    def decrypt(
        self, *, CiphertextBlob: bytes, EncryptionContext: Mapping[str, str]
    ) -> dict[str, Any]:
        try:
            encoded, context = CiphertextBlob.split(b"|", 1)
        except ValueError as exc:
            raise RuntimeError("InvalidCiphertextException") from exc
        if context != _context_bytes(EncryptionContext):
            # What real KMS does when the context does not match, and the reason a
            # ciphertext cannot be moved between users' rows.
            raise RuntimeError("InvalidCiphertextException")
        return {"KeyId": DATA_KEY, "Plaintext": base64.b64decode(encoded)}


def _context_bytes(context: Mapping[str, str]) -> bytes:
    return repr(sorted(context.items())).encode("utf-8")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def cheap_bcrypt(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Pin bcrypt to its minimum cost for the whole module. M2's fixture, unchanged.

    Wrapping the two functions rather than patching `security.DEFAULT_ROUNDS`. Since 0.12.1
    patching the module attribute would work too, because the cost is read at call time; the
    wrapper is kept because it also pins the cost for a caller that passes `rounds=`
    explicitly, which a changed default does not.
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
        "data_key_arn": DATA_KEY,
        "email_verification_required": False,
        "frontend_base_url": FRONTEND,
        "product_name": "Example",
        "support_email": "support@example.com",
    }
    base.update(overrides)
    return IdentitySettings(**base)


class FakeHooks(BaseIdentityHooks):
    """A product's policy, in memory. M3's fake, unchanged."""

    def __init__(self, *, refuse: str = "") -> None:
        self.users: dict[str, dict[str, Any]] = {}
        self.by_email: dict[str, str] = {}
        self.refuse = refuse
        self.calls: list[str] = []
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
        # Deliberately tries to set both. `_mint_access` must overwrite them: a hook that
        # could forge `amr` could claim a factor the user never satisfied.
        return {"amr": ["forged"], "auth_time": 1}

    def create_user(self, *, email: str, attributes: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls.append("create_user")
        return self.add(email, **dict(attributes))


@pytest.fixture
def hooks() -> FakeHooks:
    return FakeHooks()


@pytest.fixture
def stores() -> IdentityStores:
    return IdentityStores(
        credentials=InMemoryCredentialStore(),
        refresh_tokens=InMemoryRefreshTokenStore(),
        identity_tokens=InMemoryIdentityTokenStore(),
        totp_factors=InMemoryTotpFactorStore(),
        recovery_codes=InMemoryRecoveryCodeStore(),
    )


@pytest.fixture
def attempts() -> InMemoryLoginAttemptStore:
    return InMemoryLoginAttemptStore()


@pytest.fixture
def flows(
    hooks: FakeHooks,
    stores: IdentityStores,
    kms: FakeKms,
    attempts: InMemoryLoginAttemptStore,
) -> IdentityFlows:
    settings = make_settings()
    return IdentityFlows(
        settings,
        hooks,
        stores,
        TokenService(settings, kms),
        attempts=attempts,
        kms_client=kms,
    )


@pytest.fixture
def mfa(flows: IdentityFlows) -> MfaService:
    service = flows.mfa
    assert service is not None, "the fixtures wire every M4 store, so MFA must be mounted"
    return service


@pytest.fixture
def client(
    hooks: FakeHooks,
    stores: IdentityStores,
    kms: FakeKms,
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
            limiter_enabled=False,
        )
    )
    with TestClient(app, base_url="https://api.example.com") as test_client:
        yield test_client


def prefix() -> str:
    return identity_prefix(make_settings())


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


def enrol(mfa: MfaService, user_id: str = USER_ID) -> tuple[str, list[str]]:
    """Enrol and activate a factor, returning the seed and the recovery codes.

    Goes through the service rather than writing store rows directly, so a test that uses
    this is also exercising the enrolment path it depends on.
    """
    enrolment = mfa.begin_enrolment(user_id, account_name=EMAIL)
    step = totp_module.current_step()
    codes = mfa.confirm_enrolment(user_id, totp_module.generate_code(enrolment.secret, step=step))
    return enrolment.secret, codes.codes


def code_now(seed: str, *, offset: int = 0) -> str:
    """The code for the current step, or `offset` steps away from it."""
    return totp_module.generate_code(seed, step=totp_module.current_step() + offset)


@contextmanager
def clock_advanced(monkeypatch: pytest.MonkeyPatch, steps: int) -> Iterator[None]:
    """Move the TOTP clock forward by whole time steps for the body of the block.

    Needed because a second verification cannot simply reach for a code further ahead: the
    window is one step either side of *now*, so the code two steps out is refused for being
    outside the window rather than for being replayed, and a test written that way would be
    asserting the wrong refusal. Advancing the clock is what really happens between two
    verifications by the same user.

    `time.time` is patched process-wide for the block, so token `iat` and `exp` move with
    it too. That is the honest simulation of time passing, and it is why any assertion
    inside the block has to be made against the advanced clock rather than against real
    time.
    """
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + steps * totp_module.TIME_STEP_SECONDS)
    try:
        yield
    finally:
        monkeypatch.undo()


def claims_of(token: str) -> dict[str, Any]:
    """The payload of a JWT, without verifying it. For asserting on claims only."""
    import json

    payload = token.split(".")[1]
    padded = payload + "=" * (-len(payload) % 4)
    result: dict[str, Any] = json.loads(base64.urlsafe_b64decode(padded))
    return result


# ---------------------------------------------------------------------------
# TOTP against RFC 6238
# ---------------------------------------------------------------------------

#: The RFC 6238 Appendix B seed. The document gives it as the ASCII "12345678901234567890";
#: base32 is the form a `otpauth://` URI carries and the form this module works in.
RFC_SEED = base64.b32encode(b"12345678901234567890").decode("ascii").rstrip("=")

#: Appendix B's SHA-1 rows: (unix time, the 8 digit code). The table publishes eight digits
#: and this implementation emits six, so the assertion takes the last six, which is what
#: truncating the same dynamic-truncation result to six digits gives.
RFC_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


@pytest.mark.parametrize(("moment", "expected"), RFC_VECTORS)
def test_the_generator_agrees_with_rfc_6238_appendix_b(moment: int, expected: str) -> None:
    """The only test that can catch a generator and verifier that are wrong together.

    Every other TOTP test here compares this implementation against itself, which passes
    whatever the arithmetic does as long as it is consistent. These six rows come from the
    RFC, so agreeing with them is agreeing with every authenticator app the user might have
    installed. Getting this wrong ships a feature where enrolment succeeds and nothing the
    user types is ever accepted.
    """
    step = moment // totp_module.TIME_STEP_SECONDS
    assert totp_module.generate_code(RFC_SEED, step=step) == expected[-6:]


def test_a_code_is_six_digits_including_its_leading_zeros() -> None:
    """`07081804` truncates to `081804`, not to `81804`.

    Formatting with `%d` rather than a zero-padded width is the classic bug here, and it only
    shows up on the one code in ten that starts with a zero. A user hitting it sees a code
    their app displays being refused with no pattern.
    """
    step = 1111111109 // totp_module.TIME_STEP_SECONDS
    assert totp_module.generate_code(RFC_SEED, step=step) == "081804"
    assert len(totp_module.generate_code(RFC_SEED, step=step)) == totp_module.CODE_DIGITS


def test_the_seed_is_long_enough_and_decodes_as_base32() -> None:
    """RFC 4226 section 4 requires at least 128 bits and recommends 160."""
    seed = totp_module.generate_seed()
    assert seed == seed.upper()
    assert "=" not in seed
    decoded = base64.b32decode(seed + "=" * (-len(seed) % 8))
    assert len(decoded) == totp_module.SEED_BYTES
    assert len(decoded) * 8 >= 128


def test_two_seeds_are_never_the_same() -> None:
    """A seed generated from anything but a CSPRNG is the whole factor gone."""
    assert len({totp_module.generate_seed() for _ in range(50)}) == 50


def test_a_seed_is_accepted_however_the_user_typed_it() -> None:
    """Lower case, padding and the spaces some apps display between groups.

    A user typing a seed by hand copies what is on screen, spaces included.
    """
    seed = totp_module.generate_seed()
    step = totp_module.current_step()
    expected = totp_module.generate_code(seed, step=step)
    spaced = " ".join(seed[i : i + 4] for i in range(0, len(seed), 4))
    for variant in (seed.lower(), seed + "=" * 4, spaced):
        assert totp_module.generate_code(variant, step=step) == expected


def test_a_seed_that_is_not_base32_raises_rather_than_producing_a_code() -> None:
    """Silently hashing garbage would give a code that is stably wrong forever."""
    with pytest.raises(ValueError):
        totp_module.generate_code("not-valid-base32-1!", step=1)


# ---------------------------------------------------------------------------
# TOTP verification: the window and the replay refusal
# ---------------------------------------------------------------------------


def test_verification_accepts_the_current_step_and_returns_it() -> None:
    """Returns the step rather than a bool because the caller must store the watermark.

    A verifier returning `True` gives the caller nothing to record, and replay defence then
    has to recompute which step matched, which is the sort of duplication that drifts.
    """
    seed = totp_module.generate_seed()
    step = totp_module.current_step()
    assert totp_module.verify_code(seed, totp_module.generate_code(seed, step=step)) == step


def test_verification_accepts_one_step_either_side_and_not_two() -> None:
    """Section 6.1 fixes the window at one step, which is thirty seconds each way.

    Both sides, not just behind: a phone whose clock is a little fast produces the next
    step's code, and refusing it would make the factor unusable for that user. Two steps
    away is refused, because each extra step multiplies an attacker's chance against a
    million-value space and the window is the only thing bounding that.
    """
    seed = totp_module.generate_seed()
    now = totp_module.current_step()
    for offset in (-1, 0, 1):
        code = totp_module.generate_code(seed, step=now + offset)
        assert totp_module.verify_code(seed, code) == now + offset
    for offset in (-2, 2):
        code = totp_module.generate_code(seed, step=now + offset)
        assert totp_module.verify_code(seed, code) is None


def test_a_step_at_or_below_the_watermark_is_refused() -> None:
    """The replay refusal, at the level of the pure function.

    Not `<`, but `<=`: the step just used is exactly the one an attacker who shoulder-surfed
    the code would present, and it is still inside the window for another thirty seconds.
    """
    seed = totp_module.generate_seed()
    now = totp_module.current_step()
    code = totp_module.generate_code(seed, step=now)
    assert totp_module.verify_code(seed, code, last_used_step=now - 1) == now
    assert totp_module.verify_code(seed, code, last_used_step=now) is None
    assert totp_module.verify_code(seed, code, last_used_step=now + 5) is None


def test_a_wrong_code_of_the_right_shape_is_refused() -> None:
    seed = totp_module.generate_seed()
    wrong = "000000" if code_now(seed) != "000000" else "111111"
    assert totp_module.verify_code(seed, wrong) is None


def test_codes_are_normalised_of_spaces_and_hyphens_only() -> None:
    """Authenticator apps display `123 456`, and a user pastes what they see.

    Only whitespace and hyphens, though: stripping anything else would mean a code with a
    stray letter in it being silently reshaped into a valid one.
    """
    assert totp_module.normalise_code(" 123 456 ") == "123456"
    assert totp_module.normalise_code("123-456") == "123456"
    assert totp_module.normalise_code("12a456") == "12a456"


def test_the_provisioning_uri_is_a_uri_not_a_form_body() -> None:
    """A space in the issuer must encode as `%20`, never as `+`.

    `urlencode` defaults to form encoding, where a space becomes `+`. The Key URI format is
    a URI, so a compliant parser reads that `+` literally and the user's authenticator lists
    the account under a name with a plus sign in it. It is the sort of bug that never fails
    a test written against the implementation's own parser.
    """
    seed = totp_module.generate_seed()
    uri = totp_module.provisioning_uri(seed, account_name=EMAIL, issuer="WebbPulse Portfolio")
    assert "+" not in uri
    assert "issuer=WebbPulse%20Portfolio" in uri


def test_the_provisioning_uri_carries_the_issuer_in_both_places() -> None:
    """The Key URI format puts the issuer in the label prefix *and* in a parameter.

    Older apps read the prefix, newer ones read the parameter, and an app that reads both
    warns when they disagree. Emitting only one is what makes an account show up unlabelled.
    """
    from urllib.parse import parse_qs, unquote, urlsplit

    seed = totp_module.generate_seed()
    uri = totp_module.provisioning_uri(seed, account_name=EMAIL, issuer="Example")
    parts = urlsplit(uri)
    assert parts.scheme == "otpauth"
    assert parts.netloc == "totp"
    assert unquote(parts.path) == f"/Example:{EMAIL}"
    query = parse_qs(parts.query)
    assert query["issuer"] == ["Example"]
    assert query["secret"] == [seed]


def test_the_provisioning_uri_omits_the_parameters_that_are_defaults() -> None:
    """SHA-1, six digits and thirty seconds are what every app assumes.

    Spelling them out is not merely redundant: several popular apps ignore `algorithm`
    entirely, so a URI that names one implies a promise the apps do not keep.
    """
    uri = totp_module.provisioning_uri(
        totp_module.generate_seed(), account_name=EMAIL, issuer="Example"
    )
    assert "algorithm=" not in uri
    assert "digits=" not in uri
    assert "period=" not in uri


def test_an_independent_implementation_agrees_with_this_one() -> None:
    """Twenty random seeds through eight lines of RFC 4226 written from the spec.

    The Appendix B vectors pin one seed. This pins the arithmetic across seeds, which is
    where a masking or endianness mistake would show up on some inputs and not others.
    """
    for _ in range(20):
        seed = totp_module.generate_seed()
        step = totp_module.current_step()
        key = base64.b32decode(seed + "=" * (-len(seed) % 8))
        digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
        assert totp_module.generate_code(seed, step=step) == f"{truncated % 1_000_000:06d}"


# ---------------------------------------------------------------------------
# The envelope: the hand fake, then moto
# ---------------------------------------------------------------------------


def test_a_sealed_seed_round_trips(kms: FakeKms) -> None:
    cipher = EnvelopeCipher(DATA_KEY, kms)
    sealed = cipher.seal(b"the seed", user_id=USER_ID)
    assert cipher.open(sealed, user_id=USER_ID) == b"the seed"


def test_the_sealed_fields_never_contain_the_plaintext(kms: FakeKms) -> None:
    """The row is what a person with table read access sees.

    Every field is asserted, not just the ciphertext: the failure this guards against is a
    later change that keeps the plaintext around "for debugging" in a field nobody checks.
    """
    cipher = EnvelopeCipher(DATA_KEY, kms)
    seed = totp_module.generate_seed()
    sealed = cipher.seal(seed.encode("ascii"), user_id=USER_ID)
    for value in sealed.as_item().values():
        assert seed not in value
        assert seed.lower() not in value.lower()


def test_a_ciphertext_moved_to_another_users_row_will_not_open(kms: FakeKms) -> None:
    """The point of putting `user_id` in the encryption context.

    Without it, somebody who can write the table copies the row of a user whose seed they
    know onto the account they want, and the factor they now control passes.
    """
    cipher = EnvelopeCipher(DATA_KEY, kms)
    sealed = cipher.seal(b"the seed", user_id=USER_ID)
    with pytest.raises(EnvelopeDecryptionFailed):
        cipher.open(sealed, user_id="user-9999")


def test_a_ciphertext_from_another_purpose_will_not_open_as_a_seed(kms: FakeKms) -> None:
    """The other half of the context. A later feature encrypting under the same key must not
    produce values that can be dropped into the TOTP column."""
    cipher = EnvelopeCipher(DATA_KEY, kms)
    sealed = cipher.seal(b"something else", user_id=USER_ID, purpose="other")
    with pytest.raises(EnvelopeDecryptionFailed):
        cipher.open(sealed, user_id=USER_ID)


def test_tampering_with_the_ciphertext_is_detected(kms: FakeKms) -> None:
    """AES-GCM is authenticated, so this is a property of the mode rather than of the code.

    Asserted anyway, because it stops being true the moment somebody swaps GCM for CTR to
    "simplify" and the seed becomes malleable.
    """
    cipher = EnvelopeCipher(DATA_KEY, kms)
    sealed = cipher.seal(b"the seed", user_id=USER_ID)
    raw = bytearray(base64.b64decode(sealed.ciphertext))
    raw[0] ^= 0xFF
    flipped = SealedSecret(
        ciphertext=base64.b64encode(bytes(raw)).decode("ascii"),
        nonce=sealed.nonce,
        wrapped_key=sealed.wrapped_key,
    )
    with pytest.raises(EnvelopeDecryptionFailed):
        cipher.open(flipped, user_id=USER_ID)


def test_every_seal_uses_a_fresh_data_key_and_a_fresh_nonce(kms: FakeKms) -> None:
    """A reused GCM nonce under a reused key is a total break of confidentiality.

    A data key per secret makes the pair impossible to repeat by construction, which is
    exactly why the envelope is worth the extra call over `kms:Encrypt`.
    """
    cipher = EnvelopeCipher(DATA_KEY, kms)
    sealed = [cipher.seal(b"the seed", user_id=USER_ID) for _ in range(10)]
    assert len({item.nonce for item in sealed}) == 10
    assert len({item.wrapped_key for item in sealed}) == 10
    assert len({item.ciphertext for item in sealed}) == 10


def test_the_data_key_request_asks_for_256_bits_under_the_configured_key(kms: FakeKms) -> None:
    cipher = EnvelopeCipher(DATA_KEY, kms)
    cipher.seal(b"the seed", user_id=USER_ID)
    assert kms.data_key_calls == [
        {
            "KeyId": DATA_KEY,
            "NumberOfBytes": 32,
            "EncryptionContext": encryption_context(USER_ID),
        }
    ]


def test_a_half_written_row_reads_back_as_no_usable_factor() -> None:
    """`None`, not a `KeyError` and not a partial object.

    A row missing one of the three fields cannot be decrypted whatever the caller does. The
    difference between `None` and a raise is a 401 on one user's login versus a 500.
    """
    assert SealedSecret.from_item({}) is None
    assert SealedSecret.from_item({"secret_ciphertext": "x", "secret_nonce": "y"}) is None
    full = {"secret_ciphertext": "x", "secret_nonce": "y", "wrapped_data_key": "z"}
    assert SealedSecret.from_item(full) is not None


def test_the_envelope_works_against_moto() -> None:
    """The one test that runs the envelope against a real KMS implementation.

    M1 decision 8 found moto unusable for asymmetric signing, and it would be easy to
    conclude KMS is off limits in tests entirely. It is not: moto 5.x implements symmetric
    `GenerateDataKey` and `Decrypt` including encryption context, so the three properties
    the design rests on can be asserted against something that was not written to agree.

    A hand fake cannot tell us that a real client accepts these call shapes at all, and that
    is the part this covers.
    """
    moto = pytest.importorskip("moto")
    boto3 = pytest.importorskip("boto3")

    with moto.mock_aws():
        kms_client = boto3.client("kms", region_name="us-west-2")
        key_id = kms_client.create_key(Description="totp seeds")["KeyMetadata"]["KeyId"]
        cipher = EnvelopeCipher(key_id, kms_client)

        seed = totp_module.generate_seed()
        sealed = cipher.seal(seed.encode("ascii"), user_id=USER_ID)
        assert cipher.open(sealed, user_id=USER_ID).decode("ascii") == seed

        # The context is enforced by KMS itself, not by anything in this package.
        with pytest.raises(EnvelopeDecryptionFailed):
            cipher.open(sealed, user_id="user-9999")

        raw = bytearray(base64.b64decode(sealed.wrapped_key))
        raw[-1] ^= 0xFF
        tampered = SealedSecret(
            ciphertext=sealed.ciphertext,
            nonce=sealed.nonce,
            wrapped_key=base64.b64encode(bytes(raw)).decode("ascii"),
        )
        with pytest.raises(EnvelopeDecryptionFailed):
            cipher.open(tampered, user_id=USER_ID)


def test_the_cipher_names_the_missing_setting_rather_than_failing_deep(
    hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    """An unset `data_key_arn` must fail with the setting's name in the message.

    The alternative is a `ValueError` out of the middle of the cipher on the first enrolment
    in production, and whoever is paged has to read three modules to learn which environment
    variable is missing.
    """
    settings = make_settings(data_key_arn="")
    service = MfaService(settings, stores, TokenService(settings, kms), kms_client=kms)
    with pytest.raises(ValueError, match="IDENTITY_DATA_KEY_ARN"):
        _ = service.cipher


# ---------------------------------------------------------------------------
# Enrolment
# ---------------------------------------------------------------------------


def test_enrolment_leaves_the_factor_inactive_until_a_code_confirms_it(
    mfa: MfaService, stores: IdentityStores
) -> None:
    """The whole reason confirmation exists.

    A factor active from the moment a QR code is drawn locks out every user who scans badly
    or closes the tab, and the only way back is a support request.
    """
    mfa.begin_enrolment(USER_ID, account_name=EMAIL)
    factor = stores.require_totp_factors().get(USER_ID)
    assert factor is not None
    assert not factor.is_active
    assert mfa.factors_for(USER_ID) == []


def test_confirming_with_a_correct_code_activates_and_issues_recovery_codes(
    mfa: MfaService, stores: IdentityStores
) -> None:
    enrolment = mfa.begin_enrolment(USER_ID, account_name=EMAIL)
    codes = mfa.confirm_enrolment(USER_ID, code_now(enrolment.secret))
    assert mfa.factors_for(USER_ID) == [TOTP_FACTOR]
    assert len(codes.codes) == RECOVERY_CODE_COUNT
    factor = stores.require_totp_factors().get(USER_ID)
    assert factor is not None and factor.is_active


def test_confirming_with_a_wrong_code_leaves_the_factor_inactive(mfa: MfaService) -> None:
    mfa.begin_enrolment(USER_ID, account_name=EMAIL)
    with pytest.raises(MfaRejected):
        mfa.confirm_enrolment(USER_ID, "000000")
    assert mfa.factors_for(USER_ID) == []


def test_the_confirming_code_cannot_then_be_replayed_as_a_login_code(mfa: MfaService) -> None:
    """Activation records the step it was confirmed at.

    Without that, the code the user typed to finish enrolment is still valid for the rest of
    its thirty second window, and anyone who watched them type it can use it.
    """
    enrolment = mfa.begin_enrolment(USER_ID, account_name=EMAIL)
    code = code_now(enrolment.secret)
    mfa.confirm_enrolment(USER_ID, code)
    with pytest.raises(MfaRejected):
        mfa.verify_challenge(USER_ID, code)


def test_enrolling_again_over_an_active_factor_is_refused(mfa: MfaService) -> None:
    """409, not a silent replacement.

    Overwriting a working authenticator with an unconfirmed seed is how a user ends up with
    a factor they cannot satisfy. Replacing one means disabling and enrolling again.
    """
    enrol(mfa)
    with pytest.raises(MfaRejected) as caught:
        mfa.begin_enrolment(USER_ID, account_name=EMAIL)
    assert caught.value.error_code == "TOTP_ALREADY_ENABLED"
    assert caught.value.status_code == 409


def test_enrolling_again_over_a_pending_factor_issues_a_new_seed(mfa: MfaService) -> None:
    """A user who lost the first QR code before confirming just starts again.

    The seed is never redisplayed, so the only thing `begin_enrolment` can do for them is
    issue a fresh one, and the old pending row must not survive to be confirmed later.
    """
    first = mfa.begin_enrolment(USER_ID, account_name=EMAIL)
    second = mfa.begin_enrolment(USER_ID, account_name=EMAIL)
    assert first.secret != second.secret
    with pytest.raises(MfaRejected):
        mfa.confirm_enrolment(USER_ID, code_now(first.secret))
    mfa.confirm_enrolment(USER_ID, code_now(second.secret))
    assert mfa.factors_for(USER_ID) == [TOTP_FACTOR]


def test_confirming_with_no_pending_enrolment_is_refused(mfa: MfaService) -> None:
    with pytest.raises(MfaRejected) as caught:
        mfa.confirm_enrolment(USER_ID, "123456")
    assert caught.value.error_code == "NO_PENDING_ENROLMENT"


def test_disabling_removes_the_factor_and_every_recovery_code(
    mfa: MfaService, stores: IdentityStores
) -> None:
    """Both, always.

    Recovery codes left behind after TOTP is disabled are live credentials satisfying a
    factor the user believes is gone, and nothing in the UI would ever show them again.
    """
    _, codes = enrol(mfa)
    mfa.disable_totp(USER_ID)
    assert mfa.factors_for(USER_ID) == []
    assert stores.require_totp_factors().get(USER_ID) is None
    assert list(stores.require_recovery_codes().list_for_user(USER_ID)) == []
    with pytest.raises(MfaRejected):
        mfa.verify_challenge(USER_ID, codes[0])


# ---------------------------------------------------------------------------
# Verification through the service
# ---------------------------------------------------------------------------


def test_a_totp_code_is_accepted_once_and_then_refused(mfa: MfaService) -> None:
    """The replay refusal at the level a route actually reaches.

    The pure function has its own test; this one proves the watermark is written, which is
    the half that is easy to leave out.
    """
    seed, _ = enrol(mfa)
    code = code_now(seed, offset=1)
    assert mfa.verify_challenge(USER_ID, code) == AMR_OTP
    with pytest.raises(MfaRejected):
        mfa.verify_challenge(USER_ID, code)


def test_a_recovery_code_is_accepted_once_and_then_refused(mfa: MfaService) -> None:
    _, codes = enrol(mfa)
    assert mfa.verify_challenge(USER_ID, codes[0]) == AMR_RECOVERY
    with pytest.raises(MfaRejected):
        mfa.verify_challenge(USER_ID, codes[0])


def test_spending_one_recovery_code_leaves_the_others_alone(mfa: MfaService) -> None:
    _, codes = enrol(mfa)
    mfa.verify_challenge(USER_ID, codes[0])
    assert mfa.remaining_recovery_codes(USER_ID) == RECOVERY_CODE_COUNT - 1
    assert mfa.verify_challenge(USER_ID, codes[1]) == AMR_RECOVERY


def test_a_recovery_code_is_accepted_however_it_was_typed(mfa: MfaService) -> None:
    """Read off paper, so hyphens and case must not matter.

    Base32 has no lower case and no 0, 1 or 8, so folding case introduces no ambiguity.
    """
    _, codes = enrol(mfa)
    typed = codes[0].replace("-", "").lower()
    assert mfa.verify_challenge(USER_ID, typed) == AMR_RECOVERY


def test_recovery_codes_are_stored_hashed(mfa: MfaService, stores: IdentityStores) -> None:
    """A code is only ever compared, so the store holds the weakest thing that supports that.

    The seed is the opposite case and is sealed rather than hashed, because verification
    needs it back. Two secrets, two storage choices, for one reason each.
    """
    _, codes = enrol(mfa)
    stored = list(stores.require_recovery_codes().list_for_user(USER_ID))
    hashes_stored = {record.code_hash for record in stored}
    for code in codes:
        assert code not in hashes_stored
        assert normalise_recovery_code(code) not in hashes_stored
        assert hash_recovery_code(code) in hashes_stored


def test_the_stored_hash_is_of_the_normalised_code() -> None:
    """Otherwise the same code typed with and without hyphens hashes differently."""
    assert hash_recovery_code("abcde-fghij") == hash_recovery_code("ABCDEFGHIJ")
    assert hash_recovery_code("abcde fghij") == hash_recovery_code("ABCDEFGHIJ")


def test_regenerating_invalidates_the_previous_set(mfa: MfaService) -> None:
    """The entire reason a user regenerates is that the old printout is no longer trusted.

    A new set that leaves the old one working has not done the thing the user asked for.
    """
    _, old = enrol(mfa)
    fresh = mfa.regenerate_recovery_codes(USER_ID)
    assert len(fresh.codes) == RECOVERY_CODE_COUNT
    assert set(fresh.codes).isdisjoint(old)
    with pytest.raises(MfaRejected):
        mfa.verify_challenge(USER_ID, old[0])
    assert mfa.verify_challenge(USER_ID, fresh.codes[0]) == AMR_RECOVERY


def test_one_users_codes_do_not_work_for_another(mfa: MfaService, hooks: FakeHooks) -> None:
    hooks.add("other@example.com", user_id="user-0002")
    seed, codes = enrol(mfa)
    enrol(mfa, "user-0002")
    with pytest.raises(MfaRejected):
        mfa.verify_challenge("user-0002", codes[0])
    with pytest.raises(MfaRejected):
        mfa.verify_challenge("user-0002", code_now(seed, offset=1))


def test_a_user_with_no_factor_is_refused_rather_than_waved_through(mfa: MfaService) -> None:
    """The failure mode where "no factor configured" reads as "nothing to check"."""
    with pytest.raises(MfaRejected):
        mfa.verify_challenge(USER_ID, "123456")


def test_every_refusal_carries_the_same_message(mfa: MfaService) -> None:
    """Enumeration resistance: a caller must not learn *why* a code failed.

    Wrong code, replayed code, unknown user and no factor all answer identically. A distinct
    message for "you have no TOTP factor" tells an attacker which accounts to target with
    something else.
    """
    seed, codes = enrol(mfa)
    spent = code_now(seed, offset=1)
    mfa.verify_challenge(USER_ID, spent)
    mfa.verify_challenge(USER_ID, codes[0])

    messages = set()
    for user, code in (
        (USER_ID, "000000"),
        (USER_ID, spent),
        (USER_ID, codes[0]),
        ("user-9999", "000000"),
        ("user-9999", "NOT-A-REAL-CODE"),
    ):
        with pytest.raises(MfaRejected) as caught:
            mfa.verify_challenge(user, code)
        messages.add((caught.value.message, caught.value.error_code, caught.value.status_code))
    assert len(messages) == 1


def test_a_seed_that_cannot_be_decrypted_is_an_ordinary_refusal(
    mfa: MfaService, stores: IdentityStores
) -> None:
    """A key policy change is not something the user can act on.

    It is logged as the fault it is, but the caller sees the same 401 as a wrong code: an
    attacker should not learn that the key stopped working either.
    """
    enrol(mfa)
    store = stores.require_totp_factors()
    factor = store.get(USER_ID)
    assert factor is not None
    store.put(
        TotpFactorRecord(
            user_id=USER_ID,
            secret_ciphertext=factor.secret_ciphertext,
            secret_nonce=factor.secret_nonce,
            wrapped_data_key=base64.b64encode(b"nonsense").decode("ascii"),
            created_at=factor.created_at,
            activated_at=factor.activated_at,
        )
    )
    with pytest.raises(MfaRejected) as caught:
        mfa.verify_challenge(USER_ID, "123456")
    assert caught.value.status_code == 401


# ---------------------------------------------------------------------------
# The MFA ticket
# ---------------------------------------------------------------------------


def test_a_ticket_is_not_an_access_token(mfa: MfaService, kms: FakeKms) -> None:
    """Three separations, and the audience is the one that matters at the gateway.

    An API Gateway JWT authorizer configured for the API's audience must refuse a ticket, or
    the first leg of login hands out something that opens every route behind it.
    """
    settings = make_settings()
    tokens = TokenService(settings, kms)
    challenge = mfa.issue_challenge(USER_ID, factors=[TOTP_FACTOR])
    claims = claims_of(challenge.ticket)
    assert claims["typ"] == MFA_TICKET_TYPE
    assert claims["aud"] == f"{ISSUER}/mfa"
    assert claims["aud"] != AUDIENCE
    assert "sid" not in claims
    with pytest.raises(InvalidToken):
        tokens.verify_access_token(challenge.ticket)


def test_an_access_token_is_not_a_ticket(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    """The other direction, which does not follow from the first.

    A ticket verifier that only checked the signature would accept every access token the
    issuer ever minted, and any of them would complete somebody's second login leg.
    """
    seed_account(hooks, stores)
    result = flows.login(email=EMAIL, password=PASSWORD)
    tokens = TokenService(make_settings(), kms)
    assert claims_of(result.access_token)["typ"] == ACCESS_TOKEN_TYPE
    with pytest.raises(InvalidToken):
        tokens.verify_mfa_ticket(result.access_token)


def test_a_ticket_is_short_lived(mfa: MfaService) -> None:
    """Five minutes, per the settings default. It is the gap between two legs of one login.

    An access token's lifetime would be wrong here: nothing is happening in between except
    a user reading six digits off a screen.
    """
    challenge = mfa.issue_challenge(USER_ID, factors=[TOTP_FACTOR])
    claims = claims_of(challenge.ticket)
    assert claims["exp"] - claims["iat"] == 300


def test_a_ticket_is_recorded_before_it_is_returned(
    mfa: MfaService, stores: IdentityStores
) -> None:
    """The safe failure direction.

    A ticket with no row cannot be spent, so a failed write costs a login the user retries.
    A row written after the return would mean a window where the ticket works twice.
    """
    from webbpulse.identity import hash_token

    challenge = mfa.issue_challenge(USER_ID, factors=[TOTP_FACTOR])
    jti = str(claims_of(challenge.ticket)["jti"])
    record = stores.require_identity_tokens().get(hash_token(jti))
    assert record is not None
    assert record.purpose == "mfa_ticket"
    assert record.user_id == USER_ID


def test_a_ticket_is_spent_by_its_first_use(mfa: MfaService) -> None:
    challenge = mfa.issue_challenge(USER_ID, factors=[TOTP_FACTOR])
    assert mfa.consume_ticket(challenge.ticket) == USER_ID
    with pytest.raises(MfaRejected) as caught:
        mfa.consume_ticket(challenge.ticket)
    assert caught.value.error_code == "MFA_TICKET_INVALID"


def test_a_forged_ticket_is_refused(mfa: MfaService) -> None:
    with pytest.raises(MfaRejected):
        mfa.consume_ticket("not.a.token")


def test_the_challenge_body_matches_what_the_frontend_reads(mfa: MfaService) -> None:
    """`@webbpulse/auth` 0.4.0 branches on exactly these three keys.

    Asserted as an exact set rather than key by key: an extra key is how a frontend that
    switches on the body shape starts taking a branch nobody intended.
    """
    challenge = mfa.issue_challenge(USER_ID, factors=[TOTP_FACTOR])
    body = challenge.as_body()
    assert set(body) == {"mfa_required", "mfa_ticket", "factors"}
    assert body["mfa_required"] is True
    assert body["factors"] == [TOTP_FACTOR]
    assert body["mfa_ticket"] == challenge.ticket


# ---------------------------------------------------------------------------
# Login: the two legs
# ---------------------------------------------------------------------------


def test_login_without_a_factor_still_issues_tokens_directly(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """M2's behaviour, unchanged for every user who has not enrolled."""
    seed_account(hooks, stores)
    result = flows.login(email=EMAIL, password=PASSWORD)
    assert result.access_token
    assert result.refresh_token


def test_login_with_a_factor_raises_the_challenge_instead_of_issuing_tokens(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Raised rather than returned, so a product that has not handled MFA fails loudly.

    A second success shape returned from `login` would be silently ignored by every existing
    caller, and those callers would hand out sessions to users who never satisfied a factor.
    """
    seed_account(hooks, stores)
    enrol(mfa)
    with pytest.raises(MfaChallengeRequired) as caught:
        flows.login(email=EMAIL, password=PASSWORD)
    assert caught.value.challenge.factors == [TOTP_FACTOR]


def test_a_pending_enrolment_does_not_challenge_a_login(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A factor the user never confirmed cannot be satisfied, so challenging on it locks
    them out with no way through."""
    seed_account(hooks, stores)
    mfa.begin_enrolment(USER_ID, account_name=EMAIL)
    assert flows.login(email=EMAIL, password=PASSWORD).access_token


def test_a_wrong_password_is_refused_before_any_ticket_is_minted(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Ordering, and it is the ordering that matters.

    A ticket minted before the password check is a ticket anybody can get for any account,
    and the second leg would then be the only thing standing between them and a session.
    """
    from webbpulse.identity.flows import LoginRejected

    seed_account(hooks, stores)
    enrol(mfa)
    with pytest.raises(LoginRejected):
        flows.login(email=EMAIL, password="wrong password entirely")
    # `revoke_for_user` reports how many rows it removed, which is the only count the store
    # ABC exposes. Zero here means no ticket was ever written.
    assert stores.require_identity_tokens().revoke_for_user(USER_ID, "mfa_ticket") == 0


def test_completing_the_second_leg_issues_the_session(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    seed_account(hooks, stores)
    seed, _ = enrol(mfa)
    with pytest.raises(MfaChallengeRequired) as caught:
        flows.login(email=EMAIL, password=PASSWORD)
    ticket = caught.value.challenge.ticket

    result = flows.complete_mfa(ticket=ticket, code=code_now(seed, offset=1))
    assert result.access_token
    assert result.refresh_token
    assert claims_of(result.access_token)["sub"] == USER_ID


def test_a_recovery_code_completes_the_second_leg(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """One route takes both kinds, so a user who lost their phone is not locked out."""
    seed_account(hooks, stores)
    _, codes = enrol(mfa)
    with pytest.raises(MfaChallengeRequired) as caught:
        flows.login(email=EMAIL, password=PASSWORD)
    result = flows.complete_mfa(ticket=caught.value.challenge.ticket, code=codes[0])
    assert AMR_RECOVERY in claims_of(result.access_token)["amr"]


def test_the_ticket_is_spent_even_when_the_code_is_wrong(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Deliberate, and the stricter choice.

    A ticket that survives a wrong code is a ticket a thief can grind codes against. Spending
    it first means a user who mistypes signs in again, which costs them a password entry and
    costs an attacker the whole attempt.
    """
    seed_account(hooks, stores)
    seed, _ = enrol(mfa)
    with pytest.raises(MfaChallengeRequired) as caught:
        flows.login(email=EMAIL, password=PASSWORD)
    ticket = caught.value.challenge.ticket

    with pytest.raises(MfaRejected):
        flows.complete_mfa(ticket=ticket, code="000000")
    with pytest.raises(MfaRejected) as second:
        flows.complete_mfa(ticket=ticket, code=code_now(seed, offset=1))
    assert second.value.error_code == "MFA_TICKET_INVALID"


def test_one_users_ticket_cannot_be_completed_with_another_users_code(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """The ticket binds the second leg to the login it came from.

    Without that binding, anybody holding their own valid code could complete a ticket
    issued for somebody else's password.
    """
    seed_account(hooks, stores)
    seed_account(hooks, stores, email="other@example.com", user_id="user-0002")
    enrol(mfa)
    other_seed, _ = enrol(mfa, "user-0002")

    with pytest.raises(MfaChallengeRequired) as caught:
        flows.login(email=EMAIL, password=PASSWORD)
    with pytest.raises(MfaRejected):
        flows.complete_mfa(
            ticket=caught.value.challenge.ticket, code=code_now(other_seed, offset=1)
        )


def test_completing_with_no_ticket_is_refused(flows: IdentityFlows) -> None:
    with pytest.raises(MfaRejected):
        flows.complete_mfa(ticket="", code="123456")


# ---------------------------------------------------------------------------
# `amr` and `auth_time`
# ---------------------------------------------------------------------------


def test_a_password_only_login_claims_pwd_alone(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """No `mfa` value, because one factor is not multi-factor.

    A route asserting on `amr` containing `mfa` is asserting on exactly this distinction, so
    claiming it for a single factor would make the assertion meaningless.
    """
    seed_account(hooks, stores)
    claims = claims_of(flows.login(email=EMAIL, password=PASSWORD).access_token)
    assert claims["amr"] == [AMR_PASSWORD]
    assert AMR_MFA not in claims["amr"]


def test_a_two_leg_login_claims_the_factors_and_mfa(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """RFC 8176 values, and `mfa` appended because more than one method was used."""
    seed_account(hooks, stores)
    seed, _ = enrol(mfa)
    with pytest.raises(MfaChallengeRequired) as caught:
        flows.login(email=EMAIL, password=PASSWORD)
    result = flows.complete_mfa(ticket=caught.value.challenge.ticket, code=code_now(seed, offset=1))
    amr = claims_of(result.access_token)["amr"]
    assert AMR_PASSWORD in amr
    assert AMR_OTP in amr
    assert AMR_MFA in amr


def test_recovery_is_not_claimed_as_an_rfc_8176_factor(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """`recovery` is deliberately not `otp`.

    A recovery code is a bearer secret off a printout, not a possession factor, and a route
    that requires a real second factor for something sensitive has to be able to tell them
    apart. Claiming `otp` for a recovery code would make that impossible.
    """
    seed_account(hooks, stores)
    _, codes = enrol(mfa)
    with pytest.raises(MfaChallengeRequired) as caught:
        flows.login(email=EMAIL, password=PASSWORD)
    amr = claims_of(
        flows.complete_mfa(ticket=caught.value.challenge.ticket, code=codes[0]).access_token
    )["amr"]
    assert AMR_RECOVERY in amr
    assert AMR_OTP not in amr


def test_a_hook_cannot_forge_amr_or_auth_time(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """`claims_for` returns both here, and neither survives.

    The claims are applied after the hook, not merged with it. A product hook that could set
    `amr` could assert a factor its user never satisfied, and every step-up check downstream
    would believe it.
    """
    seed_account(hooks, stores)
    claims = claims_of(flows.login(email=EMAIL, password=PASSWORD).access_token)
    assert claims["amr"] == [AMR_PASSWORD]
    assert claims["auth_time"] != 1


def test_auth_time_is_present_and_recent_on_a_login(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    seed_account(hooks, stores)
    claims = claims_of(flows.login(email=EMAIL, password=PASSWORD).access_token)
    assert abs(int(claims["auth_time"]) - int(time.time())) < 5


# ---------------------------------------------------------------------------
# Step-up
# ---------------------------------------------------------------------------


def test_step_up_returns_a_fresher_auth_time_without_a_new_session(
    flows: IdentityFlows,
    mfa: MfaService,
    hooks: FakeHooks,
    stores: IdentityStores,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The `auth_time` moves, the session does not.

    Section 2.6 asserts on freshness rather than on a boolean precisely so that "recently"
    is expressible. A new refresh family here would log the user out of nothing and rotate a
    cookie that never moved.
    """
    seed_account(hooks, stores)
    seed, _ = enrol(mfa)
    with pytest.raises(MfaChallengeRequired) as caught:
        flows.login(email=EMAIL, password=PASSWORD)
    first = flows.complete_mfa(ticket=caught.value.challenge.ticket, code=code_now(seed, offset=1))
    session = claims_of(first.access_token)["sid"]

    first_auth_time = int(claims_of(first.access_token)["auth_time"])
    with clock_advanced(monkeypatch, 2):
        stepped = flows.step_up(user_id=USER_ID, session_id=str(session), code=code_now(seed))
        expected = int(time.time())
    claims = claims_of(stepped.access_token)
    assert claims["sid"] == session
    assert stepped.refresh_token == ""
    assert stepped.family_id == session
    # Compared against the advanced clock, and asserted to have actually moved. Comparing
    # against real time would pass on an implementation that never refreshed `auth_time`
    # at all, which is the one thing this test exists to rule out.
    assert abs(int(claims["auth_time"]) - expected) < 5
    assert int(claims["auth_time"]) > first_auth_time
    assert AMR_OTP in claims["amr"]


def test_step_up_with_a_wrong_code_is_refused(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    seed_account(hooks, stores)
    enrol(mfa)
    with pytest.raises(MfaRejected):
        flows.step_up(user_id=USER_ID, session_id="session-1", code="000000")


def test_step_up_for_an_unknown_user_is_refused(flows: IdentityFlows) -> None:
    with pytest.raises(MfaRejected):
        flows.step_up(user_id="user-9999", session_id="session-1", code="123456")


def test_step_up_spends_the_code_it_used(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Same replay refusal as login. A step-up code is not a lesser code."""
    seed_account(hooks, stores)
    seed, _ = enrol(mfa)
    code = code_now(seed, offset=1)
    flows.step_up(user_id=USER_ID, session_id="session-1", code=code)
    with pytest.raises(MfaRejected):
        flows.step_up(user_id=USER_ID, session_id="session-1", code=code)
    # And still refused a moment later, while the code is inside the window but behind the
    # watermark. This is the case a naive "is it the current code" check would let through.
    with pytest.raises(MfaRejected):
        flows.step_up(user_id=USER_ID, session_id="session-1", code=code)


# ---------------------------------------------------------------------------
# The stores
# ---------------------------------------------------------------------------


def test_a_factor_activates_exactly_once() -> None:
    """`activate` returning `False` the second time is what makes the route's 409 correct."""
    store = InMemoryTotpFactorStore()
    store.put(
        TotpFactorRecord(
            user_id=USER_ID,
            secret_ciphertext="c",
            secret_nonce="n",
            wrapped_data_key="w",
            created_at="2026-09-10T00:00:00Z",
        )
    )
    assert store.activate(USER_ID, step=100) is True
    assert store.activate(USER_ID, step=101) is False


def test_the_step_watermark_only_moves_forward() -> None:
    """The conditional write, which on DynamoDB is what makes two concurrent presentations
    of the same code resolve to one acceptance."""
    store = InMemoryTotpFactorStore()
    store.put(
        TotpFactorRecord(
            user_id=USER_ID,
            secret_ciphertext="c",
            secret_nonce="n",
            wrapped_data_key="w",
            created_at="2026-09-10T00:00:00Z",
        )
    )
    store.activate(USER_ID, step=100)
    assert store.record_use(USER_ID, step=101) is True
    assert store.record_use(USER_ID, step=101) is False
    assert store.record_use(USER_ID, step=100) is False
    assert store.record_use(USER_ID, step=102) is True


def test_a_recovery_code_consumes_exactly_once() -> None:
    store = InMemoryRecoveryCodeStore()
    digest = hash_recovery_code("ABCDE-FGHIJ")
    store.put_many(
        [RecoveryCodeRecord(user_id=USER_ID, code_hash=digest, created_at="2026-09-10T00:00:00Z")]
    )
    assert store.consume(USER_ID, digest) is True
    assert store.consume(USER_ID, digest) is False


def test_consuming_an_unknown_code_reports_failure_rather_than_raising() -> None:
    store = InMemoryRecoveryCodeStore()
    assert store.consume(USER_ID, hash_recovery_code("NOPE")) is False


def test_recovery_codes_are_scoped_to_their_user() -> None:
    store = InMemoryRecoveryCodeStore()
    digest = hash_recovery_code("ABCDE-FGHIJ")
    store.put_many(
        [RecoveryCodeRecord(user_id=USER_ID, code_hash=digest, created_at="2026-09-10T00:00:00Z")]
    )
    assert store.consume("user-0002", digest) is False
    assert store.consume(USER_ID, digest) is True


def test_deleting_a_users_codes_leaves_another_users_alone() -> None:
    store = InMemoryRecoveryCodeStore()
    created = "2026-09-10T00:00:00Z"
    mine = hash_recovery_code("MINE-CODE")
    theirs = hash_recovery_code("THEIR-CODE")
    store.put_many([RecoveryCodeRecord(user_id=USER_ID, code_hash=mine, created_at=created)])
    store.put_many([RecoveryCodeRecord(user_id="user-0002", code_hash=theirs, created_at=created)])
    store.delete_for_user(USER_ID)
    assert list(store.list_for_user(USER_ID)) == []
    assert store.consume("user-0002", theirs) is True


# ---------------------------------------------------------------------------
# The routes
# ---------------------------------------------------------------------------


def router_paths(**kwargs: Any) -> set[str]:
    """The paths one built router declares.

    Read off the router rather than off an app, the way the M2 and M3 suites do: an app's
    `routes` list holds the include wrapper rather than the routes themselves.
    """
    router = build_identity_router(make_settings(), limiter_enabled=False, **kwargs)
    return {route.path for route in router.routes}  # type: ignore[attr-defined]


def test_the_mfa_routes_are_declared(
    hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    paths = router_paths(hooks=hooks, stores=stores, kms_client=kms)
    for path in (
        LOGIN_TOTP_PATH,
        TOTP_ENROL_PATH,
        TOTP_ACTIVATE_PATH,
        TOTP_DISABLE_PATH,
        RECOVERY_CODES_PATH,
        STEP_UP_PATH,
    ):
        assert f"{prefix()}{path}" in paths


def test_the_mfa_routes_are_absent_when_the_stores_are_not_wired(
    hooks: FakeHooks, kms: FakeKms
) -> None:
    """Section 6.1 makes TOTP a capability, and a capability that cannot be switched off is
    not one.

    A route answering 503 because the product never created the tables is worse than a route
    that does not exist: it appears in the OpenAPI document as something a caller can use.
    """
    paths = router_paths(
        hooks=hooks,
        stores=IdentityStores(
            credentials=InMemoryCredentialStore(),
            refresh_tokens=InMemoryRefreshTokenStore(),
            identity_tokens=InMemoryIdentityTokenStore(),
        ),
        kms_client=kms,
    )
    assert f"{prefix()}{LOGIN_TOTP_PATH}" not in paths
    assert f"{prefix()}{LOGIN_PATH}" in paths


def test_the_mfa_routes_are_absent_when_totp_is_disabled(
    hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    router = build_identity_router(
        make_settings(totp_enabled=False),
        hooks,
        stores,
        kms_client=kms,
        limiter_enabled=False,
    )
    paths = {route.path for route in router.routes}  # type: ignore[attr-defined]
    assert f"{prefix()}{LOGIN_TOTP_PATH}" not in paths
    assert f"{prefix()}{LOGIN_PATH}" in paths


def test_login_answers_200_with_the_challenge_not_401(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    """The single most load-bearing assertion in this file.

    `@webbpulse/auth` 0.4.0 branches on the body of a **successful** response. A 401 here,
    however sensible it looks, sends every MFA user down the frontend's error path and there
    is no way for them to sign in. Nothing was refused: the password was correct.
    """
    seed_account(hooks, stores)
    settings = make_settings()
    service = MfaService(settings, stores, TokenService(settings, kms), kms_client=kms)
    enrol(service)

    response = client.post(f"{prefix()}{LOGIN_PATH}", json={"email": EMAIL, "password": PASSWORD})
    assert response.status_code == 200
    body = response.json()
    assert body["mfa_required"] is True
    assert body["factors"] == [TOTP_FACTOR]
    assert body["mfa_ticket"]
    assert "access_token" not in body
    assert "wp_refresh" not in response.cookies


def test_the_second_leg_reads_the_field_names_the_frontend_sends(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    """`mfa_ticket`, not `ticket`. That is what `AuthClient.completeTotp` posts.

    A rename here type-checks perfectly on both sides and breaks every sign-in, which is
    exactly the class of failure a test on the wire names exists to catch.
    """
    seed_account(hooks, stores)
    settings = make_settings()
    service = MfaService(settings, stores, TokenService(settings, kms), kms_client=kms)
    seed, _ = enrol(service)

    first = client.post(f"{prefix()}{LOGIN_PATH}", json={"email": EMAIL, "password": PASSWORD})
    ticket = first.json()["mfa_ticket"]

    response = client.post(
        f"{prefix()}{LOGIN_TOTP_PATH}",
        json={"mfa_ticket": ticket, "code": code_now(seed, offset=1)},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["access_token"]
    assert "wp_refresh" in response.cookies


def test_the_second_leg_refuses_a_wrong_code_in_the_shared_envelope(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    """One envelope for every refusal, so the frontend has one error shape to read."""
    seed_account(hooks, stores)
    settings = make_settings()
    service = MfaService(settings, stores, TokenService(settings, kms), kms_client=kms)
    enrol(service)

    first = client.post(f"{prefix()}{LOGIN_PATH}", json={"email": EMAIL, "password": PASSWORD})
    response = client.post(
        f"{prefix()}{LOGIN_TOTP_PATH}",
        json={"mfa_ticket": first.json()["mfa_ticket"], "code": "000000"},
    )
    assert response.status_code == 401
    assert response.json()["error_code"] == "INVALID_MFA_CODE"


def test_the_enrolment_routes_refuse_an_unauthenticated_caller(client: TestClient) -> None:
    """The subject comes from verified claims, never from the body.

    A user id in the body is how anybody enrols a factor on anybody's account, or disables
    one on an account they are locking somebody out of.
    """
    for path in (TOTP_ENROL_PATH, TOTP_DISABLE_PATH, RECOVERY_CODES_PATH):
        response = client.post(f"{prefix()}{path}", json={})
        assert response.status_code == 401, path
        assert response.json()["error_code"] == "NOT_AUTHENTICATED"


def test_the_enrolment_round_trip_over_http(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Enrol, activate, sign out, and sign in again through the challenge.

    End to end over the routes rather than through the service, because the wiring between
    them is where a subject read from the wrong place would show up.
    """
    seed_account(hooks, stores)
    login = client.post(f"{prefix()}{LOGIN_PATH}", json={"email": EMAIL, "password": PASSWORD})
    access = login.json()["access_token"]
    auth = {"Authorization": f"Bearer {access}"}

    enrolment = client.post(f"{prefix()}{TOTP_ENROL_PATH}", headers=auth, json={})
    assert enrolment.status_code == 200
    secret = enrolment.json()["secret"]
    assert enrolment.json()["provisioning_uri"].startswith("otpauth://totp/")

    activation = client.post(
        f"{prefix()}{TOTP_ACTIVATE_PATH}", headers=auth, json={"code": code_now(secret)}
    )
    assert activation.status_code == 200
    assert activation.json()["activated"] is True
    codes = activation.json()["recovery_codes"]
    assert len(codes) == RECOVERY_CODE_COUNT

    challenge = client.post(f"{prefix()}{LOGIN_PATH}", json={"email": EMAIL, "password": PASSWORD})
    assert challenge.json()["mfa_required"] is True
    completed = client.post(
        f"{prefix()}{LOGIN_TOTP_PATH}",
        json={"mfa_ticket": challenge.json()["mfa_ticket"], "code": codes[0]},
    )
    assert completed.status_code == 200


def test_the_enrolment_route_returns_the_seed_exactly_once(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """There is no route that reads a seed back.

    A user who loses it before confirming enrols again and gets a new one. A read-back route
    would turn every stolen access token into a copy of the user's second factor.
    """
    seed_account(hooks, stores)
    login = client.post(f"{prefix()}{LOGIN_PATH}", json={"email": EMAIL, "password": PASSWORD})
    auth = {"Authorization": f"Bearer {login.json()['access_token']}"}
    first = client.post(f"{prefix()}{TOTP_ENROL_PATH}", headers=auth, json={}).json()["secret"]
    second = client.post(f"{prefix()}{TOTP_ENROL_PATH}", headers=auth, json={}).json()["secret"]
    assert first != second


def test_regenerating_over_http_replaces_the_set(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    seed_account(hooks, stores)
    settings = make_settings()
    service = MfaService(settings, stores, TokenService(settings, kms), kms_client=kms)
    seed, old = enrol(service)

    challenge = client.post(f"{prefix()}{LOGIN_PATH}", json={"email": EMAIL, "password": PASSWORD})
    completed = client.post(
        f"{prefix()}{LOGIN_TOTP_PATH}",
        json={"mfa_ticket": challenge.json()["mfa_ticket"], "code": code_now(seed, offset=1)},
    )
    auth = {"Authorization": f"Bearer {completed.json()['access_token']}"}

    response = client.post(f"{prefix()}{RECOVERY_CODES_PATH}", headers=auth, json={})
    assert response.status_code == 200
    fresh = response.json()["recovery_codes"]
    assert len(fresh) == RECOVERY_CODE_COUNT
    assert set(fresh).isdisjoint(old)


def test_step_up_over_http_does_not_rotate_the_refresh_cookie(
    client: TestClient,
    hooks: FakeHooks,
    stores: IdentityStores,
    kms: FakeKms,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No `Set-Cookie` at all. Step-up starts no family, so there is nothing to write."""
    seed_account(hooks, stores)
    settings = make_settings()
    service = MfaService(settings, stores, TokenService(settings, kms), kms_client=kms)
    seed, _ = enrol(service)

    challenge = client.post(f"{prefix()}{LOGIN_PATH}", json={"email": EMAIL, "password": PASSWORD})
    completed = client.post(
        f"{prefix()}{LOGIN_TOTP_PATH}",
        json={"mfa_ticket": challenge.json()["mfa_ticket"], "code": code_now(seed, offset=1)},
    )
    auth = {"Authorization": f"Bearer {completed.json()['access_token']}"}

    with clock_advanced(monkeypatch, 2):
        response = client.post(
            f"{prefix()}{STEP_UP_PATH}", headers=auth, json={"code": code_now(seed)}
        )
    assert response.status_code == 200
    assert "set-cookie" not in {name.lower() for name in response.headers}
    assert AMR_OTP in claims_of(response.json()["access_token"])["amr"]


def test_the_verify_limit_matches_section_5_1() -> None:
    """Ten attempts per fifteen minutes.

    The limit is the other half of the replay defence: a million-value code space is only
    out of reach while the number of guesses is bounded, and this is the bound.
    """
    assert TOTP_VERIFY_LIMIT == (10, 900)
