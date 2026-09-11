"""Tests for the M4 identity work: TOTP, recovery codes, the MFA ticket, step-up and `amr`.

Covers the RFC 6238 vectors, single-use enforcement on every spendable secret, the KMS
envelope against a hand fake and moto, and the login and MFA route contracts.
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
    """Local signing plus a local stand-in for the two envelope calls, in one object."""

    def __init__(self, keys: dict[str, rsa.RSAPrivateKey]) -> None:
        """Hold the signing keys and start an empty data key call log."""
        self._keys = keys
        self.data_key_calls: list[dict[str, Any]] = []

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

    def generate_data_key(
        self, *, KeyId: str, NumberOfBytes: int, EncryptionContext: Mapping[str, str]
    ) -> dict[str, Any]:
        """Record the request and return a random data key wrapped with its encryption context."""
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
        """Unwrap a data key, raising when the encryption context does not match."""
        try:
            encoded, context = CiphertextBlob.split(b"|", 1)
        except ValueError as exc:
            raise RuntimeError("InvalidCiphertextException") from exc
        if context != _context_bytes(EncryptionContext):
            raise RuntimeError("InvalidCiphertextException")
        return {"KeyId": DATA_KEY, "Plaintext": base64.b64decode(encoded)}


def _context_bytes(context: Mapping[str, str]) -> bytes:
    """A stable byte encoding of an encryption context, for comparing contexts in the fake."""
    return repr(sorted(context.items())).encode("utf-8")


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
    """Identity settings for this suite, with a data key ARN and TOTP wired."""
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
        """Start with no users and an empty call log."""
        self.users: dict[str, dict[str, Any]] = {}
        self.by_email: dict[str, str] = {}
        self.refuse = refuse
        self.calls: list[str] = []
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
        """Return claims that try to set `amr` and `auth_time`, so the overwrite can be asserted."""
        self.calls.append("claims_for")
        return {"amr": ["forged"], "auth_time": 1}

    def create_user(self, *, email: str, attributes: Mapping[str, Any]) -> Mapping[str, Any]:
        """Create and record a user from an address and attributes."""
        self.calls.append("create_user")
        return self.add(email, **dict(attributes))


@pytest.fixture
def hooks() -> FakeHooks:
    """A fresh `FakeHooks` per test."""
    return FakeHooks()


@pytest.fixture
def stores() -> IdentityStores:
    """In-memory stores for credentials, refresh and identity tokens, TOTP factors and recovery codes."""
    return IdentityStores(
        credentials=InMemoryCredentialStore(),
        refresh_tokens=InMemoryRefreshTokenStore(),
        identity_tokens=InMemoryIdentityTokenStore(),
        totp_factors=InMemoryTotpFactorStore(),
        recovery_codes=InMemoryRecoveryCodeStore(),
    )


@pytest.fixture
def attempts() -> InMemoryLoginAttemptStore:
    """An in-memory login attempt store."""
    return InMemoryLoginAttemptStore()


@pytest.fixture
def flows(
    hooks: FakeHooks,
    stores: IdentityStores,
    kms: FakeKms,
    attempts: InMemoryLoginAttemptStore,
) -> IdentityFlows:
    """Identity flows wired to the fakes, with the KMS client supplied for the envelope."""
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
    """The MFA service off the flows, asserted to be mounted by the fixtures."""
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
            limiter_enabled=False,
        )
    )
    with TestClient(app, base_url="https://api.example.com") as test_client:
        yield test_client


def prefix() -> str:
    """The identity router path prefix for the suite's settings."""
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
    """Enrol and activate a factor through the service, returning the seed and recovery codes."""
    enrolment = mfa.begin_enrolment(user_id, account_name=EMAIL)
    step = totp_module.current_step()
    codes = mfa.confirm_enrolment(user_id, totp_module.generate_code(enrolment.secret, step=step))
    return enrolment.secret, codes.codes


def code_now(seed: str, *, offset: int = 0) -> str:
    """The code for the current step, or `offset` steps away from it."""
    return totp_module.generate_code(seed, step=totp_module.current_step() + offset)


@contextmanager
def clock_advanced(monkeypatch: pytest.MonkeyPatch, steps: int) -> Iterator[None]:
    """Move the TOTP clock forward by whole time steps for the body of the block."""
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


RFC_SEED = base64.b32encode(b"12345678901234567890").decode("ascii").rstrip("=")

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
    """The generator reproduces the RFC 6238 Appendix B code for each published timestamp."""
    step = moment // totp_module.TIME_STEP_SECONDS
    assert totp_module.generate_code(RFC_SEED, step=step) == expected[-6:]


def test_a_code_is_six_digits_including_its_leading_zeros() -> None:
    """A code starting with a zero keeps it: the result is zero padded to `CODE_DIGITS`."""
    step = 1111111109 // totp_module.TIME_STEP_SECONDS
    assert totp_module.generate_code(RFC_SEED, step=step) == "081804"
    assert len(totp_module.generate_code(RFC_SEED, step=step)) == totp_module.CODE_DIGITS


def test_the_seed_is_long_enough_and_decodes_as_base32() -> None:
    """A generated seed is unpadded upper-case base32 decoding to at least 128 bits."""
    seed = totp_module.generate_seed()
    assert seed == seed.upper()
    assert "=" not in seed
    decoded = base64.b32decode(seed + "=" * (-len(seed) % 8))
    assert len(decoded) == totp_module.SEED_BYTES
    assert len(decoded) * 8 >= 128


def test_two_seeds_are_never_the_same() -> None:
    """Fifty generated seeds are all distinct, so the source is not a weak generator."""
    assert len({totp_module.generate_seed() for _ in range(50)}) == 50


def test_a_seed_is_accepted_however_the_user_typed_it() -> None:
    """Lower case, padding and grouped spaces all produce the same code as the canonical seed."""
    seed = totp_module.generate_seed()
    step = totp_module.current_step()
    expected = totp_module.generate_code(seed, step=step)
    spaced = " ".join(seed[i : i + 4] for i in range(0, len(seed), 4))
    for variant in (seed.lower(), seed + "=" * 4, spaced):
        assert totp_module.generate_code(variant, step=step) == expected


def test_a_seed_that_is_not_base32_raises_rather_than_producing_a_code() -> None:
    """A non-base32 seed raises `ValueError` rather than hashing garbage into a stable wrong code."""
    with pytest.raises(ValueError):
        totp_module.generate_code("not-valid-base32-1!", step=1)


def test_verification_accepts_the_current_step_and_returns_it() -> None:
    """`verify_code` returns the matched step, which is the watermark the caller has to store."""
    seed = totp_module.generate_seed()
    step = totp_module.current_step()
    assert totp_module.verify_code(seed, totp_module.generate_code(seed, step=step)) == step


def test_verification_accepts_one_step_either_side_and_not_two() -> None:
    """The window is one step each way: offsets of one verify, offsets of two return None."""
    seed = totp_module.generate_seed()
    now = totp_module.current_step()
    for offset in (-1, 0, 1):
        code = totp_module.generate_code(seed, step=now + offset)
        assert totp_module.verify_code(seed, code) == now + offset
    for offset in (-2, 2):
        code = totp_module.generate_code(seed, step=now + offset)
        assert totp_module.verify_code(seed, code) is None


def test_a_step_at_or_below_the_watermark_is_refused() -> None:
    """A step equal to or below `last_used_step` is refused, so the code just used cannot replay."""
    seed = totp_module.generate_seed()
    now = totp_module.current_step()
    code = totp_module.generate_code(seed, step=now)
    assert totp_module.verify_code(seed, code, last_used_step=now - 1) == now
    assert totp_module.verify_code(seed, code, last_used_step=now) is None
    assert totp_module.verify_code(seed, code, last_used_step=now + 5) is None


def test_a_wrong_code_of_the_right_shape_is_refused() -> None:
    """A six digit code that is not the current one returns None."""
    seed = totp_module.generate_seed()
    wrong = "000000" if code_now(seed) != "000000" else "111111"
    assert totp_module.verify_code(seed, wrong) is None


def test_codes_are_normalised_of_spaces_and_hyphens_only() -> None:
    """`normalise_code` strips spaces and hyphens and leaves any other character alone."""
    assert totp_module.normalise_code(" 123 456 ") == "123456"
    assert totp_module.normalise_code("123-456") == "123456"
    assert totp_module.normalise_code("12a456") == "12a456"


def test_the_provisioning_uri_is_a_uri_not_a_form_body() -> None:
    """A space in the issuer encodes as `%20`, never as the form encoding `+`."""
    seed = totp_module.generate_seed()
    uri = totp_module.provisioning_uri(seed, account_name=EMAIL, issuer="WebbPulse Portfolio")
    assert "+" not in uri
    assert "issuer=WebbPulse%20Portfolio" in uri


def test_the_provisioning_uri_carries_the_issuer_in_both_places() -> None:
    """The issuer appears in both the otpauth label prefix and the `issuer` parameter."""
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
    """`algorithm`, `digits` and `period` are omitted, since every app assumes the defaults."""
    uri = totp_module.provisioning_uri(
        totp_module.generate_seed(), account_name=EMAIL, issuer="Example"
    )
    assert "algorithm=" not in uri
    assert "digits=" not in uri
    assert "period=" not in uri


def test_an_independent_implementation_agrees_with_this_one() -> None:
    """Twenty random seeds agree with RFC 4226 dynamic truncation written out from the spec."""
    for _ in range(20):
        seed = totp_module.generate_seed()
        step = totp_module.current_step()
        key = base64.b32decode(seed + "=" * (-len(seed) % 8))
        digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
        assert totp_module.generate_code(seed, step=step) == f"{truncated % 1_000_000:06d}"


def test_a_sealed_seed_round_trips(kms: FakeKms) -> None:
    """A sealed secret opens back to its plaintext for the same user."""
    cipher = EnvelopeCipher(DATA_KEY, kms)
    sealed = cipher.seal(b"the seed", user_id=USER_ID)
    assert cipher.open(sealed, user_id=USER_ID) == b"the seed"


def test_the_sealed_fields_never_contain_the_plaintext(kms: FakeKms) -> None:
    """No field of the stored item contains the seed, in any case."""
    cipher = EnvelopeCipher(DATA_KEY, kms)
    seed = totp_module.generate_seed()
    sealed = cipher.seal(seed.encode("ascii"), user_id=USER_ID)
    for value in sealed.as_item().values():
        assert seed not in value
        assert seed.lower() not in value.lower()


def test_a_ciphertext_moved_to_another_users_row_will_not_open(kms: FakeKms) -> None:
    """Opening under a different user id fails, because `user_id` is in the encryption context."""
    cipher = EnvelopeCipher(DATA_KEY, kms)
    sealed = cipher.seal(b"the seed", user_id=USER_ID)
    with pytest.raises(EnvelopeDecryptionFailed):
        cipher.open(sealed, user_id="user-9999")


def test_a_ciphertext_from_another_purpose_will_not_open_as_a_seed(kms: FakeKms) -> None:
    """A secret sealed under another purpose will not open as a TOTP seed."""
    cipher = EnvelopeCipher(DATA_KEY, kms)
    sealed = cipher.seal(b"something else", user_id=USER_ID, purpose="other")
    with pytest.raises(EnvelopeDecryptionFailed):
        cipher.open(sealed, user_id=USER_ID)


def test_tampering_with_the_ciphertext_is_detected(kms: FakeKms) -> None:
    """A flipped ciphertext byte raises `EnvelopeDecryptionFailed`, as an authenticated mode must."""
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
    """Ten seals of the same plaintext give ten distinct nonces, wrapped keys and ciphertexts."""
    cipher = EnvelopeCipher(DATA_KEY, kms)
    sealed = [cipher.seal(b"the seed", user_id=USER_ID) for _ in range(10)]
    assert len({item.nonce for item in sealed}) == 10
    assert len({item.wrapped_key for item in sealed}) == 10
    assert len({item.ciphertext for item in sealed}) == 10


def test_the_data_key_request_asks_for_256_bits_under_the_configured_key(kms: FakeKms) -> None:
    """The data key request names the configured key, 32 bytes, and the user's encryption context."""
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
    """`SealedSecret.from_item` returns None for a row missing any of the three fields."""
    assert SealedSecret.from_item({}) is None
    assert SealedSecret.from_item({"secret_ciphertext": "x", "secret_nonce": "y"}) is None
    full = {"secret_ciphertext": "x", "secret_nonce": "y", "wrapped_data_key": "z"}
    assert SealedSecret.from_item(full) is not None


def test_the_envelope_works_against_moto() -> None:
    """A real KMS client under moto round trips a seal, and rejects a wrong context and a tampered key."""
    moto = pytest.importorskip("moto")
    boto3 = pytest.importorskip("boto3")

    with moto.mock_aws():
        kms_client = boto3.client("kms", region_name="us-west-2")
        key_id = kms_client.create_key(Description="totp seeds")["KeyMetadata"]["KeyId"]
        cipher = EnvelopeCipher(key_id, kms_client)

        seed = totp_module.generate_seed()
        sealed = cipher.seal(seed.encode("ascii"), user_id=USER_ID)
        assert cipher.open(sealed, user_id=USER_ID).decode("ascii") == seed

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
    """An unset `data_key_arn` raises naming `IDENTITY_DATA_KEY_ARN` rather than failing inside the cipher."""
    settings = make_settings(data_key_arn="")
    service = MfaService(settings, stores, TokenService(settings, kms), kms_client=kms)
    with pytest.raises(ValueError, match="IDENTITY_DATA_KEY_ARN"):
        _ = service.cipher


def test_enrolment_leaves_the_factor_inactive_until_a_code_confirms_it(
    mfa: MfaService, stores: IdentityStores
) -> None:
    """`begin_enrolment` writes an inactive factor, and `factors_for` reports none until confirmation."""
    mfa.begin_enrolment(USER_ID, account_name=EMAIL)
    factor = stores.require_totp_factors().get(USER_ID)
    assert factor is not None
    assert not factor.is_active
    assert mfa.factors_for(USER_ID) == []


def test_confirming_with_a_correct_code_activates_and_issues_recovery_codes(
    mfa: MfaService, stores: IdentityStores
) -> None:
    """A correct confirmation code activates the factor and issues the full set of recovery codes."""
    enrolment = mfa.begin_enrolment(USER_ID, account_name=EMAIL)
    codes = mfa.confirm_enrolment(USER_ID, code_now(enrolment.secret))
    assert mfa.factors_for(USER_ID) == [TOTP_FACTOR]
    assert len(codes.codes) == RECOVERY_CODE_COUNT
    factor = stores.require_totp_factors().get(USER_ID)
    assert factor is not None and factor.is_active


def test_confirming_with_a_wrong_code_leaves_the_factor_inactive(mfa: MfaService) -> None:
    """A wrong confirmation code raises `MfaRejected` and leaves the factor inactive."""
    mfa.begin_enrolment(USER_ID, account_name=EMAIL)
    with pytest.raises(MfaRejected):
        mfa.confirm_enrolment(USER_ID, "000000")
    assert mfa.factors_for(USER_ID) == []


def test_the_confirming_code_cannot_then_be_replayed_as_a_login_code(mfa: MfaService) -> None:
    """Activation records its step, so the confirming code cannot then satisfy a login challenge."""
    enrolment = mfa.begin_enrolment(USER_ID, account_name=EMAIL)
    code = code_now(enrolment.secret)
    mfa.confirm_enrolment(USER_ID, code)
    with pytest.raises(MfaRejected):
        mfa.verify_challenge(USER_ID, code)


def test_enrolling_again_over_an_active_factor_is_refused(mfa: MfaService) -> None:
    """Enrolling over an active factor is a 409 `TOTP_ALREADY_ENABLED`, not a silent replacement."""
    enrol(mfa)
    with pytest.raises(MfaRejected) as caught:
        mfa.begin_enrolment(USER_ID, account_name=EMAIL)
    assert caught.value.error_code == "TOTP_ALREADY_ENABLED"
    assert caught.value.status_code == 409


def test_enrolling_again_over_a_pending_factor_issues_a_new_seed(mfa: MfaService) -> None:
    """A second enrolment over a pending one issues a new seed and retires the old pending row."""
    first = mfa.begin_enrolment(USER_ID, account_name=EMAIL)
    second = mfa.begin_enrolment(USER_ID, account_name=EMAIL)
    assert first.secret != second.secret
    with pytest.raises(MfaRejected):
        mfa.confirm_enrolment(USER_ID, code_now(first.secret))
    mfa.confirm_enrolment(USER_ID, code_now(second.secret))
    assert mfa.factors_for(USER_ID) == [TOTP_FACTOR]


def test_confirming_with_no_pending_enrolment_is_refused(mfa: MfaService) -> None:
    """Confirming with nothing pending is refused as `NO_PENDING_ENROLMENT`."""
    with pytest.raises(MfaRejected) as caught:
        mfa.confirm_enrolment(USER_ID, "123456")
    assert caught.value.error_code == "NO_PENDING_ENROLMENT"


def test_disabling_removes_the_factor_and_every_recovery_code(
    mfa: MfaService, stores: IdentityStores
) -> None:
    """Disabling removes the factor row and every recovery code, leaving no live credential."""
    _, codes = enrol(mfa)
    mfa.disable_totp(USER_ID)
    assert mfa.factors_for(USER_ID) == []
    assert stores.require_totp_factors().get(USER_ID) is None
    assert list(stores.require_recovery_codes().list_for_user(USER_ID)) == []
    with pytest.raises(MfaRejected):
        mfa.verify_challenge(USER_ID, codes[0])


def test_a_totp_code_is_accepted_once_and_then_refused(mfa: MfaService) -> None:
    """A TOTP code verifies as `otp` once, then is refused, proving the watermark is written."""
    seed, _ = enrol(mfa)
    code = code_now(seed, offset=1)
    assert mfa.verify_challenge(USER_ID, code) == AMR_OTP
    with pytest.raises(MfaRejected):
        mfa.verify_challenge(USER_ID, code)


def test_a_recovery_code_is_accepted_once_and_then_refused(mfa: MfaService) -> None:
    """A recovery code verifies as `recovery` once and is refused the second time."""
    _, codes = enrol(mfa)
    assert mfa.verify_challenge(USER_ID, codes[0]) == AMR_RECOVERY
    with pytest.raises(MfaRejected):
        mfa.verify_challenge(USER_ID, codes[0])


def test_spending_one_recovery_code_leaves_the_others_alone(mfa: MfaService) -> None:
    """Spending one recovery code decrements the count by one and leaves the rest usable."""
    _, codes = enrol(mfa)
    mfa.verify_challenge(USER_ID, codes[0])
    assert mfa.remaining_recovery_codes(USER_ID) == RECOVERY_CODE_COUNT - 1
    assert mfa.verify_challenge(USER_ID, codes[1]) == AMR_RECOVERY


def test_a_recovery_code_is_accepted_however_it_was_typed(mfa: MfaService) -> None:
    """A recovery code typed without hyphens and in lower case still verifies."""
    _, codes = enrol(mfa)
    typed = codes[0].replace("-", "").lower()
    assert mfa.verify_challenge(USER_ID, typed) == AMR_RECOVERY


def test_recovery_codes_are_stored_hashed(mfa: MfaService, stores: IdentityStores) -> None:
    """The store holds only `hash_recovery_code` digests, never the code or its normalised form."""
    _, codes = enrol(mfa)
    stored = list(stores.require_recovery_codes().list_for_user(USER_ID))
    hashes_stored = {record.code_hash for record in stored}
    for code in codes:
        assert code not in hashes_stored
        assert normalise_recovery_code(code) not in hashes_stored
        assert hash_recovery_code(code) in hashes_stored


def test_the_stored_hash_is_of_the_normalised_code() -> None:
    """The same code hashes identically whether typed with hyphens, spaces, or neither."""
    assert hash_recovery_code("abcde-fghij") == hash_recovery_code("ABCDEFGHIJ")
    assert hash_recovery_code("abcde fghij") == hash_recovery_code("ABCDEFGHIJ")


def test_regenerating_invalidates_the_previous_set(mfa: MfaService) -> None:
    """Regenerating issues a disjoint set and stops every old code from verifying."""
    _, old = enrol(mfa)
    fresh = mfa.regenerate_recovery_codes(USER_ID)
    assert len(fresh.codes) == RECOVERY_CODE_COUNT
    assert set(fresh.codes).isdisjoint(old)
    with pytest.raises(MfaRejected):
        mfa.verify_challenge(USER_ID, old[0])
    assert mfa.verify_challenge(USER_ID, fresh.codes[0]) == AMR_RECOVERY


def test_one_users_codes_do_not_work_for_another(mfa: MfaService, hooks: FakeHooks) -> None:
    """Neither a recovery code nor a TOTP code from one user verifies for another."""
    hooks.add("other@example.com", user_id="user-0002")
    seed, codes = enrol(mfa)
    enrol(mfa, "user-0002")
    with pytest.raises(MfaRejected):
        mfa.verify_challenge("user-0002", codes[0])
    with pytest.raises(MfaRejected):
        mfa.verify_challenge("user-0002", code_now(seed, offset=1))


def test_a_user_with_no_factor_is_refused_rather_than_waved_through(mfa: MfaService) -> None:
    """A user with no factor is refused rather than treated as having nothing to check."""
    with pytest.raises(MfaRejected):
        mfa.verify_challenge(USER_ID, "123456")


def test_every_refusal_carries_the_same_message(mfa: MfaService) -> None:
    """Wrong code, replayed code, unknown user and no factor all refuse with one message, code and status."""
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
    """An undecryptable seed surfaces as the ordinary 401, not as a distinguishable failure."""
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


def test_a_ticket_is_not_an_access_token(mfa: MfaService, kms: FakeKms) -> None:
    """An MFA ticket has the MFA type and audience, carries no `sid`, and fails access token verification."""
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
    """An access token has the access type and fails MFA ticket verification."""
    seed_account(hooks, stores)
    result = flows.login(email=EMAIL, password=PASSWORD)
    tokens = TokenService(make_settings(), kms)
    assert claims_of(result.access_token)["typ"] == ACCESS_TOKEN_TYPE
    with pytest.raises(InvalidToken):
        tokens.verify_mfa_ticket(result.access_token)


def test_a_ticket_is_short_lived(mfa: MfaService) -> None:
    """An MFA ticket lives five minutes, the gap between two legs of one login."""
    challenge = mfa.issue_challenge(USER_ID, factors=[TOTP_FACTOR])
    claims = claims_of(challenge.ticket)
    assert claims["exp"] - claims["iat"] == 300


def test_a_ticket_is_recorded_before_it_is_returned(
    mfa: MfaService, stores: IdentityStores
) -> None:
    """The ticket's row is in the identity token store by the time the ticket is returned."""
    from webbpulse.identity import hash_token

    challenge = mfa.issue_challenge(USER_ID, factors=[TOTP_FACTOR])
    jti = str(claims_of(challenge.ticket)["jti"])
    record = stores.require_identity_tokens().get(hash_token(jti))
    assert record is not None
    assert record.purpose == "mfa_ticket"
    assert record.user_id == USER_ID


def test_a_ticket_is_spent_by_its_first_use(mfa: MfaService) -> None:
    """A ticket consumes once, and the second attempt is `MFA_TICKET_INVALID`."""
    challenge = mfa.issue_challenge(USER_ID, factors=[TOTP_FACTOR])
    assert mfa.consume_ticket(challenge.ticket) == USER_ID
    with pytest.raises(MfaRejected) as caught:
        mfa.consume_ticket(challenge.ticket)
    assert caught.value.error_code == "MFA_TICKET_INVALID"


def test_a_forged_ticket_is_refused(mfa: MfaService) -> None:
    """A string that is not a token is refused rather than accepted."""
    with pytest.raises(MfaRejected):
        mfa.consume_ticket("not.a.token")


def test_the_challenge_body_matches_what_the_frontend_reads(mfa: MfaService) -> None:
    """The challenge body is exactly `mfa_required`, `mfa_ticket` and `factors`, with no extra keys."""
    challenge = mfa.issue_challenge(USER_ID, factors=[TOTP_FACTOR])
    body = challenge.as_body()
    assert set(body) == {"mfa_required", "mfa_ticket", "factors"}
    assert body["mfa_required"] is True
    assert body["factors"] == [TOTP_FACTOR]
    assert body["mfa_ticket"] == challenge.ticket


def test_login_without_a_factor_still_issues_tokens_directly(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A user with no factor still gets an access and refresh token straight from `login`."""
    seed_account(hooks, stores)
    result = flows.login(email=EMAIL, password=PASSWORD)
    assert result.access_token
    assert result.refresh_token


def test_login_with_a_factor_raises_the_challenge_instead_of_issuing_tokens(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A user with an active factor makes `login` raise `MfaChallengeRequired` rather than return tokens."""
    seed_account(hooks, stores)
    enrol(mfa)
    with pytest.raises(MfaChallengeRequired) as caught:
        flows.login(email=EMAIL, password=PASSWORD)
    assert caught.value.challenge.factors == [TOTP_FACTOR]


def test_a_pending_enrolment_does_not_challenge_a_login(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """An unconfirmed factor does not challenge a login, so a half-finished enrolment is not a lockout."""
    seed_account(hooks, stores)
    mfa.begin_enrolment(USER_ID, account_name=EMAIL)
    assert flows.login(email=EMAIL, password=PASSWORD).access_token


def test_a_wrong_password_is_refused_before_any_ticket_is_minted(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A wrong password is refused before any MFA ticket row is written."""
    from webbpulse.identity.flows import LoginRejected

    seed_account(hooks, stores)
    enrol(mfa)
    with pytest.raises(LoginRejected):
        flows.login(email=EMAIL, password="wrong password entirely")
    assert stores.require_identity_tokens().revoke_for_user(USER_ID, "mfa_ticket") == 0


def test_completing_the_second_leg_issues_the_session(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Completing the ticket with a valid code issues the session for the right subject."""
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
    """A recovery code completes the second leg and claims `recovery` in `amr`."""
    seed_account(hooks, stores)
    _, codes = enrol(mfa)
    with pytest.raises(MfaChallengeRequired) as caught:
        flows.login(email=EMAIL, password=PASSWORD)
    result = flows.complete_mfa(ticket=caught.value.challenge.ticket, code=codes[0])
    assert AMR_RECOVERY in claims_of(result.access_token)["amr"]


def test_the_ticket_is_spent_even_when_the_code_is_wrong(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A wrong code still spends the ticket, so the next attempt is `MFA_TICKET_INVALID`."""
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
    """A ticket is bound to its user: another user's valid code will not complete it."""
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
    """Completing with an empty ticket is refused."""
    with pytest.raises(MfaRejected):
        flows.complete_mfa(ticket="", code="123456")


def test_a_password_only_login_claims_pwd_alone(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A single-factor login claims `pwd` alone and never `mfa`."""
    seed_account(hooks, stores)
    claims = claims_of(flows.login(email=EMAIL, password=PASSWORD).access_token)
    assert claims["amr"] == [AMR_PASSWORD]
    assert AMR_MFA not in claims["amr"]


def test_a_two_leg_login_claims_the_factors_and_mfa(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A two-leg login claims `pwd`, `otp` and `mfa`."""
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
    """A recovery code claims `recovery` and never `otp`, so the two stay distinguishable."""
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
    """`amr` and `auth_time` from the product hook are overwritten, not merged."""
    seed_account(hooks, stores)
    claims = claims_of(flows.login(email=EMAIL, password=PASSWORD).access_token)
    assert claims["amr"] == [AMR_PASSWORD]
    assert claims["auth_time"] != 1


def test_auth_time_is_present_and_recent_on_a_login(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A login's `auth_time` is present and within a few seconds of now."""
    seed_account(hooks, stores)
    claims = claims_of(flows.login(email=EMAIL, password=PASSWORD).access_token)
    assert abs(int(claims["auth_time"]) - int(time.time())) < 5


def test_step_up_returns_a_fresher_auth_time_without_a_new_session(
    flows: IdentityFlows,
    mfa: MfaService,
    hooks: FakeHooks,
    stores: IdentityStores,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Step-up refreshes `auth_time` and claims `otp` while keeping the session and issuing no refresh token."""
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
    assert abs(int(claims["auth_time"]) - expected) < 5
    assert int(claims["auth_time"]) > first_auth_time
    assert AMR_OTP in claims["amr"]


def test_step_up_with_a_wrong_code_is_refused(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Step-up with a wrong code is refused."""
    seed_account(hooks, stores)
    enrol(mfa)
    with pytest.raises(MfaRejected):
        flows.step_up(user_id=USER_ID, session_id="session-1", code="000000")


def test_step_up_for_an_unknown_user_is_refused(flows: IdentityFlows) -> None:
    """Step-up for a user with no factor is refused."""
    with pytest.raises(MfaRejected):
        flows.step_up(user_id="user-9999", session_id="session-1", code="123456")


def test_step_up_spends_the_code_it_used(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A step-up code is spent by its use and cannot be presented again."""
    seed_account(hooks, stores)
    seed, _ = enrol(mfa)
    code = code_now(seed, offset=1)
    flows.step_up(user_id=USER_ID, session_id="session-1", code=code)
    with pytest.raises(MfaRejected):
        flows.step_up(user_id=USER_ID, session_id="session-1", code=code)
    with pytest.raises(MfaRejected):
        flows.step_up(user_id=USER_ID, session_id="session-1", code=code)


def test_a_factor_activates_exactly_once() -> None:
    """`activate` returns True the first time and False after, which is what makes the route's 409 correct."""
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
    """`record_use` accepts only a step above the watermark, so a repeat or an earlier step fails."""
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
    """`consume` returns True once for a stored hash and False afterwards."""
    store = InMemoryRecoveryCodeStore()
    digest = hash_recovery_code("ABCDE-FGHIJ")
    store.put_many(
        [RecoveryCodeRecord(user_id=USER_ID, code_hash=digest, created_at="2026-09-10T00:00:00Z")]
    )
    assert store.consume(USER_ID, digest) is True
    assert store.consume(USER_ID, digest) is False


def test_consuming_an_unknown_code_reports_failure_rather_than_raising() -> None:
    """Consuming a hash that was never stored returns False rather than raising."""
    store = InMemoryRecoveryCodeStore()
    assert store.consume(USER_ID, hash_recovery_code("NOPE")) is False


def test_recovery_codes_are_scoped_to_their_user() -> None:
    """A stored code hash consumes only for the user it was written for."""
    store = InMemoryRecoveryCodeStore()
    digest = hash_recovery_code("ABCDE-FGHIJ")
    store.put_many(
        [RecoveryCodeRecord(user_id=USER_ID, code_hash=digest, created_at="2026-09-10T00:00:00Z")]
    )
    assert store.consume("user-0002", digest) is False
    assert store.consume(USER_ID, digest) is True


def test_deleting_a_users_codes_leaves_another_users_alone() -> None:
    """`delete_for_user` empties one user's codes and leaves another user's usable."""
    store = InMemoryRecoveryCodeStore()
    created = "2026-09-10T00:00:00Z"
    mine = hash_recovery_code("MINE-CODE")
    theirs = hash_recovery_code("THEIR-CODE")
    store.put_many([RecoveryCodeRecord(user_id=USER_ID, code_hash=mine, created_at=created)])
    store.put_many([RecoveryCodeRecord(user_id="user-0002", code_hash=theirs, created_at=created)])
    store.delete_for_user(USER_ID)
    assert list(store.list_for_user(USER_ID)) == []
    assert store.consume("user-0002", theirs) is True


def router_paths(**kwargs: Any) -> set[str]:
    """The paths one built router declares, read off the router rather than off an app."""
    router = build_identity_router(make_settings(), limiter_enabled=False, **kwargs)
    return {route.path for route in router.routes}  # type: ignore[attr-defined]


def test_the_mfa_routes_are_declared(
    hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    """All six MFA routes are declared when the stores and the KMS client are wired."""
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
    """Without the TOTP and recovery stores the MFA routes are absent, while login remains."""
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
    """With `totp_enabled=False` the MFA routes are absent, while login remains."""
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
    """A challenged login is a 200 carrying the challenge body, with no access token and no cookie."""
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
    """The second leg accepts `mfa_ticket` and `code`, and sets the refresh cookie on success."""
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
    """A wrong code on the second leg is a 401 `INVALID_MFA_CODE` in the shared envelope."""
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
    """All three enrolment routes answer 401 `NOT_AUTHENTICATED` without a bearer token."""
    for path in (TOTP_ENROL_PATH, TOTP_DISABLE_PATH, RECOVERY_CODES_PATH):
        response = client.post(f"{prefix()}{path}", json={})
        assert response.status_code == 401, path
        assert response.json()["error_code"] == "NOT_AUTHENTICATED"


def test_the_enrolment_round_trip_over_http(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Enrol, activate, then sign in again through the challenge, entirely over the routes."""
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
    """Enrolling twice returns two different seeds: there is no route that reads a seed back."""
    seed_account(hooks, stores)
    login = client.post(f"{prefix()}{LOGIN_PATH}", json={"email": EMAIL, "password": PASSWORD})
    auth = {"Authorization": f"Bearer {login.json()['access_token']}"}
    first = client.post(f"{prefix()}{TOTP_ENROL_PATH}", headers=auth, json={}).json()["secret"]
    second = client.post(f"{prefix()}{TOTP_ENROL_PATH}", headers=auth, json={}).json()["secret"]
    assert first != second


def test_regenerating_over_http_replaces_the_set(
    client: TestClient,
    hooks: FakeHooks,
    stores: IdentityStores,
    kms: FakeKms,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The recovery codes route returns a full disjoint set, replacing the old one."""
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

    with clock_advanced(monkeypatch, 2):
        response = client.post(
            f"{prefix()}{RECOVERY_CODES_PATH}", headers=auth, json={"code": code_now(seed)}
        )
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
    """The step-up route sets no cookie at all and returns a token claiming `otp`."""
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
    """The MFA verify limit is ten attempts per fifteen minutes."""
    assert TOTP_VERIFY_LIMIT == (10, 900)


def test_disabling_requires_a_code_and_a_correct_one_works(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A correct TOTP code disables the factor and clears every recovery code."""
    seed_account(hooks, stores)
    seed, _ = enrol(mfa)
    flows.disable_totp(user_id=USER_ID, code=code_now(seed, offset=1))
    assert stores.require_totp_factors().get(USER_ID) is None
    assert list(stores.require_recovery_codes().list_for_user(USER_ID)) == []


def test_a_recovery_code_disables_and_is_spent_doing_it(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A recovery code also disables the factor, and the whole set goes with it."""
    seed_account(hooks, stores)
    _, codes = enrol(mfa)
    flows.disable_totp(user_id=USER_ID, code=codes[0])
    assert stores.require_totp_factors().get(USER_ID) is None
    assert list(stores.require_recovery_codes().list_for_user(USER_ID)) == []


def test_a_wrong_code_refuses_the_disable_and_leaves_the_factor_standing(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A wrong code is a 401 and leaves the factor active with every recovery code intact."""
    seed_account(hooks, stores)
    enrol(mfa)
    with pytest.raises(MfaRejected) as caught:
        flows.disable_totp(user_id=USER_ID, code="000000")
    assert caught.value.error_code == "INVALID_MFA_CODE"
    assert caught.value.status_code == 401

    factor = stores.require_totp_factors().get(USER_ID)
    assert factor is not None and factor.is_active
    assert mfa.remaining_recovery_codes(USER_ID) == RECOVERY_CODE_COUNT


def test_a_reauthentication_code_cannot_be_replayed(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A code used to authorise a regenerate cannot authorise a second one."""
    seed_account(hooks, stores)
    seed, _ = enrol(mfa)
    code = code_now(seed, offset=1)
    flows.regenerate_recovery_codes(user_id=USER_ID, code=code)

    with pytest.raises(MfaRejected):
        flows.regenerate_recovery_codes(user_id=USER_ID, code=code)


def test_regenerating_requires_a_code_and_a_correct_one_replaces_the_set(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A correct code replaces the recovery set with a full disjoint one."""
    seed_account(hooks, stores)
    seed, old = enrol(mfa)
    fresh = flows.regenerate_recovery_codes(user_id=USER_ID, code=code_now(seed, offset=1))
    assert len(fresh.codes) == RECOVERY_CODE_COUNT
    assert set(fresh.codes).isdisjoint(old)
    assert mfa.remaining_recovery_codes(USER_ID) == RECOVERY_CODE_COUNT


def test_a_recovery_code_can_authorise_its_own_replacement(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A recovery code can authorise a regenerate, and does not survive into the new set."""
    seed_account(hooks, stores)
    _, old = enrol(mfa)
    fresh = flows.regenerate_recovery_codes(user_id=USER_ID, code=old[0])
    assert set(fresh.codes).isdisjoint(old)
    assert mfa.remaining_recovery_codes(USER_ID) == RECOVERY_CODE_COUNT


def test_a_wrong_code_refuses_the_regenerate_and_keeps_every_existing_code(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """A refused regenerate leaves the old set intact and still usable."""
    seed_account(hooks, stores)
    _, old = enrol(mfa)
    with pytest.raises(MfaRejected) as caught:
        flows.regenerate_recovery_codes(user_id=USER_ID, code="000000")
    assert caught.value.error_code == "INVALID_MFA_CODE"

    assert mfa.remaining_recovery_codes(USER_ID) == RECOVERY_CODE_COUNT
    assert mfa.verify_challenge(USER_ID, old[0]) == AMR_RECOVERY


def test_neither_route_can_be_used_against_a_user_with_no_factor(
    flows: IdentityFlows, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Disable and regenerate both refuse for a user with nothing enrolled."""
    seed_account(hooks, stores)
    with pytest.raises(MfaRejected):
        flows.disable_totp(user_id=USER_ID, code="000000")
    with pytest.raises(MfaRejected):
        flows.regenerate_recovery_codes(user_id=USER_ID, code="000000")


def test_neither_route_works_for_an_unknown_user(flows: IdentityFlows) -> None:
    """Disable and regenerate both refuse for an unknown user."""
    with pytest.raises(MfaRejected):
        flows.disable_totp(user_id="user-9999", code="123456")
    with pytest.raises(MfaRejected):
        flows.regenerate_recovery_codes(user_id="user-9999", code="123456")


def test_one_users_code_cannot_disable_anothers_factor(
    flows: IdentityFlows, mfa: MfaService, hooks: FakeHooks, stores: IdentityStores
) -> None:
    """Another user's valid code cannot disable this user's factor, which stays active."""
    seed_account(hooks, stores)
    seed_account(hooks, stores, email="other@example.com", user_id="user-0002")
    enrol(mfa)
    other_seed, _ = enrol(mfa, "user-0002")

    with pytest.raises(MfaRejected):
        flows.disable_totp(user_id=USER_ID, code=code_now(other_seed, offset=1))
    factor = stores.require_totp_factors().get(USER_ID)
    assert factor is not None and factor.is_active


def _signed_in(client: TestClient, seed: str) -> dict[str, str]:
    """Complete a two-leg login and return the Authorization header for it."""
    challenge = client.post(f"{prefix()}{LOGIN_PATH}", json={"email": EMAIL, "password": PASSWORD})
    completed = client.post(
        f"{prefix()}{LOGIN_TOTP_PATH}",
        json={"mfa_ticket": challenge.json()["mfa_ticket"], "code": code_now(seed, offset=1)},
    )
    return {"Authorization": f"Bearer {completed.json()['access_token']}"}


def test_disabling_over_http_needs_the_code(
    client: TestClient,
    hooks: FakeHooks,
    stores: IdentityStores,
    kms: FakeKms,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The disable route with a correct code answers 200 and removes the factor."""
    seed_account(hooks, stores)
    settings = make_settings()
    service = MfaService(settings, stores, TokenService(settings, kms), kms_client=kms)
    seed, _ = enrol(service)
    auth = _signed_in(client, seed)

    with clock_advanced(monkeypatch, 2):
        response = client.post(
            f"{prefix()}{TOTP_DISABLE_PATH}", headers=auth, json={"code": code_now(seed)}
        )
    assert response.status_code == 200
    assert response.json()["disabled"] is True
    assert stores.require_totp_factors().get(USER_ID) is None


def test_a_bearer_token_alone_no_longer_disables_the_factor(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    """A disable with no code is a 422 and leaves the factor active."""
    seed_account(hooks, stores)
    settings = make_settings()
    service = MfaService(settings, stores, TokenService(settings, kms), kms_client=kms)
    seed, _ = enrol(service)
    auth = _signed_in(client, seed)

    response = client.post(f"{prefix()}{TOTP_DISABLE_PATH}", headers=auth, json={})
    assert response.status_code == 422
    assert response.json()["error_code"] == "VALIDATION_ERROR"
    factor = stores.require_totp_factors().get(USER_ID)
    assert factor is not None and factor.is_active


def test_a_bearer_token_alone_no_longer_regenerates_the_codes(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    """A regenerate with no code is a 422 and leaves the existing codes usable."""
    seed_account(hooks, stores)
    settings = make_settings()
    service = MfaService(settings, stores, TokenService(settings, kms), kms_client=kms)
    seed, old = enrol(service)
    auth = _signed_in(client, seed)

    response = client.post(f"{prefix()}{RECOVERY_CODES_PATH}", headers=auth, json={})
    assert response.status_code == 422
    assert response.json()["error_code"] == "VALIDATION_ERROR"
    assert service.verify_challenge(USER_ID, old[0]) == AMR_RECOVERY


@pytest.mark.parametrize("path", [TOTP_DISABLE_PATH, RECOVERY_CODES_PATH])
def test_a_blank_code_is_a_validation_error_not_a_wrong_code(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores, kms: FakeKms, path: str
) -> None:
    """A whitespace-only code is a 422 `VALIDATION_ERROR`, not a wrong-code refusal."""
    seed_account(hooks, stores)
    settings = make_settings()
    service = MfaService(settings, stores, TokenService(settings, kms), kms_client=kms)
    seed, _ = enrol(service)
    auth = _signed_in(client, seed)

    response = client.post(f"{prefix()}{path}", headers=auth, json={"code": "   "})
    assert response.status_code == 422
    assert response.json()["error_code"] == "VALIDATION_ERROR"


@pytest.mark.parametrize("path", [TOTP_DISABLE_PATH, RECOVERY_CODES_PATH])
def test_a_wrong_code_over_http_is_the_shared_mfa_envelope(
    client: TestClient, hooks: FakeHooks, stores: IdentityStores, kms: FakeKms, path: str
) -> None:
    """Both routes refuse a wrong code with the same 401 `INVALID_MFA_CODE` as `login/totp`."""
    seed_account(hooks, stores)
    settings = make_settings()
    service = MfaService(settings, stores, TokenService(settings, kms), kms_client=kms)
    seed, _ = enrol(service)
    auth = _signed_in(client, seed)

    response = client.post(f"{prefix()}{path}", headers=auth, json={"code": "000000"})
    assert response.status_code == 401
    assert response.json()["error_code"] == "INVALID_MFA_CODE"


def test_the_missing_body_is_refused_before_the_code_is_read(client: TestClient) -> None:
    """Both routes answer 401 to an unauthenticated caller, never 422, so they are not an oracle."""
    for path in (TOTP_DISABLE_PATH, RECOVERY_CODES_PATH):
        response = client.post(f"{prefix()}{path}", json={"code": "123456"})
        assert response.status_code == 401, path
        assert response.json()["error_code"] == "NOT_AUTHENTICATED"


def test_both_routes_carry_the_same_number_of_limits_as_the_second_leg(
    hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    """Disable and regenerate declare the same single rate limit dependency as `login/totp`."""
    router = build_identity_router(make_settings(), hooks, stores, kms_client=kms)
    counts = {
        route.path: len(route.dependencies)  # type: ignore[attr-defined]
        for route in router.routes
    }
    expected = counts[f"{prefix()}{LOGIN_TOTP_PATH}"]
    assert expected == 1, "the second leg of login carries exactly the mfa-verify limit"
    assert counts[f"{prefix()}{TOTP_DISABLE_PATH}"] == expected
    assert counts[f"{prefix()}{RECOVERY_CODES_PATH}"] == expected


def test_the_two_routes_have_no_limit_when_the_limiter_is_off(
    hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
) -> None:
    """With the limiter off both routes declare no dependencies, which is the mode the fixtures use."""
    router = build_identity_router(
        make_settings(), hooks, stores, kms_client=kms, limiter_enabled=False
    )
    for route in router.routes:
        if route.path in (  # type: ignore[attr-defined]
            f"{prefix()}{TOTP_DISABLE_PATH}",
            f"{prefix()}{RECOVERY_CODES_PATH}",
        ):
            assert route.dependencies == []  # type: ignore[attr-defined]
