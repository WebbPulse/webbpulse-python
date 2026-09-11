"""Tests for the M5 identity work: passkeys, WebAuthn ceremonies, and the two new tables.

The strategy is M4's, adapted to a protocol whose failure modes are almost all invisible
from the happy path:

- **The ceremonies run against real cryptography, not a stub.** `SoftAuthenticator` below is
  a working ES256 WebAuthn authenticator: it builds real CBOR attestation objects, real
  authenticator data with real flag bytes, and real ECDSA signatures over the concatenation
  the specification defines. py_webauthn verifies them the way it would verify Chrome's. A
  test that fed the verifier a fake it had itself produced would pass against an
  implementation that verified nothing, which is exactly the bug that matters here.
- **Every control is tested by violating it.** The challenge is replayed, the origin is
  changed, the RP ID is changed, the signature counter is rewound, the purposes are crossed,
  and one user's challenge is answered with another user's token. Each of those has a test
  that asserts the refusal, because each of them is a way in if the check is missing and
  none of them shows up in a passing happy path.
- **The two `amr` shapes are asserted separately.** A user-verified passkey must produce
  `mfa` and must skip the TOTP challenge; one without user verification must not, and must
  be challenged exactly as a password is. Those are the two halves of the M5 decision on
  multi-factor, and a test for one is no evidence for the other.
- **The table contract is asserted as data.** The Terraform platform module creates
  `passkeys` and `webauthn-challenges` with specific keys and a specific TTL attribute. The
  names and key shapes are constants in this package, so the test pins them here: a rename
  on either side is then a failing test rather than a deployment that writes to a table that
  does not exist.

The KMS fake and the `FakeHooks` product are M4's, redefined here rather than imported:
`tests/` is not a package.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
from typing import TYPE_CHECKING, Any

import pytest

from webbpulse.identity import (
    LOGIN_PATH,
    LOGIN_TOTP_PATH,
    PASSKEY_CREDENTIAL_INDEX,
    PASSKEYS_TABLE,
    WEBAUTHN_CHALLENGES_TABLE,
    AuthenticationRefused,
    BaseIdentityHooks,
    CredentialRecord,
    IdentitySettings,
    IdentityStores,
    InMemoryCredentialStore,
    InMemoryIdentityTokenStore,
    InMemoryLoginAttemptStore,
    InMemoryPasskeyStore,
    InMemoryRecoveryCodeStore,
    InMemoryRefreshTokenStore,
    InMemoryTotpFactorStore,
    InMemoryWebAuthnChallengeStore,
    PasskeyRecord,
    TokenService,
    WebAuthnChallengeRecord,
    build_identity_router,
    identity_prefix,
    normalise_password,
)
from webbpulse.identity import totp as totp_module
from webbpulse.identity.flows import PASSWORD_CREDENTIAL_TYPE, IdentityFlows, MfaChallengeRequired
from webbpulse.identity.oauth_routes import OAUTH_PROVIDERS_CACHE_CONTROL
from webbpulse.identity.passkey_routes import (
    LOGIN_PASSKEY_OPTIONS_PATH,
    LOGIN_PASSKEY_VERIFY_PATH,
    PASSKEY_AVAILABILITY_CACHE_CONTROL,
    PASSKEY_AVAILABILITY_PATH,
    PASSKEY_REGISTER_OPTIONS_PATH,
    PASSKEY_REGISTER_VERIFY_PATH,
    PASSKEYS_PATH,
)
from webbpulse.identity.passkeys import (
    AMR_PASSKEY,
    AMR_PIN,
    CHALLENGE_TTL_SECONDS,
    PasskeyRejected,
    PasskeyService,
    b64url_decode,
    b64url_encode,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

from collections.abc import Mapping

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient

KEY_A = "arn:aws:kms:us-west-2:111122223333:key/aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa"
DATA_KEY = "arn:aws:kms:us-west-2:111122223333:key/dddddddd-4444-4444-4444-dddddddddddd"
ISSUER = "https://api.staging.example.com/api/auth"
AUDIENCE = "webbpulse-staging"
FRONTEND = "https://app.example.com"

RP_ID = "example.com"
ORIGIN = "https://app.example.com"

PASSWORD = "correct horse battery staple"
EMAIL = "person@example.com"
USER_ID = "user-0001"

#: The flag bits of the authenticator data byte, per WebAuthn section 6.1. Named because a
#: test that asserts on a raw `0x45` is a test nobody can check against the specification.
FLAG_USER_PRESENT = 0x01
FLAG_USER_VERIFIED = 0x04
FLAG_BACKUP_ELIGIBLE = 0x08
FLAG_BACKUP_STATE = 0x10
FLAG_ATTESTED_DATA = 0x40

#: 16 zero bytes: the AAGUID a platform authenticator reports when it declines to identify
#: its model, which is what Apple and Google both do for privacy.
AAGUID_UNKNOWN = bytes(16)


# ---------------------------------------------------------------------------
# A working software authenticator
# ---------------------------------------------------------------------------


class SoftAuthenticator:
    """An ES256 WebAuthn authenticator in about eighty lines.

    Produces credentials py_webauthn accepts, which is the point: the verifier under test is
    the real one, exercised against real signatures over the real byte layout, so a test
    passing here is evidence the production path works against a browser.

    `user_verified` and `backed_up` are constructor flags rather than fixed, because the two
    `amr` shapes and the backup-state field are exactly what M5 has to get right and the flag
    byte is where the browser expresses them.
    """

    def __init__(
        self,
        rp_id: str = RP_ID,
        *,
        origin: str = ORIGIN,
        user_verified: bool = True,
        backed_up: bool = True,
    ) -> None:
        self.rp_id = rp_id
        self.origin = origin
        self.user_verified = user_verified
        self.backed_up = backed_up
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)
        self.sign_count = 0

    @property
    def credential_id_b64(self) -> str:
        return b64url_encode(self.credential_id)

    def _flags(self, *, attested: bool) -> int:
        flags = FLAG_USER_PRESENT
        if self.user_verified:
            flags |= FLAG_USER_VERIFIED
        if self.backed_up:
            flags |= FLAG_BACKUP_ELIGIBLE | FLAG_BACKUP_STATE
        if attested:
            flags |= FLAG_ATTESTED_DATA
        return flags

    def _cose_key(self) -> bytes:
        """The public key in COSE_Key form, which is how WebAuthn carries it."""
        numbers = self.key.public_key().public_numbers()
        return cbor2.dumps(
            {
                1: 2,  # kty: EC2
                3: -7,  # alg: ES256
                -1: 1,  # crv: P-256
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        )

    def _client_data(self, *, ceremony: str, challenge: str, origin: str = "") -> bytes:
        return json.dumps(
            {
                "type": ceremony,
                "challenge": challenge,
                "origin": origin or self.origin,
                "crossOrigin": False,
            }
        ).encode("utf-8")

    def register(self, challenge: str, *, rp_id: str = "", origin: str = "") -> dict[str, Any]:
        """An attestation for `challenge`, as `navigator.credentials.create` would return it.

        `rp_id` and `origin` override the authenticator's own so a test can produce a
        credential minted for the wrong relying party, which is the phishing case.
        """
        rp_hash = hashlib.sha256((rp_id or self.rp_id).encode("utf-8")).digest()
        self.sign_count += 1
        cose = self._cose_key()
        attested = (
            AAGUID_UNKNOWN + len(self.credential_id).to_bytes(2, "big") + self.credential_id + cose
        )
        auth_data = (
            rp_hash
            + bytes([self._flags(attested=True)])
            + struct.pack(">I", self.sign_count)
            + attested
        )
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        client_data = self._client_data(
            ceremony="webauthn.create", challenge=challenge, origin=origin
        )
        return {
            "id": self.credential_id_b64,
            "rawId": self.credential_id_b64,
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url_encode(client_data),
                "attestationObject": b64url_encode(attestation),
                "transports": ["internal", "hybrid"],
            },
            "clientExtensionResults": {},
        }

    def assertion(
        self,
        challenge: str,
        *,
        rp_id: str = "",
        origin: str = "",
        sign_count: int | None = None,
    ) -> dict[str, Any]:
        """An assertion for `challenge`, as `navigator.credentials.get` would return it.

        `sign_count` is overridable so a test can present a counter that did not advance,
        which is the cloned-authenticator case section 6.1.3 exists for.
        """
        rp_hash = hashlib.sha256((rp_id or self.rp_id).encode("utf-8")).digest()
        if sign_count is None:
            self.sign_count += 1
            sign_count = self.sign_count
        auth_data = rp_hash + bytes([self._flags(attested=False)]) + struct.pack(">I", sign_count)
        client_data = self._client_data(ceremony="webauthn.get", challenge=challenge, origin=origin)
        signature = self.key.sign(
            auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
        )
        return {
            "id": self.credential_id_b64,
            "rawId": self.credential_id_b64,
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url_encode(client_data),
                "authenticatorData": b64url_encode(auth_data),
                "signature": b64url_encode(signature),
                "userHandle": b64url_encode(USER_ID.encode("utf-8")),
            },
            "clientExtensionResults": {},
        }


# ---------------------------------------------------------------------------
# Fixtures: M4's, with the two M5 stores added
# ---------------------------------------------------------------------------


class FakeKms:
    """M4's KMS fake, unchanged: local RSA signing plus a stand-in for the two envelope calls.

    One object, because `IdentityFlows` hands the same `kms_client` to the token service and
    the MFA service. The envelope half wraps a data key by base64-ing it with its encryption
    context appended, which is not encryption and is not pretending to be; what it does
    faithfully is fail a `decrypt` under the wrong context.
    """

    def __init__(self, keys: dict[str, rsa.RSAPrivateKey]) -> None:
        self._keys = keys
        self.data_key_calls: list[dict[str, Any]] = []

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
        self,
        *,
        KeyId: str,
        Message: bytes,
        MessageType: str,
        SigningAlgorithm: str,
    ) -> dict[str, Any]:
        signature = self._keys[KeyId].sign(
            Message, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
        )
        return {"KeyId": KeyId, "Signature": signature, "SigningAlgorithm": SigningAlgorithm}

    def generate_data_key(
        self,
        *,
        KeyId: str,
        NumberOfBytes: int,
        EncryptionContext: Mapping[str, str],
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
        self,
        *,
        CiphertextBlob: bytes,
        EncryptionContext: Mapping[str, str],
    ) -> dict[str, Any]:
        try:
            encoded, context = CiphertextBlob.split(b"|", 1)
        except ValueError as exc:
            raise RuntimeError("InvalidCiphertextException") from exc
        if context != _context_bytes(EncryptionContext):
            raise RuntimeError("InvalidCiphertextException")
        return {"KeyId": DATA_KEY, "Plaintext": base64.b64decode(encoded)}


def _context_bytes(context: Mapping[str, str]) -> bytes:
    return repr(sorted(context.items())).encode("utf-8")


@pytest.fixture(autouse=True)
def cheap_bcrypt(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Pin bcrypt to its minimum cost for the whole module. M2's fixture, unchanged."""
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
        "rp_id": RP_ID,
        "rp_name": "Example",
        "webauthn_origins": [ORIGIN],
    }
    base.update(overrides)
    return IdentitySettings(**base)


class FakeHooks(BaseIdentityHooks):
    """A product's policy, in memory. M4's fake, unchanged."""

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
        # Deliberately tries to set both, as M4's fake does. `_mint_access` must overwrite
        # them, or a hook could claim a passkey the user never presented.
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
        passkeys=InMemoryPasskeyStore(),
        webauthn_challenges=InMemoryWebAuthnChallengeStore(),
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
def passkeys(flows: IdentityFlows) -> PasskeyService:
    service = flows.passkeys
    assert service is not None, "the fixtures wire both M5 stores, so passkeys must mount"
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
    password: str | None = PASSWORD,
    user_id: str = USER_ID,
    **attributes: Any,
) -> dict[str, Any]:
    """An account, with a stored bcrypt password unless `password` is `None`.

    `password=None` is the passkey-only user, which is the case the last-credential guard
    exists for and which cannot be produced any other way.
    """
    from webbpulse.security import hash_password

    user = hooks.add(email, user_id=user_id, **attributes)
    if password is not None:
        stores.require_credentials().put(
            CredentialRecord(
                user_id=user_id,
                credential_type=PASSWORD_CREDENTIAL_TYPE,
                secret=hash_password(normalise_password(password)),
            )
        )
    return user


def enrol_passkey(
    service: PasskeyService,
    *,
    user_id: str = USER_ID,
    user_verified: bool = True,
    name: str = "Test key",
) -> tuple[SoftAuthenticator, PasskeyRecord]:
    """Run a full registration ceremony, returning the authenticator and the stored row.

    Goes through the service rather than writing a row directly, so anything that depends on
    an enrolled passkey is also exercising the enrolment path it depends on.
    """
    authenticator = SoftAuthenticator(user_verified=user_verified)
    challenge = service.begin_registration(user_id, user_name=EMAIL)
    credential = authenticator.register(_challenge_of(challenge.options))
    record = service.finish_registration(
        user_id,
        challenge_id=challenge.challenge_id,
        credential=credential,
        name=name,
    )
    return authenticator, record


def _challenge_of(options: Mapping[str, Any]) -> str:
    """The base64url challenge out of a py_webauthn options document."""
    return str(options["challenge"])


def sign_in(service: PasskeyService, authenticator: SoftAuthenticator) -> Any:
    """One full login ceremony through the service, returning the assertion result."""
    challenge = service.begin_login()
    credential = authenticator.assertion(_challenge_of(challenge.options))
    return service.finish_login(challenge_id=challenge.challenge_id, credential=credential)


# ---------------------------------------------------------------------------
# The table contract the Terraform platform module has to satisfy
# ---------------------------------------------------------------------------


class TestTableContract:
    """The names and key shapes the `dynamodb-identity` platform module creates.

    These are asserted as plain constants because that is the whole contract: Terraform
    creates a table with a name and a key schema, and this package writes to a table with a
    name and a key schema, and nothing checks that the two agree until a write fails in
    production. Pinning them here turns a rename on either side into a failing test.
    """

    def test_passkeys_table_name_and_index(self) -> None:
        assert PASSKEYS_TABLE == "passkeys"
        assert PASSKEY_CREDENTIAL_INDEX == "credential_id-index"

    def test_webauthn_challenges_table_name(self) -> None:
        assert WEBAUTHN_CHALLENGES_TABLE == "webauthn-challenges"

    def test_passkey_key_schema(self) -> None:
        """Hash `user_id`, range `credential_id`. Both are fields on the record.

        The direction matters: listing a user's passkeys must be a `query` on the base table
        rather than on an index, because the management page reads its own writes and a GSI
        cannot be read consistently.
        """
        record = PasskeyRecord(user_id=USER_ID, credential_id="cred", public_key="key")
        assert record.user_id == USER_ID
        assert record.credential_id == "cred"

    def test_webauthn_challenge_key_schema_and_ttl_attribute(self) -> None:
        """Hash `challenge_id`, TTL attribute `expires_at`.

        `expires_at` must be the name Terraform gives DynamoDB as the TTL attribute. If the
        module were pointed at a different attribute the rows would simply never be reclaimed
        and the table would grow without bound, which no functional test would notice because
        expiry is enforced in code regardless.
        """
        record = WebAuthnChallengeRecord(
            challenge_id="chal",
            challenge="Y2hhbA",
            purpose="login",
            created_at="2026-01-01T00:00:00Z",
            expires_at=1234567890,
        )
        assert record.challenge_id == "chal"
        assert record.expires_at == 1234567890

    def test_challenge_ttl_is_five_minutes(self) -> None:
        assert CHALLENGE_TTL_SECONDS == 300


# ---------------------------------------------------------------------------
# Base64url, which every credential id passes through
# ---------------------------------------------------------------------------


class TestBase64Url:
    def test_round_trips_without_padding(self) -> None:
        for length in range(1, 40):
            raw = os.urandom(length)
            encoded = b64url_encode(raw)
            assert "=" not in encoded
            assert b64url_decode(encoded) == raw

    def test_accepts_padded_input(self) -> None:
        """A client that sends padding must still match the stored unpadded form."""
        raw = os.urandom(31)
        padded = base64.urlsafe_b64encode(raw).decode("ascii")
        assert "=" in padded
        assert b64url_decode(padded) == raw

    def test_rejects_garbage(self) -> None:
        with pytest.raises(ValueError, match="base64url"):
            b64url_decode("not valid base64!!!")


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_round_trip_stores_the_credential(self, passkeys: PasskeyService) -> None:
        authenticator, record = enrol_passkey(passkeys, name="Yubikey")
        assert record.credential_id == authenticator.credential_id_b64
        assert record.name == "Yubikey"
        assert record.user_id == USER_ID
        assert record.public_key
        assert record.user_verified is True
        assert record.transports == ("internal", "hybrid")

    def test_sign_count_is_stored_as_reported_not_zero(self, passkeys: PasskeyService) -> None:
        """The counter migrates as the authenticator reported it.

        Storing zero would permanently disarm the clone check for this credential: every
        subsequent assertion exceeds zero and so looks correct forever.
        """
        authenticator, record = enrol_passkey(passkeys)
        assert authenticator.sign_count > 0
        assert record.sign_count == authenticator.sign_count

    def test_backup_state_is_recorded(self, passkeys: PasskeyService) -> None:
        _, record = enrol_passkey(passkeys)
        assert record.backup_state is True

    def test_options_exclude_existing_credentials(self, passkeys: PasskeyService) -> None:
        """A second enrolment lists the first, so the authenticator declines a duplicate."""
        authenticator, _ = enrol_passkey(passkeys)
        options = passkeys.begin_registration(USER_ID, user_name=EMAIL).options
        excluded = {entry["id"] for entry in options["excludeCredentials"]}
        assert authenticator.credential_id_b64 in excluded

    def test_challenge_is_single_use(self, passkeys: PasskeyService) -> None:
        """Replaying a spent challenge is refused, which is the whole point of M5."""
        authenticator = SoftAuthenticator()
        challenge = passkeys.begin_registration(USER_ID, user_name=EMAIL)
        credential = authenticator.register(_challenge_of(challenge.options))
        passkeys.finish_registration(
            USER_ID, challenge_id=challenge.challenge_id, credential=credential
        )
        with pytest.raises(PasskeyRejected):
            passkeys.finish_registration(
                USER_ID, challenge_id=challenge.challenge_id, credential=credential
            )

    def test_challenge_is_spent_even_when_verification_fails(
        self, passkeys: PasskeyService
    ) -> None:
        """A failed attempt burns the challenge, so a stolen one cannot be ground against."""
        authenticator = SoftAuthenticator()
        challenge = passkeys.begin_registration(USER_ID, user_name=EMAIL)
        with pytest.raises(PasskeyRejected):
            passkeys.finish_registration(
                USER_ID, challenge_id=challenge.challenge_id, credential={"id": "nonsense"}
            )
        credential = authenticator.register(_challenge_of(challenge.options))
        with pytest.raises(PasskeyRejected):
            passkeys.finish_registration(
                USER_ID, challenge_id=challenge.challenge_id, credential=credential
            )

    def test_another_users_challenge_is_refused(self, passkeys: PasskeyService) -> None:
        """A challenge minted for one account cannot be answered as another.

        Without this check, holding an access token for account B while starting an
        enrolment on account A would land the passkey wherever the token pointed.
        """
        authenticator = SoftAuthenticator()
        challenge = passkeys.begin_registration(USER_ID, user_name=EMAIL)
        credential = authenticator.register(_challenge_of(challenge.options))
        with pytest.raises(PasskeyRejected):
            passkeys.finish_registration(
                "user-9999", challenge_id=challenge.challenge_id, credential=credential
            )

    def test_login_challenge_cannot_satisfy_registration(self, passkeys: PasskeyService) -> None:
        """The purposes are kept apart, because the two legs verify different things."""
        authenticator = SoftAuthenticator()
        challenge = passkeys.begin_login()
        credential = authenticator.register(_challenge_of(challenge.options))
        with pytest.raises(PasskeyRejected):
            passkeys.finish_registration(
                USER_ID, challenge_id=challenge.challenge_id, credential=credential
            )

    def test_wrong_origin_is_refused(self, passkeys: PasskeyService) -> None:
        """The origin check is what makes a passkey phishing resistant."""
        authenticator = SoftAuthenticator()
        challenge = passkeys.begin_registration(USER_ID, user_name=EMAIL)
        credential = authenticator.register(
            _challenge_of(challenge.options), origin="https://evil.example.net"
        )
        with pytest.raises(PasskeyRejected):
            passkeys.finish_registration(
                USER_ID, challenge_id=challenge.challenge_id, credential=credential
            )

    def test_wrong_rp_id_is_refused(self, passkeys: PasskeyService) -> None:
        authenticator = SoftAuthenticator()
        challenge = passkeys.begin_registration(USER_ID, user_name=EMAIL)
        credential = authenticator.register(
            _challenge_of(challenge.options), rp_id="evil.example.net"
        )
        with pytest.raises(PasskeyRejected):
            passkeys.finish_registration(
                USER_ID, challenge_id=challenge.challenge_id, credential=credential
            )

    def test_duplicate_credential_is_refused(self, passkeys: PasskeyService) -> None:
        """Registering the same credential twice is a 409, to either account.

        The message does not say whose it is: telling a caller their authenticator is
        already enrolled elsewhere is an account oracle that needs only a security key.
        """
        authenticator, _ = enrol_passkey(passkeys)
        challenge = passkeys.begin_registration("user-0002", user_name="other@example.com")
        credential = authenticator.register(_challenge_of(challenge.options))
        with pytest.raises(PasskeyRejected) as caught:
            passkeys.finish_registration(
                "user-0002", challenge_id=challenge.challenge_id, credential=credential
            )
        assert caught.value.status_code == 409
        assert "user-0001" not in caught.value.message
        assert USER_ID not in caught.value.message

    def test_missing_rp_id_names_the_setting(self) -> None:
        settings = make_settings(rp_id="")
        service = PasskeyService(
            settings,
            IdentityStores(
                credentials=InMemoryCredentialStore(),
                refresh_tokens=InMemoryRefreshTokenStore(),
                passkeys=InMemoryPasskeyStore(),
                webauthn_challenges=InMemoryWebAuthnChallengeStore(),
            ),
        )
        with pytest.raises(ValueError, match="IDENTITY_RP_ID"):
            _ = service.rp_id

    def test_missing_origins_names_the_setting(self) -> None:
        settings = make_settings(webauthn_origins=[])
        service = PasskeyService(
            settings,
            IdentityStores(
                credentials=InMemoryCredentialStore(),
                refresh_tokens=InMemoryRefreshTokenStore(),
                passkeys=InMemoryPasskeyStore(),
                webauthn_challenges=InMemoryWebAuthnChallengeStore(),
            ),
        )
        with pytest.raises(ValueError, match="IDENTITY_WEBAUTHN_ORIGINS"):
            _ = service.origins


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


class TestLogin:
    def test_round_trip_identifies_the_user(self, passkeys: PasskeyService) -> None:
        authenticator, record = enrol_passkey(passkeys)
        result = sign_in(passkeys, authenticator)
        assert result.user_id == USER_ID
        assert result.credential_id == record.credential_id
        assert result.user_verified is True

    def test_records_the_new_sign_count(
        self, passkeys: PasskeyService, stores: IdentityStores
    ) -> None:
        authenticator, record = enrol_passkey(passkeys)
        before = record.sign_count
        sign_in(passkeys, authenticator)
        stored = stores.require_passkeys().get(USER_ID, record.credential_id)
        assert stored is not None
        assert stored.sign_count > before
        assert stored.last_used_at

    def test_counter_regression_is_refused(self, passkeys: PasskeyService) -> None:
        """A counter that did not advance is evidence of a clone. Section 6.1.3."""
        authenticator, record = enrol_passkey(passkeys)
        challenge = passkeys.begin_login()
        credential = authenticator.assertion(
            _challenge_of(challenge.options), sign_count=record.sign_count
        )
        with pytest.raises(PasskeyRejected):
            passkeys.finish_login(challenge_id=challenge.challenge_id, credential=credential)

    def test_counter_regression_is_logged(
        self, passkeys: PasskeyService, caplog: pytest.LogCaptureFixture
    ) -> None:
        """And logged at ERROR, because a clone is a finding and not a typo."""
        authenticator, record = enrol_passkey(passkeys)
        challenge = passkeys.begin_login()
        credential = authenticator.assertion(
            _challenge_of(challenge.options), sign_count=record.sign_count - 1
        )
        with (
            caplog.at_level("ERROR", logger="webbpulse.identity.passkeys"),
            pytest.raises(PasskeyRejected),
        ):
            passkeys.finish_login(challenge_id=challenge.challenge_id, credential=credential)
        assert any("counter_regression" in record.message for record in caplog.records)

    def test_zero_counter_authenticator_is_allowed(
        self, passkeys: PasskeyService, stores: IdentityStores
    ) -> None:
        """An authenticator with no counter sends zero every time, which is not a regression.

        The WebAuthn specification says to skip the check when both the stored and the
        presented count are zero. Apple's platform authenticator is that case, and refusing
        it would make passkeys unusable on every iPhone.
        """
        authenticator = SoftAuthenticator()
        authenticator.sign_count = 0
        challenge = passkeys.begin_registration(USER_ID, user_name=EMAIL)
        credential = authenticator.register(_challenge_of(challenge.options))
        record = passkeys.finish_registration(
            USER_ID, challenge_id=challenge.challenge_id, credential=credential
        )
        # The registration above incremented the counter, so put the row back to the
        # counterless state a real zero-counter authenticator would have produced.
        stores.require_passkeys().record_use(
            USER_ID, record.credential_id, sign_count=0, used_at=""
        )

        login = passkeys.begin_login()
        assertion = authenticator.assertion(_challenge_of(login.options), sign_count=0)
        result = passkeys.finish_login(challenge_id=login.challenge_id, credential=assertion)
        assert result.user_id == USER_ID

    def test_challenge_is_single_use(self, passkeys: PasskeyService) -> None:
        authenticator, _ = enrol_passkey(passkeys)
        challenge = passkeys.begin_login()
        credential = authenticator.assertion(_challenge_of(challenge.options))
        passkeys.finish_login(challenge_id=challenge.challenge_id, credential=credential)
        with pytest.raises(PasskeyRejected):
            passkeys.finish_login(challenge_id=challenge.challenge_id, credential=credential)

    def test_unknown_credential_is_refused(self, passkeys: PasskeyService) -> None:
        stranger = SoftAuthenticator()
        challenge = passkeys.begin_login()
        credential = stranger.assertion(_challenge_of(challenge.options))
        with pytest.raises(PasskeyRejected):
            passkeys.finish_login(challenge_id=challenge.challenge_id, credential=credential)

    def test_wrong_origin_is_refused(self, passkeys: PasskeyService) -> None:
        authenticator, _ = enrol_passkey(passkeys)
        challenge = passkeys.begin_login()
        credential = authenticator.assertion(
            _challenge_of(challenge.options), origin="https://evil.example.net"
        )
        with pytest.raises(PasskeyRejected):
            passkeys.finish_login(challenge_id=challenge.challenge_id, credential=credential)

    def test_wrong_rp_id_is_refused(self, passkeys: PasskeyService) -> None:
        authenticator, _ = enrol_passkey(passkeys)
        challenge = passkeys.begin_login()
        credential = authenticator.assertion(
            _challenge_of(challenge.options), rp_id="evil.example.net"
        )
        with pytest.raises(PasskeyRejected):
            passkeys.finish_login(challenge_id=challenge.challenge_id, credential=credential)

    def test_registration_challenge_cannot_satisfy_login(self, passkeys: PasskeyService) -> None:
        authenticator, _ = enrol_passkey(passkeys)
        challenge = passkeys.begin_registration(USER_ID, user_name=EMAIL)
        credential = authenticator.assertion(_challenge_of(challenge.options))
        with pytest.raises(PasskeyRejected):
            passkeys.finish_login(challenge_id=challenge.challenge_id, credential=credential)

    def test_options_for_a_known_user_list_their_credentials(
        self, passkeys: PasskeyService
    ) -> None:
        authenticator, _ = enrol_passkey(passkeys)
        options = passkeys.begin_login(user_id=USER_ID).options
        allowed = {entry["id"] for entry in options["allowCredentials"]}
        assert authenticator.credential_id_b64 in allowed


# ---------------------------------------------------------------------------
# `amr`, and whether a passkey is one factor or two
# ---------------------------------------------------------------------------


class TestAmr:
    def test_verified_passkey_is_multi_factor(self, passkeys: PasskeyService) -> None:
        authenticator, _ = enrol_passkey(passkeys, user_verified=True)
        result = sign_in(passkeys, authenticator)
        assert AMR_PASSKEY in result.amr
        assert AMR_PIN in result.amr

    def test_unverified_passkey_is_single_factor(self, passkeys: PasskeyService) -> None:
        authenticator, _ = enrol_passkey(passkeys, user_verified=False)
        result = sign_in(passkeys, authenticator)
        assert result.amr == [AMR_PASSKEY]

    def test_flow_mints_mfa_in_the_token(
        self,
        flows: IdentityFlows,
        hooks: FakeHooks,
        stores: IdentityStores,
        passkeys: PasskeyService,
        kms: FakeKms,
    ) -> None:
        """The whole login leg: a verified passkey produces `mfa` in the access token.

        And `auth_time` is now rather than the 1 the hook tried to set, which is the check
        that `_mint_access` still owns both claims on this path too.
        """
        seed_account(hooks, stores)
        authenticator, _ = enrol_passkey(passkeys, user_verified=True)
        challenge = flows.begin_passkey_login()
        credential = authenticator.assertion(_challenge_of(challenge.options))
        result = flows.login_with_passkey(
            challenge_id=challenge.challenge_id, credential=credential
        )
        settings = make_settings()
        claims = TokenService(settings, kms).verify_access_token(result.access_token)
        assert AMR_PASSKEY in claims["amr"]
        assert AMR_PIN in claims["amr"]
        assert "mfa" in claims["amr"]
        assert "forged" not in claims["amr"]
        assert claims["auth_time"] > 1

    def test_verified_passkey_skips_the_totp_challenge(
        self,
        flows: IdentityFlows,
        hooks: FakeHooks,
        stores: IdentityStores,
        passkeys: PasskeyService,
    ) -> None:
        """A user with TOTP enrolled is not asked for a code after a verified passkey.

        Two factors have already been presented in one gesture, so a third would be a policy
        this package has no business inventing. This is the M5 multi-factor decision, and it
        is the half a happy-path test would not notice.
        """
        seed_account(hooks, stores)
        _enrol_totp(flows)
        authenticator, _ = enrol_passkey(passkeys, user_verified=True)
        challenge = flows.begin_passkey_login()
        credential = authenticator.assertion(_challenge_of(challenge.options))
        result = flows.login_with_passkey(
            challenge_id=challenge.challenge_id, credential=credential
        )
        assert result.access_token

    def test_unverified_passkey_still_gets_the_totp_challenge(
        self,
        flows: IdentityFlows,
        hooks: FakeHooks,
        stores: IdentityStores,
        passkeys: PasskeyService,
    ) -> None:
        """The other half: one factor is one factor, whatever kind it is."""
        seed_account(hooks, stores)
        _enrol_totp(flows)
        authenticator, _ = enrol_passkey(passkeys, user_verified=False)
        challenge = flows.begin_passkey_login()
        credential = authenticator.assertion(_challenge_of(challenge.options))
        with pytest.raises(MfaChallengeRequired):
            flows.login_with_passkey(challenge_id=challenge.challenge_id, credential=credential)


def _enrol_totp(flows: IdentityFlows, user_id: str = USER_ID) -> str:
    service = flows.mfa
    assert service is not None
    enrolment = service.begin_enrolment(user_id, account_name=EMAIL)
    step = totp_module.current_step()
    service.confirm_enrolment(user_id, totp_module.generate_code(enrolment.secret, step=step))
    return enrolment.secret


# ---------------------------------------------------------------------------
# The flow layer: hooks, passwordless gating, last-credential guard
# ---------------------------------------------------------------------------


class TestFlowRules:
    def test_disabled_account_cannot_sign_in_with_a_passkey(
        self,
        flows: IdentityFlows,
        hooks: FakeHooks,
        stores: IdentityStores,
        passkeys: PasskeyService,
    ) -> None:
        """`may_authenticate` still has the last word, exactly as on the password path."""
        seed_account(hooks, stores)
        authenticator, _ = enrol_passkey(passkeys)
        challenge = flows.begin_passkey_login()
        credential = authenticator.assertion(_challenge_of(challenge.options))
        hooks.refuse = "This account is disabled."
        with pytest.raises(AuthenticationRefused):
            flows.login_with_passkey(challenge_id=challenge.challenge_id, credential=credential)

    def test_passwordless_off_refuses_both_login_legs(
        self,
        hooks: FakeHooks,
        stores: IdentityStores,
        kms: FakeKms,
    ) -> None:
        """With `passkeys_passwordless` false there is no way into an account here.

        Enrolment still works: a passkey is then a credential for step-up and a second
        factor, but not an entry point.
        """
        from webbpulse.identity.flows import LoginRejected

        settings = make_settings(passkeys_passwordless=False)
        flows = IdentityFlows(settings, hooks, stores, TokenService(settings, kms))
        assert flows.passkeys is not None
        with pytest.raises(LoginRejected) as caught:
            flows.begin_passkey_login()
        assert caught.value.error_code == "PASSKEY_LOGIN_DISABLED"
        with pytest.raises(LoginRejected):
            flows.login_with_passkey(challenge_id="anything", credential={})

    def test_passkeys_disabled_means_no_service(
        self,
        hooks: FakeHooks,
        stores: IdentityStores,
        kms: FakeKms,
    ) -> None:
        settings = make_settings(passkeys_enabled=False)
        flows = IdentityFlows(settings, hooks, stores, TokenService(settings, kms))
        assert flows.passkeys is None

    def test_missing_stores_mean_no_service(self, hooks: FakeHooks, kms: FakeKms) -> None:
        """M3 and M4's gate, applied to M5: no tables, no capability, no routes."""
        settings = make_settings()
        stores = IdentityStores(
            credentials=InMemoryCredentialStore(),
            refresh_tokens=InMemoryRefreshTokenStore(),
        )
        flows = IdentityFlows(settings, hooks, stores, TokenService(settings, kms))
        assert flows.passkeys is None

    def test_unknown_email_still_gets_options(self, flows: IdentityFlows) -> None:
        """Section 5.4: the options route must not become an account oracle.

        An address with no account gets a challenge and an empty allow list, which is
        byte-identical to a genuine discoverable-credential request.
        """
        challenge = flows.begin_passkey_login(email="nobody@example.com")
        assert challenge.challenge_id
        assert not challenge.options.get("allowCredentials")

    def test_last_passkey_cannot_be_deleted_without_a_password(
        self,
        flows: IdentityFlows,
        hooks: FakeHooks,
        stores: IdentityStores,
        passkeys: PasskeyService,
    ) -> None:
        seed_account(hooks, stores, password=None)
        _, record = enrol_passkey(passkeys)
        with pytest.raises(PasskeyRejected) as caught:
            flows.delete_passkey(user_id=USER_ID, credential_id=record.credential_id)
        assert caught.value.error_code == "LAST_CREDENTIAL"
        assert caught.value.status_code == 409

    def test_last_passkey_can_be_deleted_with_a_password(
        self,
        flows: IdentityFlows,
        hooks: FakeHooks,
        stores: IdentityStores,
        passkeys: PasskeyService,
    ) -> None:
        seed_account(hooks, stores)
        _, record = enrol_passkey(passkeys)
        flows.delete_passkey(user_id=USER_ID, credential_id=record.credential_id)
        assert flows.list_passkeys(user_id=USER_ID) == []

    def test_penultimate_passkey_can_be_deleted_without_a_password(
        self,
        flows: IdentityFlows,
        hooks: FakeHooks,
        stores: IdentityStores,
        passkeys: PasskeyService,
    ) -> None:
        """The guard is about the last one only. Two passkeys, delete either."""
        seed_account(hooks, stores, password=None)
        _, first = enrol_passkey(passkeys, name="One")
        _, second = enrol_passkey(passkeys, name="Two")
        flows.delete_passkey(user_id=USER_ID, credential_id=first.credential_id)
        remaining = flows.list_passkeys(user_id=USER_ID)
        assert [record.credential_id for record in remaining] == [second.credential_id]

    def test_rename_changes_the_label(
        self,
        flows: IdentityFlows,
        hooks: FakeHooks,
        stores: IdentityStores,
        passkeys: PasskeyService,
    ) -> None:
        seed_account(hooks, stores)
        _, record = enrol_passkey(passkeys, name="Old")
        updated = flows.rename_passkey(
            user_id=USER_ID, credential_id=record.credential_id, name="  New   name "
        )
        assert updated.name == "New name"

    def test_rename_of_another_users_passkey_is_a_404(
        self,
        flows: IdentityFlows,
        hooks: FakeHooks,
        stores: IdentityStores,
        passkeys: PasskeyService,
    ) -> None:
        """Scoped to the caller, so somebody else's credential id is simply not found."""
        seed_account(hooks, stores)
        _, record = enrol_passkey(passkeys)
        with pytest.raises(PasskeyRejected) as caught:
            flows.rename_passkey(
                user_id="user-9999", credential_id=record.credential_id, name="Mine now"
            )
        assert caught.value.status_code == 404

    def test_empty_rename_is_refused(
        self,
        flows: IdentityFlows,
        hooks: FakeHooks,
        stores: IdentityStores,
        passkeys: PasskeyService,
    ) -> None:
        seed_account(hooks, stores)
        _, record = enrol_passkey(passkeys)
        with pytest.raises(PasskeyRejected) as caught:
            flows.rename_passkey(user_id=USER_ID, credential_id=record.credential_id, name="   ")
        assert caught.value.status_code == 422


# ---------------------------------------------------------------------------
# The stores
# ---------------------------------------------------------------------------


class TestStores:
    def test_challenge_consume_is_single_use(self) -> None:
        store = InMemoryWebAuthnChallengeStore()
        record = WebAuthnChallengeRecord(
            challenge_id="c1",
            challenge="Y2hhbA",
            purpose="login",
            created_at="2026-01-01T00:00:00Z",
            expires_at=_far_future(),
        )
        store.put(record)
        assert store.consume("c1") is not None
        assert store.consume("c1") is None

    def test_expired_challenge_is_refused_in_code(self) -> None:
        """Expiry is enforced here, not by DynamoDB's TTL.

        TTL is storage reclamation and runs on its own schedule, up to 48 hours late. A row
        past its deadline must be unusable the moment it is past it.
        """
        store = InMemoryWebAuthnChallengeStore()
        store.put(
            WebAuthnChallengeRecord(
                challenge_id="c1",
                challenge="Y2hhbA",
                purpose="login",
                created_at="2020-01-01T00:00:00Z",
                expires_at=1,
            )
        )
        assert store.consume("c1") is None

    def test_passkey_store_round_trip(self) -> None:
        store = InMemoryPasskeyStore()
        record = PasskeyRecord(
            user_id=USER_ID, credential_id="cred-1", public_key="key", sign_count=7
        )
        store.put(record)
        stored = store.get(USER_ID, "cred-1")
        assert stored is not None
        assert stored.credential_id == "cred-1"
        assert stored.public_key == "key"
        assert stored.sign_count == 7
        # The store stamps `created_at` when the caller left it empty, so a row always
        # carries one whether it came through the service or straight from a product.
        assert stored.created_at
        assert store.find_by_credential_id("cred-1") == stored
        assert store.list_for_user(USER_ID) == [stored]

    def test_passkey_store_refuses_a_duplicate(self) -> None:
        store = InMemoryPasskeyStore()
        record = PasskeyRecord(user_id=USER_ID, credential_id="cred-1", public_key="key")
        store.put(record)
        with pytest.raises(KeyError):
            store.put(record)

    def test_record_use_advances_the_counter(self) -> None:
        store = InMemoryPasskeyStore()
        store.put(PasskeyRecord(user_id=USER_ID, credential_id="c", public_key="k", sign_count=1))
        store.record_use(USER_ID, "c", sign_count=9, used_at="2026-01-01T00:00:00Z")
        stored = store.get(USER_ID, "c")
        assert stored is not None
        assert stored.sign_count == 9
        assert stored.last_used_at == "2026-01-01T00:00:00Z"

    def test_delete_and_rename_report_absence(self) -> None:
        store = InMemoryPasskeyStore()
        assert store.delete(USER_ID, "missing") is False
        assert store.rename(USER_ID, "missing", name="x") is False


def _far_future() -> int:
    import time

    return int(time.time()) + 3600


# ---------------------------------------------------------------------------
# The routes
# ---------------------------------------------------------------------------


def _router_paths(router: APIRouter) -> set[str]:
    """Every path the router declares.

    Enumerates the router rather than `app.routes`, which is what M1 to M4 do
    and what the FastAPI version in CI forces: from FastAPI 0.141 /
    Starlette 1.6 `include_router` no longer copies the child routes onto the
    app, it appends a single `_IncludedRouter` wrapper holding them, so an app
    with a fully mounted identity router shows only `/docs` and `/openapi.json`
    at the top level. The router itself is flat on every version.
    """
    return {route.path for route in router.routes}  # type: ignore[attr-defined]


class TestRoutes:
    def test_routes_are_mounted(
        self,
        hooks: FakeHooks,
        stores: IdentityStores,
        kms: FakeKms,
    ) -> None:
        paths = _router_paths(
            build_identity_router(
                make_settings(), hooks, stores, kms_client=kms, limiter_enabled=False
            )
        )
        base = prefix()
        assert f"{base}{PASSKEY_REGISTER_OPTIONS_PATH}" in paths
        assert f"{base}{PASSKEY_REGISTER_VERIFY_PATH}" in paths
        assert f"{base}{LOGIN_PASSKEY_OPTIONS_PATH}" in paths
        assert f"{base}{LOGIN_PASSKEY_VERIFY_PATH}" in paths
        assert f"{base}{PASSKEYS_PATH}" in paths

    def test_routes_are_absent_without_the_stores(self, hooks: FakeHooks, kms: FakeKms) -> None:
        """No tables, no routes. A 503 endpoint is worse than an absent one."""
        settings = make_settings()
        stores = IdentityStores(
            credentials=InMemoryCredentialStore(),
            refresh_tokens=InMemoryRefreshTokenStore(),
        )
        paths = _router_paths(
            build_identity_router(settings, hooks, stores, kms_client=kms, limiter_enabled=False)
        )
        assert f"{prefix()}{LOGIN_PASSKEY_OPTIONS_PATH}" not in paths

    def test_login_options_are_anonymous(self, client: TestClient) -> None:
        response = client.post(f"{prefix()}{LOGIN_PASSKEY_OPTIONS_PATH}", json={})
        assert response.status_code == 200
        body = response.json()
        assert body["challenge_id"]
        assert body["publicKey"]["challenge"]

    def test_login_options_accept_no_body(self, client: TestClient) -> None:
        """A discoverable request sends nothing, and must not be a 422."""
        response = client.post(f"{prefix()}{LOGIN_PASSKEY_OPTIONS_PATH}")
        assert response.status_code == 200

    def test_register_options_require_a_token(self, client: TestClient) -> None:
        response = client.post(f"{prefix()}{PASSKEY_REGISTER_OPTIONS_PATH}")
        assert response.status_code == 401
        assert response.json()["error_code"] == "NOT_AUTHENTICATED"

    def test_list_requires_a_token(self, client: TestClient) -> None:
        response = client.get(f"{prefix()}{PASSKEYS_PATH}")
        assert response.status_code == 401

    def test_full_ceremony_over_http(
        self, client: TestClient, hooks: FakeHooks, stores: IdentityStores
    ) -> None:
        """Register a passkey and sign in with it, entirely through the client.

        The wire shape is asserted along the way, because `publicKey` and `challenge_id` are
        what a frontend hands to `navigator.credentials`, and a rename there type-checks
        perfectly and breaks every sign-in.
        """
        seed_account(hooks, stores)
        token = _password_login(client)

        options = client.post(
            f"{prefix()}{PASSKEY_REGISTER_OPTIONS_PATH}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert options.status_code == 200
        body = options.json()
        authenticator = SoftAuthenticator()
        credential = authenticator.register(body["publicKey"]["challenge"])

        registered = client.post(
            f"{prefix()}{PASSKEY_REGISTER_VERIFY_PATH}",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "challenge_id": body["challenge_id"],
                "credential": credential,
                "name": "Laptop",
            },
        )
        assert registered.status_code == 201
        summary = registered.json()["passkey"]
        assert summary["name"] == "Laptop"
        # The public key is never in a response body.
        assert "public_key" not in summary

        listed = client.get(
            f"{prefix()}{PASSKEYS_PATH}", headers={"Authorization": f"Bearer {token}"}
        )
        assert listed.status_code == 200
        assert [entry["name"] for entry in listed.json()["passkeys"]] == ["Laptop"]

        login_options = client.post(f"{prefix()}{LOGIN_PASSKEY_OPTIONS_PATH}", json={})
        assertion = authenticator.assertion(login_options.json()["publicKey"]["challenge"])
        signed_in = client.post(
            f"{prefix()}{LOGIN_PASSKEY_VERIFY_PATH}",
            json={
                "challenge_id": login_options.json()["challenge_id"],
                "credential": assertion,
            },
        )
        assert signed_in.status_code == 200
        assert signed_in.json()["token_type"] == "Bearer"
        assert signed_in.json()["access_token"]
        # The same token pair as a password login: refresh in the cookie, never in the body.
        assert "refresh_token" not in signed_in.json()
        assert signed_in.cookies.get(make_settings().cookie_name)

    def test_rename_and_delete_over_http(
        self, client: TestClient, hooks: FakeHooks, stores: IdentityStores
    ) -> None:
        seed_account(hooks, stores)
        token = _password_login(client)
        credential_id = _enrol_over_http(client, token)

        renamed = client.patch(
            f"{prefix()}/passkeys/{credential_id}",
            headers={"Authorization": f"Bearer {token}"},
            json={"name": "Desk key"},
        )
        assert renamed.status_code == 200
        assert renamed.json()["passkey"]["name"] == "Desk key"

        deleted = client.request(
            "DELETE",
            f"{prefix()}/passkeys/{credential_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert deleted.status_code == 200
        assert deleted.json() == {"deleted": True}

    def test_verify_with_no_credential_is_a_422(self, client: TestClient) -> None:
        response = client.post(
            f"{prefix()}{LOGIN_PASSKEY_VERIFY_PATH}",
            json={"challenge_id": "whatever"},
        )
        assert response.status_code == 422
        assert response.json()["error_code"] == "CREDENTIAL_REQUIRED"

    def test_bad_challenge_is_the_one_message(self, client: TestClient) -> None:
        """Every login refusal renders through the shared envelope with one message."""
        authenticator = SoftAuthenticator()
        response = client.post(
            f"{prefix()}{LOGIN_PASSKEY_VERIFY_PATH}",
            json={
                "challenge_id": "never-issued",
                "credential": authenticator.assertion(b64url_encode(os.urandom(32))),
            },
        )
        assert response.status_code == 401
        assert response.json()["error_code"] == "PASSKEY_CHALLENGE_INVALID"

    def test_unverified_passkey_over_http_gets_the_mfa_body(
        self,
        client: TestClient,
        hooks: FakeHooks,
        stores: IdentityStores,
        kms: FakeKms,
    ) -> None:
        """A 200 with `mfa_required`, the shape `@webbpulse/auth` already branches on."""
        seed_account(hooks, stores)
        settings = make_settings()
        flows = IdentityFlows(settings, hooks, stores, TokenService(settings, kms), kms_client=kms)
        _enrol_totp(flows)
        service = flows.passkeys
        assert service is not None
        authenticator, _ = enrol_passkey(service, user_verified=False)

        options = client.post(f"{prefix()}{LOGIN_PASSKEY_OPTIONS_PATH}", json={})
        assertion = authenticator.assertion(options.json()["publicKey"]["challenge"])
        response = client.post(
            f"{prefix()}{LOGIN_PASSKEY_VERIFY_PATH}",
            json={"challenge_id": options.json()["challenge_id"], "credential": assertion},
        )
        assert response.status_code == 200
        assert response.json()["mfa_required"] is True
        assert response.json()["mfa_ticket"]
        assert LOGIN_TOTP_PATH  # the leg the frontend posts that ticket to


def _password_login(client: TestClient) -> str:
    response = client.post(f"{prefix()}{LOGIN_PATH}", json={"email": EMAIL, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return str(response.json()["access_token"])


def _enrol_over_http(client: TestClient, token: str) -> str:
    options = client.post(
        f"{prefix()}{PASSKEY_REGISTER_OPTIONS_PATH}",
        headers={"Authorization": f"Bearer {token}"},
    ).json()
    authenticator = SoftAuthenticator()
    credential = authenticator.register(options["publicKey"]["challenge"])
    registered = client.post(
        f"{prefix()}{PASSKEY_REGISTER_VERIFY_PATH}",
        headers={"Authorization": f"Bearer {token}"},
        json={"challenge_id": options["challenge_id"], "credential": credential},
    )
    assert registered.status_code == 201, registered.text
    return str(registered.json()["passkey"]["credential_id"])


# ---------------------------------------------------------------------------
# Availability discovery, 0.17.0
# ---------------------------------------------------------------------------
#
# The route exists so a frontend stops inferring availability by probing
# `POST /login/passkey/options` on sign-in page load. WebbPulse-Portfolio does that today,
# and it is wrong twice: the probe spends that route's 30-per-15-minutes IP budget on page
# loads rather than on sign-ins, and `begin_passkey_login` writes a WebAuthn challenge row
# per call, so every page load in the estate leaves a row in the challenge table to expire.
# PR 182 there added a sessionStorage cache as a stopgap and asked for this route. These
# tests pin the three things a client depends on: the body shape, that `passwordless` cannot
# contradict `enabled`, and that the answer exists in every deployment.


class CountingChallengeStore(InMemoryWebAuthnChallengeStore):
    """An `InMemoryWebAuthnChallengeStore` that counts writes.

    The availability route's promise is that it writes nothing, and the only way to assert
    "nothing" is to count. A subclass rather than a reach into the fake's private dict, so
    the assertion survives a change to how the fake stores its rows.
    """

    def __init__(self) -> None:
        super().__init__()
        self.puts = 0

    def put(self, record: WebAuthnChallengeRecord) -> None:
        self.puts += 1
        super().put(record)


def _availability_router(
    hooks: FakeHooks | None = None,
    stores: IdentityStores | None = None,
    kms: FakeKms | None = None,
    **overrides: Any,
) -> Any:
    """A router built the way a product builds one, for the availability tests."""
    assert kms is not None
    if hooks is None or stores is None:
        return build_identity_router(make_settings(**overrides), kms_client=kms)
    return build_identity_router(
        make_settings(**overrides),
        hooks,
        stores,
        kms_client=kms,
        limiter_enabled=False,
    )


def _availability_client(router: Any) -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def _get_availability(client: TestClient) -> Any:
    return client.get(f"{prefix()}{PASSKEY_AVAILABILITY_PATH}")


class TestAvailability:
    def test_enabled_and_passwordless_is_the_default_shape(
        self, hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
    ) -> None:
        """Both capabilities default on, so a stock deployment offers the button."""
        client = _availability_client(_availability_router(hooks, stores, kms))
        response = _get_availability(client)
        assert response.status_code == 200
        assert response.json() == {"enabled": True, "passwordless": True}

    def test_enabled_but_not_passwordless(
        self, hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
    ) -> None:
        """A passkey as a managed credential and a second factor, but not an entry point.

        The distinction `begin_passkey_login` already enforces, reported so a settings page
        can offer enrolment while a sign-in page does not offer the button.
        """
        client = _availability_client(
            _availability_router(hooks, stores, kms, passkeys_passwordless=False)
        )
        assert _get_availability(client).json() == {"enabled": True, "passwordless": False}

    def test_disabled_reports_passwordless_false_whatever_the_setting_says(
        self, hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
    ) -> None:
        """`passkeys_passwordless` defaults on, so the pair can disagree unless gated.

        A deployment with `passkeys_enabled=False` keeps the passwordless default of `True`
        and means nothing by it, because no login route mounted. Reporting that pair would
        tell a frontend to draw a "Sign in with a passkey" button against routes that do not
        exist, which is the failure this route was added to prevent rather than cause.
        """
        client = _availability_client(
            _availability_router(hooks, stores, kms, passkeys_enabled=False)
        )
        body = _get_availability(client).json()
        assert body == {"enabled": False, "passwordless": False}
        # The setting itself is untouched: the gate is in the route, not in the settings.
        assert make_settings(passkeys_enabled=False).passkeys_passwordless is True

    def test_disabled_with_passwordless_off_too(
        self, hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
    ) -> None:
        client = _availability_client(
            _availability_router(
                hooks, stores, kms, passkeys_enabled=False, passkeys_passwordless=False
            )
        )
        assert _get_availability(client).json() == {"enabled": False, "passwordless": False}

    def test_the_route_mounts_when_passkeys_are_disabled(
        self, hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
    ) -> None:
        """The seven flow routes are absent and this one is still present.

        That is the whole point: one authoritative answer in every deployment. A route that
        were absent here would answer 404, which is indistinguishable from a routing mistake
        or an older version of this package, and is the ambiguous signal the route replaces.
        """
        router = _availability_router(hooks, stores, kms, passkeys_enabled=False)
        paths = _router_paths(router)
        assert f"{prefix()}{LOGIN_PASSKEY_OPTIONS_PATH}" not in paths
        assert f"{prefix()}{PASSKEYS_PATH}" not in paths
        assert f"{prefix()}{PASSKEY_AVAILABILITY_PATH}" in paths

    def test_the_route_mounts_when_the_stores_are_missing(
        self, hooks: FakeHooks, kms: FakeKms
    ) -> None:
        """No passkey table and no challenge table, and the answer is still served.

        It reports what the operator configured rather than what the stores can support, so
        a capability switched on with no table behind it stays visible as the configuration
        error it is instead of being hidden by a frontend that quietly stops offering
        passkeys.
        """
        stores = IdentityStores(
            credentials=InMemoryCredentialStore(),
            refresh_tokens=InMemoryRefreshTokenStore(),
        )
        router = _availability_router(hooks, stores, kms)
        assert f"{prefix()}{LOGIN_PASSKEY_OPTIONS_PATH}" not in _router_paths(router)
        assert _get_availability(_availability_client(router)).json() == {
            "enabled": True,
            "passwordless": True,
        }

    def test_the_route_mounts_on_a_documents_only_router(self, kms: FakeKms) -> None:
        """The JWKS-only shape, with no hooks and no stores at all, still answers."""
        response = _get_availability(_availability_client(_availability_router(kms=kms)))
        assert response.status_code == 200
        assert response.json() == {"enabled": True, "passwordless": True}

    def test_the_route_carries_the_same_cache_policy_as_oauth_discovery(
        self, hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
    ) -> None:
        """Five minutes: turning passkeys on is exactly when somebody is watching for it."""
        client = _availability_client(_availability_router(hooks, stores, kms))
        header = _get_availability(client).headers["cache-control"]
        assert header == PASSKEY_AVAILABILITY_CACHE_CONTROL
        assert PASSKEY_AVAILABILITY_CACHE_CONTROL == OAUTH_PROVIDERS_CACHE_CONTROL
        assert PASSKEY_AVAILABILITY_CACHE_CONTROL == "public, max-age=300"

    def test_the_route_needs_no_token_and_sets_no_cookie(
        self, hooks: FakeHooks, stores: IdentityStores, kms: FakeKms
    ) -> None:
        """It is read by the sign-in page, which by definition holds no token.

        The absent `Authorization` header is the assertion: every management route in this
        module answers 401 to exactly this request, and this one answers 200.
        """
        client = _availability_client(_availability_router(hooks, stores, kms))
        response = _get_availability(client)
        assert response.status_code == 200
        assert "authorization" not in {key.lower() for key in response.request.headers}
        assert "set-cookie" not in {key.lower() for key in response.headers}

    def test_the_management_routes_refuse_the_same_anonymous_request(
        self, client: TestClient
    ) -> None:
        """The control for the test above, on the router the rest of this suite uses."""
        assert client.get(f"{prefix()}{PASSKEYS_PATH}").status_code == 401
        assert _get_availability(client).status_code == 200

    def test_the_route_consumes_no_rate_limit_budget_and_writes_no_challenge(
        self,
        hooks: FakeHooks,
        kms: FakeKms,
        attempts: InMemoryLoginAttemptStore,
    ) -> None:
        """The reason the route exists, asserted against the two costs the probe paid.

        Forty calls is past the 30-per-15-minutes budget `PASSKEY_OPTIONS_LIMIT` sets, and
        every one answers 200 with the limiter left on, so no bucket is consumed. The
        counting challenge store is the other half: a probe of `login/passkey/options` would
        have written forty rows into it.
        """
        challenges = CountingChallengeStore()
        stores = IdentityStores(
            credentials=InMemoryCredentialStore(),
            refresh_tokens=InMemoryRefreshTokenStore(),
            identity_tokens=InMemoryIdentityTokenStore(),
            passkeys=InMemoryPasskeyStore(),
            webauthn_challenges=challenges,
        )
        app = FastAPI()
        app.include_router(
            build_identity_router(
                make_settings(),
                hooks,
                stores,
                kms_client=kms,
                attempts=attempts,
                limiter_enabled=False,
            )
        )
        client = TestClient(app)
        for _ in range(40):
            assert _get_availability(client).status_code == 200
        assert challenges.puts == 0

    def test_the_probe_this_replaces_does_write_a_challenge_row(
        self, hooks: FakeHooks, kms: FakeKms, attempts: InMemoryLoginAttemptStore
    ) -> None:
        """The control for the test above, and the cost the stopgap cache only defers.

        One call to the route a frontend probes today, and the challenge table has a row in
        it. That is the storage cost paid per sign-in page load, and the reason a
        sessionStorage cache in one frontend is not a fix: the first load of every session
        still pays it and every other consumer pays it in full.
        """
        challenges = CountingChallengeStore()
        stores = IdentityStores(
            credentials=InMemoryCredentialStore(),
            refresh_tokens=InMemoryRefreshTokenStore(),
            identity_tokens=InMemoryIdentityTokenStore(),
            passkeys=InMemoryPasskeyStore(),
            webauthn_challenges=challenges,
        )
        app = FastAPI()
        app.include_router(
            build_identity_router(
                make_settings(),
                hooks,
                stores,
                kms_client=kms,
                attempts=attempts,
                limiter_enabled=False,
            )
        )
        client = TestClient(app)
        assert challenges.puts == 0
        assert client.post(f"{prefix()}{LOGIN_PASSKEY_OPTIONS_PATH}", json={}).status_code == 200
        assert challenges.puts == 1

    def test_the_route_appears_in_the_openapi_document_under_a_passkeys_tag(
        self, kms: FakeKms
    ) -> None:
        """It is a documented public API, unlike the `.well-known` documents.

        The assertion that the schema *builds at all* is the load-bearing half. Every other
        route in this module is annotated `-> JSONResponse`, which under
        `from __future__ import annotations` is an unresolvable string that FastAPI hands
        pydantic as a response model, breaking `app.openapi()` for the whole app. This route
        mounts in every deployment including the documents-only one, whose schema builds
        today, so it must not be what takes `/docs` away from a product with no passkeys.
        """
        app = FastAPI()
        app.include_router(_availability_router(kms=kms))

        schema = app.openapi()
        operation = schema["paths"][f"{prefix()}{PASSKEY_AVAILABILITY_PATH}"]["get"]
        assert operation["tags"] == ["identity", "passkeys"]
        assert operation["tags"].count("identity") == 1

    def test_the_path_sits_under_the_passkeys_collection(self) -> None:
        """`/passkeys/availability` rather than `/passkeys-availability`.

        It reads as a property of the passkey surface, and it cannot collide with
        `PASSKEY_ITEM_PATH`: FastAPI matches the literal segment before the parameterised
        one, and a credential id is opaque bytes that never spells `availability`.
        """
        assert PASSKEY_AVAILABILITY_PATH.startswith(f"{PASSKEYS_PATH}/")
        assert PASSKEY_AVAILABILITY_PATH.removeprefix(PASSKEYS_PATH) == "/availability"

    def test_a_credential_named_availability_does_not_shadow_the_route(
        self, client: TestClient, hooks: FakeHooks, stores: IdentityStores
    ) -> None:
        """The ordering claim above, exercised rather than asserted about.

        `/passkeys/availability` is declared before `/passkeys/{credential_id}`, so the
        literal wins. If it did not, this GET would fall into the item route and answer 401
        to an anonymous caller.
        """
        seed_account(hooks, stores)
        assert _get_availability(client).json() == {"enabled": True, "passwordless": True}
