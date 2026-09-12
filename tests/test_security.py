"""Tests for password hashing and JWT signing in `webbpulse.security`.

The 72 byte bcrypt boundary is exercised from both sides, every algorithm, audience and
issuer check has a negative case, and the bcrypt cost is asserted to be read at call time.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from fastapi import Depends, FastAPI
from starlette.testclient import TestClient

from webbpulse import security
from webbpulse.http import create_app
from webbpulse.security import (
    BCRYPT_MAX_BYTES,
    DEFAULT_ALGORITHM,
    DEFAULT_ROUNDS,
    ExpiredToken,
    InvalidToken,
    TokenError,
    bearer_claims,
    create_token,
    decode_token,
    hash_password,
    needs_rehash,
    verify_password,
)

SECRET = "test-secret-value-that-is-long-enough-for-hs256-abcdefgh"
OTHER_SECRET = "a-different-secret-value-of-a-similarly-respectable-length"
LONG_SECRET = "a-secret-long-enough-for-hs512-which-wants-sixty-four-bytes-abcdefghijkl"


def test_hash_password_round_trips() -> None:
    """A hashed password verifies against the value it was made from."""
    hashed = hash_password("correct horse battery staple")

    assert verify_password("correct horse battery staple", hashed)


def test_hash_password_rejects_the_wrong_password() -> None:
    """A different password does not verify against the hash."""
    hashed = hash_password("correct horse battery staple")

    assert not verify_password("Correct horse battery staple", hashed)


def test_hash_password_salts_so_two_hashes_differ() -> None:
    """Hashing the same password twice gives different hashes that both verify."""
    first = hash_password("hunter2")
    second = hash_password("hunter2")

    assert first != second
    assert verify_password("hunter2", first)
    assert verify_password("hunter2", second)


def test_hash_password_uses_cost_twelve_by_default() -> None:
    """The default bcrypt cost is 12, written into the hash string."""
    assert hash_password("hunter2").split("$")[2] == "12"
    assert DEFAULT_ROUNDS == 12


def test_hash_password_honours_an_explicit_cost() -> None:
    """An explicit `rounds` is the cost written into the hash string."""
    assert hash_password("hunter2", rounds=4).split("$")[2] == "04"


def test_a_changed_default_rounds_takes_effect(monkeypatch: pytest.MonkeyPatch) -> None:
    """`DEFAULT_ROUNDS` is read in the body, so rebinding it changes the cost written."""
    monkeypatch.setattr(security, "DEFAULT_ROUNDS", 4)

    assert hash_password("hunter2").split("$")[2] == "04"
    kwdefaults = hash_password.__kwdefaults__
    assert kwdefaults is not None
    assert kwdefaults["rounds"] is None


def test_a_changed_default_rounds_reaches_needs_rehash(monkeypatch: pytest.MonkeyPatch) -> None:
    """`needs_rehash` compares against the current `DEFAULT_ROUNDS`, not a frozen copy."""
    monkeypatch.setattr(security, "DEFAULT_ROUNDS", 4)
    hashed = hash_password("hunter2")

    assert not needs_rehash(hashed)

    monkeypatch.setattr(security, "DEFAULT_ROUNDS", 5)
    assert needs_rehash(hashed)


def test_an_explicit_cost_still_beats_a_changed_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """An explicit `rounds` wins over a rebound `DEFAULT_ROUNDS`."""
    monkeypatch.setattr(security, "DEFAULT_ROUNDS", 4)

    assert hash_password("hunter2", rounds=5).split("$")[2] == "05"


def test_hashes_written_at_the_old_default_still_verify(monkeypatch: pytest.MonkeyPatch) -> None:
    """A hash written at one cost still verifies after the default is lowered."""
    at_twelve = hash_password("hunter2")
    assert at_twelve.split("$")[2] == "12"

    monkeypatch.setattr(security, "DEFAULT_ROUNDS", 4)
    cheap = hash_password("hunter2")

    assert verify_password("hunter2", cheap)
    assert verify_password("hunter2", at_twelve)
    assert not verify_password("wrong", at_twelve)
    assert not needs_rehash(at_twelve)


def test_hash_password_rejects_non_string_input() -> None:
    """Bytes and None raise TypeError rather than being hashed."""
    with pytest.raises(TypeError):
        hash_password(b"bytes-are-not-a-str")  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        hash_password(None)  # type: ignore[arg-type]


def test_hash_password_accepts_a_password_over_the_bcrypt_limit() -> None:
    """A password longer than bcrypt's 72 byte limit hashes and verifies rather than raising."""
    long_password = "a" * 200

    hashed = hash_password(long_password)

    assert verify_password(long_password, hashed)


def test_passwords_sharing_the_first_72_bytes_are_the_same_to_bcrypt() -> None:
    """Two passwords sharing their first 72 bytes verify against each other's hash."""
    base = "x" * BCRYPT_MAX_BYTES
    hashed = hash_password(base + "totally different tail")

    assert verify_password(base + "another tail entirely", hashed)


def test_truncation_is_on_a_byte_boundary_not_a_character_boundary() -> None:
    """Truncation cuts at 72 bytes, so a multi-byte character straddling the limit is split."""
    at_limit = "é" * 36
    over_limit = at_limit + "é"

    assert len(at_limit.encode("utf-8")) == BCRYPT_MAX_BYTES
    assert verify_password(over_limit, hash_password(at_limit))


def test_verify_truncates_with_the_same_rule_as_hash() -> None:
    """`verify_password` truncates by the same rule as `hash_password`."""
    long_password = "z" * 100

    assert verify_password(long_password, hash_password(long_password))


def test_verify_password_returns_false_for_no_stored_hash() -> None:
    """A missing or empty stored hash is a failed login, as an OAuth only account has."""
    assert not verify_password("anything", None)
    assert not verify_password("anything", "")


def test_verify_password_returns_false_for_a_corrupt_hash() -> None:
    """A stored value that is not a bcrypt hash is a failed login, not an exception."""
    assert not verify_password("hunter2", "not-a-bcrypt-hash")
    assert not verify_password("hunter2", "$2b$")


def test_verify_password_returns_false_for_non_string_password() -> None:
    """A non-string password is a failed login, not an exception."""
    hashed = hash_password("hunter2")

    assert not verify_password(None, hashed)  # type: ignore[arg-type]


def test_needs_rehash_is_false_at_the_current_cost() -> None:
    """A hash written at the current cost does not need rehashing."""
    assert not needs_rehash(hash_password("hunter2"))


def test_needs_rehash_is_true_below_the_current_cost() -> None:
    """A hash written below the current cost needs rehashing."""
    assert needs_rehash(hash_password("hunter2", rounds=4))


def test_needs_rehash_is_false_above_the_current_cost() -> None:
    """A stronger hash is left alone rather than rehashed down to the current cost."""
    assert not needs_rehash("$2b$14$" + "x" * 53)


def test_needs_rehash_is_true_for_an_unparseable_hash() -> None:
    """A hash whose cost cannot be parsed is reported as needing replacement."""
    assert needs_rehash("garbage")
    assert needs_rehash("$2b$notanumber$xxxx")


def test_needs_rehash_honours_an_explicit_target() -> None:
    """An explicit `rounds` is the cost `needs_rehash` compares against."""
    hashed = hash_password("hunter2", rounds=4)

    assert not needs_rehash(hashed, rounds=4)
    assert needs_rehash(hashed, rounds=5)


def test_create_and_decode_round_trips_the_claims() -> None:
    """Claims given to `create_token` come back out of `decode_token`."""
    token = create_token({"sub": "alice", "role": "admin"}, SECRET)

    claims = decode_token(token, SECRET)

    assert claims["sub"] == "alice"
    assert claims["role"] == "admin"


def test_create_token_always_sets_iat() -> None:
    """Every token carries an `iat` claim."""
    claims = decode_token(create_token({"sub": "alice"}, SECRET), SECRET)

    assert "iat" in claims


def test_create_token_sets_exp_from_expires_in() -> None:
    """`exp` is `now` plus `expires_in`, and `iat` is `now`, both in epoch seconds."""
    now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)

    token = create_token({"sub": "alice"}, SECRET, expires_in=timedelta(minutes=30), now=now)
    claims = jwt.decode(token, SECRET, algorithms=["HS256"], options={"verify_exp": False})

    assert claims["exp"] == int((now + timedelta(minutes=30)).timestamp())
    assert claims["iat"] == int(now.timestamp())


def test_a_token_with_no_expires_in_has_no_exp() -> None:
    """With no `expires_in`, no `exp` claim is added: the caller decides."""
    assert "exp" not in decode_token(create_token({"sub": "alice"}, SECRET), SECRET)


def test_caller_claims_override_the_generated_ones() -> None:
    """A claim passed by the caller wins over the one `create_token` would generate."""
    token = create_token({"sub": "alice", "iss": "explicit"}, SECRET, issuer="generated")

    assert decode_token(token, SECRET, issuer="explicit")["iss"] == "explicit"


def test_no_product_claims_are_invented() -> None:
    """A token made from no claims carries only `iat`, with no product conventions added."""
    claims = decode_token(create_token({}, SECRET), SECRET)

    assert set(claims) == {"iat"}


def test_decode_rejects_the_wrong_secret() -> None:
    """Decoding with a different secret raises `InvalidToken`."""
    token = create_token({"sub": "alice"}, SECRET)

    with pytest.raises(InvalidToken):
        decode_token(token, OTHER_SECRET)


def test_decode_rejects_a_malformed_token() -> None:
    """A string that is not a JWT raises `InvalidToken`."""
    with pytest.raises(InvalidToken):
        decode_token("not.a.token", SECRET)


def test_decode_raises_expired_token_for_a_passed_exp() -> None:
    """A token whose `exp` has passed raises `ExpiredToken`."""
    stale = datetime.now(UTC) - timedelta(hours=2)
    token = create_token({"sub": "alice"}, SECRET, expires_in=timedelta(minutes=30), now=stale)

    with pytest.raises(ExpiredToken):
        decode_token(token, SECRET)


def test_expired_and_invalid_are_both_token_errors() -> None:
    """`ExpiredToken` and `InvalidToken` both subclass `TokenError`."""
    assert issubclass(ExpiredToken, TokenError)
    assert issubclass(InvalidToken, TokenError)


def test_leeway_tolerates_clock_skew() -> None:
    """A `leeway` wide enough to cover the skew accepts a just-expired token."""
    just_expired = datetime.now(UTC) - timedelta(seconds=61)
    token = create_token({"sub": "alice"}, SECRET, expires_in=timedelta(seconds=30), now=just_expired)

    with pytest.raises(ExpiredToken):
        decode_token(token, SECRET)

    assert decode_token(token, SECRET, leeway=timedelta(minutes=5))["sub"] == "alice"


def test_decode_does_not_leak_why_it_failed() -> None:
    """A bad signature and a bad audience raise the same message, so neither is disclosed."""
    token = create_token({"sub": "alice"}, SECRET, audience="api")

    with pytest.raises(InvalidToken) as bad_signature:
        decode_token(token, OTHER_SECRET, audience="api")
    with pytest.raises(InvalidToken) as bad_audience:
        decode_token(token, SECRET, audience="other")

    assert str(bad_signature.value) == str(bad_audience.value)


def test_decode_refuses_an_algorithm_outside_the_list() -> None:
    """A token signed with an algorithm outside the accepted list raises `InvalidToken`."""
    token = jwt.encode({"sub": "attacker"}, LONG_SECRET, algorithm="HS512")

    with pytest.raises(InvalidToken):
        decode_token(token, LONG_SECRET)


def test_decode_refuses_an_unsigned_token() -> None:
    """An `alg: none` token raises `InvalidToken`."""
    token = jwt.encode({"sub": "attacker"}, key="", algorithm="none")

    with pytest.raises(InvalidToken):
        decode_token(token, SECRET)


def test_decode_accepts_an_algorithm_the_caller_widened_to() -> None:
    """An algorithm the caller listed in `algorithms` is accepted."""
    token = create_token({"sub": "alice"}, LONG_SECRET, algorithm="HS512")

    assert decode_token(token, LONG_SECRET, algorithms=["HS256", "HS512"])["sub"] == "alice"


def test_the_default_algorithm_is_hs256() -> None:
    """Tokens are signed with HS256 by default, matching `DEFAULT_ALGORITHM`."""
    token = create_token({"sub": "alice"}, SECRET)

    assert jwt.get_unverified_header(token)["alg"] == "HS256" == DEFAULT_ALGORITHM


def test_audience_is_verified_not_merely_returned() -> None:
    """A mismatched audience raises rather than being returned unchecked."""
    token = create_token({"sub": "alice"}, SECRET, audience="cmp-api")

    assert decode_token(token, SECRET, audience="cmp-api")["aud"] == "cmp-api"
    with pytest.raises(InvalidToken):
        decode_token(token, SECRET, audience="portfolio-api")


def test_issuer_is_verified_not_merely_returned() -> None:
    """A mismatched issuer raises rather than being returned unchecked."""
    token = create_token({"sub": "alice"}, SECRET, issuer="cmp")

    assert decode_token(token, SECRET, issuer="cmp")["iss"] == "cmp"
    with pytest.raises(InvalidToken):
        decode_token(token, SECRET, issuer="portfolio")


def test_a_token_with_no_audience_fails_an_audience_check() -> None:
    """A token with no `aud` is rejected when an audience is required."""
    token = create_token({"sub": "alice"}, SECRET)

    with pytest.raises(InvalidToken):
        decode_token(token, SECRET, audience="cmp-api")


def test_require_rejects_a_token_missing_a_claim() -> None:
    """`require` rejects a token missing one of the named claims and accepts one with them."""
    token = create_token({"sub": "alice"}, SECRET)

    with pytest.raises(InvalidToken):
        decode_token(token, SECRET, require=["exp"])

    with_exp = create_token({"sub": "alice"}, SECRET, expires_in=timedelta(minutes=5))
    assert decode_token(with_exp, SECRET, require=["sub", "exp"])["sub"] == "alice"


def test_a_python_jose_style_token_decodes() -> None:
    """A plain HS256 token built outside this module decodes, so existing sessions survive."""
    token = jwt.encode({"sub": "alice", "exp": datetime.now(UTC) + timedelta(hours=1)}, SECRET)

    assert decode_token(token, SECRET)["sub"] == "alice"


def _client(dependency: Any, **app_kwargs: Any) -> TestClient:
    """Build a client for an app with one route guarded by the given dependency."""
    app: FastAPI = create_app([], title="security-test", **app_kwargs)

    @app.get("/claims")
    async def claims_route(claims: Any = Depends(dependency)) -> dict[str, Any]:
        """Report the claims the dependency resolved."""
        return {"claims": claims}

    return TestClient(app)


def _auth(token: str) -> dict[str, str]:
    """Build a bearer Authorization header for the token."""
    return {"Authorization": f"Bearer {token}"}


def test_bearer_claims_returns_the_decoded_claims() -> None:
    """A valid bearer token resolves to its decoded claims."""
    client = _client(bearer_claims(SECRET))
    token = create_token({"sub": "alice"}, SECRET)

    response = client.get("/claims", headers=_auth(token))

    assert response.status_code == 200
    assert response.json()["claims"]["sub"] == "alice"


def test_bearer_claims_401s_without_a_header() -> None:
    """A request with no Authorization header gets a 401."""
    response = _client(bearer_claims(SECRET)).get("/claims")

    assert response.status_code == 401


def test_bearer_claims_renders_the_package_error_envelope() -> None:
    """The 401 body is the package error envelope, not a new shape."""
    response = _client(bearer_claims(SECRET)).get("/claims")
    body = response.json()

    assert body["success"] is False
    assert body["status"] == 401
    assert "request_id" in body
    assert isinstance(body["message"], str)


def test_bearer_claims_challenges_with_www_authenticate() -> None:
    """The 401 carries a `WWW-Authenticate: Bearer` challenge."""
    response = _client(bearer_claims(SECRET)).get("/claims")

    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_bearer_claims_distinguishes_expired_from_invalid() -> None:
    """An expired token reports TOKEN_EXPIRED and a garbage one INVALID_TOKEN."""
    client = _client(bearer_claims(SECRET))
    stale = datetime.now(UTC) - timedelta(hours=2)
    expired = create_token({"sub": "alice"}, SECRET, expires_in=timedelta(minutes=1), now=stale)

    expired_body = client.get("/claims", headers=_auth(expired)).json()
    invalid_body = client.get("/claims", headers=_auth("garbage")).json()

    assert expired_body["error_code"] == "TOKEN_EXPIRED"
    assert invalid_body["error_code"] == "INVALID_TOKEN"


def test_the_error_code_survives_without_error_codes_enabled() -> None:
    """The error code is carried on the raise, so it reaches the client either way."""
    client = _client(bearer_claims(SECRET), error_codes=True)
    body = client.get("/claims", headers=_auth("garbage")).json()

    assert body["error_code"] == "INVALID_TOKEN"


def test_bearer_claims_401s_for_the_wrong_secret() -> None:
    """A token signed with another secret gets a 401."""
    client = _client(bearer_claims(SECRET))
    token = create_token({"sub": "alice"}, OTHER_SECRET)

    assert client.get("/claims", headers=_auth(token)).status_code == 401


def test_bearer_claims_enforces_audience_and_issuer() -> None:
    """The dependency accepts the configured audience and issuer and rejects others."""
    client = _client(bearer_claims(SECRET, audience="cmp-api", issuer="cmp"))
    right = create_token({"sub": "alice"}, SECRET, audience="cmp-api", issuer="cmp")
    wrong = create_token({"sub": "alice"}, SECRET, audience="other", issuer="cmp")

    assert client.get("/claims", headers=_auth(right)).status_code == 200
    assert client.get("/claims", headers=_auth(wrong)).status_code == 401


def test_bearer_claims_enforces_require() -> None:
    """A token missing a required claim gets a 401."""
    client = _client(bearer_claims(SECRET, require=["sub", "exp"]))
    without_exp = create_token({"sub": "alice"}, SECRET)

    assert client.get("/claims", headers=_auth(without_exp)).status_code == 401


def test_auto_error_false_returns_none_without_a_header() -> None:
    """With `auto_error=False`, a missing header resolves to None and a 200."""
    response = _client(bearer_claims(SECRET, auto_error=False)).get("/claims")

    assert response.status_code == 200
    assert response.json()["claims"] is None


def test_auto_error_false_reads_a_bad_token_as_anonymous() -> None:
    """With `auto_error=False`, a garbage or expired token resolves to None."""
    client = _client(bearer_claims(SECRET, auto_error=False))
    stale = datetime.now(UTC) - timedelta(hours=2)
    expired = create_token({"sub": "alice"}, SECRET, expires_in=timedelta(minutes=1), now=stale)

    assert client.get("/claims", headers=_auth("garbage")).json()["claims"] is None
    assert client.get("/claims", headers=_auth(expired)).json()["claims"] is None


def test_auto_error_false_still_returns_claims_for_a_good_token() -> None:
    """With `auto_error=False`, a valid token still resolves to its claims."""
    client = _client(bearer_claims(SECRET, auto_error=False))
    token = create_token({"sub": "alice"}, SECRET)

    assert client.get("/claims", headers=_auth(token)).json()["claims"]["sub"] == "alice"
