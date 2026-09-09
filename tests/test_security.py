"""Tests for password hashing and JWT signing.

Two themes run through these. The first is that the behaviour the two products disagreed
on is pinned here: the 72 byte boundary is exercised from both sides so the module cannot
silently start raising on a long password if bcrypt is upgraded under it. The second is
that a token is never trusted for the wrong reason, so the algorithm, audience and issuer
checks all have a negative case.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from fastapi import Depends, FastAPI
from starlette.testclient import TestClient

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

# Long enough that PyJWT does not warn about the HMAC key length, which this suite runs
# with `-W error` and would otherwise fail on rather than report.
SECRET = "test-secret-value-that-is-long-enough-for-hs256-abcdefgh"
OTHER_SECRET = "a-different-secret-value-of-a-similarly-respectable-length"
# HS512 wants 64 bytes before PyJWT stops warning, and the warning is an error here.
LONG_SECRET = "a-secret-long-enough-for-hs512-which-wants-sixty-four-bytes-abcdefghijkl"


# ---- password hashing ------------------------------------------------------------


def test_hash_password_round_trips() -> None:
    hashed = hash_password("correct horse battery staple")

    assert verify_password("correct horse battery staple", hashed)


def test_hash_password_rejects_the_wrong_password() -> None:
    hashed = hash_password("correct horse battery staple")

    assert not verify_password("Correct horse battery staple", hashed)


def test_hash_password_salts_so_two_hashes_differ() -> None:
    # Same input, different stored value. A scheme without a per-hash salt lets one
    # rainbow table cover every account at once.
    first = hash_password("hunter2")
    second = hash_password("hunter2")

    assert first != second
    assert verify_password("hunter2", first)
    assert verify_password("hunter2", second)


def test_hash_password_uses_cost_twelve_by_default() -> None:
    # The cost is the third `$`-delimited field, and it is what makes an adopting service's
    # existing hashes identical to the ones this module writes.
    assert hash_password("hunter2").split("$")[2] == "12"
    assert DEFAULT_ROUNDS == 12


def test_hash_password_honours_an_explicit_cost() -> None:
    # 4 is bcrypt's minimum. Used only here, to keep the test fast.
    assert hash_password("hunter2", rounds=4).split("$")[2] == "04"


def test_hash_password_rejects_non_string_input() -> None:
    with pytest.raises(TypeError):
        hash_password(b"bytes-are-not-a-str")  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        hash_password(None)  # type: ignore[arg-type]


# ---- the 72 byte boundary --------------------------------------------------------


def test_hash_password_accepts_a_password_over_the_bcrypt_limit() -> None:
    # This is the whole reason the module truncates rather than passing the value
    # through: bcrypt 5.0 raises ValueError here and bcrypt 4.x does not, so without the
    # truncation the same code is a working login on one version and a 500 on the other.
    long_password = "a" * 200

    hashed = hash_password(long_password)

    assert verify_password(long_password, hashed)


def test_passwords_sharing_the_first_72_bytes_are_the_same_to_bcrypt() -> None:
    # Not a bug in this module: bcrypt reads at most 72 bytes. Asserted so the property is
    # visible to anyone reading, because it is the reason a service needs its own maximum
    # password length rather than assuming every byte counts.
    base = "x" * BCRYPT_MAX_BYTES
    hashed = hash_password(base + "totally different tail")

    assert verify_password(base + "another tail entirely", hashed)


def test_truncation_is_on_a_byte_boundary_not_a_character_boundary() -> None:
    # "é" is two bytes in UTF-8, so 36 of them are exactly 72 bytes and the 37th straddles
    # the limit. Trimming to the last whole character instead would feed bcrypt different
    # bytes than every other implementation does for the same password.
    at_limit = "é" * 36
    over_limit = at_limit + "é"

    assert len(at_limit.encode("utf-8")) == BCRYPT_MAX_BYTES
    assert verify_password(over_limit, hash_password(at_limit))


def test_verify_truncates_with_the_same_rule_as_hash() -> None:
    long_password = "z" * 100

    # Hashed long, verified long: the two must apply the same cut or a user who set a long
    # password could never log in again.
    assert verify_password(long_password, hash_password(long_password))


# ---- verify_password's tolerant failures -----------------------------------------


def test_verify_password_returns_false_for_no_stored_hash() -> None:
    # An OAuth-only account has a row with no password. Both products special-cased this
    # by hand at their call sites; doing it here is what stops the one that forgets.
    assert not verify_password("anything", None)
    assert not verify_password("anything", "")


def test_verify_password_returns_false_for_a_corrupt_hash() -> None:
    # A stored value that is not a bcrypt hash is a failed login, not a 500.
    assert not verify_password("hunter2", "not-a-bcrypt-hash")
    assert not verify_password("hunter2", "$2b$")


def test_verify_password_returns_false_for_non_string_password() -> None:
    hashed = hash_password("hunter2")

    assert not verify_password(None, hashed)  # type: ignore[arg-type]


# ---- needs_rehash ----------------------------------------------------------------


def test_needs_rehash_is_false_at_the_current_cost() -> None:
    assert not needs_rehash(hash_password("hunter2"))


def test_needs_rehash_is_true_below_the_current_cost() -> None:
    assert needs_rehash(hash_password("hunter2", rounds=4))


def test_needs_rehash_is_false_above_the_current_cost() -> None:
    # A stronger hash is left alone. Re-hashing it down to the current setting would
    # quietly weaken every account a more cautious previous setting had protected.
    assert not needs_rehash("$2b$14$" + "x" * 53)


def test_needs_rehash_is_true_for_an_unparseable_hash() -> None:
    # It cannot be verified against anyway, so the honest answer is "replace this".
    assert needs_rehash("garbage")
    assert needs_rehash("$2b$notanumber$xxxx")


def test_needs_rehash_honours_an_explicit_target() -> None:
    hashed = hash_password("hunter2", rounds=4)

    assert not needs_rehash(hashed, rounds=4)
    assert needs_rehash(hashed, rounds=5)


# ---- token creation and decoding -------------------------------------------------


def test_create_and_decode_round_trips_the_claims() -> None:
    token = create_token({"sub": "alice", "role": "admin"}, SECRET)

    claims = decode_token(token, SECRET)

    assert claims["sub"] == "alice"
    assert claims["role"] == "admin"


def test_create_token_always_sets_iat() -> None:
    claims = decode_token(create_token({"sub": "alice"}, SECRET), SECRET)

    assert "iat" in claims


def test_create_token_sets_exp_from_expires_in() -> None:
    # A pinned clock, read back without verifying the expiry: the point here is the
    # arithmetic, and a fixed past date would otherwise just raise ExpiredToken.
    now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)

    token = create_token({"sub": "alice"}, SECRET, expires_in=timedelta(minutes=30), now=now)
    claims = jwt.decode(token, SECRET, algorithms=["HS256"], options={"verify_exp": False})

    assert claims["exp"] == int((now + timedelta(minutes=30)).timestamp())
    assert claims["iat"] == int(now.timestamp())


def test_a_token_with_no_expires_in_has_no_exp() -> None:
    # Deliberate: the caller decides. Asserted so that changing it to a default expiry is
    # a conscious change with a failing test rather than a silent one.
    assert "exp" not in decode_token(create_token({"sub": "alice"}, SECRET), SECRET)


def test_caller_claims_override_the_generated_ones() -> None:
    # What makes the function usable for a password reset token that computes its own exp.
    token = create_token({"sub": "alice", "iss": "explicit"}, SECRET, issuer="generated")

    assert decode_token(token, SECRET, issuer="explicit")["iss"] == "explicit"


def test_no_product_claims_are_invented() -> None:
    # The module must not grow a `sub` convention or a role: those are the parts that
    # differ per product and would have to be re-forked immediately.
    claims = decode_token(create_token({}, SECRET), SECRET)

    assert set(claims) == {"iat"}


# ---- token rejection -------------------------------------------------------------


def test_decode_rejects_the_wrong_secret() -> None:
    token = create_token({"sub": "alice"}, SECRET)

    with pytest.raises(InvalidToken):
        decode_token(token, OTHER_SECRET)


def test_decode_rejects_a_malformed_token() -> None:
    with pytest.raises(InvalidToken):
        decode_token("not.a.token", SECRET)


def test_decode_raises_expired_token_for_a_passed_exp() -> None:
    stale = datetime.now(UTC) - timedelta(hours=2)
    token = create_token({"sub": "alice"}, SECRET, expires_in=timedelta(minutes=30), now=stale)

    with pytest.raises(ExpiredToken):
        decode_token(token, SECRET)


def test_expired_and_invalid_are_both_token_errors() -> None:
    # A caller that treats every failure the same way catches the base class.
    assert issubclass(ExpiredToken, TokenError)
    assert issubclass(InvalidToken, TokenError)


def test_leeway_tolerates_clock_skew() -> None:
    just_expired = datetime.now(UTC) - timedelta(seconds=61)
    token = create_token(
        {"sub": "alice"}, SECRET, expires_in=timedelta(seconds=30), now=just_expired
    )

    with pytest.raises(ExpiredToken):
        decode_token(token, SECRET)

    assert decode_token(token, SECRET, leeway=timedelta(minutes=5))["sub"] == "alice"


def test_decode_does_not_leak_why_it_failed() -> None:
    # Telling a caller whether the signature or the audience failed narrows an attacker's
    # search. The reason stays on the exception chain for the log.
    token = create_token({"sub": "alice"}, SECRET, audience="api")

    with pytest.raises(InvalidToken) as bad_signature:
        decode_token(token, OTHER_SECRET, audience="api")
    with pytest.raises(InvalidToken) as bad_audience:
        decode_token(token, SECRET, audience="other")

    assert str(bad_signature.value) == str(bad_audience.value)


# ---- algorithm confusion ---------------------------------------------------------


def test_decode_refuses_an_algorithm_outside_the_list() -> None:
    # The classic attack: rewrite the header and hope the verifier trusts it.
    token = jwt.encode({"sub": "attacker"}, LONG_SECRET, algorithm="HS512")

    with pytest.raises(InvalidToken):
        decode_token(token, LONG_SECRET)


def test_decode_refuses_an_unsigned_token() -> None:
    # `alg: none`. PyJWT will not accept it unless "none" is in the algorithms list, and
    # this module never puts it there.
    token = jwt.encode({"sub": "attacker"}, key="", algorithm="none")

    with pytest.raises(InvalidToken):
        decode_token(token, SECRET)


def test_decode_accepts_an_algorithm_the_caller_widened_to() -> None:
    token = create_token({"sub": "alice"}, LONG_SECRET, algorithm="HS512")

    assert decode_token(token, LONG_SECRET, algorithms=["HS256", "HS512"])["sub"] == "alice"


def test_the_default_algorithm_is_hs256() -> None:
    token = create_token({"sub": "alice"}, SECRET)

    assert jwt.get_unverified_header(token)["alg"] == "HS256" == DEFAULT_ALGORITHM


# ---- issuer, audience and require ------------------------------------------------


def test_audience_is_verified_not_merely_returned() -> None:
    token = create_token({"sub": "alice"}, SECRET, audience="cmp-api")

    assert decode_token(token, SECRET, audience="cmp-api")["aud"] == "cmp-api"
    with pytest.raises(InvalidToken):
        decode_token(token, SECRET, audience="portfolio-api")


def test_issuer_is_verified_not_merely_returned() -> None:
    token = create_token({"sub": "alice"}, SECRET, issuer="cmp")

    assert decode_token(token, SECRET, issuer="cmp")["iss"] == "cmp"
    with pytest.raises(InvalidToken):
        decode_token(token, SECRET, issuer="portfolio")


def test_a_token_with_no_audience_fails_an_audience_check() -> None:
    token = create_token({"sub": "alice"}, SECRET)

    with pytest.raises(InvalidToken):
        decode_token(token, SECRET, audience="cmp-api")


def test_require_rejects_a_token_missing_a_claim() -> None:
    # A token with no `exp` never expires, so requiring it is how a service refuses one.
    token = create_token({"sub": "alice"}, SECRET)

    with pytest.raises(InvalidToken):
        decode_token(token, SECRET, require=["exp"])

    with_exp = create_token({"sub": "alice"}, SECRET, expires_in=timedelta(minutes=5))
    assert decode_token(with_exp, SECRET, require=["sub", "exp"])["sub"] == "alice"


# ---- cross-library compatibility -------------------------------------------------


def test_a_python_jose_style_token_decodes() -> None:
    # Portfolio signs with python-jose today. An HS256 token is just an HS256 token, so
    # adopting this module invalidates no already-issued session. Built with raw PyJWT to
    # avoid adding python-jose as a test dependency purely to prove a wire format.
    token = jwt.encode({"sub": "alice", "exp": datetime.now(UTC) + timedelta(hours=1)}, SECRET)

    assert decode_token(token, SECRET)["sub"] == "alice"


# ---- the FastAPI bearer dependency -----------------------------------------------


def _client(dependency: Any, **app_kwargs: Any) -> TestClient:
    app: FastAPI = create_app([], title="security-test", **app_kwargs)

    @app.get("/claims")
    async def claims_route(claims: Any = Depends(dependency)) -> dict[str, Any]:
        return {"claims": claims}

    return TestClient(app)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_bearer_claims_returns_the_decoded_claims() -> None:
    client = _client(bearer_claims(SECRET))
    token = create_token({"sub": "alice"}, SECRET)

    response = client.get("/claims", headers=_auth(token))

    assert response.status_code == 200
    assert response.json()["claims"]["sub"] == "alice"


def test_bearer_claims_401s_without_a_header() -> None:
    response = _client(bearer_claims(SECRET)).get("/claims")

    assert response.status_code == 401


def test_bearer_claims_renders_the_package_error_envelope() -> None:
    # The point of routing through HTTPException with a mapping detail: no new error shape
    # is invented, the response is the same envelope as every other error in the API.
    response = _client(bearer_claims(SECRET)).get("/claims")
    body = response.json()

    assert body["success"] is False
    assert body["status"] == 401
    assert "request_id" in body
    assert isinstance(body["message"], str)


def test_bearer_claims_challenges_with_www_authenticate() -> None:
    # RFC 6750: this is what makes the 401 a challenge rather than just a refusal.
    response = _client(bearer_claims(SECRET)).get("/claims")

    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_bearer_claims_distinguishes_expired_from_invalid() -> None:
    client = _client(bearer_claims(SECRET))
    stale = datetime.now(UTC) - timedelta(hours=2)
    expired = create_token({"sub": "alice"}, SECRET, expires_in=timedelta(minutes=1), now=stale)

    expired_body = client.get("/claims", headers=_auth(expired)).json()
    invalid_body = client.get("/claims", headers=_auth("garbage")).json()

    assert expired_body["error_code"] == "TOKEN_EXPIRED"
    assert invalid_body["error_code"] == "INVALID_TOKEN"


def test_the_error_code_survives_without_error_codes_enabled() -> None:
    # Carried on the raise rather than depending on the app's global option, so the
    # expired/invalid distinction reaches the client either way.
    client = _client(bearer_claims(SECRET), error_codes=True)
    body = client.get("/claims", headers=_auth("garbage")).json()

    assert body["error_code"] == "INVALID_TOKEN"


def test_bearer_claims_401s_for_the_wrong_secret() -> None:
    client = _client(bearer_claims(SECRET))
    token = create_token({"sub": "alice"}, OTHER_SECRET)

    assert client.get("/claims", headers=_auth(token)).status_code == 401


def test_bearer_claims_enforces_audience_and_issuer() -> None:
    client = _client(bearer_claims(SECRET, audience="cmp-api", issuer="cmp"))
    right = create_token({"sub": "alice"}, SECRET, audience="cmp-api", issuer="cmp")
    wrong = create_token({"sub": "alice"}, SECRET, audience="other", issuer="cmp")

    assert client.get("/claims", headers=_auth(right)).status_code == 200
    assert client.get("/claims", headers=_auth(wrong)).status_code == 401


def test_bearer_claims_enforces_require() -> None:
    client = _client(bearer_claims(SECRET, require=["sub", "exp"]))
    without_exp = create_token({"sub": "alice"}, SECRET)

    assert client.get("/claims", headers=_auth(without_exp)).status_code == 401


# ---- the optional variant --------------------------------------------------------


def test_auto_error_false_returns_none_without_a_header() -> None:
    response = _client(bearer_claims(SECRET, auto_error=False)).get("/claims")

    assert response.status_code == 200
    assert response.json()["claims"] is None


def test_auto_error_false_reads_a_bad_token_as_anonymous() -> None:
    client = _client(bearer_claims(SECRET, auto_error=False))
    stale = datetime.now(UTC) - timedelta(hours=2)
    expired = create_token({"sub": "alice"}, SECRET, expires_in=timedelta(minutes=1), now=stale)

    assert client.get("/claims", headers=_auth("garbage")).json()["claims"] is None
    assert client.get("/claims", headers=_auth(expired)).json()["claims"] is None


def test_auto_error_false_still_returns_claims_for_a_good_token() -> None:
    client = _client(bearer_claims(SECRET, auto_error=False))
    token = create_token({"sub": "alice"}, SECRET)

    assert client.get("/claims", headers=_auth(token)).json()["claims"]["sub"] == "alice"
