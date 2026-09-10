"""Password hashing and JWT signing, with nothing product specific in either half.

Both backends grew their own copy of this file, and the copies had drifted in the two
places that are expensive to get wrong: how a password longer than bcrypt's 72 byte limit
is treated, and which JWT library validates the token. This module is one implementation
of each, with every product decision (the claim names, the user lookup, the expiry) left
to the caller.

## What is shared and what is not

Shared: turning a password into a hash and checking one, and turning a claims mapping into
a signed token and back. Those are the same operations in every service.

Not shared: what the claims mean. There is no `sub` convention here, no user model, no
database lookup, and no notion of an admin. `decode_token` returns the claims mapping and
stops. A service maps that onto its own user however it already does, which is the part
that genuinely differs between the two apps and would have to be re-forked immediately if
this module guessed at it.

## bcrypt, and the 72 byte cliff

bcrypt hashes at most 72 bytes of a password and ignores the rest. That is a property of
the algorithm, not of any library. What differs is what the library does when handed more:

- bcrypt 4.x silently truncates and returns a hash.
- bcrypt 5.0 raises `ValueError("password cannot be longer than 72 bytes, truncate
  manually if necessary")`.

So the same code, on the same input, is a working login on one version and a 500 on the
other. This module removes the version from the question: `hash_password` and
`verify_password` truncate to 72 **bytes** themselves, before bcrypt sees the value, and
therefore behave identically on 4.x and 5.x.

Truncation is on a byte boundary and deliberately not on a character boundary. bcrypt's
limit is a byte limit, and a UTF-8 encoded password can split a multi-byte character at
byte 72. Re-decoding to trim to the last whole character would change the bytes fed to
bcrypt, which would not match a hash that any existing implementation produced for the
same password. The bytes are what must match, so the bytes are what is truncated.

`verify_password` truncates with exactly the same rule as `hash_password`, so a password
that was hashed at its truncated length still verifies. A password long enough to be
truncated shares a hash with every other password having the same first 72 bytes; that is
inherent to bcrypt and the reason a length cap belongs in the service's own validation.

## Cost

`DEFAULT_ROUNDS` is 12, which is what both services already produce: CarModPicker passes
`rounds=12` explicitly and Portfolio takes bcrypt's default, which is also 12 on both
4.3.0 and 5.0.0. Hashes are therefore identical in cost and mutually verifiable, and
adopting this module re-verifies every stored hash unchanged. Nothing here needs a
migration.

The cost is resolved **when the function is called**, not when this module is imported.
`hash_password` and `needs_rehash` take `rounds: int | None = None` and read
`DEFAULT_ROUNDS` in the body, so setting `webbpulse.security.DEFAULT_ROUNDS` after import
changes what the next call writes. The obvious spelling, `rounds: int = DEFAULT_ROUNDS`,
does not behave that way: a default argument is evaluated once as the `def` executes, so it
froze 12 into the function object and a consumer configuring the cost afterwards, or a test
monkeypatching it to bcrypt's minimum to stay fast, was ignored without any error. Passing
`rounds=` explicitly still wins over both.

## PyJWT, not python-jose

The two services disagree, so one of them has to move. This module uses PyJWT because
`python-jose` has been effectively unmaintained, and because PyJWT validates more by
default: `decode` verifies `exp` and, when an audience or issuer is supplied, verifies
those too, and it will not accept a token whose `alg` is outside the list it was given.

The migration is cheap in the direction that matters. A token is a token: an HS256 token
signed by `python-jose` decodes under PyJWT and the reverse also holds, with the same
secret. So a service can switch libraries without invalidating a single already-issued
session, and this module can sit behind both.

## The algorithm is never taken from the token

`decode_token` passes an explicit algorithm list to PyJWT and never reads `alg` from the
token header to decide how to verify it. That is the `alg: none` / algorithm confusion
class of attack: an attacker rewrites the header, and a verifier that trusts it either
skips verification entirely or verifies an RS256 public key as an HMAC secret. PyJWT
requires the `algorithms` argument for this reason, and this module always passes it.
`DEFAULT_ALGORITHM` is HS256, which is what both services sign with today.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, Final

__all__ = [
    "BCRYPT_MAX_BYTES",
    "DEFAULT_ALGORITHM",
    "DEFAULT_ROUNDS",
    "ExpiredToken",
    "InvalidToken",
    "TokenError",
    "bearer_claims",
    "create_token",
    "decode_token",
    "hash_password",
    "needs_rehash",
    "verify_password",
]

#: The most bytes bcrypt reads from a password. Anything past this is ignored by the
#: algorithm itself, so it is truncated here rather than left for the library to either
#: drop silently (bcrypt 4.x) or reject (bcrypt 5.x).
BCRYPT_MAX_BYTES: Final = 72

#: bcrypt cost. 12 is what both services already write, so adopting this module leaves
#: every stored hash verifying unchanged.
#:
#: Deliberately **not** `Final`. `hash_password` and `needs_rehash` read this at call time
#: rather than binding it as a default argument, so a service that sets
#: `webbpulse.security.DEFAULT_ROUNDS` after import, and a test that monkeypatches it, both
#: take effect. Annotating it `Final` would tell mypy that rebinding is an error and take
#: that away again.
DEFAULT_ROUNDS: int = 12

#: Signing algorithm. HS256 is what both services sign with today. It is passed explicitly
#: to every decode; the token's own `alg` header is never trusted.
DEFAULT_ALGORITHM: Final = "HS256"

#: What a decoded token's claims look like. Values are whatever JSON carried.
type Claims = dict[str, Any]


class TokenError(Exception):
    """Base class for a token that could not be trusted.

    Callers that treat every failure the same way catch this. It is deliberately not an
    `HTTPException`: this module has no opinion about status codes, and a service that
    decodes a token outside a request (a CLI, a queue consumer) should not have to depend
    on FastAPI to catch a decode failure.
    """


class ExpiredToken(TokenError):
    """The signature verified but the token's `exp` has passed.

    Separate from `InvalidToken` because the two mean genuinely different things to a
    client: an expired token should prompt a refresh, while an invalid one should prompt a
    fresh login and is worth noticing in the logs.
    """


class InvalidToken(TokenError):
    """The token was malformed, wrongly signed, or failed an audience or issuer check.

    The reason is deliberately not in the message that a service is likely to echo. Telling
    a caller whether the signature or the audience failed narrows an attacker's search for
    a forged token, and the service's own log line already has the detail.
    """


def _truncate(password: str) -> bytes:
    """Encode to UTF-8 and cut to bcrypt's 72 byte limit.

    On a byte boundary, not a character boundary. See the module docstring: the bytes are
    what has to match an existing hash, so trimming back to the last whole character would
    make this implementation disagree with every other one.
    """
    return password.encode("utf-8")[:BCRYPT_MAX_BYTES]


def hash_password(password: str, *, rounds: int | None = None) -> str:
    """Hash a password with bcrypt, returning the encoded hash as a string.

    The returned string carries the algorithm, the cost and the salt as well as the digest,
    which is why `verify_password` needs no other stored state.

    `rounds` defaults to `DEFAULT_ROUNDS`, **read at call time**. The default is written as
    `None` rather than as `DEFAULT_ROUNDS` itself because a default argument is evaluated
    once, when the `def` executes at import, and is then frozen into the function object.
    Writing `rounds: int = DEFAULT_ROUNDS` therefore captured 12 permanently, and a service
    that lowered the cost after importing this module, or a test that monkeypatched it, was
    silently ignored while everything kept hashing at 12. Resolving the module attribute
    inside the body is what makes either of those take effect.

    Raises `TypeError` when `password` is not a string. bcrypt would otherwise accept bytes
    and produce a hash that a `str` caller could never reproduce, and `None` reaches the
    encode as a confusing `AttributeError` several frames from the mistake.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    import bcrypt

    cost = DEFAULT_ROUNDS if rounds is None else rounds
    return bcrypt.hashpw(_truncate(password), bcrypt.gensalt(rounds=cost)).decode("utf-8")


def verify_password(password: str, hashed: str | None) -> bool:
    """Check a password against a stored hash. Never raises on bad input, returns `False`.

    `hashed` accepts `None` and returns `False`, because an account that has no password
    set at all is a real state in both services: a user who signed up through OAuth has a
    row with no hash, and asking every call site to special-case that invites the one that
    forgets. A malformed or truncated hash is also `False` rather than an exception, since
    a corrupt stored value must not turn a login into a 500.

    **This is not constant time across the "no hash" case.** Returning `False` immediately
    when there is no stored hash is measurably faster than running bcrypt, which leaks
    whether an account has a password. A service that cares should verify against a fixed
    dummy hash instead of skipping the call; that decision belongs to the service, because
    it also has to decide whether an unknown username is distinguishable from a known one,
    and that question is about its user lookup rather than about this function.
    """
    if not hashed or not isinstance(password, str):
        return False
    import bcrypt

    try:
        return bcrypt.checkpw(_truncate(password), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        # bcrypt raises ValueError on a hash it cannot parse. A stored value that is not a
        # bcrypt hash is a failed verification, not a server error.
        return False


def needs_rehash(hashed: str, *, rounds: int | None = None) -> bool:
    """Whether a stored hash was produced at a lower cost than `rounds`.

    `rounds` defaults to `DEFAULT_ROUNDS` read at call time, for the same reason
    `hash_password` does: a default argument would freeze 12 into the function at import and
    quietly ignore a cost the service raised afterwards. The two have to agree, or a service
    that raised the cost would re-hash on every single login without the stored hash ever
    catching up.

    Call it after a successful `verify_password`, which is the only moment the plaintext is
    available to re-hash with::

        if verify_password(password, user.hashed_password):
            if needs_rehash(user.hashed_password):
                store(hash_password(password))

    Only a **lower** cost returns `True`. A hash written at a higher cost than the current
    setting is left alone: it is already stronger than the policy asks for, and re-hashing
    it down would quietly weaken every account that a previous, more cautious setting had
    protected.

    An unparseable hash returns `True`. It cannot be verified against anyway, so the honest
    answer is that whatever is stored should be replaced.
    """
    # A bcrypt hash is `$2<variant>$<cost>$<22 char salt><31 char digest>`, so the cost is
    # the third `$`-delimited field. Parsing that one field is enough and avoids making
    # this function import bcrypt at all.
    parts = hashed.split("$")
    if len(parts) < 4 or not parts[2].isdigit():
        return True
    target = DEFAULT_ROUNDS if rounds is None else rounds
    return int(parts[2]) < target


def create_token(
    claims: Mapping[str, Any],
    secret: str,
    *,
    expires_in: timedelta | None = None,
    algorithm: str = DEFAULT_ALGORITHM,
    issuer: str | None = None,
    audience: str | None = None,
    now: datetime | None = None,
) -> str:
    """Sign `claims` into a JWT.

    Everything the token means is the caller's: this function adds only the registered
    claims it was asked for and never invents a `sub`, a role or a scope.

    `expires_in` sets `exp` relative to now. It is optional, but omitting it mints a token
    that is valid until the secret rotates, so pass one for anything a browser holds.
    `issuer` and `audience` set `iss` and `aud`, and are worth setting when more than one
    service shares a secret: without them a token minted for one audience is accepted by
    every other, which is how a low-value token becomes a high-value one.

    `iat` is always set, so a service can reason about a token's age even when the token
    outlives its `exp` policy. A claim the caller passes explicitly wins over the generated
    one, which is what makes this usable for a password reset token that wants its own
    `exp` computed elsewhere.

    `now` exists so tests can pin the clock, and is otherwise the current UTC time.
    """
    import jwt

    issued_at = now if now is not None else datetime.now(UTC)
    payload: dict[str, Any] = {"iat": issued_at}
    if expires_in is not None:
        payload["exp"] = issued_at + expires_in
    if issuer is not None:
        payload["iss"] = issuer
    if audience is not None:
        payload["aud"] = audience
    # The caller's claims land last, so an explicit `exp` or `sub` overrides what was
    # generated above rather than being silently dropped.
    payload.update(claims)
    return jwt.encode(payload, secret, algorithm=algorithm)


def decode_token(
    token: str,
    secret: str,
    *,
    algorithms: Sequence[str] | None = None,
    issuer: str | None = None,
    audience: str | None = None,
    require: Iterable[str] | None = None,
    leeway: timedelta | float = 0,
) -> Claims:
    """Verify a JWT and return its claims.

    Raises `ExpiredToken` when `exp` has passed and `InvalidToken` for everything else: a
    bad signature, a malformed token, an `alg` outside `algorithms`, or a failed issuer,
    audience or `require` check.

    `algorithms` defaults to `[DEFAULT_ALGORITHM]` and is always passed to PyJWT
    explicitly. The token's own `alg` header never decides how it is verified, which is
    what stops both `alg: none` and the RS256-verified-as-HMAC confusion. Pass a list only
    to widen it deliberately, and keep it as narrow as the service actually signs with.

    `issuer` and `audience`, when given, are verified rather than merely returned, and a
    mismatch is an `InvalidToken`. Verifying them is the entire point of setting them, and
    a caller that reads `claims["aud"]` itself after the fact has usually already decided
    to trust the token.

    `require` names claims that must be present, for example `["sub", "exp"]`. A token with
    no `exp` at all never expires, so requiring it is how a service refuses one.

    `leeway` tolerates clock skew between the signer and this verifier.
    """
    import jwt

    try:
        return dict(
            jwt.decode(
                token,
                secret,
                algorithms=list(algorithms) if algorithms is not None else [DEFAULT_ALGORITHM],
                issuer=issuer,
                audience=audience,
                leeway=leeway,
                options={"require": list(require)} if require is not None else {},
            )
        )
    except jwt.ExpiredSignatureError as exc:
        raise ExpiredToken("The token has expired.") from exc
    except jwt.PyJWTError as exc:
        # Everything else PyJWT raises is one answer to the caller: do not trust this
        # token. The specific reason stays on the exception chain for the log, and is
        # deliberately not in the message, so a service echoing `str(exc)` cannot tell an
        # attacker whether it was the signature or the audience that failed.
        raise InvalidToken("The token is not valid.") from exc


def bearer_claims(
    secret: str,
    *,
    algorithms: Sequence[str] | None = None,
    issuer: str | None = None,
    audience: str | None = None,
    require: Iterable[str] | None = None,
    leeway: timedelta | float = 0,
    auto_error: bool = True,
) -> Any:
    """Build a FastAPI dependency that returns the decoded claims of the bearer token.

    A thin helper, on purpose. It reads the `Authorization` header, verifies the token and
    hands back the claims mapping. It does **not** look up a user, because that is the part
    that differs between every service::

        Claims = Annotated[dict, Depends(bearer_claims(settings.secret_key))]

        @router.get("/me")
        async def me(claims: Claims, repos: Repos = Depends(get_repos)):
            return repos.users.get_by_username(claims["sub"])

    On failure it raises `HTTPException(401)` with a mapping detail, which
    `webbpulse.http.register_error_handlers` renders into the package's standard envelope
    with `error_code` `TOKEN_EXPIRED` or `INVALID_TOKEN`. No new error shape is introduced
    here, and the code is carried on the raise rather than depending on the app having
    `error_codes=True`, so the distinction survives either configuration.

    `WWW-Authenticate: Bearer` is set on the 401, because that is what makes the response a
    correct challenge under RFC 6750 rather than just a refusal.

    With `auto_error=False` the dependency returns `None` instead of raising, for a route
    that serves both anonymous and authenticated callers. A malformed or expired token then
    reads as anonymous rather than as an error, which is the behaviour both services
    already implement by hand for their optional routes.
    """
    from fastapi import Depends, HTTPException
    from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

    scheme = HTTPBearer(auto_error=False)

    def _unauthorised(message: str, code: str) -> HTTPException:
        return HTTPException(
            status_code=401,
            detail={"message": message, "error_code": code},
            headers={"WWW-Authenticate": "Bearer"},
        )

    async def dependency(
        credentials: HTTPAuthorizationCredentials | None = Depends(scheme),
    ) -> Claims | None:
        if credentials is None:
            if auto_error:
                raise _unauthorised("Not authenticated.", "NOT_AUTHENTICATED")
            return None
        try:
            return decode_token(
                credentials.credentials,
                secret,
                algorithms=algorithms,
                issuer=issuer,
                audience=audience,
                require=require,
                leeway=leeway,
            )
        except ExpiredToken:
            if auto_error:
                raise _unauthorised("The token has expired.", "TOKEN_EXPIRED") from None
            return None
        except InvalidToken:
            if auto_error:
                raise _unauthorised("Could not validate credentials.", "INVALID_TOKEN") from None
            return None

    return dependency
