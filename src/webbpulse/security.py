"""Password hashing and JWT signing, with nothing product specific in either half.

Passwords are truncated to bcrypt's 72 byte limit here, so behaviour is the same on bcrypt
4.x and 5.x. Tokens are PyJWT, and the algorithm list is always passed explicitly rather
than read from the token header. What the claims mean is left to the caller.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, Final

__all__ = [
    "BCRYPT_MAX_BYTES",
    "DEFAULT_ALGORITHM",
    "DEFAULT_ROUNDS",
    "HASH_LENGTH",
    "ExpiredToken",
    "InvalidToken",
    "TokenError",
    "app_secrets",
    "apply_app_secrets",
    "bearer_claims",
    "create_token",
    "decode_token",
    "derive_key",
    "expand_key",
    "extract_key",
    "flatten_secret",
    "hash_password",
    "load_app_secrets",
    "needs_rehash",
    "reset_secret_cache",
    "verify_password",
]

BCRYPT_MAX_BYTES: Final = 72

HASH_LENGTH: Final = hashlib.sha256().digest_size
"""The output size of the hash HKDF runs over here, which bounds a derivation at 255 times it."""

DEFAULT_ROUNDS: int = 12

DEFAULT_ALGORITHM: Final = "HS256"

_secrets_log = logging.getLogger(__name__)

_SECRET_CACHE: dict[str, dict[str, str]] = {}

type Claims = dict[str, Any]


class TokenError(Exception):
    """Base class for a token that could not be trusted.

    Not an `HTTPException`, so a CLI or a queue consumer can catch a decode failure without
    depending on FastAPI.
    """


class ExpiredToken(TokenError):
    """The signature verified but the token's `exp` has passed.

    Separate from `InvalidToken` because this one should prompt a refresh, not a re-login.
    """


class InvalidToken(TokenError):
    """The token was malformed, wrongly signed, or failed an audience or issuer check.

    The specific reason stays off the message, so a service echoing it tells an attacker
    nothing about which check failed.
    """


def extract_key(master: bytes, salt: bytes = b"") -> bytes:
    """The HKDF-Extract step of RFC 5869 over SHA-256: one pseudorandom key from `master`.

    Extract is a plain HMAC with the salt as the key and the input keying material as the
    message, which concentrates whatever entropy `master` holds into a uniform
    `HASH_LENGTH` byte value. An empty salt is RFC 5869's own default and hashes as
    `HASH_LENGTH` zero bytes, which is what makes an unsalted derivation reproducible.

    Args:
        master: The input keying material. Any length, including empty.
        salt: An optional non-secret salt. Defaults to the RFC's zero-filled one.

    Returns:
        The `HASH_LENGTH` byte pseudorandom key to expand from.
    """
    return hmac.new(salt or bytes(HASH_LENGTH), master, hashlib.sha256).digest()


def expand_key(prk: bytes, info: bytes, length: int) -> bytes:
    """The HKDF-Expand step of RFC 5869 over SHA-256: `length` bytes bound to `info`.

    Separate from `extract_key` because a caller whose input is already a uniform random
    key, such as one read from a secret store, may skip extraction, and because the two
    halves are what the RFC's own test vectors exercise. `derive_key` is the pair and is
    what product code should reach for.

    Args:
        prk: The pseudorandom key, normally `extract_key`'s result.
        info: The context binding this derivation apart from any other under the same key.
        length: How many bytes to return, at most 255 times `HASH_LENGTH`.

    Returns:
        Exactly `length` bytes.

    Raises:
        ValueError: When `length` is negative or over the RFC's 255 block ceiling, which is
            the point past which the block counter wraps and the output silently repeats.
    """
    if length < 0:
        raise ValueError(f"A derived key cannot be {length} bytes long.")
    if length > 255 * HASH_LENGTH:
        raise ValueError(
            f"HKDF over SHA-256 cannot produce more than {255 * HASH_LENGTH} bytes, and {length} "
            "was asked for. Derive a shorter key, or derive several under different info."
        )
    output = bytearray()
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        output += block
        counter += 1
    return bytes(output[:length])


def derive_key(master: bytes, info: str, length: int = 32, *, salt: bytes = b"") -> bytes:
    """Derive one key from a master key and a context string, with HKDF-SHA256.

    RFC 5869 in full: extract `master` into a pseudorandom key, then expand that to
    `length` bytes bound to `info`. Two different `info` strings under one master give
    independent keys, so a product stores one secret and derives a key per purpose, and
    leaking one derived key says nothing about another or about the master.

    `info` is text because it is a context label rather than key material, and it is encoded
    as UTF-8. Version it and include everything the key is scoped to, in a fixed order, so
    two scopes can never render the same string: `"acme.webhook.v1:<webhook_id>:<salt>"`
    rather than a bare id.

    The default empty `salt` is deliberate. HKDF is defined with an optional salt and the
    derivation is reproducible without one, which is what a key that must be re-derived on
    every request needs. Pass a random `salt` and store it alongside the ciphertext only
    when every derivation is a fresh one, as sealing a secret is.

    Args:
        master: The master key. High entropy random bytes, never a password: HKDF is a
            key derivation function, not a password hash, and does no stretching.
        info: The context this key is scoped to.
        length: How many bytes to return. Defaults to 32, which is an AES-256 or an
            HMAC-SHA256 key.
        salt: An optional non-secret salt, stored with whatever the key protects.

    Returns:
        Exactly `length` bytes.

    Raises:
        ValueError: When `length` is negative or over 255 times `HASH_LENGTH`.
    """
    return expand_key(extract_key(master, salt), info.encode("utf-8"), length)


def _truncate(password: str) -> bytes:
    """Encode to UTF-8 and cut to bcrypt's 72 byte limit.

    On a byte boundary, not a character boundary, because the bytes are what has to match
    an existing hash.
    """
    return password.encode("utf-8")[:BCRYPT_MAX_BYTES]


def hash_password(password: str, *, rounds: int | None = None) -> str:
    """Hash a password with bcrypt, returning the encoded hash as a string.

    The string carries the algorithm, cost and salt, so nothing else need be stored.
    `rounds` defaults to `DEFAULT_ROUNDS` read at call time, so rebinding that module
    attribute takes effect. Raises `TypeError` when `password` is not a string.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    import bcrypt

    cost = DEFAULT_ROUNDS if rounds is None else rounds
    return bcrypt.hashpw(_truncate(password), bcrypt.gensalt(rounds=cost)).decode("utf-8")


def verify_password(password: str, hashed: str | None) -> bool:
    """Check a password against a stored hash. Never raises on bad input, returns `False`.

    A `None` or malformed `hashed` is `False` rather than an exception. This is not
    constant time across the no-hash case, which returns without running bcrypt at all.
    """
    if not hashed or not isinstance(password, str):
        return False
    import bcrypt

    try:
        return bcrypt.checkpw(_truncate(password), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def needs_rehash(hashed: str, *, rounds: int | None = None) -> bool:
    """Whether a stored hash was produced at a lower cost than `rounds`.

    Call it after a successful `verify_password`, the only moment the plaintext is
    available. `rounds` defaults to `DEFAULT_ROUNDS` read at call time, like
    `hash_password`. A higher cost is left alone; an unparseable hash returns `True`.
    """
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
    """Sign `claims` into a JWT, adding only the registered claims it was asked for.

    `iat` is always set; `expires_in`, `issuer` and `audience` set `exp`, `iss` and `aud`.
    A claim passed in `claims` wins over the generated one, and `now` pins the clock.
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

    Raises `ExpiredToken` for a passed `exp` and `InvalidToken` for everything else.
    `algorithms` defaults to `[DEFAULT_ALGORITHM]` and is always passed explicitly, so the
    token's own `alg` header never decides how it is verified.
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

    It verifies the `Authorization` header and hands back the claims; looking up a user is
    the service's job. Failure raises a 401 carrying `TOKEN_EXPIRED` or `INVALID_TOKEN` and
    a `WWW-Authenticate` challenge, unless `auto_error` is off, when it returns `None`.
    """
    from fastapi import Depends, HTTPException
    from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

    scheme = HTTPBearer(auto_error=False)

    def _unauthorised(message: str, code: str) -> HTTPException:
        """Build the 401 for one failure, carrying its error code and the Bearer challenge."""
        return HTTPException(
            status_code=401,
            detail={"message": message, "error_code": code},
            headers={"WWW-Authenticate": "Bearer"},
        )

    async def dependency(
        credentials: HTTPAuthorizationCredentials | None = Depends(scheme),
    ) -> Claims | None:
        """Decode the bearer token, or refuse the request when `auto_error` is set."""
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


def flatten_secret(payload: Mapping[str, Any]) -> dict[str, str]:
    """Flatten a parsed JSON secret to the string map settings and the environment want.

    A non-string value is JSON encoded rather than stringified, so a list or an object
    survives a round trip through an environment variable. A `null` is dropped, which is
    how a secret says a key is absent without removing it from the document.
    """
    return {
        name: value if isinstance(value, str) else json.dumps(value)
        for name, value in payload.items()
        if value is not None
    }


def app_secrets(
    secret_arn: str | None = None,
    *,
    client: Any = None,
    region_name: str | None = None,
) -> dict[str, str]:
    """The service's one JSON secret as a flat map of strings, cached per ARN.

    Nothing runs at import and nothing is fetched until a caller asks, so a function that
    touches no secret needs no `secretsmanager:GetSecretValue` grant. No value is ever
    logged; the key names are, since knowing which keys arrived is what makes a missing one
    diagnosable.

    Args:
        secret_arn: The secret to read, defaulting to the `APP_SECRETS_ARN` environment
            variable. An empty ARN returns `{}`, which is the normal local and test path
            rather than an error.
        client: A Secrets Manager client to read through, for tests. A supplied client
            bypasses the shared cache in `webbpulse.config` entirely, so an injected stub
            cannot leak into a later real call.
        region_name: Region for the shared client. Ignored when `client` is given.

    Raises:
        SecretNotJsonObjectError: When the secret holds binary data, is not valid JSON, or
            parses as something other than an object.
    """
    from webbpulse.config import APP_SECRETS_ARN_ENV, load_json_secret, read_json_secret

    arn = secret_arn if secret_arn is not None else os.environ.get(APP_SECRETS_ARN_ENV, "")
    if not arn:
        return {}

    if client is None:
        cached = _SECRET_CACHE.get(arn)
        if cached is not None:
            return dict(cached)

    try:
        payload = read_json_secret(arn, client) if client is not None else load_json_secret(arn, region_name)
    except Exception:
        _secrets_log.exception("Failed to read application secrets from %s", arn)
        raise

    values = flatten_secret(payload)
    _secrets_log.info("Loaded %d application secrets from %s: %s", len(values), arn, ", ".join(sorted(values)))
    if client is None:
        _SECRET_CACHE[arn] = values
    return dict(values)


def load_app_secrets(
    secret_arn: str | None = None,
    *,
    client: Any = None,
    region_name: str | None = None,
    override: bool = True,
) -> dict[str, str]:
    """Read the secret and export every key into `os.environ`, returning what was applied.

    For a consumer or a script that reads its configuration straight from the environment.
    A service using `BaseServiceSettings` should prefer `apply_app_secrets`, which validates
    each value against the field that will hold it.

    `override=False` leaves an existing environment variable alone, so a value set for a
    local run wins over the deployed secret.
    """
    applied = app_secrets(secret_arn, client=client, region_name=region_name)
    for name, value in applied.items():
        if override or name not in os.environ:
            os.environ[name] = value
    return applied


def apply_app_secrets(
    settings: Any,
    secret_arn: str | None = None,
    *,
    client: Any = None,
    region_name: str | None = None,
) -> dict[str, str]:
    """Export the secret into the environment and set the matching fields on `settings`.

    A key with no field of that name on the settings model reaches the environment and
    nothing else, so a secret may carry values for other consumers. Each value that does
    match a field is validated against that field's annotation before being assigned, so a
    malformed secret fails here rather than at the first use of the value.

    Matching is case-insensitive, since pydantic-settings resolves environment variables
    that way and a secret written in either case should behave the same.
    """
    from pydantic import TypeAdapter

    applied = load_app_secrets(secret_arn, client=client, region_name=region_name)
    fields = getattr(type(settings), "model_fields", {})
    by_lower = {name.lower(): name for name in fields}
    for name, value in applied.items():
        field_name = by_lower.get(name.lower())
        if field_name is None:
            continue
        setattr(settings, field_name, TypeAdapter(fields[field_name].annotation).validate_python(value))
    return applied


def reset_secret_cache() -> None:
    """Drop the flattened secrets here and the parsed ones in `webbpulse.config`.

    Both halves: this map is derived from the shared parse, so clearing only one would
    refill it from the other's stale copy.
    """
    from webbpulse.config import reset_secret_cache as reset_shared

    _SECRET_CACHE.clear()
    reset_shared()
