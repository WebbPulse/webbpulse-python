# Passwords and JWTs

`webbpulse.security`: bcrypt hashing and JWT signing, with no product policy. For the full
app-managed identity system see [identity.md](identity.md) and the
[identity standard](identity-standard.md). Back to the [README](../README.md).

## `webbpulse.security`

bcrypt password hashing and JWT signing, with nothing product specific in either half.
Needs the `security` extra.

```python
from datetime import timedelta
from webbpulse.security import (
    create_token,
    decode_token,
    hash_password,
    needs_rehash,
    verify_password,
)

hashed = hash_password(password)

if verify_password(password, user.hashed_password):
    if needs_rehash(user.hashed_password):
        repos.users.update(user.id, hashed_password=hash_password(password))
    token = create_token({"sub": user.username}, secret, expires_in=timedelta(minutes=30))

claims = decode_token(token, secret)  # raises ExpiredToken or InvalidToken
```

What is shared is turning a password into a hash and a claims mapping into a signed token.
What is **not** shared is what the claims mean: there is no `sub` convention here, no user
model, no database lookup and no notion of an admin. `decode_token` returns the claims and
stops. That is the part that genuinely differs between the two apps, and guessing at it
would force a fork immediately.

**Adoption changes no stored hash and invalidates no issued token.** `DEFAULT_ROUNDS` is
12, which is what both apps already write: CarModPicker passes `rounds=12` explicitly and
Portfolio takes bcrypt's default, which is also 12 on both 4.3.0 and 5.0.0.

The cost is read **when the function is called**, so a service can raise it by setting
`webbpulse.security.DEFAULT_ROUNDS` after importing the module and the next
`hash_password` picks it up. Before 0.12.1 that was a no-op: the default argument was bound
once at import and a later change was silently ignored. Passing `rounds=` explicitly
overrides both. Raising the cost needs no migration, since the cost lives in the hash
string and `needs_rehash` reports an existing hash as due on its owner's next login.

**The 72 byte cliff is the reason this is worth sharing.** bcrypt reads at most 72 bytes of
a password, and libraries disagree about what to do with more: bcrypt 4.x truncates
silently, bcrypt 5.0 raises `ValueError`. Portfolio truncates by hand and is safe on
either; CarModPicker does not and is pinned to 5.0.0, so a password over 72 bytes is
currently a 500 rather than a login. This module truncates internally, on a **byte**
boundary rather than a character boundary, so it behaves identically on 4.x and 5.x and
still agrees with every hash either app has already written.

`verify_password` returns `False` for a `None` or empty stored hash, because an OAuth-only
account genuinely has no password and asking every call site to remember that invites the
one that forgets. It is deliberately not constant time across that case; a service wanting
that should verify against a fixed dummy hash, which is a decision bound up with its own
user lookup. `needs_rehash` returns `True` only for a **lower** cost, so a hash written
under a more cautious setting is never quietly re-hashed down.

**PyJWT rather than python-jose**, because `python-jose` is effectively unmaintained and
PyJWT validates more by default. An HS256 token is interchangeable between the two, so
Portfolio switching invalidates no already-issued session. `decode_token` always passes an
explicit `algorithms` list and never reads `alg` from the token header, which is what
refuses both `alg: none` and the RS256-verified-as-an-HMAC confusion. `issuer` and
`audience`, when given, are verified rather than merely returned.

An optional FastAPI dependency returns the decoded claims, and needs the `fastapi` extra:

```python
Claims = Annotated[dict, Depends(bearer_claims(settings.secret_key))]


@router.get("/me")
async def me(claims: Claims, repos: Repos = Depends(get_repos)):
    return repos.users.get_by_username(claims["sub"])
```

It raises `HTTPException(401)` with a mapping detail, so `register_error_handlers` renders
it in the package's existing envelope rather than a new shape, with `error_code`
`TOKEN_EXPIRED` or `INVALID_TOKEN` and a `WWW-Authenticate: Bearer` challenge. With
`auto_error=False` it returns `None` instead of raising, for a route serving both anonymous
and authenticated callers.
