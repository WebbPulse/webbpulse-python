"""Password policy and the timing equalisation that keeps a login from leaking accounts.

Section 5.6 of `docs/identity-standard.md` specifies the policy and section 5.3 specifies
the equalisation. Both are here rather than spread across the flow, because both are
security controls whose correctness is a property of this module and not of the caller.

## The policy, and what is deliberately absent

NIST SP 800-63B shaped, which mostly means the rules it tells verifiers **not** to have:

- **Minimum 8 characters.** Counted in characters after NFKC normalisation, not in bytes,
  because a user counts what they typed.
- **No composition rules.** No required upper case, no required digit, no required symbol.
  SP 800-63B says verifiers "SHOULD NOT impose other composition rules", and the reason is
  that they push users toward `Password1!` rather than toward entropy.
- **No periodic expiry.** Rotation on evidence of compromise, never on a calendar.
- **All Unicode accepted**, spaces included, normalised to NFKC before hashing so that two
  visually identical passwords typed on different keyboards hash the same.

## Why the maximum is 72 **bytes** and not 64 characters

bcrypt reads at most 72 bytes. `webbpulse.security` truncates to exactly that in both
`hash_password` and `verify_password`, on a byte boundary, so behaviour is identical across
bcrypt 4 and 5 and every stored hash stays verifiable. Its own docstring names the
consequence: "A password long enough to be truncated shares a hash with every other password
having the same first 72 bytes; that is inherent to bcrypt and the reason a length cap
belongs in the service's own validation."

This module is that validation. A password over 72 UTF-8 bytes is **rejected**, not
truncated, and the message says bytes rather than characters, because a 64-character
password of emoji is 256 bytes and a user told "too long, maximum 64 characters" would have
no idea why theirs was refused.

The cap is below the 64 characters SP 800-63B asks verifiers to support for multi-byte
input, and that is a recorded trade rather than an oversight. Accepting longer would mean
pre-hashing with SHA-256 before bcrypt, which changes the stored format and invalidates
every hash in both products. Section 5.6 and open question 6 both record it.

## The dummy hash, and what it is actually for

`verify_password` returns `False` immediately when there is no stored hash, and its docstring
says plainly that this "is not constant time across the no-hash case" and that fixing it is
the caller's job. This module is the caller that fixes it.

`equalise_password_timing` runs one bcrypt verification against a fixed hash generated at
import and throws the result away. The login flow calls it on **every** path that does not
run a real verification: no such user, a user with no password credential, a user whose
credential is a placeholder. Every login then costs one bcrypt verification regardless of
whether the address exists, which is what makes the timing shape of "no such user" and
"wrong password" the same.

The dummy hash is generated once at import from a random password nobody holds, at the same
cost as a real one. Generating it per call would double the work and make the equalisation
itself slower than the path it is equalising, which is the failure mode of a naive fix.

`password_breach_check` is a **flag only** in this milestone. Section 5.2 records the
2026-09-09 decision: off by default, not adopted, and a product opts in. `check_password`
raises when it is on rather than silently ignoring it, because a product that switched the
flag on and got no check would believe it had a control it does not have.
"""

from __future__ import annotations

import secrets
import unicodedata
from typing import Final

__all__ = [
    "MAX_PASSWORD_BYTES",
    "MIN_PASSWORD_CHARACTERS",
    "PasswordRejected",
    "check_password",
    "equalise_password_timing",
    "normalise_password",
]

#: SP 800-63B's floor. Eight characters, counted after NFKC normalisation.
MIN_PASSWORD_CHARACTERS: Final = 8

#: bcrypt's ceiling, in bytes. Matches `webbpulse.security.BCRYPT_MAX_BYTES`, and the two
#: must agree: this module rejects what that module would silently truncate.
MAX_PASSWORD_BYTES: Final = 72


class PasswordRejected(ValueError):
    """A password failed the policy in section 5.6.

    Carries a `message` the flow shows the user and an `error_code` the frontend branches
    on, matching `AuthenticationRefused`'s shape so a router renders both the same way.

    Unlike a login failure, this one is safe to be specific about: it describes the password
    the caller just supplied and says nothing about any account, so there is nothing here to
    enumerate with.
    """

    def __init__(self, message: str, *, error_code: str = "PASSWORD_REJECTED") -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code


def normalise_password(password: str) -> str:
    """NFKC, and nothing else.

    Not stripped: a leading or trailing space is a legitimate part of a password and
    stripping it silently changes what the user chose. Not case-folded, for the obvious
    reason. NFKC alone, so the same password typed on a keyboard that emits a composed
    character and one that emits a combining sequence hashes identically.

    Applied before both hashing and verification, or a password that verified yesterday
    stops verifying the day normalisation is introduced.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    return unicodedata.normalize("NFKC", password)


def check_password(password: str, *, breach_check: bool = False) -> str:
    """Apply the policy and return the normalised password ready to hash.

    Returns the NFKC form rather than `None`, so a caller cannot normalise for the check and
    then hash the original. The one value that leaves here is the one that goes to bcrypt.

    Raises `PasswordRejected` for a password that is too short or over 72 UTF-8 bytes.

    `breach_check` is section 5.2's `password_breach_check` flag. It is **not implemented**
    in this milestone, per the 2026-09-09 decision that no product adopts it, and passing
    `True` raises `NotImplementedError` rather than quietly doing nothing. A product that
    turned the flag on and received no check would believe it had a control it does not.
    """
    if breach_check:
        raise NotImplementedError(
            "password_breach_check is a flag only. Section 5.2 records the 2026-09-09 "
            "decision that the breach corpus check is off by default and not adopted, and "
            "no milestone through M2 implements it. Raising rather than ignoring the flag, "
            "so a product cannot believe it has a control it does not have."
        )

    normalised = normalise_password(password)

    if len(normalised) < MIN_PASSWORD_CHARACTERS:
        raise PasswordRejected(
            f"Password must be at least {MIN_PASSWORD_CHARACTERS} characters.",
            error_code="PASSWORD_TOO_SHORT",
        )

    encoded = len(normalised.encode("utf-8"))
    if encoded > MAX_PASSWORD_BYTES:
        # Bytes, not characters, and the message says so. bcrypt reads 72 bytes and
        # `webbpulse.security` truncates to exactly that, so anything longer would share a
        # hash with every password having the same first 72 bytes. Rejecting is honest;
        # truncating silently accepts a password whose tail does nothing.
        raise PasswordRejected(
            f"Password must be at most {MAX_PASSWORD_BYTES} bytes when encoded as UTF-8, "
            f"and this one is {encoded}. Accented characters and emoji cost more than one "
            "byte each, so a password can be short and still be too long.",
            error_code="PASSWORD_TOO_LONG",
        )

    return normalised


#: A bcrypt hash of a random password nobody holds, generated once at import.
#:
#: Deliberately module state rather than a per-call value. The whole point is to spend the
#: same time a real verification spends, and generating a fresh hash per call would spend
#: roughly twice that, making the equalising path measurably *slower* than the path it
#: equalises and reintroducing the oracle with the sign flipped.
#:
#: Built lazily on first use rather than at import: hashing at import cost is paid by every
#: process that imports the module, including one that only serves a JWKS, and a Lambda cold
#: start is the worst place to spend a bcrypt round.
_DUMMY_HASH: str | None = None


def _dummy_hash() -> str:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        from webbpulse.security import hash_password

        _DUMMY_HASH = hash_password(secrets.token_urlsafe(32))
    return _DUMMY_HASH


def equalise_password_timing(password: str = "") -> None:
    """Spend one bcrypt verification and discard the result.

    Called on every login path that does **not** run a real verification: no such user, a
    user with no password credential, a user whose stored secret will not parse. Both paths
    then cost one bcrypt round, which is what makes "no such user" and "wrong password"
    indistinguishable by timing as well as by response body.

    `password` defaults to an empty string because the value is irrelevant: the verification
    is guaranteed to fail and its result is thrown away. It is a parameter anyway so that
    the caller passes the real one, which keeps the work faithful to a genuine verification
    including its length-dependent encoding, rather than always hashing zero bytes.

    Never raises. A failure here must not turn a login into a 500, and it has no result
    anybody reads.
    """
    from webbpulse.security import verify_password

    try:
        verify_password(password, _dummy_hash())
    except Exception:  # pragma: no cover - defensive, verify_password does not raise
        # `verify_password` documents that it never raises on bad input. This is here so
        # that a future change to it cannot turn the equalisation into a login outage.
        return
