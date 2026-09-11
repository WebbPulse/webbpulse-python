"""Password policy and the timing equalisation that keeps a login from leaking accounts.

NIST SP 800-63B shaped: a minimum of 8 NFKC characters, no composition rules, no expiry,
and a hard 72 byte cap because bcrypt reads no further.
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

MIN_PASSWORD_CHARACTERS: Final = 8

MAX_PASSWORD_BYTES: Final = 72


class PasswordRejected(ValueError):
    """A password failed the policy.

    Safe to be specific about: it describes the password the caller just supplied and says
    nothing about any account, so there is nothing here to enumerate with.
    """

    def __init__(self, message: str, *, error_code: str = "PASSWORD_REJECTED") -> None:
        """Record the user-facing message and the code the frontend branches on."""
        super().__init__(message)
        self.message = message
        self.error_code = error_code


def normalise_password(password: str) -> str:
    """Apply NFKC normalisation and nothing else.

    Never stripped and never case-folded, so the user keeps exactly what they chose. Must be
    applied before both hashing and verification or stored hashes stop verifying.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    return unicodedata.normalize("NFKC", password)


def check_password(password: str, *, breach_check: bool = False) -> str:
    """Apply the policy and return the normalised password ready to hash.

    Returns the NFKC form, so the value checked is the value that goes to bcrypt. Raises
    `PasswordRejected` when too short or over 72 UTF-8 bytes, and `NotImplementedError` when
    `breach_check` is on, so a product cannot believe it has a control it does not have.
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
        raise PasswordRejected(
            f"Password must be at most {MAX_PASSWORD_BYTES} bytes when encoded as UTF-8, "
            f"and this one is {encoded}. Accented characters and emoji cost more than one "
            "byte each, so a password can be short and still be too long.",
            error_code="PASSWORD_TOO_LONG",
        )

    return normalised


_DUMMY_HASH: str | None = None


def _dummy_hash() -> str:
    """Return the shared dummy bcrypt hash, building it on first use.

    Module state, not per-call: a fresh hash each time would cost about twice a real
    verification and reintroduce the timing oracle with the sign flipped.
    """
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        from webbpulse.security import hash_password

        _DUMMY_HASH = hash_password(secrets.token_urlsafe(32))
    return _DUMMY_HASH


def equalise_password_timing(password: str = "") -> None:
    """Spend one bcrypt verification and discard the result.

    Called on every login path that does not run a real verification, so "no such user" and
    "wrong password" cost the same. Pass the real password to keep the work faithful. Never
    raises: a failure here must not turn a login into a 500.
    """
    from webbpulse.security import verify_password

    try:
        verify_password(password, _dummy_hash())
    except Exception:  # pragma: no cover
        return
