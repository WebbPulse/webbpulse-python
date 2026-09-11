"""RFC 6238 TOTP: seed generation, the provisioning URI, and code verification.

HMAC-SHA1, which is what every authenticator app implements and is not weakened by SHA-1's
collision results. The one step window and the strictly increasing step watermark that
refuses a replay are both part of what makes a six digit secret acceptable.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from typing import Final
from urllib.parse import quote, urlencode

__all__ = [
    "CODE_DIGITS",
    "SEED_BYTES",
    "TIME_STEP_SECONDS",
    "VERIFICATION_WINDOW",
    "current_step",
    "generate_code",
    "generate_seed",
    "normalise_code",
    "provisioning_uri",
    "verify_code",
]

SEED_BYTES: Final = 20

TIME_STEP_SECONDS: Final = 30

CODE_DIGITS: Final = 6

VERIFICATION_WINDOW: Final = 1


def generate_seed() -> str:
    """Generate a fresh base32 TOTP seed, unpadded and uppercase.

    Base32 is what the `otpauth://` URI carries; the padding is dropped because several apps
    mishandle it and it carries no information.
    """
    return base64.b32encode(secrets.token_bytes(SEED_BYTES)).decode("ascii").rstrip("=")


def _decode_seed(seed: str) -> bytes:
    """Decode base32 back to bytes, tolerating the case and padding a user might type.

    Existing padding is stripped before it is recomputed, so a seed that kept its `=` is not
    padded twice. Raises `ValueError` on anything that is not base32.
    """
    cleaned = "".join(seed.split()).upper().rstrip("=")
    padding = "=" * (-len(cleaned) % 8)
    try:
        return base64.b32decode(cleaned + padding, casefold=True)
    except Exception as exc:
        raise ValueError(f"seed is not valid base32: {exc}") from exc


def current_step(*, now: int | None = None) -> int:
    """Compute the RFC 6238 time step for a moment: Unix seconds floor-divided by the step."""
    moment = int(time.time()) if now is None else now
    return moment // TIME_STEP_SECONDS


def generate_code(seed: str, *, step: int) -> str:
    """Compute the code for one time step, zero-padded to `CODE_DIGITS`.

    RFC 4226's dynamic truncation, with the top bit masked off so the value is a positive 31
    bit integer whatever the platform does.
    """
    key = _decode_seed(seed)
    counter = struct.pack(">Q", step)
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10**CODE_DIGITS)).zfill(CODE_DIGITS)


def normalise_code(code: str) -> str:
    """Strip the spaces and hyphens an authenticator's display or a user's keyboard adds.

    Nothing else is stripped: a code with a letter in it is wrong, not dirty.
    """
    return code.strip().replace(" ", "").replace("-", "")


def verify_code(
    seed: str,
    code: str,
    *,
    last_used_step: int = 0,
    now: int | None = None,
    window: int = VERIFICATION_WINDOW,
) -> int | None:
    """Check a code and return the step it matched, or `None`.

    Returns the step rather than a boolean because the caller must store it as the new
    `last_used_step`, which is the whole of the replay defence: a step at or below it is
    refused, indistinguishably from a wrong code. Every candidate step is compared in
    constant time whether or not an earlier one matched.
    """
    presented = normalise_code(code)
    if len(presented) != CODE_DIGITS or not presented.isdigit():
        return None

    now_step = current_step(now=now)
    matched: int | None = None
    for candidate in range(now_step - window, now_step + window + 1):
        if candidate <= last_used_step:
            continue
        expected = generate_code(seed, step=candidate)
        if hmac.compare_digest(expected, presented) and matched is None:
            matched = candidate
    return matched


def provisioning_uri(
    seed: str,
    *,
    account_name: str,
    issuer: str,
) -> str:
    """Build the `otpauth://totp/...` URI an authenticator scans or accepts pasted.

    The issuer appears in both the label prefix and the parameter, as the Key URI format
    recommends, and the defaulted parameters are omitted because several apps mis-parse them.
    The query uses `quote_via=quote` so a space becomes `%20` rather than a literal `+`.
    """
    label = quote(f"{issuer}:{account_name}", safe="")
    parameters = urlencode({"secret": seed, "issuer": issuer}, quote_via=quote)
    return f"otpauth://totp/{label}?{parameters}"
