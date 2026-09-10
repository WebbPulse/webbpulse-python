"""RFC 6238 TOTP: seed generation, the provisioning URI, and code verification.

No dependency. TOTP is HMAC-SHA1 over a counter with a truncation rule, which is about
fifteen lines, and every Python library for it is those fifteen lines plus a QR encoder this
package has no use for. Writing it here keeps the `identity` extra as it is and keeps the
window and replay policy, which are the parts that are actually easy to get wrong, in the
same file as the arithmetic they govern.

## SHA-1, deliberately, and it is not a weakness here

RFC 6238 allows SHA-256 and SHA-512, and every authenticator app in practice implements
SHA-1 only. Google Authenticator ignores the `algorithm` parameter in the provisioning URI
outright, so a service that "upgrades" to SHA-256 produces codes that agree with nothing the
user's phone shows, and the failure looks like a broken seed rather than a mismatch.

The choice costs nothing. HMAC-SHA1 is not affected by SHA-1's collision weaknesses: those
are collision attacks on the hash, and HMAC's security rests on the pseudorandomness of the
compression function under a secret key, which no published result touches. There is also
nothing to collide with, since the output is truncated to six digits and the input is a
counter the attacker cannot choose.

## The window, and why it is one step and not three

`VERIFICATION_WINDOW` is 1, meaning the current step plus one either side: about ninety
seconds of tolerance for a clock that drifts and a user who types slowly.

Widening it is the tempting fix for support tickets and it is a real weakening. Each extra
step multiplies the number of codes valid at any instant, so a window of 3 makes an online
guess seven times as likely to land as one step would, against a secret with only a million
values. The rate limit, section 5.1's ten TOTP attempts per fifteen minutes, is what makes
six digits acceptable at all, and the window is the other half of that arithmetic.

One step **either side** rather than one step behind: a client whose clock is fast is exactly
as common as one whose clock is slow, and refusing the fast half produces a user whose codes
never work and whose phone shows the right number.

## Replay is refused, and the store is the reason it can be

A code is valid for a whole time step, so the same six digits work for up to thirty seconds.
An attacker who observes one, over a shoulder or through a phished form, can replay it inside
that window and the arithmetic cannot tell the difference: it is the same correct code.

The only defence is remembering. `last_used_step` on the factor record is the highest step
this user has ever successfully presented, and a verification is accepted only for a step
**strictly greater** than it. So a code is usable once per user, ever, and a replay of the
one just used is refused even one second later.

That also refuses a *legitimate* second login inside the same thirty seconds, which is the
right trade: the user waits for the next code, and the alternative is that a captured code
stays live for the rest of its step. It is stored on the factor rather than in a separate
table because it is one number that changes on exactly the write that verification already
makes.

## Constant time, even here

`hmac.compare_digest` on the code comparison, per section 5.3. A six digit code is small
enough that a timing oracle on the comparison is not the weakest link, and comparing it in
constant time costs one function call, so there is no argument for the `==` that would
otherwise be an exception to a rule the rest of the package holds without exception.
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

#: Bytes of seed entropy. 20 is RFC 4226's recommendation and the HMAC-SHA1 block-relevant
#: size; it base32-encodes to 32 characters, which is what every authenticator expects when
#: a user types a seed in by hand rather than scanning.
SEED_BYTES: Final = 20

#: Seconds per time step. 30 is RFC 6238's default and is what every authenticator assumes.
#: It is not configurable: an app that reads the `period` parameter is the exception, so a
#: different value produces codes the user's phone disagrees with.
TIME_STEP_SECONDS: Final = 30

#: Digits in a code. Six, universally.
CODE_DIGITS: Final = 6

#: Steps of tolerance either side of the current one. See the module docstring: this is one
#: half of the arithmetic that makes a six digit secret acceptable, and the rate limit is
#: the other. Raising it to quiet a support ticket weakens both.
VERIFICATION_WINDOW: Final = 1


def generate_seed() -> str:
    """A fresh base32 TOTP seed, unpadded and uppercase.

    Base32 because that is what the `otpauth://` URI carries and what an authenticator
    expects when a seed is typed rather than scanned. Unpadded because the `=` characters
    confuse several apps and carry no information: the length is implied.
    """
    return base64.b32encode(secrets.token_bytes(SEED_BYTES)).decode("ascii").rstrip("=")


def _decode_seed(seed: str) -> bytes:
    """Base32 back to bytes, tolerating the case and padding a user might type.

    Accepts lowercase and re-adds the padding base32 needs, because a seed that came back
    through a form field has usually lost both. Raises `ValueError` on anything that is not
    base32 at all.

    Existing `=` is stripped before the padding is recomputed rather than counted. A seed
    copied from somewhere that kept its padding would otherwise be padded twice, and
    `b32decode` rejects that as an incorrect length: the tolerance meant to help a user
    pasting an unmodified seed would reject exactly that case.
    """
    cleaned = "".join(seed.split()).upper().rstrip("=")
    padding = "=" * (-len(cleaned) % 8)
    try:
        return base64.b32decode(cleaned + padding, casefold=True)
    except Exception as exc:
        raise ValueError(f"seed is not valid base32: {exc}") from exc


def current_step(*, now: int | None = None) -> int:
    """The RFC 6238 time step for a moment. Unix seconds divided by the step, floored."""
    moment = int(time.time()) if now is None else now
    return moment // TIME_STEP_SECONDS


def generate_code(seed: str, *, step: int) -> str:
    """The code for one time step, zero-padded to `CODE_DIGITS`.

    RFC 4226's dynamic truncation: the low nibble of the last byte selects a four byte
    window, its top bit is masked off so the value is a positive 31 bit integer whatever the
    platform's signedness does, and the remainder modulo a million is the code.
    """
    key = _decode_seed(seed)
    counter = struct.pack(">Q", step)
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10**CODE_DIGITS)).zfill(CODE_DIGITS)


def normalise_code(code: str) -> str:
    """Strip what a user's keyboard or an authenticator's display adds.

    Spaces because several apps render `123 456`, and a user copying that pastes the space.
    Nothing else is stripped: a code with a letter in it is wrong, not dirty, and quietly
    removing characters until something parses is how a comparison starts accepting values
    it should not.
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

    Returns the **step**, not a boolean, because the caller has to store it: the returned
    step becomes the new `last_used_step`, and that write is the whole of the replay
    defence. A boolean-returning version of this function cannot express it, which is why
    this one does not have one.

    A step at or below `last_used_step` is refused even when the arithmetic matches. That is
    the replay case, and it is deliberately indistinguishable to the caller from a wrong
    code: both are `None`, so a route cannot accidentally tell an attacker that the code they
    replayed was the right one.

    Every candidate step is checked even after one matches, so the work does not depend on
    which step was right. The compare itself is `hmac.compare_digest`, per section 5.3.
    """
    presented = normalise_code(code)
    if len(presented) != CODE_DIGITS or not presented.isdigit():
        # Length and shape are checked before any HMAC, because a caller sending an empty
        # string or a whole password should not cost a decode of the seed. This leaks only
        # that a code has to be six digits, which the enrolment screen already says.
        return None

    now_step = current_step(now=now)
    matched: int | None = None
    for candidate in range(now_step - window, now_step + window + 1):
        if candidate <= last_used_step:
            # Already spent, or older than something already spent. Skipped rather than
            # compared: comparing and then discarding the result would accept a replay for
            # anyone who removed the discard later.
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
    """The `otpauth://totp/...` URI an authenticator scans or accepts pasted.

    The `issuer` appears **twice**, in the label prefix and as a parameter, which looks
    redundant and is not. The Key URI format says older apps read only the label prefix and
    newer ones prefer the parameter, and an app that finds only one of them shows the account
    under the wrong heading or under no heading at all. Both is what the format's own
    documentation recommends.

    `algorithm`, `digits` and `period` are omitted rather than written as their defaults.
    They are the defaults every app assumes, and several apps mis-parse the parameters when
    present, so writing them can only make a working URI stop working.

    Every component is percent-encoded, the label with `/` and `:` escaped as well: an
    account name containing either would otherwise end the label early and produce a URI that
    parses as a different account.

    The query is encoded with `quote_via=quote`, **not** `urlencode`'s default. The default
    is form encoding, which writes a space as `+`, and this is a URI rather than a form body:
    a compliant parser reads that `+` literally, so an issuer with a space in it shows up in
    the user's authenticator with a `+` where the space belongs. `quote` writes `%20`, which
    every parser reads back as the space it was.
    """
    label = quote(f"{issuer}:{account_name}", safe="")
    parameters = urlencode({"secret": seed, "issuer": issuer}, quote_via=quote)
    return f"otpauth://totp/{label}?{parameters}"
