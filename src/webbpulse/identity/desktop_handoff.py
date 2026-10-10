"""Browser to desktop session handoff.

A signed-in browser mints a single-use code bound to a desktop app's PKCE challenge and
custom URL scheme, and hands it to the app through `<scheme>://auth/handoff?code=...`.
The app redeems the code with its verifier for a session of its own, at the MFA level the
browser session had. Only the code's hash is stored, and neither the code nor the
verifier is ever logged or echoed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final

from webbpulse.dynamodb import now_iso, ttl_in
from webbpulse.identity.oauth import pkce_challenge
from webbpulse.identity.storage import (
    IdentityTokenRecord,
    constant_time_equals,
    hash_token,
    is_expired,
    new_token,
)

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Sequence

    from webbpulse.identity.settings import IdentitySettings
    from webbpulse.identity.storage import IdentityTokenStore

__all__ = [
    "HANDOFF_CHALLENGE_METHOD",
    "HANDOFF_INVALID_MESSAGE",
    "HANDOFF_PURPOSE",
    "DesktopHandoffService",
    "HandoffRejected",
    "MintedHandoff",
    "RedeemedHandoff",
    "normalise_scheme",
]

HANDOFF_PURPOSE: Final = "desktop_handoff"

HANDOFF_CHALLENGE_METHOD: Final = "S256"

HANDOFF_INVALID_MESSAGE: Final = "This sign-in handoff is invalid or has expired. Start again from the app."

_CHALLENGE_PATTERN: Final = re.compile(r"^[A-Za-z0-9_-]{43}$")

_VERIFIER_PATTERN: Final = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")

_CODE_MAX_LENGTH: Final = 128


class HandoffRejected(Exception):
    """A handoff mint or exchange was refused, with a fixed message that never names the code."""

    def __init__(self, message: str, *, error_code: str, status_code: int = 400) -> None:
        """Hold the message, the `error_code` a client branches on, and the HTTP status."""
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class MintedHandoff:
    """A freshly minted code and the seconds it stays redeemable."""

    code: str
    expires_in: int


@dataclass(frozen=True, slots=True)
class RedeemedHandoff:
    """What a spent code was bound to: the user and the browser session's sign-in state."""

    user_id: str
    amr: tuple[str, ...]
    auth_time: int
    scheme: str
    source_family_id: str


def normalise_scheme(value: str) -> str:
    """A scheme as the allowlist stores it: trimmed, lower case, without `://` or `:`."""
    return value.strip().lower().removesuffix("://").removesuffix(":")


def _invalid() -> HandoffRejected:
    """The one refusal every failed exchange gets, so no outcome is distinguishable."""
    return HandoffRejected(HANDOFF_INVALID_MESSAGE, error_code="HANDOFF_INVALID")


class DesktopHandoffService:
    """Mint and redeem desktop handoff codes over the `identity-tokens` store."""

    def __init__(self, settings: IdentitySettings, store: IdentityTokenStore) -> None:
        """Bind the service to the scheme allowlist, the code lifetime and the token store."""
        self._settings = settings
        self._store = store

    def allows(self, scheme: str) -> bool:
        """Whether `scheme` is on this environment's allowlist. An empty allowlist allows nothing."""
        return normalise_scheme(scheme) in self._settings.desktop_handoff_schemes

    def mint(
        self,
        user_id: str,
        *,
        code_challenge: str,
        code_challenge_method: str,
        scheme: str,
        amr: Sequence[str],
        auth_time: int,
        family_id: str,
    ) -> MintedHandoff:
        """Mint a single-use code bound to the user, the session's `amr`, the challenge and the scheme.

        Refuses an unknown scheme, a method other than `S256` and a malformed challenge
        before anything is written.
        """
        if not user_id:
            raise HandoffRejected("Sign in first.", error_code="NOT_AUTHENTICATED", status_code=401)
        normalised = normalise_scheme(scheme)
        if not self.allows(normalised):
            raise HandoffRejected(
                "This app is not allowed to receive a sign-in handoff.",
                error_code="HANDOFF_SCHEME_NOT_ALLOWED",
            )
        if code_challenge_method != HANDOFF_CHALLENGE_METHOD:
            raise HandoffRejected(
                "code_challenge_method must be S256.",
                error_code="HANDOFF_INVALID_REQUEST",
            )
        if not _CHALLENGE_PATTERN.fullmatch(code_challenge):
            raise HandoffRejected(
                "code_challenge must be the base64url SHA-256 of a PKCE verifier.",
                error_code="HANDOFF_INVALID_REQUEST",
            )
        ttl_seconds = int(self._settings.desktop_handoff_code_ttl.total_seconds())
        code = new_token()
        self._store.put(
            IdentityTokenRecord(
                token_hash=hash_token(code),
                purpose=HANDOFF_PURPOSE,
                user_id=user_id,
                created_at=now_iso(),
                expires_at=ttl_in(ttl_seconds),
                attributes={
                    "code_challenge": code_challenge,
                    "scheme": normalised,
                    "amr": list(dict.fromkeys(amr)),
                    "auth_time": int(auth_time),
                    "family_id": family_id,
                },
            )
        )
        return MintedHandoff(code=code, expires_in=ttl_seconds)

    def redeem(
        self,
        code: str,
        *,
        code_verifier: str,
        scheme: str,
        now: datetime | None = None,
    ) -> RedeemedHandoff:
        """Spend a code and return what it was bound to, or raise `HandoffRejected`.

        The code is consumed before the verifier and scheme are checked, so a wrong guess
        burns it and a stolen code cannot be retried. Every failure is the same refusal.
        """
        if not code or len(code) > _CODE_MAX_LENGTH:
            raise _invalid()
        record = self._store.consume(hash_token(code))
        if record is None or record.purpose != HANDOFF_PURPOSE:
            raise _invalid()
        if is_expired(record.expires_at, now=now or datetime.now(UTC)):
            raise _invalid()
        attributes = record.attributes
        bound_scheme = str(attributes.get("scheme", ""))
        if not bound_scheme or not constant_time_equals(bound_scheme, normalise_scheme(scheme)):
            raise _invalid()
        if not self.allows(bound_scheme):
            raise _invalid()
        if not _VERIFIER_PATTERN.fullmatch(code_verifier):
            raise _invalid()
        challenge = str(attributes.get("code_challenge", ""))
        if not challenge or not constant_time_equals(pkce_challenge(code_verifier), challenge):
            raise _invalid()
        raw_amr = attributes.get("amr") or ()
        return RedeemedHandoff(
            user_id=record.user_id,
            amr=tuple(str(method) for method in raw_amr),
            auth_time=int(attributes.get("auth_time", 0) or 0),
            scheme=bound_scheme,
            source_family_id=str(attributes.get("family_id", "")),
        )
