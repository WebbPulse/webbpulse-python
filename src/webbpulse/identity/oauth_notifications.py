"""Apple's server-to-server account notifications: verification and the package defaults.

Synchronous and free of FastAPI; the route lives in `oauth_routes.py`. What a change means to
a product is its own policy, so the optional `on_provider_account_event` hook runs first and
the defaults here only keep the link truthful and end the user's sessions. They never delete
the local account.
"""

from __future__ import annotations

import json
import logging
from dataclasses import replace
from datetime import datetime
from typing import TYPE_CHECKING, Any, Final

from webbpulse.identity.hooks import ProviderAccountEvent, ProviderAccountEventHooks
from webbpulse.identity.oauth import (
    APPLE_ISSUER,
    APPLE_PROVIDER,
    PROVIDERS,
    OAuthRejected,
    _as_bool,
    provider_account_key,
    provider_key_for,
    published_provider_keys,
)

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Callable, Mapping

    from webbpulse.identity.hooks import IdentityHooks
    from webbpulse.identity.oauth import HttpClient, OAuthLinkRecord, OAuthLinkStore
    from webbpulse.identity.settings import IdentitySettings

__all__ = [
    "APPLE_ACCOUNT_DELETED",
    "APPLE_CONSENT_REVOKED",
    "APPLE_EMAIL_DISABLED",
    "APPLE_EMAIL_ENABLED",
    "AppleNotifications",
]

_log = logging.getLogger(__name__)

APPLE_EMAIL_DISABLED: Final = "email-disabled"
APPLE_EMAIL_ENABLED: Final = "email-enabled"
APPLE_CONSENT_REVOKED: Final = "consent-revoked"
APPLE_ACCOUNT_DELETED: Final = "account-deleted"

_EMAIL_EVENTS: Final = frozenset({APPLE_EMAIL_DISABLED, APPLE_EMAIL_ENABLED})
_ENDING_EVENTS: Final = frozenset({APPLE_CONSENT_REVOKED, APPLE_ACCOUNT_DELETED})

_MILLISECOND_EPOCH_FLOOR: Final = 100_000_000_000
"""An `event_time` above this reads as milliseconds. In seconds it is the year 5138."""


class AppleNotifications:
    """Verify one notification from Apple and apply it to the link it names.

    Every step is idempotent, because Apple documents no retry or dedupe behaviour and `jti`
    is not persisted. A consent or deletion event older than the link's last sign-in is
    ignored, since it describes an authorization the user has since granted again.
    """

    def __init__(
        self,
        settings: IdentitySettings,
        hooks: IdentityHooks,
        *,
        links: OAuthLinkStore,
        http_client: HttpClient,
        other_sign_in: Callable[..., bool],
    ) -> None:
        """Hold the settings, hooks, link store, HTTP client and the last-way-in check."""
        self._settings = settings
        self._hooks = hooks
        self._links = links
        self._http = http_client
        self._other_sign_in = other_sign_in

    def handle(self, payload: str, *, end_sessions: Callable[[str], object]) -> str:
        """Verify and apply a notification, returning the outcome it logged.

        Refuses with `OAuthRejected`: a 400 for anything unverifiable, and a 503 when Apple's
        keys are unavailable or applying the event failed, so a redelivery can succeed.
        """
        events = _events_from(self._verified_claims(payload))
        event_type = str(events.get("type", ""))
        subject = str(events.get("sub", ""))
        if not event_type or not subject:
            raise self._invalid("events_incomplete")

        user_id = ""
        outcome = "ignored"
        if event_type in _EMAIL_EVENTS | _ENDING_EVENTS:
            try:
                record = self._links.get(provider_account_key(APPLE_PROVIDER, subject))
                outcome = "unknown_subject"
                if record is not None:
                    user_id = record.user_id
                    outcome = self._apply(event_type, events, record, end_sessions)
            except Exception as exc:
                _log.warning(
                    "An Apple notification could not be applied.",
                    extra={
                        "event": "oauth.apple_notification_failed",
                        "event_type": event_type,
                        "user_id": user_id,
                        "reason": type(exc).__name__,
                    },
                )
                raise _unavailable() from exc

        _log.info(
            "An Apple notification was received.",
            extra={
                "event": "oauth.apple_notification",
                "event_type": event_type[:64],
                "user_id": user_id,
                "outcome": outcome,
            },
        )
        return outcome

    def _verified_claims(self, payload: str) -> dict[str, Any]:
        """The claims of a JWS whose signature, `iss` and `aud` all check out.

        RS256 is pinned rather than read from the header, which is what stops an algorithm
        confusion. The header is read first so a junk body costs no JWKS fetch.
        """
        import jwt

        try:
            header = jwt.get_unverified_header(payload)
        except Exception as exc:
            raise self._invalid(type(exc).__name__) from exc
        kid = str(header.get("kid", ""))
        if not kid or header.get("alg") != "RS256":
            raise self._invalid("header")

        try:
            keys = published_provider_keys(self._http, PROVIDERS[APPLE_PROVIDER])
        except Exception as exc:
            _log.warning(
                "Apple's signing keys could not be fetched.",
                extra={"event": "oauth.apple_notification_failed", "reason": type(exc).__name__},
            )
            raise _unavailable() from exc
        if keys is None:
            _log.warning(
                "Apple's signing keys could not be read.",
                extra={"event": "oauth.apple_notification_failed", "reason": "jwks"},
            )
            raise _unavailable()

        try:
            key = provider_key_for(keys, kid)
            if key is None:
                raise self._invalid("unknown_kid")
            claims: dict[str, Any] = jwt.decode(
                payload,
                key,
                algorithms=["RS256"],
                audience=self._settings.apple_notification_audiences or [self._settings.apple_client_id],
                issuer=APPLE_ISSUER,
                leeway=self._settings.clock_skew_leeway,
                options={"require": ["iss", "aud", "iat"]},
            )
        except OAuthRejected:
            raise
        except Exception as exc:
            raise self._invalid(type(exc).__name__) from exc
        return claims

    def _apply(
        self,
        event_type: str,
        events: Mapping[str, Any],
        record: OAuthLinkRecord,
        end_sessions: Callable[[str], object],
    ) -> str:
        """Run the product's hook and then, unless it took over, the package default."""
        event_time = _event_seconds(events.get("event_time"))
        ending = event_type in _ENDING_EVENTS
        if ending and _older_than_last_sign_in(event_time, record.last_login_at):
            return "stale"

        event = ProviderAccountEvent(
            provider=APPLE_PROVIDER,
            event_type=event_type,
            user_id=record.user_id,
            subject=record.subject,
            email=str(events.get("email", "")).strip().lower(),
            is_private_email=_as_bool(events.get("is_private_email")),
            event_time=event_time,
            jwt_id=str(events.get("jti", "")),
            has_other_sign_in=ending and self._other_sign_in(record.user_id, removing={record.provider_subject}),
        )
        if isinstance(self._hooks, ProviderAccountEventHooks) and self._hooks.on_provider_account_event(event) is True:
            return "handled_by_product"

        self._apply_default(event, record, end_sessions)
        return "applied"

    def _apply_default(
        self,
        event: ProviderAccountEvent,
        record: OAuthLinkRecord,
        end_sessions: Callable[[str], object],
    ) -> None:
        """Keep the link truthful and end the sessions an ended authorization should not outlive.

        A revoked consent keeps its link, so a returning user lands on the same account, and
        drops the token Apple has already invalidated. Sessions end before a row changes, so a
        failure there leaves something for the redelivery to find.
        """
        if event.event_type in _EMAIL_EVENTS:
            self._links.put(
                replace(
                    record,
                    provider_email=event.email or record.provider_email,
                    provider_email_disabled=event.event_type == APPLE_EMAIL_DISABLED,
                )
            )
            return
        end_sessions(record.user_id)
        if event.event_type == APPLE_CONSENT_REVOKED:
            self._links.put(replace(record, provider_token=None))
        else:
            self._links.delete(record.provider_subject)

    def _invalid(self, reason: str) -> OAuthRejected:
        """Log and build the refusal for a notification that cannot be verified."""
        _log.warning(
            "An Apple notification failed verification.",
            extra={"event": "oauth.apple_notification_invalid", "reason": reason},
        )
        return OAuthRejected(
            "That notification could not be verified.",
            error_code="OAUTH_NOTIFICATION_INVALID",
        )


def _unavailable() -> OAuthRejected:
    """The refusal that invites a redelivery."""
    return OAuthRejected(
        "That notification could not be processed. Try again.",
        error_code="OAUTH_NOTIFICATION_FAILED",
        status_code=503,
    )


def _events_from(claims: Mapping[str, Any]) -> dict[str, Any]:
    """The `events` claim as a mapping, empty when it is neither an object nor one encoded.

    Apple documents an object, and integrators report a JSON-encoded string, so both are read.
    The fields are merged with `jti` so the event carries everything from one place.
    """
    events = claims.get("events")
    if isinstance(events, str):
        try:
            events = json.loads(events)
        except ValueError:
            return {}
    if not isinstance(events, dict):
        return {}
    return {**events, "jti": claims.get("jti", "")}


def _event_seconds(value: object) -> int:
    """An `event_time` as epoch seconds, or 0 when it is absent or unreadable."""
    if not isinstance(value, int | float | str):
        return 0
    try:
        stamp = int(value)
    except (ValueError, OverflowError):
        return 0
    return stamp // 1000 if stamp > _MILLISECOND_EPOCH_FLOOR else stamp


def _older_than_last_sign_in(event_time: int, last_login_at: str) -> bool:
    """Whether an event predates the link's last sign-in. Unknown either way means it does not."""
    if not event_time or not last_login_at:
        return False
    try:
        return event_time < int(datetime.fromisoformat(last_login_at).timestamp())
    except ValueError:
        return False
