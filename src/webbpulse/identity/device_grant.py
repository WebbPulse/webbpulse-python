"""The OAuth 2.0 device authorization grant (RFC 8628), so a CLI can sign a person in.

A CLI asks `/device/code` for a device code and a short user code, prints the user code
and a URL, and polls `/device/token`. The person opens the URL in a browser where they are
already signed in, confirms the code and approves. Approval is a step-up: it needs a
sign-in no older than `device_approval_max_age`, and an older one is sent back through the
product's login page with `prompt=login`.

What the CLI receives is bound to the person and to the scopes they approved. The access
token is an RS256 JWT for its own audience, `settings.device_token_audience`, never the
session `audience`, and carries `grant: "device"`, `client_id` and the grant id as `sid`.
Identity's session routes refuse it by audience and by those claims, so it can never widen
itself through step-up, consent, TOTP enrolment, a password change or another approval. A
resource server that serves the CLI opts in by accepting the device audience (its gateway
authorizer, or `JwksVerifier.from_settings(..., accept_device_tokens=True)`) and must check
`device_grant_is_live`, which `claims_or_api_key(device_grants=...)` does for it, so a
revoked CLI session stops at once rather than at expiry.

The refresh token is opaque, rotates on every use and dies at the session cap. Presenting
the one it replaced within `DEVICE_REFRESH_GRACE_SECONDS` of the rotation is a lost race and
returns the same successor; presenting it later ends the grant. None of it touches the
browser's refresh families. Approval forms and refresh successors are keyed on HKDF keys
derived from the environment's `mfa_master_key`, and the grant refuses to run without one.
"""

from __future__ import annotations

import logging
import secrets
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import urlencode

from webbpulse.identity.device_grant_storage import (
    DeviceCodeRecord,
    DeviceGrantRecord,
    DeviceGrantStores,
)
from webbpulse.identity.oauth_server import (
    AuthorizationSubject,
    OAuthServerError,
    _form_params,
    _iso,
    _redirect_with,
)
from webbpulse.identity.storage import constant_time_equals, hash_token, is_expired, new_token

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import APIRouter, Request

    from webbpulse.identity.consent_page import ConsentTheme
    from webbpulse.identity.hooks import IdentityHooks
    from webbpulse.identity.service import TokenService
    from webbpulse.identity.settings import IdentitySettings

__all__ = [
    "DEVICE_APPROVE_PATH",
    "DEVICE_CODE_GRANT_TYPE",
    "DEVICE_CODE_IP_LIMIT",
    "DEVICE_CODE_PATH",
    "DEVICE_GRANTS_IP_LIMIT",
    "DEVICE_GRANTS_PATH",
    "DEVICE_GRANT_CLAIM",
    "DEVICE_LIVENESS_MAX_CACHE_SECONDS",
    "DEVICE_REFRESH_GRACE_SECONDS",
    "DEVICE_REFRESH_PREFIX",
    "DEVICE_REVOKE_PATH",
    "DEVICE_TOKEN_IP_LIMIT",
    "DEVICE_TOKEN_PATH",
    "DEVICE_USER_CODE_FAILURE_LIMIT",
    "DEVICE_VERIFY_IP_LIMIT",
    "DEVICE_VERIFY_PATH",
    "SLOW_DOWN_STEP",
    "USER_CODE_ALPHABET",
    "DeviceGrantKeyMissing",
    "DeviceGrantLiveness",
    "DeviceGrantService",
    "build_device_grant_router",
    "device_grant_is_live",
    "normalize_user_code",
]

_log = logging.getLogger(__name__)

DEVICE_CODE_PATH: Final = "/device/code"
DEVICE_TOKEN_PATH: Final = "/device/token"
DEVICE_VERIFY_PATH: Final = "/device"
DEVICE_APPROVE_PATH: Final = "/device/approve"
DEVICE_REVOKE_PATH: Final = "/device/revoke"
DEVICE_GRANTS_PATH: Final = "/device/grants"

DEVICE_CODE_GRANT_TYPE: Final = "urn:ietf:params:oauth:grant-type:device_code"
DEVICE_REFRESH_PREFIX: Final = "wpdr_"
DEVICE_GRANT_CLAIM: Final = "grant"
USER_CODE_ALPHABET: Final = "BCDFGHJKLMNPQRSTVWXZ"
USER_CODE_LENGTH: Final = 8
SLOW_DOWN_STEP: Final = 5

DEVICE_CODE_IP_LIMIT: Final = (30, 900)
DEVICE_TOKEN_IP_LIMIT: Final = (600, 900)
DEVICE_VERIFY_IP_LIMIT: Final = (30, 900)
DEVICE_GRANTS_IP_LIMIT: Final = (120, 900)
DEVICE_USER_CODE_FAILURE_LIMIT: Final = (10, 900)
DEVICE_REFRESH_GRACE_SECONDS: Final = 30
DEVICE_LIVENESS_MAX_CACHE_SECONDS: Final = 5.0
USER_CODE_ATTEMPTS: Final = 5

_APPROVAL_KEY_INFO: Final = "webbpulse.device-grant.approval.v1"
_REFRESH_KEY_INFO: Final = "webbpulse.device-grant.refresh.v1"

_FastAPIRequest: Any = None
if not TYPE_CHECKING:
    Request = None


def _bind_fastapi_request() -> None:
    """Put `fastapi.Request` in this module's globals, so FastAPI can resolve route annotations."""
    global _FastAPIRequest, Request
    if _FastAPIRequest is None:
        from fastapi import Request as _Request

        _FastAPIRequest = _Request
        Request = _Request  # type: ignore[misc]


def new_user_code() -> str:
    """A fresh user code, `XXXX-XXXX` from consonants only.

    Twenty letters with no vowels and no digits: nothing reads as a word, and nothing is
    confused with another character (no 0/O, 1/I/L, 5/S, 8/B pairs survive). Eight of them
    is about 34 bits, far beyond what the rate limit lets anyone guess inside the code's life.
    """
    raw = "".join(secrets.choice(USER_CODE_ALPHABET) for _ in range(USER_CODE_LENGTH))
    return f"{raw[:4]}-{raw[4:]}"


def normalize_user_code(value: str) -> str:
    """A typed user code in its canonical form: upper-case, no dashes or spaces.

    Empty when what was typed cannot be a user code, so it never reaches a lookup.
    """
    cleaned = "".join(character for character in value.upper() if character not in "- \t")
    if len(cleaned) != USER_CODE_LENGTH or any(character not in USER_CODE_ALPHABET for character in cleaned):
        return ""
    return cleaned


def _format_user_code(normalized: str) -> str:
    """The display form of a normalized user code."""
    return f"{normalized[:4]}-{normalized[4:]}"


def _user_code_hash(normalized: str) -> str:
    """The stored form of a normalized user code."""
    return hash_token(f"user-code:{normalized}")


def _split_refresh(token: str) -> tuple[str, str]:
    """The grant id and secret halves of a device refresh token, or two empty strings."""
    if not token.startswith(DEVICE_REFRESH_PREFIX):
        return "", ""
    grant_id, _, secret = token[len(DEVICE_REFRESH_PREFIX) :].partition(".")
    if not grant_id or not secret:
        return "", ""
    return grant_id, secret


def device_grant_is_live(grants: Any, claims: Mapping[str, Any]) -> bool:
    """Whether the device grant behind an access token is still live.

    True for any token that did not come from a device login. For one that did, the grant
    named by `sid` must exist, belong to `sub`, and be neither revoked nor past its cap. A
    resource server calls this so a revoked CLI session stops working at once rather than
    when its access token expires. `grants` is the `DeviceGrantStore`.
    """
    if str(claims.get(DEVICE_GRANT_CLAIM, "") or "") != "device":
        return True
    grant_id = str(claims.get("sid", "") or "")
    if not grant_id:
        return False
    try:
        record = grants.get(grant_id)
    except Exception as exc:
        _log.warning("Could not load a device grant: %s", type(exc).__name__)
        return False
    return record is not None and record.user_id == str(claims.get("sub", "") or "") and record.live()


class DeviceGrantLiveness:
    """`device_grant_is_live` behind a short cache, for a resource server's hot path.

    A decision is reused for at most `ttl_seconds`, capped at
    `DEVICE_LIVENESS_MAX_CACHE_SECONDS`, so a revocation takes effect within a few seconds
    while a burst of CLI calls costs one read. Tokens that did not come from a device login
    pass without a read.
    """

    def __init__(
        self,
        grants: Any,
        *,
        ttl_seconds: float = DEVICE_LIVENESS_MAX_CACHE_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        max_entries: int = 4096,
    ) -> None:
        """Bind the check to the `DeviceGrantStore`, refusing a cache longer than the cap."""
        if not 0 <= ttl_seconds <= DEVICE_LIVENESS_MAX_CACHE_SECONDS:
            raise ValueError(f"ttl_seconds must be between 0 and {DEVICE_LIVENESS_MAX_CACHE_SECONDS}.")
        self._grants = grants
        self._ttl = ttl_seconds
        self._clock = clock
        self._max = max_entries
        self._cache: dict[tuple[str, str], tuple[float, bool]] = {}

    def __call__(self, claims: Mapping[str, Any]) -> bool:
        """Whether these claims' device grant is live; True for any other token."""
        if str(claims.get(DEVICE_GRANT_CLAIM, "") or "") != "device":
            return True
        key = (str(claims.get("sid", "") or ""), str(claims.get("sub", "") or ""))
        moment = self._clock()
        hit = self._cache.get(key)
        if hit is not None and hit[0] > moment:
            return hit[1]
        live = device_grant_is_live(self._grants, claims)
        if self._ttl > 0:
            if len(self._cache) >= self._max:
                self._cache.clear()
            self._cache[key] = (moment + self._ttl, live)
        return live


class DeviceGrantKeyMissing(ValueError):
    """The device grant was asked to sign something with no master key to derive from."""


def device_grant_master_key(settings: IdentitySettings) -> bytes:
    """The 32 byte master key the device grant derives its keys from.

    `totp_master_key` where set, else `IDENTITY_TOTP_MASTER_KEY`, else the `mfa_master_key`
    entry of the app secret, resolved at runtime as `MfaService` does. There is no fallback:
    with none of them the grant raises rather than key an HMAC on something public.
    """
    import base64

    from webbpulse.identity.crypto import MASTER_KEY_BYTES, resolve_totp_master_key

    if settings.totp_master_key:
        return settings.totp_master_key_bytes
    resolved = resolve_totp_master_key()
    if not resolved:
        raise DeviceGrantKeyMissing(
            "device_grant_enabled is on but no master key was found. Set totp_master_key or "
            "IDENTITY_TOTP_MASTER_KEY, or put mfa_master_key in the app secret."
        )
    try:
        raw = base64.b64decode(resolved.encode("ascii"), validate=True)
    except Exception as exc:
        raise DeviceGrantKeyMissing(f"the device grant master key is not valid base64: {exc}") from exc
    if len(raw) != MASTER_KEY_BYTES:
        raise DeviceGrantKeyMissing(f"the device grant master key is {len(raw)} bytes, expected {MASTER_KEY_BYTES}.")
    return raw


@dataclass(frozen=True, slots=True)
class DeviceApproval:
    """What the approval page shows for one pending request."""

    record: DeviceCodeRecord
    user_code: str
    client_name: str
    scopes: tuple[str, ...]


class DeviceGrantService:
    """The device grant's logic, free of HTTP so the security properties test directly."""

    def __init__(
        self,
        settings: IdentitySettings,
        hooks: IdentityHooks,
        stores: DeviceGrantStores,
        tokens: TokenService,
    ) -> None:
        """Bind the service to its settings, the product hooks, its stores and the token minter."""
        self._settings = settings
        self._hooks = hooks
        self._stores = stores
        self._tokens = tokens
        self._keys: tuple[bytes, bytes] | None = None

    def require_keys(self) -> None:
        """Derive the keys now, raising `DeviceGrantKeyMissing` when there is no master key."""
        self._derived_keys()

    def _derived_keys(self) -> tuple[bytes, bytes]:
        """The approval and refresh keys, derived once from the master key."""
        if self._keys is None:
            from webbpulse.security import derive_key

            master = device_grant_master_key(self._settings)
            self._keys = (derive_key(master, _APPROVAL_KEY_INFO), derive_key(master, _REFRESH_KEY_INFO))
        return self._keys

    def _successor(self, grant_id: str, presented_hash: str) -> str:
        """The refresh secret that replaces `presented_hash`, the same every time it is asked for.

        Deterministic so a client that lost the race for a rotation, or lost the response,
        can present the previous token again inside the grace window and be handed the same
        pair, with nothing extra stored.
        """
        import base64
        import hashlib
        import hmac

        digest = hmac.new(self._derived_keys()[1], f"{grant_id}|{presented_hash}".encode(), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    @property
    def stores(self) -> DeviceGrantStores:
        """The two stores this service reads and writes."""
        return self._stores

    def client_name(self, client_id: str) -> str:
        """The display name for a registered device client."""
        return self._settings.device_clients.get(client_id, client_id)

    def _default_scopes(self) -> tuple[str, ...]:
        """The scopes a request naming none receives: every supported one that is not explicit-only."""
        explicit = set(self._settings.device_explicit_scopes)
        return tuple(scope for scope in self._settings.device_scopes_supported if scope not in explicit)

    def start(self, params: Mapping[str, str], *, now: int | None = None) -> dict[str, Any]:
        """Begin a device login: validate the client and scopes, store the codes, answer RFC 8628 section 3.2."""
        moment = int(time.time()) if now is None else now
        client_id = params.get("client_id", "")
        if client_id not in self._settings.device_clients:
            raise OAuthServerError("invalid_client", "That client may not start a device login.", status=401)
        requested = tuple(dict.fromkeys(params.get("scope", "").split()))
        supported = set(self._settings.device_scopes_supported)
        if any(scope not in supported for scope in requested):
            raise OAuthServerError("invalid_scope", "A requested scope is not one a device login may hold.")
        scopes = requested or self._default_scopes()
        if not scopes:
            raise OAuthServerError("invalid_scope", "Name the scopes this device login needs.")

        ttl = int(self._settings.device_code_ttl.total_seconds())
        interval = self._settings.device_poll_interval
        for _ in range(USER_CODE_ATTEMPTS):
            device_code = new_token()
            user_code = new_user_code()
            stored = self._stores.codes.put(
                DeviceCodeRecord(
                    device_code_hash=hash_token(device_code),
                    user_code_hash=_user_code_hash(normalize_user_code(user_code)),
                    client_id=client_id,
                    scopes=scopes,
                    created_at=_iso(moment),
                    expires_at=moment + ttl,
                    interval=interval,
                )
            )
            if stored:
                break
        else:
            raise OAuthServerError("temporarily_unavailable", "Could not issue a user code; try again.", status=503)
        verification_uri = f"{self._settings.issuer}{DEVICE_VERIFY_PATH}"
        return {
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": verification_uri,
            "verification_uri_complete": f"{verification_uri}?{urlencode({'user_code': user_code})}",
            "expires_in": ttl,
            "interval": interval,
        }

    def held_scopes(self, user: Mapping[str, Any]) -> tuple[str, ...] | None:
        """The scopes the product's claims give this user, or `None` when it carries no scope model."""
        from webbpulse.identity.scopes import claims_scopes

        claims = self._hooks.claims_for(user)
        if "scope" not in claims and "scopes" not in claims:
            return None
        return claims_scopes(claims)

    def lookups_exhausted(self, user_id: str, *, now: int | None = None) -> bool:
        """Whether this user has failed too many user code lookups in the current window."""
        moment = int(time.time()) if now is None else now
        limit, window = DEVICE_USER_CODE_FAILURE_LIMIT
        return self._stores.codes.failed_lookups(user_id, now=moment, window=window) >= limit

    def note_failed_lookup(self, user_id: str, *, now: int | None = None) -> None:
        """Count one failed user code lookup against this user."""
        moment = int(time.time()) if now is None else now
        self._stores.codes.record_failed_lookup(user_id, now=moment, window=DEVICE_USER_CODE_FAILURE_LIMIT[1])

    def pending(self, user_code: str, user_id: str) -> DeviceApproval | None:
        """The pending request a typed user code names, with what this user may grant, or `None`."""
        normalized = normalize_user_code(user_code)
        if not normalized:
            return None
        record = self._stores.codes.find_by_user_code(_user_code_hash(normalized))
        if record is None or record.status != "pending" or is_expired(record.expires_at):
            return None
        user = self._hooks.load_user_by_id(user_id)
        if user is None:
            return None
        held = self.held_scopes(user)
        scopes = record.scopes if held is None else tuple(scope for scope in record.scopes if scope in set(held))
        return DeviceApproval(
            record=record,
            user_code=_format_user_code(normalized),
            client_name=self.client_name(record.client_id),
            scopes=scopes,
        )

    def approval_signature(self, approval: DeviceApproval, user_id: str) -> str:
        """The HMAC binding an approval form to its request, the scopes shown and the signed-in user.

        Keyed on a key derived from the master key for this purpose alone, never on anything
        public such as the issuer, so no one can forge a form for another person's code.
        """
        import hashlib
        import hmac

        material = "|".join(
            (
                "device-approval",
                approval.record.device_code_hash,
                " ".join(approval.scopes),
                user_id,
            )
        )
        return hmac.new(self._derived_keys()[0], material.encode("utf-8"), hashlib.sha256).hexdigest()

    def decide(self, approval: DeviceApproval, *, user_id: str, allow: bool, auth_time: int) -> bool:
        """Record the person's decision once. False when the request was already decided or has gone."""
        if allow and not approval.scopes:
            return False
        return self._stores.codes.decide(
            approval.record.device_code_hash,
            status="approved" if allow else "denied",
            user_id=user_id,
            scopes=approval.scopes if allow else (),
            auth_time=auth_time,
        )

    def poll(self, params: Mapping[str, str], *, now: int | None = None) -> dict[str, Any]:
        """Answer one device code poll per RFC 8628 section 3.5."""
        moment = int(time.time()) if now is None else now
        device_code = params.get("device_code", "")
        client_id = params.get("client_id", "")
        if not device_code or not client_id:
            raise OAuthServerError("invalid_request", "device_code and client_id are required.")
        code_hash = hash_token(device_code)
        record = self._stores.codes.get(code_hash, include_expired=True)
        if record is None:
            raise OAuthServerError("invalid_grant", "The device code is unknown or has already been used.")
        if record.expires_at <= moment:
            raise OAuthServerError("expired_token", "The device code has expired.")
        if not constant_time_equals(record.client_id, client_id):
            raise OAuthServerError("invalid_grant", "The device code was issued to another client.")
        if not self._stores.codes.record_poll(code_hash, now=moment, interval=record.interval):
            self._stores.codes.slow_down(code_hash, interval=record.interval + SLOW_DOWN_STEP)
            raise OAuthServerError("slow_down", "Polling too fast; wait longer between requests.")
        if record.status == "pending":
            raise OAuthServerError("authorization_pending", "The person has not approved this login yet.")
        consumed = self._stores.codes.consume(code_hash, now=moment)
        if consumed is None:
            raise OAuthServerError("invalid_grant", "The device code has already been used.")
        if consumed.status != "approved" or not consumed.user_id:
            raise OAuthServerError("access_denied", "The person declined this login.")
        return self._open_grant(consumed, now=moment)

    def _open_grant(self, record: DeviceCodeRecord, *, now: int) -> dict[str, Any]:
        """Create the grant an approved code earns and mint its first token pair."""
        user = self._load_permitted(record.user_id)
        if user is None:
            raise OAuthServerError("access_denied", "This account may not sign in.")
        grant_id = uuid.uuid4().hex
        secret = self._successor(grant_id, hash_token(new_token()))
        grant = DeviceGrantRecord(
            grant_id=grant_id,
            user_id=record.user_id,
            client_id=record.client_id,
            scopes=record.scopes,
            created_at=_iso(now),
            expires_at=now + int(self._settings.device_session_ttl.total_seconds()),
            refresh_hash=hash_token(secret),
            auth_time=record.auth_time,
            last_used_at=_iso(now),
        )
        self._stores.grants.put(grant)
        return self._token_body(grant, user, secret=secret, now=now)

    def refresh(self, params: Mapping[str, str], *, now: int | None = None) -> dict[str, Any]:
        """Rotate a device refresh token and mint a fresh access token for the same grant.

        The refresh token is single use. Presenting the one it replaced within
        `DEVICE_REFRESH_GRACE_SECONDS` of the rotation, as a client that lost a race or a
        response does, returns the same successor and a fresh access token; presenting it
        after that ends the grant, since two parties hold it. The scopes never widen, and
        narrow when the person no longer holds one they approved.
        """
        moment = int(time.time()) if now is None else now
        grant_id, secret = _split_refresh(params.get("refresh_token", ""))
        client_id = params.get("client_id", "")
        if not grant_id or not client_id:
            raise OAuthServerError("invalid_request", "refresh_token and client_id are required.")
        grant = self._stores.grants.get(grant_id)
        if grant is None or not constant_time_equals(grant.client_id, client_id):
            raise OAuthServerError("invalid_grant", "The refresh token is unknown, expired or revoked.")
        if not grant.live():
            raise OAuthServerError("invalid_grant", "The refresh token is unknown, expired or revoked.")
        presented = hash_token(secret)
        successor = self._successor(grant_id, presented)
        if constant_time_equals(grant.refresh_hash, presented):
            if self._stores.grants.rotate(
                grant_id,
                presented_hash=presented,
                successor_hash=hash_token(successor),
                used_at=_iso(moment),
                rotated_at=moment,
            ):
                return self._issue(grant, successor, now=moment)
            reloaded = self._stores.grants.get(grant_id)
            if reloaded is None:
                raise OAuthServerError("invalid_grant", "The refresh token is unknown, expired or revoked.")
            grant = reloaded
        if self._within_grace(grant, presented, successor, now=moment):
            return self._issue(grant, successor, now=moment)
        if grant.previous_refresh_hash and constant_time_equals(grant.previous_refresh_hash, presented):
            self._stores.grants.revoke(grant_id)
            _log.warning("Device refresh token reuse; grant revoked.", extra={"grant_id": grant_id})
        raise OAuthServerError("invalid_grant", "The refresh token is unknown, expired or revoked.")

    def _within_grace(self, grant: DeviceGrantRecord, presented: str, successor: str, *, now: int) -> bool:
        """Whether `presented` is the token just replaced, inside the grace window, by this very successor."""
        return (
            grant.live()
            and bool(grant.previous_refresh_hash)
            and constant_time_equals(grant.previous_refresh_hash, presented)
            and grant.rotated_at > 0
            and 0 <= now - grant.rotated_at <= DEVICE_REFRESH_GRACE_SECONDS
            and constant_time_equals(grant.refresh_hash, hash_token(successor))
        )

    def _issue(self, grant: DeviceGrantRecord, successor: str, *, now: int) -> dict[str, Any]:
        """The token pair for a refresh that rotated or fell inside the grace window."""
        grant_id = grant.grant_id
        user = self._load_permitted(grant.user_id)
        if user is None:
            self._stores.grants.revoke(grant_id)
            raise OAuthServerError("invalid_grant", "This account may no longer sign in.")
        return self._token_body(grant, user, secret=successor, now=now)

    def revoke_token(self, token: str) -> bool:
        """Revoke the grant behind a device refresh token, current or just rotated.

        Answers whether a grant was revoked. The route still answers 200 either way, per
        RFC 7009, so nothing about other tokens leaks.
        """
        grant_id, secret = _split_refresh(token)
        if not grant_id:
            return False
        grant = self._stores.grants.get(grant_id)
        if grant is None:
            return False
        presented = hash_token(secret)
        if constant_time_equals(grant.refresh_hash, presented) or (
            grant.previous_refresh_hash and constant_time_equals(grant.previous_refresh_hash, presented)
        ):
            return self._stores.grants.revoke(grant_id)
        return False

    def revoke_grant(self, grant_id: str, *, user_id: str) -> bool:
        """Revoke one of this user's grants. False when it is not theirs or does not exist."""
        grant = self._stores.grants.get(grant_id)
        if grant is None or grant.user_id != user_id:
            return False
        return self._stores.grants.revoke(grant_id)

    def revoke_all(self, user_id: str) -> int:
        """Revoke every device grant this user holds."""
        return self._stores.grants.revoke_all_for_user(user_id)

    def list_grants(self, user_id: str) -> list[dict[str, Any]]:
        """This user's live device logins, safe to show: no hashes."""
        return [
            {
                "grant_id": grant.grant_id,
                "client_id": grant.client_id,
                "client_name": self.client_name(grant.client_id),
                "scopes": list(grant.scopes),
                "created_at": grant.created_at,
                "expires_at": grant.expires_at,
                "last_used_at": grant.last_used_at,
            }
            for grant in self._stores.grants.list_for_user(user_id)
            if grant.live()
        ]

    def _load_permitted(self, user_id: str) -> Mapping[str, Any] | None:
        """The user, when they exist and `may_authenticate` lets them in."""
        from webbpulse.identity.hooks import AuthenticationRefused

        user = self._hooks.load_user_by_id(user_id)
        if user is None:
            return None
        try:
            self._hooks.may_authenticate(user)
        except AuthenticationRefused:
            return None
        return user

    def _token_body(
        self, grant: DeviceGrantRecord, user: Mapping[str, Any], *, secret: str, now: int
    ) -> dict[str, Any]:
        """The token response for a grant: an access token bound to its scopes and a refresh token."""
        held = self.held_scopes(user)
        scopes = grant.scopes if held is None else tuple(scope for scope in grant.scopes if scope in set(held))
        claims = {key: value for key, value in self._hooks.claims_for(user).items() if key not in ("scope", "scopes")}
        claims.update(
            {
                "scope": " ".join(scopes),
                "client_id": grant.client_id,
                DEVICE_GRANT_CLAIM: "device",
                "amr": ["device"],
                "auth_time": grant.auth_time,
            }
        )
        ttl = self._settings.device_access_token_ttl
        access = self._tokens.mint_access_token(
            grant.user_id,
            claims=claims,
            audience=self._tokens.device_audience,
            session_id=grant.grant_id,
            now=now,
            ttl=ttl,
        )
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": int(ttl.total_seconds()),
            "refresh_token": f"{DEVICE_REFRESH_PREFIX}{grant.grant_id}.{secret}",
            "refresh_token_expires_in": max(grant.expires_at - now, 0),
            "scope": " ".join(scopes),
        }


def build_device_grant_router(
    settings: IdentitySettings,
    hooks: IdentityHooks,
    stores: DeviceGrantStores,
    *,
    tokens: TokenService,
    subject_resolver: Callable[[Request], AuthorizationSubject | None],
    prefix: str = "",
    limits: Callable[..., list[Any]] | None = None,
    consent_theme: ConsentTheme | None = None,
) -> APIRouter:
    """The device grant router, mounted by `build_identity_router` behind `device_grant_enabled`.

    `subject_resolver` finds the signed-in person for the browser pages, from a bearer or
    the refresh cookie; a device access token is never accepted there, so a CLI session
    cannot approve another device. The approval POST must carry an `Origin` equal to the
    issuer's, and revoking a login from `/device/grants` one equal to the issuer's or
    `frontend_base_url`'s, so no other site can drive either through an ambient cookie.
    Raises `DeviceGrantKeyMissing` at build time when no master key can be resolved.
    """
    from fastapi import APIRouter
    from fastapi.responses import JSONResponse, RedirectResponse, Response

    _bind_fastapi_request()
    service = DeviceGrantService(settings, hooks, stores, tokens)
    service.require_keys()
    router = APIRouter(tags=["identity", "device-grant"])

    def route_limits(*specs: tuple[str, tuple[int, int], str]) -> list[Any]:
        """The rate limit dependencies for one route."""
        return limits(*specs) if limits is not None else []

    def error_response(exc: OAuthServerError) -> JSONResponse:
        """The flat RFC 6749 error body."""
        return JSONResponse(
            {"error": exc.error, "error_description": exc.description},
            status_code=exc.status,
            headers={"Cache-Control": "no-store"},
        )

    issuer_origin = _origin_of(settings.issuer)
    revoke_origins = {issuer_origin}
    if settings.frontend_base_url:
        revoke_origins.add(_origin_of(settings.frontend_base_url))

    def origin_refused(request: Request, allowed: set[str]) -> JSONResponse | None:
        """A 403 unless the request's `Origin` is one of `allowed`; a missing one is refused too."""
        origin = request.headers.get("origin", "").strip().rstrip("/").lower()
        if origin and origin in allowed:
            return None
        return error_response(
            OAuthServerError("invalid_request", "This request must come from this service's own pages.", status=403)
        )

    def person(request: Request) -> AuthorizationSubject | None:
        """The signed-in person, refusing any credential minted for a client rather than a browser.

        `_claims_from_request`, which the resolver reads through, already refuses a device
        token by audience and by its `grant` and `client_id` claims; the second check here
        keeps that true should a product pass its own resolver.
        """
        from webbpulse.identity.claims import identity_claims, is_browser_session

        try:
            gateway = identity_claims(request)
        except Exception:
            gateway = None
        if gateway is not None and not is_browser_session(gateway, settings.audience):
            return None
        found = subject_resolver(request)
        return found if found is not None and found.user_id else None

    def too_many_lookups(subject: AuthorizationSubject) -> Any:
        """The 429 page for a person who has mistyped too many codes, or `None`."""
        if not service.lookups_exhausted(subject.user_id):
            return None
        return page(
            "Too many attempts",
            _message_markup("Too many attempts", "Too many codes did not match. Wait a few minutes and try again."),
            status=429,
        )

    def is_stale(subject: AuthorizationSubject) -> bool:
        """Whether the sign-in is too old to approve a device login."""
        max_age = int(settings.device_approval_max_age.total_seconds())
        return subject.auth_time <= 0 or int(time.time()) - subject.auth_time > max_age

    def sign_in(user_code: str, *, fresh: bool, status: int) -> Any:
        """Send the browser to sign in and come back to this code, or 401 when no login page is set."""
        login_url = settings.device_login_url or settings.mcp_login_url
        return_param = (
            settings.device_login_return_param if settings.device_login_url else settings.mcp_login_return_param
        )
        if not login_url:
            return JSONResponse(
                {"error": "login_required", "error_description": "Sign in, then open this page again."},
                status_code=401,
                headers={"Cache-Control": "no-store"},
            )
        normalized = normalize_user_code(user_code)
        return_to = f"{settings.issuer}{DEVICE_VERIFY_PATH}"
        if normalized:
            return_to += "?" + urlencode({"user_code": _format_user_code(normalized)})
        extra = {return_param: return_to}
        if fresh:
            extra["prompt"] = "login"
        return RedirectResponse(
            _redirect_with(login_url, extra), status_code=status, headers={"Cache-Control": "no-store"}
        )

    def page(title: str, body: str, *, status: int = 200) -> Any:
        """One device page in the consent screen's theme."""
        return _render_page(settings, consent_theme, title, body, status=status)

    def entry_page(error: str = "", *, status: int = 200) -> Any:
        """The form a person types the code into."""
        return page(
            "Connect a device",
            _entry_markup(f"{prefix}{DEVICE_VERIFY_PATH}", settings.product_name, error),
            status=status,
        )

    @router.post(
        f"{prefix}{DEVICE_CODE_PATH}",
        include_in_schema=False,
        dependencies=route_limits(("device_code", DEVICE_CODE_IP_LIMIT, "ip64")),
    )
    async def device_code(request: Request) -> JSONResponse:
        """Start a device login (RFC 8628 section 3.1)."""
        try:
            body = service.start(await _form_params(request))
        except OAuthServerError as exc:
            return error_response(exc)
        return JSONResponse(body, headers={"Cache-Control": "no-store"})

    @router.post(
        f"{prefix}{DEVICE_TOKEN_PATH}",
        include_in_schema=False,
        dependencies=route_limits(("device_token", DEVICE_TOKEN_IP_LIMIT, "ip64")),
    )
    async def device_token(request: Request) -> JSONResponse:
        """Poll a device code, or rotate a device refresh token."""
        params = await _form_params(request)
        grant_type = params.get("grant_type", "")
        try:
            if grant_type == DEVICE_CODE_GRANT_TYPE:
                body = service.poll(params)
            elif grant_type == "refresh_token":
                body = service.refresh(params)
            else:
                raise OAuthServerError(
                    "unsupported_grant_type", f"grant_type must be '{DEVICE_CODE_GRANT_TYPE}' or 'refresh_token'."
                )
        except OAuthServerError as exc:
            return error_response(exc)
        return JSONResponse(body, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})

    @router.get(
        f"{prefix}{DEVICE_VERIFY_PATH}",
        include_in_schema=False,
        dependencies=route_limits(("device_verify", DEVICE_VERIFY_IP_LIMIT, "ip64")),
    )
    async def device_verify(request: Request) -> Any:
        """Show the code entry form, or the approval page for a code already typed."""
        user_code = request.query_params.get("user_code", "")
        subject = person(request)
        if subject is None or is_stale(subject):
            return sign_in(user_code, fresh=subject is not None, status=302)
        if not user_code:
            return entry_page()
        limited = too_many_lookups(subject)
        if limited is not None:
            return limited
        approval = service.pending(user_code, subject.user_id)
        if approval is None:
            service.note_failed_lookup(subject.user_id)
            return entry_page("That code is not valid, has expired or has already been used.", status=404)
        if not approval.scopes:
            return page(
                "Nothing to approve",
                _message_markup(
                    "Nothing to approve",
                    f"Your account does not hold the access {approval.client_name} asked for.",
                ),
                status=403,
            )
        return page(
            f"Connect {approval.client_name}",
            _approval_markup(
                approval,
                action=f"{prefix}{DEVICE_APPROVE_PATH}",
                signature=service.approval_signature(approval, subject.user_id),
                product=settings.product_name,
                account=subject.email or subject.name,
                theme=consent_theme,
            ),
        )

    @router.post(
        f"{prefix}{DEVICE_APPROVE_PATH}",
        include_in_schema=False,
        dependencies=route_limits(("device_verify", DEVICE_VERIFY_IP_LIMIT, "ip64")),
    )
    async def device_approve(request: Request) -> Any:
        """Record the approval or denial, re-checking the origin, the step-up and the signed form."""
        refused = origin_refused(request, {issuer_origin})
        if refused is not None:
            return refused
        params = await _form_params(request)
        user_code = params.get("user_code", "")
        subject = person(request)
        if subject is None or is_stale(subject):
            return sign_in(user_code, fresh=subject is not None, status=303)
        limited = too_many_lookups(subject)
        if limited is not None:
            return limited
        approval = service.pending(user_code, subject.user_id)
        if approval is None:
            service.note_failed_lookup(subject.user_id)
            return entry_page("That code is not valid, has expired or has already been used.", status=404)
        expected = service.approval_signature(approval, subject.user_id)
        if not constant_time_equals(params.get("signature", ""), expected):
            return error_response(
                OAuthServerError("invalid_request", "The approval form did not match the request it approves.")
            )
        allow = params.get("decision", "") == "allow"
        if not service.decide(approval, user_id=subject.user_id, allow=allow, auth_time=subject.auth_time):
            return entry_page("That code is not valid, has expired or has already been used.", status=409)
        if allow:
            return page(
                "Device connected",
                _message_markup(
                    "Device connected",
                    f"{approval.client_name} is signed in. You can close this tab and return to your terminal.",
                ),
            )
        return page("Request denied", _message_markup("Request denied", f"{approval.client_name} was not connected."))

    @router.post(
        f"{prefix}{DEVICE_REVOKE_PATH}",
        include_in_schema=False,
        dependencies=route_limits(("device_token", DEVICE_TOKEN_IP_LIMIT, "ip64")),
    )
    async def device_revoke(request: Request) -> Response:
        """Revoke the grant behind a device refresh token (RFC 7009), always answering 200."""
        params = await _form_params(request)
        service.revoke_token(params.get("token", ""))
        return Response(status_code=200, headers={"Cache-Control": "no-store"})

    @router.get(
        f"{prefix}{DEVICE_GRANTS_PATH}",
        include_in_schema=False,
        dependencies=route_limits(("device_grants", DEVICE_GRANTS_IP_LIMIT, "ip64")),
    )
    async def device_grants(request: Request) -> JSONResponse:
        """The signed-in person's live device logins."""
        subject = person(request)
        if subject is None:
            return error_response(OAuthServerError("login_required", "Sign in first.", status=401))
        return JSONResponse({"grants": service.list_grants(subject.user_id)}, headers={"Cache-Control": "no-store"})

    @router.delete(
        f"{prefix}{DEVICE_GRANTS_PATH}/{{grant_id}}",
        include_in_schema=False,
        dependencies=route_limits(("device_grants", DEVICE_GRANTS_IP_LIMIT, "ip64")),
    )
    async def device_grant_revoke(grant_id: str, request: Request) -> Response:
        """Revoke one of the signed-in person's device logins."""
        refused = origin_refused(request, revoke_origins)
        if refused is not None:
            return refused
        subject = person(request)
        if subject is None:
            return error_response(OAuthServerError("login_required", "Sign in first.", status=401))
        if not service.revoke_grant(grant_id, user_id=subject.user_id):
            return error_response(OAuthServerError("not_found", "No such device login.", status=404))
        return Response(status_code=204)

    return router


def _origin_of(url: str) -> str:
    """The `scheme://host[:port]` origin of a URL, lower-cased, as a browser sends it in `Origin`."""
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}".lower()


_DEVICE_CSS: Final = (
    ".field{display:block;width:100%;margin:0 0 16px;padding:10px 12px;border-radius:8px;"
    "border:1px solid var(--line-strong);background:var(--surface);color:var(--text);"
    "font:600 20px/28px ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.18em;text-align:center;"
    "text-transform:uppercase}"
    ".field:focus{outline:2px solid var(--ring);outline-offset:1px}"
    ".code{display:block;margin:0 0 20px;padding:12px;border-radius:8px;border:1px solid var(--line);"
    "background:var(--surface);font:600 22px/28px ui-monospace,SFMono-Regular,Menlo,monospace;"
    "letter-spacing:.18em;text-align:center}"
    ".error{color:var(--danger);margin:0 0 12px}"
    ".actions.single{grid-template-columns:1fr}"
)


def _render_page(
    settings: IdentitySettings, theme: ConsentTheme | None, title: str, body: str, *, status: int = 200
) -> Any:
    """Wrap device page markup in the consent screen's shell, styles and security headers."""
    from fastapi.responses import HTMLResponse

    from webbpulse.identity.consent_page import (
        ConsentTheme as _Theme,
    )
    from webbpulse.identity.consent_page import (
        _escape,
        _product_tile,
        _stylesheet,
    )

    resolved = theme or _Theme()
    nonce = secrets.token_urlsafe(18)
    product = settings.product_name or "this app"
    scheme = resolved.color_scheme
    markup = f"""<!doctype html>
<html lang="en" data-scheme="{scheme}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="color-scheme" content="{"light dark" if scheme == "system" else scheme}">
<title>{_escape(title)}</title>
<style nonce="{nonce}">{_stylesheet(resolved)}{_DEVICE_CSS}</style></head>
<body><main class="shell"><div class="column">
<div class="marks" aria-hidden="true">{_product_tile(product, resolved)}</div>
{body}
</div></main></body></html>"""
    from webbpulse.identity.consent_page import _DATA_FONT, _DATA_IMAGE, _asset_source, _logos

    images = sorted({_asset_source(url, data_pattern=_DATA_IMAGE, what="logo") for url in _logos(resolved)})
    fonts = sorted({_asset_source(face.src, data_pattern=_DATA_FONT, what="font") for face in resolved.font_faces})
    directives = ["default-src 'none'", f"style-src 'nonce-{nonce}'"]
    if images:
        directives.append(f"img-src {' '.join(images)}")
    if fonts:
        directives.append(f"font-src {' '.join(fonts)}")
    directives += ["form-action 'self'", "frame-ancestors 'none'", "base-uri 'none'"]
    return HTMLResponse(
        markup,
        status_code=status,
        headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": "; ".join(directives),
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        },
    )


def _entry_markup(action: str, product_name: str, error: str) -> str:
    """The code entry form."""
    from webbpulse.identity.consent_page import _escape

    product = product_name or "this app"
    problem = f'<p class="error" role="alert">{_escape(error)}</p>' if error else ""
    return f"""<h1>Connect a device</h1>
<p class="lede">Enter the code your terminal is showing to sign it in to {_escape(product)}.</p>
<form method="get" action="{_escape(action)}">
{problem}<input class="field" name="user_code" autocomplete="off" autocapitalize="characters" spellcheck="false"
 inputmode="text" maxlength="12" placeholder="XXXX-XXXX" aria-label="Device code" required autofocus>
<div class="actions single"><button class="primary" type="submit">Continue</button></div>
</form>"""


def _message_markup(title: str, message: str) -> str:
    """A result page's heading and message."""
    from webbpulse.identity.consent_page import _escape

    return f'<h1>{_escape(title)}</h1><p class="lede">{_escape(message)}</p>'


def _approval_markup(
    approval: DeviceApproval,
    *,
    action: str,
    signature: str,
    product: str,
    account: str,
    theme: ConsentTheme | None,
) -> str:
    """The approval form: the code to compare, the account, the scopes and the two buttons."""
    from webbpulse.identity.consent_page import _escape, describe_scopes

    labels = theme.scope_labels if theme is not None else None
    rows = _scope_rows(describe_scopes(approval.scopes, labels))
    signed_in = f'<p class="fine">Signed in as <strong>{_escape(account)}</strong>.</p>' if account else ""
    revoke = f" {_escape(theme.revoke_note)}" if theme is not None and theme.revoke_note else ""
    return f"""<h1>Connect {_escape(approval.client_name)}</h1>
<p class="lede">Check this code matches the one in your terminal before you allow it.</p>
<span class="code">{_escape(approval.user_code)}</span>
{signed_in}
<form method="post" action="{_escape(action)}">
<input type="hidden" name="user_code" value="{_escape(approval.user_code)}">
<input type="hidden" name="signature" value="{_escape(signature)}">
<section class="section" aria-labelledby="perms-label"><h2 class="label" id="perms-label">
{_escape(approval.client_name)} will be able to</h2><div class="perms">{rows}</div></section>
<div class="actions">
<button class="primary" type="submit" name="decision" value="allow">Allow access</button>
<button class="secondary" type="submit" name="decision" value="deny">Deny</button>
</div>
<p class="fine">Only allow this if you started the sign-in yourself. Anyone holding this code could
otherwise act as you in {_escape(product or "this app")}.{revoke}</p>
</form>"""


def _scope_rows(groups: Iterable[Any]) -> str:
    """The grouped scope list, in the consent screen's markup."""
    from webbpulse.identity.consent_page import _READ_ICON, _WRITE_ICON, _escape

    parts: list[str] = []
    for group in groups:
        icon = _READ_ICON if group.access == "read" else _WRITE_ICON
        rows = "".join(
            f'<li class="perm">{icon}<div><div class="what">{_escape(row.label)}</div>'
            + (f'<div class="detail">{_escape(row.detail)}</div>' if row.detail else "")
            + "</div></li>"
            for row in group.rows
        )
        parts.append(f'<div class="group"><p class="group-title">{_escape(group.title)}</p><ul>{rows}</ul></div>')
    return "".join(parts)
