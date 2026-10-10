"""Tests for the browser to desktop session handoff: settings, the service and both routes."""

from __future__ import annotations

import dataclasses
import logging
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from webbpulse.identity import (
    DESKTOP_HANDOFF_EXCHANGE_PATH,
    DESKTOP_HANDOFF_PATH,
    HANDOFF_PURPOSE,
    AuthenticationRefused,
    BaseIdentityHooks,
    DesktopHandoffService,
    HandoffRejected,
    IdentitySettings,
    IdentityStores,
    InMemoryCredentialStore,
    InMemoryIdentityTokenStore,
    InMemoryRefreshTokenStore,
    IdentityTokenRecord,
    TokenService,
    build_identity_router,
    identity_prefix,
    normalise_scheme,
)
from webbpulse.identity.mfa import AMR_MFA, AMR_OTP, AMR_PASSWORD
from webbpulse.identity.oauth import new_pkce_verifier, pkce_challenge
from webbpulse.identity.sessions import SessionService
from webbpulse.identity.storage import hash_token

KEY_A = "arn:aws:kms:us-west-2:111122223333:key/aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa"
ISSUER = "https://api.staging.example.com/api/auth"
AUDIENCE = "webbpulse-staging"
SCHEME = "exampleapp"
STAGING_SCHEME = "exampleapp-staging"
USER = "user-abc"


class Hooks(BaseIdentityHooks):
    """Hooks where every user loads and may sign in unless a test says otherwise."""

    def __init__(self) -> None:
        """Start with no removed or refused users."""
        self.gone: set[str] = set()
        self.refused: set[str] = set()

    def load_user_by_id(self, user_id: str) -> dict[str, Any] | None:
        """Every user id resolves unless the test removed it."""
        if user_id in self.gone:
            return None
        return {"id": user_id, "email": "person@example.com", "email_verified": True}

    def claims_for(self, user: Any) -> dict[str, Any]:
        """A product claim, plus an `amr` the flows must overwrite."""
        return {"plan": "pro", "amr": ["forged"]}

    def may_authenticate(self, user: Any) -> None:
        """Refuse a user the test marked as refused."""
        if user["id"] in self.refused:
            raise AuthenticationRefused("This account is disabled.", error_code="ACCOUNT_DISABLED")


def build_settings(**overrides: Any) -> IdentitySettings:
    """An `IdentitySettings` with the handoff on for the two example schemes."""
    values: dict[str, Any] = {
        "environment": "test",
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "signing_key_arns": [KEY_A],
        "desktop_handoff_schemes": [SCHEME, STAGING_SCHEME],
    }
    values.update(overrides)
    return IdentitySettings(**values)


class Harness:
    """An app with the handoff routes mounted, and the stores a test reaches into."""

    def __init__(self, fake_kms: Any, *, with_tokens_store: bool = True, **overrides: Any) -> None:
        """Mount the identity router over in-memory stores."""
        self.settings = build_settings(**overrides)
        self.hooks = Hooks()
        self.refresh_tokens = InMemoryRefreshTokenStore()
        self.identity_tokens = InMemoryIdentityTokenStore()
        self.tokens = TokenService(self.settings, fake_kms)
        self.sessions = SessionService(self.settings, self.refresh_tokens)
        self.prefix = identity_prefix(self.settings)
        app = FastAPI()
        self.app = app
        app.include_router(
            build_identity_router(
                self.settings,
                self.hooks,
                IdentityStores(
                    credentials=InMemoryCredentialStore(),
                    refresh_tokens=self.refresh_tokens,
                    identity_tokens=self.identity_tokens if with_tokens_store else None,
                ),
                tokens=self.tokens,
                limiter_enabled=False,
            )
        )
        self.client = TestClient(app)

    def url(self, path: str) -> str:
        """The mounted path."""
        return f"{self.prefix}{path}"

    def browser(
        self,
        user_id: str = USER,
        *,
        amr: tuple[str, ...] = (AMR_PASSWORD,),
        auth_time: int | None = None,
        **claims: Any,
    ) -> dict[str, str]:
        """A signed-in browser's bearer over a real refresh family that recorded `amr`."""
        moment = int(time.time()) - 600 if auth_time is None else auth_time
        family = self.sessions.start_family(user_id, amr=amr, auth_time=moment)
        token = self.tokens.mint_access_token(
            user_id,
            claims={"auth_time": moment, "amr": list(amr), **claims},
            session_id=family.family_id,
        )
        return {"Authorization": f"Bearer {token}"}

    def mint(self, verifier: str, *, scheme: str = SCHEME, headers: dict[str, str] | None = None) -> Any:
        """Ask the mint route for a code bound to `verifier`'s challenge."""
        return self.client.post(
            self.url(DESKTOP_HANDOFF_PATH),
            json={"code_challenge": pkce_challenge(verifier), "code_challenge_method": "S256", "scheme": scheme},
            headers=self.browser() if headers is None else headers,
        )

    def exchange(self, code: str, verifier: str, *, scheme: str = SCHEME, **headers: str) -> Any:
        """Redeem a code at the exchange route."""
        return self.client.post(
            self.url(DESKTOP_HANDOFF_EXCHANGE_PATH),
            json={"code": code, "code_verifier": verifier, "scheme": scheme},
            headers=headers,
        )

    def code(self, verifier: str, **kwargs: Any) -> str:
        """A freshly minted code."""
        response = self.mint(verifier, **kwargs)
        assert response.status_code == 200, response.text
        return str(response.json()["code"])


@pytest.fixture
def harness(fake_kms: Any) -> Harness:
    """The default harness."""
    return Harness(fake_kms)


class TestSettings:
    """The scheme allowlist and the code lifetime."""

    def test_the_allowlist_is_empty_by_default(self) -> None:
        """No scheme is allowed unless one is configured."""
        settings = build_settings(desktop_handoff_schemes=[])
        assert settings.desktop_handoff_schemes == []
        assert settings.desktop_handoff_code_ttl == timedelta(seconds=60)

    def test_entries_are_normalised(self) -> None:
        """Case, whitespace and a trailing `://` or `:` are dropped."""
        settings = build_settings(desktop_handoff_schemes=[" ExampleApp:// ", "other-app:"])
        assert settings.desktop_handoff_schemes == ["exampleapp", "other-app"]

    def test_the_allowlist_reads_a_json_array_from_the_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """`IDENTITY_DESKTOP_HANDOFF_SCHEMES` is a JSON array, as every list field is."""
        monkeypatch.setenv("IDENTITY_DESKTOP_HANDOFF_SCHEMES", '["exampleapp-staging"]')
        settings = IdentitySettings(environment="test", issuer=ISSUER, audience=AUDIENCE, signing_key_arns=[KEY_A])
        assert settings.desktop_handoff_schemes == ["exampleapp-staging"]

    @pytest.mark.parametrize(
        "scheme", ["https", "http", "javascript", "data", "file", "blob", "about", "ws", "wss", "mailto", "vbscript"]
    )
    def test_web_and_browser_schemes_are_refused(self, scheme: str) -> None:
        """A code must never be sent to a scheme any web page can receive."""
        with pytest.raises(ValidationError, match="web or browser scheme"):
            build_settings(desktop_handoff_schemes=[scheme])

    @pytest.mark.parametrize("scheme", ["", "1app", "my app", "app/x", "app?x", "ünï"])
    def test_malformed_schemes_are_refused(self, scheme: str) -> None:
        """Only an RFC 3986 scheme is accepted."""
        with pytest.raises(ValidationError, match="not a valid URL scheme"):
            build_settings(desktop_handoff_schemes=[scheme])

    def test_a_duplicate_is_refused(self) -> None:
        """Two spellings of one scheme are one scheme listed twice."""
        with pytest.raises(ValidationError, match="twice"):
            build_settings(desktop_handoff_schemes=["exampleapp", "ExampleApp://"])

    @pytest.mark.parametrize("ttl", [timedelta(0), timedelta(seconds=-1), timedelta(minutes=3)])
    def test_the_code_lifetime_is_positive_and_capped(self, ttl: timedelta) -> None:
        """The lifetime cannot be zero, negative or longer than two minutes."""
        with pytest.raises(ValidationError, match="desktop_handoff_code_ttl"):
            build_settings(desktop_handoff_code_ttl=ttl)

    def test_normalise_scheme(self) -> None:
        """The helper matches what the allowlist stores."""
        assert normalise_scheme(" ExampleApp://") == "exampleapp"


class TestMounting:
    """The routes exist only when a scheme is allowlisted."""

    def test_unset_allowlist_leaves_the_routes_unmounted(self, fake_kms: Any) -> None:
        """Fail closed: no allowlist, no handoff."""
        harness = Harness(fake_kms, desktop_handoff_schemes=[])
        verifier = new_pkce_verifier()
        assert harness.mint(verifier).status_code == 404
        assert harness.exchange("x" * 43, verifier).status_code == 404

    def test_no_identity_tokens_store_leaves_the_routes_unmounted(self, fake_kms: Any) -> None:
        """Without the table the codes live in, there is nothing to mount."""
        harness = Harness(fake_kms, with_tokens_store=False)
        assert harness.mint(new_pkce_verifier()).status_code == 404

    def test_the_routes_declare_their_statuses(self, harness: Harness) -> None:
        """The OpenAPI document lists what each route really answers."""
        paths = harness.app.openapi()["paths"]
        mint = paths[harness.url(DESKTOP_HANDOFF_PATH)]["post"]["responses"]
        exchange = paths[harness.url(DESKTOP_HANDOFF_EXCHANGE_PATH)]["post"]["responses"]
        assert {"400", "401", "429"} <= set(mint)
        assert {"400", "403", "429"} <= set(exchange)


class TestMint:
    """`POST /desktop-handoff`."""

    def test_a_signed_in_browser_gets_a_code(self, harness: Harness) -> None:
        """The answer is the code and its lifetime, never cached."""
        response = harness.mint(new_pkce_verifier())
        assert response.status_code == 200, response.text
        body = response.json()
        assert set(body) == {"code", "expires_in"}
        assert body["expires_in"] == 60
        assert len(body["code"]) >= 43
        assert response.headers["cache-control"] == "no-store"

    def test_only_the_hash_is_stored(self, harness: Harness) -> None:
        """The row is keyed by the hash and carries no raw code."""
        verifier = new_pkce_verifier()
        code = harness.code(verifier)
        record = harness.identity_tokens.get(hash_token(code))
        assert record is not None
        assert record.purpose == HANDOFF_PURPOSE
        assert record.user_id == USER
        assert record.attributes["code_challenge"] == pkce_challenge(verifier)
        assert record.attributes["scheme"] == SCHEME
        assert code not in repr(harness.identity_tokens._items)

    def test_the_code_expires_after_the_configured_lifetime(self, harness: Harness) -> None:
        """About sixty seconds from now."""
        code = harness.code(new_pkce_verifier())
        record = harness.identity_tokens.get(hash_token(code))
        assert record is not None
        assert abs(record.expires_at - (int(time.time()) + 60)) <= 2

    def test_an_unauthenticated_mint_is_refused(self, harness: Harness) -> None:
        """No bearer, no code."""
        response = harness.mint(new_pkce_verifier(), headers={})
        assert response.status_code == 401
        assert response.json()["error_code"] == "NOT_AUTHENTICATED"
        assert harness.identity_tokens._items == {}

    def test_a_token_for_another_audience_is_refused(self, harness: Harness) -> None:
        """A device or client token is not a browser session."""
        token = harness.tokens.mint_access_token(USER, claims={"client_id": "cli"})
        response = harness.mint(new_pkce_verifier(), headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401

    @pytest.mark.parametrize("scheme", ["otherapp", "https", "javascript", ""])
    def test_an_unknown_scheme_is_refused(self, harness: Harness, scheme: str) -> None:
        """Only an allowlisted scheme gets a code."""
        response = harness.mint(new_pkce_verifier(), scheme=scheme)
        assert response.status_code == 400
        assert response.json()["error_code"] == "HANDOFF_SCHEME_NOT_ALLOWED"
        assert harness.identity_tokens._items == {}

    def test_the_scheme_is_matched_after_normalising(self, harness: Harness) -> None:
        """`ExampleApp://` is the allowlisted `exampleapp`."""
        assert harness.mint(new_pkce_verifier(), scheme="ExampleApp://").status_code == 200

    def test_plain_pkce_is_refused(self, harness: Harness) -> None:
        """Only S256."""
        verifier = new_pkce_verifier()
        response = harness.client.post(
            harness.url(DESKTOP_HANDOFF_PATH),
            json={"code_challenge": verifier, "code_challenge_method": "plain", "scheme": SCHEME},
            headers=harness.browser(),
        )
        assert response.status_code == 400
        assert response.json()["error_code"] == "HANDOFF_INVALID_REQUEST"

    @pytest.mark.parametrize("challenge", ["", "short", "a" * 44, "+" * 43])
    def test_a_malformed_challenge_is_refused(self, harness: Harness, challenge: str) -> None:
        """A challenge must be 43 base64url characters, the shape of a SHA-256."""
        response = harness.client.post(
            harness.url(DESKTOP_HANDOFF_PATH),
            json={"code_challenge": challenge, "code_challenge_method": "S256", "scheme": SCHEME},
            headers=harness.browser(),
        )
        assert response.status_code == 400
        assert response.json()["error_code"] == "HANDOFF_INVALID_REQUEST"


class TestExchange:
    """`POST /desktop-handoff/exchange`."""

    def test_the_exchange_issues_a_sign_in_session(self, harness: Harness) -> None:
        """A body like `POST /login`, the refresh cookie, and a token for the session audience."""
        verifier = new_pkce_verifier()
        response = harness.exchange(harness.code(verifier), verifier)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["token_type"] == "Bearer"
        assert body["expires_in"] == int(harness.settings.access_token_ttl.total_seconds())
        assert "refresh_token" not in body
        assert f"{harness.settings.cookie_name}=" in response.headers["set-cookie"]
        claims = harness.tokens.verify_access_token(body["access_token"], audience=AUDIENCE)
        assert claims["sub"] == USER
        assert claims["plan"] == "pro"

    def test_the_desktop_session_is_its_own_family(self, harness: Harness) -> None:
        """A new family, so signing the desktop out leaves the browser signed in."""
        verifier = new_pkce_verifier()
        headers = harness.browser()
        browser_sid = harness.tokens.verify_access_token(
            headers["Authorization"].removeprefix("Bearer "), audience=AUDIENCE
        )["sid"]
        code = harness.code(verifier, headers=headers)
        body = harness.exchange(code, verifier).json()
        claims = harness.tokens.verify_access_token(body["access_token"], audience=AUDIENCE)
        assert claims["sid"] and claims["sid"] != browser_sid

    def test_the_mfa_level_carries_over(self, harness: Harness) -> None:
        """A session that signed in with two factors hands over two factors and `mfa`."""
        verifier = new_pkce_verifier()
        signed_in = int(time.time()) - 1200
        headers = harness.browser(amr=(AMR_PASSWORD, AMR_OTP), auth_time=signed_in)
        body = harness.exchange(harness.code(verifier, headers=headers), verifier).json()
        claims = harness.tokens.verify_access_token(body["access_token"], audience=AUDIENCE)
        assert AMR_OTP in claims["amr"]
        assert AMR_MFA in claims["amr"]
        assert "forged" not in claims["amr"]
        assert claims["auth_time"] == signed_in

    def test_a_single_factor_session_does_not_gain_mfa(self, harness: Harness) -> None:
        """The level is carried, never raised."""
        verifier = new_pkce_verifier()
        body = harness.exchange(harness.code(verifier), verifier).json()
        claims = harness.tokens.verify_access_token(body["access_token"], audience=AUDIENCE)
        assert claims["amr"] == [AMR_PASSWORD]

    def test_the_new_family_records_the_amr(self, harness: Harness) -> None:
        """A refresh of the desktop session keeps the MFA level too."""
        verifier = new_pkce_verifier()
        headers = harness.browser(amr=(AMR_PASSWORD, AMR_OTP))
        body = harness.exchange(harness.code(verifier, headers=headers), verifier).json()
        sid = harness.tokens.verify_access_token(body["access_token"], audience=AUDIENCE)["sid"]
        assert harness.sessions.family_amr(sid) == (AMR_PASSWORD, AMR_OTP)

    def test_a_replay_is_refused(self, harness: Harness) -> None:
        """A code is spent by its first exchange."""
        verifier = new_pkce_verifier()
        code = harness.code(verifier)
        assert harness.exchange(code, verifier).status_code == 200
        replay = harness.exchange(code, verifier)
        assert replay.status_code == 400
        assert replay.json()["error_code"] == "HANDOFF_INVALID"

    def test_an_expired_code_is_refused(self, harness: Harness) -> None:
        """Expiry is checked in code, not left to the table's TTL."""
        verifier = new_pkce_verifier()
        code = harness.code(verifier)
        key = hash_token(code)
        record = harness.identity_tokens._items[key]
        harness.identity_tokens._items[key] = dataclasses.replace(record, expires_at=int(time.time()) - 1)
        response = harness.exchange(code, verifier)
        assert response.status_code == 400
        assert response.json()["error_code"] == "HANDOFF_INVALID"

    def test_a_wrong_verifier_is_refused_and_burns_the_code(self, harness: Harness) -> None:
        """A stolen code without its verifier is worthless, and gets one try."""
        verifier = new_pkce_verifier()
        code = harness.code(verifier)
        wrong = harness.exchange(code, new_pkce_verifier())
        assert wrong.status_code == 400
        assert wrong.json()["error_code"] == "HANDOFF_INVALID"
        assert harness.exchange(code, verifier).status_code == 400

    @pytest.mark.parametrize("verifier", ["", "short", "a" * 129, "é" * 43, "a b" * 20])
    def test_a_malformed_verifier_is_refused(self, harness: Harness, verifier: str) -> None:
        """Only an RFC 7636 verifier is hashed."""
        code = harness.code(new_pkce_verifier())
        response = harness.exchange(code, verifier)
        assert response.status_code == 400
        assert response.json()["error_code"] == "HANDOFF_INVALID"

    def test_a_different_allowlisted_scheme_is_refused(self, harness: Harness) -> None:
        """A code minted for one app cannot be redeemed as another."""
        verifier = new_pkce_verifier()
        code = harness.code(verifier, scheme=SCHEME)
        response = harness.exchange(code, verifier, scheme=STAGING_SCHEME)
        assert response.status_code == 400
        assert response.json()["error_code"] == "HANDOFF_INVALID"

    def test_an_unknown_scheme_is_refused(self, harness: Harness) -> None:
        """An exchange naming a scheme off the allowlist fails."""
        verifier = new_pkce_verifier()
        response = harness.exchange(harness.code(verifier), verifier, scheme="otherapp")
        assert response.status_code == 400

    def test_an_unknown_code_is_refused(self, harness: Harness) -> None:
        """A guessed code answers like every other failure."""
        response = harness.exchange("A" * 43, new_pkce_verifier())
        assert response.status_code == 400
        assert response.json()["error_code"] == "HANDOFF_INVALID"

    def test_another_purpose_cannot_be_redeemed(self, harness: Harness) -> None:
        """An email link's token is not a handoff code."""
        harness.identity_tokens.put(
            IdentityTokenRecord(
                token_hash=hash_token("email-link-token"),
                purpose="verify_email",
                user_id=USER,
                created_at="2026-10-09T00:00:00Z",
                expires_at=int(time.time()) + 600,
            )
        )
        assert harness.exchange("email-link-token", new_pkce_verifier()).status_code == 400

    def test_a_refused_user_cannot_redeem(self, harness: Harness) -> None:
        """`may_authenticate` runs again on the exchange."""
        verifier = new_pkce_verifier()
        code = harness.code(verifier)
        harness.hooks.refused.add(USER)
        response = harness.exchange(code, verifier)
        assert response.status_code == 403
        assert response.json()["error_code"] == "ACCOUNT_DISABLED"

    def test_a_deleted_user_cannot_redeem(self, harness: Harness) -> None:
        """A user who no longer loads gets the generic refusal."""
        verifier = new_pkce_verifier()
        code = harness.code(verifier)
        harness.hooks.gone.add(USER)
        assert harness.exchange(code, verifier).status_code == 400

    def test_a_cross_site_request_is_refused(self, harness: Harness) -> None:
        """The exchange sets the refresh cookie, so it refuses a forged cross-site post."""
        verifier = new_pkce_verifier()
        code = harness.code(verifier)
        response = harness.exchange(code, verifier, **{"Sec-Fetch-Site": "cross-site"})
        assert response.status_code == 403
        assert harness.exchange(code, verifier).status_code == 200

    def test_the_code_and_verifier_never_reach_a_response_or_the_log(
        self, harness: Harness, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Neither secret is echoed or logged, on success or failure."""
        caplog.set_level(logging.DEBUG)
        verifier = new_pkce_verifier()
        code = harness.code(verifier)
        wrong = new_pkce_verifier()
        failed = harness.exchange(code, wrong)
        second_verifier = new_pkce_verifier()
        second = harness.code(second_verifier)
        ok = harness.exchange(second, second_verifier)
        assert ok.status_code == 200
        for secret in (code, verifier, wrong, second, second_verifier):
            assert secret not in failed.text
            assert secret not in caplog.text
            for log_record in caplog.records:
                assert secret not in repr(log_record.__dict__)
        events = {getattr(log_record, "event", "") for log_record in caplog.records}
        assert {"session.handoff_minted", "session.handoff_exchanged", "session.handoff_exchange_failed"} <= events


class TestService:
    """`DesktopHandoffService` directly, for the cases a route cannot reach."""

    def test_expiry_is_judged_against_now(self) -> None:
        """A code redeemed after its lifetime is refused even though the row still exists."""
        settings = build_settings()
        store = InMemoryIdentityTokenStore()
        service = DesktopHandoffService(settings, store)
        verifier = new_pkce_verifier()
        minted = service.mint(
            USER,
            code_challenge=pkce_challenge(verifier),
            code_challenge_method="S256",
            scheme=SCHEME,
            amr=(AMR_PASSWORD,),
            auth_time=int(time.time()),
            family_id="family-1",
        )
        later = datetime.now(UTC) + timedelta(seconds=61)
        with pytest.raises(HandoffRejected) as refused:
            service.redeem(minted.code, code_verifier=verifier, scheme=SCHEME, now=later)
        assert refused.value.error_code == "HANDOFF_INVALID"
        assert minted.code not in refused.value.message

    def test_a_scheme_removed_from_the_allowlist_stops_redeeming(self) -> None:
        """A code minted before a scheme was withdrawn cannot be spent after."""
        store = InMemoryIdentityTokenStore()
        verifier = new_pkce_verifier()
        minted = DesktopHandoffService(build_settings(), store).mint(
            USER,
            code_challenge=pkce_challenge(verifier),
            code_challenge_method="S256",
            scheme=STAGING_SCHEME,
            amr=(AMR_PASSWORD,),
            auth_time=int(time.time()),
            family_id="family-1",
        )
        narrowed = DesktopHandoffService(build_settings(desktop_handoff_schemes=[SCHEME]), store)
        with pytest.raises(HandoffRejected):
            narrowed.redeem(minted.code, code_verifier=verifier, scheme=STAGING_SCHEME)

    def test_redeem_returns_the_bound_state(self) -> None:
        """The user, `amr`, `auth_time` and scheme come back as minted."""
        store = InMemoryIdentityTokenStore()
        service = DesktopHandoffService(build_settings(), store)
        verifier = new_pkce_verifier()
        minted = service.mint(
            USER,
            code_challenge=pkce_challenge(verifier),
            code_challenge_method="S256",
            scheme=SCHEME,
            amr=(AMR_PASSWORD, AMR_OTP),
            auth_time=1_700_000_000,
            family_id="family-1",
        )
        redeemed = service.redeem(minted.code, code_verifier=verifier, scheme=SCHEME)
        assert redeemed.user_id == USER
        assert redeemed.amr == (AMR_PASSWORD, AMR_OTP)
        assert redeemed.auth_time == 1_700_000_000
        assert redeemed.scheme == SCHEME
        assert redeemed.source_family_id == "family-1"


def test_the_dynamo_store_round_trips_the_attributes(dynamodb_resource: Any) -> None:
    """A handoff row keeps its attributes through DynamoDB, and the consume stays atomic."""
    from webbpulse.dynamodb import Repository
    from webbpulse.identity.storage import DynamoIdentityTokenStore
    from webbpulse.testing import create_table

    create_table(dynamodb_resource, "identity-tokens", hash_key="token_hash", ttl_attribute="expires_at")
    store = DynamoIdentityTokenStore(Repository("identity-tokens", prefix="", region_name="us-west-2"))
    service = DesktopHandoffService(build_settings(), store)
    verifier = new_pkce_verifier()
    minted = service.mint(
        USER,
        code_challenge=pkce_challenge(verifier),
        code_challenge_method="S256",
        scheme=SCHEME,
        amr=(AMR_PASSWORD, AMR_OTP),
        auth_time=1_700_000_000,
        family_id="family-1",
    )
    redeemed = service.redeem(minted.code, code_verifier=verifier, scheme=SCHEME)
    assert redeemed.amr == (AMR_PASSWORD, AMR_OTP)
    assert redeemed.auth_time == 1_700_000_000
    with pytest.raises(HandoffRejected):
        service.redeem(minted.code, code_verifier=verifier, scheme=SCHEME)
    plain = IdentityTokenRecord(
        token_hash=hash_token("plain"),
        purpose="verify_email",
        user_id=USER,
        created_at="2026-10-09T00:00:00Z",
        expires_at=int(time.time()) + 600,
    )
    store.put(plain)
    assert store.get(hash_token("plain")) == plain
