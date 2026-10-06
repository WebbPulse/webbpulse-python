"""Tests for the OAuth device authorization grant: the codes, approval, tokens and revocation."""

from __future__ import annotations

import dataclasses
import re
import socket
import threading
import time
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from webbpulse.e2e.browser import browser_is_available
from webbpulse.identity import (
    DEVICE_APPROVE_PATH,
    DEVICE_CODE_GRANT_TYPE,
    DEVICE_CODE_PATH,
    DEVICE_GRANT_TABLES,
    DEVICE_GRANTS_PATH,
    DEVICE_REVOKE_PATH,
    DEVICE_TOKEN_PATH,
    DEVICE_VERIFY_PATH,
    LOGOUT_ALL_PATH,
    BaseIdentityHooks,
    DeviceGrantService,
    DeviceGrantStores,
    IdentitySettings,
    IdentityStores,
    InMemoryCredentialStore,
    InMemoryDeviceCodeStore,
    InMemoryDeviceGrantStore,
    InMemoryRefreshTokenStore,
    OAuthServerError,
    TokenService,
    build_identity_router,
    device_grant_is_live,
    dynamo_device_grant_stores,
    identity_prefix,
    normalize_user_code,
)
from webbpulse.identity.device_grant import (
    DEVICE_REFRESH_GRACE_SECONDS,
    USER_CODE_ALPHABET,
    DeviceApproval,
    new_user_code,
)
from webbpulse.identity.tokens import DISCOVERY_PATH

KEY_A = "arn:aws:kms:us-west-2:111122223333:key/aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa"
ISSUER = "https://api.staging.example.com/api/auth"
AUDIENCE = "webbpulse-staging"
LOGIN = "https://app.staging.example.com/login"
USER = "user-abc"
OTHER = "user-xyz"
CLIENT = "wp-tf"
MASTER_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
ORIGIN = "https://api.staging.example.com"


class Hooks(BaseIdentityHooks):
    """Hooks whose users hold scopes, so approval and refresh intersect with them."""

    def __init__(self) -> None:
        """Every user holds every scope until a test takes one away."""
        self.held: dict[str, str] = {}
        self.gone: set[str] = set()

    def load_user_by_id(self, user_id: str) -> dict[str, Any] | None:
        """Every user id resolves unless the test removed it."""
        if user_id in self.gone:
            return None
        return {"id": user_id, "email": "person@example.com", "email_verified": True}

    def claims_for(self, user: Any) -> dict[str, Any]:
        """The scopes the user holds, plus a product claim that must survive onto the device token."""
        return {"scope": self.held.get(user["id"], "runs:read runs:plan runs:apply"), "plan": "pro"}

    def may_authenticate(self, user: Any) -> None:
        """Every user who loads may sign in."""


def build_settings(**overrides: Any) -> IdentitySettings:
    """An `IdentitySettings` with the device grant turned on."""
    values: dict[str, Any] = {
        "environment": "test",
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "signing_key_arns": [KEY_A],
        "product_name": "Terraform",
        "device_grant_enabled": True,
        "device_clients": {CLIENT: "wp-tf CLI"},
        "device_scopes_supported": ["runs:read", "runs:plan", "runs:apply", "admin"],
        "device_explicit_scopes": ["runs:apply", "admin"],
        "device_login_url": LOGIN,
        "totp_master_key": MASTER_KEY,
    }
    values.update(overrides)
    return IdentitySettings(**values)


def build_stores() -> DeviceGrantStores:
    """Fresh in-memory device grant stores."""
    return DeviceGrantStores(codes=InMemoryDeviceCodeStore(), grants=InMemoryDeviceGrantStore())


class Harness:
    """An app with the device grant mounted, and the pieces a test reaches into."""

    def __init__(self, fake_kms: Any, **overrides: Any) -> None:
        """Mount the identity router over in-memory stores."""
        self.settings = build_settings(**overrides)
        self.hooks = Hooks()
        self.stores = build_stores()
        self.tokens = TokenService(self.settings, fake_kms)
        self.prefix = identity_prefix(self.settings)
        app = FastAPI()
        app.include_router(
            build_identity_router(
                self.settings,
                self.hooks,
                IdentityStores(credentials=InMemoryCredentialStore(), refresh_tokens=InMemoryRefreshTokenStore()),
                tokens=self.tokens,
                device_grant_stores=self.stores,
                limiter_enabled=False,
            )
        )
        self.client = TestClient(app)

    def url(self, path: str) -> str:
        """The mounted path."""
        return f"{self.prefix}{path}"

    def browser(self, user_id: str = USER, *, auth_time: int | None = None, **claims: Any) -> dict[str, str]:
        """A signed-in browser's bearer, with a recent sign-in unless told otherwise."""
        moment = int(time.time()) if auth_time is None else auth_time
        token = self.tokens.mint_access_token(user_id, claims={"auth_time": moment, **claims})
        return {"Authorization": f"Bearer {token}", "Origin": ORIGIN}

    def start(self, scope: str = "") -> dict[str, Any]:
        """Start a device login as the CLI would."""
        response = self.client.post(self.url(DEVICE_CODE_PATH), data={"client_id": CLIENT, "scope": scope})
        assert response.status_code == 200, response.text
        return dict(response.json())

    def approval_form(self, user_code: str, headers: dict[str, str]) -> dict[str, str]:
        """The hidden fields of the approval page for a code."""
        page = self.client.get(self.url(DEVICE_VERIFY_PATH), params={"user_code": user_code}, headers=headers)
        assert page.status_code == 200, page.text
        return dict(re.findall(r'name="(user_code|signature)" value="([^"]*)"', page.text))

    def decide(self, user_code: str, decision: str = "allow", headers: dict[str, str] | None = None) -> Any:
        """Open the approval page and submit it."""
        headers = headers or self.browser()
        form = self.approval_form(user_code, headers)
        form["decision"] = decision
        return self.client.post(self.url(DEVICE_APPROVE_PATH), data=form, headers=headers, follow_redirects=False)

    def poll(self, device_code: str, client_id: str = CLIENT) -> Any:
        """One poll of the token endpoint, clearing the pacing stamp so tests need not wait."""
        self._unpace(device_code)
        return self.client.post(
            self.url(DEVICE_TOKEN_PATH),
            data={"grant_type": DEVICE_CODE_GRANT_TYPE, "device_code": device_code, "client_id": client_id},
        )

    def _unpace(self, device_code: str) -> None:
        """Forget the last poll time, so a test can poll back to back without tripping `slow_down`."""
        from webbpulse.identity.storage import hash_token

        codes = self.stores.codes
        assert isinstance(codes, InMemoryDeviceCodeStore)
        key = hash_token(device_code)
        record = codes._items.get(key)
        if record is not None:
            codes._items[key] = dataclasses.replace(record, last_polled_at=0)

    def _unpace_all(self) -> None:
        """Forget every request's last poll time."""
        codes = self.stores.codes
        assert isinstance(codes, InMemoryDeviceCodeStore)
        for key, record in list(codes._items.items()):
            codes._items[key] = dataclasses.replace(record, last_polled_at=0)

    def refresh(self, refresh_token: str, client_id: str = CLIENT) -> Any:
        """Rotate a refresh token."""
        return self.client.post(
            self.url(DEVICE_TOKEN_PATH),
            data={"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": client_id},
        )

    def login(self, scope: str = "") -> dict[str, Any]:
        """A full, approved device login, answering the first token response."""
        started = self.start(scope)
        assert self.decide(started["user_code"]).status_code == 200
        response = self.poll(started["device_code"])
        assert response.status_code == 200, response.text
        return dict(response.json())

    def grant(self, grant_id: str) -> Any:
        """The stored grant."""
        return self.stores.grants.get(grant_id)


def _age_rotation(harness: Harness, grant_id: str) -> None:
    """Move the last rotation outside the grace window."""
    grants = harness.stores.grants
    record = grants._items[grant_id]  # type: ignore[attr-defined]
    grants._items[grant_id] = dataclasses.replace(  # type: ignore[attr-defined]
        record, rotated_at=record.rotated_at - DEVICE_REFRESH_GRACE_SECONDS - 5
    )


@pytest.fixture
def harness(fake_kms: Any) -> Harness:
    """The default harness."""
    return Harness(fake_kms)


def _grant_id(body: dict[str, Any]) -> str:
    """The grant id inside a device refresh token."""
    return str(body["refresh_token"]).removeprefix("wpdr_").split(".", 1)[0]


class TestUserCodes:
    """User codes are short, unambiguous and forgiving to type."""

    def test_a_user_code_uses_only_the_unambiguous_alphabet(self) -> None:
        """Eight consonants in two groups: no digits, no vowels."""
        for _ in range(50):
            code = new_user_code()
            assert re.fullmatch(r"[A-Z]{4}-[A-Z]{4}", code)
            assert set(code.replace("-", "")) <= set(USER_CODE_ALPHABET)
            assert not set(code) & set("AEIOU01")

    def test_typing_is_forgiving(self) -> None:
        """Case, dashes and spaces do not matter."""
        assert normalize_user_code("bcdf-ghjk") == "BCDFGHJK"
        assert normalize_user_code(" BCDF GHJK ") == "BCDFGHJK"

    @pytest.mark.parametrize("typed", ["", "BCDF-GHJ", "BCDF-GHJKL", "ABCD-EFGH", "BCD0-GHJK"])
    def test_an_impossible_code_normalizes_to_nothing(self, typed: str) -> None:
        """A code of the wrong length or with a letter outside the alphabet never reaches a lookup."""
        assert normalize_user_code(typed) == ""


class TestStart:
    """`/device/code`."""

    def test_a_start_answers_rfc_8628(self, harness: Harness) -> None:
        """The response carries everything section 3.2 requires, and the verification URL on the issuer."""
        body = harness.start()
        assert set(body) == {
            "device_code",
            "user_code",
            "verification_uri",
            "verification_uri_complete",
            "expires_in",
            "interval",
        }
        assert body["verification_uri"] == f"{ISSUER}/device"
        assert body["verification_uri_complete"].startswith(f"{ISSUER}/device?user_code=")
        assert body["expires_in"] == 600
        assert body["interval"] == 5

    def test_the_default_scopes_leave_out_the_explicit_ones(self, harness: Harness) -> None:
        """Apply and admin must be asked for by name."""
        started = harness.start()
        record = next(iter(harness.stores.codes._items.values()))  # type: ignore[attr-defined]
        assert record.scopes == ("runs:read", "runs:plan")
        assert started["device_code"] not in str(record)

    def test_an_explicit_scope_is_granted_when_named(self, harness: Harness) -> None:
        """Naming apply is enough to request it."""
        body = harness.login("runs:read runs:apply")
        assert body["scope"] == "runs:read runs:apply"

    def test_an_unknown_client_is_refused(self, harness: Harness) -> None:
        """Only registered device clients may start."""
        response = harness.client.post(harness.url(DEVICE_CODE_PATH), data={"client_id": "stranger"})
        assert response.status_code == 401
        assert response.json()["error"] == "invalid_client"

    def test_an_unsupported_scope_is_refused(self, harness: Harness) -> None:
        """A scope outside the supported list is refused, not narrowed."""
        response = harness.client.post(
            harness.url(DEVICE_CODE_PATH), data={"client_id": CLIENT, "scope": "runs:read billing:write"}
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_scope"

    def test_the_endpoint_is_in_discovery(self, harness: Harness) -> None:
        """Clients find the device endpoint in the OpenID discovery document."""
        body = harness.client.get(harness.url(DISCOVERY_PATH)).json()
        assert body["device_authorization_endpoint"] == f"{ISSUER}/device/code"

    def test_the_grant_is_off_by_default(self, fake_kms: Any) -> None:
        """Without the flag nothing is mounted and discovery does not advertise it."""
        settings = IdentitySettings(environment="test", issuer=ISSUER, audience=AUDIENCE, signing_key_arns=[KEY_A])
        app = FastAPI()
        app.include_router(
            build_identity_router(
                settings,
                Hooks(),
                IdentityStores(credentials=InMemoryCredentialStore(), refresh_tokens=InMemoryRefreshTokenStore()),
                tokens=TokenService(settings, fake_kms),
                device_grant_stores=build_stores(),
                limiter_enabled=False,
            )
        )
        client = TestClient(app)
        prefix = identity_prefix(settings)
        assert client.post(f"{prefix}{DEVICE_CODE_PATH}", data={"client_id": CLIENT}).status_code in {404, 405}
        assert "device_authorization_endpoint" not in client.get(f"{prefix}{DISCOVERY_PATH}").json()


class TestPolling:
    """`/device/token` with the device code grant."""

    def test_pending_until_approved(self, harness: Harness) -> None:
        """A poll before approval answers `authorization_pending`."""
        started = harness.start()
        response = harness.poll(started["device_code"])
        assert response.status_code == 400
        assert response.json()["error"] == "authorization_pending"

    def test_polling_too_fast_answers_slow_down_and_raises_the_interval(self, harness: Harness) -> None:
        """A second poll inside the interval is `slow_down`, and the interval grows by five seconds."""
        from webbpulse.identity.storage import hash_token

        started = harness.start()
        data = {"grant_type": DEVICE_CODE_GRANT_TYPE, "device_code": started["device_code"], "client_id": CLIENT}
        first = harness.client.post(harness.url(DEVICE_TOKEN_PATH), data=data)
        second = harness.client.post(harness.url(DEVICE_TOKEN_PATH), data=data)
        assert first.json()["error"] == "authorization_pending"
        assert second.json()["error"] == "slow_down"
        record = harness.stores.codes.get(hash_token(started["device_code"]))
        assert record is not None and record.interval == 10

    def test_an_expired_code_answers_expired_token(self, harness: Harness) -> None:
        """Once past its life the device code is gone."""
        from webbpulse.identity.storage import hash_token

        started = harness.start()
        codes = harness.stores.codes
        key = hash_token(started["device_code"])
        codes._items[key] = dataclasses.replace(codes._items[key], expires_at=int(time.time()) - 1)  # type: ignore[attr-defined]
        response = harness.poll(started["device_code"])
        assert response.json()["error"] == "expired_token"

    def test_an_expired_code_cannot_be_approved(self, harness: Harness) -> None:
        """The approval page refuses a code past its life."""
        started = harness.start()
        codes = harness.stores.codes
        key = next(iter(codes._items))  # type: ignore[attr-defined]
        codes._items[key] = dataclasses.replace(codes._items[key], expires_at=int(time.time()) - 1)  # type: ignore[attr-defined]
        page = harness.client.get(
            harness.url(DEVICE_VERIFY_PATH), params={"user_code": started["user_code"]}, headers=harness.browser()
        )
        assert page.status_code == 404

    def test_an_unknown_device_code_answers_invalid_grant(self, harness: Harness) -> None:
        """An invented device code is `invalid_grant`."""
        response = harness.poll("not-a-real-device-code")
        assert response.json()["error"] == "invalid_grant"

    def test_another_client_cannot_collect_the_code(self, harness: Harness) -> None:
        """The device code is bound to the client that started it."""
        started = harness.start()
        harness.decide(started["user_code"])
        response = harness.poll(started["device_code"], client_id="another")
        assert response.json()["error"] == "invalid_grant"

    def test_a_denial_answers_access_denied(self, harness: Harness) -> None:
        """Declining in the browser ends the login."""
        started = harness.start()
        page = harness.decide(started["user_code"], "deny")
        assert page.status_code == 200
        assert "Request denied" in page.text
        response = harness.poll(started["device_code"])
        assert response.json()["error"] == "access_denied"
        assert harness.poll(started["device_code"]).json()["error"] == "invalid_grant"
        assert not harness.stores.grants._items  # type: ignore[attr-defined]

    def test_an_approved_code_is_collected_once(self, harness: Harness) -> None:
        """The second collection of the same device code finds nothing."""
        started = harness.start()
        harness.decide(started["user_code"])
        assert harness.poll(started["device_code"]).status_code == 200
        again = harness.poll(started["device_code"])
        assert again.json()["error"] == "invalid_grant"

    def test_a_consume_race_is_invalid_grant(self, harness: Harness, fake_kms: Any) -> None:
        """When another poll consumed the code in between, the loser gets `invalid_grant`."""
        service = DeviceGrantService(harness.settings, harness.hooks, harness.stores, harness.tokens)
        started = service.start({"client_id": CLIENT})
        approval = service.pending(started["user_code"], USER)
        assert approval is not None
        assert service.decide(approval, user_id=USER, allow=True, auth_time=int(time.time()))
        original = harness.stores.codes.consume
        harness.stores.codes.consume = lambda code_hash, **kwargs: (original(code_hash, **kwargs), None)[1]  # type: ignore[method-assign]
        with pytest.raises(OAuthServerError) as caught:
            service.poll({"device_code": started["device_code"], "client_id": CLIENT})
        assert caught.value.error == "invalid_grant"

    def test_an_unknown_grant_type_is_refused(self, harness: Harness) -> None:
        """Only the two grant types this endpoint serves."""
        response = harness.client.post(harness.url(DEVICE_TOKEN_PATH), data={"grant_type": "password"})
        assert response.json()["error"] == "unsupported_grant_type"


class TestApproval:
    """The browser pages: entry, approval, the step-up and the signed form."""

    def test_the_page_needs_a_signed_in_person(self, harness: Harness) -> None:
        """Anonymous visitors go to the product login and come back to the code."""
        started = harness.start()
        response = harness.client.get(
            harness.url(DEVICE_VERIFY_PATH), params={"user_code": started["user_code"]}, follow_redirects=False
        )
        assert response.status_code == 302
        location = response.headers["location"]
        assert location.startswith(LOGIN)
        assert "returnTo=" in location
        assert "prompt=login" not in location

    def test_without_a_login_url_the_page_answers_login_required(self, fake_kms: Any) -> None:
        """With nowhere to send the browser, the page says so."""
        harness = Harness(fake_kms, device_login_url="")
        response = harness.client.get(harness.url(DEVICE_VERIFY_PATH), follow_redirects=False)
        assert response.status_code == 401
        assert response.json()["error"] == "login_required"

    def test_a_stale_sign_in_is_sent_to_log_in_again(self, harness: Harness) -> None:
        """Approval is a step-up: an old sign-in goes back through login with `prompt=login`."""
        started = harness.start()
        stale = harness.browser(auth_time=int(time.time()) - 3600)
        response = harness.client.get(
            harness.url(DEVICE_VERIFY_PATH),
            params={"user_code": started["user_code"]},
            headers=stale,
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert "prompt=login" in response.headers["location"]

    def test_a_stale_sign_in_cannot_post_an_approval(self, harness: Harness) -> None:
        """The step-up is checked again on the post, not only on the page."""
        started = harness.start()
        form = harness.approval_form(started["user_code"], harness.browser())
        form["decision"] = "allow"
        response = harness.client.post(
            harness.url(DEVICE_APPROVE_PATH),
            data=form,
            headers=harness.browser(auth_time=int(time.time()) - 3600),
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "prompt=login" in response.headers["location"]
        assert harness.poll(started["device_code"]).json()["error"] == "authorization_pending"

    def test_the_entry_form_shows_without_a_code(self, harness: Harness) -> None:
        """A signed-in person with no code sees the form to type one."""
        page = harness.client.get(harness.url(DEVICE_VERIFY_PATH), headers=harness.browser())
        assert page.status_code == 200
        assert 'name="user_code"' in page.text
        assert "form-action 'self'" in page.headers["content-security-policy"]
        assert page.headers["x-frame-options"] == "DENY"
        assert page.headers["cache-control"] == "no-store"
        assert page.headers["referrer-policy"] == "same-origin"

    def test_a_wrong_code_is_refused(self, harness: Harness) -> None:
        """A code no request holds shows the entry form again with an error."""
        harness.start()
        page = harness.client.get(
            harness.url(DEVICE_VERIFY_PATH), params={"user_code": "BCDF-GHJK"}, headers=harness.browser()
        )
        assert page.status_code == 404
        assert "not valid" in page.text

    def test_a_used_code_is_refused(self, harness: Harness) -> None:
        """Once decided, the user code no longer opens an approval page or accepts a second decision."""
        started = harness.start()
        headers = harness.browser()
        form = harness.approval_form(started["user_code"], headers)
        form["decision"] = "allow"
        first = harness.client.post(harness.url(DEVICE_APPROVE_PATH), data=form, headers=headers)
        assert first.status_code == 200
        assert "Device connected" in first.text
        again = harness.client.post(harness.url(DEVICE_APPROVE_PATH), data=form, headers=headers)
        assert again.status_code == 404
        page = harness.client.get(
            harness.url(DEVICE_VERIFY_PATH), params={"user_code": started["user_code"]}, headers=headers
        )
        assert page.status_code == 404

    def test_a_decide_race_is_a_conflict(self, harness: Harness) -> None:
        """A request decided between the page load and the post answers 409."""
        service = DeviceGrantService(harness.settings, harness.hooks, harness.stores, harness.tokens)
        started = harness.start()
        approval = service.pending(started["user_code"], USER)
        assert approval is not None
        harness.stores.codes.decide = lambda *args, **kwargs: False  # type: ignore[method-assign]
        headers = harness.browser()
        form = harness.approval_form(started["user_code"], headers)
        form["decision"] = "allow"
        response = harness.client.post(harness.url(DEVICE_APPROVE_PATH), data=form, headers=headers)
        assert response.status_code == 409

    def test_the_form_is_bound_to_the_scopes_it_shows(self, harness: Harness) -> None:
        """A signature from one request does not approve another."""
        first = harness.start()
        second = harness.start("runs:read runs:apply")
        headers = harness.browser()
        form = harness.approval_form(first["user_code"], headers)
        form["user_code"] = second["user_code"]
        form["decision"] = "allow"
        response = harness.client.post(harness.url(DEVICE_APPROVE_PATH), data=form, headers=headers)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"

    def test_the_form_is_bound_to_the_person(self, harness: Harness) -> None:
        """A form signed for one person cannot be posted by another."""
        started = harness.start()
        form = harness.approval_form(started["user_code"], harness.browser(USER))
        form["decision"] = "allow"
        response = harness.client.post(harness.url(DEVICE_APPROVE_PATH), data=form, headers=harness.browser(OTHER))
        assert response.status_code == 400

    @pytest.mark.parametrize(
        ("origin", "fetch_site"),
        [
            ("https://evil.example.com", ""),
            ("https://app.staging.example.com", ""),
            ("", ""),
            ("null", ""),
            ("null", "cross-site"),
            ("null", "same-site"),
            ("https://evil.example.com", "same-origin"),
        ],
    )
    def test_an_approval_from_another_origin_is_refused(self, harness: Harness, origin: str, fetch_site: str) -> None:
        """The approval must carry this issuer's own `Origin`; a missing or unvouched null one is refused too."""
        started = harness.start()
        headers = harness.browser()
        form = harness.approval_form(started["user_code"], headers)
        form["decision"] = "allow"
        sent = {key: value for key, value in headers.items() if key != "Origin"}
        if origin:
            sent["Origin"] = origin
        if fetch_site:
            sent["Sec-Fetch-Site"] = fetch_site
        response = harness.client.post(harness.url(DEVICE_APPROVE_PATH), data=form, headers=sent)
        assert response.status_code == 403
        assert harness.poll(started["device_code"]).json()["error"] == "authorization_pending"

    def test_a_null_origin_the_browser_vouches_for_is_accepted(self, harness: Harness) -> None:
        """A form posted under a strict referrer policy sends `Origin: null` with `Sec-Fetch-Site: same-origin`."""
        started = harness.start()
        headers = harness.browser()
        form = harness.approval_form(started["user_code"], headers)
        form["decision"] = "allow"
        sent = {**headers, "Origin": "null", "Sec-Fetch-Site": "same-origin"}
        response = harness.client.post(harness.url(DEVICE_APPROVE_PATH), data=form, headers=sent)
        assert response.status_code == 200
        assert harness.poll(started["device_code"]).status_code == 200

    def test_a_device_token_cannot_approve_another_device(self, harness: Harness) -> None:
        """A CLI session is not a browser: its token is refused on the approval page."""
        body = harness.login()
        started = harness.start()
        response = harness.client.get(
            harness.url(DEVICE_VERIFY_PATH),
            params={"user_code": started["user_code"]},
            headers={"Authorization": f"Bearer {body['access_token']}"},
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert response.headers["location"].startswith(LOGIN)

    def test_the_page_escapes_what_it_shows(self, fake_kms: Any) -> None:
        """A client name with markup in it is shown as text."""
        harness = Harness(fake_kms, device_clients={CLIENT: "<script>x</script>"})
        started = harness.start()
        page = harness.client.get(
            harness.url(DEVICE_VERIFY_PATH), params={"user_code": started["user_code"]}, headers=harness.browser()
        )
        assert "<script>x</script>" not in page.text
        assert "&lt;script&gt;" in page.text

    def test_the_approval_page_never_shows_the_device_code(self, harness: Harness) -> None:
        """Only the user code reaches the browser; the device code stays with the CLI."""
        started = harness.start()
        page = harness.client.get(
            harness.url(DEVICE_VERIFY_PATH), params={"user_code": started["user_code"]}, headers=harness.browser()
        )
        assert started["user_code"] in page.text
        assert started["device_code"] not in page.text


class TestScopeBinding:
    """The token carries what was approved and what the person holds, nothing more."""

    def test_the_access_token_is_bound_to_the_user_scopes_and_grant(self, harness: Harness) -> None:
        """The JWT names the user, the approved scopes, the client and the grant."""
        body = harness.login()
        claims = harness.tokens.verify_access_token(body["access_token"], audience=harness.tokens.device_audience)
        assert claims["sub"] == USER
        assert claims["scope"] == "runs:read runs:plan"
        assert claims["client_id"] == CLIENT
        assert claims["grant"] == "device"
        assert claims["amr"] == ["device"]
        assert claims["sid"] == _grant_id(body)
        assert claims["plan"] == "pro"
        assert claims["exp"] - claims["iat"] == 3600
        assert body["expires_in"] == 3600
        assert body["token_type"] == "Bearer"
        assert body["refresh_token"].startswith("wpdr_")

    def test_approval_narrows_to_the_scopes_the_person_holds(self, harness: Harness) -> None:
        """A person without apply cannot hand apply to a CLI."""
        harness.hooks.held[USER] = "runs:read"
        body = harness.login("runs:read runs:apply")
        assert body["scope"] == "runs:read"
        assert (
            harness.tokens.verify_access_token(body["access_token"], audience=harness.tokens.device_audience)["scope"]
            == "runs:read"
        )

    def test_nothing_to_approve_when_the_person_holds_none(self, harness: Harness) -> None:
        """A request for only scopes the person lacks cannot be approved at all."""
        harness.hooks.held[USER] = "runs:read"
        started = harness.start("runs:apply")
        page = harness.client.get(
            harness.url(DEVICE_VERIFY_PATH), params={"user_code": started["user_code"]}, headers=harness.browser()
        )
        assert page.status_code == 403
        assert "Nothing to approve" in page.text

    def test_an_allow_with_no_scopes_is_refused(self, harness: Harness) -> None:
        """The service never records an approval that grants nothing."""
        service = DeviceGrantService(harness.settings, harness.hooks, harness.stores, harness.tokens)
        started = service.start({"client_id": CLIENT})
        approval = service.pending(started["user_code"], USER)
        assert approval is not None
        empty = DeviceApproval(record=approval.record, user_code=approval.user_code, client_name="x", scopes=())
        assert not service.decide(empty, user_id=USER, allow=True, auth_time=1)

    def test_refresh_narrows_when_a_scope_is_lost(self, harness: Harness) -> None:
        """A scope the person no longer holds drops off at the next refresh, and never comes back wider."""
        body = harness.login("runs:read runs:apply")
        harness.hooks.held[USER] = "runs:read"
        refreshed = harness.refresh(body["refresh_token"]).json()
        assert refreshed["scope"] == "runs:read"
        harness.hooks.held[USER] = "runs:read runs:plan runs:apply"
        again = harness.refresh(refreshed["refresh_token"]).json()
        assert again["scope"] == "runs:read runs:apply"

    def test_a_product_without_a_scope_model_grants_what_was_asked(self, fake_kms: Any) -> None:
        """When `claims_for` carries no scope, the approved scopes are the requested ones."""
        harness = Harness(fake_kms)
        harness.hooks.claims_for = lambda user: {}  # type: ignore[method-assign]
        body = harness.login("runs:read admin")
        assert body["scope"] == "runs:read admin"


class TestRefresh:
    """Rotation, reuse detection and the session cap."""

    def test_a_refresh_rotates_the_token(self, harness: Harness) -> None:
        """Each refresh answers a new refresh token and a new access token for the same grant."""
        body = harness.login()
        refreshed = harness.refresh(body["refresh_token"])
        assert refreshed.status_code == 200
        new = refreshed.json()
        assert new["refresh_token"] != body["refresh_token"]
        assert new["access_token"] != body["access_token"]
        assert _grant_id(new) == _grant_id(body)
        assert harness.grant(_grant_id(body)).generation == 2
        assert refreshed.headers["cache-control"] == "no-store"

    def test_replaying_a_rotated_token_revokes_the_grant(self, harness: Harness) -> None:
        """Presenting the replaced refresh token means two holders, so the whole grant ends."""
        body = harness.login()
        new = harness.refresh(body["refresh_token"]).json()
        _age_rotation(harness, _grant_id(body))
        replay = harness.refresh(body["refresh_token"])
        assert replay.json()["error"] == "invalid_grant"
        assert harness.grant(_grant_id(body)).revoked
        assert harness.refresh(new["refresh_token"]).json()["error"] == "invalid_grant"
        access = harness.tokens.verify_access_token(new["access_token"], audience=harness.tokens.device_audience)
        assert not device_grant_is_live(harness.stores.grants, access)

    def test_a_forged_secret_is_refused_without_revoking(self, harness: Harness) -> None:
        """A guess at the secret is refused, but does not let anyone end someone else's grant."""
        body = harness.login()
        forged = f"wpdr_{_grant_id(body)}.not-the-secret"
        assert harness.refresh(forged).json()["error"] == "invalid_grant"
        assert harness.grant(_grant_id(body)).live()

    def test_another_client_cannot_refresh(self, harness: Harness) -> None:
        """The refresh token is bound to its client."""
        body = harness.login()
        assert harness.refresh(body["refresh_token"], client_id="another").json()["error"] == "invalid_grant"

    @pytest.mark.parametrize("token", ["", "garbage", "wpdr_", "wpdr_abc", "wpdr_.secret"])
    def test_a_malformed_token_is_refused(self, harness: Harness, token: str) -> None:
        """Anything that is not a device refresh token is an invalid request."""
        assert harness.refresh(token).json()["error"] == "invalid_request"

    def test_the_session_cap_ends_refresh(self, harness: Harness) -> None:
        """Past the cap, the refresh token is dead no matter how recently it rotated."""
        body = harness.login()
        grants = harness.stores.grants
        grant_id = _grant_id(body)
        grants._items[grant_id] = dataclasses.replace(grants._items[grant_id], expires_at=int(time.time()) - 1)  # type: ignore[attr-defined]
        assert harness.refresh(body["refresh_token"]).json()["error"] == "invalid_grant"

    def test_the_session_cap_is_twelve_hours_and_never_moves(self, harness: Harness) -> None:
        """The cap is set when the grant opens and a refresh does not extend it."""
        before = int(time.time())
        body = harness.login()
        grant = harness.grant(_grant_id(body))
        assert before + 12 * 3600 <= grant.expires_at <= int(time.time()) + 12 * 3600
        assert body["refresh_token_expires_in"] <= 12 * 3600
        harness.refresh(body["refresh_token"])
        assert harness.grant(_grant_id(body)).expires_at == grant.expires_at

    def test_a_lost_rotation_race_hands_back_the_winners_pair(self, harness: Harness) -> None:
        """When another request rotated first, the loser gets the same successor, not a fork."""
        body = harness.login()
        grants = harness.stores.grants
        original = grants.rotate

        def rotate_then_lose(*args: Any, **kwargs: Any) -> bool:
            """Let the rotation land, then report that another request won it."""
            original(*args, **kwargs)
            return False

        grants.rotate = rotate_then_lose  # type: ignore[method-assign]
        first = harness.refresh(body["refresh_token"]).json()
        grants.rotate = original  # type: ignore[method-assign]
        second = harness.refresh(body["refresh_token"]).json()
        assert first["refresh_token"] == second["refresh_token"]
        assert harness.grant(_grant_id(body)).live()

    def test_a_retry_inside_the_grace_window_gets_the_same_pair(self, harness: Harness) -> None:
        """A client that lost the response presents the old token again and is not revoked."""
        body = harness.login()
        first = harness.refresh(body["refresh_token"]).json()
        again = harness.refresh(body["refresh_token"])
        assert again.status_code == 200
        assert again.json()["refresh_token"] == first["refresh_token"]
        assert harness.grant(_grant_id(body)).live()
        assert harness.refresh(first["refresh_token"]).status_code == 200

    def test_a_user_who_may_no_longer_sign_in_is_refused(self, harness: Harness) -> None:
        """A deleted account ends the grant at the next refresh."""
        body = harness.login()
        harness.hooks.gone.add(USER)
        assert harness.refresh(body["refresh_token"]).json()["error"] == "invalid_grant"
        assert harness.grant(_grant_id(body)).revoked


class TestRevocation:
    """Ending a device session, from the CLI or the browser."""

    def test_revoking_the_refresh_token_kills_both_tokens(self, harness: Harness) -> None:
        """`/device/revoke` ends the grant, so refresh fails and the access token reads as dead."""
        body = harness.login()
        response = harness.client.post(harness.url(DEVICE_REVOKE_PATH), data={"token": body["refresh_token"]})
        assert response.status_code == 200
        assert harness.refresh(body["refresh_token"]).json()["error"] == "invalid_grant"
        claims = harness.tokens.verify_access_token(body["access_token"], audience=harness.tokens.device_audience)
        assert not device_grant_is_live(harness.stores.grants, claims)

    def test_revoke_answers_200_for_anything(self, harness: Harness) -> None:
        """RFC 7009: an unknown token is not an error, and reveals nothing."""
        for token in ("", "garbage", "wpdr_nope.nope"):
            assert harness.client.post(harness.url(DEVICE_REVOKE_PATH), data={"token": token}).status_code == 200

    def test_revoke_with_a_forged_secret_does_nothing(self, harness: Harness) -> None:
        """Knowing a grant id is not enough to end it."""
        body = harness.login()
        harness.client.post(harness.url(DEVICE_REVOKE_PATH), data={"token": f"wpdr_{_grant_id(body)}.forged"})
        assert harness.grant(_grant_id(body)).live()

    def test_the_person_lists_and_revokes_grants_in_the_browser(self, harness: Harness) -> None:
        """`/device/grants` lists live logins without hashes, and DELETE ends one."""
        body = harness.login()
        listed = harness.client.get(harness.url(DEVICE_GRANTS_PATH), headers=harness.browser()).json()["grants"]
        assert [grant["grant_id"] for grant in listed] == [_grant_id(body)]
        assert listed[0]["client_name"] == "wp-tf CLI"
        assert "refresh_hash" not in listed[0]
        response = harness.client.delete(
            harness.url(f"{DEVICE_GRANTS_PATH}/{_grant_id(body)}"), headers=harness.browser()
        )
        assert response.status_code == 204
        assert harness.refresh(body["refresh_token"]).json()["error"] == "invalid_grant"
        assert harness.client.get(harness.url(DEVICE_GRANTS_PATH), headers=harness.browser()).json()["grants"] == []

    def test_a_person_cannot_revoke_someone_elses_grant(self, harness: Harness) -> None:
        """Another user's grant id answers 404 and stays live."""
        body = harness.login()
        response = harness.client.delete(
            harness.url(f"{DEVICE_GRANTS_PATH}/{_grant_id(body)}"), headers=harness.browser(OTHER)
        )
        assert response.status_code == 404
        assert harness.grant(_grant_id(body)).live()

    def test_the_grant_list_needs_a_browser_session(self, harness: Harness) -> None:
        """Anonymous callers and device tokens are both refused."""
        body = harness.login()
        assert harness.client.get(harness.url(DEVICE_GRANTS_PATH)).status_code == 401
        device = {"Authorization": f"Bearer {body['access_token']}", "Origin": ORIGIN}
        assert harness.client.get(harness.url(DEVICE_GRANTS_PATH), headers=device).status_code == 401
        assert (
            harness.client.delete(harness.url(f"{DEVICE_GRANTS_PATH}/{_grant_id(body)}"), headers=device).status_code
            == 401
        )

    def test_a_delete_from_another_origin_is_refused(self, harness: Harness) -> None:
        """The revoke button must be this site's own."""
        body = harness.login()
        response = harness.client.delete(
            harness.url(f"{DEVICE_GRANTS_PATH}/{_grant_id(body)}"),
            headers={**harness.browser(), "Origin": "https://evil.example.com"},
        )
        assert response.status_code == 403
        assert harness.grant(_grant_id(body)).live()

    def test_logout_everywhere_ends_device_logins(self, harness: Harness) -> None:
        """Signing out everywhere revokes every device grant as well."""
        first = harness.login()
        second = harness.login()
        response = harness.client.post(harness.url(LOGOUT_ALL_PATH), headers=harness.browser())
        assert response.status_code == 200
        assert harness.grant(_grant_id(first)).revoked
        assert harness.grant(_grant_id(second)).revoked


class TestLiveness:
    """`device_grant_is_live`, the check a resource server makes."""

    def test_a_browser_token_is_always_live(self, harness: Harness) -> None:
        """Only device tokens are looked up."""
        assert device_grant_is_live(harness.stores.grants, {"sub": USER})

    def test_a_device_token_is_live_while_its_grant_is(self, harness: Harness) -> None:
        """A fresh device login reads as live."""
        body = harness.login()
        assert device_grant_is_live(
            harness.stores.grants,
            harness.tokens.verify_access_token(body["access_token"], audience=harness.tokens.device_audience),
        )

    def test_a_grant_for_another_user_is_not_live(self, harness: Harness) -> None:
        """The grant must belong to the token's subject."""
        body = harness.login()
        claims = dict(harness.tokens.verify_access_token(body["access_token"], audience=harness.tokens.device_audience))
        claims["sub"] = OTHER
        assert not device_grant_is_live(harness.stores.grants, claims)

    def test_a_device_token_without_a_grant_id_is_not_live(self, harness: Harness) -> None:
        """No `sid`, no grant."""
        assert not device_grant_is_live(harness.stores.grants, {"sub": USER, "grant": "device"})

    def test_a_store_failure_reads_as_not_live(self) -> None:
        """Failing closed: a store that raises never lets a token through."""

        class Broken:
            def get(self, grant_id: str) -> None:
                """Always fail."""
                raise RuntimeError("down")

        assert not device_grant_is_live(Broken(), {"sub": USER, "grant": "device", "sid": "g"})


class TestSettings:
    """The flag's validation."""

    def test_the_flag_needs_a_client(self) -> None:
        """No client, nothing could start."""
        with pytest.raises(ValueError, match="device_clients"):
            build_settings(device_clients={})

    def test_the_flag_needs_scopes(self) -> None:
        """No scopes, nothing could be granted."""
        with pytest.raises(ValueError, match="device_scopes_supported"):
            build_settings(device_scopes_supported=[], device_explicit_scopes=[])

    def test_explicit_scopes_must_be_supported(self) -> None:
        """An explicit scope outside the supported list is a typo."""
        with pytest.raises(ValueError, match="device_explicit_scopes"):
            build_settings(device_explicit_scopes=["runs:destroy"])

    def test_the_session_cap_is_capped(self) -> None:
        """The session may not outlive a day."""
        with pytest.raises(ValueError, match="device_session_ttl"):
            build_settings(device_session_ttl=timedelta(days=2))

    def test_the_access_token_is_capped(self) -> None:
        """The access token may not outlive an hour."""
        with pytest.raises(ValueError, match="device_access_token_ttl"):
            build_settings(device_access_token_ttl=timedelta(hours=2))

    def test_the_code_life_is_capped(self) -> None:
        """A user code may not linger."""
        with pytest.raises(ValueError, match="device_code_ttl"):
            build_settings(device_code_ttl=timedelta(hours=1))

    def test_the_step_up_cannot_be_turned_off(self) -> None:
        """There is no setting that skips the recent sign-in check."""
        with pytest.raises(ValueError, match="device_approval_max_age"):
            build_settings(device_approval_max_age=timedelta(0))

    def test_a_plaintext_login_url_is_refused_outside_local(self) -> None:
        """The login page collects credentials."""
        with pytest.raises(ValueError, match="plaintext"):
            build_settings(environment="production", device_login_url="http://app.example.com/login")

    def test_the_flag_needs_its_stores(self, fake_kms: Any) -> None:
        """Mounting with the flag on and no stores is a startup error."""
        settings = build_settings()
        with pytest.raises(ValueError, match="device_grant_stores"):
            build_identity_router(
                settings,
                Hooks(),
                IdentityStores(credentials=InMemoryCredentialStore(), refresh_tokens=InMemoryRefreshTokenStore()),
                tokens=TokenService(settings, fake_kms),
                limiter_enabled=False,
            )


class TestSecrets:
    """No token or code secret is stored in the clear or logged."""

    def test_only_hashes_are_stored(self, harness: Harness) -> None:
        """The device code, user code and refresh secret never appear in a stored record."""
        started = harness.start()
        harness.decide(started["user_code"])
        body = harness.poll(started["device_code"]).json()
        stored = str(list(harness.stores.grants._items.values()))  # type: ignore[attr-defined]
        secret = body["refresh_token"].split(".", 1)[1]
        assert secret not in stored
        assert started["device_code"] not in stored

    def test_nothing_secret_reaches_the_log(self, harness: Harness, caplog: pytest.LogCaptureFixture) -> None:
        """A reuse warning names the grant, never a token."""
        caplog.set_level("DEBUG")
        body = harness.login()
        new = harness.refresh(body["refresh_token"]).json()
        harness.refresh(body["refresh_token"])
        for token in (body["access_token"], body["refresh_token"], new["access_token"], new["refresh_token"]):
            assert token not in caplog.text


@pytest.mark.usefixtures("aws_credentials")
def test_the_dynamo_stores_run_the_whole_flow(fake_kms: Any) -> None:
    """The Dynamo stores against moto: start, approve, collect, rotate, detect reuse, list and revoke."""
    import boto3
    from moto import mock_aws

    with mock_aws():
        client = boto3.client("dynamodb", region_name="us-west-2")
        for spec in DEVICE_GRANT_TABLES:
            client.create_table(**spec.create_table_request("wp-test"))
        stores = dynamo_device_grant_stores("wp-test", region_name="us-west-2")
        settings = build_settings()
        service = DeviceGrantService(settings, Hooks(), stores, TokenService(settings, fake_kms))
        now = int(time.time())

        started = service.start({"client_id": CLIENT}, now=now)
        params = {"device_code": started["device_code"], "client_id": CLIENT}
        with pytest.raises(OAuthServerError) as pending:
            service.poll(params, now=now)
        assert pending.value.error == "authorization_pending"
        with pytest.raises(OAuthServerError) as fast:
            service.poll(params, now=now + 1)
        assert fast.value.error == "slow_down"

        approval = service.pending(started["user_code"], USER)
        assert approval is not None
        assert service.decide(approval, user_id=USER, allow=True, auth_time=now)
        assert not service.decide(approval, user_id=USER, allow=True, auth_time=now)
        assert service.pending(started["user_code"], USER) is None

        body = service.poll(params, now=now + 60)
        with pytest.raises(OAuthServerError) as used:
            service.poll(params, now=now + 120)
        assert used.value.error == "invalid_grant"

        refresh = {"refresh_token": body["refresh_token"], "client_id": CLIENT}
        rotated = service.refresh(refresh, now=now + 180)
        with pytest.raises(OAuthServerError):
            service.refresh(refresh, now=now + 180 + DEVICE_REFRESH_GRACE_SECONDS + 10)
        grant_id = _grant_id(body)
        record = stores.grants.get(grant_id)
        assert record is not None and record.revoked
        with pytest.raises(OAuthServerError):
            service.refresh({"refresh_token": rotated["refresh_token"], "client_id": CLIENT})

        second = service.start({"client_id": CLIENT}, now=now)
        approval = service.pending(second["user_code"], USER)
        assert approval is not None
        service.decide(approval, user_id=USER, allow=True, auth_time=now)
        other = service.poll({"device_code": second["device_code"], "client_id": CLIENT}, now=now + 300)
        assert [grant["grant_id"] for grant in service.list_grants(USER)] == [_grant_id(other)]
        assert service.revoke_all(USER) == 1
        assert service.list_grants(USER) == []


def test_the_device_tables_create_against_dynamodb(aws_credentials: None) -> None:
    """Both table specs are ones DynamoDB accepts, with their GSIs and TTL."""
    import boto3
    from moto import mock_aws

    with mock_aws():
        client = boto3.client("dynamodb", region_name="us-west-2")
        for spec in DEVICE_GRANT_TABLES:
            client.create_table(**spec.create_table_request("wp-local"))
            ttl = spec.time_to_live_request("wp-local")
            assert ttl is not None
            client.update_time_to_live(**ttl)
        codes = client.describe_table(TableName="wp-local-device-codes")["Table"]
        grants = client.describe_table(TableName="wp-local-device-grants")["Table"]
        assert codes["GlobalSecondaryIndexes"][0]["IndexName"] == "user_code_hash-index"
        assert codes["GlobalSecondaryIndexes"][0]["Projection"]["ProjectionType"] == "KEYS_ONLY"
        assert grants["GlobalSecondaryIndexes"][0]["IndexName"] == "user_id-index"
        assert grants["GlobalSecondaryIndexes"][0]["Projection"]["ProjectionType"] == "ALL"


def test_the_cli_client_signs_in_against_the_server(
    harness: Harness, capsys: pytest.CaptureFixture[str], tmp_path: Any
) -> None:
    """`DeviceLoginClient` end to end: print, approve in a browser, refresh, revoke, with no token printed."""
    import io

    from webbpulse.device_login import DeviceLoginClient

    class Ring:
        def __init__(self) -> None:
            self.items: dict[tuple[str, str], str] = {}

        def get_password(self, service_name: str, username: str) -> str | None:
            return self.items.get((service_name, username))

        def set_password(self, service_name: str, username: str, password: str) -> None:
            self.items[(service_name, username)] = password

        def delete_password(self, service_name: str, username: str) -> None:
            self.items.pop((service_name, username), None)

    out = io.StringIO()
    printed: list[str] = []

    def approve_in_browser(seconds: float) -> None:
        """While the CLI waits, the person approves the code it printed."""
        harness._unpace_all()
        if not printed:
            code = re.search(r"code ([A-Z]{4}-[A-Z]{4})", out.getvalue())
            assert code is not None
            printed.append(code.group(1))
            assert harness.decide(printed[0]).status_code == 200

    ring = Ring()
    http: Any = harness.client
    client = DeviceLoginClient(
        ISSUER, CLIENT, http=http, keyring_backend=ring, sleep=approve_in_browser, out=out, lock_dir=tmp_path
    )
    session = client.login(["runs:read", "runs:apply"])
    assert session.scope == "runs:read runs:apply"
    token = client.access_token()
    claims = harness.tokens.verify_access_token(token, audience=harness.tokens.device_audience)
    assert claims["sub"] == USER
    assert claims["scope"] == "runs:read runs:apply"

    stored = client.stored()
    assert stored is not None
    ring.items[next(iter(ring.items))] = dataclasses.replace(stored, expires_at=0).to_json()
    rotated = client.access_token()
    assert rotated != token
    renewed = client.stored()
    assert renewed is not None and renewed.refresh_token != stored.refresh_token

    result = client.logout()
    assert result and result.revoked
    assert harness.grant(claims["sid"]).revoked
    captured = capsys.readouterr()
    for secret in (token, rotated, stored.refresh_token, renewed.refresh_token):
        assert secret not in out.getvalue() + captured.out + captured.err


def _context_request(claims: dict[str, Any] | None = None, **headers: str) -> Any:
    """A Starlette request carrying gateway claims in the request context and any extra headers."""
    import json

    from starlette.requests import Request

    values = dict(headers)
    if claims is not None:
        values["x-amzn-request-context"] = json.dumps({"authorizer": {"jwt": {"claims": claims}}})
    raw = [(key.lower().replace("_", "-").encode(), value.encode()) for key, value in values.items()]
    return Request({"type": "http", "method": "GET", "path": "/", "headers": raw, "query_string": b""})


class TestAudienceSeparation:
    """A device token is for resource servers only: identity routes and default verifiers refuse it."""

    def test_the_default_verifier_refuses_the_device_audience(self, harness: Harness) -> None:
        """`verify_access_token` without an audience accepts only browser sessions."""
        body = harness.login()
        with pytest.raises(Exception):  # noqa: B017
            harness.tokens.verify_access_token(body["access_token"])

    def test_the_device_audience_must_differ(self) -> None:
        """A device audience equal to the session audience would undo the separation."""
        with pytest.raises(ValueError, match="device_audience"):
            build_settings(device_audience=AUDIENCE)

    def test_claims_from_request_refuses_a_device_bearer(self, harness: Harness) -> None:
        """A device bearer reads as no session at all on an identity route."""
        from webbpulse.identity.router import _claims_from_request

        body = harness.login()
        request = _context_request(authorization=f"Bearer {body['access_token']}")
        assert _claims_from_request(request, harness.tokens) == {}
        browser = _context_request(authorization=harness.browser()["Authorization"])
        assert _claims_from_request(browser, harness.tokens)["sub"] == USER

    def test_claims_from_request_refuses_device_gateway_claims(self, harness: Harness) -> None:
        """Gateway claims carrying the device grant are refused, whatever the audience says."""
        from webbpulse.identity.router import _claims_from_request

        request = _context_request({"sub": USER, "aud": AUDIENCE, "grant": "device", "sid": "g"})
        assert _claims_from_request(request, harness.tokens) == {}

    def test_the_subject_resolver_does_not_fall_back_to_the_cookie(self, harness: Harness) -> None:
        """A device bearer alongside a live refresh cookie still resolves to no one."""
        from webbpulse.identity.router import _authorization_subject_resolver

        peeked: list[str] = []

        class Sessions:
            def peek(self, value: str) -> Any:
                """Record the read and answer a live session."""
                peeked.append(value)
                return type("Presented", (), {"user_id": USER, "family_id": "f"})()

        class Flows:
            sessions = Sessions()

        resolve = _authorization_subject_resolver(harness.settings, harness.hooks, Flows(), harness.tokens)
        body = harness.login()
        cookie = f"{harness.settings.cookie_name}=refresh-cookie"
        request = _context_request(authorization=f"Bearer {body['access_token']}", cookie=cookie)
        assert resolve(request) is None
        assert peeked == []

    def test_the_subject_resolver_accepts_a_browser_bearer(self, harness: Harness) -> None:
        """A browser session still resolves to its user."""
        from webbpulse.identity.router import _authorization_subject_resolver

        resolve = _authorization_subject_resolver(harness.settings, harness.hooks, None, harness.tokens)
        found = resolve(_context_request(authorization=harness.browser()["Authorization"]))
        assert found is not None and found.user_id == USER


class TestResourceServerCheck:
    """`claims_or_api_key` refuses device tokens unless their grant is checked and live."""

    @staticmethod
    def _client(device_grants: Any = None) -> TestClient:
        """A one-route app behind `claims_or_api_key`."""
        from fastapi import Depends

        from webbpulse.identity.scopes import claims_or_api_key

        app = FastAPI()
        dependency = claims_or_api_key(device_grants=device_grants)

        @app.get("/runs")
        async def runs(claims: Any = Depends(dependency)) -> dict[str, str]:
            """Echo the subject."""
            return {"sub": str(claims.get("sub", ""))}

        return TestClient(app)

    @staticmethod
    def _headers(claims: dict[str, Any]) -> dict[str, str]:
        """The gateway request context for these claims."""
        import json

        return {"x-amzn-request-context": json.dumps({"authorizer": {"jwt": {"claims": claims}}})}

    def test_device_claims_are_refused_without_the_check(self, harness: Harness) -> None:
        """Left unwired, the dependency fails closed for device tokens and stays open for browsers."""
        client = self._client()
        body = harness.login()
        claims = dict(harness.tokens.verify_access_token(body["access_token"], audience=harness.tokens.device_audience))
        assert client.get("/runs", headers=self._headers(claims)).status_code == 401
        assert client.get("/runs", headers=self._headers({"sub": USER})).status_code == 200

    def test_a_live_grant_passes_and_a_revoked_one_does_not(self, harness: Harness) -> None:
        """With the store wired, revocation takes effect on the next request once the cache is off."""
        from webbpulse.identity import DeviceGrantLiveness

        client = self._client(DeviceGrantLiveness(harness.stores.grants, ttl_seconds=0))
        body = harness.login()
        claims = dict(harness.tokens.verify_access_token(body["access_token"], audience=harness.tokens.device_audience))
        assert client.get("/runs", headers=self._headers(claims)).status_code == 200
        harness.stores.grants.revoke(_grant_id(body))
        assert client.get("/runs", headers=self._headers(claims)).status_code == 401

    def test_a_bare_store_is_wrapped(self, harness: Harness) -> None:
        """Passing the store itself works the same as passing a liveness check."""
        client = self._client(harness.stores.grants)
        body = harness.login()
        claims = dict(harness.tokens.verify_access_token(body["access_token"], audience=harness.tokens.device_audience))
        assert client.get("/runs", headers=self._headers(claims)).status_code == 200


class TestLivenessCache:
    """The liveness cache is short and bounded."""

    def test_the_cache_cannot_exceed_the_cap(self, harness: Harness) -> None:
        """A longer cache is a configuration error."""
        from webbpulse.identity import DeviceGrantLiveness
        from webbpulse.identity.device_grant import DEVICE_LIVENESS_MAX_CACHE_SECONDS

        with pytest.raises(ValueError, match="ttl_seconds"):
            DeviceGrantLiveness(harness.stores.grants, ttl_seconds=DEVICE_LIVENESS_MAX_CACHE_SECONDS + 1)

    def test_a_decision_is_reused_only_within_the_ttl(self, harness: Harness) -> None:
        """A revocation is seen once the cached decision ages out."""
        from webbpulse.identity import DeviceGrantLiveness

        moment = [100.0]
        live = DeviceGrantLiveness(harness.stores.grants, ttl_seconds=5, clock=lambda: moment[0])
        body = harness.login()
        claims = harness.tokens.verify_access_token(body["access_token"], audience=harness.tokens.device_audience)
        assert live(claims)
        harness.stores.grants.revoke(_grant_id(body))
        assert live(claims)
        moment[0] += 6
        assert not live(claims)


class TestMasterKey:
    """The approval and refresh keys need a real master key."""

    def test_the_router_refuses_to_build_without_one(self, fake_kms: Any) -> None:
        """No master key, no device grant: the failure is at startup, not on the first login."""
        from webbpulse.identity import DeviceGrantKeyMissing

        settings = build_settings(totp_master_key="")
        with pytest.raises(DeviceGrantKeyMissing):
            build_identity_router(
                settings,
                Hooks(),
                IdentityStores(credentials=InMemoryCredentialStore(), refresh_tokens=InMemoryRefreshTokenStore()),
                tokens=TokenService(settings, fake_kms),
                device_grant_stores=build_stores(),
                limiter_enabled=False,
            )


class TestLookupCap:
    """A signed-in person who keeps mistyping codes is stopped, whatever address they use."""

    def test_too_many_wrong_codes_return_429(self, harness: Harness) -> None:
        """After the cap, even a right code waits out the window."""
        from webbpulse.identity.device_grant import DEVICE_USER_CODE_FAILURE_LIMIT

        headers = harness.browser()
        for _ in range(DEVICE_USER_CODE_FAILURE_LIMIT[0]):
            response = harness.client.get(
                harness.url(DEVICE_VERIFY_PATH), params={"user_code": "BCDF-GHJK"}, headers=headers
            )
            assert response.status_code == 404
        started = harness.start()
        response = harness.client.get(
            harness.url(DEVICE_VERIFY_PATH), params={"user_code": started["user_code"]}, headers=headers
        )
        assert response.status_code == 429
        other = harness.client.get(
            harness.url(DEVICE_VERIFY_PATH), params={"user_code": started["user_code"]}, headers=harness.browser(OTHER)
        )
        assert other.status_code == 200


class TestRevocationOnPasswordAndPurge:
    """Password changes end device logins, and a purge deletes everything the device grant stored."""

    @staticmethod
    def _flows(harness: Harness) -> Any:
        """Identity flows over the harness's device stores, with a password set for the user."""
        from webbpulse.identity import PASSWORD_CREDENTIAL_TYPE, IdentityFlows
        from webbpulse.identity.storage import CredentialRecord
        from webbpulse.security import hash_password

        credentials = InMemoryCredentialStore()
        credentials.put(
            CredentialRecord(
                user_id=USER, credential_type=PASSWORD_CREDENTIAL_TYPE, secret=hash_password("old-pass-123!")
            )
        )
        stores = IdentityStores(
            credentials=credentials,
            refresh_tokens=InMemoryRefreshTokenStore(),
            device_grants=harness.stores.grants,
            device_codes=harness.stores.codes,
        )
        return IdentityFlows(harness.settings, harness.hooks, stores, harness.tokens)

    def test_a_password_change_revokes_every_device_grant(self, harness: Harness) -> None:
        """Both CLI logins end with the password change."""
        first, second = harness.login(), harness.login()
        flows = self._flows(harness)
        flows.change_password(
            user_id=USER, current_password="old-pass-123!", new_password="a much better passphrase 42"
        )
        assert harness.grant(_grant_id(first)).revoked
        assert harness.grant(_grant_id(second)).revoked

    def test_a_purge_deletes_grants_codes_and_counters(self, harness: Harness) -> None:
        """Nothing the device grant stored for the user survives a purge."""
        body = harness.login()
        started = harness.start()
        harness.decide(started["user_code"])
        harness.client.get(
            harness.url(DEVICE_VERIFY_PATH), params={"user_code": "BCDF-GHJK"}, headers=harness.browser()
        )
        codes = harness.stores.codes
        assert isinstance(codes, InMemoryDeviceCodeStore)
        assert codes._failures
        result = self._flows(harness).purge_user(USER)
        assert result.device_grants == 1
        assert result.device_codes == 1
        assert harness.grant(_grant_id(body)) is None
        assert not [record for record in codes._items.values() if record.user_id == USER]
        assert not codes._failures


@pytest.mark.usefixtures("aws_credentials")
def test_the_dynamo_purge_reaches_decided_codes_without_a_scan(fake_kms: Any) -> None:
    """The owner item lets a purge find the user's decided requests; counters and the item go too."""
    import boto3
    from moto import mock_aws

    from webbpulse.identity import IdentityFlows

    with mock_aws():
        client = boto3.client("dynamodb", region_name="us-west-2")
        for spec in DEVICE_GRANT_TABLES:
            client.create_table(**spec.create_table_request("wp-test"))
        stores = dynamo_device_grant_stores("wp-test", region_name="us-west-2")
        settings = build_settings()
        tokens = TokenService(settings, fake_kms)
        service = DeviceGrantService(settings, Hooks(), stores, tokens)
        now = int(time.time())

        login = service.start({"client_id": CLIENT}, now=now)
        approval = service.pending(login["user_code"], USER)
        assert approval is not None
        service.decide(approval, user_id=USER, allow=True, auth_time=now)
        service.poll({"device_code": login["device_code"], "client_id": CLIENT}, now=now + 60)

        waiting = service.start({"client_id": CLIENT}, now=now)
        approval = service.pending(waiting["user_code"], USER)
        assert approval is not None
        service.decide(approval, user_id=USER, allow=False, auth_time=now)
        service.note_failed_lookup(USER)

        bystander = service.start({"client_id": CLIENT}, now=now)
        approval = service.pending(bystander["user_code"], OTHER)
        assert approval is not None
        service.decide(approval, user_id=OTHER, allow=True, auth_time=now)

        flows = IdentityFlows(
            settings,
            Hooks(),
            IdentityStores(
                refresh_tokens=InMemoryRefreshTokenStore(), device_grants=stores.grants, device_codes=stores.codes
            ),
            tokens,
        )
        result = flows.purge_user(USER)
        assert result.device_grants == 1
        assert result.device_codes >= 1

        remaining = client.scan(TableName="wp-test-device-codes")["Items"]
        keys = [item["device_code_hash"]["S"] for item in remaining]
        assert not [key for key in keys if USER in key]
        assert any(OTHER in key for key in keys)
        assert service.list_grants(USER) == []


_CHROMIUM_MISSING = browser_is_available("chromium")


def _free_port() -> int:
    """A loopback port nothing is listening on."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.fixture
def served(fake_kms: Any) -> Iterator[tuple[Harness, str]]:
    """A harness whose app listens on loopback, with its issuer on that same origin."""
    import uvicorn

    port = _free_port()
    origin = f"http://127.0.0.1:{port}"
    harness = Harness(fake_kms, environment="local", issuer=f"{origin}/api/auth")
    server = uvicorn.Server(uvicorn.Config(harness.client.app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        assert time.monotonic() < deadline, "the test server did not start"
        time.sleep(0.05)
    try:
        yield harness, origin
    finally:
        server.should_exit = True
        thread.join(timeout=10)


@pytest.mark.skipif(bool(_CHROMIUM_MISSING), reason=_CHROMIUM_MISSING or "chromium is available")
def test_a_browser_approves_through_the_real_page(served: tuple[Harness, str]) -> None:
    """Clicking "Allow access" in Chromium approves the code, and the CLI's next poll gets tokens."""
    from playwright.sync_api import sync_playwright

    harness, origin = served
    started = harness.start()
    bearer = {key: value for key, value in harness.browser().items() if key != "Origin"}
    with sync_playwright() as playwright:
        try:
            browser = playwright.chromium.launch()
        except Exception as error:
            if "Executable doesn't exist" not in str(error):
                raise
            pytest.skip("this Playwright's chromium build is not installed where it looks")
        try:
            context = browser.new_context(extra_http_headers=bearer)
            page = context.new_page()
            page.goto(f"{origin}{harness.url(DEVICE_VERIFY_PATH)}?user_code={started['user_code']}")
            with page.expect_response(lambda response: response.request.method == "POST") as posted:
                page.get_by_role("button", name="Allow access").click()
            assert posted.value.status == 200, posted.value.text()
            assert "Device connected" in page.content()
        finally:
            browser.close()
    assert harness.poll(started["device_code"]).status_code == 200
