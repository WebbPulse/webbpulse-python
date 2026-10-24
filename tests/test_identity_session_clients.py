"""Tests for the session list's last-seen IP, client and platform (PLAT-79).

Covers the user agent readers, what a family records at sign-in and on each refresh, the
fallbacks for rows written before the fields existed, the DynamoDB round trip and the
`GET /sessions` body.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from webbpulse.identity import (
    IdentitySettings,
    InMemoryRefreshTokenStore,
    SessionService,
    client_from_user_agent,
    oauth_client_of_device,
    platform_from_user_agent,
)
from webbpulse.identity.storage import RefreshTokenRecord, hash_token

KEY_A = "arn:aws:kms:us-west-2:111122223333:key/aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa"
USER_ID = "user-0001"

CHROME_MAC = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)
ELECTRON_WINDOWS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Standupless/0.4.0 Chrome/130.0.6723.191 Electron/33.2.1 Safari/537.36"
)
SAFARI_IPHONE = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
)
FIREFOX_LINUX = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
EDGE_WINDOWS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0"
)
CHROME_ANDROID = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0.0.0 Mobile Safari/537.36"
)


def make_settings() -> IdentitySettings:
    """Settings for a session service under test."""
    return IdentitySettings(
        environment="test",
        issuer="https://api.staging.example.com/api/auth",
        audience="webbpulse-staging",
        signing_key_arns=[KEY_A],
        email_verification_required=False,
    )


@pytest.fixture
def store() -> InMemoryRefreshTokenStore:
    """An in-memory refresh token store."""
    return InMemoryRefreshTokenStore()


@pytest.fixture
def sessions(store: InMemoryRefreshTokenStore) -> SessionService:
    """A session service over the in-memory store."""
    return SessionService(make_settings(), store)


@pytest.mark.parametrize(
    ("user_agent", "client"),
    [
        ("", ""),
        (CHROME_MAC, ""),
        (FIREFOX_LINUX, ""),
        (SAFARI_IPHONE, ""),
        (EDGE_WINDOWS, ""),
        (CHROME_ANDROID, ""),
        (ELECTRON_WINDOWS, "Standupless"),
        ("claude-code/2.0.14 (cli)", "claude-code"),
        ("Bun/1.2.3", "Bun"),
        ("standupless-cli/0.1.0", "standupless-cli"),
        ("Standupless/12 CFNetwork/1490.0.4 Darwin/23.2.0", "Standupless"),
        ("python-httpx/0.27.0", "python-httpx"),
        ("not a user agent", ""),
    ],
)
def test_the_client_is_the_first_product_token_a_browser_does_not_send(user_agent: str, client: str) -> None:
    """Browsers answer no client, and anything else answers its product name without a version."""
    assert client_from_user_agent(user_agent) == client


@pytest.mark.parametrize(
    ("user_agent", "platform"),
    [
        ("", ""),
        (CHROME_MAC, "macOS"),
        (ELECTRON_WINDOWS, "Windows"),
        (SAFARI_IPHONE, "iOS"),
        (FIREFOX_LINUX, "Linux"),
        (CHROME_ANDROID, "Android"),
        ("Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 Chrome/130 Safari/537.36", "ChromeOS"),
        ("claude-code/2.0.14 (cli)", ""),
        ("Microsoft Office/16.0", ""),
    ],
)
def test_the_platform_is_a_coarse_operating_system(user_agent: str, platform: str) -> None:
    """A phone reads before the desktop system its user agent also names, and an unknown answers empty."""
    assert platform_from_user_agent(user_agent) == platform


def test_the_oauth_client_is_read_off_the_device_label() -> None:
    """Both label shapes the OAuth server writes name their client, and any other label names none."""
    assert oauth_client_of_device("mcp:client-1:tenant-1") == "client-1"
    assert oauth_client_of_device("mcp:client-1") == "client-1"
    assert oauth_client_of_device("desktop") == ""
    assert oauth_client_of_device("") == ""


def test_a_new_family_records_its_ip_client_and_platform(sessions: SessionService) -> None:
    """Sign-in records the address as both first and last seen, and the client and platform."""
    sessions.start_family(USER_ID, device="desktop", ip="198.51.100.1", user_agent=ELECTRON_WINDOWS)

    (summary,) = sessions.list_for_user(USER_ID)
    assert summary.ip == "198.51.100.1"
    assert summary.last_ip == "198.51.100.1"
    assert summary.client == "Standupless"
    assert summary.platform == "Windows"
    assert summary.client_id == ""


def test_a_refresh_moves_the_last_seen_ip_and_keeps_the_sign_in_ip(sessions: SessionService) -> None:
    """Each rotation records where it came from, so the newest generation says where the session is."""
    first = sessions.start_family(USER_ID, device="desktop", ip="198.51.100.1", user_agent=CHROME_MAC)
    rotated = sessions.rotate(first.token, ip="203.0.113.2", user_agent=CHROME_MAC)
    assert rotated.issued is not None

    (summary,) = sessions.list_for_user(USER_ID)
    assert summary.ip == "198.51.100.1"
    assert summary.last_ip == "203.0.113.2"
    assert summary.platform == "macOS"


def test_a_refresh_with_no_ip_keeps_the_last_one(sessions: SessionService) -> None:
    """A rotation that knows no address leaves the last-seen one where it was."""
    first = sessions.start_family(USER_ID, ip="198.51.100.1")
    second = sessions.rotate(first.token, ip="203.0.113.2")
    assert second.issued is not None
    sessions.rotate(second.issued.token)

    (summary,) = sessions.list_for_user(USER_ID)
    assert summary.last_ip == "203.0.113.2"


def test_a_grace_replay_keeps_the_winners_last_seen_ip(sessions: SessionService) -> None:
    """A concurrent refresh inside the grace window carries the address the winning rotation recorded."""
    first = sessions.start_family(USER_ID, ip="198.51.100.1")
    winner = sessions.rotate(first.token, ip="203.0.113.2")
    loser = sessions.rotate(first.token, ip="203.0.113.3")
    assert winner.issued is not None
    assert loser.outcome == "replayed"

    (summary,) = sessions.list_for_user(USER_ID)
    assert summary.last_ip == "203.0.113.2"


def test_a_family_started_before_the_fields_existed_falls_back(
    sessions: SessionService, store: InMemoryRefreshTokenStore
) -> None:
    """An old row lists its sign-in IP as last seen, and its first refresh fills in the client."""
    now = datetime.now(UTC)
    stamp = now.isoformat(timespec="seconds").replace("+00:00", "Z")
    store.put(
        RefreshTokenRecord(
            token_hash=hash_token("legacy-token"),
            family_id="legacy",
            user_id=USER_ID,
            generation=1,
            created_at=stamp,
            expires_at=int((now + timedelta(days=1)).timestamp()),
            device="mcp:client-1:tenant-1",
            ip_first_seen="198.51.100.1",
            family_started_at=stamp,
        )
    )

    (before,) = sessions.list_for_user(USER_ID)
    assert before.last_ip == "198.51.100.1"
    assert before.client == ""
    assert before.client_id == "client-1"

    sessions.rotate("legacy-token", ip="203.0.113.2", user_agent="claude-code/2.0.14 (cli)")

    (after,) = sessions.list_for_user(USER_ID)
    assert after.ip == "198.51.100.1"
    assert after.last_ip == "203.0.113.2"
    assert after.client == "claude-code"


def test_the_dynamo_store_round_trips_the_new_fields(dynamodb_resource: Any) -> None:
    """`ip_last_seen`, `client` and `platform` survive a write and a read, and stay off a row without them."""
    from webbpulse.dynamodb import Repository
    from webbpulse.identity.storage import DynamoRefreshTokenStore

    dynamodb_resource.create_table(
        TableName="refresh-tokens",
        KeySchema=[{"AttributeName": "token_hash", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "token_hash", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    store = DynamoRefreshTokenStore(Repository("refresh-tokens", prefix="", region_name="us-west-2"), user_index="")
    base: dict[str, Any] = {
        "family_id": "fam",
        "user_id": USER_ID,
        "generation": 1,
        "created_at": "2026-10-23T00:00:00Z",
        "expires_at": 4_102_444_800,
    }
    store.put(
        RefreshTokenRecord(
            token_hash="with",
            ip_last_seen="203.0.113.2",
            client="claude-code",
            platform="macOS",
            **base,
        )
    )
    store.put(RefreshTokenRecord(token_hash="without", **base))

    with_fields = store.get("with")
    assert with_fields is not None
    assert (with_fields.ip_last_seen, with_fields.client, with_fields.platform) == (
        "203.0.113.2",
        "claude-code",
        "macOS",
    )
    raw = dynamodb_resource.Table("refresh-tokens").get_item(Key={"token_hash": "without"})["Item"]
    assert not {"ip_last_seen", "client", "platform"} & raw.keys()
    without = store.get("without")
    assert without is not None
    assert (without.ip_last_seen, without.client, without.platform) == ("", "", "")
