"""`webbpulse.audit`: the tenant audit log, its scrubbing, its recorder and its export."""

from __future__ import annotations

import csv
import io
import logging
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from enum import Enum
from typing import Any

import pytest

from webbpulse.audit import (
    AUDIT_TABLE,
    AUDIT_TABLE_SPEC,
    AUDIT_TARGET_INDEX,
    REDACTED,
    SYSTEM_ACTOR,
    AuditAction,
    AuditActor,
    AuditAttributes,
    AuditCatalogue,
    AuditEvent,
    AuditEventExists,
    AuditQuery,
    AuditRecorder,
    AuditTarget,
    DynamoAuditLogStore,
    FakeAuditLogStore,
    InMemoryAuditLogStore,
    Redaction,
    audit_csv,
    audit_table_spec,
    changed_fields,
    csv_safe,
    cursor_scope,
    iter_events,
    time_floor,
)
from webbpulse.dynamodb import InvalidStartKey, Repository, encode_start_key, new_ulid
from webbpulse.identity.api_keys import PREFIX_DISPLAY_LENGTH, display_prefix, new_api_key
from webbpulse.testing import assert_audit_log_contract

PREFIX = "wp-local"
TENANT = "t1"
ALICE = AuditActor(id="alice", kind="user", source="web", ip="203.0.113.7", amr=("pwd", "otp", "mfa"))
STANDUPLESS = AuditAttributes(
    tenant_id="workspace_id",
    event_id="audit_id",
    action="event",
    occurred_at="created_at",
)
MOMENT = datetime(2026, 10, 8, 7, 1, 47, tzinfo=UTC)

CATALOGUE = AuditCatalogue(
    {
        "workspace.updated": "Workspace settings changed",
        "token.created": AuditAction("Token created", payload_fields=frozenset({"name", "scopes", "token"})),
        "variable.updated": AuditAction("Variable changed", payload_fields=frozenset({"key", "sensitive"})),
    }
)


class Colour(Enum):
    """A payload enum, stored by its value."""

    RED = "red"


def _fake(*parts: str) -> str:
    """A credential-shaped test string, assembled so no literal sits in the source."""
    return "".join(parts)


def _create(resource: Any, spec: Any = AUDIT_TABLE_SPEC) -> None:
    """Create one audit table under the test prefix."""
    client = resource.meta.client
    client.create_table(**spec.create_table_request(PREFIX))
    ttl = spec.time_to_live_request(PREFIX)
    if ttl is not None:
        client.update_time_to_live(**ttl)


@pytest.fixture
def dynamo_store(dynamodb_resource: Any) -> DynamoAuditLogStore:
    """A store over a fresh default `audit` table with the target index."""
    _create(dynamodb_resource)
    return DynamoAuditLogStore(Repository(AUDIT_TABLE, prefix=PREFIX))


@pytest.fixture
def standupless_store(dynamodb_resource: Any) -> DynamoAuditLogStore:
    """A store over a table shaped as Standupless provisions it, with no target index."""
    _create(dynamodb_resource, audit_table_spec(STANDUPLESS, target_index=None))
    return DynamoAuditLogStore(Repository(AUDIT_TABLE, prefix=PREFIX), attributes=STANDUPLESS, target_index=None)


def _event(**overrides: Any) -> AuditEvent:
    """An event in `TENANT` by `ALICE`, with any field overridden."""
    fields: dict[str, Any] = {"tenant_id": TENANT, "action": "workspace.updated", "actor": ALICE}
    fields.update(overrides)
    return AuditEvent(**fields)


def test_the_in_memory_store_meets_the_contract() -> None:
    """The fake keeps every promise the table does."""
    assert_audit_log_contract(InMemoryAuditLogStore())
    assert FakeAuditLogStore is InMemoryAuditLogStore


def test_the_dynamo_store_meets_the_contract(dynamo_store: DynamoAuditLogStore) -> None:
    """The table store with the target index keeps the contract under moto."""
    assert_audit_log_contract(dynamo_store)


def test_the_dynamo_store_meets_the_contract_without_a_target_index(dynamodb_resource: Any) -> None:
    """A table without the GSI serves target listings by filtering the tenant partition."""
    _create(dynamodb_resource, audit_table_spec(target_index=None))
    assert_audit_log_contract(DynamoAuditLogStore(Repository(AUDIT_TABLE, prefix=PREFIX), target_index=None))


def test_the_standupless_mapping_meets_the_contract(standupless_store: DynamoAuditLogStore) -> None:
    """Standupless's attribute names keep the whole contract."""
    assert_audit_log_contract(standupless_store, tenant_id="ws-contract")


def test_append_refuses_a_duplicate_event(dynamo_store: DynamoAuditLogStore) -> None:
    """The log is append-only: a second write of one id raises and leaves the first row."""
    event = dynamo_store.append(_event(payload={"name": "first"}))
    clash = AuditEvent(
        tenant_id=TENANT, action="workspace.updated", actor=ALICE, event_id=event.event_id, payload={"name": "second"}
    )
    with pytest.raises(AuditEventExists):
        dynamo_store.append(clash)
    stored = dynamo_store.list_events(TENANT).events
    assert [row.payload for row in stored] == [{"name": "first"}]


def test_the_in_memory_store_refuses_a_duplicate_event() -> None:
    """The fake refuses a duplicate the way the conditional put does."""
    store = InMemoryAuditLogStore()
    event = store.append(_event())
    with pytest.raises(AuditEventExists):
        store.append(event)
    assert store.events == [event]


def test_a_time_range_is_a_key_condition_on_the_ulid(dynamo_store: DynamoAuditLogStore) -> None:
    """since is inclusive and until exclusive, to the millisecond, naive bounds read as UTC."""
    at_since = dynamo_store.append(_event(occurred_at=MOMENT))
    before = dynamo_store.append(_event(occurred_at=MOMENT - timedelta(milliseconds=1)))
    at_until = dynamo_store.append(_event(occurred_at=MOMENT + timedelta(hours=1)))
    query = AuditQuery(since=MOMENT.replace(tzinfo=None), until=MOMENT + timedelta(hours=1))
    assert [row.event_id for row in dynamo_store.list_events(TENANT, query).events] == [at_since.event_id]
    everything = [row.event_id for row in dynamo_store.list_events(TENANT).events]
    assert everything == [at_until.event_id, at_since.event_id, before.event_id]


def test_a_target_listing_uses_the_index_and_resumes_with_a_target_cursor(dynamo_store: DynamoAuditLogStore) -> None:
    """A target query reads the sparse GSI and mints a cursor scoped to the target."""
    token = AuditTarget(type="token", id="tok_1", label="CI")
    written = [
        dynamo_store.append(_event(action="token.created", target=token, occurred_at=MOMENT + timedelta(minutes=i)))
        for i in range(3)
    ]
    dynamo_store.append(_event(occurred_at=MOMENT + timedelta(minutes=5)))
    page = dynamo_store.list_events(TENANT, AuditQuery(target=token), limit=2)
    assert [row.event_id for row in page.events] == [written[2].event_id, written[1].event_id]
    assert page.next_cursor is not None
    with pytest.raises(InvalidStartKey):
        dynamo_store.list_events(TENANT, limit=2, cursor=page.next_cursor)
    rest = dynamo_store.list_events(TENANT, AuditQuery(target=token), limit=2, cursor=page.next_cursor)
    assert [row.event_id for row in rest.events] == [written[0].event_id]
    assert cursor_scope(TENANT, token) == "audit:t1:target:token#tok_1"
    assert cursor_scope(TENANT) == "audit:t1"


def test_the_target_key_is_written_only_for_an_event_with_a_target(dynamo_store: DynamoAuditLogStore) -> None:
    """The index is sparse: an untargeted event has no target_key attribute."""
    targeted = _event(target=AuditTarget(type="workspace", id="w1"))
    untargeted = _event()
    assert targeted.target_key == "t1#workspace#w1"
    assert untargeted.target_key == ""
    dynamo_store.append(targeted)
    dynamo_store.append(untargeted)
    table = Repository(AUDIT_TABLE, prefix=PREFIX).table
    stored = {str(item["event_id"]): item for item in table.scan()["Items"]}
    assert stored[targeted.event_id]["target_key"] == "t1#workspace#w1"
    assert "target_key" not in stored[untargeted.event_id]


@pytest.mark.parametrize("store_kind", ["memory", "dynamo"])
def test_actor_and_action_filters_read_on_past_empty_pages(store_kind: str, request: pytest.FixtureRequest) -> None:
    """A filter that leaves a read short keeps reading until the page fills or the log ends."""
    store: Any = InMemoryAuditLogStore() if store_kind == "memory" else request.getfixturevalue("dynamo_store")
    bob = AuditActor(id="bob", kind="api_key", source="cli")
    match = store.append(_event(actor=bob, action="token.created", occurred_at=MOMENT))
    for minute in range(1, 6):
        store.append(_event(occurred_at=MOMENT + timedelta(minutes=minute)))
    page = store.list_events(TENANT, AuditQuery(actor_id="bob"), limit=1)
    assert [row.event_id for row in page.events] == [match.event_id]
    by_action = store.list_events(TENANT, AuditQuery(action="token.created"), limit=5)
    assert [row.event_id for row in by_action.events] == [match.event_id]
    assert store.list_events(TENANT, AuditQuery(actor_id="bob", action="workspace.updated")).events == []


@pytest.mark.parametrize("store_kind", ["memory", "dynamo"])
def test_a_cursor_round_trips_across_pages(store_kind: str, request: pytest.FixtureRequest) -> None:
    """Following cursors visits every event exactly once, newest first."""
    store: Any = InMemoryAuditLogStore() if store_kind == "memory" else request.getfixturevalue("dynamo_store")
    written = [store.append(_event(occurred_at=MOMENT + timedelta(seconds=i))) for i in range(7)]
    seen: list[str] = []
    cursor: str | None = None
    for _ in range(10):
        page = store.list_events(TENANT, limit=3, cursor=cursor)
        seen.extend(row.event_id for row in page.events)
        cursor = page.next_cursor
        if cursor is None:
            break
    assert seen == [event.event_id for event in reversed(written)]
    assert [row.event_id for row in iter_events(store, TENANT, page_size=2, max_items=3)] == seen[:3]


@pytest.mark.parametrize("store_kind", ["memory", "dynamo"])
def test_a_foreign_or_forged_cursor_is_refused(store_kind: str, request: pytest.FixtureRequest) -> None:
    """A cursor resumes only its own tenant's listing, even one forged under the right scope."""
    store: Any = InMemoryAuditLogStore() if store_kind == "memory" else request.getfixturevalue("dynamo_store")
    for i in range(3):
        store.append(_event(occurred_at=MOMENT + timedelta(seconds=i)))
    cursor = store.list_events(TENANT, limit=1).next_cursor
    with pytest.raises(InvalidStartKey):
        store.list_events("t2", limit=1, cursor=cursor)
    forged = encode_start_key({"tenant_id": "t2", "event_id": new_ulid(MOMENT)}, scope=cursor_scope(TENANT))
    with pytest.raises(InvalidStartKey):
        store.list_events(TENANT, limit=1, cursor=forged)


@pytest.mark.parametrize("store_kind", ["memory", "dynamo"])
def test_purge_tenant_removes_only_that_tenant(store_kind: str, request: pytest.FixtureRequest) -> None:
    """A purge pages through the partition and leaves every other tenant untouched."""
    store: Any = InMemoryAuditLogStore() if store_kind == "memory" else request.getfixturevalue("dynamo_store")
    for i in range(130):
        store.append(_event(occurred_at=MOMENT + timedelta(milliseconds=i)))
    kept = store.append(_event(tenant_id="t2"))
    assert store.purge_tenant(TENANT) == 130
    assert store.list_events(TENANT).events == []
    assert [row.event_id for row in store.list_events("t2").events] == [kept.event_id]
    assert store.purge_tenant("") == 0


def test_secret_keys_are_scrubbed_at_any_depth() -> None:
    """A secret-named key is redacted wherever it sits; an identifier beside it is kept."""
    event = _event(
        payload={
            "access_token": "abc",
            "token_id": "tok_1",
            "token_name": "CI",
            "secret_name": "deploy",
            "Api-Key": "k",
            "nested": {"dbPassword": "p", "items": [{"client_secret": "s", "name": "ok"}]},
        },
        before={"password": "old"},
        after={"password": "new", "name": "kept"},
    )
    assert event.payload == {
        "access_token": REDACTED,
        "token_id": "tok_1",
        "token_name": "CI",
        "secret_name": "deploy",
        "Api-Key": REDACTED,
        "nested": {"dbPassword": REDACTED, "items": [{"client_secret": REDACTED, "name": "ok"}]},
    }
    assert event.before == {"password": REDACTED}
    assert event.after == {"password": REDACTED, "name": "kept"}


@pytest.mark.parametrize(
    "value",
    [
        _fake("ghp_", "a" * 36),
        _fake("github_pat_", "b" * 30),
        _fake("AK", "IA", "Q" * 16),
        _fake("sk", "_live_", "c" * 20),
        _fake("wpk", "_", "d" * 20),
        _fake("xox", "b-", "e" * 20),
        _fake("-----BEGIN RSA ", "PRIVATE KEY-----\nMII"),
        _fake("ey", "JhbGciOiJIUzI1", ".", "eyJzdWIiOiIxMjM0", ".", "sig"),
        _fake("Bearer ", "f" * 24),
        _fake("see ", "ghp_", "g" * 36, " here"),
    ],
)
def test_values_shaped_like_credentials_are_scrubbed(value: str) -> None:
    """A credential-shaped string is redacted whole, whatever key holds it."""
    event = _event(payload={"note": value, "list": [value]})
    assert event.payload == {"note": REDACTED, "list": [REDACTED]}


def test_ordinary_values_survive_scrubbing() -> None:
    """Prose, ids and short prefixes are not mistaken for credentials."""
    payload = {"note": "rotated the sk_ prefix", "id": "01J0000000000000000000000A", "skip": "task_1"}
    assert _event(payload=payload).payload == payload


def test_an_api_key_display_prefix_survives_and_a_full_key_does_not() -> None:
    """The clear-text display prefix is not a credential; one character past it is treated as one."""
    key = new_api_key()
    prefix = display_prefix(key)
    event = _event(payload={"prefix": prefix, "key": key, "longer": key[: PREFIX_DISPLAY_LENGTH + 1]})
    assert event.payload == {"prefix": prefix, "key": REDACTED, "longer": REDACTED}
    share = _fake("wps", "_", "h" * 8)
    assert _event(payload={"share": share}).payload == {"share": share}


def test_a_stored_row_is_not_scrubbed_again_on_read(dynamo_store: DynamoAuditLogStore) -> None:
    """Redaction runs on the write path only, so a row reads back exactly as it was stored."""
    table = Repository(AUDIT_TABLE, prefix=PREFIX).table
    event_id = new_ulid(MOMENT)
    stored_value = _fake("sk", "_live_", "c" * 20)
    table.put_item(
        Item={
            "tenant_id": TENANT,
            "event_id": event_id,
            "action": "workspace.updated",
            "occurred_at": "2026-10-08T07:01:47Z",
            "actor_id": "alice",
            "payload": {"note": stored_value, "password": "legacy"},
        }
    )
    row = dynamo_store.list_events(TENANT).events[0]
    assert row.payload == {"note": stored_value, "password": "legacy"}


def test_restore_keeps_payloads_and_still_checks_the_shape() -> None:
    """`AuditEvent.restore` skips scrubbing but refuses an event with no tenant or a bad id."""
    secret = _fake("sk", "_live_", "c" * 20)
    restored = AuditEvent.restore(
        tenant_id=TENANT,
        action="workspace.updated",
        actor=ALICE,
        event_id=new_ulid(MOMENT),
        occurred_at=MOMENT,
        payload={"note": secret},
        before={"password": "old"},
    )
    assert restored.payload == {"note": secret}
    assert restored.before == {"password": "old"}
    assert restored.after is None
    with pytest.raises(ValueError):
        AuditEvent.restore(tenant_id="", action="a", actor=ALICE, event_id=new_ulid(MOMENT), occurred_at=MOMENT)
    with pytest.raises(ValueError):
        AuditEvent.restore(tenant_id=TENANT, action="a", actor=ALICE, event_id="nope", occurred_at=MOMENT)


def test_payloads_are_normalised_to_json() -> None:
    """Datetimes, enums, decimals, sets and tuples become JSON values; anything else is refused."""
    event = _event(
        payload={
            "at": datetime(2026, 1, 1, 12, 0),
            "on": date(2026, 1, 2),
            "colour": Colour.RED,
            "count": Decimal("3"),
            "ratio": Decimal("0.5"),
            "tags": {"b", "a"},
            "pair": (1, 2),
        }
    )
    assert event.payload == {
        "at": "2026-01-01T12:00:00+00:00",
        "on": "2026-01-02",
        "colour": "red",
        "count": 3,
        "ratio": 0.5,
        "tags": ["a", "b"],
        "pair": [1, 2],
    }
    with pytest.raises(TypeError):
        _event(payload={"thing": object()})
    numeric_keys: dict[Any, Any] = {1: "x"}
    with pytest.raises(TypeError):
        Redaction().apply(numeric_keys)


def test_an_event_refuses_a_bad_shape() -> None:
    """No tenant, a '#' in a key part, no action, no actor or a non-ULID id are refused."""
    with pytest.raises(ValueError, match="tenant_id"):
        _event(tenant_id="")
    with pytest.raises(ValueError, match="'#'"):
        _event(tenant_id="a#b")
    with pytest.raises(ValueError, match="action"):
        _event(action="")
    with pytest.raises(ValueError, match="actor"):
        _event(actor=AuditActor(id=""))
    with pytest.raises(ValueError, match="target type"):
        _event(target=AuditTarget(type="a#b", id="x"))
    with pytest.raises(ValueError, match="ULID"):
        _event(event_id="not-a-ulid")
    naive = _event(occurred_at=datetime(2026, 1, 1))
    assert naive.occurred_at.tzinfo is UTC
    assert naive.event_id[:10] == time_floor(datetime(2026, 1, 1))


def test_the_catalogue_labels_and_lists_actions() -> None:
    """Labels come from the catalogue, an unknown action falls back to itself."""
    assert "token.created" in CATALOGUE
    assert "nope" not in CATALOGUE
    assert len(CATALOGUE) == 3
    assert list(CATALOGUE) == ["workspace.updated", "token.created", "variable.updated"]
    assert CATALOGUE.label("token.created") == "Token created"
    assert CATALOGUE.label("nope") == "nope"
    assert CATALOGUE.event_types()[0] == ("workspace.updated", "Workspace settings changed")


def test_a_catalogue_allowlist_drops_unlisted_fields_and_still_scrubs_secrets() -> None:
    """Only the action's payload fields are kept, and an allowed secret key is still redacted."""
    recorder = AuditRecorder(InMemoryAuditLogStore(), CATALOGUE)
    event = recorder.record(
        TENANT,
        "token.created",
        actor=ALICE,
        payload={"name": "CI", "scopes": ["runs:read"], "token": "plain", "hash": "h"},
    )
    assert event is not None
    assert event.payload == {"name": "CI", "scopes": ["runs:read"], "token": REDACTED}
    changed = recorder.record(
        TENANT,
        "variable.updated",
        actor=ALICE,
        before={"key": "DB_URL", "value": "old", "sensitive": False},
        after={"key": "DB_URL", "value": "new", "sensitive": True},
    )
    assert changed is not None
    assert changed.before == {"key": "DB_URL", "sensitive": False}
    assert changed.after == {"key": "DB_URL", "sensitive": True}
    unrestricted = recorder.record(TENANT, "workspace.updated", actor=ALICE, payload={"name": "x", "extra": 1})
    assert unrestricted is not None
    assert unrestricted.payload == {"name": "x", "extra": 1}


def test_a_product_redaction_adds_secret_keys() -> None:
    """A catalogue's base redaction extends the default secret names."""
    catalogue = AuditCatalogue(
        {"run.confirmed": "Run confirmed"},
        redaction=Redaction(secret_keys=frozenset({"state_url"})),
    )
    event = AuditRecorder(InMemoryAuditLogStore(), catalogue).record(
        TENANT, "run.confirmed", actor=ALICE, payload={"state_url": "https://x", "password": "p"}
    )
    assert event is not None
    assert event.payload == {"state_url": REDACTED, "password": REDACTED}


class _BrokenStore(InMemoryAuditLogStore):
    """A store whose every append fails."""

    def append(self, event: AuditEvent) -> AuditEvent:
        """Fail the write."""
        raise RuntimeError("table unavailable")


def test_the_recorder_never_raises_on_a_store_failure(caplog: pytest.LogCaptureFixture) -> None:
    """A failed write is logged and answers None, so the change it describes still lands."""
    recorder = AuditRecorder(_BrokenStore(), CATALOGUE)
    with caplog.at_level(logging.ERROR, logger="webbpulse.audit"):
        assert recorder.record(TENANT, "workspace.updated", actor=ALICE) is None
    assert any(record.message == "audit_write_failed" for record in caplog.records)
    strict = AuditRecorder(_BrokenStore(), CATALOGUE, best_effort=False)
    with pytest.raises(RuntimeError):
        strict.record(TENANT, "workspace.updated", actor=ALICE)


def test_the_recorder_skips_a_read_only_table(dynamodb_resource: Any) -> None:
    """A function without the audit grant skips the write quietly."""
    _create(dynamodb_resource)
    store = DynamoAuditLogStore(Repository(AUDIT_TABLE, prefix=PREFIX, read_only=True))
    recorder = AuditRecorder(store, CATALOGUE)
    assert recorder.record(TENANT, "workspace.updated", actor=ALICE) is None
    assert store.list_events(TENANT).events == []


def test_the_recorder_raises_on_programming_errors() -> None:
    """An unknown action and a payload that is not JSON are bugs, so they raise."""
    recorder = AuditRecorder(InMemoryAuditLogStore(), CATALOGUE)
    with pytest.raises(ValueError, match="Unknown audit action"):
        recorder.record(TENANT, "nope", actor=ALICE)
    with pytest.raises(TypeError):
        recorder.record(TENANT, "workspace.updated", actor=ALICE, payload={"x": object()})


def test_the_recorder_records_a_system_event() -> None:
    """A webhook or a job records under the system actor."""
    store = InMemoryAuditLogStore()
    event = AuditRecorder(store, CATALOGUE).record(TENANT, "workspace.updated", actor=SYSTEM_ACTOR)
    assert event is not None
    assert store.events[0].actor == AuditActor(id="system", kind="system", source="system")


@pytest.mark.parametrize("store_kind", ["memory", "dynamo"])
def test_the_recorder_keeps_a_label_only_target(store_kind: str, request: pytest.FixtureRequest) -> None:
    """A target with only a label round trips through build and record and joins no target index."""
    store = InMemoryAuditLogStore() if store_kind == "memory" else request.getfixturevalue("dynamo_store")
    recorder = AuditRecorder(store, CATALOGUE, best_effort=False)
    labelled = AuditTarget(label="Deleted workspace")
    built = recorder.build(TENANT, "workspace.updated", actor=ALICE, target=labelled)
    assert built.target == labelled
    assert built.target_key == ""
    recorded = recorder.record(TENANT, "workspace.updated", actor=ALICE, target=labelled)
    assert recorded is not None
    assert recorded.target == labelled
    assert store.list_events(TENANT).events[0].target == labelled
    if store_kind == "dynamo":
        table = Repository(AUDIT_TABLE, prefix=PREFIX).table
        item = table.get_item(Key={"tenant_id": TENANT, "event_id": recorded.event_id})["Item"]
        assert item["target_label"] == "Deleted workspace"
        assert "target_key" not in item
    assert recorder.build(TENANT, "workspace.updated", actor=ALICE).target == AuditTarget()


def test_retention_sets_the_ttl(dynamo_store: DynamoAuditLogStore) -> None:
    """The expiry is the event time plus the retention, stored on the TTL attribute."""
    recorder = AuditRecorder(dynamo_store, CATALOGUE, retention=timedelta(days=365), clock=lambda: MOMENT)
    event = recorder.record(TENANT, "workspace.updated", actor=ALICE)
    assert event is not None
    assert event.expires_at == int((MOMENT + timedelta(days=365)).timestamp())
    assert dynamo_store.list_events(TENANT).events[0].expires_at == event.expires_at
    later = recorder.record(TENANT, "workspace.updated", actor=ALICE, occurred_at=MOMENT + timedelta(days=1))
    assert later is not None
    assert later.expires_at == int((MOMENT + timedelta(days=366)).timestamp())
    kept = AuditRecorder(InMemoryAuditLogStore(), CATALOGUE).record(TENANT, "workspace.updated", actor=ALICE)
    assert kept is not None
    assert kept.expires_at is None
    assert AUDIT_TABLE_SPEC.ttl_attribute == "expires_at"


def test_changed_fields_keeps_only_the_differences() -> None:
    """A field that did not change is left out of both sides; a new field reads None before."""
    before, after = changed_fields({"name": "a", "plan": "free", "gone": 1}, {"name": "a", "plan": "pro", "new": 2})
    assert before == {"plan": "free", "new": None}
    assert after == {"plan": "pro", "new": 2}
    assert changed_fields({"a": 1}, {"a": 1}) == ({}, {})


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@", "\t", "\r"])
def test_csv_safe_guards_every_formula_prefix(prefix: str) -> None:
    """A cell a spreadsheet would evaluate is quoted."""
    assert csv_safe(f"{prefix}SUM(A1)") == f"'{prefix}SUM(A1)"
    assert csv_safe("plain") == "plain"
    assert csv_safe("") == ""


def test_audit_csv_guards_formulas_and_maps_columns() -> None:
    """Every cell is guarded, labels come from the catalogue, and columns and headers remap."""
    event = _event(
        action="token.created",
        target=AuditTarget(type="token", id="t1", label='=HYPERLINK("http://x")'),
        payload={"name": "@evil"},
        occurred_at=MOMENT,
    )
    rows = list(csv.reader(io.StringIO(audit_csv([event], catalogue=CATALOGUE, actor_names={"alice": "+Alice"}))))
    header, row = rows
    cells = dict(zip(header, row, strict=True))
    assert cells["target_label"] == '\'=HYPERLINK("http://x")'
    assert cells["actor_name"] == "'+Alice"
    assert cells["label"] == "Token created"
    assert cells["amr"] == "pwd otp mfa"
    assert cells["payload"] == '{"name":"@evil"}'
    assert cells["occurred_at"] == MOMENT.isoformat()

    remapped = audit_csv(
        [event],
        columns=("occurred_at", "action", "actor_id", "before"),
        headers={"occurred_at": "created_at", "action": "event"},
    )
    assert remapped.splitlines()[0] == "created_at,event,actor_id,before"
    assert remapped.splitlines()[1].endswith(",token.created,alice,")
    with pytest.raises(ValueError, match="Unknown audit CSV columns"):
        audit_csv([event], columns=("nope",))


def test_the_table_spec_matches_the_default_and_standupless_shapes() -> None:
    """The default spec carries the sparse target index; the Standupless one is its existing table."""
    request = AUDIT_TABLE_SPEC.create_table_request("wp-prod")
    assert request["TableName"] == "wp-prod-audit"
    assert request["KeySchema"] == [
        {"AttributeName": "tenant_id", "KeyType": "HASH"},
        {"AttributeName": "event_id", "KeyType": "RANGE"},
    ]
    assert [index["IndexName"] for index in request["GlobalSecondaryIndexes"]] == [AUDIT_TARGET_INDEX]
    standupless = audit_table_spec(STANDUPLESS, target_index=None).create_table_request("stup-prod")
    assert standupless["KeySchema"] == [
        {"AttributeName": "workspace_id", "KeyType": "HASH"},
        {"AttributeName": "audit_id", "KeyType": "RANGE"},
    ]
    assert "GlobalSecondaryIndexes" not in standupless
    assert {entry["AttributeName"] for entry in standupless["AttributeDefinitions"]} == {"workspace_id", "audit_id"}


def test_the_standupless_mapping_reads_existing_rows_and_cursors(standupless_store: DynamoAuditLogStore) -> None:
    """A row Standupless already wrote reads back, and a cursor it minted still resumes."""
    table = Repository(AUDIT_TABLE, prefix=PREFIX).table
    first_id = new_ulid(MOMENT)
    second_id = new_ulid(MOMENT + timedelta(minutes=1))
    for audit_id, label in ((first_id, "Bob"), (second_id, "Carol")):
        table.put_item(
            Item={
                "workspace_id": "ws1",
                "audit_id": audit_id,
                "event": "member.removed",
                "actor_id": "u1",
                "actor_kind": "user",
                "source": "web",
                "ip": "",
                "amr": ["pwd"],
                "target_type": "user",
                "target_id": label.lower(),
                "target_label": label,
                "before": {"role": "admin"},
                "after": None,
                "created_at": "2026-10-08T07:01:47.314402Z",
                "expires_at": 1_791_000_000,
            }
        )
    page = standupless_store.list_events("ws1", limit=1)
    row = page.events[0]
    assert row.event_id == second_id
    assert row.action == "member.removed"
    assert row.actor == AuditActor(id="u1", kind="user", source="web", ip="", amr=("pwd",))
    assert row.target == AuditTarget(type="user", id="carol", label="Carol")
    assert row.before == {"role": "admin"}
    assert row.after is None
    assert row.payload == {}
    assert row.occurred_at == datetime(2026, 10, 8, 7, 1, 47, 314402, tzinfo=UTC)
    assert row.expires_at == 1_791_000_000

    legacy_cursor = encode_start_key({"workspace_id": "ws1", "audit_id": second_id}, scope="audit:ws1")
    resumed = standupless_store.list_events("ws1", limit=5, cursor=legacy_cursor)
    assert [event.event_id for event in resumed.events] == [first_id]
    by_target = standupless_store.list_events("ws1", AuditQuery(target=row.target))
    assert [event.event_id for event in by_target.events] == [second_id]
    filtered = standupless_store.list_events("ws1", AuditQuery(action="member.removed", actor_id="u1"))
    assert len(filtered.events) == 2


def test_the_standupless_mapping_writes_its_attribute_names(standupless_store: DynamoAuditLogStore) -> None:
    """A row written through the mapping uses Standupless's names, so its own reader still works."""
    event = standupless_store.append(
        AuditEvent(
            tenant_id="ws1",
            action="api_key.created",
            actor=ALICE,
            target=AuditTarget(type="api_key", id="k1"),
            occurred_at=MOMENT,
            expires_at=1_791_000_000,
        )
    )
    table = Repository(AUDIT_TABLE, prefix=PREFIX).table
    item = table.get_item(Key={"workspace_id": "ws1", "audit_id": event.event_id})["Item"]
    assert item["event"] == "api_key.created"
    assert item["created_at"] == "2026-10-08T07:01:47Z"
    assert item["expires_at"] == 1_791_000_000
    assert item["actor_id"] == "alice"
    assert item["amr"] == ["pwd", "otp", "mfa"]
    assert "tenant_id" not in item
    assert "action" not in item
