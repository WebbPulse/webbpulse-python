# Tenant audit log

`webbpulse.audit` records who did what to which target, and when, in an append-only log
with one partition per tenant. Every payload is scrubbed of secrets before it is stored,
listings are tenant-scoped with signed cursors, and the CSV export is safe to open in a
spreadsheet.

```python
from datetime import timedelta

from webbpulse.audit import (
    AuditAction,
    AuditActor,
    AuditCatalogue,
    AuditQuery,
    AuditRecorder,
    AuditTarget,
    DynamoAuditLogStore,
    changed_fields,
)
from webbpulse.dynamodb import Repository

catalogue = AuditCatalogue(
    {
        "workspace.renamed": AuditAction("Workspace renamed", payload_fields=frozenset({"name"})),
        "token.created": "API token created",
    }
)
store = DynamoAuditLogStore(Repository("audit", prefix=settings.table_prefix))
recorder = AuditRecorder(store, catalogue, retention=timedelta(days=365))

before, after = changed_fields(old.to_dict(), new.to_dict())
recorder.record(
    workspace_id,
    "workspace.renamed",
    actor=AuditActor(id=user_id, source="web", ip=client_ip, amr=("pwd", "otp")),
    target=AuditTarget("workspace", workspace_id, new.name),
    before=before,
    after=after,
)

page = store.list_events(workspace_id, AuditQuery(action="token.created"), limit=50)
```

## The table

| Attribute | Role |
| --- | --- |
| `tenant_id` | Hash key: one partition per workspace, org or whatever the product scopes by |
| `event_id` | Range key: a ULID minted at `occurred_at`, so newest first is one descending query |
| `target_key` | `<tenant>#<target type>#<target id>`, written only when the target has both a type and an id |
| `expires_at` | TTL epoch second, written only when the recorder has a `retention` |

`AUDIT_TABLE_SPEC` is the default shape, including the sparse GSI `target_key-event_id-index`
(`AUDIT_TARGET_INDEX`). Rows are written once with a conditional put and never edited; a
second append of the same tenant and id raises `AuditEventExists`. The only removals are the
TTL and `purge_tenant`. A target with only a label, such as a deleted object, keeps its
`target_label` through `AuditRecorder.build` and `record` but joins no target index.

The other attributes are `action`, `occurred_at` (ISO 8601 with `Z`), `actor_id`,
`actor_kind`, `source`, `ip`, `amr`, `target_type`, `target_id`, `target_label`, and
`payload`, `before` and `after` as maps.

### Adopting an existing table

`AuditAttributes` maps the stored names, so a product with an audit table already in place
adopts the module without a data migration. Standupless keeps its names and has no target
GSI:

```python
STANDUPLESS = AuditAttributes(
    tenant_id="workspace_id",
    event_id="audit_id",
    action="event",
    occurred_at="created_at",
)
spec = audit_table_spec(STANDUPLESS, target_index=None)
store = DynamoAuditLogStore(repository, attributes=STANDUPLESS, target_index=None)
```

With `target_index=None` a target listing filters the tenant partition instead of querying
the index. The store still writes `target_key`, so adding the GSI later needs no backfill
for new rows.

## Recording

`AuditRecorder.record` is what a handler calls after the change has landed. It is best
effort: a store failure logs `audit_write_failed` and answers `None`, so recording never
fails the change it describes. A `ReadOnlyTable` refusal (a function without the audit grant)
is skipped quietly. `best_effort=False` re-raises both, for jobs that must not lose an event.

An action missing from the catalogue, or a payload that is not JSON, always raises, since
both are programming errors. `build` returns the scrubbed event without storing it.

`SYSTEM_ACTOR` is the actor for webhooks and scheduled jobs. `changed_fields(before, after)`
keeps only the fields that differ, which is what an update event should carry.

## The catalogue

`AuditCatalogue` is the fixed set of actions a product records. It gives each action a
display label (`label`, `event_types` for a filter dropdown) and, optionally, a
`payload_fields` allowlist applied to `payload`, `before` and `after`. Fields outside the
allowlist are dropped; allowed fields are still scrubbed for secrets.

## Redaction

Every `AuditEvent` passes its `payload`, `before` and `after` through the default
`Redaction` when it is built, so no store, recorder or caller path can persist:

- a value under a secret-looking key, at any depth. `DEFAULT_SECRET_KEYS` is matched on the
  snake-cased key or its trailing segments: `access_token`, `dbPassword` and `client_secret`
  are scrubbed, `token_id` and `secret_name` are not.
- a string shaped like a credential, under any key. `DEFAULT_SECRET_VALUE_PATTERNS` covers
  `wpk_`/`sk_`-style keys, GitHub tokens, Slack tokens, AWS access key ids, PEM private keys,
  JWTs and bearer headers. A `wpk_` or `wps_` value is scrubbed only when it runs past
  `PREFIX_DISPLAY_LENGTH` characters, so the API key display prefix from
  `webbpulse.identity.api_keys.display_prefix` is kept in an `api_key.created` payload while a
  full key is not.

Redaction runs on the write path only. A store reads its rows back through
`AuditEvent.restore`, which checks the shape but keeps `payload`, `before` and `after` as
stored, so a row written before a product adopted this module is not scrubbed again on every
read.

Scrubbed values become `"[redacted]"`. Values are normalised to JSON: datetimes to ISO 8601,
enums to their value, sets and tuples to lists, `Decimal` to int or float. Anything else, or
a non-string key, raises `TypeError`. A product extends the defaults by passing
`AuditCatalogue(..., redaction=Redaction(secret_keys=DEFAULT_SECRET_KEYS | {...}))`.

## Listing

`list_events(tenant_id, query, limit=, cursor=)` answers one `AuditPage` newest first.
`AuditQuery` narrows it:

| Field | How |
| --- | --- |
| `since`, `until` | Key condition on the ULID time prefix; `since` inclusive, `until` exclusive, naive values read as UTC |
| `target` | Queries the target GSI, or filters the partition without one |
| `actor_id`, `action` | Filters; a page can come back short, even empty, with a cursor |

`limit` runs from 1 to `MAX_PAGE_SIZE` (1000), and an empty tenant raises `ValueError`.
`iter_events` follows cursors for an export.

Cursors are signed with `encode_start_key` under `cursor_scope`: `audit:<tenant>`, or
`audit:<tenant>:target:<type>#<id>` for a target listing. A cursor from another tenant, from
a different listing, outside the query's time range, or forged raises `InvalidStartKey`.

`purge_tenant` deletes the tenant's whole log and answers how many rows went.

## CSV export

`audit_csv(events, catalogue=, actor_names=, columns=, headers=)` renders events as CSV.
`columns` picks and orders from `CSV_COLUMNS` plus `tenant_id` and `event_id`, and `headers`
renames them, so a product keeps the export its users know. Every cell passes `csv_safe`,
which prefixes `'` to a value starting with `=`, `+`, `-`, `@`, a tab or a carriage return.

## Retention

`AuditRecorder(retention=timedelta(...))` sets `expires_at` on each event, and the table's
TTL removes it. Without a retention, rows are kept until `purge_tenant`.

## Testing

`InMemoryAuditLogStore` (alias `FakeAuditLogStore`) has the table's ordering, filters and
cursors. `webbpulse.testing.assert_audit_log_contract(store)` runs the shared contract
against any `AuditLogStore`: round trip, duplicate refusal, pagination, cursor scoping, time
ranges, filters, limits and purge. Run it against a product's store, including one with
mapped attributes, to prove the adoption.
