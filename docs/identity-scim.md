# SCIM provisioning

`webbpulse.identity.scim` is a SCIM 2.0 server (RFC 7643 and 7644) that identity providers
such as Okta and Entra ID call to create, update, deactivate and group a tenant's users. It
needs only the `identity` extra; FastAPI is imported when the router is built.

The nouns are generic: a **tenant** is whatever the product sells to, the **directory** is
that tenant's identity provider, and a **group** maps onto whatever the product groups users
by (teams, roles).

## Wiring

```python
from webbpulse.identity import api_keys
from webbpulse.identity.scim import ScimHooks, ScimService, build_scim_router, mint_scim_token

class Directory(ScimHooks):
    def get_user(self, tenant_id, user_id): ...
    def list_users(self, tenant_id, query): ...
    def create_user(self, tenant_id, user): ...
    def update_user(self, tenant_id, user): ...
    def deactivate_user(self, tenant_id, user): ...
    def delete_user(self, tenant_id, user_id): ...
    def get_group(self, tenant_id, group_id, *, include_members=True): ...
    def list_groups(self, tenant_id, query): ...
    def create_group(self, tenant_id, group): ...
    def update_group(self, tenant_id, group): ...
    def delete_group(self, tenant_id, group_id): ...
    def add_group_members(self, tenant_id, group_id, members): ...
    def remove_group_members(self, tenant_id, group_id, member_ids): ...

service = ScimService(Directory(), key_store, base_url="https://api.example.com/scim/v2")
app.include_router(build_scim_router(service))
```

`reactivate_user` and `scim_enabled` have defaults. Every hook is tenant-scoped and must
never touch another tenant's rows. A hook may raise `ScimError` (for example
`ScimError.uniqueness()`); anything else becomes a 500 SCIM error without detail.

## Tokens

`mint_scim_token(store, tenant_id=..., user_id=...)` mints an `api_keys` key with the `scim`
scope and kind `scim`. The plaintext is shown once and stored only as a SHA-256 hash; revoke
it with `api_keys.revoke_by_id`. The router answers 401 with a `Bearer` challenge for a
missing or unknown token, and 403 for a key without the scope or a tenant whose
`scim_enabled` is false.

## Routes

Under `/scim/v2` by default:

- `GET /ServiceProviderConfig`, `/ResourceTypes[/{name}]`, `/Schemas[/{id}]`: public.
- `GET /Users`, `POST /Users/.search`, `POST /Users`, `GET|PUT|PATCH|DELETE /Users/{id}`.
- The same for `/Groups`. A group PATCH answers 204.

Lists take `filter`, `startIndex`, `count` (clamped to `max_results`), `attributes` and
`excludedAttributes`. Filters support the full RFC 7644 grammar evaluated in memory by
`ScimQuery.apply_users` and `apply_groups`; a product with many rows answers the point
lookups providers send (`userName eq`, `externalId eq`, `displayName eq`, `id eq`) through
`query.equality(...)`. Writes and gets carry a weak `ETag`; `If-Match` gives 412 and
`If-None-Match` gives 304.

## Behaviour

- `userName` is unique per tenant, case-insensitively: a duplicate is 409 `uniqueness`.
- `active` turning false calls `deactivate_user`, true again calls `reactivate_user`,
  whether it arrives by POST, PUT or PATCH.
- Group create calls `create_group` without members, then `add_group_members`. A PATCH that
  only adds or removes members (what Okta and Entra send) skips loading the group's
  members. `excludedAttributes=members` sets `query.include_members` false unless the filter
  names members.
- `password` is accepted and dropped; `groups` on a user is read-only output.

## Provider quirks handled

- Okta: path-less `replace` with `{"active": false}`, `id` echoed inside path-less values
  (skipped), `members[value eq "id"]` removes.
- Entra ID: capitalised ops, `"True"` and `"False"` strings, path-less values keyed by
  dotted names and extension URNs, `emails[type eq "work"].value` creating the element when
  missing, `manager` given as a bare string, removes with a value list, and
  `id eq "g" and members[value eq "u"]` membership checks.
