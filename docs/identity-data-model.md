# Identity standard: the data model

Section 4 of [the identity standard](identity-standard.md), split out for length. Every
statement here is normative and belongs to that standard. The table and index names are the
contract between the Terraform platform module and this package. Back to the
[README](../README.md).

## 4. Data model

### 4.1 Per-entity tables, not single-table

Access patterns are point lookups on an exact key. Per-table TTL decides it: refresh tokens,
challenges, states and verification tokens want a TTL; users, passkeys and recovery codes MUST
never have one. TTL is table-level, so mixing them means permanent items carry a TTL attribute
that must never be set, and one bug silently deletes accounts. Per-table IAM keeps each
domain's grants to its own tables. Alarms are aggregated, never per table.

### 4.2 The tables

Names are the logical constants in `webbpulse.identity.storage`, `.oauth` and `.lockout`.
`webbpulse.dynamodb.table_name` prefixes each with the environment (`<prefix>-<logical>`).

| Table (constant) | Hash / range | Index | TTL |
|---|---|---|---|
| `users` (`USERS_TABLE`) | `id` | `email_lower-index`, `username_lower-index` | **never** |
| `credentials` (`CREDENTIALS_TABLE`) | `user_id` / `credential_type` | none | none |
| `passkeys` (`PASSKEYS_TABLE`) | `user_id` / `credential_id` | `credential_id-index` (`PASSKEY_CREDENTIAL_INDEX`) | none |
| `totp-factors` (`TOTP_FACTORS_TABLE`) | `user_id` | none | none |
| `recovery-codes` (`RECOVERY_CODES_TABLE`) | `user_id` / `code_hash` | none | **never** |
| `oauth-links` (`OAUTH_LINKS_TABLE`) | `provider_subject` | `user_id-index` (`OAUTH_LINK_USER_INDEX`) | none |
| `refresh-tokens` (`REFRESH_TOKENS_TABLE`) | `token_hash` | `family_id-generation-index` (`REFRESH_FAMILY_INDEX`), `user_id-family_id-index` (`REFRESH_USER_INDEX`) | `expires_at` |
| `identity-tokens` (`IDENTITY_TOKENS_TABLE`) | `token_hash` | none | `expires_at` |
| `webauthn-challenges` (`WEBAUTHN_CHALLENGES_TABLE`) | `challenge_id` | none | `expires_at` |
| `oauth-states` (`OAUTH_STATES_TABLE`) | `state` | none | `expires_at` |
| `login-attempts` (`LOGIN_ATTEMPTS_TABLE`) | `identity_key` / `attempted_at` | none | `expires_at` |

Attributes beyond the keys:

- **`users`** (exists, extended): `password_updated_at`, `mfa_enforced`, `failed_login_count`,
  `locked_until`, `last_login_at`. Username and email uniqueness is enforced by a sentinel item
  `#unique#<attr>#<value>` written in the same `TransactWriteItems` as the user record. **A GSI
  MUST NOT be relied on for uniqueness**: a GSI write is asynchronous and a conditional check
  cannot span it. The record is **owned by the product's `users` domain**; identity reads
  freely and writes only the attributes above, through the `user_repository` hook. **The
  record model must not annotate the address `EmailStr`**: ephemeral e2e users are created on
  the reserved `e2e.invalid` domain, which `email-validator` refuses with no setting that
  re-admits it, so an `EmailStr` record model answers 500 on `POST /api/auth/e2e/users`. Keep
  `EmailStr` on request schemas and let the record hold a plain `local@domain` string.
- **`credentials`**: the password hash under type `password` (`PASSWORD_CREDENTIAL_TYPE`), kept
  off the user record so a route returning a user cannot serialise a hash.
- **`passkeys`**: `credential_id`, `public_key` (COSE), `sign_count`, `transports`, `aaguid`,
  `name`, `backed_up`, `uv_capable`, `created_at`, `last_used_at`.
- **`totp-factors`**: `secret_ciphertext`, `encryption_context_user`, `activated_at`,
  `last_used_step`. See 4.4.
- **`recovery-codes`**: `used_at`, `created_at`.
- **`oauth-links`**: `provider_account_key`, `provider_email`, `provider_email_verified`,
  `linked_at`.
- **`refresh-tokens`**: `family_id`, `user_id`, `generation`, `consumed_at`, `successor_hash`,
  `revoked`, `device` (a coarse user-agent class, **never a fingerprint**), `ip_first_seen`,
  `created_at`, `expires_at`. Keying on the hash makes validation one `GetItem`;
  `family_id-generation-index` supports family revocation and `user_id-family_id-index`
  supports signing one user out everywhere, which is what a password change and a password
  reset do. The user index projects `KEYS_ONLY` and its name is read from
  `IDENTITY_REFRESH_USER_INDEX`; a table provisioned without it makes
  `revoke_all_for_user` raise, which `SessionService` reports as nothing revoked.
- **`identity-tokens`** (verification and reset): `purpose`, `user_id`, `created_at`,
  `consumed_at`, `expires_at`.
- **`webauthn-challenges`**: `user_id` (absent for a discoverable-credential login, present
  for a registration or a step-up), `challenge`, `purpose` (`register`, `login` or
  `step_up`, which is what keeps the three ceremonies from answering each other),
  `expires_at` (`CHALLENGE_TTL_SECONDS` = 300).
- **`oauth-states`**: `pkce_verifier`, `provider`, `mode`, `return_to`, `expires_at`
  (`OAUTH_STATE_TTL_SECONDS` = 600).
- **`login-attempts`**: `identity_key` is `email#<lower>` or `ip#<addr>`; `outcome`, `user_id`,
  `ip`, `user_agent`, `expires_at` (`ATTEMPT_TTL` = 30 days). Feeds lockout (5.1) and audit.

The limiter's own `rate-limits` table is reused unchanged.

`webbpulse.identity.storage.TABLES` is these ten tables as `TableSpec` values, matching
the `tables` default in `platform-modules/aws//modules/identity` exactly. Each carries
`create_table_request(prefix)`, the boto3 `create_table` keyword mapping under that
environment's prefix, and `time_to_live_request(prefix)`, which is `None` for a table with
no TTL. Billing is always `PAY_PER_REQUEST`. A local bootstrap walks it rather than
hand-writing the shapes per repo, so a key schema cannot drift from what Terraform
provisions; `users` is not among them, because it belongs to the product's own domain,
though `create_identity_tables` in section 4.5 creates it alongside them by default.
`tests/test_identity_tables.py` pins every name, key, index and TTL against a literal copy
of the module.

```python
import boto3

from webbpulse.identity import TABLES

client = boto3.client("dynamodb", endpoint_url="http://127.0.0.1:8001")
for spec in TABLES:
    client.create_table(**spec.create_table_request("webbpulse-local"))
    ttl = spec.time_to_live_request("webbpulse-local")
    if ttl is not None:
        client.update_time_to_live(**ttl)
```

### 4.3 Every TTL, in one place

| Table | TTL attribute | Window |
|---|---|---|
| `refresh-tokens` | `expires_at` | 30 days rolling, 90 absolute |
| `identity-tokens` | `expires_at` | 24 h verify, 1 h reset |
| `webauthn-challenges` | `expires_at` | 5 minutes |
| `oauth-states` | `expires_at` | 10 minutes |
| `login-attempts` | `expires_at` | 30 days |

TTL is storage reclamation only. **Every one MUST also be checked against the clock on read.**

### 4.4 TOTP seeds are envelope encrypted

A TOTP seed is a symmetric shared secret: it cannot be hashed, and a table read compromises
the second factor for every user.

Seeds MUST be **envelope encrypted under a separate KMS key** (`data_key_arn`, distinct from
the signing key) with a per-user encryption context (`TOTP_ENCRYPTION_PURPOSE` = `totp`):

```
EncryptionContext = {"user_id": "<id>", "purpose": "totp"}
```

The context is authenticated additional data: a ciphertext moved to another user's row fails
to decrypt (`EnvelopeDecryptionFailed`). Reading a seed needs both `dynamodb:GetItem` and
`kms:Decrypt` with that context, and every decrypt is a CloudTrail event.

**A data key per seed, not direct `Encrypt`/`Decrypt`.** `GenerateDataKey` returns a fresh
256-bit key every time (`AES_KEY_BYTES` = 32, `GCM_NONCE_BYTES` = 12), making AES-GCM nonce
reuse impossible. One KMS call to seal, one to open. The AES-GCM is `cryptography`'s.

Recovery codes are **hashed, not encrypted** (`hash_recovery_code`). They are high-entropy
(`RECOVERY_CODE_BYTES` = 12, `RECOVERY_CODE_COUNT` = 10 per set), so SHA-256 with a
constant-time comparison replaces bcrypt, and codes are **single use**.
`normalise_recovery_code` canonicalises input before hashing.

### 4.5 Mounting it: the shared DynamoDB glue

Three products were hand-writing the same four things to put this data model behind the
router: a `package_glue.py` assembling nine stores, a users repository, an `IdentityHooks`
implementation, and a create-tables loop. All four are in the package now, so a product
supplies its `claims_for` override and its table prefix and nothing else.

```python
from webbpulse.identity import (
    DynamoUsersHooks,
    build_dynamo_router,
    create_identity_tables,
    dynamo_stores,
    users_repository,
)
```

**`dynamo_stores(prefix=None, *, region_name=None, endpoint_url=None) -> IdentityStores`**
builds all nine `Dynamo*Store` instances from the package's own table constants. Nothing
touches AWS: each repository resolves its table on first use, so a cold Lambda import stays
free. `dynamo_login_attempts` builds the lockout store, which `build_identity_router` takes
as its own argument rather than as a field of `IdentityStores`.

**`build_dynamo_router(settings, hooks, *, prefix=None, service="identity", version="", ...)`**
wraps `build_identity_router` with the stores, the login attempt store and the signing client
built from `prefix` and `settings`. Every other argument `build_identity_router` takes is
passed straight through, so a product that mounts the OAuth authorization server
(`oauth_server_stores`, `consent_renderer`, `tenant_resolver`) or supplies `email_sender` and
`oauth_client_secrets` loses nothing by adopting it. `stores`, `attempts` and `kms_client`
override what would be built, which is how a test substitutes in-memory stores.

The router carries the issuer's own path, so mount it with **no prefix of its own**: a prefix
would double every path to `/api/auth/api/auth/...`.

**`User` and `DynamoUsersRepository`** are the shared account row: `id`, `email`,
`display_name`, `email_verified`, `disabled`, `is_admin`, `created_at`, with `email_lower`
written alongside the address so the `email_lower-index` GSI (`EMAIL_INDEX`) can resolve a
lowercased address to its user. `update` aliases every attribute name, because DynamoDB
reserves ordinary words such as `name` and `status`; setting `email` rewrites `email_lower`
in the same call, so the index can never disagree with the row. `delete` is idempotent and
`get_many` is one `BatchGetItem` behind a member list.

Two ways to name the physical table, matching the two patterns in the estate:

```python
users_repository(prefix="standupless-staging")          # -> standupless-staging-users
users_repository(table_name="control-plane-prod-users")  # the stack named it outright
```

Passing both is a `ValueError` rather than a precedence rule, since the two would disagree.
A product with extra fields subclasses `User` and passes it as `model=`; the repository is
generic over the model, so the subclass round-trips without a second repository.

**`DynamoUsersHooks(BaseIdentityHooks)`** implements every hook over that repository:
`may_authenticate` (disabled -> `ACCOUNT_DISABLED`, unverified -> `EMAIL_NOT_VERIFIED`, both
behind one `REFUSAL_MESSAGE` so the difference cannot enumerate addresses), `load_user_by_id`,
`load_user_by_email`, `create_user`, `mark_email_verified`, `delete_user`, `on_user_created`,
`has_other_sign_in_method` and `user_repository`. `claims_for` inherits `BaseIdentityHooks`'s
empty mapping, which is correct for a product with no roles, and is the one hook a product
with roles overrides.

**`create_identity_tables(client, prefix="", *, skip_existing=True, include_users=True)`**
walks `TABLES`, creates each table and applies its declared TTL through
`update_time_to_live`, because TTL is not part of `CreateTable`. It returns the names it
created. `users` is included by default; pass `include_users=False` for a product whose own
stack or script names that table. For a local stack or a test suite only: in AWS these
tables belong to `platform-modules/aws//modules/identity`.

For tests, `webbpulse.testing` adds an `identity_tables` fixture creating all of them under
no prefix in moto, and `assert_users_repository_contract(repository)`, a reusable contract a
product runs against its own repository: round trip, case-insensitive address lookup, an
update that keeps the index in step, `KeyError` for an absent row, `get_many` skipping what
is gone, and an idempotent delete.

#### Migration for adopters

`package_glue.py` loses the store assembly. Before:

```python
def build_router(settings: "Settings") -> "APIRouter":
    from webbpulse.dynamodb import Repository
    from webbpulse.identity import (
        CREDENTIALS_TABLE, ..., DynamoCredentialStore, ..., IdentityStores,
        build_identity_router, signing_client,
    )

    def repository(logical_name: str) -> Repository:
        return Repository(
            logical_name,
            prefix=settings.dynamodb_table_prefix,
            endpoint_url=settings.DYNAMODB_ENDPOINT_URL or None,
        )

    identity_settings = build_identity_settings(settings)
    stores = IdentityStores(
        credentials=DynamoCredentialStore(repository(CREDENTIALS_TABLE)),
        ...  # eight more
    )
    return build_identity_router(
        identity_settings,
        ProductIdentityHooks(),
        stores,
        kms_client=signing_client(identity_settings),
        service="product-identity",
        version=IDENTITY_ROUTER_VERSION,
        attempts=DynamoLoginAttemptStore(repository(LOGIN_ATTEMPTS_TABLE)),
        email_sender=build_email_sender(identity_settings),
        oauth_client_secrets=build_oauth_client_secrets(settings),
    )
```

After:

```python
def build_router(settings: "Settings") -> "APIRouter":
    from webbpulse.identity import build_dynamo_router

    from app.domains.identity.identity_hooks import ProductIdentityHooks

    identity_settings = build_identity_settings(settings)
    return build_dynamo_router(
        identity_settings,
        ProductIdentityHooks(prefix=settings.dynamodb_table_prefix),
        prefix=settings.dynamodb_table_prefix,
        endpoint_url=settings.DYNAMODB_ENDPOINT_URL or None,
        service="product-identity",
        version=IDENTITY_ROUTER_VERSION,
        email_sender=build_email_sender(identity_settings),
        oauth_client_secrets=build_oauth_client_secrets(settings),
    )
```

`identity_hooks.py` becomes the `claims_for` override. Before, ~135 lines implementing nine
hooks over a local `UserRepository`. After:

```python
from webbpulse.identity import DynamoUsersHooks, User


class ProductIdentityHooks(DynamoUsersHooks[User]):
    """This product's hooks: the shared users hooks plus its own claims."""

    def claims_for(self, user: Mapping[str, Any]) -> Mapping[str, Any]:
        """The roles list and the display name."""
        roles: list[str] = [ADMIN_ROLE] if user.get("is_admin") else []
        return {"roles": roles, "display_name": user.get("display_name", "")}
```

A product that also stamps a `scope` claim adds it to the same mapping; one whose account
row carries further sign-in flags overrides `may_authenticate`, calls `super()` first and
adds its own refusals; one with a legacy passkey or OAuth table overrides
`has_other_sign_in_method`.

The local `app/common/db/.../users.py` (`User`, `UserRepository`, `EMAIL_INDEX`, `_as_item`,
`_as_user`) is deleted in favour of the package's, and the local create-tables loop over
`webbpulse.identity.storage.TABLES` is replaced by one `create_identity_tables(client, prefix)`
call. A product whose account row is genuinely its own -- extra fields, a second unique index,
a non-UUID id -- keeps its repository and adopts only `dynamo_stores`, `build_dynamo_router`
and `create_identity_tables`.
