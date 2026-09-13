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
| `passkeys` (`PASSKEYS_TABLE`) | `id` | `credential_id-index` (`PASSKEY_CREDENTIAL_INDEX`) | none |
| `totp-factors` (`TOTP_FACTORS_TABLE`) | `user_id` | none | none |
| `recovery-codes` (`RECOVERY_CODES_TABLE`) | `user_id` / `code_hash` | none | **never** |
| `oauth-links` (`OAUTH_LINKS_TABLE`) | `id` | `user_id-index` (`OAUTH_LINK_USER_INDEX`) | none |
| `refresh-tokens` (`REFRESH_TOKENS_TABLE`) | `token_hash` | `family_id-generation-index` (`REFRESH_FAMILY_INDEX`) | `expires_at` |
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
  freely and writes only the attributes above, through the `user_repository` hook.
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
  `created_at`, `expires_at`. Keying on the hash makes validation one `GetItem`; the GSI
  supports family revocation.
- **`identity-tokens`** (verification and reset): `purpose`, `user_id`, `created_at`,
  `consumed_at`, `expires_at`.
- **`webauthn-challenges`**: `user_id` (absent for a discoverable-credential login),
  `challenge`, `ceremony`, `expires_at` (`CHALLENGE_TTL_SECONDS` = 300).
- **`oauth-states`**: `pkce_verifier`, `provider`, `mode`, `return_to`, `expires_at`
  (`OAUTH_STATE_TTL_SECONDS` = 600).
- **`login-attempts`**: `identity_key` is `email#<lower>` or `ip#<addr>`; `outcome`, `user_id`,
  `ip`, `user_agent`, `expires_at` (`ATTEMPT_TTL` = 30 days). Feeds lockout (5.1) and audit.

The limiter's own `rate-limits` table is reused unchanged.

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
