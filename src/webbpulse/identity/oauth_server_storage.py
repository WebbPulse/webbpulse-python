"""Storage for the OAuth 2.1 authorization server: clients, codes and consent.

Three tables alongside the identity ones, following the same rules: only hashes of
anything bearer-like are stored, single use is one conditional operation, and every TTL is
storage reclamation with the deadline re-checked in code.
"""

from __future__ import annotations

import dataclasses
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from webbpulse.dynamodb import now_iso
from webbpulse.identity.storage import IDENTITY_TTL_ATTRIBUTE, TableAttribute, TableIndex, TableSpec, is_expired

if TYPE_CHECKING:  # pragma: no cover
    from webbpulse.dynamodb import Repository

__all__ = [
    "AUTHORIZATION_CODES_TABLE",
    "CONSENT_USER_INDEX",
    "OAUTH_CLIENTS_TABLE",
    "OAUTH_CONSENTS_TABLE",
    "OAUTH_SERVER_TABLES",
    "AuthorizationCodeRecord",
    "AuthorizationCodeStore",
    "ConsentRecord",
    "ConsentStore",
    "DynamoAuthorizationCodeStore",
    "DynamoConsentStore",
    "DynamoOAuthClientStore",
    "InMemoryAuthorizationCodeStore",
    "InMemoryConsentStore",
    "InMemoryOAuthClientStore",
    "OAuthClientRecord",
    "OAuthClientStore",
    "OAuthServerStores",
]

OAUTH_CLIENTS_TABLE: Final = "oauth-clients"
AUTHORIZATION_CODES_TABLE: Final = "authorization-codes"
OAUTH_CONSENTS_TABLE: Final = "oauth-consents"

CONSENT_USER_INDEX: Final = "user_id-index"

TOKEN_ENDPOINT_AUTH_NONE: Final = "none"
"""The only `token_endpoint_auth_method` this server registers.

Every MCP client is a public client: a desktop editor or a CLI cannot hold a secret, and
issuing one would be a credential that only ever leaks. PKCE is the proof instead.
"""


@dataclass(frozen=True, slots=True)
class OAuthClientRecord:
    """One registered client, dynamic or pre-registered from settings.

    `redirect_uris` is the whole allow-list for this client and is matched by exact string
    equality, never by prefix. `expires_at` is zero for a first-party client, which is
    never reclaimed; a dynamically registered one carries a TTL refreshed on each use, so
    only registrations nothing ever came back for go.
    """

    client_id: str
    redirect_uris: tuple[str, ...]
    client_name: str = ""
    created_at: str = ""
    last_used_at: str = ""
    expires_at: int = 0
    first_party: bool = False
    scopes: tuple[str, ...] = ()

    def allows(self, redirect_uri: str) -> bool:
        """Whether this exact redirect URI was registered.

        Exact equality: a prefix match would admit `https://app.example.test.attacker.test`,
        which is a domain an attacker can register today, and the redirect is where a live
        authorization code is delivered.
        """
        return redirect_uri in self.redirect_uris


@dataclass(frozen=True, slots=True)
class AuthorizationCodeRecord:
    """One issued authorization code, stored by hash and spent exactly once.

    Holds everything the token exchange must compare against rather than trust from the
    request: the PKCE challenge, the redirect URI, the resource, the granted scopes and the
    tenant the user consented to. A value the client re-sends is checked, never believed.
    """

    code_hash: str
    client_id: str
    user_id: str
    redirect_uri: str
    code_challenge: str
    resource: str
    tenant_id: str
    created_at: str
    expires_at: int
    scopes: tuple[str, ...] = ()
    code_challenge_method: str = "S256"


@dataclass(frozen=True, slots=True)
class ConsentRecord:
    """One user's standing grant to one client, for one tenant and one resource.

    Recorded so a returning client is not made to ask again for a narrower or equal scope,
    and so a user can see and revoke what they have granted. Never a substitute for the
    authorization code exchange: consent authorises, the code delivers.
    """

    consent_id: str
    user_id: str
    client_id: str
    tenant_id: str
    resource: str
    scopes: tuple[str, ...]
    granted_at: str
    updated_at: str = ""

    def covers(self, scopes: tuple[str, ...]) -> bool:
        """Whether this grant already covers every scope being asked for now."""
        return set(scopes).issubset(self.scopes)


class OAuthClientStore(ABC):
    """The `oauth-clients` table: hash `client_id`, TTL `expires_at`, no secrets ever.

    A client record is public information: a client id, the names it registered and the
    redirect URIs it may use. There is no client secret to store, because every client this
    server registers is a public one proving itself with PKCE.
    """

    @abstractmethod
    def get(self, client_id: str) -> OAuthClientRecord | None:
        """The client, or `None` when it was never registered or has been reclaimed.

        Must be a strongly consistent read: it gates an authorization, and a client that
        registered a moment ago must be able to use the registration it was handed.
        """

    @abstractmethod
    def put(self, record: OAuthClientRecord) -> None:
        """Write or replace a client registration."""

    @abstractmethod
    def touch(self, client_id: str, *, expires_at: int) -> None:
        """Push a client's TTL out, recording that it was used.

        Called on every successful token exchange, so an actively used registration is
        never reclaimed while a client that registered and vanished expires on schedule.
        """


class AuthorizationCodeStore(ABC):
    """The `authorization-codes` table: hash `code_hash`, TTL `expires_at`, single use.

    Only the SHA-256 of the code is stored, so a read of the table cannot be turned into a
    token. `consume` must be one conditional operation, because two concurrent exchanges
    both reading an unspent code is exactly the race single use exists to lose.
    """

    @abstractmethod
    def put(self, record: AuthorizationCodeRecord) -> None:
        """Write a freshly issued code, immediately before the redirect carries it away."""

    @abstractmethod
    def consume(self, code_hash: str) -> AuthorizationCodeRecord | None:
        """Atomically spend a code and return it, or `None` if unknown or already spent.

        Deletes rather than marks: a spent code has no state worth auditing beyond the
        refresh family it produced, and deletion is what makes a second exchange fail.
        Expiry is checked here as well, since the TTL deletes on DynamoDB's own schedule.
        """


class ConsentStore(ABC):
    """The `oauth-consents` table: hash `consent_id`, GSI `user_id-index`, no TTL ever.

    Never a TTL: a consent that silently expires would send a user back through an
    authorization screen they have no way to predict, and the record is small.
    """

    @abstractmethod
    def get(self, consent_id: str) -> ConsentRecord | None:
        """The consent, or `None`."""

    @abstractmethod
    def put(self, record: ConsentRecord) -> None:
        """Write or replace a consent grant."""

    @abstractmethod
    def list_for_user(self, user_id: str) -> list[ConsentRecord]:
        """Every consent this user has granted. Backed by the GSI, so it may be stale."""

    @abstractmethod
    def delete(self, consent_id: str) -> None:
        """Revoke a consent. Idempotent: removing an absent one is not an error."""


@dataclass(frozen=True, slots=True)
class OAuthServerStores:
    """The three stores `build_oauth_server_router` takes, in one object.

    Mirrors `IdentityStores`: one argument rather than one per table, so adding a fourth
    store later is not a signature change at every call site.
    """

    clients: OAuthClientStore
    codes: AuthorizationCodeStore
    consents: ConsentStore


class InMemoryOAuthClientStore(OAuthClientStore):
    """Dict-backed `OAuthClientStore`, honouring the TTL the real table reclaims on."""

    def __init__(self, records: Mapping[str, OAuthClientRecord] | None = None) -> None:
        """Start from an optional set of pre-registered clients."""
        self._items: dict[str, OAuthClientRecord] = dict(records or {})

    def get(self, client_id: str) -> OAuthClientRecord | None:
        """The client, or `None` when unknown or past its TTL."""
        record = self._items.get(client_id)
        if record is None:
            return None
        if record.expires_at and is_expired(record.expires_at):
            return None
        return record

    def put(self, record: OAuthClientRecord) -> None:
        """Write or replace a client registration."""
        self._items[record.client_id] = record

    def touch(self, client_id: str, *, expires_at: int) -> None:
        """Push a client's TTL out, recording that it was used."""
        record = self._items.get(client_id)
        if record is None or record.first_party:
            return
        self._items[client_id] = dataclasses.replace(record, last_used_at=now_iso(), expires_at=expires_at)


class InMemoryAuthorizationCodeStore(AuthorizationCodeStore):
    """Dict-backed `AuthorizationCodeStore`, deleting on consumption as the real one does."""

    def __init__(self) -> None:
        """Start with an empty backing dict."""
        self._items: dict[str, AuthorizationCodeRecord] = {}

    def put(self, record: AuthorizationCodeRecord) -> None:
        """Write a freshly issued code."""
        self._items[record.code_hash] = record

    def consume(self, code_hash: str) -> AuthorizationCodeRecord | None:
        """Atomically spend a code, returning it, or `None` if unknown or already spent."""
        existing = self._items.pop(code_hash, None)
        if existing is None or is_expired(existing.expires_at):
            return None
        return existing


class InMemoryConsentStore(ConsentStore):
    """Dict-backed `ConsentStore`."""

    def __init__(self) -> None:
        """Start with an empty backing dict."""
        self._items: dict[str, ConsentRecord] = {}

    def get(self, consent_id: str) -> ConsentRecord | None:
        """The consent, or `None`."""
        return self._items.get(consent_id)

    def put(self, record: ConsentRecord) -> None:
        """Write or replace a consent grant."""
        self._items[record.consent_id] = record

    def list_for_user(self, user_id: str) -> list[ConsentRecord]:
        """Every consent this user has granted."""
        return [record for record in self._items.values() if record.user_id == user_id]

    def delete(self, consent_id: str) -> None:
        """Revoke a consent. Idempotent."""
        self._items.pop(consent_id, None)


class DynamoOAuthClientStore(OAuthClientStore):
    """`OAuthClientStore` over a `webbpulse.dynamodb.Repository`.

    Reads consistently, because a registration is handed to a client that uses it on its
    very next request and an eventually consistent miss would look like a refusal.
    """

    def __init__(self, repository: Repository) -> None:
        """Bind this store to the repository holding its table."""
        self._repo = repository

    def get(self, client_id: str) -> OAuthClientRecord | None:
        """The client, or `None` when unknown or past its TTL."""
        item = self._repo.get({"client_id": client_id}, consistent=True)
        if item is None:
            return None
        record = _client_from_item(item)
        if record.expires_at and is_expired(record.expires_at):
            return None
        return record

    def put(self, record: OAuthClientRecord) -> None:
        """Write or replace a client registration."""
        item: dict[str, Any] = {
            "client_id": record.client_id,
            "redirect_uris": list(record.redirect_uris),
            "client_name": record.client_name,
            "created_at": record.created_at or now_iso(),
            "last_used_at": record.last_used_at,
            "first_party": record.first_party,
            "scopes": list(record.scopes),
        }
        if record.expires_at:
            item[IDENTITY_TTL_ATTRIBUTE] = record.expires_at
        self._repo.put(item)

    def touch(self, client_id: str, *, expires_at: int) -> None:
        """Push a client's TTL out, recording that it was used.

        Conditional on the record existing and not being first party, so a concurrent
        reclaim does not resurrect a row and a settings-backed client never grows a TTL.
        """
        from botocore.exceptions import ClientError

        try:
            self._repo.table.update_item(
                Key={"client_id": client_id},
                UpdateExpression=(f"SET last_used_at = :now, {IDENTITY_TTL_ATTRIBUTE} = :expires"),
                ConditionExpression="attribute_exists(client_id) AND first_party = :false",
                ExpressionAttributeValues={":now": now_iso(), ":expires": expires_at, ":false": False},
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                raise


class DynamoAuthorizationCodeStore(AuthorizationCodeStore):
    """`AuthorizationCodeStore` over a `webbpulse.dynamodb.Repository`.

    `consume` is one `DeleteItem` with `ReturnValues=ALL_OLD`, so two concurrent exchanges
    cannot both be handed the same code: exactly one delete returns attributes.
    """

    def __init__(self, repository: Repository) -> None:
        """Bind this store to the repository holding its table."""
        self._repo = repository

    def put(self, record: AuthorizationCodeRecord) -> None:
        """Write a freshly issued code."""
        self._repo.put(
            {
                "code_hash": record.code_hash,
                "client_id": record.client_id,
                "user_id": record.user_id,
                "redirect_uri": record.redirect_uri,
                "code_challenge": record.code_challenge,
                "code_challenge_method": record.code_challenge_method,
                "resource": record.resource,
                "tenant_id": record.tenant_id,
                "scopes": list(record.scopes),
                "created_at": record.created_at,
                IDENTITY_TTL_ATTRIBUTE: record.expires_at,
            }
        )

    def consume(self, code_hash: str) -> AuthorizationCodeRecord | None:
        """Atomically spend a code, returning it, or `None` if unknown or already spent."""
        response = self._repo.table.delete_item(Key={"code_hash": code_hash}, ReturnValues="ALL_OLD")
        attributes = response.get("Attributes")
        if not attributes:
            return None
        record = _code_from_item(attributes)
        return None if is_expired(record.expires_at) else record


class DynamoConsentStore(ConsentStore):
    """`ConsentStore` over a `webbpulse.dynamodb.Repository`, with a `user_id-index` GSI."""

    def __init__(self, repository: Repository, *, user_index: str = CONSENT_USER_INDEX) -> None:
        """Bind this store to its repository and the name of its user index."""
        self._repo = repository
        self._user_index = user_index

    def get(self, consent_id: str) -> ConsentRecord | None:
        """The consent, or `None`."""
        item = self._repo.get({"consent_id": consent_id})
        return None if item is None else _consent_from_item(item)

    def put(self, record: ConsentRecord) -> None:
        """Write or replace a consent grant."""
        self._repo.put(
            {
                "consent_id": record.consent_id,
                "user_id": record.user_id,
                "client_id": record.client_id,
                "tenant_id": record.tenant_id,
                "resource": record.resource,
                "scopes": list(record.scopes),
                "granted_at": record.granted_at or now_iso(),
                "updated_at": record.updated_at or now_iso(),
            }
        )

    def list_for_user(self, user_id: str) -> list[ConsentRecord]:
        """Every consent this user has granted, through the GSI."""
        from boto3.dynamodb.conditions import Key

        items = self._repo.iter_query(Key("user_id").eq(user_id), index_name=self._user_index)
        return [_consent_from_item(item) for item in items]

    def delete(self, consent_id: str) -> None:
        """Revoke a consent. Idempotent."""
        self._repo.delete({"consent_id": consent_id})


def _client_from_item(item: Mapping[str, Any]) -> OAuthClientRecord:
    """Build an `OAuthClientRecord` from a DynamoDB item."""
    return OAuthClientRecord(
        client_id=str(item["client_id"]),
        redirect_uris=tuple(str(value) for value in item.get("redirect_uris", [])),
        client_name=str(item.get("client_name", "")),
        created_at=str(item.get("created_at", "")),
        last_used_at=str(item.get("last_used_at", "")),
        expires_at=int(item.get(IDENTITY_TTL_ATTRIBUTE, 0)),
        first_party=bool(item.get("first_party", False)),
        scopes=tuple(str(value) for value in item.get("scopes", [])),
    )


def _code_from_item(item: Mapping[str, Any]) -> AuthorizationCodeRecord:
    """Build an `AuthorizationCodeRecord` from a DynamoDB item."""
    return AuthorizationCodeRecord(
        code_hash=str(item["code_hash"]),
        client_id=str(item.get("client_id", "")),
        user_id=str(item.get("user_id", "")),
        redirect_uri=str(item.get("redirect_uri", "")),
        code_challenge=str(item.get("code_challenge", "")),
        code_challenge_method=str(item.get("code_challenge_method", "S256")),
        resource=str(item.get("resource", "")),
        tenant_id=str(item.get("tenant_id", "")),
        scopes=tuple(str(value) for value in item.get("scopes", [])),
        created_at=str(item.get("created_at", "")),
        expires_at=int(item.get(IDENTITY_TTL_ATTRIBUTE, 0)),
    )


def _consent_from_item(item: Mapping[str, Any]) -> ConsentRecord:
    """Build a `ConsentRecord` from a DynamoDB item."""
    return ConsentRecord(
        consent_id=str(item["consent_id"]),
        user_id=str(item.get("user_id", "")),
        client_id=str(item.get("client_id", "")),
        tenant_id=str(item.get("tenant_id", "")),
        resource=str(item.get("resource", "")),
        scopes=tuple(str(value) for value in item.get("scopes", [])),
        granted_at=str(item.get("granted_at", "")),
        updated_at=str(item.get("updated_at", "")),
    )


OAUTH_SERVER_TABLES: Final[tuple[TableSpec, ...]] = (
    TableSpec(
        logical_name=OAUTH_CLIENTS_TABLE,
        attributes=(TableAttribute("client_id", "S"),),
        hash_key="client_id",
        ttl_attribute=IDENTITY_TTL_ATTRIBUTE,
    ),
    TableSpec(
        logical_name=AUTHORIZATION_CODES_TABLE,
        attributes=(TableAttribute("code_hash", "S"),),
        hash_key="code_hash",
        ttl_attribute=IDENTITY_TTL_ATTRIBUTE,
    ),
    TableSpec(
        logical_name=OAUTH_CONSENTS_TABLE,
        attributes=(TableAttribute("consent_id", "S"), TableAttribute("user_id", "S")),
        hash_key="consent_id",
        global_secondary_indexes=(TableIndex(name=CONSENT_USER_INDEX, hash_key="user_id"),),
    ),
)
"""The three tables the authorization server adds, in `TableSpec` form.

Kept separate from `TABLES` rather than appended to it, so a product that mounts identity
without the MCP flag provisions nothing it does not use.
"""
