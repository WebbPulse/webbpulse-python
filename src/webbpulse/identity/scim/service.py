"""The SCIM service: tenant-scoped User and Group operations over a product's `ScimHooks`.

The service owns the protocol: parsing and normalising bodies, PATCH, ETags, `userName`
uniqueness, turning `active` changes into deactivate and reactivate calls, and per-tenant
bearer tokens. The product owns persistence and side effects through `ScimHooks`, mapping a
directory user onto its own user and a directory group onto its own team or role.

Tokens are `webbpulse.identity.api_keys` keys carrying the `scim` scope, so they are shown
once, stored only as a SHA-256 hash, bound to one tenant and revocable by id.
"""

from __future__ import annotations

import dataclasses
import json
import logging
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from webbpulse.dynamodb import now_iso
from webbpulse.identity import api_keys
from webbpulse.identity.scim.errors import ScimError
from webbpulse.identity.scim.filters import ScimFilter, parse_filter
from webbpulse.identity.scim.patch import apply_patch, member_changes, parse_patch_request
from webbpulse.identity.scim.resources import ScimGroup, ScimMember, ScimUser, unique_members
from webbpulse.identity.scim.schema import GROUP_RESOURCE_TYPE, USER_RESOURCE_TYPE, ScimResourceType

__all__ = [
    "DEFAULT_PAGE_SIZE",
    "MAX_PAGE_SIZE",
    "SCIM_SCOPE",
    "SCIM_TOKEN_KIND",
    "ScimHooks",
    "ScimPage",
    "ScimPrincipal",
    "ScimQuery",
    "ScimService",
    "etag_matches",
    "mint_scim_token",
]

_log = logging.getLogger(__name__)

SCIM_SCOPE: Final = "scim"
"""The scope a SCIM bearer token carries, and the only one the router accepts."""

SCIM_TOKEN_KIND: Final = "scim"
"""The `api_keys` kind of a SCIM token, so a product can list them apart from personal keys."""

DEFAULT_PAGE_SIZE: Final = 100
MAX_PAGE_SIZE: Final = 1000


@dataclass(frozen=True, slots=True)
class ScimPage[T]:
    """One page of a list: its resources and the total number matching the filter."""

    resources: tuple[T, ...]
    total_results: int


@dataclass(frozen=True, slots=True)
class ScimQuery:
    """A list request: the parsed filter, the 1-based `start_index` and the page `count`.

    `include_members` is false when the client excluded `members` and the filter does not
    name them, so a product can skip loading memberships.
    """

    filter: ScimFilter | None = None
    start_index: int = 1
    count: int = DEFAULT_PAGE_SIZE
    include_members: bool = True

    def equality(self, attribute: str) -> str | None:
        """The value when the whole filter is `<attribute> eq "<value>"`, for a point lookup."""
        return self.filter.equality(attribute) if self.filter is not None else None

    def apply_users(self, users: Iterable[ScimUser]) -> ScimPage[ScimUser]:
        """Filter and paginate users in memory, for a product with few enough to load."""
        return self._apply(users, lambda user: user.to_resource(""), USER_RESOURCE_TYPE)

    def apply_groups(self, groups: Iterable[ScimGroup]) -> ScimPage[ScimGroup]:
        """Filter and paginate groups in memory, `members` filters included when loaded."""
        return self._apply(groups, lambda group: group.to_resource(""), GROUP_RESOURCE_TYPE)

    def _apply[T](
        self,
        items: Iterable[T],
        render: Callable[[T], dict[str, Any]],
        resource_type: ScimResourceType,
    ) -> ScimPage[T]:
        """Filter by the rendered form, then slice the page."""
        matched = [
            item for item in items if self.filter is None or self.filter.matches(render(item), resource_type)
        ]
        start = max(self.start_index, 1) - 1
        return ScimPage(resources=tuple(matched[start : start + max(self.count, 0)]), total_results=len(matched))


@dataclass(frozen=True, slots=True)
class ScimPrincipal:
    """The tenant a verified SCIM token provisions, and the token's id for logs."""

    tenant_id: str
    key_id: str


class ScimHooks(ABC):
    """What a product implements to store directory users and groups.

    Every method is scoped to the tenant the token belongs to, and must never read or write
    another tenant's rows. A hook may raise `ScimError`, for example `ScimError.uniqueness()`
    on a duplicate or `ScimError.invalid_value()` for a member id it does not know; anything
    else becomes a 500 SCIM error.
    """

    @abstractmethod
    def get_user(self, tenant_id: str, user_id: str) -> ScimUser | None:
        """The user with this id in the tenant, or `None`."""

    @abstractmethod
    def list_users(self, tenant_id: str, query: ScimQuery) -> ScimPage[ScimUser]:
        """A page of users matching the query.

        At least `userName`, `externalId` and `id` equality must be answered, through
        `query.equality`, because identity providers look users up that way before creating
        them. `query.apply_users` does the rest in memory.
        """

    @abstractmethod
    def create_user(self, tenant_id: str, user: ScimUser) -> ScimUser:
        """Store a new user and return it with the product's `id` assigned."""

    @abstractmethod
    def update_user(self, tenant_id: str, user: ScimUser) -> ScimUser:
        """Store a replaced or patched user, `active` included, and return it."""

    @abstractmethod
    def deactivate_user(self, tenant_id: str, user: ScimUser) -> None:
        """Side effects of `active` turning false: end sessions, revoke keys, block sign-in."""

    def reactivate_user(self, tenant_id: str, user: ScimUser) -> None:
        """Side effects of `active` turning true again. Nothing by default."""
        return None

    @abstractmethod
    def delete_user(self, tenant_id: str, user_id: str) -> bool:
        """Remove the user and its memberships, answering whether it existed."""

    @abstractmethod
    def get_group(self, tenant_id: str, group_id: str, *, include_members: bool = True) -> ScimGroup | None:
        """The group with this id, with its members unless `include_members` is false, or `None`."""

    @abstractmethod
    def list_groups(self, tenant_id: str, query: ScimQuery) -> ScimPage[ScimGroup]:
        """A page of groups matching the query, at least `displayName`, `externalId` and `id` equality.

        Members are loaded only when `query.include_members` is true.
        """

    @abstractmethod
    def create_group(self, tenant_id: str, group: ScimGroup) -> ScimGroup:
        """Store a new group, without members, and return it with its `id` assigned.

        Members in the request follow through `add_group_members`.
        """

    @abstractmethod
    def update_group(self, tenant_id: str, group: ScimGroup) -> ScimGroup:
        """Store a group's renamed or changed attributes. Members change only through the member hooks."""

    @abstractmethod
    def delete_group(self, tenant_id: str, group_id: str) -> bool:
        """Remove the group and its memberships, answering whether it existed."""

    @abstractmethod
    def add_group_members(self, tenant_id: str, group_id: str, members: Sequence[ScimMember]) -> None:
        """Add members to a group, ignoring any already in it."""

    @abstractmethod
    def remove_group_members(self, tenant_id: str, group_id: str, member_ids: Sequence[str]) -> None:
        """Remove members from a group by id, ignoring any not in it."""

    def scim_enabled(self, tenant_id: str) -> bool:
        """Whether the tenant may be provisioned now, for a plan or a switch. True by default."""
        return True


def mint_scim_token(
    store: api_keys.ApiKeyStore,
    *,
    tenant_id: str,
    user_id: str,
    name: str = "SCIM",
    created_by: str | None = None,
    expires_at: datetime | int | None = None,
) -> api_keys.MintedApiKey:
    """Mint a tenant's SCIM bearer token. The plaintext is in the result once and never again.

    `user_id` is the subject the token acts as, normally the administrator who connected the
    directory or a service id the product reserves for it.
    """
    return api_keys.mint(
        user_id=user_id,
        tenant_id=tenant_id,
        scopes=(SCIM_SCOPE,),
        name=name,
        expires_at=expires_at,
        store=store,
        kind=SCIM_TOKEN_KIND,
        created_by=created_by,
    )


def _bare_version(text: str) -> str:
    """An entity tag without its weak prefix and quotes."""
    value = text.strip()
    if value[:2].upper() == "W/":
        value = value[2:]
    return value.strip().strip('"')


def etag_matches(header: str, version: str) -> bool:
    """Whether an `If-Match` or `If-None-Match` header names this version, `*` naming any."""
    target = _bare_version(version)
    for candidate in header.split(","):
        stripped = candidate.strip()
        if stripped == "*" or (stripped and _bare_version(stripped) == target):
            return True
    return False


def _version_of(resource: Mapping[str, Any]) -> str:
    """The `meta.version` of a rendered resource."""
    meta = resource.get("meta")
    return str(meta.get("version", "")) if isinstance(meta, Mapping) else ""


class ScimService:
    """SCIM operations for one product, with `base_url` the absolute URL of the SCIM root."""

    def __init__(
        self,
        hooks: ScimHooks,
        keys: api_keys.ApiKeyStore,
        *,
        base_url: str,
        max_results: int = MAX_PAGE_SIZE,
        documentation_uri: str = "",
    ) -> None:
        """Bind the product's hooks, the API key store tokens live in, and the public SCIM root."""
        self.hooks = hooks
        self.keys = keys
        self.base_url = base_url.rstrip("/")
        self.max_results = max_results
        self.documentation_uri = documentation_uri

    def authenticate(self, authorization: str) -> ScimPrincipal:
        """The principal for an `Authorization` header: 401 without a valid token, 403 without the scope."""
        scheme, _, token = authorization.strip().partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise ScimError.unauthorized()
        record = api_keys.verify(token.strip(), self.keys)
        if record is None:
            _log.warning("SCIM token refused.", extra={"event": "scim.token_refused"})
            raise ScimError.unauthorized()
        if SCIM_SCOPE not in record.scopes:
            _log.warning(
                "SCIM token lacks the scim scope.",
                extra={"event": "scim.scope_missing", "tenant_id": record.tenant_id, "key_id": record.key_id},
            )
            raise ScimError.forbidden("This token does not carry the 'scim' scope.")
        if not self.hooks.scim_enabled(record.tenant_id):
            raise ScimError.forbidden("Provisioning is not enabled for this directory.")
        return ScimPrincipal(tenant_id=record.tenant_id, key_id=record.key_id)

    def render_user(self, user: ScimUser) -> dict[str, Any]:
        """The user's SCIM JSON."""
        return user.to_resource(self.base_url)

    def render_group(self, group: ScimGroup, *, include_members: bool = True) -> dict[str, Any]:
        """The group's SCIM JSON, members left out when they were not loaded."""
        return group.to_resource(self.base_url, include_members=include_members)

    def _check_version(self, resource: Mapping[str, Any], if_match: str) -> None:
        """Refuse with 412 when an `If-Match` no longer names the stored version."""
        if if_match and not etag_matches(if_match, _version_of(resource)):
            raise ScimError.precondition_failed()

    def _record(self, event: str, tenant_id: str, resource_id: str) -> None:
        """One structured line per write, naming ids only."""
        _log.info(
            "SCIM %s.",
            event.removeprefix("scim.").replace("_", " "),
            extra={"event": event, "tenant_id": tenant_id, "resource_id": resource_id},
        )

    def get_user(self, tenant_id: str, user_id: str) -> ScimUser:
        """The user, or 404."""
        user = self.hooks.get_user(tenant_id, user_id)
        if user is None:
            raise ScimError.not_found(f"User {user_id} not found.")
        return user

    def list_users(self, tenant_id: str, query: ScimQuery) -> ScimPage[ScimUser]:
        """A page of users."""
        return self.hooks.list_users(tenant_id, query)

    def _ensure_unique(self, tenant_id: str, user_name: str, *, own_id: str = "") -> None:
        """Refuse with 409 when another user in the tenant already has this `userName`."""
        query = ScimQuery(filter=parse_filter(f"userName eq {json.dumps(user_name, ensure_ascii=False)}"), count=2)
        for existing in self.hooks.list_users(tenant_id, query).resources:
            if existing.id != own_id and existing.user_name.lower() == user_name.lower():
                raise ScimError.uniqueness(f"A user with that userName already exists in this directory: {existing.id}")

    def create_user(self, tenant_id: str, body: Mapping[str, Any]) -> ScimUser:
        """Create a user from a POST body. One created inactive is deactivated straight away."""
        parsed = ScimUser.from_resource(body)
        self._ensure_unique(tenant_id, parsed.user_name)
        stamp = now_iso()
        created = self.hooks.create_user(
            tenant_id, dataclasses.replace(parsed, created=stamp, last_modified=stamp)
        )
        self._record("scim.user_created", tenant_id, created.id)
        if not created.active:
            self.hooks.deactivate_user(tenant_id, created)
            self._record("scim.user_deactivated", tenant_id, created.id)
        return created

    def _store_user(self, tenant_id: str, before: ScimUser, after: ScimUser, event: str) -> ScimUser:
        """Write a changed user and run the deactivate or reactivate side effects."""
        if after.user_name.lower() != before.user_name.lower():
            self._ensure_unique(tenant_id, after.user_name, own_id=before.id)
        merged = dataclasses.replace(
            after,
            id=before.id,
            groups=before.groups,
            created=before.created,
            last_modified=now_iso(),
            version="",
        )
        stored = self.hooks.update_user(tenant_id, merged)
        self._record(event, tenant_id, before.id)
        if before.active and not stored.active:
            self.hooks.deactivate_user(tenant_id, stored)
            self._record("scim.user_deactivated", tenant_id, before.id)
        elif not before.active and stored.active:
            self.hooks.reactivate_user(tenant_id, stored)
            self._record("scim.user_reactivated", tenant_id, before.id)
        return stored

    def replace_user(self, tenant_id: str, user_id: str, body: Mapping[str, Any], *, if_match: str = "") -> ScimUser:
        """Replace a user from a PUT body."""
        before = self.get_user(tenant_id, user_id)
        self._check_version(self.render_user(before), if_match)
        return self._store_user(tenant_id, before, ScimUser.from_resource(body), "scim.user_replaced")

    def patch_user(self, tenant_id: str, user_id: str, body: Any, *, if_match: str = "") -> ScimUser:
        """Apply a PATCH body to a user."""
        operations = parse_patch_request(body)
        before = self.get_user(tenant_id, user_id)
        rendered = self.render_user(before)
        self._check_version(rendered, if_match)
        patched = apply_patch(rendered, operations, USER_RESOURCE_TYPE)
        return self._store_user(tenant_id, before, ScimUser.from_resource(patched), "scim.user_patched")

    def delete_user(self, tenant_id: str, user_id: str, *, if_match: str = "") -> None:
        """Delete a user, or 404."""
        if if_match:
            self._check_version(self.render_user(self.get_user(tenant_id, user_id)), if_match)
        if not self.hooks.delete_user(tenant_id, user_id):
            raise ScimError.not_found(f"User {user_id} not found.")
        self._record("scim.user_deleted", tenant_id, user_id)

    def get_group(self, tenant_id: str, group_id: str, *, include_members: bool = True) -> ScimGroup:
        """The group, or 404."""
        group = self.hooks.get_group(tenant_id, group_id, include_members=include_members)
        if group is None:
            raise ScimError.not_found(f"Group {group_id} not found.")
        return group

    def list_groups(self, tenant_id: str, query: ScimQuery) -> ScimPage[ScimGroup]:
        """A page of groups."""
        return self.hooks.list_groups(tenant_id, query)

    def create_group(self, tenant_id: str, body: Mapping[str, Any]) -> ScimGroup:
        """Create a group from a POST body, then add its members."""
        parsed = ScimGroup.from_resource(body)
        stamp = now_iso()
        created = self.hooks.create_group(
            tenant_id, dataclasses.replace(parsed, members=(), created=stamp, last_modified=stamp)
        )
        self._record("scim.group_created", tenant_id, created.id)
        if parsed.members:
            self.hooks.add_group_members(tenant_id, created.id, parsed.members)
            self._record("scim.group_members_added", tenant_id, created.id)
            created = dataclasses.replace(created, members=parsed.members)
        return created

    def _store_group(self, tenant_id: str, before: ScimGroup, after: ScimGroup, event: str) -> ScimGroup:
        """Write a changed group's attributes and the difference in its members."""
        stored = before
        if (after.display_name, after.external_id, dict(after.attributes)) != (
            before.display_name,
            before.external_id,
            dict(before.attributes),
        ):
            stored = self.hooks.update_group(
                tenant_id,
                dataclasses.replace(
                    after,
                    id=before.id,
                    members=(),
                    created=before.created,
                    last_modified=now_iso(),
                    version="",
                ),
            )
            self._record(event, tenant_id, before.id)
        current = {member.value for member in before.members}
        wanted = {member.value for member in after.members}
        added = tuple(member for member in after.members if member.value not in current)
        removed = [member.value for member in before.members if member.value not in wanted]
        self._change_members(tenant_id, before.id, added, removed)
        return dataclasses.replace(stored, members=after.members)

    def _change_members(
        self,
        tenant_id: str,
        group_id: str,
        added: Sequence[ScimMember],
        removed: Sequence[str],
    ) -> None:
        """Call the member hooks for whatever changed."""
        if removed:
            self.hooks.remove_group_members(tenant_id, group_id, removed)
            self._record("scim.group_members_removed", tenant_id, group_id)
        if added:
            self.hooks.add_group_members(tenant_id, group_id, added)
            self._record("scim.group_members_added", tenant_id, group_id)

    def replace_group(self, tenant_id: str, group_id: str, body: Mapping[str, Any], *, if_match: str = "") -> ScimGroup:
        """Replace a group from a PUT body, members included."""
        before = self.get_group(tenant_id, group_id)
        self._check_version(self.render_group(before), if_match)
        return self._store_group(tenant_id, before, ScimGroup.from_resource(body), "scim.group_replaced")

    def patch_group(self, tenant_id: str, group_id: str, body: Any, *, if_match: str = "") -> None:
        """Apply a PATCH body to a group.

        A body that only adds or removes members, which is nearly every one Okta and Entra
        send, goes straight to the member hooks without loading the group's members.
        """
        operations = parse_patch_request(body)
        changes = None if if_match else member_changes(operations, GROUP_RESOURCE_TYPE)
        if changes is not None:
            self.get_group(tenant_id, group_id, include_members=False)
            raw_added, removed = changes
            added = unique_members(ScimMember.from_value(item) for item in raw_added)
            doomed = set(removed)
            self._change_members(
                tenant_id,
                group_id,
                tuple(member for member in added if member.value not in doomed),
                list(dict.fromkeys(removed)),
            )
            return
        before = self.get_group(tenant_id, group_id)
        rendered = self.render_group(before)
        self._check_version(rendered, if_match)
        patched = apply_patch(rendered, operations, GROUP_RESOURCE_TYPE)
        self._store_group(tenant_id, before, ScimGroup.from_resource(patched), "scim.group_patched")

    def delete_group(self, tenant_id: str, group_id: str, *, if_match: str = "") -> None:
        """Delete a group, or 404."""
        if if_match:
            self._check_version(self.render_group(self.get_group(tenant_id, group_id)), if_match)
        if not self.hooks.delete_group(tenant_id, group_id):
            raise ScimError.not_found(f"Group {group_id} not found.")
        self._record("scim.group_deleted", tenant_id, group_id)
