"""The User and Group resources a product stores, and their SCIM JSON form.

A product reads and writes the typed fields it cares about and keeps `attributes` as an
opaque blob, which holds every other schema attribute (phone numbers, addresses, the
enterprise extension under its URN) so a GET after a PUT or PATCH answers what the identity
provider sent. Parsing folds attribute names to their schema spelling, turns Entra's string
booleans into booleans, and drops read-only attributes and passwords.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from webbpulse.identity.scim.errors import ScimError
from webbpulse.identity.scim.schema import (
    ENTERPRISE_USER_SCHEMA,
    GROUP_RESOURCE_TYPE,
    GROUP_SCHEMA,
    USER_RESOURCE_TYPE,
    USER_SCHEMA,
    ScimAttribute,
    ScimResourceType,
)

__all__ = [
    "MEMBER_TYPE_GROUP",
    "MEMBER_TYPE_USER",
    "ScimEmail",
    "ScimGroup",
    "ScimMember",
    "ScimName",
    "ScimUser",
    "coerce_boolean",
    "normalise_resource",
    "normalise_value",
    "project_resource",
    "resource_version",
    "unique_members",
]

MEMBER_TYPE_USER: Final = "User"
MEMBER_TYPE_GROUP: Final = "Group"

_TRUE: Final = frozenset({"true", "1", "yes"})
_FALSE: Final = frozenset({"false", "0", "no", ""})


def coerce_boolean(value: Any, *, attribute: str = "value") -> bool:
    """A JSON boolean, or Entra's `"True"` and `"False"` strings, as a boolean."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in _TRUE:
            return True
        if lowered in _FALSE:
            return False
    raise ScimError.invalid_value(f"'{attribute}' must be a boolean.")


def normalise_value(definition: ScimAttribute, value: Any) -> Any:
    """One attribute's value with canonical sub-attribute names and booleans coerced."""
    if value is None:
        return None
    if definition.multi_valued:
        items = value if isinstance(value, list) else [value]
        return [_normalise_single(definition, item) for item in items if item is not None]
    return _normalise_single(definition, value)


def _normalise_single(definition: ScimAttribute, value: Any) -> Any:
    """One value of an attribute, complex or simple."""
    if definition.type == "boolean":
        return coerce_boolean(value, attribute=definition.name)
    if definition.type != "complex":
        if isinstance(value, Mapping | list):
            raise ScimError.invalid_value(f"'{definition.name}' must be a single value.")
        return value
    if not isinstance(value, Mapping):
        if definition.sub("value") is not None and isinstance(value, str | int | float):
            return {"value": value}
        raise ScimError.invalid_value(f"'{definition.name}' must be an object.")
    result: dict[str, Any] = {}
    for key, inner in value.items():
        sub = definition.sub(key)
        if sub is None:
            continue
        normalised = normalise_value(sub, inner)
        if normalised is not None:
            result[sub.name] = normalised
    return result


def normalise_resource(body: Mapping[str, Any], resource_type: ScimResourceType) -> dict[str, Any]:
    """A request body folded onto the schema: canonical names, booleans, read-only and unknown keys dropped.

    `id`, `meta`, `groups` and `password` never survive, so a client can neither set an id nor
    have a password stored. Unknown attributes are ignored, as RFC 7644 lets a server do.
    """
    result: dict[str, Any] = {}
    for key, value in body.items():
        lowered = key.lower()
        if lowered == "schemas":
            continue
        if lowered == "externalid":
            if value is not None:
                if not isinstance(value, str):
                    raise ScimError.invalid_value("'externalId' must be a string.")
                result["externalId"] = value
            continue
        if lowered in {"id", "meta"}:
            continue
        extension = resource_type.extension(key)
        if extension is not None:
            if not isinstance(value, Mapping):
                raise ScimError.invalid_value(f"'{extension.id}' must be an object.")
            inner: dict[str, Any] = {}
            for inner_key, inner_value in value.items():
                definition = extension.attribute(inner_key)
                if definition is None or definition.mutability == "readOnly":
                    continue
                normalised = normalise_value(definition, inner_value)
                if normalised is not None:
                    inner[definition.name] = normalised
            result[extension.id] = inner
            continue
        definition = resource_type.schema.attribute(key)
        if definition is None or definition.mutability in {"readOnly", "writeOnly"}:
            continue
        normalised = normalise_value(definition, value)
        if normalised is not None:
            result[definition.name] = normalised
    return result


def resource_version(resource: Mapping[str, Any]) -> str:
    """A weak version from a rendered resource's content, for a product that keeps none."""
    content = {key: value for key, value in resource.items() if key != "meta"}
    digest = hashlib.sha256(json.dumps(content, sort_keys=True, default=str).encode("utf-8")).hexdigest()
    return digest[:32]


def _meta(
    *,
    resource_type: str,
    location: str,
    created: str,
    last_modified: str,
    version: str,
) -> dict[str, Any]:
    """The `meta` object, leaving out timestamps the product does not keep."""
    meta: dict[str, Any] = {"resourceType": resource_type, "location": location}
    if created:
        meta["created"] = created
    if last_modified or created:
        meta["lastModified"] = last_modified or created
    if version:
        meta["version"] = f'W/"{version}"'
    return meta


def _text(value: Any) -> str:
    """A string attribute's value, or an empty string."""
    return value if isinstance(value, str) else ("" if value is None else str(value))


@dataclass(frozen=True, slots=True)
class ScimName:
    """The `name` complex attribute."""

    formatted: str = ""
    family_name: str = ""
    given_name: str = ""
    middle_name: str = ""
    honorific_prefix: str = ""
    honorific_suffix: str = ""

    def as_dict(self) -> dict[str, str]:
        """The non-empty parts, keyed as SCIM spells them."""
        pairs = {
            "formatted": self.formatted,
            "familyName": self.family_name,
            "givenName": self.given_name,
            "middleName": self.middle_name,
            "honorificPrefix": self.honorific_prefix,
            "honorificSuffix": self.honorific_suffix,
        }
        return {key: value for key, value in pairs.items() if value}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ScimName:
        """A name from its normalised SCIM form."""
        return cls(
            formatted=_text(value.get("formatted")),
            family_name=_text(value.get("familyName")),
            given_name=_text(value.get("givenName")),
            middle_name=_text(value.get("middleName")),
            honorific_prefix=_text(value.get("honorificPrefix")),
            honorific_suffix=_text(value.get("honorificSuffix")),
        )


@dataclass(frozen=True, slots=True)
class ScimEmail:
    """One `emails` element."""

    value: str
    type: str = ""
    primary: bool = False
    display: str = ""

    def as_dict(self) -> dict[str, Any]:
        """The element as SCIM renders it."""
        body: dict[str, Any] = {"value": self.value}
        if self.type:
            body["type"] = self.type
        if self.primary:
            body["primary"] = True
        if self.display:
            body["display"] = self.display
        return body


@dataclass(frozen=True, slots=True)
class ScimUser:
    """A directory user as the product stores it.

    `id` is the product's own immutable id, empty until `create_user` assigns one.
    `attributes` holds every other normalised attribute, the enterprise extension under
    `ENTERPRISE_USER_SCHEMA`, and should be stored as given. `groups` is read-only output
    the product may fill. `version`, when kept, is the ETag; otherwise one is derived.
    """

    user_name: str
    id: str = ""
    external_id: str = ""
    active: bool = True
    display_name: str = ""
    name: ScimName = field(default_factory=ScimName)
    emails: tuple[ScimEmail, ...] = ()
    attributes: Mapping[str, Any] = field(default_factory=dict)
    groups: tuple[ScimMember, ...] = ()
    created: str = ""
    last_modified: str = ""
    version: str = ""

    @property
    def email(self) -> str:
        """The primary email, else the first, else the `userName` when it is an address."""
        for item in self.emails:
            if item.primary and item.value:
                return item.value
        for item in self.emails:
            if item.value:
                return item.value
        return self.user_name if "@" in self.user_name else ""

    @property
    def enterprise(self) -> Mapping[str, Any]:
        """The enterprise extension's attributes, or an empty mapping."""
        value = self.attributes.get(ENTERPRISE_USER_SCHEMA)
        return value if isinstance(value, Mapping) else {}

    def to_resource(self, base_url: str) -> dict[str, Any]:
        """The full SCIM JSON for this user, `meta` included."""
        schemas = [USER_SCHEMA]
        body: dict[str, Any] = {"schemas": schemas, "id": self.id}
        if self.external_id:
            body["externalId"] = self.external_id
        body["userName"] = self.user_name
        name = self.name.as_dict()
        if name:
            body["name"] = name
        if self.display_name:
            body["displayName"] = self.display_name
        body["active"] = self.active
        if self.emails:
            body["emails"] = [item.as_dict() for item in self.emails]
        for key, value in self.attributes.items():
            if key in body or key in {"schemas", "id", "meta", "password", "groups"}:
                continue
            if key == ENTERPRISE_USER_SCHEMA:
                if isinstance(value, Mapping) and value:
                    schemas.append(ENTERPRISE_USER_SCHEMA)
                    body[key] = copy.deepcopy(dict(value))
                continue
            body[key] = copy.deepcopy(value)
        if self.groups:
            body["groups"] = [{**item.as_dict(base_url, resource="Groups"), "type": "direct"} for item in self.groups]
        body["meta"] = _meta(
            resource_type="User",
            location=f"{base_url}/Users/{self.id}",
            created=self.created,
            last_modified=self.last_modified,
            version=self.version or resource_version(body),
        )
        return body

    @classmethod
    def from_resource(cls, body: Mapping[str, Any], *, normalised: bool = False) -> ScimUser:
        """A user from a request body or a patched resource, refusing one without a `userName`.

        Read-only fields (`id`, `meta`, `groups`) are not read, so the caller fills them from
        the stored user.
        """
        data = dict(body) if normalised else normalise_resource(body, USER_RESOURCE_TYPE)
        user_name = data.pop("userName", None)
        if not isinstance(user_name, str) or not user_name.strip():
            raise ScimError.invalid_value("'userName' is required.")
        external_id = _text(data.pop("externalId", ""))
        active = coerce_boolean(data.pop("active", True), attribute="active")
        display_name = _text(data.pop("displayName", ""))
        raw_name = data.pop("name", None)
        name = ScimName.from_dict(raw_name) if isinstance(raw_name, Mapping) else ScimName()
        emails = tuple(
            ScimEmail(
                value=_text(item.get("value")),
                type=_text(item.get("type")),
                primary=bool(item.get("primary", False)),
                display=_text(item.get("display")),
            )
            for item in data.pop("emails", None) or []
            if isinstance(item, Mapping) and item.get("value")
        )
        for key in ("id", "meta", "groups", "password", "schemas"):
            data.pop(key, None)
        return cls(
            user_name=user_name.strip(),
            external_id=external_id,
            active=active,
            display_name=display_name,
            name=name,
            emails=emails,
            attributes=data,
        )


@dataclass(frozen=True, slots=True)
class ScimMember:
    """One `members` element: a user id, or a nested group's id with `type="Group"`."""

    value: str
    display: str = ""
    type: str = MEMBER_TYPE_USER

    def as_dict(self, base_url: str, *, resource: str = "") -> dict[str, Any]:
        """The element as SCIM renders it, with its `$ref`."""
        endpoint = resource or ("Groups" if self.type == MEMBER_TYPE_GROUP else "Users")
        body: dict[str, Any] = {"value": self.value, "$ref": f"{base_url}/{endpoint}/{self.value}"}
        if self.display:
            body["display"] = self.display
        if not resource:
            body["type"] = self.type
        return body

    @classmethod
    def from_value(cls, value: Any) -> ScimMember:
        """A member from a `members` element, or a bare id string."""
        if isinstance(value, str):
            raw: Mapping[str, Any] = {"value": value}
        elif isinstance(value, Mapping):
            raw = value
        else:
            raise ScimError.invalid_value("A member must be an object with a 'value'.")
        member_id = _text(raw.get("value")).strip()
        if not member_id:
            raise ScimError.invalid_value("A member must carry a 'value'.")
        kind = _text(raw.get("type")) or MEMBER_TYPE_USER
        if kind.lower() not in {MEMBER_TYPE_USER.lower(), MEMBER_TYPE_GROUP.lower()}:
            raise ScimError.invalid_value("A member's 'type' must be 'User' or 'Group'.")
        canonical = MEMBER_TYPE_GROUP if kind.lower() == MEMBER_TYPE_GROUP.lower() else MEMBER_TYPE_USER
        return cls(value=member_id, display=_text(raw.get("display")), type=canonical)


def unique_members(members: Iterable[ScimMember]) -> tuple[ScimMember, ...]:
    """Members with duplicates of the same id dropped, first one kept."""
    seen: set[str] = set()
    result: list[ScimMember] = []
    for member in members:
        if member.value not in seen:
            seen.add(member.value)
            result.append(member)
    return tuple(result)


@dataclass(frozen=True, slots=True)
class ScimGroup:
    """A directory group as the product stores it, typically mapped onto one of its teams.

    `members` is empty when the group was loaded without them. `attributes` holds any other
    normalised attribute and should be stored as given.
    """

    display_name: str
    id: str = ""
    external_id: str = ""
    members: tuple[ScimMember, ...] = ()
    attributes: Mapping[str, Any] = field(default_factory=dict)
    created: str = ""
    last_modified: str = ""
    version: str = ""

    def to_resource(self, base_url: str, *, include_members: bool = True) -> dict[str, Any]:
        """The full SCIM JSON for this group, `meta` included."""
        body: dict[str, Any] = {"schemas": [GROUP_SCHEMA], "id": self.id}
        if self.external_id:
            body["externalId"] = self.external_id
        body["displayName"] = self.display_name
        if include_members:
            body["members"] = [item.as_dict(base_url) for item in self.members]
        for key, value in self.attributes.items():
            if key not in body and key not in {"schemas", "id", "meta", "members"}:
                body[key] = copy.deepcopy(value)
        body["meta"] = _meta(
            resource_type="Group",
            location=f"{base_url}/Groups/{self.id}",
            created=self.created,
            last_modified=self.last_modified,
            version=self.version or resource_version({**body, "members": [m.value for m in self.members]}),
        )
        return body

    @classmethod
    def from_resource(cls, body: Mapping[str, Any], *, normalised: bool = False) -> ScimGroup:
        """A group from a request body or a patched resource, refusing one without a `displayName`."""
        data = dict(body) if normalised else normalise_resource(body, GROUP_RESOURCE_TYPE)
        display_name = data.pop("displayName", None)
        if not isinstance(display_name, str) or not display_name.strip():
            raise ScimError.invalid_value("'displayName' is required.")
        external_id = _text(data.pop("externalId", ""))
        raw_members = data.pop("members", None) or []
        members = unique_members(ScimMember.from_value(item) for item in raw_members)
        for key in ("id", "meta", "schemas"):
            data.pop(key, None)
        return cls(
            display_name=display_name.strip(),
            external_id=external_id,
            members=members,
            attributes=data,
        )


def _split_projection(path: str, resource_type: ScimResourceType) -> tuple[str, str, str]:
    """`(container, attribute, sub)` for an `attributes` entry, container being an extension URN or empty."""
    raw = path.strip()
    for schema in (resource_type.schema, *resource_type.extensions):
        if raw.lower() == schema.id.lower():
            return ("", schema.id, "") if schema is not resource_type.schema else ("", "", "")
        if raw.lower().startswith(schema.id.lower() + ":"):
            rest = raw[len(schema.id) + 1 :]
            attribute, _, sub = rest.partition(".")
            container = "" if schema is resource_type.schema else schema.id
            return container, attribute, sub
    attribute, _, sub = raw.partition(".")
    return "", attribute, sub


def _key_in(container: Mapping[str, Any], name: str) -> str | None:
    """The key of a mapping matching a name in any case, or `None`."""
    lowered = name.lower()
    for key in container:
        if key.lower() == lowered:
            return key
    return None


_ALWAYS: Final = frozenset({"schemas", "id"})


def project_resource(
    resource: Mapping[str, Any],
    resource_type: ScimResourceType,
    *,
    attributes: Sequence[str] = (),
    excluded: Sequence[str] = (),
) -> dict[str, Any]:
    """Apply the `attributes` or `excludedAttributes` parameter to a rendered resource.

    `schemas` and `id` are always returned. `attributes` wins when both are given.
    """
    if attributes:
        result: dict[str, Any] = {key: resource[key] for key in resource if key in _ALWAYS}
        for path in attributes:
            container, attribute, sub = _split_projection(path, resource_type)
            if not attribute:
                continue
            source: Any = resource
            if container:
                source = resource.get(container)
                if not isinstance(source, Mapping):
                    continue
            key = _key_in(source, attribute)
            if key is None:
                continue
            target = result.setdefault(container, {}) if container else result
            value = source[key]
            if not sub:
                target[key] = copy.deepcopy(value)
                continue
            if isinstance(value, list):
                picked: list[dict[str, Any]] = []
                for item in value:
                    if isinstance(item, Mapping):
                        inner = _key_in(item, sub)
                        if inner is not None:
                            picked.append({inner: copy.deepcopy(item[inner])})
                existing = target.get(key)
                if isinstance(existing, list) and len(existing) == len(picked):
                    target[key] = [{**a, **b} for a, b in zip(existing, picked, strict=True)]
                else:
                    target[key] = picked
            elif isinstance(value, Mapping):
                inner = _key_in(value, sub)
                if inner is not None:
                    target.setdefault(key, {})[inner] = copy.deepcopy(value[inner])
        return result
    result = copy.deepcopy(dict(resource))
    for path in excluded:
        container, attribute, sub = _split_projection(path, resource_type)
        if not attribute or (not container and attribute.lower() in _ALWAYS):
            continue
        holder: Any = result.get(container) if container else result
        if not isinstance(holder, dict):
            continue
        key = _key_in(holder, attribute)
        if key is None:
            continue
        if not sub:
            del holder[key]
            continue
        value = holder[key]
        for item in value if isinstance(value, list) else [value]:
            if isinstance(item, dict):
                inner = _key_in(item, sub)
                if inner is not None:
                    del item[inner]
    return result
