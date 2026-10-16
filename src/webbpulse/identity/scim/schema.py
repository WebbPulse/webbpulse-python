"""The SCIM schemas this router serves: RFC 7643 User, Enterprise User and Group.

The definitions drive the `/Schemas` endpoint and also the router's own behaviour: the
canonical spelling of an attribute named in any case, whether a comparison is case exact,
which attributes are multi-valued for PATCH, which are booleans for Entra's string
booleans, and which are read-only.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, Literal

__all__ = [
    "COMMON_ATTRIBUTES",
    "ENTERPRISE_USER_SCHEMA",
    "GROUP_RESOURCE_TYPE",
    "GROUP_SCHEMA",
    "LIST_RESPONSE_SCHEMA",
    "PATCH_OP_SCHEMA",
    "RESOURCE_TYPE_SCHEMA",
    "SCHEMA_SCHEMA",
    "SEARCH_REQUEST_SCHEMA",
    "SERVICE_PROVIDER_CONFIG_SCHEMA",
    "USER_RESOURCE_TYPE",
    "USER_SCHEMA",
    "ResourceKind",
    "ScimAttribute",
    "ScimResourceType",
    "ScimSchema",
    "all_schemas",
    "resource_type",
    "schema_by_id",
    "service_provider_config",
]

USER_SCHEMA: Final = "urn:ietf:params:scim:schemas:core:2.0:User"
ENTERPRISE_USER_SCHEMA: Final = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
GROUP_SCHEMA: Final = "urn:ietf:params:scim:schemas:core:2.0:Group"
LIST_RESPONSE_SCHEMA: Final = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCH_OP_SCHEMA: Final = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SEARCH_REQUEST_SCHEMA: Final = "urn:ietf:params:scim:api:messages:2.0:SearchRequest"
SERVICE_PROVIDER_CONFIG_SCHEMA: Final = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
RESOURCE_TYPE_SCHEMA: Final = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
SCHEMA_SCHEMA: Final = "urn:ietf:params:scim:schemas:core:2.0:Schema"

type ResourceKind = Literal["User", "Group"]

type Mutability = Literal["readOnly", "readWrite", "immutable", "writeOnly"]
type Returned = Literal["always", "never", "default", "request"]


@dataclass(frozen=True, slots=True)
class ScimAttribute:
    """One attribute definition, in the shape RFC 7643 section 7 describes."""

    name: str
    type: str = "string"
    multi_valued: bool = False
    required: bool = False
    case_exact: bool = False
    mutability: Mutability = "readWrite"
    returned: Returned = "default"
    uniqueness: Literal["none", "server", "global"] = "none"
    description: str = ""
    sub_attributes: tuple[ScimAttribute, ...] = ()
    canonical_values: tuple[str, ...] = ()
    reference_types: tuple[str, ...] = ()

    def sub(self, name: str) -> ScimAttribute | None:
        """The sub-attribute with this name in any case, or `None`."""
        lowered = name.lower()
        for item in self.sub_attributes:
            if item.name.lower() == lowered:
                return item
        return None

    def as_dict(self) -> dict[str, Any]:
        """The definition as the `/Schemas` endpoint renders it."""
        body: dict[str, Any] = {
            "name": self.name,
            "type": self.type,
            "multiValued": self.multi_valued,
            "description": self.description or self.name,
            "required": self.required,
            "caseExact": self.case_exact,
            "mutability": self.mutability,
            "returned": self.returned,
            "uniqueness": self.uniqueness,
        }
        if self.sub_attributes:
            body["subAttributes"] = [item.as_dict() for item in self.sub_attributes]
        if self.canonical_values:
            body["canonicalValues"] = list(self.canonical_values)
        if self.reference_types:
            body["referenceTypes"] = list(self.reference_types)
        return body


@dataclass(frozen=True, slots=True)
class ScimSchema:
    """A schema: its URN, name and attribute definitions."""

    id: str
    name: str
    description: str
    attributes: tuple[ScimAttribute, ...]

    def attribute(self, name: str) -> ScimAttribute | None:
        """The top-level attribute with this name in any case, or `None`."""
        lowered = name.lower()
        for item in self.attributes:
            if item.name.lower() == lowered:
                return item
        return None

    def as_dict(self, base_url: str) -> dict[str, Any]:
        """The schema as the `/Schemas` endpoint renders it."""
        return {
            "schemas": [SCHEMA_SCHEMA],
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "attributes": [item.as_dict() for item in self.attributes],
            "meta": {"resourceType": "Schema", "location": f"{base_url}/Schemas/{self.id}"},
        }


@dataclass(frozen=True, slots=True)
class ScimResourceType:
    """A resource type: its endpoint, core schema and extensions."""

    name: ResourceKind
    endpoint: str
    schema: ScimSchema
    extensions: tuple[ScimSchema, ...] = ()

    def extension(self, urn: str) -> ScimSchema | None:
        """The extension schema with this URN in any case, or `None`."""
        lowered = urn.lower()
        for item in self.extensions:
            if item.id.lower() == lowered:
                return item
        return None

    def schema_for(self, urn: str) -> ScimSchema | None:
        """The core or extension schema with this URN in any case, or `None`."""
        if urn.lower() == self.schema.id.lower():
            return self.schema
        return self.extension(urn)

    def as_dict(self, base_url: str) -> dict[str, Any]:
        """The resource type as the `/ResourceTypes` endpoint renders it."""
        return {
            "schemas": [RESOURCE_TYPE_SCHEMA],
            "id": self.name,
            "name": self.name,
            "endpoint": self.endpoint,
            "description": f"{self.name} resources",
            "schema": self.schema.id,
            "schemaExtensions": [{"schema": item.id, "required": False} for item in self.extensions],
            "meta": {"resourceType": "ResourceType", "location": f"{base_url}/ResourceTypes/{self.name}"},
        }


def _multi(name: str, *, sub: tuple[ScimAttribute, ...] | None = None, **kwargs: Any) -> ScimAttribute:
    """A multi-valued complex attribute with the usual `value`, `display`, `type`, `primary`."""
    default_sub = (
        ScimAttribute("value"),
        ScimAttribute("display"),
        ScimAttribute("type"),
        ScimAttribute("primary", type="boolean"),
    )
    return ScimAttribute(name, type="complex", multi_valued=True, sub_attributes=sub or default_sub, **kwargs)


COMMON_ATTRIBUTES: Final = (
    ScimAttribute("id", case_exact=True, mutability="readOnly", returned="always", uniqueness="server"),
    ScimAttribute("externalId", case_exact=True),
    ScimAttribute(
        "meta",
        type="complex",
        mutability="readOnly",
        sub_attributes=(
            ScimAttribute("resourceType", case_exact=True, mutability="readOnly"),
            ScimAttribute("created", type="dateTime", mutability="readOnly"),
            ScimAttribute("lastModified", type="dateTime", mutability="readOnly"),
            ScimAttribute("location", type="reference", case_exact=True, mutability="readOnly"),
            ScimAttribute("version", case_exact=True, mutability="readOnly"),
        ),
    ),
)
"""`id`, `externalId` and `meta`: on every resource, and in no schema's attribute list."""

_USER: Final = ScimSchema(
    id=USER_SCHEMA,
    name="User",
    description="User Account",
    attributes=(
        ScimAttribute("userName", required=True, uniqueness="server", description="Unique identifier for the User."),
        ScimAttribute(
            "name",
            type="complex",
            sub_attributes=(
                ScimAttribute("formatted"),
                ScimAttribute("familyName"),
                ScimAttribute("givenName"),
                ScimAttribute("middleName"),
                ScimAttribute("honorificPrefix"),
                ScimAttribute("honorificSuffix"),
            ),
        ),
        ScimAttribute("displayName"),
        ScimAttribute("nickName"),
        ScimAttribute("profileUrl", type="reference", reference_types=("external",)),
        ScimAttribute("title"),
        ScimAttribute("userType"),
        ScimAttribute("preferredLanguage"),
        ScimAttribute("locale"),
        ScimAttribute("timezone"),
        ScimAttribute("active", type="boolean"),
        ScimAttribute("password", mutability="writeOnly", returned="never"),
        _multi("emails"),
        _multi("phoneNumbers"),
        _multi("ims"),
        _multi("photos"),
        _multi(
            "addresses",
            sub=(
                ScimAttribute("formatted"),
                ScimAttribute("streetAddress"),
                ScimAttribute("locality"),
                ScimAttribute("region"),
                ScimAttribute("postalCode"),
                ScimAttribute("country"),
                ScimAttribute("type"),
                ScimAttribute("primary", type="boolean"),
            ),
        ),
        _multi(
            "groups",
            mutability="readOnly",
            sub=(
                ScimAttribute("value", mutability="readOnly"),
                ScimAttribute("$ref", type="reference", mutability="readOnly", reference_types=("Group",)),
                ScimAttribute("display", mutability="readOnly"),
                ScimAttribute("type", mutability="readOnly", canonical_values=("direct", "indirect")),
            ),
        ),
        _multi("entitlements"),
        _multi("roles"),
        _multi("x509Certificates"),
    ),
)

_ENTERPRISE_USER: Final = ScimSchema(
    id=ENTERPRISE_USER_SCHEMA,
    name="EnterpriseUser",
    description="Enterprise User",
    attributes=(
        ScimAttribute("employeeNumber"),
        ScimAttribute("costCenter"),
        ScimAttribute("organization"),
        ScimAttribute("division"),
        ScimAttribute("department"),
        ScimAttribute(
            "manager",
            type="complex",
            sub_attributes=(
                ScimAttribute("value"),
                ScimAttribute("$ref", type="reference", reference_types=("User",)),
                ScimAttribute("displayName", mutability="readOnly"),
            ),
        ),
    ),
)

_GROUP: Final = ScimSchema(
    id=GROUP_SCHEMA,
    name="Group",
    description="Group",
    attributes=(
        ScimAttribute("displayName", required=True, description="A human-readable name for the Group."),
        ScimAttribute(
            "members",
            type="complex",
            multi_valued=True,
            sub_attributes=(
                ScimAttribute("value", case_exact=True, mutability="immutable"),
                ScimAttribute("$ref", type="reference", mutability="immutable", reference_types=("User", "Group")),
                ScimAttribute("display", mutability="readOnly"),
                ScimAttribute("type", mutability="immutable", canonical_values=("User", "Group")),
            ),
        ),
    ),
)

USER_RESOURCE_TYPE: Final = ScimResourceType("User", "/Users", _USER, (_ENTERPRISE_USER,))
GROUP_RESOURCE_TYPE: Final = ScimResourceType("Group", "/Groups", _GROUP)

_SCHEMAS: Final[Mapping[str, ScimSchema]] = {item.id.lower(): item for item in (_USER, _ENTERPRISE_USER, _GROUP)}


def resource_type(kind: ResourceKind) -> ScimResourceType:
    """The resource type for `User` or `Group`."""
    return USER_RESOURCE_TYPE if kind == "User" else GROUP_RESOURCE_TYPE


def schema_by_id(urn: str) -> ScimSchema | None:
    """A served schema by its URN in any case, or `None`."""
    return _SCHEMAS.get(urn.lower())


def all_schemas() -> tuple[ScimSchema, ...]:
    """Every served schema, User first."""
    return (_USER, _ENTERPRISE_USER, _GROUP)


def service_provider_config(base_url: str, *, max_results: int, documentation_uri: str = "") -> dict[str, Any]:
    """The `/ServiceProviderConfig` document: PATCH, filter and ETags on; bulk, sort and passwords off."""
    body: dict[str, Any] = {
        "schemas": [SERVICE_PROVIDER_CONFIG_SCHEMA],
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": max_results},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": True},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "A per-directory bearer token, sent as `Authorization: Bearer <token>`.",
                "primary": True,
            }
        ],
        "meta": {"resourceType": "ServiceProviderConfig", "location": f"{base_url}/ServiceProviderConfig"},
    }
    if documentation_uri:
        body["documentationUri"] = documentation_uri
    return body
