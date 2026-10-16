"""SCIM 2.0 provisioning (RFC 7643 and 7644) for identity providers such as Okta and Entra ID.

A product implements `ScimHooks` to store directory users and groups, builds a
`ScimService` over them and the `api_keys` store its tokens live in, and mounts
`build_scim_router(service)`. `mint_scim_token` issues a tenant's bearer token. FastAPI is
only imported when the router is built. See docs/identity-scim.md.
"""

from __future__ import annotations

from webbpulse.identity.scim.errors import SCIM_ERROR_SCHEMA, ScimError
from webbpulse.identity.scim.filters import ScimFilter, parse_filter
from webbpulse.identity.scim.patch import PatchOperation, apply_patch, parse_patch_request
from webbpulse.identity.scim.resources import (
    MEMBER_TYPE_GROUP,
    MEMBER_TYPE_USER,
    ScimEmail,
    ScimGroup,
    ScimMember,
    ScimName,
    ScimUser,
)
from webbpulse.identity.scim.routes import SCIM_MEDIA_TYPE, SCIM_PREFIX, build_scim_router
from webbpulse.identity.scim.schema import ENTERPRISE_USER_SCHEMA, GROUP_SCHEMA, USER_SCHEMA
from webbpulse.identity.scim.service import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    SCIM_SCOPE,
    SCIM_TOKEN_KIND,
    ScimHooks,
    ScimPage,
    ScimPrincipal,
    ScimQuery,
    ScimService,
    mint_scim_token,
)

__all__ = [
    "DEFAULT_PAGE_SIZE",
    "ENTERPRISE_USER_SCHEMA",
    "GROUP_SCHEMA",
    "MAX_PAGE_SIZE",
    "MEMBER_TYPE_GROUP",
    "MEMBER_TYPE_USER",
    "SCIM_ERROR_SCHEMA",
    "SCIM_MEDIA_TYPE",
    "SCIM_PREFIX",
    "SCIM_SCOPE",
    "SCIM_TOKEN_KIND",
    "USER_SCHEMA",
    "PatchOperation",
    "ScimEmail",
    "ScimError",
    "ScimFilter",
    "ScimGroup",
    "ScimHooks",
    "ScimMember",
    "ScimName",
    "ScimPage",
    "ScimPrincipal",
    "ScimQuery",
    "ScimService",
    "ScimUser",
    "apply_patch",
    "build_scim_router",
    "mint_scim_token",
    "parse_filter",
    "parse_patch_request",
]
