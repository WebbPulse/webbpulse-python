"""Tests for the SCIM 2.0 router, including the request shapes Okta and Entra ID send."""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Sequence
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import webbpulse.identity.api_keys as api_keys
from webbpulse.identity.scim import (
    ENTERPRISE_USER_SCHEMA,
    GROUP_SCHEMA,
    SCIM_MEDIA_TYPE,
    SCIM_SCOPE,
    SCIM_TOKEN_KIND,
    USER_SCHEMA,
    PatchOperation,
    ScimError,
    ScimGroup,
    ScimHooks,
    ScimMember,
    ScimPage,
    ScimQuery,
    ScimService,
    ScimUser,
    apply_patch,
    build_scim_router,
    mint_scim_token,
    parse_filter,
    parse_patch_request,
)
from webbpulse.identity.scim.filters import parse_patch_path
from webbpulse.identity.scim.patch import member_changes
from webbpulse.identity.scim.resources import coerce_boolean, project_resource
from webbpulse.identity.scim.schema import (
    GROUP_RESOURCE_TYPE,
    LIST_RESPONSE_SCHEMA,
    PATCH_OP_SCHEMA,
    SEARCH_REQUEST_SCHEMA,
    USER_RESOURCE_TYPE,
)
from webbpulse.identity.scim.service import etag_matches

BASE_URL = "https://api.example.com/scim/v2"
TENANT = "tenant-a"
OTHER_TENANT = "tenant-b"


class MemoryHooks(ScimHooks):
    """Directory users and groups in dictionaries, recording side effects."""

    def __init__(self) -> None:
        """Start empty."""
        self.users: dict[tuple[str, str], ScimUser] = {}
        self.groups: dict[tuple[str, str], ScimGroup] = {}
        self.members: dict[tuple[str, str], list[ScimMember]] = {}
        self.deactivated: list[str] = []
        self.reactivated: list[str] = []
        self.member_loads = 0
        self.disabled: set[str] = set()
        self.counter = 0

    def _next_id(self, prefix: str) -> str:
        """A fresh id."""
        self.counter += 1
        return f"{prefix}{self.counter}"

    def get_user(self, tenant_id: str, user_id: str) -> ScimUser | None:
        """The stored user."""
        return self.users.get((tenant_id, user_id))

    def list_users(self, tenant_id: str, query: ScimQuery) -> ScimPage[ScimUser]:
        """A point lookup on `userName`, else an in-memory filter."""
        users = [user for (tenant, _), user in self.users.items() if tenant == tenant_id]
        user_name = query.equality("userName")
        if user_name is not None:
            users = [user for user in users if user.user_name.lower() == user_name.lower()]
            return ScimQuery(start_index=query.start_index, count=query.count).apply_users(users)
        return query.apply_users(users)

    def create_user(self, tenant_id: str, user: ScimUser) -> ScimUser:
        """Store a user under a fresh id."""
        stored = dataclasses.replace(user, id=self._next_id("u"))
        self.users[(tenant_id, stored.id)] = stored
        return stored

    def update_user(self, tenant_id: str, user: ScimUser) -> ScimUser:
        """Overwrite a user."""
        self.users[(tenant_id, user.id)] = user
        return user

    def deactivate_user(self, tenant_id: str, user: ScimUser) -> None:
        """Record a deactivation."""
        self.deactivated.append(user.id)

    def reactivate_user(self, tenant_id: str, user: ScimUser) -> None:
        """Record a reactivation."""
        self.reactivated.append(user.id)

    def delete_user(self, tenant_id: str, user_id: str) -> bool:
        """Drop a user and its memberships."""
        found = self.users.pop((tenant_id, user_id), None)
        for key, members in self.members.items():
            if key[0] == tenant_id:
                self.members[key] = [member for member in members if member.value != user_id]
        return found is not None

    def _with_members(self, tenant_id: str, group: ScimGroup, include_members: bool) -> ScimGroup:
        """The group with its members attached when asked for."""
        if not include_members:
            return group
        self.member_loads += 1
        return dataclasses.replace(group, members=tuple(self.members.get((tenant_id, group.id), [])))

    def get_group(self, tenant_id: str, group_id: str, *, include_members: bool = True) -> ScimGroup | None:
        """The stored group."""
        group = self.groups.get((tenant_id, group_id))
        return None if group is None else self._with_members(tenant_id, group, include_members)

    def list_groups(self, tenant_id: str, query: ScimQuery) -> ScimPage[ScimGroup]:
        """An in-memory filter over the tenant's groups."""
        groups = [
            self._with_members(tenant_id, group, query.include_members)
            for (tenant, _), group in self.groups.items()
            if tenant == tenant_id
        ]
        return query.apply_groups(groups)

    def create_group(self, tenant_id: str, group: ScimGroup) -> ScimGroup:
        """Store a group, which never arrives with members."""
        assert not group.members
        stored = dataclasses.replace(group, id=self._next_id("g"))
        self.groups[(tenant_id, stored.id)] = stored
        self.members[(tenant_id, stored.id)] = []
        return stored

    def update_group(self, tenant_id: str, group: ScimGroup) -> ScimGroup:
        """Overwrite a group's attributes."""
        assert not group.members
        self.groups[(tenant_id, group.id)] = group
        return group

    def delete_group(self, tenant_id: str, group_id: str) -> bool:
        """Drop a group."""
        self.members.pop((tenant_id, group_id), None)
        return self.groups.pop((tenant_id, group_id), None) is not None

    def add_group_members(self, tenant_id: str, group_id: str, members: Sequence[ScimMember]) -> None:
        """Add members not already present."""
        current = self.members.setdefault((tenant_id, group_id), [])
        known = {member.value for member in current}
        current.extend(member for member in members if member.value not in known)

    def remove_group_members(self, tenant_id: str, group_id: str, member_ids: Sequence[str]) -> None:
        """Remove members by id."""
        doomed = set(member_ids)
        key = (tenant_id, group_id)
        self.members[key] = [member for member in self.members.get(key, []) if member.value not in doomed]

    def scim_enabled(self, tenant_id: str) -> bool:
        """Off for tenants in `disabled`."""
        return tenant_id not in self.disabled


class ExplodingHooks(MemoryHooks):
    """Hooks whose user lookup fails unexpectedly."""

    def get_user(self, tenant_id: str, user_id: str) -> ScimUser | None:
        """Fail."""
        raise RuntimeError("database unavailable")


@pytest.fixture
def hooks() -> MemoryHooks:
    """Fresh in-memory hooks."""
    return MemoryHooks()


@pytest.fixture
def keys() -> api_keys.InMemoryApiKeyStore:
    """A fresh key store."""
    return api_keys.InMemoryApiKeyStore()


@pytest.fixture
def service(hooks: MemoryHooks, keys: api_keys.InMemoryApiKeyStore) -> ScimService:
    """The service over the in-memory hooks."""
    return ScimService(hooks, keys, base_url=BASE_URL + "/")


def _client(service: ScimService, token: str = "") -> TestClient:
    """A client over an app with the router mounted, sending `token` when given."""
    app = FastAPI()
    app.include_router(build_scim_router(service))
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return TestClient(app, headers=headers)


@pytest.fixture
def token(keys: api_keys.InMemoryApiKeyStore) -> str:
    """A SCIM token for the main tenant."""
    return mint_scim_token(keys, tenant_id=TENANT, user_id="admin-1").plaintext


@pytest.fixture
def client(service: ScimService, token: str) -> TestClient:
    """An authenticated client for the main tenant."""
    return _client(service, token)


def _scim(body: dict[str, Any]) -> dict[str, Any]:
    """Keyword arguments sending a body as `application/scim+json`."""
    return {"content": json.dumps(body), "headers": {"Content-Type": SCIM_MEDIA_TYPE}}


def _patch(*operations: dict[str, Any]) -> dict[str, Any]:
    """A `PatchOp` body."""
    return {"schemas": [PATCH_OP_SCHEMA], "Operations": list(operations)}


OKTA_CREATE_USER: dict[str, Any] = {
    "schemas": [USER_SCHEMA],
    "userName": "isabella.ortiz@example.com",
    "name": {"givenName": "Isabella", "familyName": "Ortiz"},
    "emails": [{"primary": True, "value": "isabella.ortiz@example.com", "type": "work"}],
    "displayName": "Isabella Ortiz",
    "locale": "en-US",
    "externalId": "00ujl29u0le5T6Aj10h7",
    "groups": [],
    "password": "1mz050nq",
    "active": True,
}

ENTRA_CREATE_USER: dict[str, Any] = {
    "schemas": [USER_SCHEMA, ENTERPRISE_USER_SCHEMA],
    "externalId": "0a21f0f2-8d2a-4f8e-bf98-7363c4aed4ef",
    "userName": "Test_User_ab6490ee@testuser.com",
    "active": True,
    "emails": [{"primary": True, "type": "work", "value": "Test_User_fd0ea19b@testuser.com"}],
    "meta": {"resourceType": "User"},
    "name": {"formatted": "givenName familyName", "familyName": "familyName", "givenName": "givenName"},
    "roles": [],
    ENTERPRISE_USER_SCHEMA: {"department": "Engineering", "employeeNumber": "1234"},
}


def _create_user(client: TestClient, body: dict[str, Any] | None = None, **overrides: Any) -> dict[str, Any]:
    """Create a user through the route and answer its JSON."""
    payload = {**(body or OKTA_CREATE_USER), **overrides}
    response = client.post("/scim/v2/Users", **_scim(payload))
    assert response.status_code == 201, response.text
    created: dict[str, Any] = response.json()
    return created


def _create_group(client: TestClient, display_name: str, members: Sequence[str] = ()) -> dict[str, Any]:
    """Create a group through the route and answer its JSON."""
    body = {
        "schemas": [GROUP_SCHEMA],
        "displayName": display_name,
        "members": [{"value": member} for member in members],
    }
    response = client.post("/scim/v2/Groups", **_scim(body))
    assert response.status_code == 201, response.text
    created: dict[str, Any] = response.json()
    return created


def test_the_discovery_endpoints_answer_without_a_token(service: ScimService) -> None:
    """ServiceProviderConfig, ResourceTypes and Schemas are public and SCIM-typed."""
    client = _client(service)
    config = client.get("/scim/v2/ServiceProviderConfig")
    assert config.status_code == 200
    assert config.headers["content-type"].startswith(SCIM_MEDIA_TYPE)
    body = config.json()
    assert body["patch"]["supported"] is True
    assert body["bulk"]["supported"] is False
    assert body["filter"]["supported"] is True
    assert body["authenticationSchemes"][0]["type"] == "oauthbearertoken"

    types = client.get("/scim/v2/ResourceTypes").json()
    assert types["schemas"] == [LIST_RESPONSE_SCHEMA]
    assert [item["id"] for item in types["Resources"]] == ["User", "Group"]
    assert types["Resources"][0]["schemaExtensions"][0]["schema"] == ENTERPRISE_USER_SCHEMA
    assert client.get("/scim/v2/ResourceTypes/user").json()["endpoint"] == "/Users"
    assert client.get("/scim/v2/ResourceTypes/Nope").status_code == 404

    schemas = client.get("/scim/v2/Schemas").json()
    assert schemas["totalResults"] == 3
    user_schema = client.get(f"/scim/v2/Schemas/{USER_SCHEMA}").json()
    assert user_schema["id"] == USER_SCHEMA
    assert any(item["name"] == "userName" for item in user_schema["attributes"])
    missing = client.get("/scim/v2/Schemas/urn:example:nope")
    assert missing.status_code == 404
    assert missing.json()["status"] == "404"


def test_resource_routes_need_a_bearer_token(service: ScimService) -> None:
    """No token, or one that is not a key, answers 401 with a Bearer challenge."""
    anonymous = _client(service)
    response = anonymous.get("/scim/v2/Users")
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer")
    assert response.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
    assert _client(service, "wpk_not-a-real-key").get("/scim/v2/Users").status_code == 401
    basic = anonymous.get("/scim/v2/Users", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert basic.status_code == 401


def test_a_token_without_the_scim_scope_is_forbidden(service: ScimService, keys: api_keys.InMemoryApiKeyStore) -> None:
    """An ordinary API key in the same tenant cannot provision."""
    minted = api_keys.mint(user_id="admin-1", tenant_id=TENANT, scopes=("issues:read",), store=keys)
    response = _client(service, minted.plaintext).get("/scim/v2/Users")
    assert response.status_code == 403


def test_a_revoked_token_is_refused(service: ScimService, keys: api_keys.InMemoryApiKeyStore) -> None:
    """Revoking the key ends provisioning straight away."""
    minted = mint_scim_token(keys, tenant_id=TENANT, user_id="admin-1")
    api_keys.revoke(minted.plaintext, keys)
    assert _client(service, minted.plaintext).get("/scim/v2/Users").status_code == 401


def test_a_disabled_tenant_is_forbidden(client: TestClient, hooks: MemoryHooks) -> None:
    """`scim_enabled` false answers 403."""
    hooks.disabled.add(TENANT)
    assert client.get("/scim/v2/Users").status_code == 403


def test_a_scim_token_is_stored_only_as_a_hash(keys: api_keys.InMemoryApiKeyStore) -> None:
    """The plaintext appears once; the record carries the scope, kind and tenant."""
    minted = mint_scim_token(keys, tenant_id=TENANT, user_id="admin-1", name="Okta")
    record = keys.get(api_keys.hash_key(minted.plaintext))
    assert record is not None
    assert record.scopes == (SCIM_SCOPE,)
    assert record.kind == SCIM_TOKEN_KIND
    assert record.tenant_id == TENANT
    assert record.name == "Okta"
    assert minted.plaintext not in json.dumps(dataclasses.asdict(record))


def test_okta_looks_a_user_up_then_creates_it(client: TestClient, hooks: MemoryHooks) -> None:
    """Okta's pre-create lookup, its create body with `groups` and `password`, and the lookup after."""
    params = {"filter": 'userName eq "isabella.ortiz@example.com"', "startIndex": "1", "count": "100"}
    before = client.get("/scim/v2/Users", params=params)
    assert before.status_code == 200
    assert before.json() == {
        "schemas": [LIST_RESPONSE_SCHEMA],
        "totalResults": 0,
        "startIndex": 1,
        "itemsPerPage": 0,
        "Resources": [],
    }

    response = client.post("/scim/v2/Users", **_scim(OKTA_CREATE_USER))
    assert response.status_code == 201
    created = response.json()
    assert response.headers["location"] == f"{BASE_URL}/Users/{created['id']}"
    assert response.headers["etag"].startswith('W/"')
    assert created["userName"] == "isabella.ortiz@example.com"
    assert created["externalId"] == "00ujl29u0le5T6Aj10h7"
    assert created["active"] is True
    assert created["locale"] == "en-US"
    assert created["meta"]["resourceType"] == "User"
    assert created["meta"]["location"] == f"{BASE_URL}/Users/{created['id']}"
    assert "password" not in created
    assert "groups" not in created
    stored = hooks.users[(TENANT, created["id"])]
    assert stored.email == "isabella.ortiz@example.com"
    assert stored.name.given_name == "Isabella"
    assert "password" not in stored.attributes

    after = client.get("/scim/v2/Users", params=params).json()
    assert after["totalResults"] == 1
    assert after["Resources"][0]["id"] == created["id"]


def test_a_taken_user_name_answers_409(client: TestClient) -> None:
    """A second user with the same `userName`, in any case, is refused with `uniqueness`."""
    _create_user(client)
    response = client.post("/scim/v2/Users", **_scim({**OKTA_CREATE_USER, "userName": "Isabella.Ortiz@example.com"}))
    assert response.status_code == 409
    assert response.json()["scimType"] == "uniqueness"


def test_okta_deactivates_and_reactivates_through_patch(client: TestClient, hooks: MemoryHooks) -> None:
    """Okta's path-less replace of `active` runs the deactivate and reactivate hooks."""
    user_id = _create_user(client)["id"]
    response = client.patch(
        f"/scim/v2/Users/{user_id}", **_scim(_patch({"op": "replace", "value": {"active": False}}))
    )
    assert response.status_code == 200
    assert response.json()["active"] is False
    assert hooks.deactivated == [user_id]
    assert hooks.users[(TENANT, user_id)].active is False

    response = client.patch(f"/scim/v2/Users/{user_id}", **_scim(_patch({"op": "replace", "value": {"active": True}})))
    assert response.json()["active"] is True
    assert hooks.reactivated == [user_id]
    assert hooks.deactivated == [user_id]


def test_okta_profile_patch_ignores_the_id_it_echoes(client: TestClient) -> None:
    """Okta puts `id` inside a path-less replace; it is skipped, not refused."""
    user_id = _create_user(client)["id"]
    body = _patch(
        {"op": "replace", "value": {"id": user_id, "name": {"givenName": "Bella"}, "displayName": "Bella Ortiz"}}
    )
    response = client.patch(f"/scim/v2/Users/{user_id}", **_scim(body))
    assert response.status_code == 200
    updated = response.json()
    assert updated["id"] == user_id
    assert updated["name"] == {"givenName": "Bella", "familyName": "Ortiz"}
    assert updated["displayName"] == "Bella Ortiz"


def test_okta_put_replaces_the_user_and_can_deactivate(client: TestClient, hooks: MemoryHooks) -> None:
    """A PUT replaces every attribute, and `active: false` deactivates."""
    created = _create_user(client)
    body = {**OKTA_CREATE_USER, "id": created["id"], "displayName": "I. Ortiz", "locale": None, "active": False}
    response = client.put(f"/scim/v2/Users/{created['id']}", **_scim(body))
    assert response.status_code == 200
    replaced = response.json()
    assert replaced["displayName"] == "I. Ortiz"
    assert "locale" not in replaced
    assert replaced["active"] is False
    assert replaced["meta"]["created"] == created["meta"]["created"]
    assert hooks.deactivated == [created["id"]]


def test_a_user_created_inactive_is_deactivated(client: TestClient, hooks: MemoryHooks) -> None:
    """A create with `active: false` runs the deactivate hook too."""
    created = _create_user(client, active=False)
    assert created["active"] is False
    assert hooks.deactivated == [created["id"]]


def test_entra_creates_a_user_with_the_enterprise_extension(client: TestClient, hooks: MemoryHooks) -> None:
    """Entra's create body keeps the enterprise extension and drops `meta`."""
    created = _create_user(client, ENTRA_CREATE_USER)
    assert created["schemas"] == [USER_SCHEMA, ENTERPRISE_USER_SCHEMA]
    assert created[ENTERPRISE_USER_SCHEMA] == {"department": "Engineering", "employeeNumber": "1234"}
    assert created["name"]["formatted"] == "givenName familyName"
    assert hooks.users[(TENANT, created["id"])].enterprise["department"] == "Engineering"


def test_entra_lookups_by_user_name_and_external_id(client: TestClient) -> None:
    """Entra's `userName eq` for a missing user answers an empty list; `externalId eq` finds one."""
    missing = client.get("/scim/v2/Users", params={"filter": 'userName eq "Test_User_nobody@testuser.com"'})
    assert missing.status_code == 200
    assert missing.json()["totalResults"] == 0
    assert missing.json()["Resources"] == []
    created = _create_user(client, ENTRA_CREATE_USER)
    found = client.get(
        "/scim/v2/Users", params={"filter": f'externalId eq "{ENTRA_CREATE_USER["externalId"]}"'}
    ).json()
    assert [item["id"] for item in found["Resources"]] == [created["id"]]
    wrong_case = client.get(
        "/scim/v2/Users", params={"filter": f'externalId eq "{ENTRA_CREATE_USER["externalId"].upper()}"'}
    ).json()
    assert wrong_case["totalResults"] == 0


def test_entra_patches_a_user(client: TestClient, hooks: MemoryHooks) -> None:
    """Capitalised ops, string booleans, filtered email paths, sub-attributes and extension URNs."""
    user_id = _create_user(client, ENTRA_CREATE_USER)["id"]
    body = _patch(
        {"op": "Replace", "path": "displayName", "value": "Updated Name"},
        {"op": "Replace", "path": 'emails[type eq "work"].value', "value": "updated@contoso.com"},
        {"op": "Replace", "path": "name.givenName", "value": "Updated"},
        {"op": "Add", "path": f"{ENTERPRISE_USER_SCHEMA}:manager", "value": "manager-1"},
        {"op": "Replace", "path": f"{ENTERPRISE_USER_SCHEMA}:department", "value": "Sales"},
        {"op": "Replace", "path": "active", "value": "False"},
    )
    response = client.patch(f"/scim/v2/Users/{user_id}", **_scim(body))
    assert response.status_code == 200, response.text
    updated = response.json()
    assert updated["displayName"] == "Updated Name"
    assert updated["emails"] == [{"value": "updated@contoso.com", "type": "work", "primary": True}]
    assert updated["name"]["givenName"] == "Updated"
    assert updated[ENTERPRISE_USER_SCHEMA]["manager"]["value"] == "manager-1"
    assert updated[ENTERPRISE_USER_SCHEMA]["department"] == "Sales"
    assert updated[ENTERPRISE_USER_SCHEMA]["employeeNumber"] == "1234"
    assert updated["active"] is False
    assert hooks.deactivated == [user_id]


def test_entra_adds_a_first_work_email_through_a_filter(client: TestClient) -> None:
    """`emails[type eq "work"].value` with no work email yet creates the element."""
    user_id = _create_user(client, {"schemas": [USER_SCHEMA], "userName": "nomail"})["id"]
    body = _patch({"op": "Add", "path": 'emails[type eq "work"].value', "value": "new@contoso.com"})
    updated = client.patch(f"/scim/v2/Users/{user_id}", **_scim(body)).json()
    assert updated["emails"] == [{"value": "new@contoso.com", "type": "work"}]


def test_entra_path_less_replace_with_dotted_and_urn_keys(client: TestClient) -> None:
    """A path-less value whose keys are paths, as Entra sends for several attributes at once."""
    user_id = _create_user(client, ENTRA_CREATE_USER)["id"]
    body = _patch(
        {
            "op": "Replace",
            "value": {
                "name.familyName": "Smith",
                "title": "Engineer",
                f"{ENTERPRISE_USER_SCHEMA}:employeeNumber": "42",
                "active": "True",
            },
        }
    )
    updated = client.patch(f"/scim/v2/Users/{user_id}", **_scim(body)).json()
    assert updated["name"]["familyName"] == "Smith"
    assert updated["title"] == "Engineer"
    assert updated[ENTERPRISE_USER_SCHEMA]["employeeNumber"] == "42"
    assert updated["active"] is True


def test_entra_removes_the_manager(client: TestClient) -> None:
    """A remove on an extension attribute drops it."""
    user_id = _create_user(client, ENTRA_CREATE_USER)["id"]
    client.patch(
        f"/scim/v2/Users/{user_id}",
        **_scim(_patch({"op": "Add", "path": f"{ENTERPRISE_USER_SCHEMA}:manager", "value": "manager-1"})),
    )
    response = client.patch(
        f"/scim/v2/Users/{user_id}",
        **_scim(_patch({"op": "Remove", "path": f"{ENTERPRISE_USER_SCHEMA}:manager"})),
    )
    assert "manager" not in response.json()[ENTERPRISE_USER_SCHEMA]


def test_patch_refusals(client: TestClient) -> None:
    """Read-only paths, required removals, missing paths, unknown ops and bad bodies answer 400."""
    user_id = _create_user(client)["id"]
    url = f"/scim/v2/Users/{user_id}"
    cases: list[tuple[dict[str, Any], str]] = [
        (_patch({"op": "replace", "path": "id", "value": "x"}), "mutability"),
        (_patch({"op": "remove", "path": "userName"}), "mutability"),
        (_patch({"op": "remove"}), "noTarget"),
        (_patch({"op": "move", "path": "title", "value": "x"}), "invalidSyntax"),
        (_patch({"op": "add", "path": "title"}), "invalidSyntax"),
        (_patch({"op": "replace", "path": "emails[type eq]", "value": "x"}), "invalidPath"),
        (_patch({"op": "replace", "path": 'emails[type co "w"].value', "value": "x"}), "noTarget"),
        ({"schemas": [PATCH_OP_SCHEMA], "Operations": []}, "invalidSyntax"),
        ({"schemas": ["urn:example:wrong"], "Operations": [{"op": "add", "value": {}}]}, "invalidSyntax"),
    ]
    for body, scim_type in cases:
        response = client.patch(url, **_scim(body))
        assert response.status_code == 400, (body, response.text)
        assert response.json()["scimType"] == scim_type, body
    assert client.get(url).json()["userName"] == OKTA_CREATE_USER["userName"]


def test_invalid_json_and_non_object_bodies_answer_invalid_syntax(client: TestClient) -> None:
    """A body that is not JSON, or not an object, is a 400 `invalidSyntax`."""
    response = client.post("/scim/v2/Users", content="{not json", headers={"Content-Type": SCIM_MEDIA_TYPE})
    assert response.status_code == 400
    assert response.json()["scimType"] == "invalidSyntax"
    assert client.post("/scim/v2/Users", json=["a"]).json()["scimType"] == "invalidSyntax"
    missing = client.post("/scim/v2/Users", json={"schemas": [USER_SCHEMA]})
    assert missing.status_code == 400
    assert missing.json()["scimType"] == "invalidValue"


def test_get_and_delete_users(client: TestClient) -> None:
    """GET answers the user; DELETE answers 204, then the user is gone."""
    user_id = _create_user(client)["id"]
    assert client.get(f"/scim/v2/Users/{user_id}").json()["id"] == user_id
    assert client.delete(f"/scim/v2/Users/{user_id}").status_code == 204
    gone = client.get(f"/scim/v2/Users/{user_id}")
    assert gone.status_code == 404
    assert gone.json()["status"] == "404"
    assert client.delete(f"/scim/v2/Users/{user_id}").status_code == 404


def test_tenants_never_see_each_others_users(
    client: TestClient, service: ScimService, keys: api_keys.InMemoryApiKeyStore
) -> None:
    """A token for another tenant neither lists nor reads nor deletes this tenant's users."""
    user_id = _create_user(client)["id"]
    other = _client(service, mint_scim_token(keys, tenant_id=OTHER_TENANT, user_id="admin-2").plaintext)
    assert other.get("/scim/v2/Users").json()["totalResults"] == 0
    assert other.get(f"/scim/v2/Users/{user_id}").status_code == 404
    assert other.delete(f"/scim/v2/Users/{user_id}").status_code == 404
    assert client.get(f"/scim/v2/Users/{user_id}").status_code == 200


def test_pagination_and_projection(client: TestClient) -> None:
    """`startIndex` is 1-based, `count` bounds the page, and `attributes` narrows each resource."""
    ids = [_create_user(client, userName=f"user{index}@example.com")["id"] for index in range(5)]
    page = client.get("/scim/v2/Users", params={"startIndex": "2", "count": "2"}).json()
    assert page["totalResults"] == 5
    assert page["startIndex"] == 2
    assert page["itemsPerPage"] == 2
    assert [item["id"] for item in page["Resources"]] == ids[1:3]
    assert client.get("/scim/v2/Users", params={"count": "0"}).json()["itemsPerPage"] == 0
    assert client.get("/scim/v2/Users", params={"startIndex": "0"}).json()["startIndex"] == 1
    bad = client.get("/scim/v2/Users", params={"count": "lots"})
    assert bad.status_code == 400
    assert bad.json()["scimType"] == "invalidValue"
    narrow = client.get("/scim/v2/Users", params={"attributes": "userName", "count": "1"}).json()
    assert set(narrow["Resources"][0]) == {"schemas", "id", "userName"}
    wide = client.get(f"/scim/v2/Users/{ids[0]}", params={"excludedAttributes": "emails,name"}).json()
    assert "emails" not in wide
    assert "name" not in wide
    assert wide["userName"] == "user0@example.com"


def test_search_through_post(client: TestClient) -> None:
    """`POST /Users/.search` takes the list parameters in a `SearchRequest` body."""
    created = _create_user(client)
    body = {
        "schemas": [SEARCH_REQUEST_SCHEMA],
        "filter": 'userName eq "isabella.ortiz@example.com"',
        "startIndex": 1,
        "count": 10,
        "attributes": ["userName", "name.givenName"],
    }
    found = client.post("/scim/v2/Users/.search", **_scim(body)).json()
    assert found["totalResults"] == 1
    assert found["Resources"][0] == {
        "schemas": [USER_SCHEMA],
        "id": created["id"],
        "userName": "isabella.ortiz@example.com",
        "name": {"givenName": "Isabella"},
    }
    wrong = client.post("/scim/v2/Users/.search", **_scim({"schemas": ["urn:example:nope"]}))
    assert wrong.status_code == 400


def test_an_invalid_filter_answers_invalid_filter(client: TestClient) -> None:
    """A filter that does not parse is a 400 `invalidFilter`."""
    response = client.get("/scim/v2/Users", params={"filter": 'userName eq "unterminated'})
    assert response.status_code == 400
    assert response.json()["scimType"] == "invalidFilter"
    assert client.get("/scim/v2/Users", params={"filter": "userName zz 1"}).json()["scimType"] == "invalidFilter"


def test_etags_guard_writes_and_answer_not_modified(client: TestClient) -> None:
    """`If-None-Match` answers 304; a stale `If-Match` answers 412; a fresh one writes."""
    user_id = _create_user(client)["id"]
    first = client.get(f"/scim/v2/Users/{user_id}")
    etag = first.headers["etag"]
    assert first.json()["meta"]["version"] == etag
    assert client.get(f"/scim/v2/Users/{user_id}", headers={"If-None-Match": etag}).status_code == 304
    body = {**OKTA_CREATE_USER, "displayName": "Changed"}
    stale = client.put(f"/scim/v2/Users/{user_id}", json=body, headers={"If-Match": 'W/"stale"'})
    assert stale.status_code == 412
    fresh = client.put(f"/scim/v2/Users/{user_id}", json=body, headers={"If-Match": etag})
    assert fresh.status_code == 200
    assert fresh.headers["etag"] != etag
    assert client.delete(f"/scim/v2/Users/{user_id}", headers={"If-Match": etag}).status_code == 412


def test_an_unexpected_hook_failure_answers_a_scim_500(keys: api_keys.InMemoryApiKeyStore) -> None:
    """A hook raising anything but `ScimError` answers 500 in the SCIM error shape, naming nothing internal."""
    exploding = ScimService(ExplodingHooks(), keys, base_url=BASE_URL)
    client = _client(exploding, mint_scim_token(keys, tenant_id=TENANT, user_id="admin-1").plaintext)
    response = client.get("/scim/v2/Users/u1")
    assert response.status_code == 500
    assert response.json()["status"] == "500"
    assert "database" not in response.text


def test_okta_creates_and_renames_a_group(client: TestClient, hooks: MemoryHooks) -> None:
    """Okta's group create with empty members, and its path-less rename echoing `id`."""
    created = _create_group(client, "Test SCIMv2")
    assert created["members"] == []
    assert created["schemas"] == [GROUP_SCHEMA]
    body = _patch({"op": "replace", "value": {"id": created["id"], "displayName": "Renamed"}})
    response = client.patch(f"/scim/v2/Groups/{created['id']}", **_scim(body))
    assert response.status_code == 204
    assert hooks.groups[(TENANT, created["id"])].display_name == "Renamed"


def test_okta_pushes_group_members(client: TestClient, hooks: MemoryHooks) -> None:
    """Okta adds with a list and removes with `members[value eq "id"]`, without loading the group's members."""
    first = _create_user(client)["id"]
    second = _create_user(client, userName="second@example.com")["id"]
    group_id = _create_group(client, "Engineering")["id"]
    loads = hooks.member_loads
    add = _patch(
        {
            "op": "add",
            "path": "members",
            "value": [{"value": first, "display": "isabella"}, {"value": second, "display": "second"}],
        }
    )
    assert client.patch(f"/scim/v2/Groups/{group_id}", **_scim(add)).status_code == 204
    remove = _patch({"op": "remove", "path": f'members[value eq "{first}"]'})
    assert client.patch(f"/scim/v2/Groups/{group_id}", **_scim(remove)).status_code == 204
    assert hooks.member_loads == loads
    assert [member.value for member in hooks.members[(TENANT, group_id)]] == [second]
    group = client.get(f"/scim/v2/Groups/{group_id}").json()
    assert group["members"] == [
        {"value": second, "$ref": f"{BASE_URL}/Users/{second}", "type": "User"},
    ]


def test_entra_group_membership_and_rename(client: TestClient, hooks: MemoryHooks) -> None:
    """Entra's capitalised add, its remove with a value list, and a replace of `displayName`."""
    user_id = _create_user(client, ENTRA_CREATE_USER)["id"]
    group_id = _create_group(client, "Group_1")["id"]
    add = _patch({"op": "Add", "path": "members", "value": [{"value": user_id}]})
    assert client.patch(f"/scim/v2/Groups/{group_id}", **_scim(add)).status_code == 204
    assert [member.value for member in hooks.members[(TENANT, group_id)]] == [user_id]
    remove = _patch({"op": "Remove", "path": "members", "value": [{"value": user_id}]})
    assert client.patch(f"/scim/v2/Groups/{group_id}", **_scim(remove)).status_code == 204
    assert hooks.members[(TENANT, group_id)] == []
    rename = _patch({"op": "Replace", "path": "displayName", "value": "Group_2"})
    assert client.patch(f"/scim/v2/Groups/{group_id}", **_scim(rename)).status_code == 204
    assert hooks.groups[(TENANT, group_id)].display_name == "Group_2"


def test_entra_checks_membership_with_a_members_filter(client: TestClient, hooks: MemoryHooks) -> None:
    """`id eq` and `members[value eq]` with `excludedAttributes=members` loads members but omits them."""
    user_id = _create_user(client)["id"]
    group_id = _create_group(client, "Group_1", [user_id])["id"]
    params = {
        "filter": f'id eq "{group_id}" and members[value eq "{user_id}"]',
        "excludedAttributes": "members",
    }
    found = client.get("/scim/v2/Groups", params=params).json()
    assert found["totalResults"] == 1
    assert "members" not in found["Resources"][0]
    params["filter"] = f'id eq "{group_id}" and members[value eq "someone-else"]'
    assert client.get("/scim/v2/Groups", params=params).json()["totalResults"] == 0

    loads = hooks.member_loads
    by_name = client.get(
        "/scim/v2/Groups", params={"filter": 'displayName eq "Group_1"', "excludedAttributes": "members"}
    ).json()
    assert [item["id"] for item in by_name["Resources"]] == [group_id]
    assert hooks.member_loads == loads
    single = client.get(f"/scim/v2/Groups/{group_id}", params={"excludedAttributes": "members"}).json()
    assert "members" not in single
    assert hooks.member_loads == loads


def test_group_put_replaces_members(client: TestClient, hooks: MemoryHooks) -> None:
    """A PUT adds and removes the difference in members."""
    first = _create_user(client)["id"]
    second = _create_user(client, userName="second@example.com")["id"]
    group = _create_group(client, "Team", [first])
    body = {"schemas": [GROUP_SCHEMA], "displayName": "Team", "members": [{"value": second}]}
    response = client.put(f"/scim/v2/Groups/{group['id']}", **_scim(body))
    assert response.status_code == 200
    assert [item["value"] for item in response.json()["members"]] == [second]
    assert [member.value for member in hooks.members[(TENANT, group["id"])]] == [second]


def test_group_patch_replacing_members_falls_back_to_a_full_load(client: TestClient, hooks: MemoryHooks) -> None:
    """A replace of `members` loads the group and applies the difference."""
    first = _create_user(client)["id"]
    second = _create_user(client, userName="second@example.com")["id"]
    group_id = _create_group(client, "Team", [first])["id"]
    body = _patch({"op": "replace", "path": "members", "value": [{"value": second}]})
    assert client.patch(f"/scim/v2/Groups/{group_id}", **_scim(body)).status_code == 204
    assert [member.value for member in hooks.members[(TENANT, group_id)]] == [second]


def test_delete_groups(client: TestClient) -> None:
    """DELETE answers 204, then 404."""
    group_id = _create_group(client, "Gone")["id"]
    assert client.delete(f"/scim/v2/Groups/{group_id}").status_code == 204
    assert client.get(f"/scim/v2/Groups/{group_id}").status_code == 404
    assert client.delete(f"/scim/v2/Groups/{group_id}").status_code == 404
    patch = client.patch(f"/scim/v2/Groups/{group_id}", **_scim(_patch({"op": "add", "path": "members", "value": []})))
    assert patch.status_code == 404


def test_a_group_without_a_display_name_is_refused(client: TestClient) -> None:
    """`displayName` is required."""
    response = client.post("/scim/v2/Groups", json={"schemas": [GROUP_SCHEMA]})
    assert response.status_code == 400
    assert response.json()["scimType"] == "invalidValue"


def test_the_filter_parser_and_evaluator() -> None:
    """Logical operators, grouping, `pr`, value paths and case exactness."""
    resource = USER_RESOURCE_TYPE
    rendered: dict[str, Any] = {
        "id": "Abc",
        "userName": "Alice",
        "active": True,
        "emails": [{"value": "alice@example.com", "type": "work"}],
        "meta": {"lastModified": "2026-10-01T00:00:00Z"},
    }
    assert parse_filter('userName eq "alice"').matches(rendered, resource)
    assert not parse_filter('id eq "abc"').matches(rendered, resource)
    assert parse_filter('id eq "Abc"').matches(rendered, resource)
    assert parse_filter('emails[type eq "work" and value co "@example.com"]').matches(rendered, resource)
    assert parse_filter('emails.value ew "example.com"').matches(rendered, resource)
    assert parse_filter("title pr or active eq true").matches(rendered, resource)
    assert not parse_filter("title pr").matches(rendered, resource)
    assert parse_filter('not (userName sw "b") and (active eq true)').matches(rendered, resource)
    assert parse_filter('meta.lastModified gt "2026-09-01T00:00:00Z"').matches(rendered, resource)
    assert parse_filter(f'{USER_SCHEMA}:userName eq "ALICE"').matches(rendered, resource)
    assert parse_filter(f'{USER_SCHEMA}:userName eq "x"').equality("username") == "x"
    assert parse_filter('userName eq "x" and active eq true').equality("userName") is None
    assert parse_filter('members[value eq "u1"]').references("members")
    for bad in ["", "userName", 'userName eq "a" and', "(userName pr", "userName eq [", 'a eq "b" c']:
        with pytest.raises(ScimError) as caught:
            parse_filter(bad)
        assert caught.value.scim_type == "invalidFilter"


def test_patch_paths_and_member_changes() -> None:
    """PATCH paths parse URNs before dots, and member-only bodies are recognised."""
    path = parse_patch_path(f"{ENTERPRISE_USER_SCHEMA}:manager.value", USER_RESOURCE_TYPE)
    assert (path.urn, path.attribute, path.sub) == (ENTERPRISE_USER_SCHEMA, "manager", "value")
    core = parse_patch_path(f"{USER_SCHEMA}:name.givenName", USER_RESOURCE_TYPE)
    assert (core.urn, core.attribute, core.sub) == ("", "name", "givenName")
    whole = parse_patch_path(ENTERPRISE_USER_SCHEMA, USER_RESOURCE_TYPE)
    assert (whole.urn, whole.attribute) == (ENTERPRISE_USER_SCHEMA, "")
    filtered = parse_patch_path('emails[type eq "work"].value', USER_RESOURCE_TYPE)
    assert filtered.value_filter is not None
    assert filtered.sub == "value"

    operations = parse_patch_request(
        _patch(
            {"op": "Add", "path": "members", "value": [{"value": "u1"}]},
            {"op": "remove", "path": 'members[value eq "u2"]'},
            {"op": "Remove", "path": "members", "value": [{"value": "u3"}]},
        )
    )
    assert member_changes(operations, GROUP_RESOURCE_TYPE) == ([{"value": "u1"}], ["u2", "u3"])
    rename = parse_patch_request(_patch({"op": "replace", "path": "displayName", "value": "x"}))
    assert member_changes(rename, GROUP_RESOURCE_TYPE) is None
    wholesale = parse_patch_request(_patch({"op": "replace", "path": "members", "value": []}))
    assert member_changes(wholesale, GROUP_RESOURCE_TYPE) is None
    lowercase = parse_patch_request({"operations": [{"OP": "ADD", "Path": "members", "Value": []}]})
    assert lowercase == [PatchOperation(op="add", path="members", value=[], has_value=True)]


def test_apply_patch_is_atomic_and_handles_multi_valued_attributes() -> None:
    """A refused operation applies nothing; adds merge by value and keep one primary."""
    resource = {
        "schemas": [USER_SCHEMA],
        "id": "u1",
        "userName": "alice",
        "emails": [{"value": "a@example.com", "type": "work", "primary": True}],
    }
    operations = parse_patch_request(
        _patch(
            {"op": "add", "path": "emails", "value": [{"value": "b@example.com", "type": "home", "primary": True}]},
            {"op": "replace", "path": "id", "value": "u2"},
        )
    )
    with pytest.raises(ScimError):
        apply_patch(resource, operations, USER_RESOURCE_TYPE)
    assert len(resource["emails"]) == 1

    merged = apply_patch(resource, operations[:1], USER_RESOURCE_TYPE)
    assert merged["emails"] == [
        {"value": "a@example.com", "type": "work", "primary": False},
        {"value": "b@example.com", "type": "home", "primary": True},
    ]
    removed = apply_patch(
        merged,
        parse_patch_request(_patch({"op": "remove", "path": 'emails[type eq "home"]'})),
        USER_RESOURCE_TYPE,
    )
    assert [item["value"] for item in removed["emails"]] == ["a@example.com"]
    no_match = apply_patch(
        merged,
        parse_patch_request(_patch({"op": "remove", "path": 'emails[type eq "other"]'})),
        USER_RESOURCE_TYPE,
    )
    assert len(no_match["emails"]) == 2


def test_helpers() -> None:
    """Entra booleans, ETag matching and projection of extension attributes."""
    assert coerce_boolean("True") is True
    assert coerce_boolean("false") is False
    with pytest.raises(ScimError):
        coerce_boolean("maybe")
    assert etag_matches('W/"abc"', 'W/"abc"')
    assert etag_matches('"abc"', 'W/"abc"')
    assert etag_matches("*", 'W/"abc"')
    assert etag_matches('W/"x", W/"abc"', 'W/"abc"')
    assert not etag_matches('W/"x"', 'W/"abc"')
    resource = {
        "schemas": [USER_SCHEMA, ENTERPRISE_USER_SCHEMA],
        "id": "u1",
        "userName": "alice",
        ENTERPRISE_USER_SCHEMA: {"department": "Sales", "employeeNumber": "7"},
    }
    projected = project_resource(
        resource, USER_RESOURCE_TYPE, attributes=[f"{ENTERPRISE_USER_SCHEMA}:department"]
    )
    assert projected == {
        "schemas": [USER_SCHEMA, ENTERPRISE_USER_SCHEMA],
        "id": "u1",
        ENTERPRISE_USER_SCHEMA: {"department": "Sales"},
    }
    excluded = project_resource(resource, USER_RESOURCE_TYPE, excluded=["id", "userName"])
    assert excluded["id"] == "u1"
    assert "userName" not in excluded
