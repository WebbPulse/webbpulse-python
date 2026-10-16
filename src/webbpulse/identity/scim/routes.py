"""The SCIM 2.0 HTTP routes, built onto a FastAPI `APIRouter` for a product to mount.

Kept apart from the service so the rest of the package imports without FastAPI. Bodies are
read by hand rather than through FastAPI's validation, because identity providers send
`application/scim+json` and every failure must answer the SCIM error shape.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any, Final

from webbpulse.identity.scim.errors import ScimError
from webbpulse.identity.scim.filters import parse_filter
from webbpulse.identity.scim.resources import project_resource
from webbpulse.identity.scim.schema import (
    GROUP_RESOURCE_TYPE,
    LIST_RESPONSE_SCHEMA,
    SEARCH_REQUEST_SCHEMA,
    USER_RESOURCE_TYPE,
    ScimResourceType,
    all_schemas,
    schema_by_id,
    service_provider_config,
)
from webbpulse.identity.scim.service import (
    DEFAULT_PAGE_SIZE,
    ScimPrincipal,
    ScimQuery,
    ScimService,
    etag_matches,
)

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import APIRouter
    from starlette.requests import Request
    from starlette.responses import Response

    type _FastAPIRequest = Request
else:
    _FastAPIRequest = None

__all__ = [
    "SCIM_MEDIA_TYPE",
    "SCIM_PREFIX",
    "build_scim_router",
]

_log = logging.getLogger(__name__)

SCIM_MEDIA_TYPE: Final = "application/scim+json"
SCIM_PREFIX: Final = "/scim/v2"
MAX_BODY_BYTES: Final = 1_000_000


def _bind_fastapi_request() -> None:
    """Put `fastapi.Request` in this module's globals, so FastAPI can resolve the annotation."""
    if globals().get("_FastAPIRequest") is None:
        from fastapi import Request as _Request

        globals()["_FastAPIRequest"] = _Request


def _response(body: Any, status: int = 200, headers: dict[str, str] | None = None) -> Response:
    """A SCIM JSON response."""
    from starlette.responses import Response

    content = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return Response(content=content, status_code=status, media_type=SCIM_MEDIA_TYPE, headers=headers)


def _empty(status: int, headers: dict[str, str] | None = None) -> Response:
    """A response with no body, such as a 204 or a 304."""
    from starlette.responses import Response

    return Response(status_code=status, headers=headers)


def _error(exc: ScimError) -> Response:
    """The SCIM error response, with a Bearer challenge on a 401."""
    headers = {"WWW-Authenticate": 'Bearer realm="SCIM"'} if exc.status == 401 else None
    return _response(exc.as_body(), exc.status, headers)


def _split_list(value: str | None) -> list[str]:
    """A comma-separated `attributes` parameter as a list."""
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def _as_list(value: Any, name: str) -> list[str]:
    """A search body's `attributes`, given as a list or a comma-separated string."""
    if value is None:
        return []
    if isinstance(value, str):
        return _split_list(value)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return [item.strip() for item in value if item.strip()]
    raise ScimError.invalid_value(f"'{name}' must be a list of attribute names.")


def _integer(value: Any, name: str, default: int) -> int:
    """A `startIndex` or `count` parameter, refusing a non-integer with 400."""
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        raise ScimError.invalid_value(f"'{name}' must be an integer.")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ScimError.invalid_value(f"'{name}' must be an integer.") from exc


def _names(attributes: Sequence[str], name: str) -> bool:
    """Whether an `attributes` list names a top-level attribute, with or without its URN."""
    lowered = name.lower()
    for item in attributes:
        tail = item.rsplit(":", 1)[-1].lower()
        if tail.split(".", 1)[0] == lowered:
            return True
    return False


class _ListRequest:
    """The parameters of a list or `.search` request, validated."""

    def __init__(
        self,
        *,
        filter_text: str,
        start_index: Any,
        count: Any,
        attributes: list[str],
        excluded: list[str],
        default_count: int,
        max_count: int,
    ) -> None:
        """Parse the filter and clamp the page bounds."""
        self.filter = parse_filter(filter_text) if filter_text.strip() else None
        self.start_index = max(_integer(start_index, "startIndex", 1), 1)
        self.count = min(max(_integer(count, "count", default_count), 0), max_count)
        self.attributes = attributes
        self.excluded = excluded

    def query(self, resource_type: ScimResourceType) -> ScimQuery:
        """The `ScimQuery` handed to the hooks."""
        include_members = True
        if resource_type is GROUP_RESOURCE_TYPE:
            if self.attributes:
                include_members = _names(self.attributes, "members")
            elif _names(self.excluded, "members"):
                include_members = False
            if self.filter is not None and self.filter.references("members"):
                include_members = True
        return ScimQuery(
            filter=self.filter,
            start_index=self.start_index,
            count=self.count,
            include_members=include_members,
        )


def build_scim_router(
    service: ScimService,
    *,
    prefix: str = SCIM_PREFIX,
    dependencies: Sequence[Any] = (),
    default_count: int = DEFAULT_PAGE_SIZE,
) -> APIRouter:
    """The SCIM 2.0 router: `/Users`, `/Groups`, `/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`.

    Every resource route needs `Authorization: Bearer <scim token>` and acts in that token's
    tenant only. The discovery routes are public, as RFC 7644 section 4 allows, because they
    describe the server rather than any directory.

    Args:
        service: The product's `ScimService`, whose `base_url` must be this router's public
            absolute URL, such as `https://api.example.com/scim/v2`.
        prefix: Where the routes mount.
        dependencies: FastAPI dependencies for every route, such as a rate limit.
        default_count: The page size when a list names no `count`.
    """
    from fastapi import APIRouter

    from webbpulse.identity.router import run_sync

    _bind_fastapi_request()
    router = APIRouter(prefix=prefix, dependencies=list(dependencies), tags=["scim"])
    max_count = service.max_results

    async def read_body(request: Request) -> Any:
        """The JSON body, or 400 `invalidSyntax`."""
        raw = await request.body()
        if len(raw) > MAX_BODY_BYTES:
            raise ScimError(413, "The request body is too large.")
        try:
            return json.loads(raw) if raw else None
        except (ValueError, UnicodeDecodeError) as exc:
            raise ScimError.invalid_syntax("The request body is not valid JSON.") from exc

    async def handle(
        request: Request,
        work: Callable[[ScimPrincipal, Any], Response],
        *,
        with_body: bool = False,
    ) -> Response:
        """Authenticate, read the body, run the work off the loop, and answer errors as SCIM."""
        try:
            authorization = request.headers.get("authorization", "")
            principal = await run_sync(lambda: service.authenticate(authorization))
            body = await read_body(request) if with_body else None
            return await run_sync(lambda: work(principal, body))
        except ScimError as exc:
            return _error(exc)
        except Exception:
            _log.exception("SCIM request failed.", extra={"event": "scim.error", "path": request.url.path})
            return _error(ScimError(500, "The request could not be completed."))

    def projected(request: Request, resource: dict[str, Any], resource_type: ScimResourceType) -> dict[str, Any]:
        """The resource with the request's `attributes` or `excludedAttributes` applied."""
        params = request.query_params
        return project_resource(
            resource,
            resource_type,
            attributes=_split_list(params.get("attributes")),
            excluded=_split_list(params.get("excludedAttributes")),
        )

    def single(
        request: Request,
        resource: dict[str, Any],
        resource_type: ScimResourceType,
        status: int = 200,
    ) -> Response:
        """One resource with its `ETag`, and `Location` on a create."""
        meta = resource.get("meta") or {}
        headers: dict[str, str] = {}
        if meta.get("version"):
            headers["ETag"] = str(meta["version"])
        if status == 201 and meta.get("location"):
            headers["Location"] = str(meta["location"])
        return _response(projected(request, resource, resource_type), status, headers)

    def list_response(resources: list[dict[str, Any]], total: int, start_index: int) -> Response:
        """A `ListResponse`."""
        return _response(
            {
                "schemas": [LIST_RESPONSE_SCHEMA],
                "totalResults": total,
                "startIndex": start_index,
                "itemsPerPage": len(resources),
                "Resources": resources,
            }
        )

    def run_list(principal: ScimPrincipal, resource_type: ScimResourceType, request: _ListRequest) -> Response:
        """Answer a list or `.search` for users or groups."""
        query = request.query(resource_type)
        rendered: list[dict[str, Any]]
        if resource_type is USER_RESOURCE_TYPE:
            users = service.list_users(principal.tenant_id, query)
            total = users.total_results
            rendered = [service.render_user(item) for item in users.resources]
        else:
            groups = service.list_groups(principal.tenant_id, query)
            total = groups.total_results
            rendered = [service.render_group(item, include_members=query.include_members) for item in groups.resources]
        resources = [
            project_resource(item, resource_type, attributes=request.attributes, excluded=request.excluded)
            for item in rendered
        ]
        return list_response(resources, total, request.start_index)

    def from_query(request: Request) -> _ListRequest:
        """The list parameters of a GET."""
        params = request.query_params
        return _ListRequest(
            filter_text=params.get("filter", ""),
            start_index=params.get("startIndex"),
            count=params.get("count"),
            attributes=_split_list(params.get("attributes")),
            excluded=_split_list(params.get("excludedAttributes")),
            default_count=default_count,
            max_count=max_count,
        )

    def from_search(body: Any) -> _ListRequest:
        """The list parameters of a `.search` body."""
        if not isinstance(body, dict):
            raise ScimError.invalid_syntax("A search body must be an object.")
        schemas = body.get("schemas")
        if schemas is not None and SEARCH_REQUEST_SCHEMA not in (schemas if isinstance(schemas, list) else []):
            raise ScimError.invalid_syntax(f"A search body's schemas must include {SEARCH_REQUEST_SCHEMA}.")
        filter_text = body.get("filter") or ""
        if not isinstance(filter_text, str):
            raise ScimError.invalid_filter("'filter' must be a string.")
        return _ListRequest(
            filter_text=filter_text,
            start_index=body.get("startIndex"),
            count=body.get("count"),
            attributes=_as_list(body.get("attributes"), "attributes"),
            excluded=_as_list(body.get("excludedAttributes"), "excludedAttributes"),
            default_count=default_count,
            max_count=max_count,
        )

    def object_body(body: Any) -> dict[str, Any]:
        """A resource body, which must be a JSON object."""
        if not isinstance(body, dict):
            raise ScimError.invalid_syntax("The request body must be a JSON object.")
        return body

    @router.get("/ServiceProviderConfig")
    async def scim_service_provider_config() -> Any:
        """What this server supports: PATCH, filters and ETags, but not bulk, sort or passwords."""
        return _response(
            service_provider_config(
                service.base_url,
                max_results=max_count,
                documentation_uri=service.documentation_uri,
            )
        )

    @router.get("/ResourceTypes")
    async def scim_resource_types() -> Any:
        """The User and Group resource types."""
        items = [item.as_dict(service.base_url) for item in (USER_RESOURCE_TYPE, GROUP_RESOURCE_TYPE)]
        return list_response(items, len(items), 1)

    @router.get("/ResourceTypes/{name}")
    async def scim_resource_type(name: str) -> Any:
        """One resource type by name."""
        for item in (USER_RESOURCE_TYPE, GROUP_RESOURCE_TYPE):
            if item.name.lower() == name.lower():
                return _response(item.as_dict(service.base_url))
        return _error(ScimError.not_found(f"Resource type {name} not found."))

    @router.get("/Schemas")
    async def scim_schemas() -> Any:
        """The User, Enterprise User and Group schemas."""
        items = [item.as_dict(service.base_url) for item in all_schemas()]
        return list_response(items, len(items), 1)

    @router.get("/Schemas/{schema_id}")
    async def scim_schema(schema_id: str) -> Any:
        """One schema by URN."""
        found = schema_by_id(schema_id)
        if found is None:
            return _error(ScimError.not_found(f"Schema {schema_id} not found."))
        return _response(found.as_dict(service.base_url))

    @router.get("/Users")
    async def scim_list_users(request: _FastAPIRequest) -> Any:
        """List users, with `filter`, `startIndex`, `count`, `attributes` and `excludedAttributes`."""
        return await handle(request, lambda principal, _: run_list(principal, USER_RESOURCE_TYPE, from_query(request)))

    @router.post("/Users/.search")
    async def scim_search_users(request: _FastAPIRequest) -> Any:
        """List users from a `SearchRequest` body."""
        return await handle(
            request,
            lambda principal, body: run_list(principal, USER_RESOURCE_TYPE, from_search(body)),
            with_body=True,
        )

    @router.post("/Users")
    async def scim_create_user(request: _FastAPIRequest) -> Any:
        """Create a user, answering 201 with `Location`, or 409 `uniqueness` for a taken `userName`."""

        def work(principal: ScimPrincipal, body: Any) -> Response:
            user = service.create_user(principal.tenant_id, object_body(body))
            return single(request, service.render_user(user), USER_RESOURCE_TYPE, 201)

        return await handle(request, work, with_body=True)

    @router.get("/Users/{user_id}")
    async def scim_get_user(request: _FastAPIRequest, user_id: str) -> Any:
        """One user, or 304 when `If-None-Match` names its version."""

        def work(principal: ScimPrincipal, _: Any) -> Response:
            rendered = service.render_user(service.get_user(principal.tenant_id, user_id))
            return conditional(request, rendered, USER_RESOURCE_TYPE)

        return await handle(request, work)

    @router.put("/Users/{user_id}")
    async def scim_replace_user(request: _FastAPIRequest, user_id: str) -> Any:
        """Replace a user. `active: false` deactivates it."""

        def work(principal: ScimPrincipal, body: Any) -> Response:
            user = service.replace_user(
                principal.tenant_id,
                user_id,
                object_body(body),
                if_match=request.headers.get("if-match", ""),
            )
            return single(request, service.render_user(user), USER_RESOURCE_TYPE)

        return await handle(request, work, with_body=True)

    @router.patch("/Users/{user_id}")
    async def scim_patch_user(request: _FastAPIRequest, user_id: str) -> Any:
        """Patch a user and answer it. `active` replaced with false deactivates it."""

        def work(principal: ScimPrincipal, body: Any) -> Response:
            user = service.patch_user(principal.tenant_id, user_id, body, if_match=request.headers.get("if-match", ""))
            return single(request, service.render_user(user), USER_RESOURCE_TYPE)

        return await handle(request, work, with_body=True)

    @router.delete("/Users/{user_id}")
    async def scim_delete_user(request: _FastAPIRequest, user_id: str) -> Any:
        """Delete a user, answering 204."""

        def work(principal: ScimPrincipal, _: Any) -> Response:
            service.delete_user(principal.tenant_id, user_id, if_match=request.headers.get("if-match", ""))
            return _empty(204)

        return await handle(request, work)

    @router.get("/Groups")
    async def scim_list_groups(request: _FastAPIRequest) -> Any:
        """List groups. `excludedAttributes=members` skips loading members unless the filter names them."""
        return await handle(
            request,
            lambda principal, _: run_list(principal, GROUP_RESOURCE_TYPE, from_query(request)),
        )

    @router.post("/Groups/.search")
    async def scim_search_groups(request: _FastAPIRequest) -> Any:
        """List groups from a `SearchRequest` body."""
        return await handle(
            request,
            lambda principal, body: run_list(principal, GROUP_RESOURCE_TYPE, from_search(body)),
            with_body=True,
        )

    @router.post("/Groups")
    async def scim_create_group(request: _FastAPIRequest) -> Any:
        """Create a group with its members, answering 201 with `Location`."""

        def work(principal: ScimPrincipal, body: Any) -> Response:
            group = service.create_group(principal.tenant_id, object_body(body))
            return single(request, service.render_group(group), GROUP_RESOURCE_TYPE, 201)

        return await handle(request, work, with_body=True)

    @router.get("/Groups/{group_id}")
    async def scim_get_group(request: _FastAPIRequest, group_id: str) -> Any:
        """One group, members left unloaded when `excludedAttributes=members`."""

        def work(principal: ScimPrincipal, _: Any) -> Response:
            params = request.query_params
            attributes = _split_list(params.get("attributes"))
            excluded = _split_list(params.get("excludedAttributes"))
            include_members = _names(attributes, "members") if attributes else not _names(excluded, "members")
            group = service.get_group(principal.tenant_id, group_id, include_members=include_members)
            rendered = service.render_group(group, include_members=include_members)
            return conditional(request, rendered, GROUP_RESOURCE_TYPE)

        return await handle(request, work)

    @router.put("/Groups/{group_id}")
    async def scim_replace_group(request: _FastAPIRequest, group_id: str) -> Any:
        """Replace a group, members included."""

        def work(principal: ScimPrincipal, body: Any) -> Response:
            group = service.replace_group(
                principal.tenant_id,
                group_id,
                object_body(body),
                if_match=request.headers.get("if-match", ""),
            )
            return single(request, service.render_group(group), GROUP_RESOURCE_TYPE)

        return await handle(request, work, with_body=True)

    @router.patch("/Groups/{group_id}")
    async def scim_patch_group(request: _FastAPIRequest, group_id: str) -> Any:
        """Patch a group, answering 204. Member adds and removes never load the whole group."""

        def work(principal: ScimPrincipal, body: Any) -> Response:
            service.patch_group(principal.tenant_id, group_id, body, if_match=request.headers.get("if-match", ""))
            return _empty(204)

        return await handle(request, work, with_body=True)

    @router.delete("/Groups/{group_id}")
    async def scim_delete_group(request: _FastAPIRequest, group_id: str) -> Any:
        """Delete a group, answering 204."""

        def work(principal: ScimPrincipal, _: Any) -> Response:
            service.delete_group(principal.tenant_id, group_id, if_match=request.headers.get("if-match", ""))
            return _empty(204)

        return await handle(request, work)

    def conditional(request: Request, rendered: dict[str, Any], resource_type: ScimResourceType) -> Response:
        """A 304 when `If-None-Match` names the current version, else the resource."""
        version = str((rendered.get("meta") or {}).get("version", ""))
        if_none_match = request.headers.get("if-none-match", "")
        if version and if_none_match and etag_matches(if_none_match, version):
            return _empty(304, {"ETag": version})
        return single(request, rendered, resource_type)

    return router
