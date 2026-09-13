"""Live API Gateway routes and the precedence matcher that predicts which one wins.

The matcher is `CarModPicker/scripts/expected_route_key.py` ported whole. That script
replaced a string rule that went stale on every explicit-route promotion, so the
expectation is resolved the way the gateway resolves it: a literal segment beats a
`{var}` segment, a `{var}` segment beats a greedy `{proxy+}`, and a method-specific key
beats `ANY`. Routes are read live from `apigatewayv2 get-routes` rather than parsed out of
Terraform, so the expectation describes the deployed stage and not a plan.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

__all__ = [
    "GREEDY",
    "LITERAL",
    "VARIABLE",
    "Operation",
    "Route",
    "fetch_routes",
    "matching_route",
    "operations_from_openapi",
    "resolve",
    "route_key_is_expressible",
]

LITERAL = 2
VARIABLE = 1
GREEDY = 0

_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")


@dataclass(frozen=True)
class Route:
    """One live route on the HTTP API.

    `target` is the integration target string API Gateway reports, of the form
    `integrations/<id>`, and `authorizer_id` is empty when the route carries no authorizer.
    """

    route_key: str
    target: str
    authorizer_id: str
    authorization_type: str

    @property
    def method(self) -> str:
        """The route key's method, which is `ANY` for a catch-all key."""
        return self.route_key.partition(" ")[0]

    @property
    def path(self) -> str:
        """The route key's path half."""
        return self.route_key.partition(" ")[2]

    @property
    def has_authorizer(self) -> bool:
        """Whether the gateway will run an authorizer before this route's integration."""
        return bool(self.authorizer_id) or self.authorization_type in ("JWT", "CUSTOM", "AWS_IAM")


@dataclass(frozen=True)
class Operation:
    """One OpenAPI operation, reduced to what the route assertions need."""

    method: str
    path: str
    operation_id: str
    requires_auth: bool
    expected_statuses: tuple[int, ...]

    @property
    def path_parameters(self) -> tuple[str, ...]:
        """Every `{name}` placeholder in the path, in order."""
        return tuple(
            segment[1:-1]
            for segment in self.path.strip("/").split("/")
            if segment.startswith("{") and segment.endswith("}")
        )

    @property
    def is_bare_mutation(self) -> bool:
        """Whether calling this operation as a real user would change that user's state.

        A non-GET operation with no path parameter has nothing to point at an absent id, so
        an authenticated probe of it executes for real: `POST /api/auth/logout` signs the
        durable user out mid-run. Such operations are probed anonymously only.
        """
        return self.method not in ("GET", "HEAD", "OPTIONS") and not self.path_parameters

    @property
    def label(self) -> str:
        """A stable id for pytest parametrisation, so junit output reads well."""
        return f"{self.method} {self.path}"


def _segments(path: str) -> list[str]:
    """One path split into segments, preserving a trailing slash as a final empty segment.

    `"/"` alone is the root and yields no segments; `"/a/"` yields `["a", ""]`, so a key
    for `/a` cannot match it.
    """
    trimmed = path.removeprefix("/")
    if not trimmed:
        return []
    return trimmed.split("/")


def _segment_score(segment: str) -> int:
    """The precedence class of one route key segment."""
    if not segment:
        return LITERAL
    if segment == "{proxy+}":
        return GREEDY
    if segment.startswith("{") and segment.endswith("}"):
        return VARIABLE
    return LITERAL


def _match_score(key_path: str, path: str) -> tuple[int, tuple[int, ...]] | None:
    """Precedence score for a key against a path, or None when it cannot match.

    Higher sorts better. The score is the per-segment kind from left to right, so a literal
    beats a `{var}` at the first segment they differ on, which is the order API Gateway
    resolves in.

    Only the leading slash is stripped, never the trailing one. Stripping both would make
    `/api/build-lists/` and `/api/build-lists` the same string, and the whole reason this
    matcher exists is that the gateway treats them as different: it neither normalises an
    inbound trailing slash nor accepts a key carrying one, so a slashed path falls through
    to a catch-all with no authorizer claims. A trailing slash therefore yields a final
    empty segment, which no literal and no `{var}` segment matches.
    """
    key_segments = _segments(key_path)
    path_segments = _segments(path)

    score: list[int] = []
    for index, key_segment in enumerate(key_segments):
        if key_segment == "{proxy+}":
            if index >= len(path_segments):
                return None
            score.append(GREEDY)
            return (len(score), tuple(score))
        if index >= len(path_segments):
            return None
        kind = _segment_score(key_segment)
        if kind == LITERAL and key_segment != path_segments[index]:
            return None
        score.append(kind)

    if len(key_segments) != len(path_segments):
        return None
    return (len(score), tuple(score))


def resolve(path: str, method: str, route_keys: Iterable[str]) -> str:
    """The route key the gateway resolves `method path` to, or "" for none.

    A path ending in a slash resolves to nothing under any key that does not itself end in
    a slash, which is the trailing-slash trap: the gateway neither normalises an inbound
    slash nor accepts a key carrying one, so the request falls through to a `{proxy+}`
    catch-all with no authorizer claims, or to the gateway's own 404.
    """
    best_key = ""
    best_score: tuple[tuple[int, tuple[int, ...]], bool] | None = None

    for key in route_keys:
        key_method, _, key_path = key.partition(" ")
        if key_method != "ANY" and key_method != method:
            continue

        score = _match_score(key_path, path)
        if score is None:
            continue

        ranked = (score, key_method != "ANY")
        if best_score is None or ranked > best_score:
            best_score = ranked
            best_key = key

    return best_key


def route_key_is_expressible(route_key: str) -> bool:
    """Whether a route key is legal for an HTTP API.

    A path part is a whole variable or a whole literal, never a variable embedded in a
    literal, so `GET /sitemap-{name}.xml` is refused at apply time after a green plan. A
    key whose path ends in a slash is equally unusable, since the gateway will never match
    an inbound request to it.
    """
    method, _, path = route_key.partition(" ")
    if not path.startswith("/"):
        return False
    if method != "ANY" and method not in _METHODS and method != "$default":
        return False
    if path != "/" and path.endswith("/"):
        return False
    for segment in path.strip("/").split("/"):
        if not segment:
            continue
        if "{" not in segment and "}" not in segment:
            continue
        if not (segment.startswith("{") and segment.endswith("}")):
            return False
        inner = segment[1:-1].removesuffix("+")
        if not inner or "{" in inner or "}" in inner:
            return False
    return True


def fetch_routes(client: Any, api_id: str) -> tuple[Route, ...]:
    """Every live route on the API, read through `apigatewayv2 get-routes`.

    Paginated by hand rather than through a paginator, because botocore ships no paginator
    for this operation and a partial route list would silently weaken every assertion
    derived from it.
    """
    routes: list[Route] = []
    next_token: str | None = None
    while True:
        kwargs: dict[str, Any] = {"ApiId": api_id, "MaxResults": "100"}
        if next_token:
            kwargs["NextToken"] = next_token
        response = client.get_routes(**kwargs)
        for item in response.get("Items", []):
            routes.append(
                Route(
                    route_key=str(item.get("RouteKey", "")),
                    target=str(item.get("Target", "")),
                    authorizer_id=str(item.get("AuthorizerId", "")),
                    authorization_type=str(item.get("AuthorizationType", "NONE")),
                )
            )
        next_token = response.get("NextToken")
        if not next_token:
            break
    return tuple(sorted(routes, key=lambda route: route.route_key))


def _operation_requires_auth(operation: Mapping[str, Any], document: Mapping[str, Any]) -> bool:
    """Whether an operation declares a security requirement, falling back to the document's."""
    security = operation.get("security")
    if security is None:
        security = document.get("security", [])
    if not isinstance(security, list):
        return False
    return any(isinstance(entry, dict) and entry for entry in security)


def _expected_statuses(operation: Mapping[str, Any]) -> tuple[int, ...]:
    """The numeric status codes the operation's `responses` table declares."""
    responses = operation.get("responses", {})
    if not isinstance(responses, dict):
        return ()
    statuses: list[int] = []
    for code in responses:
        try:
            statuses.append(int(code))
        except (TypeError, ValueError):
            continue
    return tuple(sorted(statuses))


def operations_from_openapi(document: Mapping[str, Any]) -> tuple[Operation, ...]:
    """Every operation in an OpenAPI document, as `Operation` records.

    The document comes from the product's own app factory, so it describes exactly the
    commit that was deployed. `servers` is not consulted: the API base URL is configuration,
    and a document that carries a server prefix its gateway does not would make every
    coverage assertion agree with itself and with nothing else.
    """
    operations: list[Operation] = []
    paths = document.get("paths", {})
    if not isinstance(paths, dict):
        return ()
    for path, item in sorted(paths.items()):
        if not isinstance(item, dict):
            continue
        for method, operation in sorted(item.items()):
            upper = method.upper()
            if upper not in _METHODS or not isinstance(operation, dict):
                continue
            operations.append(
                Operation(
                    method=upper,
                    path=str(path),
                    operation_id=str(operation.get("operationId", f"{upper} {path}")),
                    requires_auth=_operation_requires_auth(operation, document),
                    expected_statuses=_expected_statuses(operation),
                )
            )
    return tuple(operations)


def matching_route(operation: Operation, routes: Sequence[Route]) -> Route | None:
    """The live route an operation's path would resolve to, under gateway precedence.

    The operation's `{name}` placeholders are filled with a literal sample so a `{var}`
    route key matches them the way a real request would. A path that ends in a slash is
    passed through unchanged, so it resolves to nothing and the caller reports the failure
    rather than this quietly normalising it away.
    """
    sample = _sample_path(operation.path)
    by_key = {route.route_key: route for route in routes}
    key = resolve(sample, operation.method, by_key)
    return by_key.get(key)


def _sample_path(path: str) -> str:
    """A concrete path for an operation template, with placeholders filled in.

    Trailing slashes survive, because a slashed path is exactly the case that must fail.
    """
    segments = path.strip("/").split("/")
    filled = ["e2e-sample" if segment.startswith("{") and segment.endswith("}") else segment for segment in segments]
    joined = "/" + "/".join(segment for segment in filled if segment)
    if path.endswith("/") and path != "/":
        joined += "/"
    return joined
