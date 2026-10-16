"""RFC 7644 section 3.5.2 PATCH, applied to a rendered resource.

Applying operations to the JSON form, then parsing the result back, makes every attribute
patchable by the same code. The provider quirks it accepts:

- Entra's capitalised `Add`, `Replace` and `Remove`, and its `"True"` and `"False"` strings.
- A path-less `replace` whose value keys are themselves paths, such as `name.givenName` or
  an enterprise extension URN, as Entra sends, and `id` inside that value, as Okta sends.
- `add` or `replace` on `emails[type eq "work"].value` when no work email exists yet, which
  creates the element.
- `remove` on `members` with a list of members as the value, as Entra sends.
- `remove` with a filter that matches nothing, which succeeds.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal, cast

from webbpulse.identity.scim.errors import ScimError
from webbpulse.identity.scim.filters import And, Compare, FilterNode, PatchPath, parse_patch_path
from webbpulse.identity.scim.resources import normalise_value
from webbpulse.identity.scim.schema import (
    COMMON_ATTRIBUTES,
    PATCH_OP_SCHEMA,
    ScimAttribute,
    ScimResourceType,
)

__all__ = [
    "MAX_PATCH_OPERATIONS",
    "PatchOperation",
    "apply_patch",
    "member_changes",
    "parse_patch_request",
]

MAX_PATCH_OPERATIONS: Final = 1000

type PatchOp = Literal["add", "replace", "remove"]

_MISSING: Final = object()


@dataclass(frozen=True, slots=True)
class PatchOperation:
    """One operation of a PATCH request, its `op` folded to lower case."""

    op: PatchOp
    path: str = ""
    value: Any = None
    has_value: bool = False


def _key(container: Mapping[str, Any], name: str) -> str | None:
    """The key of a mapping that matches a name in any case."""
    lowered = name.lower()
    for key in container:
        if key.lower() == lowered:
            return key
    return None


def parse_patch_request(body: Any) -> list[PatchOperation]:
    """The operations of a `PatchOp` body, refusing a malformed one with 400 `invalidSyntax`.

    The `schemas` member is not required, because some clients leave it out.
    """
    if not isinstance(body, Mapping):
        raise ScimError.invalid_syntax("A PATCH body must be an object.")
    schemas = body.get("schemas")
    if schemas is not None and (
        not isinstance(schemas, list) or not any(str(item).lower() == PATCH_OP_SCHEMA.lower() for item in schemas)
    ):
        raise ScimError.invalid_syntax(f"A PATCH body's schemas must include {PATCH_OP_SCHEMA}.")
    key = _key(body, "Operations")
    raw = body.get(key) if key else None
    if not isinstance(raw, list) or not raw:
        raise ScimError.invalid_syntax("A PATCH body needs a non-empty 'Operations' list.")
    if len(raw) > MAX_PATCH_OPERATIONS:
        raise ScimError(413, "Too many PATCH operations.", scim_type="tooMany")
    operations: list[PatchOperation] = []
    for item in raw:
        if not isinstance(item, Mapping):
            raise ScimError.invalid_syntax("Each PATCH operation must be an object.")
        op_key = _key(item, "op")
        op = str(item.get(op_key, "") if op_key else "").strip().lower()
        if op not in {"add", "replace", "remove"}:
            raise ScimError.invalid_syntax(f"Unknown PATCH op: {op or '(none)'}")
        path_key = _key(item, "path")
        path = item.get(path_key) if path_key else None
        if path is not None and not isinstance(path, str):
            raise ScimError.invalid_path("A PATCH path must be a string.")
        value_key = _key(item, "value")
        has_value = value_key is not None
        value = item.get(value_key) if value_key else None
        if op in {"add", "replace"} and not has_value:
            raise ScimError.invalid_syntax(f"A PATCH '{op}' needs a value.")
        if op == "remove" and not path:
            raise ScimError.no_target("A PATCH 'remove' needs a path.")
        operations.append(PatchOperation(op=cast(PatchOp, op), path=path or "", value=value, has_value=has_value))
    return operations


def _definition(resource_type: ScimResourceType, path: PatchPath) -> ScimAttribute | None:
    """The definition of the attribute a path names, `externalId` included."""
    schema = resource_type.schema_for(path.urn) if path.urn else resource_type.schema
    found = schema.attribute(path.attribute) if schema is not None else None
    if found is None and not path.urn:
        for common in COMMON_ATTRIBUTES:
            if common.name.lower() == path.attribute.lower():
                return common
    return found


def _eq_pairs(node: FilterNode) -> dict[str, Any] | None:
    """The `attr eq value` pairs of a filter made only of them joined by `and`, else `None`."""
    if isinstance(node, Compare) and node.op == "eq" and not node.path.sub and not node.path.urn:
        return {node.path.attribute: node.value}
    if isinstance(node, And):
        left = _eq_pairs(node.left)
        right = _eq_pairs(node.right)
        if left is None or right is None:
            return None
        return {**left, **right}
    return None


class _Patcher:
    """Applies operations one at a time to a deep copy of a resource."""

    def __init__(self, resource: Mapping[str, Any], resource_type: ScimResourceType) -> None:
        """Copy the resource, so a failed operation leaves the caller's copy untouched."""
        self.doc: dict[str, Any] = copy.deepcopy(dict(resource))
        self.resource_type = resource_type

    def apply(self, operation: PatchOperation) -> None:
        """Apply one operation, path-less ones key by key."""
        if not operation.path:
            if not isinstance(operation.value, Mapping):
                raise ScimError.invalid_value("A PATCH without a path needs an object value.")
            for key, value in operation.value.items():
                if key.lower() == "schemas":
                    continue
                extension = self.resource_type.extension(key)
                if extension is not None and isinstance(value, Mapping):
                    for inner_key, inner_value in value.items():
                        self._apply_path(operation.op, f"{extension.id}:{inner_key}", inner_value, lenient=True)
                    continue
                self._apply_path(operation.op, key, value, lenient=True)
            return
        self._apply_path(
            operation.op,
            operation.path,
            operation.value if operation.has_value else _MISSING,
            lenient=False,
        )

    def _container(self, urn: str, *, create: bool) -> dict[str, Any] | None:
        """The object an attribute lives in: the resource, or its extension object."""
        if not urn:
            return self.doc
        key = _key(self.doc, urn)
        existing = self.doc.get(key) if key is not None else None
        if isinstance(existing, dict):
            holder: dict[str, Any] = existing
            return holder
        if not create:
            return None
        fresh: dict[str, Any] = {}
        self.doc[key or urn] = fresh
        return fresh

    def _apply_path(self, op: PatchOp, raw_path: str, value: Any, *, lenient: bool) -> None:
        """Apply one operation to one parsed path."""
        try:
            path = parse_patch_path(raw_path, self.resource_type)
        except ScimError:
            if lenient:
                return
            raise
        if not path.attribute:
            self._apply_extension(op, path.urn, value)
            return
        definition = _definition(self.resource_type, path)
        if definition is None:
            return
        if definition.mutability == "readOnly":
            if lenient:
                return
            raise ScimError.mutability(f"'{definition.name}' is read-only.")
        if op == "remove":
            self._remove(path, definition, value)
        else:
            if value is _MISSING:
                raise ScimError.invalid_syntax(f"A PATCH '{op}' needs a value.")
            self._set(op, path, definition, value)

    def _apply_extension(self, op: PatchOp, urn: str, value: Any) -> None:
        """A path naming a whole extension: merge its attributes, or remove it."""
        if op == "remove":
            key = _key(self.doc, urn)
            if key is not None:
                del self.doc[key]
            return
        if not isinstance(value, Mapping):
            raise ScimError.invalid_value(f"'{urn}' must be an object.")
        for inner_key, inner_value in value.items():
            self._apply_path(op, f"{urn}:{inner_key}", inner_value, lenient=True)

    def _remove(self, path: PatchPath, definition: ScimAttribute, value: Any) -> None:
        """Remove an attribute, a sub-attribute, or the elements a filter or value list selects."""
        if definition.required and not path.sub and path.value_filter is None:
            raise ScimError.mutability(f"'{definition.name}' is required and cannot be removed.")
        container = self._container(path.urn, create=False)
        if container is None:
            return
        key = _key(container, definition.name)
        if key is None:
            return
        current = container[key]
        if path.value_filter is not None:
            if not isinstance(current, list):
                return
            matched = [
                isinstance(item, Mapping)
                and path.value_filter.matches_element(item, self.resource_type, definition.name)
                for item in current
            ]
            if path.sub:
                for item, hit in zip(current, matched, strict=True):
                    sub_key = _key(item, path.sub) if hit else None
                    if sub_key is not None:
                        del item[sub_key]
            else:
                container[key] = [item for item, hit in zip(current, matched, strict=True) if not hit]
            return
        if path.sub:
            for item in current if isinstance(current, list) else [current]:
                if isinstance(item, dict):
                    sub_key = _key(item, path.sub)
                    if sub_key is not None:
                        del item[sub_key]
            return
        if definition.multi_valued and isinstance(current, list) and value is not _MISSING and value is not None:
            targets = value if isinstance(value, list) else [value]
            doomed = {_element_value(item) for item in targets} - {None}
            container[key] = [item for item in current if _element_value(item) not in doomed]
            return
        del container[key]

    def _set(self, op: PatchOp, path: PatchPath, definition: ScimAttribute, value: Any) -> None:
        """`add` or `replace` at an attribute, sub-attribute or filtered element."""
        container = self._container(path.urn, create=True)
        assert container is not None
        key = _key(container, definition.name) or definition.name
        if path.value_filter is not None:
            self._set_filtered(container, key, path, definition, value)
            return
        if path.sub:
            sub_definition = definition.sub(path.sub)
            if sub_definition is None:
                return
            normalised = normalise_value(sub_definition, value)
            current = container.get(key)
            if definition.multi_valued:
                for item in current if isinstance(current, list) else []:
                    if isinstance(item, dict):
                        item[_key(item, sub_definition.name) or sub_definition.name] = normalised
                return
            holder = current if isinstance(current, dict) else {}
            holder[_key(holder, sub_definition.name) or sub_definition.name] = normalised
            container[key] = holder
            return
        normalised = normalise_value(definition, value)
        current = container.get(key)
        if definition.multi_valued:
            incoming = normalised if isinstance(normalised, list) else [normalised]
            if op == "replace" or not isinstance(current, list):
                container[key] = _dedupe([], incoming)
            else:
                container[key] = _dedupe(current, incoming)
            return
        if definition.type == "complex" and isinstance(current, dict) and isinstance(normalised, dict):
            current.update(normalised)
            return
        container[key] = normalised

    def _set_filtered(
        self,
        container: dict[str, Any],
        key: str,
        path: PatchPath,
        definition: ScimAttribute,
        value: Any,
    ) -> None:
        """Set a sub-attribute on, or merge a value into, the elements a filter selects.

        When nothing matches and the filter is only `eq` comparisons, a new element carrying
        them is added, which is how Entra writes a first work email or phone number.
        """
        assert path.value_filter is not None
        current = container.get(key)
        elements = current if isinstance(current, list) else []
        matched = [
            item
            for item in elements
            if isinstance(item, dict) and path.value_filter.matches_element(item, self.resource_type, definition.name)
        ]
        if not matched:
            pairs = _eq_pairs(path.value_filter.root)
            if pairs is None or not definition.multi_valued:
                raise ScimError.no_target(f"No '{definition.name}' element matches the PATCH filter.")
            seed: dict[str, Any] = {}
            for name, literal in pairs.items():
                sub_definition = definition.sub(name)
                if sub_definition is not None:
                    seed[sub_definition.name] = literal
            elements = [*elements, seed]
            container[key] = elements
            matched = [seed]
        if path.sub:
            sub_definition = definition.sub(path.sub)
            if sub_definition is None:
                return
            normalised = normalise_value(sub_definition, value)
            for item in matched:
                item[_key(item, sub_definition.name) or sub_definition.name] = normalised
            return
        if not isinstance(value, Mapping):
            raise ScimError.invalid_value(f"'{definition.name}' elements must be objects.")
        element = ScimAttribute(definition.name, type="complex", sub_attributes=definition.sub_attributes)
        merged = normalise_value(element, value)
        for item in matched:
            item.update(merged)


def _element_value(item: Any) -> Any:
    """The identity of a multi-valued element: its `value`, or the item itself when simple."""
    if isinstance(item, Mapping):
        key = _key(item, "value")
        found = item.get(key) if key else None
        return found if isinstance(found, str | int | float | bool) else None
    return item if isinstance(item, str | int | float | bool) else None


def _dedupe(current: Sequence[Any], incoming: Sequence[Any]) -> list[Any]:
    """Append incoming elements, replacing any with the same `value`, and keep one primary."""
    result = list(current)
    for item in incoming:
        identity = _element_value(item)
        if identity is not None:
            result = [existing for existing in result if _element_value(existing) != identity]
        if isinstance(item, Mapping) and item.get("primary") is True:
            for existing in result:
                if isinstance(existing, dict) and existing.get("primary") is True:
                    existing["primary"] = False
        result.append(item)
    return result


def apply_patch(
    resource: Mapping[str, Any],
    operations: Sequence[PatchOperation],
    resource_type: ScimResourceType,
) -> dict[str, Any]:
    """The resource with every operation applied in order, atomically: any refusal applies none."""
    patcher = _Patcher(resource, resource_type)
    for operation in operations:
        patcher.apply(operation)
    return patcher.doc


def member_changes(
    operations: Sequence[PatchOperation],
    resource_type: ScimResourceType,
) -> tuple[list[Any], list[str]] | None:
    """The member elements added and the member ids removed, when every operation is only that.

    `None` when any operation touches anything else, replaces `members` wholesale, or
    removes members through a filter other than `value eq "<id>"`, so the caller falls back to
    loading the whole group.
    """
    added: list[Any] = []
    removed: list[str] = []
    for operation in operations:
        if not operation.path:
            return None
        try:
            path = parse_patch_path(operation.path, resource_type)
        except ScimError:
            return None
        if path.urn or path.attribute.lower() != "members" or path.sub:
            return None
        if operation.op == "add" and path.value_filter is None:
            values = operation.value if isinstance(operation.value, list) else [operation.value]
            added.extend(values)
            continue
        if operation.op != "remove":
            return None
        if path.value_filter is not None:
            pairs = _eq_pairs(path.value_filter.root)
            if pairs is None or len(pairs) != 1:
                return None
            name, literal = next(iter(pairs.items()))
            if name.lower() != "value" or not isinstance(literal, str):
                return None
            removed.append(literal)
            continue
        if not operation.has_value or operation.value is None:
            return None
        values = operation.value if isinstance(operation.value, list) else [operation.value]
        for item in values:
            identity = _element_value(item)
            if not isinstance(identity, str):
                return None
            removed.append(identity)
    return added, removed
