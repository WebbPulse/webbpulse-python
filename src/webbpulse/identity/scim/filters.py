"""The RFC 7644 section 3.4.2.2 filter language, and the PATCH path grammar built on it.

`parse_filter` turns a `filter` query parameter into a tree that evaluates against a
rendered resource, so a product with a small directory can filter in memory, while
`ScimFilter.equality` hands a product the one `userName eq "..."` shape it should answer
with a point lookup.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from webbpulse.identity.scim.errors import ScimError
from webbpulse.identity.scim.schema import (
    COMMON_ATTRIBUTES,
    GROUP_SCHEMA,
    USER_SCHEMA,
    ScimAttribute,
    ScimResourceType,
)

__all__ = [
    "COMPARE_OPERATORS",
    "MAX_FILTER_DEPTH",
    "MAX_FILTER_LENGTH",
    "And",
    "AttrPath",
    "Compare",
    "FilterNode",
    "Not",
    "Or",
    "PatchPath",
    "ScimFilter",
    "ValuePath",
    "parse_attr_path",
    "parse_filter",
    "parse_patch_path",
]

COMPARE_OPERATORS: Final = frozenset({"eq", "ne", "co", "sw", "ew", "gt", "lt", "ge", "le"})
_ORDERING: Final = frozenset({"gt", "lt", "ge", "le"})

MAX_FILTER_LENGTH: Final = 4096
MAX_FILTER_DEPTH: Final = 32

_TOKEN: Final = re.compile(
    r"""\s*(?:
        (?P<paren>[()\[\]])
      | (?P<string>"(?:[^"\\]|\\.)*")
      | (?P<word>[A-Za-z0-9_$.:\-+]+)
    )""",
    re.VERBOSE,
)
_NUMBER: Final = re.compile(r"-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?")
_ATTR_NAME: Final = re.compile(r"\$?[A-Za-z][A-Za-z0-9_$\-]*")


@dataclass(frozen=True, slots=True)
class AttrPath:
    """An attribute path: an optional schema URN, an attribute and an optional sub-attribute."""

    urn: str
    attribute: str
    sub: str = ""

    def __str__(self) -> str:
        """The path as written, URN prefix included when one was given."""
        dotted = f"{self.attribute}.{self.sub}" if self.sub else self.attribute
        return f"{self.urn}:{dotted}" if self.urn else dotted


@dataclass(frozen=True, slots=True)
class Compare:
    """`attrPath op value`, or `attrPath pr` with `op="pr"` and no value."""

    path: AttrPath
    op: str
    value: Any = None


@dataclass(frozen=True, slots=True)
class And:
    """Both sides match."""

    left: FilterNode
    right: FilterNode


@dataclass(frozen=True, slots=True)
class Or:
    """Either side matches."""

    left: FilterNode
    right: FilterNode


@dataclass(frozen=True, slots=True)
class Not:
    """The inner filter does not match."""

    inner: FilterNode


@dataclass(frozen=True, slots=True)
class ValuePath:
    """`attr[filter]`: some element of a multi-valued attribute matches the inner filter."""

    path: AttrPath
    inner: FilterNode


type FilterNode = Compare | And | Or | Not | ValuePath


def parse_attr_path(text: str) -> AttrPath:
    """Split `urn:...:attr.sub`, `attr.sub` or `attr` into its parts, refusing anything else."""
    urn = ""
    rest = text
    if text.lower().startswith("urn:"):
        urn, _, rest = text.rpartition(":")
        if not urn or not rest:
            raise ScimError.invalid_filter(f"Invalid attribute path: {text}")
    attribute, _, sub = rest.partition(".")
    if not _ATTR_NAME.fullmatch(attribute) or (sub and not _ATTR_NAME.fullmatch(sub)):
        raise ScimError.invalid_filter(f"Invalid attribute path: {text}")
    return AttrPath(urn=urn, attribute=attribute, sub=sub)


class _Parser:
    """A recursive descent parser over the tokens of one filter: `or` < `and` < `not`."""

    def __init__(self, text: str) -> None:
        """Tokenize the whole filter up front, refusing any character outside the grammar."""
        self._tokens: list[tuple[str, str]] = []
        position = 0
        while position < len(text):
            if text[position:].strip() == "":
                break
            match = _TOKEN.match(text, position)
            if match is None or match.end() == position:
                raise ScimError.invalid_filter(f"Unexpected character at position {position}.")
            kind = match.lastgroup or ""
            self._tokens.append((kind, match.group(kind)))
            position = match.end()
        self._index = 0
        self._depth = 0

    def _peek(self) -> tuple[str, str] | None:
        """The next token, or `None` at the end."""
        return self._tokens[self._index] if self._index < len(self._tokens) else None

    def _next(self) -> tuple[str, str]:
        """Consume the next token, refusing a filter that ends early."""
        token = self._peek()
        if token is None:
            raise ScimError.invalid_filter("The filter ended unexpectedly.")
        self._index += 1
        return token

    def _expect(self, value: str) -> None:
        """Consume a bracket, refusing anything else."""
        kind, text = self._next()
        if kind != "paren" or text != value:
            raise ScimError.invalid_filter(f"Expected '{value}'.")

    def _keyword(self, *words: str) -> str | None:
        """Consume and return the next token when it is one of these keywords."""
        token = self._peek()
        if token is not None and token[0] == "word" and token[1].lower() in words:
            self._index += 1
            return token[1].lower()
        return None

    def parse(self) -> FilterNode:
        """The whole filter, refusing trailing tokens."""
        node = self._or()
        if self._peek() is not None:
            raise ScimError.invalid_filter("Unexpected text after the filter.")
        return node

    def _or(self) -> FilterNode:
        """`and` expressions joined by `or`."""
        node = self._and()
        while self._keyword("or"):
            node = Or(node, self._and())
        return node

    def _and(self) -> FilterNode:
        """Unary expressions joined by `and`."""
        node = self._unary()
        while self._keyword("and"):
            node = And(node, self._unary())
        return node

    def _unary(self) -> FilterNode:
        """`not (...)`, a parenthesised filter, a value path or an attribute expression."""
        self._depth += 1
        if self._depth > MAX_FILTER_DEPTH:
            raise ScimError.invalid_filter("The filter is nested too deeply.")
        try:
            if self._keyword("not"):
                self._expect("(")
                inner = self._or()
                self._expect(")")
                return Not(inner)
            token = self._peek()
            if token == ("paren", "("):
                self._index += 1
                inner = self._or()
                self._expect(")")
                return inner
            return self._attribute_expression()
        finally:
            self._depth -= 1

    def _attribute_expression(self) -> FilterNode:
        """`attr pr`, `attr op value`, or `attr[filter]`."""
        kind, text = self._next()
        if kind != "word":
            raise ScimError.invalid_filter("Expected an attribute name.")
        path = parse_attr_path(text)
        if self._peek() == ("paren", "["):
            self._index += 1
            inner = self._or()
            self._expect("]")
            return ValuePath(path, inner)
        op_kind, op = self._next()
        op = op.lower()
        if op_kind != "word" or (op != "pr" and op not in COMPARE_OPERATORS):
            raise ScimError.invalid_filter(f"Unknown operator: {op}")
        if op == "pr":
            return Compare(path, "pr")
        value = self._value()
        if op in _ORDERING and (value is None or isinstance(value, bool)):
            raise ScimError.invalid_filter(f"'{op}' cannot compare a boolean or null.")
        return Compare(path, op, value)

    def _value(self) -> Any:
        """A JSON string, number, `true`, `false` or `null`."""
        kind, text = self._next()
        if kind == "string":
            try:
                return json.loads(text)
            except ValueError as exc:
                raise ScimError.invalid_filter("Invalid string literal.") from exc
        if kind == "word":
            lowered = text.lower()
            if lowered in {"true", "false"}:
                return lowered == "true"
            if lowered == "null":
                return None
            if _NUMBER.fullmatch(text):
                return float(text) if any(char in text for char in ".eE") else int(text)
        raise ScimError.invalid_filter(f"Invalid comparison value: {text}")


def _child(container: Mapping[str, Any], name: str) -> Any:
    """A mapping's value for a key in any case, or `None`."""
    if name in container:
        return container[name]
    lowered = name.lower()
    for key, value in container.items():
        if key.lower() == lowered:
            return value
    return None


def _definition(resource_type: ScimResourceType | None, path: AttrPath, parent: str = "") -> ScimAttribute | None:
    """The definition of the attribute a path names, for its case exactness."""
    if resource_type is None:
        return None
    if parent:
        outer = _definition(resource_type, AttrPath(path.urn, parent))
        return outer.sub(path.attribute) if outer is not None else None
    schema = resource_type.schema_for(path.urn) if path.urn else resource_type.schema
    found: ScimAttribute | None = None
    if schema is not None:
        found = schema.attribute(path.attribute)
    if found is None and not path.urn:
        for common in COMMON_ATTRIBUTES:
            if common.name.lower() == path.attribute.lower():
                found = common
    if found is not None and path.sub:
        return found.sub(path.sub)
    return found


def _resolve(resource: Mapping[str, Any], path: AttrPath, resource_type: ScimResourceType | None) -> list[Any]:
    """Every value a path reaches in a resource, flattening multi-valued attributes."""
    container: Any = resource
    if path.urn and resource_type is not None and resource_type.extension(path.urn) is not None:
        container = _child(resource, path.urn)
        if not isinstance(container, Mapping):
            return []
    value = _child(container, path.attribute)
    items = list(value) if isinstance(value, list) else [value]
    values: list[Any] = []
    for item in items:
        if item is None:
            continue
        if isinstance(item, Mapping):
            inner = _child(item, path.sub or "value")
            if inner is not None:
                values.append(inner)
        elif not path.sub:
            values.append(item)
    return values


def _comparable(value: Any, case_exact: bool) -> Any:
    """A value ready to compare: strings fold their case unless the attribute is case exact."""
    if isinstance(value, str) and not case_exact:
        return value.casefold()
    return value


def _compare(actual: Any, op: str, expected: Any, case_exact: bool) -> bool:
    """One comparison between a stored value and a filter literal."""
    if isinstance(actual, str) and isinstance(expected, bool) and actual.lower() in {"true", "false"}:
        actual = actual.lower() == "true"
    left = _comparable(actual, case_exact)
    right = _comparable(expected, case_exact)
    if op == "eq":
        return bool(left == right)
    if op == "ne":
        return bool(left != right)
    if isinstance(left, bool) or isinstance(right, bool):
        return False
    if op in {"co", "sw", "ew"}:
        if not isinstance(left, str) or not isinstance(right, str):
            return False
        if op == "co":
            return right in left
        return left.startswith(right) if op == "sw" else left.endswith(right)
    numeric = isinstance(left, int | float) and isinstance(right, int | float)
    if not numeric and not (isinstance(left, str) and isinstance(right, str)):
        return False
    if op == "gt":
        return bool(left > right)
    if op == "ge":
        return bool(left >= right)
    if op == "lt":
        return bool(left < right)
    return bool(left <= right)


def _evaluate(
    node: FilterNode,
    resource: Mapping[str, Any],
    resource_type: ScimResourceType | None,
    parent: str = "",
) -> bool:
    """Whether a resource, or one element of a multi-valued attribute, matches a node."""
    if isinstance(node, And):
        return _evaluate(node.left, resource, resource_type, parent) and _evaluate(
            node.right, resource, resource_type, parent
        )
    if isinstance(node, Or):
        return _evaluate(node.left, resource, resource_type, parent) or _evaluate(
            node.right, resource, resource_type, parent
        )
    if isinstance(node, Not):
        return not _evaluate(node.inner, resource, resource_type, parent)
    if isinstance(node, ValuePath):
        elements = _child(resource, node.path.attribute)
        if isinstance(elements, Mapping):
            elements = [elements]
        if not isinstance(elements, list):
            return False
        return any(
            isinstance(element, Mapping) and _evaluate(node.inner, element, resource_type, node.path.attribute)
            for element in elements
        )
    values = _resolve(resource, node.path, resource_type)
    if node.op == "pr":
        return any(value not in ("", [], {}) for value in values)
    definition = _definition(resource_type, node.path, parent)
    case_exact = definition.case_exact if definition is not None else False
    if node.op == "ne":
        return not any(_compare(value, "eq", node.value, case_exact) for value in values)
    return any(_compare(value, node.op, node.value, case_exact) for value in values)


def _references(node: FilterNode, attribute: str) -> bool:
    """Whether any part of a filter names a top-level attribute."""
    if isinstance(node, And | Or):
        return _references(node.left, attribute) or _references(node.right, attribute)
    if isinstance(node, Not):
        return _references(node.inner, attribute)
    return node.path.attribute.lower() == attribute.lower()


@dataclass(frozen=True, slots=True)
class ScimFilter:
    """A parsed filter and the text it came from."""

    text: str
    root: FilterNode

    def matches(self, resource: Mapping[str, Any], resource_type: ScimResourceType | None = None) -> bool:
        """Whether a rendered resource matches, honouring each attribute's case exactness."""
        return _evaluate(self.root, resource, resource_type)

    def matches_element(
        self,
        element: Mapping[str, Any],
        resource_type: ScimResourceType | None,
        attribute: str,
    ) -> bool:
        """Whether one element of a multi-valued attribute matches, as inside `attribute[...]`."""
        return _evaluate(self.root, element, resource_type, attribute)

    def equality(self, attribute: str) -> str | None:
        """The compared string when the whole filter is `<attribute> eq "<value>"`, else `None`.

        The attribute is matched in any case and with or without its core schema URN, so a
        product answers `userName eq`, `externalId eq` and `displayName eq` with a point lookup.
        """
        node = self.root
        if not isinstance(node, Compare) or node.op != "eq" or node.path.sub or not isinstance(node.value, str):
            return None
        if node.path.urn and node.path.urn.lower() not in {USER_SCHEMA.lower(), GROUP_SCHEMA.lower()}:
            return None
        return node.value if node.path.attribute.lower() == attribute.lower() else None

    def references(self, attribute: str) -> bool:
        """Whether the filter names a top-level attribute, such as `members`."""
        return _references(self.root, attribute)


def parse_filter(text: str) -> ScimFilter:
    """Parse a filter, raising `ScimError` 400 `invalidFilter` on any syntax error."""
    if not text.strip():
        raise ScimError.invalid_filter("The filter is empty.")
    if len(text) > MAX_FILTER_LENGTH:
        raise ScimError.invalid_filter("The filter is too long.")
    return ScimFilter(text=text, root=_Parser(text).parse())


@dataclass(frozen=True, slots=True)
class PatchPath:
    """A PATCH `path`: an attribute, an optional element filter and an optional sub-attribute.

    `urn` is the schema URN prefix when one was given. A path that is only an extension URN
    has an empty `attribute` and addresses the whole extension object.
    """

    urn: str
    attribute: str
    value_filter: ScimFilter | None = None
    sub: str = ""


def parse_patch_path(text: str, resource_type: ScimResourceType) -> PatchPath:
    """Parse a PATCH path, raising `ScimError` 400 `invalidPath` on anything malformed.

    A known schema URN is matched first, because a URN contains the dots and colons that
    would otherwise read as attribute separators.
    """
    raw = text.strip()
    if not raw:
        raise ScimError.invalid_path("The PATCH path is empty.")
    urn = ""
    rest = raw
    if raw.lower().startswith("urn:"):
        known = (resource_type.schema, *resource_type.extensions)
        for schema in sorted(known, key=lambda item: len(item.id), reverse=True):
            if raw.lower() == schema.id.lower():
                return PatchPath(urn=schema.id, attribute="")
            if raw.lower().startswith(schema.id.lower() + ":"):
                urn = schema.id
                rest = raw[len(schema.id) + 1 :]
                break
        else:
            raise ScimError.invalid_path(f"Unknown schema in PATCH path: {raw}")
    value_filter: ScimFilter | None = None
    sub = ""
    if "[" in rest:
        attribute, _, remainder = rest.partition("[")
        inner, closed, after = remainder.rpartition("]")
        if not closed:
            raise ScimError.invalid_path(f"Unclosed filter in PATCH path: {raw}")
        try:
            value_filter = parse_filter(inner)
        except ScimError as exc:
            raise ScimError.invalid_path(f"Invalid filter in PATCH path: {exc.detail}") from exc
        if after:
            if not after.startswith("."):
                raise ScimError.invalid_path(f"Invalid PATCH path: {raw}")
            sub = after[1:]
    else:
        attribute, _, sub = rest.partition(".")
    if not _ATTR_NAME.fullmatch(attribute) or (sub and not _ATTR_NAME.fullmatch(sub)):
        raise ScimError.invalid_path(f"Invalid PATCH path: {raw}")
    if urn.lower() == resource_type.schema.id.lower():
        urn = ""
    return PatchPath(urn=urn, attribute=attribute, value_filter=value_filter, sub=sub)
