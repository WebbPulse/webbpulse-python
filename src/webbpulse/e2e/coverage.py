"""Matching the requests a run made back to the routes the deployment serves.

A suite can be green and still cover almost nothing, so the coverage check asks the
opposite question from the rest of the suite: not whether the routes that were exercised
answered correctly, but which served routes were never exercised at all. That only works if
a concrete request path can be matched back to the templated route that served it, which is
what this module does.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

__all__ = [
    "RouteCoverage",
    "matched_template",
    "measure_coverage",
    "template_pattern",
]

_TEMPLATE_PART = re.compile(r"\\\{[^/}]+\\\}")


def template_pattern(path: str) -> re.Pattern[str]:
    """One compiled matcher for a templated path, where each brace part is one segment.

    The path is escaped first and the escaped brace parts are then replaced, so a literal
    segment carrying a regex character is matched literally rather than as a pattern. A
    variable matches one segment and never a slash, because `{id}` in a route key stands for
    exactly one path part.
    """
    escaped = re.escape(path)
    return re.compile(f"^{_TEMPLATE_PART.sub(r'[^/]+', escaped)}$")


def matched_template(path: str, templates: Iterable[str]) -> str | None:
    """The templated route that served a concrete path, or None when none matches.

    Ties are broken the way API Gateway breaks them, by specificity: the candidate with the
    longest literal prefix wins, so `/a/{id}/comments` beats `/a/{id}` for a comment path and
    a literal segment beats a variable in the same position. Without that, a concrete path
    would be credited to whichever template happened to be visited first and the coverage
    numbers would move with dictionary order.
    """
    candidates = [template for template in templates if template_pattern(template).match(path)]
    if not candidates:
        return None
    return max(candidates, key=lambda template: (_literal_prefix_length(template), -template.count("{")))


def _literal_prefix_length(template: str) -> int:
    """How many characters of a template precede its first variable."""
    brace = template.find("{")
    return len(template) if brace < 0 else brace


@dataclass(frozen=True)
class RouteCoverage:
    """What one run exercised, what it did not, and which gaps were allowed."""

    covered: frozenset[tuple[str, str]]
    uncovered: tuple[tuple[str, str], ...]
    allowed: tuple[tuple[str, str], ...]
    stale: tuple[tuple[str, str], ...]
    unmatched: tuple[tuple[str, str], ...]


def measure_coverage(
    served: Iterable[tuple[str, str]],
    requests: Iterable[tuple[str, str]],
    allowlist: Mapping[tuple[str, str], str] | None = None,
) -> RouteCoverage:
    """Match every request back to a served route and report what was left uncovered.

    `served` is the deployment's own routes as `(method, path)` with templated paths, and
    `requests` is what the run actually sent, with concrete paths. A request that matches no
    served route is reported separately rather than counted as covering something: it is
    usually a path the product builds wrongly, and silently dropping it would hide that.

    Entries in `allowlist` that name a route no longer served come back as `stale`, so an
    allowlist cannot outlive the gap it excuses.
    """
    allowed_reasons = dict(allowlist or {})
    served_pairs = {(method.upper(), path) for method, path in served}
    by_method: dict[str, list[str]] = {}
    for method, path in served_pairs:
        by_method.setdefault(method, []).append(path)

    covered: set[tuple[str, str]] = set()
    unmatched: list[tuple[str, str]] = []
    for method, path in requests:
        upper = method.upper()
        template = matched_template(path, by_method.get(upper, ()))
        if template is None:
            unmatched.append((upper, path))
            continue
        covered.add((upper, template))

    allowed_pairs = {(method.upper(), path) for method, path in allowed_reasons}
    uncovered = sorted(served_pairs - covered - allowed_pairs)
    stale = sorted(allowed_pairs - served_pairs)
    allowed = sorted(allowed_pairs & served_pairs)
    return RouteCoverage(
        covered=frozenset(covered),
        uncovered=tuple(uncovered),
        allowed=tuple(allowed),
        stale=tuple(stale),
        unmatched=tuple(_unique(unmatched)),
    )


def _unique(pairs: Sequence[tuple[str, str]]) -> list[tuple[str, str]]:
    """The distinct pairs, in a stable order, so a report does not repeat one path."""
    return sorted(set(pairs))
