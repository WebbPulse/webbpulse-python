"""Group the suite for `pytest-xdist --dist loadgroup`, so the read-only probes parallelise.

The suite splits cleanly in two. The route-cut and reachability cases are independent
read-only probes against one route each, and there are hundreds of them; on CarModPicker
they are 441 and 350 cases and about 155 seconds of the run. Everything else either signs in
as the session user and mutates it, or drives one Playwright page, and those must stay on
one worker and in one order.

`--dist loadgroup` sends every test carrying the same `xdist_group` to the same worker.
Marking the shared-state cases into one group and leaving the probes unmarked gives the
probes to the scheduler and keeps the rest together, which is the whole change.

Session fixtures under xdist are per worker, not per run: each worker runs its own session
setup. That is safe here by construction rather than by locking. Each worker makes its own
ephemeral user, keyed on its own worker id, and deletes that one; the access log window is
opened per worker over its own probes, and the lookup reads an unfiltered window, so two
workers reading overlapping windows cost one extra CloudWatch read rather than a wrong
answer. Nothing is created once per run, so no lock file is needed.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Final, Protocol

import pytest

__all__ = [
    "INDEPENDENT_PREFIXES",
    "SHARED_STATE_GROUP",
    "SHARED_STATE_PREFIXES",
    "GroupableItem",
    "GroupingPlugin",
    "apply_groups",
    "group_for",
    "worker_id",
]


class GroupableItem(Protocol):
    """The slice of `pytest.Item` the grouping reads and writes."""

    @property
    def nodeid(self) -> str:
        """The item's node id, `path::Class::test`."""
        ...

    def get_closest_marker(self, name: str) -> Any:
        """The nearest marker of this name, or None."""
        ...

    def add_marker(self, marker: Any) -> None:
        """Attach one marker to this item."""
        ...


SHARED_STATE_GROUP: Final = "webbpulse-e2e-session-user"

SHARED_STATE_PREFIXES: Final[tuple[str, ...]] = (
    "TestIdentity",
    "TestBrowser",
    "TestHygiene",
)

INDEPENDENT_PREFIXES: Final[tuple[str, ...]] = (
    "TestRouteCut",
    "TestCoverage",
    "TestReachability",
    "TestFrontend",
)


def worker_id(config: Any) -> str:
    """This worker's xdist id, or `master` when the run is not distributed.

    Used to keep one worker's created resources from colliding with another's. `master` is
    the same string xdist itself uses for a non-distributed run, so a serial run and a
    one-worker run name their resources the same way.
    """
    return str(getattr(config, "workerinput", {}).get("workerid", "") or "master")


def group_for(item: GroupableItem) -> str:
    """The `xdist_group` this item belongs in, or empty to leave it schedulable.

    Membership is by test class, because that is what the shared state follows: the identity
    cases sign in and mutate the session user, the browser cases drive one page, and the
    hygiene cases assert about the run's own created-resources list. Route cut, coverage,
    reachability and frontend cases touch none of that and are left free.

    A product's own cases are grouped when they carry the `e2e_writes` marker, so a case
    that mutates the session user is held with the rest without the product naming a group.
    The plugin's own independent probe classes stay free even where a case carries the
    marker: the authenticated reachability probe is marked only so a read-only run skips it,
    and it neither refreshes nor ends the session, so pinning its hundreds of cases to one
    worker would serialise the run for nothing.
    """
    classes = _owning_classes(item)
    if any(cls.startswith(SHARED_STATE_PREFIXES) for cls in classes):
        return SHARED_STATE_GROUP
    if any(cls.startswith(INDEPENDENT_PREFIXES) for cls in classes):
        return ""
    if item.get_closest_marker("e2e_writes") is not None:
        return SHARED_STATE_GROUP
    return ""


def _owning_classes(item: GroupableItem) -> tuple[str, ...]:
    """Every class name in this item's own node id, outermost first."""
    parts = item.nodeid.split("::")
    return tuple(part for part in parts[1:-1] if part)


def apply_groups(items: Sequence[GroupableItem]) -> int:
    """Mark every shared-state item with its `xdist_group`, returning how many were marked.

    Applied whether or not xdist is installed: the marker is inert in a serial run, so the
    suite carries one grouping rather than two code paths.
    """
    marked = 0
    for item in items:
        group = group_for(item)
        if not group:
            continue
        item.add_marker(pytest.mark.xdist_group(group))
        marked += 1
    return marked


class GroupingPlugin:
    """Applies the `xdist_group` markers before xdist reads them.

    xdist's worker turns each `xdist_group` marker into the `@group` suffix on the node id
    in its own `pytest_collection_modifyitems`, and `--dist loadgroup` schedules by that
    suffix alone. That hook is registered after every conftest and entry point plugin, so
    pluggy calls it first; a marker added by an ordinary hook of this plugin arrived after
    the suffix was written and grouped nothing. `tryfirst` puts this pass ahead of it.
    """

    @pytest.hookimpl(tryfirst=True)
    def pytest_collection_modifyitems(self, items: list[pytest.Item]) -> None:
        """Mark the shared-state cases with their group ahead of xdist's suffix pass."""
        apply_groups(items)
