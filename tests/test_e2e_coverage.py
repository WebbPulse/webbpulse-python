"""Tests for matching a run's requests back to the routes a deployment serves.

The coverage check is only as good as the matching underneath it: a concrete path has to be
credited to the templated route that really served it, or the numbers move with dictionary
order and a green run means nothing.
"""

from __future__ import annotations

from webbpulse.e2e.coverage import matched_template, measure_coverage, template_pattern


class TestTemplatePattern:
    """A templated path compiles to a matcher whose variables span exactly one segment."""

    def test_a_variable_matches_one_segment(self) -> None:
        """A brace part matches a single path part."""
        pattern = template_pattern("/api/issues/{issue_id}")
        assert pattern.match("/api/issues/abc")

    def test_a_variable_never_matches_across_a_slash(self) -> None:
        """A brace part stops at a slash, so it cannot swallow a deeper path."""
        pattern = template_pattern("/api/issues/{issue_id}")
        assert pattern.match("/api/issues/abc/comments") is None

    def test_a_literal_segment_is_matched_literally(self) -> None:
        """A regex character in a literal segment is escaped rather than interpreted."""
        pattern = template_pattern("/api/a.b/{id}")
        assert pattern.match("/api/a.b/1")
        assert pattern.match("/api/axb/1") is None

    def test_a_longer_path_does_not_match_a_shorter_template(self) -> None:
        """The matcher is anchored at both ends."""
        assert template_pattern("/api/issues").match("/api/issues/1") is None


class TestMatchedTemplate:
    """Ties between candidate templates are broken by specificity, as the gateway breaks them."""

    def test_the_longest_literal_prefix_wins(self) -> None:
        """A nested literal route beats the variable route it sits inside."""
        templates = ["/api/issues/{issue_id}", "/api/issues/{issue_id}/comments"]
        assert matched_template("/api/issues/7/comments", templates) == "/api/issues/{issue_id}/comments"

    def test_a_literal_segment_beats_a_variable_in_the_same_position(self) -> None:
        """`/api/issues/mine` is credited to the literal route, not the id route."""
        templates = ["/api/issues/{issue_id}", "/api/issues/mine"]
        assert matched_template("/api/issues/mine", templates) == "/api/issues/mine"

    def test_no_candidate_returns_none(self) -> None:
        """A path nothing serves matches nothing rather than the nearest route."""
        assert matched_template("/api/unknown", ["/api/issues/{issue_id}"]) is None


class TestMeasureCoverage:
    """The report separates what was reached, what was excused and what is stale."""

    def test_an_exercised_route_is_covered(self) -> None:
        """A concrete request credits the templated route that serves it."""
        result = measure_coverage([("GET", "/api/issues/{issue_id}")], [("GET", "/api/issues/7")])
        assert result.covered == frozenset({("GET", "/api/issues/{issue_id}")})
        assert result.uncovered == ()

    def test_an_untouched_route_is_reported(self) -> None:
        """A served route nothing reached is reported as uncovered."""
        result = measure_coverage([("GET", "/api/issues"), ("POST", "/api/issues")], [("GET", "/api/issues")])
        assert result.uncovered == (("POST", "/api/issues"),)

    def test_the_method_has_to_match(self) -> None:
        """Reaching a path with one method does not cover it under another."""
        result = measure_coverage([("DELETE", "/api/issues/{id}")], [("GET", "/api/issues/7")])
        assert result.uncovered == (("DELETE", "/api/issues/{id}"),)

    def test_an_allowlisted_route_is_excused(self) -> None:
        """A named route is not reported as a gap, and is listed as allowed."""
        result = measure_coverage(
            [("POST", "/api/attachments")],
            [],
            {("POST", "/api/attachments"): "needs a real upload"},
        )
        assert result.uncovered == ()
        assert result.allowed == (("POST", "/api/attachments"),)

    def test_an_allowlist_entry_for_a_gone_route_is_stale(self) -> None:
        """An entry naming a route the deployment no longer serves is reported as stale."""
        result = measure_coverage([("GET", "/api/issues")], [("GET", "/api/issues")], {("GET", "/api/gone"): "was"})
        assert result.stale == (("GET", "/api/gone"),)

    def test_a_request_matching_nothing_is_reported_separately(self) -> None:
        """A request no served route matches is surfaced rather than silently dropped."""
        result = measure_coverage([("GET", "/api/issues")], [("GET", "/api/typo")])
        assert result.unmatched == (("GET", "/api/typo"),)
        assert result.covered == frozenset()

    def test_methods_are_compared_case_insensitively(self) -> None:
        """A lowercase recorded method still credits the served route."""
        result = measure_coverage([("GET", "/api/issues")], [("get", "/api/issues")])
        assert result.uncovered == ()
