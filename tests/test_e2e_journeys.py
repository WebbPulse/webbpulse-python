"""Tests for the vocabulary a product declares its browser contract in.

The validation here is the point: a journey that mutates a stage without recording what it
created leaks a resource the cleanup hook never sees, and the only moment that is cheap to
notice is construction, which happens at collection.
"""

from __future__ import annotations

import pytest

from webbpulse.e2e.journeys import (
    ACCESS_LEVELS,
    Click,
    ExpectText,
    ExpectUrl,
    ExpectVisible,
    Fill,
    Goto,
    Journey,
    LoginForm,
    Record,
    RouteSpec,
    expand,
    url_matches,
)


class TestLoginForm:
    """Tests for the login locator declaration."""

    def test_the_defaults_follow_the_data_testid_convention(self) -> None:
        """A product that adds the documented attributes needs to declare only its path."""
        form = LoginForm(path="/login")
        assert form.email == "[data-testid=login-email]"
        assert form.password == "[data-testid=login-password]"
        assert form.submit == "[data-testid=login-submit]"
        assert form.sign_out == "[data-testid=sign-out]"

    def test_a_relative_path_is_refused(self) -> None:
        """Locators are joined against the web base URL, so the path must be absolute."""
        with pytest.raises(ValueError, match="absolute path"):
            LoginForm(path="login")

    def test_an_empty_locator_is_refused(self) -> None:
        """An empty locator matches everything, so the sign-in case would assert nothing."""
        with pytest.raises(ValueError, match="signed_in_marker"):
            LoginForm(path="/login", signed_in_marker="  ")

    def test_the_anonymous_redirect_defaults_to_the_login_path(self) -> None:
        """Most apps bounce an anonymous visitor to the login page they already declared."""
        assert LoginForm(path="/sign-in").anonymous_redirect == "/sign-in"

    def test_an_explicit_protected_redirect_wins(self) -> None:
        """An app with a separate unauthorised page declares it rather than the login path."""
        assert LoginForm(path="/sign-in", protected_redirect="/welcome").anonymous_redirect == "/welcome"


class TestRouteSpec:
    """Tests for the route declaration."""

    @pytest.mark.parametrize("access", ACCESS_LEVELS)
    def test_every_documented_access_level_is_accepted(self, access: str) -> None:
        """The three levels the guard cases are written against."""
        assert RouteSpec(path="/x", access=access).access == access

    def test_an_unknown_access_level_is_refused(self) -> None:
        """A typo would silently drop the route out of every guard case."""
        with pytest.raises(ValueError, match="access must be one of"):
            RouteSpec(path="/x", access="private")

    def test_a_relative_path_is_refused(self) -> None:
        """The path is navigated to against the context's base URL."""
        with pytest.raises(ValueError, match="absolute path"):
            RouteSpec(path="x")

    def test_the_label_names_the_access_level_and_the_path(self) -> None:
        """A junit id that says which route and which guard failed."""
        assert RouteSpec(path="/garage", access="protected").label == "protected:/garage"

    def test_an_explicit_name_wins(self) -> None:
        """A product with two routes on one path distinguishes them by name."""
        assert RouteSpec(path="/garage", name="garage-list").label == "garage-list"


class TestJourney:
    """Tests for the journey declaration and its mutation rule."""

    def test_a_read_only_journey_needs_no_record(self) -> None:
        """A journey that only looks at things creates nothing to clean up."""
        journey = Journey(name="browse", steps=[Goto("/"), ExpectVisible("#root")])
        assert not journey.mutates
        assert journey.records == ()

    def test_a_mutating_journey_without_a_record_is_refused(self) -> None:
        """This is the leak: created in the stage, never recorded, never deleted."""
        with pytest.raises(ValueError, match="no Record step"):
            Journey(
                name="create a build",
                steps=[Goto("/builds/new"), Fill("#name", "e2e-{run_id}"), Click("#save")],
                mutates=True,
            )

    def test_the_refusal_says_what_to_do(self) -> None:
        """The message names both ways out, so the fix does not need the source."""
        with pytest.raises(ValueError) as error:
            Journey(name="create", steps=[Goto("/")], mutates=True)
        assert "created_resources" in str(error.value)
        assert "mutates=False" in str(error.value)

    def test_a_mutating_journey_with_a_record_is_accepted(self) -> None:
        """The shape a product is meant to write."""
        journey = Journey(
            name="create a build",
            steps=[Goto("/builds/new"), Fill("#name", "e2e-{run_id}-build"), Record("e2e-{run_id}-build")],
            mutates=True,
        )
        assert len(journey.records) == 1

    def test_an_empty_journey_is_refused(self) -> None:
        """A journey with no steps passes vacuously, which is worse than not declaring it."""
        with pytest.raises(ValueError, match="no steps"):
            Journey(name="empty", steps=[])

    def test_an_unnamed_journey_is_refused(self) -> None:
        """The name is the junit id, so a failure with no name names nothing."""
        with pytest.raises(ValueError, match="name is empty"):
            Journey(name="  ", steps=[Goto("/")])

    def test_journeys_default_to_signed_in(self) -> None:
        """Most product journeys are things only a signed-in person can do."""
        assert Journey(name="x", steps=[Goto("/")]).signed_in


class TestExpansion:
    """Tests for the one placeholder a declared value may carry."""

    def test_the_run_id_placeholder_expands(self) -> None:
        """Created names carry the run id so the prefix sweep finds them."""
        assert expand("e2e-{run_id}-build", "abc123") == "e2e-abc123-build"

    def test_a_value_with_no_placeholder_is_untouched(self) -> None:
        """Most values are plain, and expansion must not disturb them."""
        assert expand("[data-testid=save]", "abc123") == "[data-testid=save]"

    def test_other_braces_are_left_alone(self) -> None:
        """A CSS or regex value carrying braces passes through, unlike with str.format."""
        assert expand(r"^/builds/\d{3}$", "abc123") == r"^/builds/\d{3}$"

    def test_every_occurrence_expands(self) -> None:
        """A value naming the run twice gets both, which str.replace already does."""
        assert expand("{run_id}-{run_id}", "x") == "x-x"


class TestSteps:
    """Tests for the step dataclasses themselves."""

    @pytest.mark.parametrize(
        ("step", "field_name"),
        [
            (Goto("/"), "path"),
            (Click("#a"), "locator"),
            (Fill("#a", "v"), "value"),
            (ExpectVisible("#a"), "locator"),
            (ExpectText("#a", "t"), "text"),
            (ExpectUrl("^/$"), "pattern"),
            (Record("r"), "resource"),
        ],
    )
    def test_every_step_is_frozen(self, step: object, field_name: str) -> None:
        """Steps are declared once in a conftest and must not be mutated by a run."""
        with pytest.raises(AttributeError):
            setattr(step, field_name, "changed")

    def test_a_record_carries_whatever_the_product_understands(self) -> None:
        """The plugin never inspects the shape beyond expanding a string."""
        handle = {"table": "builds", "id": "e2e-1"}
        assert Record(handle).resource is handle


class TestUrlMatching:
    """Tests for how an `ExpectUrl` pattern is applied."""

    def test_it_searches_rather_than_full_matches(self) -> None:
        """A product writes the fragment it cares about, not the whole origin."""
        assert url_matches("/builds/", "https://www.staging.example.invalid/builds/17")

    def test_a_non_match_is_false(self) -> None:
        """The negative case, which is what the journey step asserts on."""
        assert not url_matches("/garage", "https://www.staging.example.invalid/builds/17")

    def test_an_anchored_pattern_still_works(self) -> None:
        """An anchor is the product's to write when it wants one."""
        assert not url_matches("^/builds$", "https://www.staging.example.invalid/builds/17")
