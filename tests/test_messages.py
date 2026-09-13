"""Tests for the refusal copy catalogue.

Pins the rendered sentences, the parameterised helpers, and that `webbpulse.http` reads its
per-status defaults from here rather than holding a second copy.
"""

from __future__ import annotations

import pytest

from webbpulse.messages import (
    DEFAULT_MESSAGE,
    STATUS_MESSAGES,
    conflict,
    forbidden,
    not_found,
    rate_limited,
    refusal,
    unauthenticated,
    validation_failed,
)


def test_the_catalogue_covers_the_refusal_statuses() -> None:
    """Every status the shared error handlers render has a sentence."""
    assert set(STATUS_MESSAGES) == {400, 401, 403, 404, 405, 409, 422, 429, 503}
    assert STATUS_MESSAGES[403] == "You do not have access to this resource."
    assert STATUS_MESSAGES[429] == "Too many requests. Try again shortly."


def test_http_reads_its_defaults_from_the_catalogue() -> None:
    """The private table in `webbpulse.http` is this one, not a second copy that can drift."""
    pytest.importorskip("fastapi")
    from webbpulse.http import _STATUS_MESSAGES

    assert _STATUS_MESSAGES is STATUS_MESSAGES


def test_an_unnamed_refusal_is_the_catalogue_sentence() -> None:
    """With nothing named, `refusal` is a lookup, and an unknown status has a fallback."""
    assert refusal(404) == STATUS_MESSAGES[404]
    assert refusal(418) == DEFAULT_MESSAGE


def test_naming_the_action_keeps_what_the_user_acts_on() -> None:
    """A 403 that names the action reads better than flattening to "Access denied"."""
    assert refusal(403, action="delete", subject="this user") == "Not authorized to delete this user."
    assert forbidden("delete", "this user") == "Not authorized to delete this user."
    assert forbidden() == "Not authorized to access this resource."


def test_naming_only_the_subject_qualifies_the_sentence() -> None:
    """A caller with a subject and no verb still gets one sentence, not a composed one."""
    assert refusal(403, subject="this build") == "You do not have access to this build."
    assert not_found("that part") == "Could not find that part."
    assert not_found() == STATUS_MESSAGES[404]
    assert conflict("the car") == "The car was modified by another request. Try again."
    assert conflict() == STATUS_MESSAGES[409]


def test_unauthenticated_names_the_action_only_when_given_one() -> None:
    """The default 401 stays the plain sentence a sign-in wall renders."""
    assert unauthenticated() == "Authentication is required."
    assert unauthenticated("edit", "this list") == "Sign in to edit this list."


def test_validation_failed_names_the_field() -> None:
    """A 422 can point at what failed without the caller writing the sentence."""
    assert validation_failed() == "Request validation failed."
    assert validation_failed("the part number") == "Validation failed for the part number."


def test_the_two_429_sentences_converge() -> None:
    """The rate limiter and the catalogue now say the same thing."""
    assert rate_limited() == STATUS_MESSAGES[429] == "Too many requests. Try again shortly."


def test_a_scoped_429_keeps_the_lockout_wording() -> None:
    """The progressive lockout's sentence comes from here unchanged."""
    assert rate_limited(scope="failed attempts") == "Too many failed attempts. Try again shortly."


def test_retry_after_replaces_the_vague_sentence() -> None:
    """Naming the seconds says what `Retry-After` already carries, and singular reads right."""
    assert rate_limited(retry_after=30) == "Too many requests. Try again in 30 seconds."
    assert rate_limited(retry_after=1) == "Too many requests. Try again in 1 second."
    assert rate_limited(retry_after=5, scope="sign-in attempts") == (
        "Too many sign-in attempts. Try again in 5 seconds."
    )


def test_the_rate_limiter_refuses_with_the_catalogue_sentence() -> None:
    """`webbpulse.ratelimit` no longer carries its own 429 copy."""
    pytest.importorskip("fastapi")
    from webbpulse.identity.flows import RateLimited

    assert RateLimited(30).args[0] == rate_limited(scope="failed attempts")
