"""Tests for `webbpulse.messages.extract_mentions`.

The cases that matter are the ones that must not notify anybody: code spans, fenced and
indented blocks, email addresses and path segments.
"""

from __future__ import annotations

import pytest

from webbpulse.messages import extract_mentions


def test_a_plain_mention_is_found() -> None:
    """The ordinary case: one handle in a sentence, returned without the `@`."""
    assert extract_mentions("hey @ada, can you look?") == ["ada"]


def test_mentions_keep_their_order() -> None:
    """A notifier renders them in the order the author wrote them."""
    assert extract_mentions("@ada @grace @alan") == ["ada", "grace", "alan"]


def test_a_repeated_mention_appears_once() -> None:
    """Nobody is notified twice for one comment."""
    assert extract_mentions("@ada and again @ada and @grace") == ["ada", "grace"]


def test_repeats_are_case_insensitive_and_keep_the_first_spelling() -> None:
    """`@Ada` then `@ada` is one person, rendered as the author first wrote it."""
    assert extract_mentions("@Ada then @ada then @ADA") == ["Ada"]


def test_an_empty_or_mentionless_body_is_empty() -> None:
    """The common case costs nothing, since most bodies mention nobody."""
    assert extract_mentions("") == []
    assert extract_mentions("no handles here at all") == []


def test_an_inline_code_span_does_not_mention_anybody() -> None:
    """A decorator in a sample is code, not an address."""
    assert extract_mentions("use `@property` here") == []


def test_a_mention_beside_a_code_span_still_counts() -> None:
    """Blanking the code must not swallow the prose around it."""
    assert extract_mentions("@ada use `@property` and ask @grace") == ["ada", "grace"]


def test_a_fenced_block_does_not_mention_anybody() -> None:
    """A Python sample full of decorators notifies nobody."""
    body = "before\n```python\n@app.route('/')\ndef home(): ...\n```\nafter"

    assert extract_mentions(body) == []


def test_a_tilde_fenced_block_is_also_code() -> None:
    """Markdown allows `~~~` fences, and they are code just the same."""
    body = "~~~\n@media screen { }\n~~~"

    assert extract_mentions(body) == []


def test_an_unclosed_fence_runs_to_the_end() -> None:
    """A truncated body must not leak its sample code as mentions."""
    body = "text\n```\n@ada\n@grace"

    assert extract_mentions(body) == []


def test_an_indented_block_does_not_mention_anybody() -> None:
    """Four-space indentation is a code block in Markdown."""
    body = "before\n\n    @decorator\n    def f(): ...\n\nafter"

    assert extract_mentions(body) == []


def test_mentions_around_a_fenced_block_are_found() -> None:
    """The prose on both sides of a sample still addresses people."""
    body = "@ada look:\n```\n@notme\n```\nthanks @grace"

    assert extract_mentions(body) == ["ada", "grace"]


def test_a_css_at_rule_in_code_is_not_a_mention() -> None:
    """`@media` inside a fence is the exact false positive this guards."""
    assert extract_mentions("```css\n@media screen { color: red }\n```") == []


def test_an_email_address_is_not_a_mention() -> None:
    """The lookbehind is what stops `ada@example.com` from addressing `@example`."""
    assert extract_mentions("write to ada@example.com") == []


def test_a_path_segment_is_not_a_mention() -> None:
    """A scoped npm package or a path does not address anybody."""
    assert extract_mentions("install node_modules/@webbpulse/ui") == []


def test_a_doubled_at_is_not_a_mention() -> None:
    """`@@ada` is not an address either."""
    assert extract_mentions("@@ada") == []


def test_a_bare_at_sign_is_not_a_mention() -> None:
    """A handle needs at least one character."""
    assert extract_mentions("an @ on its own, and @ again") == []


def test_a_handle_may_carry_underscores_and_hyphens() -> None:
    """Real handles do, so the pattern must accept them."""
    assert extract_mentions("@ada_lovelace and @grace-hopper") == ["ada_lovelace", "grace-hopper"]


def test_a_handle_may_not_start_with_a_separator() -> None:
    """A leading underscore or hyphen is not a handle this scheme issues."""
    assert extract_mentions("@_ada @-grace") == []


def test_a_handle_is_bounded_in_length() -> None:
    """A 39-character handle is the longest accepted, which matches the issuing rule."""
    assert extract_mentions("@" + "a" * 39) == ["a" * 39]


def test_an_over_long_run_is_not_a_truncated_mention() -> None:
    """The word boundary means a 40-character run matches nothing.

    Truncating it to the first 39 would notify a real, different person, which is worse than
    ignoring a handle that was never issued.
    """
    assert extract_mentions("@" + "a" * 40) == []


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("(@ada)", ["ada"]),
        ("@ada.", ["ada"]),
        ("@ada, @grace!", ["ada", "grace"]),
        ("**@ada**", ["ada"]),
        ("- @ada\n- @grace", ["ada", "grace"]),
        ("hi @ada\n", ["ada"]),
    ],
)
def test_surrounding_punctuation_does_not_break_a_mention(body: str, expected: list[str]) -> None:
    """A mention rarely sits alone on a line, so the boundaries must be forgiving."""
    assert extract_mentions(body) == expected


def test_a_double_backtick_span_is_code() -> None:
    """Markdown allows longer span delimiters, and they are still code."""
    assert extract_mentions("``@ada``") == []


def test_line_structure_survives_the_blanking() -> None:
    """A fence is replaced by its own newlines, so the prose after it still scans."""
    body = "@ada\n```\n@notme\n@alsonotme\n```\n@grace"

    assert extract_mentions(body) == ["ada", "grace"]
