"""The user-facing sentence a refusal renders, in one place.

Copy only. The envelope, `ErrorSpec` and the exception map stay in `webbpulse.http`, which
reads `STATUS_MESSAGES` from here for its per-status defaults. A product keeps its own
response shape and takes the sentence inside `detail` from these helpers, so three wordings
for 403 and four for 429 across the org collapse to one each.

`extract_mentions` is the other user-facing text concern that had a copy per product: who a
comment or a post body addresses.
"""

from __future__ import annotations

import re
from typing import Final

__all__ = [
    "DEFAULT_MESSAGE",
    "MENTION_PATTERN",
    "STATUS_MESSAGES",
    "conflict",
    "extract_mentions",
    "forbidden",
    "not_found",
    "rate_limited",
    "refusal",
    "unauthenticated",
    "validation_failed",
]

DEFAULT_MESSAGE: Final = "Request failed."

STATUS_MESSAGES: Final[dict[int, str]] = {
    400: "The request could not be understood.",
    401: "Authentication is required.",
    403: "You do not have access to this resource.",
    404: "The requested resource was not found.",
    405: "That method is not allowed on this resource.",
    409: "The resource was modified by another request. Try again.",
    422: "Request validation failed.",
    429: "Too many requests. Try again shortly.",
    503: "The service is busy. Try again shortly.",
}
"""The default user-facing sentence for each refusal status."""


def refusal(status: int, *, subject: str | None = None, action: str | None = None) -> str:
    """The sentence for `status`, optionally naming what was refused.

    With neither `subject` nor `action` this is the `STATUS_MESSAGES` entry, or
    `DEFAULT_MESSAGE` for a status with no entry. Naming an action reads as
    "Not authorized to delete this user."; naming only a subject qualifies the default
    sentence instead, so no caller has to compose the wording itself.
    """
    if action is not None:
        return _named(status, action=action, subject=subject or "this resource")
    if subject is not None:
        return _qualified(status, subject=subject)
    return STATUS_MESSAGES.get(status, DEFAULT_MESSAGE)


def _named(status: int, *, action: str, subject: str) -> str:
    """The sentence for `status` naming both the action and what it was attempted on."""
    if status == 401:
        return f"Sign in to {action} {subject}."
    if status == 404:
        return f"Could not find {subject} to {action}."
    if status == 409:
        return f"Could not {action} {subject}: it was modified by another request. Try again."
    if status == 429:
        return f"Too many attempts to {action} {subject}. Try again shortly."
    return f"Not authorized to {action} {subject}."


def _qualified(status: int, *, subject: str) -> str:
    """The sentence for `status` naming only what was refused."""
    if status == 401:
        return f"Authentication is required to access {subject}."
    if status == 403:
        return f"You do not have access to {subject}."
    if status == 404:
        return f"Could not find {subject}."
    if status == 409:
        return f"{subject.capitalize()} was modified by another request. Try again."
    if status == 429:
        return f"Too many requests for {subject}. Try again shortly."
    return STATUS_MESSAGES.get(status, DEFAULT_MESSAGE)


def forbidden(action: str = "access", subject: str = "this resource") -> str:
    """The 403 sentence, naming the action the caller is not authorized to take."""
    return _named(403, action=action, subject=subject)


def unauthenticated(action: str | None = None, subject: str = "this resource") -> str:
    """The 401 sentence, optionally naming what the caller must sign in to do."""
    if action is None:
        return STATUS_MESSAGES[401]
    return _named(401, action=action, subject=subject)


def not_found(subject: str | None = None) -> str:
    """The 404 sentence, optionally naming what was not found."""
    return refusal(404, subject=subject)


def conflict(subject: str | None = None) -> str:
    """The 409 sentence, optionally naming the resource another request changed."""
    return refusal(409, subject=subject)


def validation_failed(subject: str | None = None) -> str:
    """The 422 sentence, optionally naming the field or body that failed validation."""
    if subject is None:
        return STATUS_MESSAGES[422]
    return f"Validation failed for {subject}."


def rate_limited(*, retry_after: int | None = None, scope: str | None = None) -> str:
    """The 429 sentence, optionally naming what was limited and when to retry.

    `scope` names the thing being protected, such as "failed sign-in attempts", and
    `retry_after` is the seconds the caller should wait, which replaces the vague
    "Try again shortly." with the number the `Retry-After` header already carries.
    """
    subject = f"Too many {scope}." if scope else "Too many requests."
    if retry_after is None:
        return f"{subject} Try again shortly."
    if retry_after == 1:
        return f"{subject} Try again in 1 second."
    return f"{subject} Try again in {retry_after} seconds."


MENTION_PATTERN: Final = re.compile(r"(?<![\w@/])@([A-Za-z0-9][A-Za-z0-9_-]{0,38})\b")
"""One `@handle`: a letter or digit, then up to 38 more with underscores and hyphens.

The lookbehind is what stops an email address, a path segment and a `@@` from reading as a
mention, since none of those addresses anybody.
"""

_CODE_SPAN_OR_BLOCK: Final = re.compile(
    r"(?P<fence>^[ \t]*(?P<ticks>`{3,}|~{3,})[^\n]*\n.*?(?:^[ \t]*(?P=ticks)[^\n]*$|\Z))"
    r"|(?P<indented>(?:^(?: {4}|\t)[^\n]*$\n?)+)"
    r"|(?P<span>(?P<open>`+)(?:(?!(?P=open)).)*?(?P=open))",
    re.DOTALL | re.MULTILINE,
)
"""A fenced block, an indented block, or an inline code span, whichever comes first."""


def extract_mentions(markdown: str) -> list[str]:
    """The `@handle` mentions in `markdown`, in order, without repeats and without the `@`.

    Code is not prose: a fenced block, an indented block and an inline span are all blanked
    before the scan, so a decorator in a Python sample or an `@media` rule in a CSS one does
    not notify anybody. Comparison is case insensitive, and the first spelling of a handle is
    the one returned, so `@Ada` then `@ada` is one mention rendered as the author wrote it.
    """
    if not markdown or "@" not in markdown:
        return []

    prose = _CODE_SPAN_OR_BLOCK.sub(_blank, markdown)
    seen: set[str] = set()
    mentions: list[str] = []
    for match in MENTION_PATTERN.finditer(prose):
        handle = match.group(1)
        folded = handle.casefold()
        if folded not in seen:
            seen.add(folded)
            mentions.append(handle)
    return mentions


def _blank(match: re.Match[str]) -> str:
    """Replace a code run with its own newlines, so line structure survives the scan."""
    return "\n" * match.group(0).count("\n")
