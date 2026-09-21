"""Routes a stage deliberately answers 503 on, because an integration is not configured yet.

A 503 is a failure everywhere else in the suite, and it should be: a route answering one is
a route nobody can use. But some routes are meant to answer it. A webhook receiver whose
upstream app does not exist yet must answer 503 rather than 200 or 404, so the sender queues
the delivery and retries it once the app is created, and the same route must still be served,
still be cut correctly and still be reachable in the meantime.

A product declares those routes through `pytest_e2e_expected_unavailable`, as a mapping keyed
like the coverage allowlist of `(method, path)` to `"ERROR_CODE: reason"`. A declared route
passes only while it answers a 503 whose error envelope carries that exact code. Anything
else, including a 200, fails as a stale entry, so the declaration retires itself the moment
the integration is configured rather than excusing a real outage forever.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

__all__ = [
    "ERROR_CODE_FIELD",
    "UNAVAILABLE_STATUS",
    "ExpectedUnavailable",
    "normalise_expected_unavailable",
    "response_error_code",
    "stale_expectation",
]

UNAVAILABLE_STATUS = 503

ERROR_CODE_FIELD = "error_code"


@dataclass(frozen=True)
class ExpectedUnavailable:
    """One declared route's expected 503, as the stable code plus why it is expected."""

    error_code: str
    reason: str


def normalise_expected_unavailable(declared: Any) -> dict[tuple[str, str], ExpectedUnavailable]:
    """A product's declared mapping parsed and normalised, or empty when it declares none.

    Methods are uppercased so a product may spell them either way, matching the coverage
    allowlist. Each value is `"ERROR_CODE: reason"`, split on the first colon; the code must
    be uppercase and the reason must not be blank, because a declaration nobody can read is
    an exception nobody can retire.

    Raises `ValueError` naming the entry when a value does not parse, rather than treating a
    malformed declaration as no declaration and letting a 503 through unexamined.
    """
    if not declared:
        return {}
    parsed: dict[tuple[str, str], ExpectedUnavailable] = {}
    for (method, path), value in dict(declared).items():
        key = (str(method).upper(), str(path))
        parsed[key] = _parse_expectation(key, value)
    return parsed


def _parse_expectation(key: tuple[str, str], value: Any) -> ExpectedUnavailable:
    """One declared value parsed into a code and a reason, or a `ValueError` saying why not."""
    method, path = key
    where = f"pytest_e2e_expected_unavailable entry {method} {path}"
    text = str(value)
    code, separator, reason = text.partition(":")
    if not separator:
        raise ValueError(
            f"{where} is {text!r}, which carries no colon. The value is "
            '"ERROR_CODE: reason", where the code is the stable error_code the route\'s 503 '
            "body carries and the reason says which integration is missing."
        )
    code = code.strip()
    reason = reason.strip()
    if not code:
        raise ValueError(f"{where} is {text!r}, which names no error code before the colon.")
    if code != code.upper():
        raise ValueError(
            f"{where} names error code {code!r}, which is not uppercase. The code is compared "
            "to the response body byte for byte, so it must be spelled as the app emits it."
        )
    if not reason:
        raise ValueError(
            f"{where} names {code} with no reason after the colon. An exception with no reason "
            "cannot be reviewed or retired."
        )
    return ExpectedUnavailable(error_code=code, reason=reason)


def response_error_code(response: Any) -> str:
    """The `error_code` a response's error envelope carries, or "" where it carries none.

    The field `webbpulse.http.error_body` writes. A body that is not JSON, not an object or
    carries no code reads as "", which never matches a declared code.
    """
    try:
        payload = response.json()
    except Exception:
        return ""
    if not isinstance(payload, Mapping):
        return ""
    code = payload.get(ERROR_CODE_FIELD)
    return str(code) if isinstance(code, str) else ""


def stale_expectation(
    expected: ExpectedUnavailable,
    status: int,
    error_code: str,
    label: str,
) -> str | None:
    """Why a declared route's answer no longer matches its declaration, or None when it does.

    `label` names the route the way its case names it, so the message reads the same from the
    reachability group and from the route cut probe.
    """
    if status == UNAVAILABLE_STATUS and error_code == expected.error_code:
        return None
    if status == UNAVAILABLE_STATUS:
        answered = f"503 carrying error_code {error_code!r}" if error_code else "503 carrying no error_code"
    else:
        answered = f"{status}"
    return (
        f"{label} is named in pytest_e2e_expected_unavailable as answering 503 with "
        f"error_code {expected.error_code!r} ({expected.reason}), but it answered {answered}. "
        "The entry is stale: remove it, because the route no longer answers the deliberate "
        "503 it excused."
    )
