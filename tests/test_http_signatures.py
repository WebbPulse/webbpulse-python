"""Tests for the wire helpers in `webbpulse.http`.

`verify_hmac_signature` is pinned against GitHub's own `X-Hub-Signature-256` shape, and the
cursor helpers against a client that edits what it was handed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

import pytest

from webbpulse.http import (
    CursorPage,
    InvalidCursor,
    SignatureMismatch,
    decode_cursor,
    encode_cursor,
    verify_hmac_signature,
)

SECRET = "shhh"

KEY = "cursor-signing-key"

BODY = b'{"action":"opened","number":7}'


def _github_header(body: bytes, secret: str = SECRET) -> str:
    """The `X-Hub-Signature-256` value GitHub sends for `body`."""
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_a_github_shaped_signature_verifies() -> None:
    """The defaults are exactly GitHub's webhook shape, with no arguments to remember."""
    assert verify_hmac_signature(BODY, _github_header(BODY), SECRET)


def test_a_wrong_secret_raises_rather_than_returning_false() -> None:
    """A caller that forgets to check a boolean is the failure mode this guards against."""
    with pytest.raises(SignatureMismatch):
        verify_hmac_signature(BODY, _github_header(BODY, "other-secret"), SECRET)


def test_a_tampered_body_raises() -> None:
    """The signature is over the bytes, so editing one of them must be caught."""
    with pytest.raises(SignatureMismatch):
        verify_hmac_signature(b'{"action":"closed"}', _github_header(BODY), SECRET)


@pytest.mark.parametrize("header", [None, "", "   "])
def test_a_missing_header_raises(header: str | None) -> None:
    """An unsigned request is refused the same way a wrongly signed one is."""
    with pytest.raises(SignatureMismatch):
        verify_hmac_signature(BODY, header, SECRET)


@pytest.mark.parametrize(
    "header",
    ["sha1=abc", "abc123", "sha256", "sha512=" + "0" * 128],
)
def test_a_header_in_the_wrong_form_raises(header: str) -> None:
    """A digest that does not carry the expected scheme prefix is not verified anyway."""
    with pytest.raises(SignatureMismatch):
        verify_hmac_signature(BODY, header, SECRET)


def test_a_non_hex_digest_raises_rather_than_crashing() -> None:
    """A malformed digest is a refusal, not a `ValueError` escaping from `bytes.fromhex`."""
    with pytest.raises(SignatureMismatch):
        verify_hmac_signature(BODY, "sha256=not-hex-at-all", SECRET)


def test_an_unsupported_algorithm_is_refused() -> None:
    """A header cannot name an arbitrary hash, which is what the allowlist is for."""
    with pytest.raises(SignatureMismatch):
        verify_hmac_signature(BODY, _github_header(BODY), SECRET, algorithm="md5")


def test_a_bare_digest_scheme_is_supported() -> None:
    """`prefix=""` covers a sender that omits the scheme name."""
    digest = hmac.new(SECRET.encode(), BODY, hashlib.sha256).hexdigest()

    assert verify_hmac_signature(BODY, digest, SECRET, prefix="")


@pytest.mark.parametrize("algorithm", ["sha1", "sha256", "sha512"])
def test_each_allowed_algorithm_round_trips(algorithm: str) -> None:
    """The allowlist names the three a real sender uses, and each one verifies."""
    digest = hmac.new(SECRET.encode(), BODY, getattr(hashlib, algorithm)).hexdigest()

    assert verify_hmac_signature(BODY, digest, SECRET, algorithm=algorithm, prefix="")


def test_the_algorithm_name_is_case_insensitive() -> None:
    """A sender that spells it `SHA256` is not a mismatch."""
    assert verify_hmac_signature(BODY, _github_header(BODY), SECRET, algorithm="SHA256")


def test_a_bytes_secret_verifies_the_same_as_text() -> None:
    """A secret read from Secrets Manager arrives either way."""
    assert verify_hmac_signature(BODY, _github_header(BODY), SECRET.encode())


def test_a_cursor_round_trips() -> None:
    """What the data layer put in comes back out unchanged."""
    state = {"pk": "ws-1", "sk": "post#2026-09-17", "n": 4}

    assert decode_cursor(encode_cursor(state, KEY), KEY) == state


def test_a_cursor_is_url_safe_and_unpadded() -> None:
    """It lives in a query string, so it carries nothing that needs escaping."""
    cursor = encode_cursor({"pk": "ws-1", "sk": "a" * 40}, KEY)

    assert "=" not in cursor
    assert "+" not in cursor
    assert "/" not in cursor


def test_the_same_state_always_encodes_the_same_way() -> None:
    """Sorted compact JSON is what makes a cursor comparable and cacheable."""
    assert encode_cursor({"b": 2, "a": 1}, KEY) == encode_cursor({"a": 1, "b": 2}, KEY)


def test_a_cursor_signed_under_another_key_is_refused() -> None:
    """A client cannot mint a cursor, which is the whole point of signing one."""
    cursor = encode_cursor({"pk": "ws-1"}, "key-a")

    with pytest.raises(InvalidCursor):
        decode_cursor(cursor, "key-b")


def test_an_edited_cursor_is_refused() -> None:
    """A client that rewrites the payload gets a refusal, not somebody else's rows."""
    payload = json.dumps({"pk": "ws-9"}, separators=(",", ":"), sort_keys=True).encode()
    good = base64.urlsafe_b64decode(encode_cursor({"pk": "ws-1"}, KEY) + "==")
    _, _, signature = good.rpartition(b".")
    forged = base64.urlsafe_b64encode(payload + b"." + signature).decode().rstrip("=")

    with pytest.raises(InvalidCursor):
        decode_cursor(forged, KEY)


@pytest.mark.parametrize(
    "cursor",
    ["", "!!!not-base64!!!", "YWJj", base64.urlsafe_b64encode(b"no-separator").decode().rstrip("=")],
)
def test_a_malformed_cursor_is_refused(cursor: str) -> None:
    """Every failure raises the same error, so nothing about the key is learnable."""
    with pytest.raises(InvalidCursor):
        decode_cursor(cursor, KEY)


def test_a_cursor_whose_payload_is_not_an_object_is_refused() -> None:
    """A signed list would still not be a key the data layer can resume from."""
    payload = b"[1,2,3]"
    signature = hmac.new(KEY.encode(), payload, hashlib.sha256).digest()[:16]
    cursor = base64.urlsafe_b64encode(payload + b"." + signature).decode().rstrip("=")

    with pytest.raises(InvalidCursor):
        decode_cursor(cursor, KEY)


@pytest.mark.parametrize("key", ["", b""])
def test_an_empty_signing_key_is_refused(key: str | bytes) -> None:
    """Signing under nothing would make every cursor forgeable."""
    with pytest.raises(ValueError, match="signing key"):
        encode_cursor({"pk": "ws-1"}, key)


def test_a_page_with_a_cursor_reports_more() -> None:
    """`has_more` is derived, so it cannot disagree with the cursor."""
    page: CursorPage[str] = CursorPage.from_page(["a", "b"], {"pk": "ws-1", "sk": "b"}, KEY)

    assert page.items == ["a", "b"]
    assert page.has_more
    assert page.next_cursor is not None
    assert decode_cursor(page.next_cursor, KEY) == {"pk": "ws-1", "sk": "b"}


@pytest.mark.parametrize("last_key", [None, {}])
def test_an_exhausted_page_issues_no_cursor(last_key: Any) -> None:
    """`next_cursor` is `None` exactly when the result set is exhausted."""
    page: CursorPage[str] = CursorPage.from_page(["a"], last_key, KEY)

    assert page.next_cursor is None
    assert not page.has_more


def test_a_page_bridges_the_data_layer_page() -> None:
    """`Page.last_evaluated_key` goes straight in, and the key shape never reaches a client."""
    pytest.importorskip("boto3")
    from webbpulse.dynamodb import Page

    data_page = Page(items=[{"id": "p-1"}], last_evaluated_key={"pk": "ws-1"}, count=1, scanned_count=1)

    page: CursorPage[dict[str, Any]] = CursorPage.from_page(data_page.items, data_page.last_evaluated_key, KEY)

    assert page.has_more is data_page.has_more
    assert page.next_cursor is not None
    assert "ws-1" not in page.next_cursor


def test_a_page_serialises_as_a_response_body() -> None:
    """It is a pydantic model, so FastAPI renders and documents it like any other."""
    page: CursorPage[str] = CursorPage.from_page(["a"], {"pk": "ws-1"}, KEY)

    body = page.model_dump()
    assert set(body) == {"items", "next_cursor"}
    assert body["items"] == ["a"]


def test_http_does_not_import_dynamodb() -> None:
    """The wire layer stays usable in a service with no `dynamodb` extra installed.

    `CursorPage.from_page` takes the items and the raw key as arguments precisely so this
    stays true. The error handlers do reach `webbpulse.dynamodb`, but only from inside the
    function that installs them, so importing `webbpulse.http` never needs the extra. It is
    the module-level import graph the test pins.
    """
    import ast
    import inspect

    import webbpulse.http

    tree = ast.parse(inspect.getsource(webbpulse.http))
    imported: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)

    assert not any("dynamodb" in name for name in imported)
