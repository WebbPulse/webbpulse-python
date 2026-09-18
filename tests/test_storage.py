"""Tests for the presigned upload helper in `webbpulse.storage`.

The assertions that matter are about what goes into the signature. A presigned PUT's guard
is the `Params` it was signed with, so returning the right headers while signing the wrong
parameters produces a URL that accepts an object of any size, and only a test reading the
recorded call can tell the difference.
"""

from __future__ import annotations

import pytest

from webbpulse.storage import (
    DEFAULT_EXPIRES_IN,
    MAX_EXPIRES_IN,
    PresignedUpload,
    presigned_put,
)
from webbpulse.testing import FakePresigner

BUCKET = "webbpulse-staging-uploads"

KEY = "avatars/user-1.png"

CONTENT_TYPE = "image/png"

MAX_BYTES = 2 * 1024 * 1024


def upload(**kwargs: object) -> tuple[PresignedUpload, FakePresigner]:
    """Mint one presigned PUT through a recording fake, returning both."""
    presigner = FakePresigner()
    result = presigned_put(BUCKET, KEY, CONTENT_TYPE, MAX_BYTES, client=presigner, **kwargs)  # type: ignore[arg-type]
    return result, presigner


def test_the_url_authorises_a_put_of_one_object() -> None:
    """The signature covers `put_object` on exactly the bucket and key asked for."""
    _, presigner = upload()
    call = presigner.calls[0]
    assert call["ClientMethod"] == "put_object"
    assert call["HttpMethod"] == "PUT"
    assert call["Params"]["Bucket"] == BUCKET
    assert call["Params"]["Key"] == KEY


def test_the_content_length_guard_is_signed_in() -> None:
    """`ContentLength` reaches the signature, which is what makes the ceiling enforceable."""
    _, presigner = upload()
    assert presigner.calls[0]["Params"]["ContentLength"] == MAX_BYTES, (
        "an unsigned ceiling bounds nothing; S3 enforces only what the signature covers"
    )


def test_the_content_type_is_signed_in() -> None:
    """`ContentType` reaches the signature, so a client cannot store a different type."""
    _, presigner = upload()
    assert presigner.calls[0]["Params"]["ContentType"] == CONTENT_TYPE


def test_the_returned_headers_match_what_was_signed() -> None:
    """A client sending these headers sends exactly what the signature authorises."""
    result, presigner = upload()
    params = presigner.calls[0]["Params"]
    assert result.headers == {"Content-Type": params["ContentType"], "Content-Length": str(params["ContentLength"])}


def test_the_result_carries_the_upload_back_to_the_caller() -> None:
    """Bucket, key, ceiling and lifetime come back, so a route need not repeat them."""
    result, _ = upload()
    assert (result.bucket, result.key, result.max_bytes) == (BUCKET, KEY, MAX_BYTES)
    assert result.expires_in == DEFAULT_EXPIRES_IN
    assert result.url.startswith("https://")


def test_the_default_lifetime_is_fifteen_minutes() -> None:
    """The default reaches the signer rather than being left to boto3's own default."""
    _, presigner = upload()
    assert presigner.calls[0]["ExpiresIn"] == DEFAULT_EXPIRES_IN == 900


def test_an_explicit_lifetime_reaches_the_signer() -> None:
    """A caller wanting a shorter window gets one that is actually signed for it."""
    _, presigner = upload(expires_in=60)
    assert presigner.calls[0]["ExpiresIn"] == 60


def test_a_lifetime_past_the_sigv4_ceiling_is_refused() -> None:
    """SigV4 caps a presigned URL at seven days; more would sign a URL S3 rejects."""
    with pytest.raises(ValueError, match="between 1 and"):
        presigned_put(BUCKET, KEY, CONTENT_TYPE, MAX_BYTES, MAX_EXPIRES_IN + 1, client=FakePresigner())


def test_the_sigv4_ceiling_itself_is_allowed() -> None:
    """Seven days exactly is valid, so the bound is inclusive rather than off by one."""
    _, presigner = upload(expires_in=MAX_EXPIRES_IN)
    assert presigner.calls[0]["ExpiresIn"] == MAX_EXPIRES_IN


def test_a_zero_lifetime_is_refused() -> None:
    """A URL valid for no time at all is a wiring mistake, not a tight window."""
    with pytest.raises(ValueError, match="between 1 and"):
        presigned_put(BUCKET, KEY, CONTENT_TYPE, MAX_BYTES, 0, client=FakePresigner())


def test_a_non_positive_max_bytes_is_refused() -> None:
    """A ceiling of zero or less bounds nothing, so it is refused before signing."""
    with pytest.raises(ValueError, match="positive max_bytes"):
        presigned_put(BUCKET, KEY, CONTENT_TYPE, 0, client=FakePresigner())


def test_an_empty_content_type_is_refused() -> None:
    """An unconstrained upload is not a content type, so it never reaches a signature."""
    with pytest.raises(ValueError, match="content type"):
        presigned_put(BUCKET, KEY, "", MAX_BYTES, client=FakePresigner())


def test_an_empty_bucket_is_refused() -> None:
    """A missing bucket would sign a URL pointing nowhere."""
    with pytest.raises(ValueError, match="bucket name"):
        presigned_put("", KEY, CONTENT_TYPE, MAX_BYTES, client=FakePresigner())


def test_an_empty_key_is_refused() -> None:
    """A missing key would authorise an upload with no destination."""
    with pytest.raises(ValueError, match="object key"):
        presigned_put(BUCKET, "", CONTENT_TYPE, MAX_BYTES, client=FakePresigner())


def test_nothing_is_signed_when_an_argument_is_refused() -> None:
    """Validation runs before the signer, so a rejected call makes no request at all."""
    presigner = FakePresigner()
    with pytest.raises(ValueError):
        presigned_put(BUCKET, KEY, CONTENT_TYPE, -1, client=presigner)
    assert presigner.calls == []


def test_the_upload_result_is_immutable() -> None:
    """A frozen dataclass, so a route cannot widen the ceiling after it was signed."""
    result, _ = upload()
    with pytest.raises(AttributeError):
        result.max_bytes = MAX_BYTES * 100  # type: ignore[misc]
