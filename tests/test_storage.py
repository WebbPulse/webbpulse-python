"""Tests for the presigned upload and download helpers in `webbpulse.storage`.

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
    PresignedDownload,
    PresignedUpload,
    presigned_get,
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


def download(**kwargs: object) -> tuple[PresignedDownload, FakePresigner]:
    """Mint one presigned GET through a recording fake, returning both."""
    presigner = FakePresigner()
    result = presigned_get(BUCKET, KEY, client=presigner, **kwargs)  # type: ignore[arg-type]
    return result, presigner


def test_the_download_url_authorises_a_get_of_one_object() -> None:
    """The signature covers `get_object` on exactly the bucket and key asked for."""
    _, presigner = download()
    call = presigner.calls[0]
    assert call["ClientMethod"] == "get_object"
    assert call["HttpMethod"] == "GET"
    assert call["Params"]["Bucket"] == BUCKET
    assert call["Params"]["Key"] == KEY


def test_the_download_result_carries_the_object_back_to_the_caller() -> None:
    """Bucket, key and lifetime come back, so a route need not repeat them."""
    result, _ = download()
    assert (result.bucket, result.key) == (BUCKET, KEY)
    assert result.expires_in == DEFAULT_EXPIRES_IN
    assert result.url.startswith("https://")


def test_the_download_default_lifetime_is_fifteen_minutes() -> None:
    """The default reaches the signer rather than being left to boto3's own default."""
    _, presigner = download()
    assert presigner.calls[0]["ExpiresIn"] == DEFAULT_EXPIRES_IN == 900


def test_an_explicit_download_lifetime_reaches_the_signer() -> None:
    """A caller wanting a shorter window gets one that is actually signed for it."""
    _, presigner = download(expires_in=60)
    assert presigner.calls[0]["ExpiresIn"] == 60


def test_no_response_headers_are_signed_when_none_are_asked_for() -> None:
    """A plain download signs the bucket and key alone, so S3 serves the stored metadata."""
    _, presigner = download()
    assert set(presigner.calls[0]["Params"]) == {"Bucket", "Key"}


def test_the_response_content_type_is_signed_in() -> None:
    """`ResponseContentType` reaches the signature, so a holder cannot change what S3 returns."""
    _, presigner = download(response_content_type=CONTENT_TYPE)
    assert presigner.calls[0]["Params"]["ResponseContentType"] == CONTENT_TYPE


def test_the_response_content_disposition_is_signed_in() -> None:
    """`ResponseContentDisposition` reaches the signature, which is what forces the filename."""
    disposition = 'attachment; filename="avatar.png"'
    _, presigner = download(response_content_disposition=disposition)
    assert presigner.calls[0]["Params"]["ResponseContentDisposition"] == disposition


def test_both_response_headers_reach_the_signature_together() -> None:
    """Asking for both signs both, rather than one overwriting the other."""
    _, presigner = download(response_content_type=CONTENT_TYPE, response_content_disposition="inline")
    params = presigner.calls[0]["Params"]
    assert (params["ResponseContentType"], params["ResponseContentDisposition"]) == (CONTENT_TYPE, "inline")


def test_a_download_lifetime_past_the_sigv4_ceiling_is_refused() -> None:
    """SigV4 caps a presigned URL at seven days; more would sign a URL S3 rejects."""
    with pytest.raises(ValueError, match="between 1 and"):
        presigned_get(BUCKET, KEY, MAX_EXPIRES_IN + 1, client=FakePresigner())


def test_the_sigv4_ceiling_is_allowed_for_a_download() -> None:
    """Seven days exactly is valid, so the bound is inclusive rather than off by one."""
    _, presigner = download(expires_in=MAX_EXPIRES_IN)
    assert presigner.calls[0]["ExpiresIn"] == MAX_EXPIRES_IN


def test_a_zero_download_lifetime_is_refused() -> None:
    """A URL valid for no time at all is a wiring mistake, not a tight window."""
    with pytest.raises(ValueError, match="between 1 and"):
        presigned_get(BUCKET, KEY, 0, client=FakePresigner())


def test_an_empty_bucket_is_refused_for_a_download() -> None:
    """A missing bucket would sign a URL pointing nowhere."""
    with pytest.raises(ValueError, match="bucket name"):
        presigned_get("", KEY, client=FakePresigner())


def test_an_empty_key_is_refused_for_a_download() -> None:
    """A missing key would authorise a read with no object."""
    with pytest.raises(ValueError, match="object key"):
        presigned_get(BUCKET, "", client=FakePresigner())


def test_an_empty_response_content_type_is_refused() -> None:
    """An empty override is a wiring mistake, and S3 would serve an empty type for it."""
    with pytest.raises(ValueError, match="response_content_type"):
        presigned_get(BUCKET, KEY, response_content_type="", client=FakePresigner())


def test_an_empty_response_content_disposition_is_refused() -> None:
    """An empty override is a wiring mistake, so it never reaches a signature."""
    with pytest.raises(ValueError, match="response_content_disposition"):
        presigned_get(BUCKET, KEY, response_content_disposition="", client=FakePresigner())


def test_nothing_is_signed_when_a_download_argument_is_refused() -> None:
    """Validation runs before the signer, so a rejected call makes no request at all."""
    presigner = FakePresigner()
    with pytest.raises(ValueError):
        presigned_get(BUCKET, KEY, 0, client=presigner)
    assert presigner.calls == []


def test_the_download_result_is_immutable() -> None:
    """A frozen dataclass, so a route cannot widen the window after it was signed."""
    result, _ = download()
    with pytest.raises(AttributeError):
        result.expires_in = MAX_EXPIRES_IN  # type: ignore[misc]
