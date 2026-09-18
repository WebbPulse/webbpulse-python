"""Tests for the presigned upload and download helpers in `webbpulse.storage`.

The assertions that matter are about what goes into the signature. A presigned PUT's guard
is the `Params` it was signed with, so returning the right headers while signing the wrong
parameters produces a URL that accepts an object of any size, and only a test reading the
recorded call can tell the difference.

The allow list and the disposition are the other half: both decide what the application will
later serve back, so the assertions worth making are that the dangerous types stay out and
that an unrecognised one downloads rather than renders.
"""

from __future__ import annotations

import pytest

from webbpulse.storage import (
    DEFAULT_EXPIRES_IN,
    INLINE_CONTENT_TYPES,
    MAX_EXPIRES_IN,
    UPLOAD_CONTENT_TYPES,
    PresignedDownload,
    PresignedUpload,
    disposition_for,
    is_allowed_upload,
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


@pytest.mark.parametrize(
    "content_type",
    [
        "image/png",
        "image/jpeg",
        "application/pdf",
        "text/plain",
        "text/csv",
        "application/json",
        "application/zip",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ],
)
def test_the_ordinary_attachment_types_are_allowed(content_type: str) -> None:
    """What an attachment on an issue or a comment actually is passes the allow list."""
    assert is_allowed_upload(content_type)


def test_html_is_not_an_allowed_upload() -> None:
    """An HTML attachment served from the application's own origin is stored cross-site scripting."""
    assert not is_allowed_upload("text/html"), "no check downstream of storing HTML makes it safe"


def test_octet_stream_is_not_an_allowed_upload() -> None:
    """It is what a browser sends when it recognises nothing, so admitting it admits everything."""
    assert not is_allowed_upload("application/octet-stream")


@pytest.mark.parametrize(
    "content_type",
    ["application/x-msdownload", "text/javascript", "application/xhtml+xml", "image/x-icon"],
)
def test_an_unlisted_type_is_refused(content_type: str) -> None:
    """An allow list, so anything nobody put on it is refused rather than admitted by default."""
    assert not is_allowed_upload(content_type)


def test_the_allow_list_carries_no_executable_or_markup_type() -> None:
    """The property that matters holds for the whole list, not just the types a test names."""
    forbidden = {"text/html", "application/xhtml+xml", "text/javascript", "application/octet-stream"}
    assert not (UPLOAD_CONTENT_TYPES & forbidden)


def test_parameters_and_case_are_ignored() -> None:
    """A browser sends `text/plain; charset=utf-8` and `TEXT/PLAIN` for the same thing."""
    assert is_allowed_upload("text/plain; charset=utf-8")
    assert is_allowed_upload("TEXT/PLAIN")
    assert is_allowed_upload("  image/png  ")


@pytest.mark.parametrize("content_type", ["", "   "])
def test_an_empty_content_type_is_not_allowed(content_type: str) -> None:
    """A browser that recognises nothing sends nothing, which is a refusal and not a fault."""
    assert not is_allowed_upload(content_type)


def test_every_inline_type_is_also_an_allowed_upload() -> None:
    """Rendering a type the application will not accept in the first place makes no sense."""
    assert INLINE_CONTENT_TYPES <= UPLOAD_CONTENT_TYPES


def test_svg_uploads_but_never_renders_inline() -> None:
    """An SVG is scripted markup, so it is storable and always forced to download."""
    assert is_allowed_upload("image/svg+xml")
    assert "image/svg+xml" not in INLINE_CONTENT_TYPES
    assert disposition_for("image/svg+xml", "diagram.svg").startswith("attachment;")


@pytest.mark.parametrize("content_type", ["image/png", "image/jpeg", "application/pdf", "text/plain"])
def test_a_browser_renderable_type_is_inline(content_type: str) -> None:
    """What a browser displays natively is shown in place rather than downloaded."""
    assert disposition_for(content_type, "file.bin").startswith("inline;")


@pytest.mark.parametrize("content_type", ["application/zip", "text/csv", "application/json"])
def test_everything_else_is_an_attachment(content_type: str) -> None:
    """The default is the conservative one, because a downloaded file is inert."""
    assert disposition_for(content_type, "file.bin").startswith("attachment;")


def test_an_unknown_type_downloads_rather_than_renders() -> None:
    """A type nobody listed must not be rendered in the application's own origin."""
    assert disposition_for("application/octet-stream", "thing.bin").startswith("attachment;")


def test_the_disposition_carries_the_filename() -> None:
    """The whole point of the header, so a download lands under the name the user gave it."""
    assert disposition_for("image/png", "photo.png") == 'inline; filename="photo.png"'


def test_a_quote_in_a_filename_cannot_close_the_parameter() -> None:
    """An unescaped quote would end the quoted string and let a second parameter be injected."""
    disposition = disposition_for("application/zip", 'ev"il.zip')
    assert disposition == 'attachment; filename="ev\\"il.zip"'


def test_no_bare_backslash_reaches_the_quoted_string() -> None:
    """A backslash left in would escape whatever follows it, the closing quote included.

    A backslash is a path separator here and is stripped with the rest of the path rather
    than escaped, which is the stronger answer: nothing survives to need escaping.
    """
    disposition = disposition_for("text/csv", "a\\b.csv")

    assert disposition == 'attachment; filename="b.csv"'
    assert "\\" not in disposition


def test_a_path_traversal_is_reduced_to_a_name() -> None:
    """The filename is a display name and a header value, never a path."""
    assert disposition_for("text/plain", "../../etc/passwd") == 'inline; filename="passwd"'


def test_a_windows_path_is_reduced_to_a_name() -> None:
    """A Windows client sends the backslash separator, so both separators are stripped."""
    assert disposition_for("application/zip", "C:\\Users\\ada\\report.zip") == 'attachment; filename="report.zip"'


def test_a_control_character_cannot_reach_the_header() -> None:
    """A newline in a header value is a response splitting primitive."""
    assert "\n" not in disposition_for("application/json", "a\nb.json")
    assert disposition_for("application/json", "a\nb.json") == 'attachment; filename="ab.json"'


def test_a_non_ascii_name_is_sent_both_ways() -> None:
    """RFC 6266: a transliterated `filename` a legacy client reads, and the real UTF-8 in `filename*`."""
    disposition = disposition_for("application/pdf", "résumé.pdf")

    assert disposition == "inline; filename=\"resume.pdf\"; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf"


def test_a_name_with_no_ascii_form_still_names_a_file() -> None:
    """A bare extension names no file, so the fallback stands in and `filename*` carries the name."""
    disposition = disposition_for("application/zip", "文件.zip")

    assert disposition == "attachment; filename=\"download.zip\"; filename*=UTF-8''%E6%96%87%E4%BB%B6.zip"


def test_an_ascii_name_gets_no_extended_parameter() -> None:
    """`filename*` is for the names that need it, so an ASCII name is sent once."""
    assert "filename*" not in disposition_for("image/png", "photo.png")


def test_an_empty_filename_is_still_a_well_formed_header() -> None:
    """A header is emitted whatever came in, since a malformed one is worse than a generic name."""
    assert disposition_for("text/csv", "") == 'attachment; filename="download"'


def test_the_disposition_ignores_content_type_parameters() -> None:
    """`text/plain; charset=utf-8` renders inline the way bare `text/plain` does."""
    assert disposition_for("text/plain; charset=utf-8", "notes.txt").startswith("inline;")


def test_the_disposition_is_what_presigned_get_signs() -> None:
    """The two compose: the header decided here is the one S3 is made to return."""
    disposition = disposition_for("application/zip", "bundle.zip")
    _, presigner = download(response_content_disposition=disposition)

    assert presigner.calls[0]["Params"]["ResponseContentDisposition"] == disposition
