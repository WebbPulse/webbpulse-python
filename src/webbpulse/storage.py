"""Presigned S3 uploads and downloads, so a browser moves a file to and from S3 and never
through a Lambda.

`presigned_put` mints a URL the client PUTs to directly, bounded by a content type and a
content length the signature itself covers. `presigned_get` mints the reading half, a URL
that authorises one object for a bounded window with optional response headers signed in.
`UPLOAD_CONTENT_TYPES` with `is_allowed_upload` is the allow list to check a declared type
against before signing anything, and `disposition_for` decides whether the download renders
in the browser or is forced to save.

Nothing opens a connection at import. Needs the `dynamodb` extra, which is where boto3 lives.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Final, Protocol
from urllib.parse import quote

if TYPE_CHECKING:  # pragma: no cover
    from mypy_boto3_s3.client import S3Client

__all__ = [
    "DEFAULT_EXPIRES_IN",
    "INLINE_CONTENT_TYPES",
    "MAX_EXPIRES_IN",
    "UPLOAD_CONTENT_TYPES",
    "PresignedDownload",
    "PresignedUpload",
    "S3Presigner",
    "disposition_for",
    "is_allowed_upload",
    "presigned_get",
    "presigned_put",
    "reset_client_cache",
]

DEFAULT_EXPIRES_IN: Final = 900
"""Fifteen minutes: long enough for a slow upload to start, short enough that a leaked URL ages out."""

MAX_EXPIRES_IN: Final = 604_800
"""SigV4's own ceiling on a presigned URL, seven days. Asking for more produces a URL that is rejected."""

UPLOAD_CONTENT_TYPES: Final = frozenset(
    {
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/webp",
        "image/svg+xml",
        "application/pdf",
        "text/plain",
        "text/csv",
        "application/json",
        "application/zip",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.ms-excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-powerpoint",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    }
)
"""The content types a user upload may declare: what an attachment on an issue or a comment actually is.

An allow list rather than a deny list, because a deny list is a list of the attacks already
thought of and every product rewrites it slightly differently. The four screenshot formats
plus `image/webp`, PDF, plain text, CSV, JSON, zip, and the six Office types in both the
legacy and the OOXML spellings, since a browser sends whichever one the source application
stamped on the file.

What is deliberately absent is the point. `text/html` is missing because an HTML attachment
served from the application's own origin is stored cross-site scripting, and no content type
check upstream of that makes it safe. `application/octet-stream` is missing because it is
what a browser sends when it recognises nothing, so admitting it admits everything and the
allow list stops meaning anything. `image/svg+xml` is in the list but is scripted markup, not
a picture: serve it through `disposition_for`, which forces it to download rather than render,
and never inline it on the application's own origin.

The list is what a type may *declare*, which is not what the bytes are. A client signs the
type it claims and S3 enforces the claim, so this stops a caller storing an object the
application will later serve as HTML; it does not stop a caller storing a PNG that is really
something else. Sniffing the stored bytes is the separate control, and a product needing one
does it after the upload.
"""

INLINE_CONTENT_TYPES: Final = frozenset(
    {
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/webp",
        "application/pdf",
        "text/plain",
    }
)
"""The types `disposition_for` renders in place rather than forcing to download.

Every one is something a browser displays natively and nothing here executes in the page's
origin. `image/svg+xml` is an upload type but not an inline one, which is the single
distinction worth keeping between the two sets: an SVG carries script, and rendering one
inline from the application's origin runs it there.
"""

_FALLBACK_FILENAME: Final = "download"
"""What a filename becomes when nothing usable survives cleaning, so the header is never malformed."""


class S3Presigner(Protocol):
    """The one S3 call the presigners make, typed structurally.

    The signature is boto3's, so a real client satisfies it with no adapter and a test can
    pass a one-method fake.
    """

    def generate_presigned_url(
        self,
        ClientMethod: str,
        Params: dict[str, Any],
        ExpiresIn: int,
        HttpMethod: str | None = None,
    ) -> str:
        """Return a URL that authorises `ClientMethod` with exactly `Params` until it expires."""
        ...


@dataclass(frozen=True, slots=True)
class PresignedUpload:
    """A presigned PUT and the headers the client has to send with it.

    `headers` is not advisory. Every one of them is inside the signature, so a request that
    omits or changes one is rejected by S3 with a 403 rather than being accepted and stored
    differently from what was authorised. Hand the whole dataclass to the frontend.
    """

    url: str
    headers: dict[str, str]
    bucket: str
    key: str
    max_bytes: int
    expires_in: int


@dataclass(frozen=True, slots=True)
class PresignedDownload:
    """A presigned GET and what it authorises.

    The URL carries its own authorisation, so anyone holding it reads the object until it
    expires. Treat it as a bearer credential for one key: hand it to the client that asked,
    keep `expires_in` short, and never log it or store it beside the record it belongs to.
    """

    url: str
    bucket: str
    key: str
    expires_in: int


@lru_cache(maxsize=4)
def _client(region_name: str | None, endpoint_url: str | None) -> S3Client:
    """Create the S3 client once per process, per region and endpoint.

    Signature version 4 is pinned rather than left to the ambient configuration, since a
    presigned URL signed with v2 is rejected outright by a bucket in a region that never
    supported it.
    """
    import boto3
    from botocore.config import Config

    client: S3Client = boto3.client(
        "s3",
        region_name=region_name,
        endpoint_url=endpoint_url,
        config=Config(signature_version="s3v4"),
    )
    return client


def reset_client_cache() -> None:
    """Clear the cached client. Tests need this between moto contexts."""
    _client.cache_clear()


def _normalise_content_type(content_type: str) -> str:
    """One content type folded to its bare lowercase `type/subtype`.

    A browser sends `text/plain; charset=utf-8` and `TEXT/PLAIN` for the same thing, and a
    membership test on the raw string calls both of them unknown, so the parameters and the
    case go before anything is compared.
    """
    return content_type.partition(";")[0].strip().lower()


def is_allowed_upload(content_type: str) -> bool:
    """Whether `content_type` is one an upload may declare.

    The check to run before signing a `presigned_put`, not after the object lands: the type
    goes into the signature, so refusing it here is what keeps the object from existing at
    all, while a check afterwards is a check on something already stored under a key the
    application will serve.

    Any parameters are ignored and the comparison is case-insensitive, so
    `text/plain; charset=utf-8` is `text/plain`. An empty or blank string is `False` rather
    than an error, since a browser that recognises nothing sends nothing and that is a refusal
    and not a fault.
    """
    return _normalise_content_type(content_type) in UPLOAD_CONTENT_TYPES


def disposition_for(content_type: str, filename: str) -> str:
    """The `Content-Disposition` to serve an object of `content_type` under `filename`.

    `inline` for the handful of types a browser displays safely and `attachment` for
    everything else, which is the decision every product with an attachment makes and makes
    slightly differently. Defaulting to `attachment` is what makes an unrecognised type safe:
    a downloaded file is inert, while an inline one is rendered in the application's own
    origin, so the unknown case has to be the conservative one. `image/svg+xml` is an allowed
    upload and still an attachment here, because an SVG is scripted markup.

    The filename is quoted per RFC 6266. An ASCII name is sent as a quoted string with the
    backslashes and quotes inside it escaped, so a name containing a quote cannot close the
    parameter early and inject another one. A name that is not ASCII is sent twice: a
    transliterated `filename` a legacy client can still read, and the RFC 5987 `filename*`
    carrying the real UTF-8 name percent-encoded, which every current browser prefers. Any
    directory separator and any control character is stripped, since the filename is a
    display name and a header value, never a path.

    Args:
        content_type: The stored object's type. Parameters and case are ignored.
        filename: The name to offer the download under.

    Returns:
        A complete header value, ready for `presigned_get(response_content_disposition=...)`.
    """
    kind = "inline" if _normalise_content_type(content_type) in INLINE_CONTENT_TYPES else "attachment"
    safe = _safe_filename(filename)
    ascii_name = _ascii_filename(safe)
    disposition = f'{kind}; filename="{_quote_filename(ascii_name)}"'
    if safe != ascii_name:
        disposition += f"; filename*=UTF-8''{quote(safe, safe='')}"
    return disposition


def _safe_filename(filename: str) -> str:
    """`filename` reduced to a display name safe to put in a header, or the fallback.

    Everything up to the last separator is dropped, so `../../etc/passwd` is `passwd`: the
    name labels a download and a client that joins it onto a path is the reason a traversal is
    worth never emitting. Both separators count, since a Windows client sends the backslash.
    Control characters go for the reason a header value cannot carry a newline, and a name
    with nothing left becomes `download`, so the header is always well formed.
    """
    base = filename.rpartition("/")[2].rpartition("\\")[2]
    cleaned = "".join(character for character in base if character.isprintable()).strip()
    return cleaned or _FALLBACK_FILENAME


def _ascii_filename(filename: str) -> str:
    """`filename` transliterated to ASCII for the plain `filename` parameter.

    A Latin letter carrying an accent decomposes to the bare letter, which keeps `resume.pdf`
    readable for `résumé.pdf`. A name written entirely in another script leaves nothing but its
    extension behind, and a bare `.zip` names no file, so the fallback stands in whenever
    nothing outside the extension survives and `filename*` carries the real name.
    """
    folded = unicodedata.normalize("NFKD", filename).encode("ascii", "ignore").decode("ascii").strip()
    stem, separator, suffix = folded.rpartition(".")
    if separator and not stem:
        return f"{_FALLBACK_FILENAME}.{suffix}" if suffix else _FALLBACK_FILENAME
    return folded or _FALLBACK_FILENAME


def _quote_filename(filename: str) -> str:
    """Escape a filename for the inside of RFC 6266's `quoted-string`.

    Only the quote needs escaping by the time a name reaches here, since `_safe_filename` has
    already taken the backslash as a path separator and dropped everything before it. An
    unescaped quote would close the parameter early and let a second one be injected into the
    header, which is the whole reason the name is not interpolated raw.
    """
    return filename.replace('"', '\\"')


def presigned_put(
    bucket: str,
    key: str,
    content_type: str,
    max_bytes: int,
    expires_in: int = DEFAULT_EXPIRES_IN,
    *,
    client: S3Presigner | None = None,
    region_name: str | None = None,
    endpoint_url: str | None = None,
) -> PresignedUpload:
    """Mint a presigned `PUT` for one object, bounded by its type and its size.

    `content_type` and `max_bytes` are signed into the URL as `Content-Type` and
    `ContentLength`, so S3 refuses a request that declares anything else. That is the point:
    an unbounded presigned PUT lets whoever holds the URL store an object of any size and any
    type under a key the application will later serve, and neither a check in the frontend nor
    a check after the upload prevents it. The guard is a ceiling the client declares and S3
    enforces, not a byte count S3 measures, so a client that lies about `Content-Length` is
    rejected at the header rather than after the body.

    Args:
        bucket: The destination bucket.
        key: The object key the URL authorises, and only that key.
        content_type: The exact `Content-Type` the client must send.
        max_bytes: The `Content-Length` the client must declare, which is the upload ceiling.
        expires_in: Seconds the URL stays valid, at most `MAX_EXPIRES_IN`.
        client: An S3 client or a fake. Defaults to one cached per region and endpoint.
        region_name: Region for the default client.
        endpoint_url: Endpoint for the default client, for a local S3 stand-in.

    Raises:
        ValueError: When `bucket`, `key` or `content_type` is empty, when `max_bytes` is not
            positive, or when `expires_in` is outside 1 to `MAX_EXPIRES_IN`. Each would mint a
            URL that S3 rejects or that bounds nothing, so it is refused before signing.
    """
    if not bucket:
        raise ValueError("presigned_put needs a bucket name.")
    if not key:
        raise ValueError("presigned_put needs an object key.")
    if not content_type:
        raise ValueError("presigned_put needs a content type; an unconstrained upload is not one.")
    if max_bytes <= 0:
        raise ValueError(f"presigned_put needs a positive max_bytes, got {max_bytes}.")
    if not 1 <= expires_in <= MAX_EXPIRES_IN:
        raise ValueError(f"expires_in must be between 1 and {MAX_EXPIRES_IN} seconds, got {expires_in}.")

    presigner = client if client is not None else _client(region_name, endpoint_url)
    url = presigner.generate_presigned_url(
        ClientMethod="put_object",
        Params={
            "Bucket": bucket,
            "Key": key,
            "ContentType": content_type,
            "ContentLength": max_bytes,
        },
        ExpiresIn=expires_in,
        HttpMethod="PUT",
    )
    return PresignedUpload(
        url=url,
        headers={"Content-Type": content_type, "Content-Length": str(max_bytes)},
        bucket=bucket,
        key=key,
        max_bytes=max_bytes,
        expires_in=expires_in,
    )


def presigned_get(
    bucket: str,
    key: str,
    expires_in: int = DEFAULT_EXPIRES_IN,
    *,
    response_content_type: str | None = None,
    response_content_disposition: str | None = None,
    client: S3Presigner | None = None,
    region_name: str | None = None,
    endpoint_url: str | None = None,
) -> PresignedDownload:
    """Mint a presigned `GET` for one object, valid for a bounded window.

    This is the reading half of `presigned_put`: a private bucket stays private and a browser
    still fetches the object directly, so the bytes never pass through a Lambda that would
    buffer them and pay for the time. The URL authorises exactly one key and nothing else, and
    it is a bearer credential until it expires, so the window is the whole guard.

    The optional response headers are signed in the same way the upload's bounds are, as
    `ResponseContentType` and `ResponseContentDisposition`. S3 then returns them with the
    object, which is how a stored key serves under a human filename or is forced to download
    rather than render inline. Because they are inside the signature, a holder of the URL
    cannot change them to have S3 serve the same bytes under a different type.

    Args:
        bucket: The source bucket.
        key: The object key the URL authorises, and only that key.
        expires_in: Seconds the URL stays valid, at most `MAX_EXPIRES_IN`.
        response_content_type: A `Content-Type` S3 returns with the object, signed in.
        response_content_disposition: A `Content-Disposition` S3 returns with the object,
            signed in, for a download filename or an attachment.
        client: An S3 client or a fake. Defaults to one cached per region and endpoint.
        region_name: Region for the default client.
        endpoint_url: Endpoint for the default client, for a local S3 stand-in.

    Raises:
        ValueError: When `bucket` or `key` is empty, when either response header is given as
            an empty string, or when `expires_in` is outside 1 to `MAX_EXPIRES_IN`. Each would
            mint a URL that S3 rejects or that names nothing, so it is refused before signing.
    """
    if not bucket:
        raise ValueError("presigned_get needs a bucket name.")
    if not key:
        raise ValueError("presigned_get needs an object key.")
    if response_content_type is not None and not response_content_type:
        raise ValueError("response_content_type was given as empty; omit it instead.")
    if response_content_disposition is not None and not response_content_disposition:
        raise ValueError("response_content_disposition was given as empty; omit it instead.")
    if not 1 <= expires_in <= MAX_EXPIRES_IN:
        raise ValueError(f"expires_in must be between 1 and {MAX_EXPIRES_IN} seconds, got {expires_in}.")

    params: dict[str, Any] = {"Bucket": bucket, "Key": key}
    if response_content_type is not None:
        params["ResponseContentType"] = response_content_type
    if response_content_disposition is not None:
        params["ResponseContentDisposition"] = response_content_disposition

    presigner = client if client is not None else _client(region_name, endpoint_url)
    url = presigner.generate_presigned_url(
        ClientMethod="get_object",
        Params=params,
        ExpiresIn=expires_in,
        HttpMethod="GET",
    )
    return PresignedDownload(url=url, bucket=bucket, key=key, expires_in=expires_in)
