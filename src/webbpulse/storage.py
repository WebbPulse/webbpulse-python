"""Presigned S3 uploads and downloads, so a browser moves a file to and from S3 and never
through a Lambda.

`presigned_put` mints a URL the client PUTs to directly, bounded by a content type and a
content length the signature itself covers. `presigned_get` mints the reading half, a URL
that authorises one object for a bounded window with optional response headers signed in.
Nothing opens a connection at import. Needs the `dynamodb` extra, which is where boto3 lives.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Final, Protocol

if TYPE_CHECKING:  # pragma: no cover
    from mypy_boto3_s3.client import S3Client

__all__ = [
    "DEFAULT_EXPIRES_IN",
    "MAX_EXPIRES_IN",
    "PresignedDownload",
    "PresignedUpload",
    "S3Presigner",
    "presigned_get",
    "presigned_put",
    "reset_client_cache",
]

DEFAULT_EXPIRES_IN: Final = 900
"""Fifteen minutes: long enough for a slow upload to start, short enough that a leaked URL ages out."""

MAX_EXPIRES_IN: Final = 604_800
"""SigV4's own ceiling on a presigned URL, seven days. Asking for more produces a URL that is rejected."""


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
