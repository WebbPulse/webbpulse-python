"""Presigned S3 uploads, so a browser sends a file to S3 and never through a Lambda.

`presigned_put` mints a URL the client PUTs to directly, bounded by a content type and a
content length the signature itself covers. Nothing opens a connection at import. Needs the
`dynamodb` extra, which is where boto3 lives.
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
    "PresignedUpload",
    "S3Presigner",
    "presigned_put",
    "reset_client_cache",
]

DEFAULT_EXPIRES_IN: Final = 900
"""Fifteen minutes: long enough for a slow upload to start, short enough that a leaked URL ages out."""

MAX_EXPIRES_IN: Final = 604_800
"""SigV4's own ceiling on a presigned URL, seven days. Asking for more produces a URL that is rejected."""


class S3Presigner(Protocol):
    """The one S3 call `presigned_put` makes, typed structurally.

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
