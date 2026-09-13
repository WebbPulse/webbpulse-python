"""The DynamoDB Streams entrypoint that purges a deleted user's identity rows.

Identity Lambdas run behind the AWS Lambda Web Adapter, which posts a non-HTTP invocation
as a JSON body to its pass-through path and returns the response body as the function's
result. That makes a stream handler an ordinary route: this module mounts one, and
`build_identity_router` includes it wherever the purge flow can run.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import APIRouter

    from webbpulse.identity.flows import IdentityFlows

__all__ = [
    "DEFAULT_EVENTS_PATH",
    "DEFAULT_USERS_KEY_ATTRIBUTE",
    "EVENTS_PATH_ENV",
    "LWA_PASS_THROUGH_PATH_ENV",
    "REMOVE_EVENT_NAME",
    "USERS_KEY_ATTRIBUTE_ENV",
    "arrived_through_api_gateway",
    "events_path",
    "register_user_purge_events",
    "users_key_attribute",
]

_log = logging.getLogger(__name__)

_FastAPIRequest: Any = None


def _bind_fastapi_request() -> None:
    """Put `fastapi.Request` in this module's globals for FastAPI's annotation lookup."""
    global _FastAPIRequest
    if _FastAPIRequest is None:
        from fastapi import Request as _Request

        _FastAPIRequest = _Request


DEFAULT_EVENTS_PATH: Final = "/events"

EVENTS_PATH_ENV: Final = "IDENTITY_EVENTS_PATH"

LWA_PASS_THROUGH_PATH_ENV: Final = "AWS_LWA_PASS_THROUGH_PATH"

DEFAULT_USERS_KEY_ATTRIBUTE: Final = "id"

USERS_KEY_ATTRIBUTE_ENV: Final = "IDENTITY_USERS_KEY_ATTRIBUTE"

REMOVE_EVENT_NAME: Final = "REMOVE"

_GATEWAY_REQUEST_ID_HEADER: Final = "x-amzn-requestid"


def events_path() -> str:
    """The path the stream route mounts at, absolute and without a trailing slash.

    `IDENTITY_EVENTS_PATH` wins, then `AWS_LWA_PASS_THROUGH_PATH`, which is the adapter's
    own variable and the one that actually decides where the invocation is posted, then
    `/events`, which is the adapter's default.
    """
    for name in (EVENTS_PATH_ENV, LWA_PASS_THROUGH_PATH_ENV):
        raw = os.environ.get(name, "").strip()
        if raw:
            return "/" + raw.strip("/")
    return DEFAULT_EVENTS_PATH


def users_key_attribute() -> str:
    """The attribute of the users table's key that holds the user id.

    `IDENTITY_USERS_KEY_ATTRIBUTE`, defaulting to `id`, which is what the identity standard
    names as the users table's hash key.
    """
    return os.environ.get(USERS_KEY_ATTRIBUTE_ENV, "").strip() or DEFAULT_USERS_KEY_ATTRIBUTE


def arrived_through_api_gateway(request: Any) -> bool:
    """Whether this request reached the function through API Gateway rather than the adapter's pass-through.

    A pass-through invocation carries no gateway request context and no gateway request id,
    because there was no HTTP request at the edge to describe. Either header being present
    means an HTTP caller reached the route, and the route is not for them.
    """
    from webbpulse.http import REQUEST_CONTEXT_HEADER

    headers = request.headers
    return any((headers.get(name) or "").strip() for name in (REQUEST_CONTEXT_HEADER, _GATEWAY_REQUEST_ID_HEADER))


def _user_id_from_record(record: Mapping[str, Any], *, key_attribute: str) -> str:
    """The deleted user's id from one stream record's `dynamodb.Keys`, or an empty string.

    Reads the DynamoDB attribute-value shape the stream sends, `{"S": "<id>"}`, and accepts
    a plain string for a caller that has already unwrapped it.
    """
    keys = record.get("dynamodb", {}).get("Keys", {})
    if not isinstance(keys, Mapping):
        return ""
    value = keys.get(key_attribute)
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, Mapping):
        for wrapped in value.values():
            if isinstance(wrapped, str):
                return wrapped.strip()
    return ""


def register_user_purge_events(router: APIRouter, flows: IdentityFlows) -> None:
    """Mount the stream route that purges a deleted user's identity rows.

    The route is unauthenticated by design and reachable only through the adapter's
    pass-through, so a request carrying an API Gateway context or request id gets a 404
    rather than a refusal that would confirm the route exists.

    Handles only `REMOVE` records, since an insert or an update to a users row says nothing
    about identity data. Returns the `ReportBatchItemFailures` shape, so the event source
    mapping retries only the records that raised rather than the whole batch.
    """
    from fastapi import HTTPException
    from fastapi.responses import JSONResponse

    _bind_fastapi_request()
    path = events_path()
    key_attribute = users_key_attribute()

    @router.post(path, include_in_schema=False)
    async def user_stream_events(request: _FastAPIRequest) -> JSONResponse:
        """Purge each removed user in a DynamoDB Streams batch, reporting per-record failures."""
        if arrived_through_api_gateway(request):
            raise HTTPException(status_code=404, detail="Not Found.")

        event = await request.json()
        records = event.get("Records", []) if isinstance(event, Mapping) else []
        failures: list[dict[str, str]] = []
        purged = 0

        for record in records:
            if not isinstance(record, Mapping) or record.get("eventName") != REMOVE_EVENT_NAME:
                continue
            user_id = _user_id_from_record(record, key_attribute=key_attribute)
            if not user_id:
                _log.warning(
                    "A REMOVE record carried no user id under the configured key attribute.",
                    extra={
                        "event": "identity.purge_record_unreadable",
                        "key_attribute": key_attribute,
                        "event_id": str(record.get("eventID", "")),
                    },
                )
                continue
            try:
                flows.purge_user(user_id)
            except Exception:
                _log.exception(
                    "Purging a deleted user failed; the event source mapping will retry this record.",
                    extra={
                        "event": "identity.purge_failed",
                        "user_id": user_id,
                        "event_id": str(record.get("eventID", "")),
                    },
                )
                failures.append({"itemIdentifier": str(record.get("eventID", ""))})
            else:
                purged += 1

        _log.info(
            "Handled a users table stream batch.",
            extra={
                "event": "identity.purge_batch",
                "records": len(records),
                "purged": purged,
                "failed": len(failures),
            },
        )
        return JSONResponse({"batchItemFailures": failures})
