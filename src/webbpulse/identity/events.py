"""The DynamoDB Streams entrypoint that purges a deleted user's identity rows.

Identity Lambdas run behind the AWS Lambda Web Adapter, which posts a non-HTTP invocation
as a JSON body to its pass-through path and returns the response body as the function's
result. That makes a stream handler an ordinary route: this module mounts one, and
`build_identity_router` includes it wherever the purge flow can run.

The route itself is `webbpulse.events.register_stream_consumer`, which owns the path, the
gateway guard and the batch item failure envelope. What is identity's own is here: reading
the deleted user's id out of a record's keys, and the purge itself.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Final

from webbpulse.events import (
    DEFAULT_EVENTS_PATH,
    EVENTS_PATH_ENV,
    LWA_PASS_THROUGH_PATH_ENV,
    arrived_through_api_gateway,
    events_path,
    record_id,
    register_stream_consumer,
)

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

DEFAULT_USERS_KEY_ATTRIBUTE: Final = "id"

USERS_KEY_ATTRIBUTE_ENV: Final = "IDENTITY_USERS_KEY_ATTRIBUTE"

REMOVE_EVENT_NAME: Final = "REMOVE"


def users_key_attribute() -> str:
    """The attribute of the users table's key that holds the user id.

    `IDENTITY_USERS_KEY_ATTRIBUTE`, defaulting to `id`, which is what the identity standard
    names as the users table's hash key.
    """
    return os.environ.get(USERS_KEY_ATTRIBUTE_ENV, "").strip() or DEFAULT_USERS_KEY_ATTRIBUTE


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
    key_attribute = users_key_attribute()

    def purge_record(record: Mapping[str, Any]) -> None:
        """Purge the user one `REMOVE` record deleted, raising so that record is retried."""
        user_id = _user_id_from_record(record, key_attribute=key_attribute)
        if not user_id:
            _log.warning(
                "A REMOVE record carried no user id under the configured key attribute.",
                extra={
                    "event": "identity.purge_record_unreadable",
                    "key_attribute": key_attribute,
                    "event_id": record_id(record),
                },
            )
            return
        try:
            flows.purge_user(user_id)
        except Exception:
            _log.exception(
                "Purging a deleted user failed; the event source mapping will retry this record.",
                extra={
                    "event": "identity.purge_failed",
                    "user_id": user_id,
                    "event_id": record_id(record),
                },
            )
            raise

    register_stream_consumer(
        router,
        purge_record,
        event_names={REMOVE_EVENT_NAME},
        log_event="identity.purge_batch",
    )
