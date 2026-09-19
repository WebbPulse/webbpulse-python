"""Tests for `webbpulse.testing`.

These fixtures are the package's public test surface, so they are themselves tested.
"""

from __future__ import annotations

import json
import os
from typing import Any

import pytest
from fastapi import FastAPI, Request

from webbpulse.http import REQUEST_CONTEXT_HEADER, client_ip
from webbpulse.testing import create_table, make_request_context_headers


def test_aws_credentials_are_set_and_restored(aws_credentials: None) -> None:
    """Placeholder credentials, so a mis-scoped mock cannot reach a real account."""
    assert os.environ["AWS_ACCESS_KEY_ID"] == "testing"
    assert os.environ["AWS_DEFAULT_REGION"] == "us-west-2"
    assert os.environ["AWS_REGION"] == "us-west-2"
    assert "AWS_PROFILE" not in os.environ


def test_the_credential_fixture_restores_the_previous_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The fixture must not leak its placeholders into the rest of the session."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "the-original-value")

    from webbpulse.testing import aws_credentials as fixture

    generator = fixture.__wrapped__()  # type: ignore[attr-defined]
    next(generator)
    assert os.environ["AWS_ACCESS_KEY_ID"] == "testing"
    with pytest.raises(StopIteration):
        next(generator)
    assert os.environ["AWS_ACCESS_KEY_ID"] == "the-original-value"


def test_create_table_makes_a_usable_hash_key_table(dynamodb_resource: Any) -> None:
    """`create_table` builds a hash key table that accepts and returns an item."""
    table = create_table(dynamodb_resource, "things")
    table.put_item(Item={"pk": "a", "value": 1})
    assert table.get_item(Key={"pk": "a"})["Item"]["value"] == 1


def test_create_table_supports_a_range_key(dynamodb_resource: Any) -> None:
    """`create_table` builds a composite key table that is queryable by hash key."""
    table = create_table(dynamodb_resource, "events", hash_key="pk", range_key="sk")
    table.put_item(Item={"pk": "a", "sk": "1"})
    table.put_item(Item={"pk": "a", "sk": "2"})
    from boto3.dynamodb.conditions import Key as KeyCondition

    result = table.query(KeyConditionExpression=KeyCondition("pk").eq("a"))
    assert result["Count"] == 2


def test_create_table_enables_ttl_when_asked(dynamodb_resource: Any) -> None:
    """`ttl_attribute` turns on time to live for that attribute."""
    create_table(dynamodb_resource, "expiring", ttl_attribute="expires_at")
    described = dynamodb_resource.meta.client.describe_time_to_live(TableName="expiring")
    spec = described["TimeToLiveDescription"]
    assert spec["TimeToLiveStatus"] == "ENABLED"
    assert spec["AttributeName"] == "expires_at"


def test_create_table_builds_a_global_secondary_index(dynamodb_resource: Any) -> None:
    """A GSI and its extra attribute definitions come through and are queryable."""
    table = create_table(
        dynamodb_resource,
        "indexed",
        attribute_definitions=[{"AttributeName": "owner", "AttributeType": "S"}],
        global_secondary_indexes=[
            {
                "IndexName": "by-owner",
                "KeySchema": [{"AttributeName": "owner", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    )
    table.put_item(Item={"pk": "a", "owner": "alice"})
    from boto3.dynamodb.conditions import Key as KeyCondition

    result = table.query(IndexName="by-owner", KeyConditionExpression=KeyCondition("owner").eq("alice"))
    assert result["Count"] == 1


def test_create_table_enables_a_stream(dynamodb_resource: Any) -> None:
    """`stream_specification` is passed through, so a consumer test has a stream to read."""
    create_table(
        dynamodb_resource,
        "streamed",
        stream_specification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
    )
    described = dynamodb_resource.meta.client.describe_table(TableName="streamed")["Table"]
    assert described["StreamSpecification"]["StreamViewType"] == "NEW_AND_OLD_IMAGES"


def test_create_table_accepts_a_whole_request_mapping(dynamodb_resource: Any) -> None:
    """A caller's own `CreateTable` mapping wins over the built defaults, under `name`."""
    table = create_table(
        dynamodb_resource,
        "wholesale",
        request={
            "TableName": "ignored",
            "KeySchema": [{"AttributeName": "id", "KeyType": "HASH"}],
            "AttributeDefinitions": [{"AttributeName": "id", "AttributeType": "N"}],
        },
    )
    assert table.name == "wholesale"
    assert table.key_schema == [{"AttributeName": "id", "KeyType": "HASH"}]
    table.put_item(Item={"id": 1})
    assert table.get_item(Key={"id": 1})["Item"]["id"] == 1


def test_create_table_keeps_a_ttl_alongside_a_request_mapping(dynamodb_resource: Any) -> None:
    """TTL is a separate call, so it still applies when the request mapping is used."""
    create_table(
        dynamodb_resource,
        "wholesale-expiring",
        ttl_attribute="expires_at",
        request={"TableClass": "STANDARD"},
    )
    described = dynamodb_resource.meta.client.describe_time_to_live(TableName="wholesale-expiring")
    assert described["TimeToLiveDescription"]["AttributeName"] == "expires_at"


def test_create_table_deduplicates_attribute_definitions(dynamodb_resource: Any) -> None:
    """Redeclaring a key attribute overrides it rather than sending DynamoDB a duplicate."""
    table = create_table(
        dynamodb_resource,
        "renumbered",
        hash_key="pk",
        attribute_definitions=[{"AttributeName": "pk", "AttributeType": "N"}],
    )
    table.put_item(Item={"pk": 7})
    assert table.get_item(Key={"pk": 7})["Item"]["pk"] == 7


def test_dynamodb_reset_hooks_default_to_nothing(dynamodb_reset_hooks: list[Any]) -> None:
    """The overridable fixture is empty by default, so the package reset is the only one."""
    assert dynamodb_reset_hooks == []


def test_dynamodb_resource_runs_reset_hooks_on_both_sides() -> None:
    """An overridden hook runs once before the mock opens and once after it closes."""
    calls: list[str] = []

    from webbpulse.testing import dynamodb_resource as fixture

    generator = fixture.__wrapped__(None, [lambda: calls.append("reset")])  # type: ignore[attr-defined]
    resource = next(generator)
    assert calls == ["reset"]
    create_table(resource, "hooked")
    with pytest.raises(StopIteration):
        next(generator)
    assert calls == ["reset", "reset"]


def test_the_rate_limit_table_matches_the_module_constants(rate_limit_table: Any) -> None:
    """The fixture table's name, key schema and TTL attribute match `webbpulse.ratelimit`."""
    from webbpulse.ratelimit import RATE_LIMIT_TABLE, TTL_ATTRIBUTE

    assert rate_limit_table.name == RATE_LIMIT_TABLE
    assert rate_limit_table.key_schema == [{"AttributeName": "pk", "KeyType": "HASH"}]
    described = rate_limit_table.meta.client.describe_time_to_live(TableName=RATE_LIMIT_TABLE)
    assert described["TimeToLiveDescription"]["AttributeName"] == TTL_ATTRIBUTE


def test_request_context_headers_use_the_http_api_shape() -> None:
    """Payload format 2.0 puts the source IP at requestContext.http.sourceIp."""
    headers = make_request_context_headers("198.51.100.4")
    context = json.loads(headers[REQUEST_CONTEXT_HEADER])
    assert context["http"]["sourceIp"] == "198.51.100.4"


def test_request_context_headers_support_the_rest_api_shape() -> None:
    """Payload format 1.0 puts it at requestContext.identity.sourceIp instead."""
    headers = make_request_context_headers("198.51.100.5", payload_format="1.0")
    context = json.loads(headers[REQUEST_CONTEXT_HEADER])
    assert context["identity"]["sourceIp"] == "198.51.100.5"
    assert "http" not in context


def test_request_context_headers_reject_an_unknown_payload_format() -> None:
    """An unsupported payload format raises rather than emitting a silently wrong shape."""
    with pytest.raises(ValueError, match="payload_format"):
        make_request_context_headers("198.51.100.6", payload_format="3.0")


def test_request_context_headers_merge_extra_keys() -> None:
    """`extra` keys are merged into the encoded request context."""
    headers = make_request_context_headers("198.51.100.7", extra={"apiId": "abc123"})
    assert json.loads(headers[REQUEST_CONTEXT_HEADER])["apiId"] == "abc123"


def _ip_app() -> FastAPI:
    """Build an app with one route that reports the resolved client IP."""
    app = FastAPI()

    @app.get("/ip")
    async def ip(request: Request) -> dict[str, str]:
        """Return the client IP as `webbpulse.http` resolves it."""
        return {"ip": client_ip(request)}

    return app


def test_the_client_fixture_makes_requests_look_like_api_gateway(test_client: Any) -> None:
    """The fixture injects an API Gateway context header, so `client_ip` reads the source IP."""
    client = test_client(_ip_app(), source_ip="203.0.113.55")
    assert client.get("/ip").json()["ip"] == "203.0.113.55"


def test_the_client_fixture_supports_the_rest_payload_shape(test_client: Any) -> None:
    """`payload_format="1.0"` still resolves the source IP through the fixture."""
    client = test_client(_ip_app(), source_ip="203.0.113.56", payload_format="1.0")
    assert client.get("/ip").json()["ip"] == "203.0.113.56"


def test_the_client_fixture_renders_error_envelopes_rather_than_raising(
    test_client: Any,
) -> None:
    """`raise_server_exceptions=False` by default, so the 500 handler is what gets tested."""
    from webbpulse.http import create_app

    app = create_app(service="svc", version="1.0.0")

    @app.get("/boom")
    async def boom() -> None:
        """Raise so the app's 500 handler runs."""
        raise RuntimeError("deliberate")

    response = test_client(app).get("/boom")
    assert response.status_code == 500
    assert response.json()["success"] is False


def test_the_fake_queue_records_requests_and_answers_message_ids() -> None:
    """A producer test asserts on the body that was sent, not on a mock's call object."""
    from webbpulse.testing import FakeQueue

    queue = FakeQueue()

    first = queue.send_message(QueueUrl="q", MessageBody='{"a":1}')
    second = queue.send_message(QueueUrl="q", MessageBody='{"a":2}')

    assert first["MessageId"] == "msg-1"
    assert second["MessageId"] == "msg-2"
    assert queue.bodies == [{"a": 1}, {"a": 2}]
    assert queue.last_body == {"a": 2}


def test_the_fake_queue_spends_its_failure_budget_then_succeeds() -> None:
    """That is how a test exercises a producer's own retry or error handling."""
    from webbpulse.testing import FakeQueue

    queue = FakeQueue(failing=2)

    for _ in range(2):
        with pytest.raises(RuntimeError):
            queue.send_message(QueueUrl="q", MessageBody="{}")

    assert queue.send_message(QueueUrl="q", MessageBody="{}")["MessageId"] == "msg-1"
    assert len(queue.requests) == 3


def test_an_empty_fake_queue_reports_no_last_body() -> None:
    """Inspecting a queue nothing was sent through must not raise."""
    from webbpulse.testing import FakeQueue

    assert FakeQueue().last_body is None


def test_the_fake_webhook_sender_scripts_responses_then_falls_back() -> None:
    """Scripted responses are consumed one per attempt, and `default` answers the rest."""
    from webbpulse.events.webhooks import WebhookResponse
    from webbpulse.testing import FakeWebhookSender

    sender = FakeWebhookSender([503, WebhookResponse(status_code=500)], default=200)

    first = sender.post("https://e.test", body=b"{}", headers={"A": "1"}, timeout=1.0)
    second = sender.post("https://e.test", body=b"{}", headers={}, timeout=1.0)
    third = sender.post("https://e.test", body=b"{}", headers={}, timeout=1.0)

    assert [first.status_code, second.status_code, third.status_code] == [503, 500, 200]
    assert sender.attempts == 3
    assert sender.calls[0]["headers"] == {"A": "1"}


def test_an_unscripted_fake_webhook_sender_always_delivers() -> None:
    """A fake with no script is the happy path, so a test need not spell it out."""
    from webbpulse.testing import FakeWebhookSender

    sender = FakeWebhookSender()

    assert sender.post("https://e.test", body=b"{}", headers={}, timeout=1.0).delivered
    assert sender.last_call is not None


def test_an_unused_fake_webhook_sender_reports_no_last_call() -> None:
    """Inspecting a sender nothing was posted through must not raise."""
    from webbpulse.testing import FakeWebhookSender

    assert FakeWebhookSender().last_call is None
