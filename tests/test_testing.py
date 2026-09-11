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
