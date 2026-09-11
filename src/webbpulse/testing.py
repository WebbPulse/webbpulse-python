"""Pytest fixtures for services built on this package.

Enable them with `pytest_plugins = ["webbpulse.testing"]`. They cover a moto-backed
DynamoDB table and a `TestClient` whose requests carry a realistic API Gateway request
context. Import only from tests; it needs the `testing` extra.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator, Mapping
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from mypy_boto3_dynamodb.service_resource import Table

__all__ = [
    "aws_credentials",
    "create_table",
    "dynamodb_resource",
    "make_request_context_headers",
    "rate_limit_table",
    "test_client",
]

_RATE_LIMIT_TABLE = "rate-limits"


@pytest.fixture
def aws_credentials() -> Iterator[None]:
    """Install fake AWS credentials and region for the duration of a test.

    botocore resolves credentials before moto intercepts anything, so setting them keeps
    the suite reproducible and stops a mis-scoped mock from reaching a real account.
    """
    previous = dict(os.environ)
    os.environ.update(
        {
            "AWS_ACCESS_KEY_ID": "testing",
            "AWS_SECRET_ACCESS_KEY": "testing",
            "AWS_SECURITY_TOKEN": "testing",
            "AWS_SESSION_TOKEN": "testing",
            "AWS_DEFAULT_REGION": "us-west-2",
            "AWS_REGION": "us-west-2",
        }
    )
    os.environ.pop("AWS_PROFILE", None)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(previous)


@pytest.fixture
def dynamodb_resource(aws_credentials: None) -> Iterator[Any]:
    """A moto-mocked DynamoDB service resource.

    The cached resource in `webbpulse.dynamodb` is cleared on both sides, so no client
    leaks into or out of the mock.
    """
    import boto3
    from moto import mock_aws

    from webbpulse.dynamodb import reset_resource_cache

    reset_resource_cache()
    with mock_aws():
        yield boto3.resource("dynamodb", region_name="us-west-2")
    reset_resource_cache()


def create_table(
    resource: Any,
    name: str,
    *,
    hash_key: str = "pk",
    range_key: str | None = None,
    ttl_attribute: str | None = None,
) -> Table:
    """Create one on-demand table and wait for it to exist.

    Attribute definitions cover only the key attributes, since DynamoDB rejects a
    definition for anything that is not part of a key or an index.
    """
    attributes: list[dict[str, str]] = [{"AttributeName": hash_key, "AttributeType": "S"}]
    schema: list[dict[str, str]] = [{"AttributeName": hash_key, "KeyType": "HASH"}]
    if range_key:
        attributes.append({"AttributeName": range_key, "AttributeType": "S"})
        schema.append({"AttributeName": range_key, "KeyType": "RANGE"})

    table = resource.create_table(
        TableName=name,
        KeySchema=schema,
        AttributeDefinitions=attributes,
        BillingMode="PAY_PER_REQUEST",
    )
    table.wait_until_exists()
    if ttl_attribute:
        resource.meta.client.update_time_to_live(
            TableName=name,
            TimeToLiveSpecification={"Enabled": True, "AttributeName": ttl_attribute},
        )
    typed_table: Table = table
    return typed_table


@pytest.fixture
def rate_limit_table(dynamodb_resource: Any) -> Table:
    """The `rate-limits` table, shaped as the Terraform module creates it.

    Neither moto nor DynamoDB expires items promptly, so assert on the window key changing
    rather than on an old item having gone.
    """
    from webbpulse.ratelimit import TTL_ATTRIBUTE

    return create_table(dynamodb_resource, _RATE_LIMIT_TABLE, ttl_attribute=TTL_ATTRIBUTE)


def make_request_context_headers(
    source_ip: str = "203.0.113.10",
    *,
    payload_format: str = "2.0",
    extra: Mapping[str, Any] | None = None,
) -> dict[str, str]:
    """Build the `x-amzn-request-context` header the Web Adapter injects.

    `payload_format="2.0"` produces the HTTP API shape and `"1.0"` the REST shape, and both
    are worth exercising.
    """
    if payload_format == "2.0":
        context: dict[str, Any] = {
            "requestId": "test-request-id",
            "http": {"method": "GET", "path": "/", "sourceIp": source_ip},
        }
    elif payload_format == "1.0":
        context = {"requestId": "test-request-id", "identity": {"sourceIp": source_ip}}
    else:
        raise ValueError(f"payload_format must be '1.0' or '2.0', got {payload_format!r}.")
    if extra:
        context.update(extra)

    from webbpulse.http import REQUEST_CONTEXT_HEADER

    return {REQUEST_CONTEXT_HEADER: json.dumps(context)}


@pytest.fixture
def test_client() -> Iterator[Any]:
    """A factory returning a `TestClient` for an app, with an API Gateway context header.

    The default headers make `client_ip` return the given `source_ip` rather than falling
    back to the testserver peer. Every client the factory builds is closed at teardown.
    """
    from fastapi.testclient import TestClient

    clients: list[TestClient] = []

    def factory(
        app: FastAPI,
        *,
        source_ip: str = "203.0.113.10",
        payload_format: str = "2.0",
        raise_server_exceptions: bool = False,
        **kwargs: Any,
    ) -> TestClient:
        """Build a client for `app` whose requests carry the API Gateway context header.

        `raise_server_exceptions` is off by default so the 500 envelope is rendered and
        can be asserted on.
        """
        client = TestClient(
            app,
            headers=make_request_context_headers(source_ip, payload_format=payload_format),
            raise_server_exceptions=raise_server_exceptions,
            **kwargs,
        )
        clients.append(client)
        return client

    yield factory
    for client in clients:
        client.close()
