"""Pytest fixtures for services built on this package.

Enable them from a service's `conftest.py`::

    pytest_plugins = ["webbpulse.testing"]

The fixtures cover the two things every service otherwise reimplements: a moto-backed
DynamoDB table, and a `TestClient` whose requests carry a realistic API Gateway request
context so `client_ip` and the rate limiter exercise their production path rather than the
local fallback.

Import this module only from tests. It needs the `testing` extra.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator, Mapping
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:  # pragma: no cover - typing only
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

#: Matches `webbpulse.ratelimit.RATE_LIMIT_TABLE` under an empty prefix.
_RATE_LIMIT_TABLE = "rate-limits"


@pytest.fixture
def aws_credentials() -> Iterator[None]:
    """Install fake AWS credentials for the duration of a test.

    moto intercepts the calls, but botocore still resolves credentials before it gets there,
    and an unset region or profile makes a test fail differently on a workstation with a
    real `~/.aws/config` than in CI. Setting them explicitly is what makes the suite
    reproducible, and it is also the guard that stops a mis-scoped mock from reaching a real
    account with the caller's own credentials.
    """
    previous = dict(os.environ)
    os.environ.update(
        {
            "AWS_ACCESS_KEY_ID": "testing",
            # These are moto's conventional placeholders, not real credentials.
            "AWS_SECRET_ACCESS_KEY": "testing",
            "AWS_SECURITY_TOKEN": "testing",
            "AWS_SESSION_TOKEN": "testing",
            "AWS_DEFAULT_REGION": "us-west-2",
            "AWS_REGION": "us-west-2",
        }
    )
    # An inherited profile would otherwise take precedence over the keys just set.
    os.environ.pop("AWS_PROFILE", None)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(previous)


@pytest.fixture
def dynamodb_resource(aws_credentials: None) -> Iterator[Any]:
    """A moto-mocked DynamoDB service resource.

    The cached resource in `webbpulse.dynamodb` is cleared on both sides of the fixture, so
    a repository built inside the mock does not leak a client into the next test and a
    repository built before it is not reused inside the mock.
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

    Attribute definitions cover only the key attributes on purpose. DynamoDB rejects a
    definition for an attribute that is not part of a key or an index, which is the usual
    reason a hand-written test table fails to create.
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
    # `resource` is deliberately Any: it is a moto-backed boto3 resource and the
    # stubs cannot describe it without forcing every caller to import them.
    typed_table: Table = table
    return typed_table


@pytest.fixture
def rate_limit_table(dynamodb_resource: Any) -> Table:
    """The `rate-limits` table, shaped as the Terraform module creates it.

    Note that moto does not actually expire items on TTL, and neither does DynamoDB
    promptly. Tests must therefore assert on the window key changing rather than on an old
    item having disappeared.
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

    `payload_format="2.0"` produces the HTTP API shape (`requestContext.http.sourceIp`) and
    `"1.0"` the REST shape (`requestContext.identity.sourceIp`). Both are worth testing: a
    service that only exercises one has no coverage of the branch it will actually meet.
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

    Used as::

        def test_health(test_client):
            client = test_client(app, source_ip="198.51.100.4")
            assert client.get("/health").status_code == 200

    The default headers make every request look like it arrived through API Gateway, which
    is what makes `client_ip` return the given address rather than falling back to the
    testserver peer.
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
        # `raise_server_exceptions=False` by default so the handler in `webbpulse.http`
        # renders its 500 envelope and the test can assert on it, instead of the exception
        # escaping into the test and never exercising the handler at all.
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
