"""Tests for `webbpulse.testing.enforce_primary_keys` and the `primary_keys_only` fixture.

Each covered operation is driven against a moto table whose GSI key moto would otherwise
accept beside the primary key.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError

from webbpulse.dynamodb import Repository
from webbpulse.testing import CheckedKey, create_table, enforce_primary_keys

_TABLE = "guarded"
_EXACT = {"pk": {"S": "a"}}
_EXTRA = {"pk": {"S": "a"}, "owner": {"S": "o"}}


@pytest.fixture
def _primary_keys_only() -> list[CheckedKey]:
    """Turn the suite-wide guard off here, so each test chooses whether it is on."""
    return []


@pytest.fixture
def client(dynamodb_resource: Any) -> Any:
    """A low-level client over a hash-keyed moto table with a GSI on `owner`, holding one item."""
    create_table(
        dynamodb_resource,
        _TABLE,
        attribute_definitions=[{"AttributeName": "owner", "AttributeType": "S"}],
        global_secondary_indexes=[
            {
                "IndexName": "by-owner",
                "KeySchema": [{"AttributeName": "owner", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    )
    low_level = boto3.client("dynamodb", region_name="us-west-2")
    low_level.put_item(TableName=_TABLE, Item={"pk": {"S": "a"}, "owner": {"S": "o"}})
    return low_level


def _calls(client: Any, key: dict[str, Any]) -> dict[str, Callable[[], Any]]:
    """Every covered operation, keyed by name, addressing the item through `key`."""
    return {
        "GetItem": lambda: client.get_item(TableName=_TABLE, Key=key),
        "UpdateItem": lambda: client.update_item(
            TableName=_TABLE,
            Key=key,
            UpdateExpression="SET #n = :n",
            ExpressionAttributeNames={"#n": "note"},
            ExpressionAttributeValues={":n": {"S": "x"}},
        ),
        "DeleteItem": lambda: client.delete_item(TableName=_TABLE, Key=key),
        "BatchGetItem": lambda: client.batch_get_item(RequestItems={_TABLE: {"Keys": [key]}}),
        "BatchWriteItem": lambda: client.batch_write_item(RequestItems={_TABLE: [{"DeleteRequest": {"Key": key}}]}),
        "TransactGetItems": lambda: client.transact_get_items(
            TransactItems=[{"Get": {"TableName": _TABLE, "Key": key}}]
        ),
        "TransactWriteItems.Update": lambda: client.transact_write_items(
            TransactItems=[
                {
                    "Update": {
                        "TableName": _TABLE,
                        "Key": key,
                        "UpdateExpression": "SET #n = :n",
                        "ExpressionAttributeNames": {"#n": "note"},
                        "ExpressionAttributeValues": {":n": {"S": "x"}},
                    }
                }
            ]
        ),
        "TransactWriteItems.Delete": lambda: client.transact_write_items(
            TransactItems=[{"Delete": {"TableName": _TABLE, "Key": key}}]
        ),
        "TransactWriteItems.ConditionCheck": lambda: client.transact_write_items(
            TransactItems=[
                {
                    "ConditionCheck": {
                        "TableName": _TABLE,
                        "Key": key,
                        "ConditionExpression": "attribute_exists(pk)",
                    }
                }
            ]
        ),
    }


_OPERATIONS = sorted(_calls(None, _EXACT))


@pytest.mark.parametrize("operation", _OPERATIONS)
def test_moto_alone_accepts_a_key_carrying_an_index_attribute(client: Any, operation: str) -> None:
    """The gap the guard closes: without it moto takes the GSI key beside the primary one."""
    _calls(client, _EXTRA)[operation]()


@pytest.mark.parametrize("operation", _OPERATIONS)
def test_a_key_carrying_an_index_attribute_is_refused(
    client: Any, primary_keys_only: list[CheckedKey], operation: str
) -> None:
    """Every covered operation raises DynamoDB's own ValidationException."""
    with pytest.raises(ClientError) as raised:
        _calls(client, _EXTRA)[operation]()
    error = raised.value.response["Error"]
    assert error["Code"] == "ValidationException"
    assert error["Message"] == "The provided key element does not match the schema"
    assert primary_keys_only[-1] == CheckedKey(operation.split(".")[0], _TABLE, frozenset({"pk", "owner"}))


@pytest.mark.parametrize("operation", _OPERATIONS)
def test_the_exact_primary_key_is_accepted(client: Any, primary_keys_only: list[CheckedKey], operation: str) -> None:
    """A key naming the primary key alone goes through to moto untouched."""
    _calls(client, _EXACT)[operation]()
    assert primary_keys_only == [CheckedKey(operation.split(".")[0], _TABLE, frozenset({"pk"}))]


def test_a_key_missing_part_of_a_composite_key_is_refused(dynamodb_resource: Any) -> None:
    """A partial key is the same mismatch as an extra attribute."""
    table = create_table(dynamodb_resource, "composite", range_key="sk")
    with enforce_primary_keys(), pytest.raises(ClientError, match="does not match the schema"):
        table.get_item(Key={"pk": "a"})


def test_a_boto3_table_and_a_repository_are_both_guarded(client: Any, dynamodb_resource: Any) -> None:
    """The handler sits in botocore, so resource and package calls are caught too."""
    table = dynamodb_resource.Table(_TABLE)
    with enforce_primary_keys() as checked:
        assert table.get_item(Key={"pk": "a"})["Item"]["owner"] == "o"
        with pytest.raises(ClientError, match="does not match the schema"):
            table.get_item(Key={"pk": "a", "owner": "o"})
        with pytest.raises(ClientError, match="does not match the schema"):
            Repository(_TABLE).get({"pk": "a", "owner": "o"})
    assert [entry.names for entry in checked] == [
        frozenset({"pk"}),
        frozenset({"pk", "owner"}),
        frozenset({"pk", "owner"}),
    ]


def test_the_guard_is_off_outside_its_block(client: Any) -> None:
    """Leaving the block restores moto's own behaviour."""
    with enforce_primary_keys():
        pass
    client.get_item(TableName=_TABLE, Key=_EXTRA)


def test_a_table_moto_cannot_describe_is_left_to_moto(client: Any) -> None:
    """An unknown table surfaces moto's own not-found error, not a schema mismatch."""
    with enforce_primary_keys(), pytest.raises(ClientError) as raised:
        client.get_item(TableName="missing", Key=_EXACT)
    assert raised.value.response["Error"]["Code"] == "ResourceNotFoundException"


def test_a_recreated_table_is_checked_against_its_new_schema(dynamodb_resource: Any) -> None:
    """The per-table cache is refreshed before a mismatch is reported."""
    create_table(dynamodb_resource, "reshaped")
    with enforce_primary_keys():
        dynamodb_resource.Table("reshaped").get_item(Key={"pk": "a"})
        dynamodb_resource.meta.client.delete_table(TableName="reshaped")
        table = create_table(dynamodb_resource, "reshaped", hash_key="id")
        table.get_item(Key={"id": "a"})
