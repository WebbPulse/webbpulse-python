"""`webbpulse.identity.storage.TABLES` against the Terraform identity module.

The expected specs below are a literal transcription of the `tables` default in
`platform-modules/aws//modules/identity`. They are written out rather than derived, so a
change to either side has to be made in both places deliberately.

Two of them are ahead of the module and are what a terraform change has to catch up with: the
`tenant_id-created_at-index` on `api-keys`, and the whole `share-tokens` table. Until that
lands, a deployment provisioned by the module answers `list_for_tenant` with a
`ValidationException` on the missing index, and a product using share tokens has no table at
all. See CHANGELOG.md for the exact key schema.
"""

from __future__ import annotations

from typing import Any

import pytest

from webbpulse.identity import (
    API_KEY_TENANT_INDEX,
    API_KEY_USER_INDEX,
    API_KEYS_TABLE,
    BILLING_MODE,
    CREDENTIALS_TABLE,
    IDENTITY_TOKENS_TABLE,
    IDENTITY_TTL_ATTRIBUTE,
    LOGIN_ATTEMPTS_TABLE,
    OAUTH_LINK_USER_INDEX,
    OAUTH_LINKS_TABLE,
    OAUTH_STATES_TABLE,
    PASSKEY_CREDENTIAL_INDEX,
    PASSKEYS_TABLE,
    RECOVERY_CODES_TABLE,
    REFRESH_FAMILY_INDEX,
    REFRESH_TOKENS_TABLE,
    REFRESH_USER_INDEX,
    SHARE_TOKEN_TENANT_INDEX,
    SHARE_TOKENS_TABLE,
    TABLES,
    TOTP_FACTORS_TABLE,
    WEBAUTHN_CHALLENGES_TABLE,
)

MODULE_TABLES: dict[str, dict[str, Any]] = {
    "credentials": {
        "attributes": [("user_id", "S"), ("credential_type", "S")],
        "hash_key": "user_id",
        "range_key": "credential_type",
        "global_secondary_indexes": [],
        "ttl_attribute": None,
    },
    "refresh-tokens": {
        "attributes": [("token_hash", "S"), ("family_id", "S"), ("generation", "N"), ("user_id", "S")],
        "hash_key": "token_hash",
        "range_key": None,
        "global_secondary_indexes": [
            ("family_id-generation-index", "family_id", "generation", "ALL"),
            ("user_id-family_id-index", "user_id", "family_id", "KEYS_ONLY"),
        ],
        "ttl_attribute": "expires_at",
    },
    "identity-tokens": {
        "attributes": [("token_hash", "S")],
        "hash_key": "token_hash",
        "range_key": None,
        "global_secondary_indexes": [],
        "ttl_attribute": "expires_at",
    },
    "login-attempts": {
        "attributes": [("identity_key", "S"), ("attempted_at", "S")],
        "hash_key": "identity_key",
        "range_key": "attempted_at",
        "global_secondary_indexes": [],
        "ttl_attribute": "expires_at",
    },
    "totp-factors": {
        "attributes": [("user_id", "S")],
        "hash_key": "user_id",
        "range_key": None,
        "global_secondary_indexes": [],
        "ttl_attribute": None,
    },
    "recovery-codes": {
        "attributes": [("user_id", "S"), ("code_hash", "S")],
        "hash_key": "user_id",
        "range_key": "code_hash",
        "global_secondary_indexes": [],
        "ttl_attribute": None,
    },
    "passkeys": {
        "attributes": [("user_id", "S"), ("credential_id", "S")],
        "hash_key": "user_id",
        "range_key": "credential_id",
        "global_secondary_indexes": [("credential_id-index", "credential_id", None, "ALL")],
        "ttl_attribute": None,
    },
    "webauthn-challenges": {
        "attributes": [("challenge_id", "S")],
        "hash_key": "challenge_id",
        "range_key": None,
        "global_secondary_indexes": [],
        "ttl_attribute": "expires_at",
    },
    "oauth-states": {
        "attributes": [("state", "S")],
        "hash_key": "state",
        "range_key": None,
        "global_secondary_indexes": [],
        "ttl_attribute": "expires_at",
    },
    "oauth-links": {
        "attributes": [("provider_subject", "S"), ("user_id", "S")],
        "hash_key": "provider_subject",
        "range_key": None,
        "global_secondary_indexes": [("user_id-index", "user_id", None, "ALL")],
        "ttl_attribute": None,
    },
    "api-keys": {
        "attributes": [("key_hash", "S"), ("user_id", "S"), ("tenant_id", "S"), ("created_at", "S")],
        "hash_key": "key_hash",
        "range_key": None,
        "global_secondary_indexes": [
            ("user_id-created_at-index", "user_id", "created_at", "ALL"),
            ("tenant_id-created_at-index", "tenant_id", "created_at", "ALL"),
        ],
        "ttl_attribute": None,
    },
    "share-tokens": {
        "attributes": [("token_hash", "S"), ("tenant_id", "S"), ("created_at", "S")],
        "hash_key": "token_hash",
        "range_key": None,
        "global_secondary_indexes": [("tenant_id-created_at-index", "tenant_id", "created_at", "ALL")],
        "ttl_attribute": "expires_at",
    },
}

BY_NAME = {spec.logical_name: spec for spec in TABLES}


def test_every_module_table_is_present_and_no_others() -> None:
    """`TABLES` holds exactly the twelve tables the module provisions, each once."""
    assert sorted(BY_NAME) == sorted(MODULE_TABLES)
    assert len(TABLES) == len(BY_NAME) == 12


def test_logical_names_are_the_package_constants() -> None:
    """Every logical name is the constant the stores already read them by."""
    assert sorted(BY_NAME) == sorted(
        {
            CREDENTIALS_TABLE,
            REFRESH_TOKENS_TABLE,
            IDENTITY_TOKENS_TABLE,
            LOGIN_ATTEMPTS_TABLE,
            TOTP_FACTORS_TABLE,
            RECOVERY_CODES_TABLE,
            PASSKEYS_TABLE,
            WEBAUTHN_CHALLENGES_TABLE,
            OAUTH_STATES_TABLE,
            OAUTH_LINKS_TABLE,
            API_KEYS_TABLE,
            SHARE_TOKENS_TABLE,
        }
    )


def test_index_names_are_the_package_constants() -> None:
    """Each index is named by the constant the query that uses it passes."""
    refresh = {index.name for index in BY_NAME[REFRESH_TOKENS_TABLE].global_secondary_indexes}
    assert refresh == {REFRESH_FAMILY_INDEX, REFRESH_USER_INDEX}
    assert [index.name for index in BY_NAME[PASSKEYS_TABLE].global_secondary_indexes] == [PASSKEY_CREDENTIAL_INDEX]
    assert [index.name for index in BY_NAME[OAUTH_LINKS_TABLE].global_secondary_indexes] == [OAUTH_LINK_USER_INDEX]
    assert [index.name for index in BY_NAME[API_KEYS_TABLE].global_secondary_indexes] == [
        API_KEY_USER_INDEX,
        API_KEY_TENANT_INDEX,
    ]
    assert [index.name for index in BY_NAME[SHARE_TOKENS_TABLE].global_secondary_indexes] == [SHARE_TOKEN_TENANT_INDEX]


@pytest.mark.parametrize("logical", sorted(MODULE_TABLES))
def test_spec_matches_the_terraform_module(logical: str) -> None:
    """Key schema, attributes, indexes and TTL match the module's `tables` default."""
    expected = MODULE_TABLES[logical]
    spec = BY_NAME[logical]
    assert [(a.name, a.type) for a in spec.attributes] == expected["attributes"]
    assert spec.hash_key == expected["hash_key"]
    assert spec.range_key == expected["range_key"]
    assert spec.ttl_attribute == expected["ttl_attribute"]
    assert [
        (index.name, index.hash_key, index.range_key, index.projection_type) for index in spec.global_secondary_indexes
    ] == expected["global_secondary_indexes"]


@pytest.mark.parametrize("logical", sorted(MODULE_TABLES))
def test_every_key_attribute_is_defined(logical: str) -> None:
    """DynamoDB rejects a key naming an attribute the table never defines."""
    spec = BY_NAME[logical]
    defined = {attribute.name for attribute in spec.attributes}
    assert spec.hash_key in defined
    assert spec.range_key is None or spec.range_key in defined
    for index in spec.global_secondary_indexes:
        assert index.hash_key in defined
        assert index.range_key is None or index.range_key in defined


@pytest.mark.parametrize("logical", sorted(MODULE_TABLES))
def test_no_attribute_is_defined_twice(logical: str) -> None:
    """A repeated attribute definition is a `CreateTable` validation error."""
    names = [attribute.name for attribute in BY_NAME[logical].attributes]
    assert len(names) == len(set(names))


def test_only_session_state_carries_a_ttl() -> None:
    """A credential, a factor or a passkey must never expire on a reclaim.

    `share-tokens` does expire: a share is a link handed out and forgotten, with no owner for
    whom keeping an expired row visible is worth anything, which is the opposite of the case
    `api-keys` makes for having no TTL.
    """
    expiring = {spec.logical_name for spec in TABLES if spec.ttl_attribute is not None}
    assert expiring == {
        REFRESH_TOKENS_TABLE,
        IDENTITY_TOKENS_TABLE,
        LOGIN_ATTEMPTS_TABLE,
        WEBAUTHN_CHALLENGES_TABLE,
        OAUTH_STATES_TABLE,
        SHARE_TOKENS_TABLE,
    }
    assert all(spec.ttl_attribute == IDENTITY_TTL_ATTRIBUTE for spec in TABLES if spec.ttl_attribute)


def test_create_table_request_is_the_boto3_shape() -> None:
    """The refresh table's request is the exact `create_table` keyword mapping."""
    assert BY_NAME[REFRESH_TOKENS_TABLE].create_table_request("wp-local") == {
        "TableName": "wp-local-refresh-tokens",
        "BillingMode": "PAY_PER_REQUEST",
        "KeySchema": [{"AttributeName": "token_hash", "KeyType": "HASH"}],
        "AttributeDefinitions": [
            {"AttributeName": "token_hash", "AttributeType": "S"},
            {"AttributeName": "family_id", "AttributeType": "S"},
            {"AttributeName": "generation", "AttributeType": "N"},
            {"AttributeName": "user_id", "AttributeType": "S"},
        ],
        "GlobalSecondaryIndexes": [
            {
                "IndexName": REFRESH_FAMILY_INDEX,
                "KeySchema": [
                    {"AttributeName": "family_id", "KeyType": "HASH"},
                    {"AttributeName": "generation", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": REFRESH_USER_INDEX,
                "KeySchema": [
                    {"AttributeName": "user_id", "KeyType": "HASH"},
                    {"AttributeName": "family_id", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "KEYS_ONLY"},
            },
        ],
    }


@pytest.mark.parametrize("logical", sorted(MODULE_TABLES))
def test_every_request_is_on_demand(logical: str) -> None:
    """The module bills every identity table on demand, so the local copy does too."""
    assert BY_NAME[logical].create_table_request()["BillingMode"] == BILLING_MODE == "PAY_PER_REQUEST"


def test_a_table_with_no_index_omits_the_key_entirely() -> None:
    """`GlobalSecondaryIndexes` is absent rather than empty, which `create_table` rejects."""
    assert "GlobalSecondaryIndexes" not in BY_NAME[CREDENTIALS_TABLE].create_table_request()


@pytest.mark.parametrize("logical", sorted(MODULE_TABLES))
def test_the_prefix_builds_the_deployed_name(logical: str) -> None:
    """Names follow the estate's `<prefix>-<logical>` rule, and an empty prefix is bare."""
    assert BY_NAME[logical].table_name("carmodpicker-staging") == f"carmodpicker-staging-{logical}"
    assert BY_NAME[logical].table_name("") == logical


@pytest.mark.parametrize("logical", sorted(MODULE_TABLES))
def test_time_to_live_request_follows_the_ttl_attribute(logical: str) -> None:
    """A table with a TTL gets an enabling request; one without gets `None`."""
    spec = BY_NAME[logical]
    request = spec.time_to_live_request("wp-local")
    if spec.ttl_attribute is None:
        assert request is None
    else:
        assert request == {
            "TableName": f"wp-local-{logical}",
            "TimeToLiveSpecification": {"Enabled": True, "AttributeName": spec.ttl_attribute},
        }


def test_the_specs_create_against_dynamodb(aws_credentials: None) -> None:
    """Every request is one DynamoDB accepts, with the indexes it declares."""
    import boto3
    from moto import mock_aws

    with mock_aws():
        client = boto3.client("dynamodb", region_name="us-west-2")
        for spec in TABLES:
            client.create_table(**spec.create_table_request("wp-local"))
            ttl = spec.time_to_live_request("wp-local")
            if ttl is not None:
                client.update_time_to_live(**ttl)
        described = client.describe_table(TableName=f"wp-local-{REFRESH_TOKENS_TABLE}")["Table"]
        assert {index["IndexName"] for index in described["GlobalSecondaryIndexes"]} == {
            REFRESH_FAMILY_INDEX,
            REFRESH_USER_INDEX,
        }
        assert (
            client.describe_time_to_live(TableName=f"wp-local-{REFRESH_TOKENS_TABLE}")["TimeToLiveDescription"][
                "AttributeName"
            ]
            == IDENTITY_TTL_ATTRIBUTE
        )
