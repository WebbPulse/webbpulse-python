"""Tests for the start-key cursor codec and the raw paged-read walk in `webbpulse.dynamodb`.

The codec is fed every malformed and tampered shape a client could send, and each must
raise the one typed error rather than reach DynamoDB. The walk is proved against moto and
against a scripted call that returns an empty filtered page with a cursor still set.
"""

from __future__ import annotations

import base64
import json
from decimal import Decimal
from typing import Any

import pytest
from boto3.dynamodb.conditions import Attr, Key
from boto3.dynamodb.types import Binary

from webbpulse.dynamodb import (
    MAX_START_KEY_LENGTH,
    DynamoError,
    InvalidStartKey,
    Repository,
    decode_start_key,
    encode_start_key,
    iter_all_pages,
    read_all_pages,
)
from webbpulse.testing import create_table

TABLE = "pages"


@pytest.fixture
def pages(dynamodb_resource: Any) -> Repository:
    """A repository over a freshly created `pages` table inside the moto mock."""
    create_table(dynamodb_resource, TABLE)
    repo = Repository(TABLE, prefix="")
    repo.put_many([{"pk": f"p-{index:04d}", "n": index} for index in range(25)])
    return repo


def forge(payload: Any) -> str:
    """A token carrying `payload` exactly as the encoder would pack it."""
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def test_a_string_key_round_trips() -> None:
    """The decoded key is the key that was encoded."""
    key = {"workspace_id": "w1", "issue_key": "PLAT-39"}
    assert decode_start_key(encode_start_key(key)) == key


def test_numbers_come_back_as_exact_decimals() -> None:
    """An int and a high-precision Decimal both decode to Decimal without loss."""
    key = {"pk": "a", "seq": 7, "score": Decimal("12345678901234567890.123456789")}
    decoded = decode_start_key(encode_start_key(key))
    assert decoded == {"pk": "a", "seq": Decimal(7), "score": Decimal("12345678901234567890.123456789")}
    assert decoded is not None
    assert isinstance(decoded["seq"], Decimal)


def test_binary_values_come_back_as_bytes() -> None:
    """Raw bytes and a boto3 `Binary` both survive as bytes."""
    key = {"pk": b"\x00\xffraw", "sk": Binary(b"\x01\x02")}
    assert decode_start_key(encode_start_key(key)) == {"pk": b"\x00\xffraw", "sk": b"\x01\x02"}


def test_an_index_key_with_four_attributes_round_trips() -> None:
    """A GSI's LastEvaluatedKey carries both the table and the index keys."""
    key = {"pk": "a", "sk": "b", "gsi_pk": "c", "gsi_sk": Decimal(3)}
    assert decode_start_key(encode_start_key(key)) == key


def test_the_token_is_url_safe_and_deterministic() -> None:
    """No padding or characters a query string has to escape, and the same key gives the same token."""
    key = {"pk": "a/b+c?d", "sk": b"\xfb\xff\xfe"}
    token = encode_start_key(key)
    assert token is not None
    assert token == encode_start_key(dict(reversed(list(key.items()))))
    assert set(token) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def test_no_key_and_no_token_mean_the_first_page() -> None:
    """`None` passes through both ways, and an empty key or token is treated the same."""
    assert encode_start_key(None) is None
    assert encode_start_key({}) is None
    assert decode_start_key(None) is None
    assert decode_start_key("") is None


def test_a_value_no_key_can_hold_is_refused_on_encode() -> None:
    """Floats, booleans and containers are not key types, so encoding them is a bug."""
    for value in (1.5, True, ["a"], {"a": 1}, None):
        with pytest.raises(TypeError):
            encode_start_key({"pk": value})


def test_a_scoped_token_resumes_only_its_own_scope() -> None:
    """A token minted for one workspace is refused for another and when unscoped."""
    token = encode_start_key({"pk": "a"}, scope="workspace-1")
    assert decode_start_key(token, scope="workspace-1") == {"pk": "a"}
    with pytest.raises(InvalidStartKey):
        decode_start_key(token, scope="workspace-2")
    with pytest.raises(InvalidStartKey):
        decode_start_key(token)


def test_an_unscoped_token_is_refused_where_a_scope_is_expected() -> None:
    """Dropping the scope from a token does not make it acceptable everywhere."""
    with pytest.raises(InvalidStartKey):
        decode_start_key(encode_start_key({"pk": "a"}), scope="workspace-1")


@pytest.mark.parametrize(
    "token",
    [
        "not base64 at all!",
        "%%%%",
        base64.urlsafe_b64encode(b"\xff\xfe\xfd").decode(),
        forge(["a", "b"]),
        forge("pk"),
        forge({"k": {"pk": {"S": "a"}}}),
        forge({"v": 2, "k": {"pk": {"S": "a"}}}),
        forge({"v": 1, "k": {"pk": {"S": "a"}}, "extra": True}),
        forge({"v": 1, "k": {}}),
        forge({"v": 1, "k": ["pk"]}),
        forge({"v": 1, "k": {"pk": "a"}}),
        forge({"v": 1, "k": {"pk": {"S": "a", "N": "1"}}}),
        forge({"v": 1, "k": {"pk": {"SS": ["a"]}}}),
        forge({"v": 1, "k": {"pk": {"BOOL": True}}}),
        forge({"v": 1, "k": {"pk": {"N": 1}}}),
        forge({"v": 1, "k": {"pk": {"N": "one"}}}),
        forge({"v": 1, "k": {"pk": {"N": "NaN"}}}),
        forge({"v": 1, "k": {"pk": {"N": "Infinity"}}}),
        forge({"v": 1, "k": {"pk": {"B": "not*base64"}}}),
        forge({"v": 1, "k": {"": {"S": "a"}}}),
        forge({"v": 1, "k": {f"a{index}": {"S": "a"} for index in range(5)}}),
        forge({"v": 1, "k": {"pk": {"S": "a"}}, "s": 7}),
    ],
)
def test_a_malformed_or_tampered_token_is_refused(token: str) -> None:
    """Every shape the encoder never writes raises the one typed error."""
    with pytest.raises(InvalidStartKey):
        decode_start_key(token)


def test_an_oversized_token_is_refused_before_decoding() -> None:
    """A token past the length cap costs no decoding work."""
    with pytest.raises(InvalidStartKey):
        decode_start_key("A" * (MAX_START_KEY_LENGTH + 1))


def test_the_error_is_a_dynamo_error_and_a_value_error() -> None:
    """Both existing handler families catch it, and the message never echoes the token."""
    token = forge({"v": 1, "k": {"pk": {"S": "secret-looking"}}, "s": "other"})
    with pytest.raises(InvalidStartKey) as caught:
        decode_start_key(token)
    assert isinstance(caught.value, DynamoError)
    assert isinstance(caught.value, ValueError)
    assert "secret-looking" not in str(caught.value)
    assert token not in str(caught.value)


def test_a_cursor_resumes_a_real_query_page(pages: Repository) -> None:
    """A page boundary encoded and decoded continues the scan without gaps or repeats."""
    first = pages.scan(limit=10)
    token = encode_start_key(first.last_evaluated_key)
    assert token is not None
    rest = list(pages.iter_scan(start_key=decode_start_key(token)))
    seen = [item["pk"] for item in first.items] + [item["pk"] for item in rest]
    assert sorted(seen) == [f"p-{index:04d}" for index in range(25)]


def test_iter_all_pages_follows_every_page_of_a_table_scan(pages: Repository) -> None:
    """A raw `Table.scan` is walked to the end with a small page size."""
    items = read_all_pages(pages.table.scan, Limit=4)
    assert len(items) == 25


def test_iter_all_pages_follows_a_raw_query(pages: Repository) -> None:
    """A raw `Table.query` with a key condition works the same way."""
    items = read_all_pages(pages.table.query, KeyConditionExpression=Key("pk").eq("p-0003"), Limit=1)
    assert [item["pk"] for item in items] == ["p-0003"]


def test_iter_all_pages_survives_filtered_pages(pages: Repository) -> None:
    """A filter that empties most pages still finds every match."""
    items = read_all_pages(pages.table.scan, Limit=3, FilterExpression=Attr("n").eq(24))
    assert [item["n"] for item in items] == [24]


def test_max_items_caps_the_walk(pages: Repository) -> None:
    """The cap holds across page boundaries."""
    assert len(read_all_pages(pages.table.scan, Limit=4, max_items=10)) == 10


class ScriptedCall:
    """A paged read that returns scripted responses and records each request."""

    def __init__(self, responses: list[dict[str, Any]]) -> None:
        """Hold the responses to return, in order."""
        self.responses = responses
        self.requests: list[dict[str, Any]] = []

    def __call__(self, **kwargs: Any) -> dict[str, Any]:
        """Record the request and return the next scripted response."""
        self.requests.append(kwargs)
        return self.responses[len(self.requests) - 1]


def test_an_empty_page_with_a_cursor_does_not_end_the_walk() -> None:
    """Only a missing LastEvaluatedKey ends it, and each cursor is passed on as given."""
    call = ScriptedCall(
        [
            {"Items": [], "LastEvaluatedKey": {"pk": "a"}},
            {"Items": [{"pk": "b"}], "LastEvaluatedKey": {"pk": "b"}},
            {"Items": [{"pk": "c"}]},
        ]
    )
    assert read_all_pages(call, TableName="t") == [{"pk": "b"}, {"pk": "c"}]
    assert call.requests == [
        {"TableName": "t"},
        {"TableName": "t", "ExclusiveStartKey": {"pk": "a"}},
        {"TableName": "t", "ExclusiveStartKey": {"pk": "b"}},
    ]


def test_a_caller_start_key_is_the_first_request() -> None:
    """Passing ExclusiveStartKey resumes from it."""
    call = ScriptedCall([{"Items": [{"pk": "z"}]}])
    assert read_all_pages(call, ExclusiveStartKey={"pk": "y"}) == [{"pk": "z"}]
    assert call.requests == [{"ExclusiveStartKey": {"pk": "y"}}]


def test_reaching_max_items_reads_no_further_page() -> None:
    """The walk stops on the cap even when a cursor is still set."""
    call = ScriptedCall(
        [
            {"Items": [{"pk": "a"}, {"pk": "b"}], "LastEvaluatedKey": {"pk": "b"}},
            {"Items": [{"pk": "c"}]},
        ]
    )
    assert read_all_pages(call, max_items=2) == [{"pk": "a"}, {"pk": "b"}]
    assert len(call.requests) == 1


def test_a_zero_cap_makes_no_call_and_a_negative_one_is_refused() -> None:
    """Zero is an empty result, and a negative cap is a caller bug."""
    call = ScriptedCall([])
    assert list(iter_all_pages(call, max_items=0)) == []
    assert call.requests == []
    with pytest.raises(ValueError, match="negative"):
        list(iter_all_pages(call, max_items=-1))
