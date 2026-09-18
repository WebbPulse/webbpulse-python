"""Pytest fixtures for services built on this package.

Enable them with `pytest_plugins = ["webbpulse.testing"]`. They cover a moto-backed
DynamoDB table, a `TestClient` whose requests carry a realistic API Gateway request
context, and a locally signing KMS stand-in. `FakeIdempotencyStore`, `FakePresigner`,
`FakeQueue` and `FakeWebhookSender` are the doubles for the seams a handler reaches the
outside world through, so a test needs neither moto nor a socket. Import only from tests; it
needs the `testing` extra, and `FakeKms` additionally needs `cryptography`, which the
`identity` extra brings in.
"""

from __future__ import annotations

import json
import os
from collections.abc import Collection, Iterator, Mapping
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from mypy_boto3_dynamodb.service_resource import Table

__all__ = [
    "FakeIdempotencyStore",
    "FakeKms",
    "FakePresigner",
    "FakeQueue",
    "FakeWebhookSender",
    "aws_credentials",
    "create_table",
    "dynamodb_resource",
    "fake_kms",
    "make_request_context_headers",
    "rate_limit_table",
    "rsa_key",
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


class FakeKms:
    """A stand-in for the KMS client the identity token service signs with.

    It signs for real with private keys held in the process, so a token it mints verifies
    against the JWKs built from the same keys and a test can assert on the whole chain
    rather than on a stubbed signature. It implements the two calls the token service makes,
    `get_public_key` and `sign`, with KMS's own keyword-only argument spelling.

    Signing is over the digest the caller passes, without re-hashing it, which is what
    `MessageType="DIGEST"` means in the KMS contract, and the signature is the raw PKCS #1
    v1.5 octet string KMS returns.
    """

    def __init__(
        self,
        keys: Any,
        der: bytes | None = None,
        *,
        key_spec: str = "RSA_2048",
        failing: Collection[str] = (),
    ) -> None:
        """Hold the signing keys and what to report about them.

        Args:
            keys: One `RSAPrivateKey`, or a mapping of key id to `RSAPrivateKey` for a test
                that rotates or serves several. A single key answers for every key id asked
                for, which is what a single-key test wants.
            der: The DER SubjectPublicKeyInfo to report for a single key. Derived from the
                key when omitted; pass it only to report a public key that does not match
                what the fake signs with.
            key_spec: The `KeySpec` to report. `RSA_2048` matches `KMS_KEY_SPEC`.
            failing: Key ids whose `get_public_key` raises, for exercising the token
                service's handling of a signing key that has gone away.

        Raises:
            ValueError: When `der` is passed alongside a mapping of keys, where it could
                only apply to one of them.
        """
        if isinstance(keys, Mapping):
            if der is not None:
                raise ValueError("der applies to a single key; with a key mapping the DER is derived per key.")
            self._keys: dict[str, Any] = dict(keys)
            self._single: Any | None = None
        else:
            self._keys = {}
            self._single = keys
        self._der = der
        self._key_spec = key_spec
        self._failing = frozenset(failing)
        self.get_public_key_calls: list[str] = []
        self.sign_calls: list[dict[str, Any]] = []

    def _key_for(self, key_id: str) -> Any:
        """The private key serving `key_id`, or raise `KeyError` for an unknown one."""
        if self._single is not None:
            return self._single
        return self._keys[key_id]

    def der_for(self, key_id: str) -> bytes:
        """The DER SubjectPublicKeyInfo this fake reports for `key_id`.

        Useful for asserting on a `kid`, which `kid_for_der` derives from exactly these
        bytes.
        """
        if self._single is not None and self._der is not None:
            return self._der
        from cryptography.hazmat.primitives import serialization

        public_bytes: bytes = (
            self._key_for(key_id)
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        return public_bytes

    def get_public_key(self, *, KeyId: str) -> dict[str, Any]:
        """Answer the `kms:GetPublicKey` shape for one key, recording the call.

        Raises `RuntimeError` naming the key when it is in `failing`, standing in for the
        `NotFoundException` a deleted key produces.
        """
        self.get_public_key_calls.append(KeyId)
        if KeyId in self._failing:
            raise RuntimeError(f"NotFoundException: key {KeyId} does not exist")

        from webbpulse.identity import KMS_SIGNING_ALGORITHM

        return {
            "KeyId": KeyId,
            "PublicKey": self.der_for(KeyId),
            "KeySpec": self._key_spec,
            "KeyUsage": "SIGN_VERIFY",
            "SigningAlgorithms": [KMS_SIGNING_ALGORITHM],
        }

    def sign(self, *, KeyId: str, Message: bytes, MessageType: str, SigningAlgorithm: str) -> dict[str, Any]:
        """Sign the prehashed message the way KMS would, recording the call.

        The arguments are recorded on `sign_calls` before signing, so a test can assert the
        token service asked for `DIGEST` and `RSASSA_PKCS1_V1_5_SHA_256` rather than
        trusting that it did.
        """
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, utils

        self.sign_calls.append(
            {
                "KeyId": KeyId,
                "Message": Message,
                "MessageType": MessageType,
                "SigningAlgorithm": SigningAlgorithm,
            }
        )
        signature = self._key_for(KeyId).sign(Message, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
        return {"KeyId": KeyId, "Signature": signature, "SigningAlgorithm": SigningAlgorithm}


@pytest.fixture
def fake_kms(rsa_key: Any) -> FakeKms:
    """A locally signing KMS stand-in for one test, over the module's shared RSA key.

    Depends on `rsa_key`, so a module wanting several keys builds `FakeKms` directly with a
    mapping rather than through this fixture.
    """
    return FakeKms(rsa_key)


@pytest.fixture(scope="module")
def rsa_key() -> Any:
    """One 2048-bit RSA key for the module. Generation is slow enough to be worth sharing."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeIdempotencyStore:
    """An in-process stand-in for `webbpulse.dynamodb.IdempotencyStore`, without a table.

    It answers `claim` and `release` with the same signatures, so a handler typed against the
    real store takes this one with no adapter. Claims are held in a dict with the monotonic
    deadline each was taken under, and expiry is evaluated on read: unlike DynamoDB's TTL,
    which deletes on its own schedule, this one forgets a key the moment its window passes, so
    a test asserting that a replay after expiry wins need not sleep on a background sweeper.

    `claims` records every key `claim` was called with, winners and losers alike, which is what
    a test asserting that a handler claimed before doing the work reads.
    """

    def __init__(self, *, now: Any | None = None) -> None:
        """Start with nothing claimed, optionally over a caller-supplied clock.

        Args:
            now: A zero-argument callable returning seconds as a float, defaulting to
                `time.monotonic`. Pass one to drive expiry forward without sleeping.
        """
        import time

        self._now = now if now is not None else time.monotonic
        self._deadlines: dict[str, float] = {}
        self.claims: list[str] = []

    def claim(self, key: str, ttl_seconds: float) -> bool:
        """Claim `key`, answering whether this caller won, exactly as the real store does.

        Raises:
            ValueError: When `ttl_seconds` is not positive, matching the real store.
        """
        if ttl_seconds <= 0:
            raise ValueError(f"claim needs a positive ttl_seconds, got {ttl_seconds}.")
        self.claims.append(key)
        moment = self._now()
        deadline = self._deadlines.get(key)
        if deadline is not None and deadline > moment:
            return False
        self._deadlines[key] = moment + ttl_seconds
        return True

    def release(self, key: str) -> None:
        """Drop a claim. Releasing a key nobody claimed is not an error."""
        self._deadlines.pop(key, None)


class FakePresigner:
    """A stand-in for the S3 client `webbpulse.storage.presigned_put` signs with.

    It returns a deterministic URL rather than a signed one and records the arguments it was
    asked to sign, which is the assertion worth making: a presigned PUT's guard lives entirely
    in the `Params` that go into the signature, so a test proves the content type and the
    length were signed in rather than merely returned as headers.
    """

    def __init__(self, base_url: str = "https://s3.example.invalid") -> None:
        """Hold the host the generated URLs are built under and start with no calls."""
        self.base_url = base_url
        self.calls: list[dict[str, Any]] = []

    def generate_presigned_url(
        self,
        ClientMethod: str,
        Params: dict[str, Any],
        ExpiresIn: int,
        HttpMethod: str | None = None,
    ) -> str:
        """Record the request and answer a URL naming the bucket and key it authorises."""
        self.calls.append(
            {
                "ClientMethod": ClientMethod,
                "Params": dict(Params),
                "ExpiresIn": ExpiresIn,
                "HttpMethod": HttpMethod,
            }
        )
        return f"{self.base_url}/{Params['Bucket']}/{Params['Key']}?X-Amz-Expires={ExpiresIn}"


class FakeQueue:
    """A stand-in for the SQS client `webbpulse.events.enqueue` sends through.

    It records every `send_message` request whole, so a test asserts on the body that was
    sent, on the FIFO group and deduplication ids, and on the order of the sends, rather
    than on a mock's call object. It satisfies `webbpulse.events.QueueClient` structurally,
    so no inheritance and no moto.

    `failing` makes the next sends raise, which is how a test exercises a producer's own
    error handling: pass the number of sends that should fail before one succeeds.
    """

    def __init__(self, *, failing: int = 0) -> None:
        """Start with an empty log and `failing` sends set to raise."""
        self.requests: list[dict[str, Any]] = []
        self._failing = failing
        self._sent = 0

    def send_message(self, **kwargs: Any) -> dict[str, Any]:
        """Record one send and answer the `MessageId` shape SQS returns.

        Raises `RuntimeError` while the failure budget lasts, standing in for the
        `ClientError` a throttled or missing queue produces.
        """
        self.requests.append(dict(kwargs))
        if self._failing > 0:
            self._failing -= 1
            raise RuntimeError("ServiceUnavailable: the queue did not accept the message")
        self._sent += 1
        return {"MessageId": f"msg-{self._sent}", "MD5OfMessageBody": "0" * 32}

    @property
    def bodies(self) -> list[Any]:
        """Every sent `MessageBody`, parsed from JSON, in the order it was sent."""
        return [json.loads(request["MessageBody"]) for request in self.requests]

    @property
    def last_body(self) -> Any:
        """The most recent parsed `MessageBody`, or `None` when nothing was sent."""
        return self.bodies[-1] if self.requests else None


class FakeWebhookSender:
    """A stand-in for the transport `webbpulse.events.webhooks.WebhookDispatcher` posts through.

    Every call is recorded on `calls` with the url, the body and the headers, so a test can
    verify the signature the dispatcher produced by re-deriving it, and the responses are
    scripted: `responses` is consumed one per attempt, and once it runs out `default`
    answers the rest. That is what makes a retry test deterministic, with no sleeping and no
    socket.

    It satisfies `WebhookSender` structurally, so it needs neither `httpx` nor inheritance.
    """

    def __init__(
        self,
        responses: Collection[Any] = (),
        *,
        default: Any = None,
    ) -> None:
        """Hold the scripted responses and the one to answer with after they run out.

        Args:
            responses: The `WebhookResponse` values to answer with, one per attempt, in
                order. An `int` is accepted as shorthand for a response with that status.
            default: What to answer once `responses` is exhausted. A 200 when omitted, so a
                fake with no script always delivers.
        """
        from webbpulse.events.webhooks import WebhookResponse

        self.calls: list[dict[str, Any]] = []
        self._scripted = [_as_webhook_response(item) for item in responses]
        self._default = _as_webhook_response(default) if default is not None else WebhookResponse(status_code=200)

    def post(self, url: str, *, body: bytes, headers: Mapping[str, str], timeout: float) -> Any:
        """Record the attempt and answer the next scripted response."""
        self.calls.append({"url": url, "body": body, "headers": dict(headers), "timeout": timeout})
        if self._scripted:
            return self._scripted.pop(0)
        return self._default

    @property
    def attempts(self) -> int:
        """How many times the dispatcher posted."""
        return len(self.calls)

    @property
    def last_call(self) -> dict[str, Any] | None:
        """The most recent recorded attempt, or `None` when nothing was posted."""
        return self.calls[-1] if self.calls else None


def _as_webhook_response(item: Any) -> Any:
    """Read a scripted entry as a `WebhookResponse`, accepting a bare status code."""
    from webbpulse.events.webhooks import WebhookResponse

    return WebhookResponse(status_code=item) if isinstance(item, int) else item
