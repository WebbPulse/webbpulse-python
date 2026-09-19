# Stream and queue consumers

The one route a consumer Lambda serves, in `webbpulse.events`. The app it lives in is
[http.md](http.md)'s `create_app`. Back to the [README](../README.md).

## Why a consumer is a route at all

A consumer runs behind the AWS Lambda Web Adapter, the same image every other function uses.
The adapter posts a non-HTTP invocation as a JSON body to its pass-through path and returns
the response body as the function's result, so a DynamoDB Streams or SQS handler is an
ordinary `POST` route and the `ReportBatchItemFailures` envelope is its response body.

## An entrypoint

```python
from webbpulse.events import stream_consumer_app


def handle(record):
    """Recompute one part's vote total."""
    repositories().parts.recount(record["dynamodb"]["Keys"]["id"]["S"])


app = stream_consumer_app(handle, title="Catalog votes stream consumer")
```

That is the whole entrypoint. `stream_consumer_app` builds the app with the root routes and
the error handlers, no CORS and no rate limiter, neither of which applies on the adapter's
loopback, and no OpenAPI document, since the one route is not part of any API. Pass
`middleware=[...]` for a product's own middleware and `version=` and `service_name=` for
what `/health` reports.

`handle` raising puts that record alone in `batchItemFailures`, so the event source mapping
retries it and leaves the rest of the batch handled. Failures are reported under the
record's `eventID`, or its `messageId` for an SQS record.

## The options

| Option | Default | What it does |
| --- | --- | --- |
| `path` | `events_path()` | Where the route mounts. |
| `event_names` | every record | Filters on the record's `eventName`, such as `{"REMOVE"}`. |
| `per_record` | `True` | `False` hands the whole event to a handler that returns the envelope itself. |
| `guard_gateway` | `True` | 404s a request that arrived through API Gateway. |
| `log_event` | `"stream.batch"` | The `event` field on the per-batch log line. |

`events_path()` resolves `IDENTITY_EVENTS_PATH`, then `APP_EVENTS_PATH`, then
`AWS_LWA_PASS_THROUGH_PATH`, which is the adapter's own variable and the one that actually
decides where the invocation is posted, then `/events`. Leave `path` unset and the route
follows the adapter's configuration.

`APP_EVENTS_PATH` is the application-facing half of the pair the `lambda-function` module
emits for a wired `sqs_event_sources` or `dynamodb_stream_event_sources`: one `events_path`
input reaches the function as both variables, the adapter reading one and the application the
other, so the two cannot drift apart. Both come from that one input, so they agree whichever
is consulted first.

The gateway guard is on by default because a consumer is queue and stream only and has no
reason to answer a gateway request. `arrived_through_api_gateway` reads
`x-amzn-request-context`: behind API Gateway it is the gateway's context, a JSON object; on a
pass-through it is the literal `null`. A bare request id header, which the runtime adds to
both, proves nothing. The refusal is a 404 rather than a 403, so it does not confirm the
route exists.

## Mounting beside other routes

`register_stream_consumer` is the primitive, for a router that carries more than the one
route. `build_identity_router` uses it this way, and the identity purge is a `RecordHandler`
with `event_names={"REMOVE"}`, since an insert or an update to a users row says nothing about
identity data.

```python
from webbpulse.events import register_stream_consumer

register_stream_consumer(router, purge_record, event_names={"REMOVE"}, log_event="identity.purge_batch")
```

## A handler that already reports failures

`per_record=False` passes the whole event through and returns whatever envelope the handler
gives back, which is the shape a batch handler written before this module already has:

```python
app = stream_consumer_app(handle, title="Users delete consumer", per_record=False)
```

`batch_item_failures(["evt-2"])` builds that envelope, and `event_records(event)` and
`record_id(record)` are the two readers a batch handler needs.

## Producing an event

`EventEnvelope` is the shape a domain event is published in, and `enqueue` puts one on an
SQS queue. A consumer reads `name` and `version` to decide whether it was written for this
payload, and `scope` names the workspace or tenant the event belongs to.

```python
from webbpulse.events import EventEnvelope, enqueue

enqueue(
    settings.events_queue_url,
    EventEnvelope(name="post.created", version=1, scope=workspace_id, payload={"post_id": post.id}),
)
```

`occurred_at` defaults to now in UTC and `event_id` to a fresh uuid4, so a producer that
supplies neither still emits a deduplicable, ordered event. The body is compact JSON with
sorted keys, which is what makes it reproducible enough to sign or to take a dedup id over.
An event with no `scope` omits the field rather than sending null, so a consumer's
`"scope" in body` reads as "this event names a tenant".

On a FIFO queue, which is a `queue_url` ending in `.fifo`, `group_id` defaults to the
envelope's `scope` and `dedup_id` to its `event_id`, so one tenant's events stay ordered
among themselves and a retried send of the same envelope is deduplicated. Neither is sent on
a standard queue, which rejects them outright. Pass `group_id=` or `dedup_id=` to override,
`delay_seconds=` for a delayed send, and `attributes=` for string message attributes.

`enqueue` builds its SQS client on first use, so importing the module needs no boto3 and no
credentials, and `client=` takes one you already hold. It does not swallow an SQS failure:
the producer decides what an unsent event means.

## Reading a stream record

```python
from webbpulse.events import deserialize_image


def handle(record):
    """Reindex the row that changed."""
    item = deserialize_image(record)
    search.index(item["id"], item["title"])
```

A stream record carries its item in DynamoDB's attribute-value shape,
`{"id": {"S": "u-1"}}`, which every consumer otherwise unwraps by hand. `deserialize_image`
runs botocore's own `TypeDeserializer` over it, so numbers come back as `Decimal` and sets as
`set`, exactly as a boto3 resource read of the same item would. Pass `"OldImage"` for the row
as it was before, which is what a `REMOVE` handler wants. A record with no such image is an
empty mapping rather than an error, since that is a shape and not a failure.

## Telling two streams apart

A consumer reading two tables' streams gets both on one route, and the record says which
table only in its source ARN:

```python
from webbpulse.dynamodb import table_name
from webbpulse.events import deserialize_image, source_table

ISSUES = table_name("issues")


def handle(record):
    """Fan one record out to the handler for the table it came from."""
    if source_table(record) == ISSUES:
        reindex_issue(deserialize_image(record))
    else:
        recount_view(deserialize_image(record))
```

`source_table` reads the name out of `eventSourceARN`,
`arn:aws:dynamodb:<region>:<account>:table/<name>/stream/<label>`, which is four lines every
multi-source consumer otherwise writes. The name comes back as the stream carries it, which
is the physical name and so still prefixed: compare it against `table_name("issues")` rather
than against `"issues"` and the consumer works in every environment. A record carrying no
source ARN, or one that is not a DynamoDB stream ARN, raises `ValueError`, since a record
that cannot be placed would otherwise be routed to the wrong handler.

## Ordering and deduping stream records

An event source mapping retries a whole batch, so a consumer sees a record it has already
applied. `record_sequence` reads the number the stream orders and identifies records by:

```python
from webbpulse.events import deserialize_image, record_sequence


def handle(record):
    """Apply one change, skipping anything the projection has already seen."""
    item = deserialize_image(record)
    sequence = record_sequence(record)
    if sequence <= last_applied(item["id"]):
        return
    reindex(item, sequence)
```

The value comes back as a Python `int` rather than the decimal string the record carries,
because one far exceeds 64 bits: string comparison would order `"100"` before `"99"` and a
float would lose the low digits, while `int` is arbitrary precision so the comparison is
exact. Ordering holds **within one partition key only**: two records for different items
carry comparable numbers that mean nothing across items. A record with no
`dynamodb.SequenceNumber`, such as an SQS one, raises `ValueError` rather than reporting
zero, which would replay every record already applied.

## Testing a producer

`webbpulse.testing.FakeQueue` satisfies the `QueueClient` protocol structurally, so a
producer test needs no moto.

```python
from webbpulse.testing import FakeQueue


def test_publishing_a_post_enqueues_the_event():
    queue = FakeQueue()

    publish(post, client=queue)

    assert queue.last_body["name"] == "post.created"
    assert queue.requests[0]["MessageGroupId"] == "ws-1"
```

`requests` holds every send whole, `bodies` parses them, and `FakeQueue(failing=2)` makes
the next two sends raise, which is how a test exercises a producer's own error handling.
