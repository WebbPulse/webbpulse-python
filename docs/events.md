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

`events_path()` resolves `IDENTITY_EVENTS_PATH`, then `AWS_LWA_PASS_THROUGH_PATH`, which is
the adapter's own variable and the one that actually decides where the invocation is posted,
then `/events`. Leave `path` unset and the route follows the adapter's configuration.

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
