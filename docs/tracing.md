# Tracing

`webbpulse.otel`: OpenTelemetry tracing, the sampler, and the Lambda shutdown flush. Back to
the [README](../README.md).

## `webbpulse.otel`

OpenTelemetry is the only instrumentation in this package. Sentry is gone, and there is no
collector, sidecar or Lambda extension in the request path. The whole pipeline is built in
process by `configure_tracing`, and a service starts with a plain `python -m`, not under
`opentelemetry-instrument`. That is deliberate: an auto-instrumentation configurator calls
`set_tracer_provider` itself, and the global provider is set-once per process, so whichever
of the configurator and `configure_tracing` ran first would win and the other would be
silently ignored. Owning the pipeline in one place removes that race.

```python
from webbpulse.otel import configure_tracing

configure_tracing("webbpulse-staging-posts", environment="staging")
```

Traces go straight to the CloudWatch X-Ray OTLP endpoint,
`https://xray.<region>.amazonaws.com/v1/traces`. Three things about that endpoint are easy
to get wrong, and all three look identical from outside: traces simply never appear.

1. **It authenticates with SigV4.** A plain OTLP exporter posts unsigned, gets a 403, and
   retries it quietly, which looks exactly like having no traffic. The signing comes from
   `OTLPAwsSpanExporter` in `aws-opentelemetry-distro`, which subclasses the plain HTTP
   exporter and swaps in a `requests` session that signs for the `xray` service. Install it
   with the **`aws-otel`** extra:

   ```
   pip install "webbpulse[otel,aws-otel]"
   ```

   `configure_tracing` picks that exporter automatically whenever the resolved endpoint is
   an X-Ray one, and a plain `OTLPSpanExporter` for anything else, such as a local
   collector. An X-Ray endpoint means `xray.<region>.amazonaws.com`, the FIPS form
   `xray-fips.<region>.amazonaws.com`, or an interface VPC endpoint
   `<vpce-id>.xray.<region>.vpce.amazonaws.com`; the signing region is taken from the host
   itself rather than from `AWS_REGION`, which would be the wrong scope for a VPC endpoint. Only the exporter class is used; the distribution's configurator and its
   `opentelemetry-instrument` entry point deliberately are not. When the extra is missing it
   warns, naming the extra, and falls back to the unsigned exporter, because a warned-about
   403 is a better failure than a crashed cold start.
2. **Transaction Search must be enabled on the account.** It is a one-time per-account
   setting that an application cannot make for itself.
3. **The execution role needs X-Ray write access.** Attach `AWSXrayWriteOnlyAccess`,
   `arn:aws:iam::aws:policy/AWSXrayWriteOnlyAccess`. There is no `AWSXrayWriteOnlyPolicy`;
   an ARN built from that name fails a Terraform apply with NoSuchEntity.

The endpoint takes OTLP over HTTP only; there is no gRPC listener. The protocol is not an
environment variable here, because the exporter class is constructed directly, so
`http/protobuf` is implicit in the code rather than something a deployment can get wrong.
Note the host is per-signal: logs go to
`logs.<region>.amazonaws.com/v1/logs` and metrics to `monitoring.<region>.amazonaws.com/v1/metrics`.
This package sends traces only, and CloudWatch handles logs.

`instrument_fastapi(app)` attaches the FastAPI instrumentation, excluding the health route
by default because the Web Adapter polls it on every cold start. Botocore is instrumented
too, so DynamoDB and Secrets Manager calls become spans. All of it is a no-op when the
`otel` extra is absent or when `WEBBPULSE_OTEL_DISABLED` or `OTEL_SDK_DISABLED` is set, so
tests and local runs cost nothing.

## Sampling

The tail sampler, its memory bound, the flush wiring and the environment variables are in
[tracing-sampling.md](tracing-sampling.md).
