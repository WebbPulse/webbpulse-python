"""OpenTelemetry tracing, exported to AWS X-Ray over the OTLP endpoint.

OpenTelemetry is the only instrumentation in this package. There is no Sentry, no vendor
SDK, and no ADOT collector in the request path.

## The X-Ray OTLP endpoint

CloudWatch exposes an OTLP trace endpoint at `https://xray.<region>.amazonaws.com/v1/traces`
which accepts OTLP over HTTP with a protobuf or JSON body. There is no gRPC listener, so
`OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` must be `http/protobuf`.

Three things about it are easy to get wrong and each looks identical from the outside,
which is traces silently never appearing:

1. **The endpoint authenticates with SigV4.** A plain OTLP exporter posts unsigned and gets
   a 403. Signing is not something this module implements: it is supplied by the ADOT
   Python distribution, `aws-opentelemetry-distro` (0.10.0 or later, with `botocore`
   present), selected through `OTEL_PYTHON_DISTRO=aws_distro` and
   `OTEL_PYTHON_CONFIGURATOR=aws_configurator` and activated by launching under
   `opentelemetry-instrument`. `configure_tracing` below checks for that distro when the
   endpoint is an X-Ray one and warns loudly rather than exporting into a 403 forever.
2. **Transaction Search has to be enabled on the account** for the endpoint to accept
   spans. It is a one-time per-account setting, not something an application can do.
3. **The execution role needs write access to X-Ray.** Attach the `AWSXrayWriteOnlyAccess`
   managed policy, `arn:aws:iam::aws:policy/AWSXrayWriteOnlyAccess`, which grants
   `xray:PutTraceSegments`, `xray:PutTelemetryRecords` and the three sampling reads. Active
   tracing with no permission records nothing. Note there is no `AWSXrayWriteOnlyPolicy`:
   that name does not exist in the managed policy reference, so an ARN built from it fails
   a Terraform apply with NoSuchEntity.

## Sampling

Exporting straight to the endpoint makes the SDK default to `parentbased_always_on`, which
is every trace. Set `OTEL_TRACES_SAMPLER=parentbased_traceidratio` with an
`OTEL_TRACES_SAMPLER_ARG` below 1.0 in production once volume justifies it. The free tier
is 100,000 traces per account per month and the estate has four accounts, so 1.0 is fine to
start with and this module does not override whatever the environment says. AWS documents
the default as costing up to 20 times the ingestion of their recommended 0.05 ratio, so this
is a deliberate choice to revisit rather than an oversight.

## Cold start

`configure_tracing` is a function called from the composition root, never module-level work.
Instrumentation is applied once per process and guarded, so a warm invoke does nothing.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:  # pragma: no cover - typing only
    from fastapi import FastAPI

__all__ = [
    "OTEL_DISABLED_ENV",
    "configure_tracing",
    "instrument_fastapi",
    "is_tracing_enabled",
    "shutdown_tracing",
    "xray_otlp_endpoint",
]

_log = logging.getLogger(__name__)

#: Set this to any of `1`, `true`, `yes`, `on` to make every entry point here a no-op.
OTEL_DISABLED_ENV: Final = "WEBBPULSE_OTEL_DISABLED"

_TRUTHY: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})

# Set once configure_tracing has installed a provider, so a second call is a no-op rather
# than a second BatchSpanProcessor quietly double-exporting every span.
_CONFIGURED = False


def is_tracing_enabled() -> bool:
    """Whether tracing should be set up at all.

    Disabled explicitly by `WEBBPULSE_OTEL_DISABLED`, and by OpenTelemetry's own
    `OTEL_SDK_DISABLED`, which the specification defines and which tooling already honours.
    """
    if os.environ.get(OTEL_DISABLED_ENV, "").strip().lower() in _TRUTHY:
        return False
    return os.environ.get("OTEL_SDK_DISABLED", "").strip().lower() not in _TRUTHY


def xray_otlp_endpoint(region: str | None = None) -> str:
    """The CloudWatch X-Ray OTLP trace endpoint for a region.

    Falls back to `AWS_REGION`, which Lambda always sets, and then to `us-west-2`, which is
    the only region this estate runs in.
    """
    resolved = (
        region
        or os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
        or "us-west-2"
    )
    return f"https://xray.{resolved}.amazonaws.com/v1/traces"


def _has_adot_distro() -> bool:
    """Whether the ADOT Python distribution that performs SigV4 signing is installed."""
    from importlib.util import find_spec

    try:
        return find_spec("amazon.opentelemetry.distro") is not None
    except (ImportError, ValueError):
        return False


def configure_tracing(
    service_name: str,
    *,
    environment: str | None = None,
    endpoint: str | None = None,
    resource_attributes: dict[str, str] | None = None,
    force: bool = False,
) -> bool:
    """Set up the tracer provider and the OTLP span exporter. Returns whether it did.

    Safe to call when the `otel` extra is not installed, when tracing is disabled by
    environment variable, and more than once. In each of those cases it returns `False` and
    leaves the global tracer provider alone, which means the API's no-op spans stay in
    place and instrumented code keeps working without a provider.

    Call it from the composition root before creating the FastAPI app, so the FastAPI
    instrumentation attaches to a real provider::

        configure_tracing("webbpulse-staging-posts", environment="staging")
        app = create_app([posts_router])
    """
    global _CONFIGURED
    if _CONFIGURED and not force:
        return False
    if not is_tracing_enabled():
        _log.debug("OpenTelemetry tracing disabled by environment; skipping setup.")
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        _log.debug("OpenTelemetry SDK not installed; install webbpulse[otel] to enable tracing.")
        return False

    resolved_endpoint = (
        endpoint or os.environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") or xray_otlp_endpoint()
    )

    # The X-Ray endpoint rejects unsigned requests with a 403 and the exporter retries
    # quietly, so without this warning a missing distro looks exactly like "no traffic".
    if ".amazonaws.com/v1/traces" in resolved_endpoint and not _has_adot_distro():
        _log.warning(
            "Exporting to the X-Ray OTLP endpoint without aws-opentelemetry-distro installed. "
            "That endpoint requires SigV4 signing, so spans will be rejected with 403. "
            "Install aws-opentelemetry-distro and run under opentelemetry-instrument.",
            extra={"otlp_endpoint": resolved_endpoint},
        )

    attributes: dict[str, Any] = {"service.name": service_name, "service.namespace": "webbpulse"}
    if environment:
        # `deployment.environment.name` is the current semantic convention; the older
        # `deployment.environment` is kept alongside it because CloudWatch and a good deal
        # of existing tooling still group on that one.
        attributes["deployment.environment.name"] = environment
        attributes["deployment.environment"] = environment
    if function_name := os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        attributes["faas.name"] = function_name
    if version := os.environ.get("AWS_LAMBDA_FUNCTION_VERSION"):
        attributes["faas.version"] = version
    if resource_attributes:
        attributes.update(resource_attributes)

    # Resource.create merges OTEL_RESOURCE_ATTRIBUTES from the environment, so a Terraform
    # supplied attribute is additive rather than being overwritten here.
    provider = TracerProvider(resource=Resource.create(attributes))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=resolved_endpoint)))
    trace.set_tracer_provider(provider)

    _instrument_botocore()
    _CONFIGURED = True
    _log.info(
        "OpenTelemetry tracing configured.",
        extra={"otlp_endpoint": resolved_endpoint, "otel_service_name": service_name},
    )
    return True


def _instrument_botocore() -> None:
    """Instrument boto3 and botocore so DynamoDB and Secrets Manager calls become spans."""
    try:
        from opentelemetry.instrumentation.botocore import BotocoreInstrumentor
    except ImportError:
        return
    # The instrumentation packages ship no type information for their constructors.
    instrumentor = BotocoreInstrumentor()  # type: ignore[no-untyped-call]
    if not instrumentor.is_instrumented_by_opentelemetry:
        instrumentor.instrument()


def instrument_fastapi(app: FastAPI, *, excluded_urls: str | None = None) -> None:
    """Instrument one FastAPI app so each request becomes a server span.

    A no-op when the `otel` extra is absent or tracing is disabled. `excluded_urls` is a
    comma separated list of path patterns; the health route is excluded by default because
    the Web Adapter polls it on every cold start and API Gateway health checks would
    otherwise dominate the trace volume for no diagnostic value.
    """
    if not is_tracing_enabled():
        return
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    except ImportError:
        return
    FastAPIInstrumentor.instrument_app(
        app, excluded_urls=excluded_urls if excluded_urls is not None else "health,ready"
    )


def shutdown_tracing() -> None:
    """Flush and shut down the tracer provider.

    Worth calling from a container's shutdown path. It matters much less under the Web
    Adapter than it did under a Lambda handler: the process stays alive between invokes, so
    the `BatchSpanProcessor` gets its own chance to flush rather than being frozen mid-batch.
    """
    global _CONFIGURED
    try:
        from opentelemetry import trace
    except ImportError:
        return
    provider = trace.get_tracer_provider()
    shutdown = getattr(provider, "shutdown", None)
    if callable(shutdown):
        shutdown()
    _CONFIGURED = False
