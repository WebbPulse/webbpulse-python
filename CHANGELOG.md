# Changelog

Notable changes to the `webbpulse` package. The version here is the one in
`src/webbpulse/_version.py`, and a release is that edit plus the matching `v<version>` tag.

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.0

### Added

- `webbpulse.otel` now tail samples, so **errors are always kept** whatever the ratio says.
  A head sampler decides when the root span starts, before the request has been handled, so
  it cannot know that a request is about to fail; a ratio of 0.1 therefore discards 90
  percent of the failures too. Every span is now recorded, buffered per trace, and judged
  once at flush time: a trace is exported if any span in it carries `StatusCode.ERROR` or an
  `exception` event, or if its trace id falls below the configured probability.
- `TailSamplingSpanProcessor`, the processor that does it. It wraps the exporter rather than
  sitting beside one, so it is the export path; do not register a `BatchSpanProcessor` for
  the same exporter alongside it.
- `configure_tracing` takes `sample_ratio`, `always_sample_errors`, `max_spans_per_trace` and
  `on_overflow` keyword arguments. All have defaults, so existing call sites are unaffected.
- `WEBBPULSE_OTEL_SAMPLE_RATIO` sets the ratio from the environment, which is how Terraform
  sets 1.0 on staging and 0.1 on production without a code change. It falls back to
  `OTEL_TRACES_SAMPLER_ARG`, but only when `OTEL_TRACES_SAMPLER` is `traceidratio` or
  `parentbased_traceidratio`, and then to 1.0. An unparseable or out-of-range value warns and
  is skipped rather than raising, so a typo costs money instead of availability.
- `flush_tracing()`, which resolves the buffered traces and exports the kept ones. This is
  where the tail decision is made, so a Lambda invocation has to reach it before the
  execution environment is frozen. `shutdown_tracing()` flushes too.
- `instrument_fastapi` now installs a Starlette middleware that calls that flush after the
  handler and before the response is returned, which is the only point that works under the
  Lambda Web Adapter: the invocation ends when the HTTP response completes and the sandbox
  freezes immediately, so a background task or `atexit` hook is caught mid-flight. On by
  default when `AWS_LAMBDA_FUNCTION_NAME` is set, off otherwise, and `flush_per_request`
  decides explicitly. Bounded by `flush_timeout_millis` (default 1000) and never raises into
  the request; a failure is logged at WARNING and the response is returned unchanged.
- An `aws-otel` extra, `pip install "webbpulse[otel,aws-otel]"`, bringing
  `aws-opentelemetry-distro` and `botocore`. `configure_tracing` now builds the exporter
  itself: `OTLPAwsSpanExporter` when the resolved endpoint is the X-Ray OTLP one, so requests
  are signed with SigV4, and a plain `OTLPSpanExporter` for anything else. Only the exporter
  class is taken from the distribution; its configurator and `opentelemetry-instrument` entry
  point are not used. Without the extra it warns, naming the extra, and falls back to the
  unsigned exporter.
- `resolve_sample_ratio()` and the `SAMPLE_RATIO_ENV` constant are public, for a service that
  wants to log or assert on the ratio it resolved.

### Changed

- `configure_tracing` now passes an explicit `ParentBased(root=ALWAYS_ON)` sampler to the
  `TracerProvider` instead of letting the SDK pick one. `TracerProvider.__init__` falls back
  to `sampling._get_from_env_or_default()`, which reads `OTEL_TRACES_SAMPLER`; leaving that
  fallback in place would let a ratio sampler in the environment, or one installed by the
  ADOT configurator, pre-drop spans before the tail step ever saw them and silently defeat
  "errors are always sampled". Spans arriving with a sampled-out decision from an upstream
  service are still honoured, because the root sampler only applies to locally started traces.
- `configure_tracing` registers `TailSamplingSpanProcessor` where it previously registered a
  `BatchSpanProcessor`. Nothing is exported until a flush, which is a behaviour change for
  any caller that relied on the batch processor's own timer.
- The tracing pipeline is now built entirely in process. There is no collector, no sidecar,
  no Lambda extension, and nothing runs under `opentelemetry-instrument`. That last one is
  the point: an auto-instrumentation configurator calls `set_tracer_provider` itself, and the
  global provider is set-once per process, so whichever of it and `configure_tracing` ran
  first would win and the other would be silently ignored, leaving either no tail sampling or
  no signed exporter with nothing in the logs to say which.

### Notes for consumers

The environment variable contract shrank to one optional variable,
`WEBBPULSE_OTEL_SAMPLE_RATIO`. `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL`, `OTEL_PYTHON_DISTRO`,
`OTEL_PYTHON_CONFIGURATOR` and `OTEL_TRACES_SAMPLER` are no longer needed and can be removed
from function environments: the protocol is implicit in the exporter class, the distribution
is used as a library rather than a launcher, and the sampler is passed explicitly.

Install with the `aws-otel` extra wherever the X-Ray endpoint is the target, and call
`instrument_fastapi(app)` so the per-request flush is wired. See the README's
`webbpulse.otel` section.

## 0.1.0

- First release: `config`, `logging`, `otel`, `http`, `dynamodb`, `ratelimit`,
  `lambda_entry` and `testing`.
