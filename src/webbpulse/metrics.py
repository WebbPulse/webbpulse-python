"""CloudWatch metrics, emitted as Embedded Metric Format on stdout.

One JSON object per flush, written to stdout. CloudWatch Logs parses the `_aws` block out
of it and creates the metrics asynchronously, so a metric costs a log line and nothing
else: no `PutMetricData` call in the request path, no `cloudwatch:PutMetricData` on the
execution role, no agent, no sidecar, no extension. The same object is also an ordinary
log event, so the dimension values and any extra properties on it stay queryable in Logs
Insights after the metric has been extracted.

## Why this is hand rolled rather than `aws-embedded-metrics`

The library is 300 lines of sink auto-detection wrapped around a JSON document this module
builds in about thirty, and both of the things it detects are wrong in this estate:

* Its environment detection falls back to a CloudWatch Agent sink over TCP when it cannot
  positively identify the runtime. That agent does not exist on Lambda, ECS Fargate or App
  Runner, so metrics are silently dropped and the only fix is remembering to set
  `AWS_EMF_ENVIRONMENT=Local` in every task definition and function. Writing to stdout
  unconditionally removes the setting and the failure mode together.
* Its flush is asynchronous and it is known to lose the final record when that record is
  the last thing a process emits, which forced CarModPicker to order an unrelated log line
  after the emission and pin the ordering with a static-analysis test. `emit` here writes
  and flushes synchronously before it returns, so there is nothing to order.

What is kept is the wire format, which is AWS's and not the library's. A document this
module writes and a document the library writes are the same document.

## Cardinality is the thing to get right

CloudWatch bills per custom metric, and one custom metric is one distinct combination of
namespace, metric name and dimension values. A dimension carrying a user id, a request id
or a URL therefore mints a new billable metric per user, per request or per URL, and the
bill and the console both become unusable. Dimensions must be bounded and code-controlled:
an adapter name from a fixed registry, an environment, a run type. Anything unbounded goes
in `properties`, which is written into the log event and is queryable in Logs Insights
without creating a metric at all.

`emit` refuses more than nine dimensions, which is the documented ceiling per metric.

## Storage resolution and the units

`put` takes a unit from the CloudWatch set (`Count`, `Seconds`, `Milliseconds`, `Bytes`,
`Percent` and the rest); an unrecognised unit is rejected at the call site rather than
silently dropped by the ingestion pipeline, which is how a typo in a unit name normally
surfaces. `Unit` is omitted from the document when it is `None`, which CloudWatch reads as
`None`, the unitless default.

High-resolution metrics are supported by passing `storage_resolution=1`, which stores at
one-second granularity for the first three hours. The default of 60 is standard resolution
and is what almost everything should use.

## When metrics are live

`enabled` stays a plain constructor argument, and it stays `True` by default, because the
policy for when metrics are on belongs to the service that holds the settings object rather
than to this module. What 0.8.0 adds is `metrics_enabled_from_env`, the one gate every
adopter was going to write anyway: silent while the testing variable is truthy, and live
only in the environments named. It reads environment variables and returns a bool, so it
composes with `enabled=` rather than replacing it, and a service that never calls it sees
no change at all.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from types import TracebackType
from typing import Final, Literal, TextIO

__all__ = [
    "DEFAULT_METRIC_ENVIRONMENTS",
    "EMF_MAX_DIMENSIONS",
    "UNITS",
    "MetricUnit",
    "MetricsEmitter",
    "emit",
    "metrics_enabled_from_env",
    "timed",
]

_log = logging.getLogger(__name__)

#: The unit names CloudWatch accepts. Anything outside this set is rejected by `put`
#: rather than being passed through, because CloudWatch drops an unknown unit silently and
#: the metric then appears with no unit and no error anywhere to explain it.
UNITS: Final[frozenset[str]] = frozenset(
    {
        "Seconds",
        "Microseconds",
        "Milliseconds",
        "Bytes",
        "Kilobytes",
        "Megabytes",
        "Gigabytes",
        "Terabytes",
        "Bits",
        "Kilobits",
        "Megabits",
        "Gigabits",
        "Terabits",
        "Percent",
        "Count",
        "Bytes/Second",
        "Kilobytes/Second",
        "Megabytes/Second",
        "Gigabytes/Second",
        "Terabytes/Second",
        "Bits/Second",
        "Kilobits/Second",
        "Megabits/Second",
        "Gigabits/Second",
        "Terabits/Second",
        "Count/Second",
        "None",
    }
)

#: A metric may carry at most nine dimensions. CloudWatch rejects the tenth.
EMF_MAX_DIMENSIONS: Final = 9

#: Standard resolution, one datapoint per minute. `1` is high resolution.
_DEFAULT_STORAGE_RESOLUTION: Final = 60

MetricUnit = str
"""The unit of a metric value. Must be a member of `UNITS`."""

#: The environments metrics are live in by default. Deliberately excludes development and
#: any per-branch preview: a metric emitted from a workstation lands in the same namespace
#: as production and skews the alarm it is next to, which is worse than not having it.
DEFAULT_METRIC_ENVIRONMENTS: Final[tuple[str, ...]] = ("staging", "production")

#: Values of the testing variable that count as "yes". Compared case-insensitively after a
#: strip, so `TESTING=True` from a shell profile and `TESTING=true` from a compose file mean
#: the same thing rather than one of them silently emitting metrics from a test run.
_TRUE_VALUES: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})


def metrics_enabled_from_env(
    environment: str | None = None,
    *,
    testing_var: str = "TESTING",
    environment_var: str = "ENVIRONMENT",
    allowed: Iterable[str] = DEFAULT_METRIC_ENVIRONMENTS,
) -> bool:
    """Whether metrics should be live, as a bool to hand to `enabled=`.

    This is the gate every adopter writes anyway, hoisted so the next one does not write it
    a third time slightly differently. It reads environment variables and returns a bool; it
    does not touch `MetricsEmitter`, whose `enabled` still defaults to `True`, so nothing
    that does not call this changes behaviour::

        emit(
            namespace="CarModPicker/Crawlers",
            metrics={"Ingested": ingested},
            enabled=metrics_enabled_from_env(settings.environment),
        )

    Two conditions, both of which must hold:

    * The testing variable is not truthy. A test suite that emitted real EMF documents would
      put test data on the same metric as production, and the test's own stdout assertions
      would have to tolerate a metric line appearing in the middle of them.
    * The environment is in `allowed`, which defaults to staging and production.

    Args:
        environment: The environment name. When `None` it is read from `environment_var`,
            so a service with a settings object passes `settings.environment` and one
            without passes nothing.
        testing_var: The variable that suppresses metrics when truthy. `"TESTING"` is the
            name CarModPicker's deleted gate used and the name its pytest configuration
            already sets.
        environment_var: The variable consulted when `environment` is `None`.
        allowed: The environment names metrics are live in. Matched case-insensitively
            after a strip, because these values arrive from Terraform and a task definition
            rather than from code.

    Returns:
        `True` only when the testing variable is not truthy and the environment is allowed.
        An unset or blank environment is not allowed, so the failure mode of a missing
        variable is silence rather than production-namespaced noise from an unknown source.
    """
    if os.environ.get(testing_var, "").strip().lower() in _TRUE_VALUES:
        return False
    name = environment if environment is not None else os.environ.get(environment_var, "")
    resolved = name.strip().lower()
    if not resolved:
        return False
    return resolved in {value.strip().lower() for value in allowed}


class MetricsEmitter:
    """Accumulate metrics for one dimension set, then write them as one EMF document.

    Built for the common case, which is a handful of values sharing one set of dimensions
    and emitted together::

        with MetricsEmitter(namespace="CarModPicker/Crawlers") as metrics:
            metrics.set_dimensions(AdapterName=name, Environment=env, RunType="live")
            metrics.put("Ingested", ingested, "Count")
            metrics.put("ParseFailures", parse_failures, "Count")
            metrics.put("ElapsedSeconds", elapsed, "Seconds")

    The context manager flushes on exit, including on an exception, so a partially
    populated emitter still reports what it managed to measure. Reusing an instance after
    a flush is fine: the metric values are cleared and the dimensions and properties are
    kept, which is what a loop emitting one document per iteration wants.

    `enabled=False` makes every method a no-op that writes nothing. That is the switch for
    a test suite and for local development, and it is a constructor argument rather than an
    environment variable read inside this module, so the policy for when metrics are live
    stays with the service that has the settings object.
    """

    def __init__(
        self,
        *,
        namespace: str,
        dimensions: Mapping[str, str] | None = None,
        properties: Mapping[str, object] | None = None,
        enabled: bool = True,
        stream: TextIO | None = None,
    ) -> None:
        """
        Args:
            namespace: The CloudWatch namespace, required and never defaulted. A default
                here would be a WebbPulse-wide namespace that every service dumped metrics
                into, which is the one shape that cannot be undone later without breaking
                every alarm. Services pass their own, `"CarModPicker/Crawlers"` or
                `"WebbPulse/Portfolio"`, usually derived from settings.
            dimensions: Initial dimension set. Bounded, code-controlled values only.
            properties: Extra fields written into the log event but not made dimensions.
                This is where an unbounded value belongs: a request id, a job id, a URL.
            enabled: When false every call is a no-op and nothing is written.
            stream: Where the document goes. Defaults to `sys.stdout` resolved at flush
                time rather than at construction, so a test capturing stdout and a Lambda
                that replaced the stream both see the document.
        """
        if not namespace or not namespace.strip():
            raise ValueError("namespace is required and must not be blank")
        self.namespace = namespace
        self.enabled = enabled
        self._stream = stream
        self._dimensions: dict[str, str] = {}
        self._properties: dict[str, object] = {}
        self._values: dict[str, list[float]] = {}
        self._units: dict[str, str | None] = {}
        self._resolutions: dict[str, int] = {}
        if dimensions:
            self.set_dimensions(**dimensions)
        if properties:
            self.set_properties(**properties)

    def set_dimensions(self, **dimensions: str) -> MetricsEmitter:
        """Replace the dimension set. Returns self so calls can be chained."""
        cleaned = {key: str(value) for key, value in dimensions.items()}
        if len(cleaned) > EMF_MAX_DIMENSIONS:
            raise ValueError(
                f"at most {EMF_MAX_DIMENSIONS} dimensions are allowed, got {len(cleaned)}"
            )
        # A blank dimension value makes CloudWatch reject the whole document, taking every
        # metric in it with the one bad dimension, so it is caught at the call site.
        blank = sorted(key for key, value in cleaned.items() if not value.strip())
        if blank:
            raise ValueError(f"dimension values must not be blank: {', '.join(blank)}")
        self._dimensions = cleaned
        return self

    def set_properties(self, **properties: object) -> MetricsEmitter:
        """Merge extra non-dimension fields into the document. Returns self."""
        self._properties.update(properties)
        return self

    def put(
        self,
        name: str,
        value: float,
        unit: MetricUnit = "None",
        *,
        storage_resolution: Literal[1, 60] = _DEFAULT_STORAGE_RESOLUTION,
    ) -> MetricsEmitter:
        """Record one value for `name`. Repeat calls accumulate into a value array.

        CloudWatch aggregates the array itself, so emitting the same metric name a hundred
        times in a loop produces one document with a hundred values rather than a hundred
        documents, which is both cheaper to ingest and what the statistics are computed
        over.
        """
        if unit not in UNITS:
            raise ValueError(f"unit must be one of the CloudWatch units, got {unit!r}")
        if not self.enabled:
            return self
        self._values.setdefault(name, []).append(float(value))
        self._units[name] = unit
        self._resolutions[name] = storage_resolution
        return self

    def document(self, *, timestamp_millis: int | None = None) -> dict[str, object]:
        """Build the EMF document without writing it. Useful in a test and in a dry run."""
        directive: dict[str, object] = {
            "Timestamp": (
                timestamp_millis if timestamp_millis is not None else int(time.time() * 1000)
            ),
            "CloudWatchMetrics": [
                {
                    # A single dimension set. EMF permits several, which produces the same
                    # metric aggregated at several granularities and multiplies the
                    # billable metric count; a service that wants that emits twice.
                    "Namespace": self.namespace,
                    "Dimensions": [sorted(self._dimensions)],
                    "Metrics": [self._metric_definition(name) for name in sorted(self._values)],
                }
            ],
        }
        payload: dict[str, object] = {"_aws": directive}
        payload.update(self._properties)
        payload.update(self._dimensions)
        for name, values in self._values.items():
            # A single value is written as a scalar rather than a one-element array. Both
            # are valid EMF; the scalar is what the log event reads like to a human and
            # what a Logs Insights `stats` over the field can use directly.
            payload[name] = values[0] if len(values) == 1 else values
        return payload

    def _metric_definition(self, name: str) -> dict[str, object]:
        definition: dict[str, object] = {"Name": name}
        unit = self._units.get(name)
        if unit is not None and unit != "None":
            definition["Unit"] = unit
        resolution = self._resolutions.get(name, _DEFAULT_STORAGE_RESOLUTION)
        # Omitted at the default. Writing `StorageResolution: 60` is legal but is noise on
        # every document, and an older CloudWatch agent parsing the field is one more
        # thing that can go wrong for no gain.
        if resolution != _DEFAULT_STORAGE_RESOLUTION:
            definition["StorageResolution"] = resolution
        return definition

    def flush(self, *, timestamp_millis: int | None = None) -> str | None:
        """Write the document as one line and clear the recorded values.

        Returns the line that was written, or `None` when nothing was written, which is
        either the disabled case or an emitter holding no metrics. A flush with no metrics
        writes nothing at all rather than an empty document, because CloudWatch treats a
        `Metrics` array of zero entries as a malformed directive.

        Never raises. A metric is a report about the work, and losing the report is always
        preferable to failing the work it was reporting on, so a serialisation failure or a
        closed stream is logged at ERROR and swallowed. That mirrors how the rest of this
        package treats telemetry in the request path.
        """
        if not self.enabled or not self._values:
            self._values.clear()
            return None
        try:
            line = json.dumps(
                self.document(timestamp_millis=timestamp_millis),
                default=str,
                separators=(",", ":"),
            )
            stream = self._stream if self._stream is not None else sys.stdout
            stream.write(line + "\n")
            # Flushed explicitly. Lambda freezes the execution environment the moment the
            # response is written, so a buffered line that has not reached the log driver
            # is not written late, it is lost.
            stream.flush()
        except Exception as exc:
            _log.error("failed to emit EMF metrics for namespace %s: %s", self.namespace, exc)
            return None
        finally:
            self._values.clear()
            self._units.clear()
            self._resolutions.clear()
        return line

    def __enter__(self) -> MetricsEmitter:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        self.flush()
        return False


def emit(
    *,
    namespace: str,
    metrics: Mapping[str, float] | Mapping[str, tuple[float, MetricUnit]],
    dimensions: Mapping[str, str] | None = None,
    properties: Mapping[str, object] | None = None,
    enabled: bool = True,
    stream: TextIO | None = None,
    timestamp_millis: int | None = None,
) -> str | None:
    """Emit one EMF document in a single call, for the one-shot case.

    `metrics` values are either a bare number, which is recorded as `Count`, or a
    `(value, unit)` pair::

        emit(
            namespace="CarModPicker/Crawlers",
            dimensions={"AdapterName": name, "Environment": env, "RunType": "live"},
            metrics={
                "Ingested": ingested,
                "ParseFailures": parse_failures,
                "ElapsedSeconds": (elapsed, "Seconds"),
            },
        )

    Returns the line written, or `None` when disabled or when `metrics` is empty. Never
    raises for a reason internal to emission; a bad unit or a blank dimension is a
    programming error and still raises, because it is caught the first time the code runs
    rather than silently costing every metric after it.
    """
    emitter = MetricsEmitter(
        namespace=namespace,
        dimensions=dimensions,
        properties=properties,
        enabled=enabled,
        stream=stream,
    )
    for name, entry in metrics.items():
        if isinstance(entry, tuple):
            value, unit = entry
            emitter.put(name, value, unit)
        else:
            emitter.put(name, entry, "Count")
    return emitter.flush(timestamp_millis=timestamp_millis)


@contextmanager
def timed(
    emitter: MetricsEmitter,
    name: str,
    *,
    unit: MetricUnit = "Milliseconds",
) -> Iterator[None]:
    """Record the wall-clock duration of the block onto `emitter`.

    Measured with `time.perf_counter`, which is monotonic, so a clock adjustment during a
    long crawl cannot produce a negative elapsed time. The value is recorded in a `finally`
    so a block that raised still reports how long it ran before failing, which is usually
    the interesting number.
    """
    if unit not in {"Seconds", "Milliseconds", "Microseconds"}:
        raise ValueError(f"timed unit must be a duration unit, got {unit!r}")
    started = time.perf_counter()
    try:
        yield
    finally:
        elapsed_seconds = time.perf_counter() - started
        scale = {"Seconds": 1.0, "Milliseconds": 1_000.0, "Microseconds": 1_000_000.0}[unit]
        emitter.put(name, elapsed_seconds * scale, unit)
