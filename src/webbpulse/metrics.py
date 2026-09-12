"""CloudWatch metrics, emitted as Embedded Metric Format on stdout.

One JSON object per flush, so a metric costs a log line and no `PutMetricData` call. Keep
dimensions bounded and code-controlled, since each distinct combination is a billable
metric; anything unbounded belongs in `properties`.
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

EMF_MAX_DIMENSIONS: Final = 9

_DEFAULT_STORAGE_RESOLUTION: Final = 60

MetricUnit = str
"""The unit of a metric value. Must be a member of `UNITS`."""

DEFAULT_METRIC_ENVIRONMENTS: Final[tuple[str, ...]] = ("staging", "production")

_TRUE_VALUES: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})


def metrics_enabled_from_env(
    environment: str | None = None,
    *,
    testing_var: str = "TESTING",
    environment_var: str = "ENVIRONMENT",
    allowed: Iterable[str] = DEFAULT_METRIC_ENVIRONMENTS,
) -> bool:
    """Whether metrics should be live, as a bool to hand to `enabled=`.

    True only when the testing variable is not truthy and the environment, taken from
    `environment` or `environment_var`, is one of `allowed`. A blank environment is not.
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

    As a context manager it flushes on exit, including on an exception, and a flush clears
    the values but keeps the dimensions. `enabled=False` makes every method a no-op.
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
        """Set up an emitter for one namespace, with its initial dimensions and properties.

        `namespace` is required and never defaulted. `stream` defaults to `sys.stdout`,
        resolved at flush time rather than here.
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
            raise ValueError(f"at most {EMF_MAX_DIMENSIONS} dimensions are allowed, got {len(cleaned)}")
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

        CloudWatch aggregates the array itself, so a loop produces one document.
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
            "Timestamp": (timestamp_millis if timestamp_millis is not None else int(time.time() * 1000)),
            "CloudWatchMetrics": [
                {
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
            payload[name] = values[0] if len(values) == 1 else values
        return payload

    def _metric_definition(self, name: str) -> dict[str, object]:
        """The EMF metric entry for `name`, omitting a unit or resolution at its default."""
        definition: dict[str, object] = {"Name": name}
        unit = self._units.get(name)
        if unit is not None and unit != "None":
            definition["Unit"] = unit
        resolution = self._resolutions.get(name, _DEFAULT_STORAGE_RESOLUTION)
        if resolution != _DEFAULT_STORAGE_RESOLUTION:
            definition["StorageResolution"] = resolution
        return definition

    def flush(self, *, timestamp_millis: int | None = None) -> str | None:
        """Write the document as one line and clear the recorded values.

        Returns the line written, or `None` when disabled or holding no metrics. Never
        raises: a write failure is logged at ERROR and swallowed.
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
        """Enter the block, returning this emitter."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        """Flush on the way out, including after an exception, which is never suppressed."""
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

    A `metrics` value is a bare number, recorded as `Count`, or a `(value, unit)` pair.
    Returns the line written, or `None` when disabled or when `metrics` is empty.
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

    Measured with the monotonic `time.perf_counter`, and recorded in a `finally` so a block
    that raised still reports how long it ran.
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
