"""Tests for `webbpulse.metrics`.

The assertions are largely about the exact shape of the `_aws` block, because CloudWatch
parses that shape and reports nothing at all when it is wrong. There is no error surface
for a malformed EMF document: the log line is ingested, the metric is silently not created,
and the only symptom is an alarm that stays in INSUFFICIENT_DATA. So the document is
pinned key by key here rather than smoke tested.
"""

from __future__ import annotations

import io
import json
import logging
from typing import Any

import pytest

from webbpulse.metrics import (
    EMF_MAX_DIMENSIONS,
    UNITS,
    MetricsEmitter,
    emit,
    timed,
)


def _emitter(**kwargs: Any) -> tuple[MetricsEmitter, io.StringIO]:
    stream = io.StringIO()
    kwargs.setdefault("namespace", "WebbPulse/Test")
    return MetricsEmitter(stream=stream, **kwargs), stream


def _lines(stream: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in stream.getvalue().splitlines() if line]


# --------------------------------------------------------------------------------------
# Construction
# --------------------------------------------------------------------------------------


def test_a_namespace_is_required() -> None:
    with pytest.raises(ValueError, match="namespace is required"):
        MetricsEmitter(namespace="")


def test_a_blank_namespace_is_rejected() -> None:
    with pytest.raises(ValueError, match="namespace is required"):
        MetricsEmitter(namespace="   ")


def test_dimensions_and_properties_can_be_passed_to_the_constructor() -> None:
    emitter, stream = _emitter(dimensions={"Environment": "staging"}, properties={"job_id": "abc"})
    emitter.put("Ingested", 1, "Count")
    emitter.flush()
    (payload,) = _lines(stream)
    assert payload["Environment"] == "staging"
    assert payload["job_id"] == "abc"


# --------------------------------------------------------------------------------------
# The document shape
# --------------------------------------------------------------------------------------


def test_the_document_carries_the_aws_directive_cloudwatch_parses() -> None:
    emitter, stream = _emitter(namespace="CarModPicker/Crawlers")
    emitter.set_dimensions(AdapterName="acme", Environment="staging", RunType="live")
    emitter.put("Ingested", 12, "Count")
    emitter.flush(timestamp_millis=1_700_000_000_000)

    (payload,) = _lines(stream)
    directive = payload["_aws"]
    assert directive["Timestamp"] == 1_700_000_000_000
    (metric_set,) = directive["CloudWatchMetrics"]
    assert metric_set["Namespace"] == "CarModPicker/Crawlers"
    assert metric_set["Dimensions"] == [["AdapterName", "Environment", "RunType"]]
    assert metric_set["Metrics"] == [{"Name": "Ingested", "Unit": "Count"}]


def test_dimension_values_are_top_level_keys_so_they_stay_queryable() -> None:
    emitter, stream = _emitter()
    emitter.set_dimensions(AdapterName="acme", Environment="staging")
    emitter.put("Ingested", 1, "Count")
    emitter.flush()
    (payload,) = _lines(stream)
    assert payload["AdapterName"] == "acme"
    assert payload["Environment"] == "staging"


def test_a_single_value_is_written_as_a_scalar() -> None:
    emitter, stream = _emitter()
    emitter.put("Ingested", 12, "Count")
    emitter.flush()
    (payload,) = _lines(stream)
    assert payload["Ingested"] == 12.0


def test_repeated_puts_accumulate_into_one_array_rather_than_one_document_each() -> None:
    emitter, stream = _emitter()
    emitter.put("Latency", 10, "Milliseconds")
    emitter.put("Latency", 20, "Milliseconds")
    emitter.put("Latency", 30, "Milliseconds")
    emitter.flush()
    (payload,) = _lines(stream)
    assert payload["Latency"] == [10.0, 20.0, 30.0]
    (metric_set,) = payload["_aws"]["CloudWatchMetrics"]
    assert metric_set["Metrics"] == [{"Name": "Latency", "Unit": "Milliseconds"}]


def test_the_unitless_default_omits_the_unit_key() -> None:
    emitter, stream = _emitter()
    emitter.put("Ratio", 0.5)
    emitter.flush()
    (payload,) = _lines(stream)
    (metric_set,) = payload["_aws"]["CloudWatchMetrics"]
    assert metric_set["Metrics"] == [{"Name": "Ratio"}]


def test_the_default_storage_resolution_is_omitted() -> None:
    emitter, stream = _emitter()
    emitter.put("Ingested", 1, "Count")
    emitter.flush()
    (payload,) = _lines(stream)
    (metric_set,) = payload["_aws"]["CloudWatchMetrics"]
    assert "StorageResolution" not in metric_set["Metrics"][0]


def test_high_resolution_is_written_when_asked_for() -> None:
    emitter, stream = _emitter()
    emitter.put("Ingested", 1, "Count", storage_resolution=1)
    emitter.flush()
    (payload,) = _lines(stream)
    (metric_set,) = payload["_aws"]["CloudWatchMetrics"]
    assert metric_set["Metrics"][0]["StorageResolution"] == 1


def test_metric_names_are_sorted_so_the_document_is_deterministic() -> None:
    emitter, stream = _emitter()
    emitter.put("Zebra", 1, "Count")
    emitter.put("Alpha", 2, "Count")
    emitter.flush()
    (payload,) = _lines(stream)
    (metric_set,) = payload["_aws"]["CloudWatchMetrics"]
    assert [m["Name"] for m in metric_set["Metrics"]] == ["Alpha", "Zebra"]


def test_the_timestamp_defaults_to_now_in_milliseconds() -> None:
    emitter, stream = _emitter()
    emitter.put("Ingested", 1, "Count")
    emitter.flush()
    (payload,) = _lines(stream)
    # Milliseconds since the epoch is a 13 digit number for any date this decade. A
    # seconds-valued timestamp would be 10 digits and CloudWatch would reject the document.
    assert 1_600_000_000_000 < payload["_aws"]["Timestamp"] < 4_000_000_000_000


def test_the_document_is_one_line() -> None:
    emitter, stream = _emitter()
    emitter.set_properties(note="a value")
    emitter.put("Ingested", 1, "Count")
    emitter.flush()
    assert stream.getvalue().count("\n") == 1


def test_document_builds_without_writing_anything() -> None:
    emitter, stream = _emitter()
    emitter.put("Ingested", 1, "Count")
    document = emitter.document(timestamp_millis=1)
    assert document["Ingested"] == 1.0
    assert stream.getvalue() == ""


# --------------------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------------------


def test_an_unknown_unit_is_rejected_at_the_call_site() -> None:
    emitter, _ = _emitter()
    with pytest.raises(ValueError, match="unit must be one of"):
        emitter.put("Ingested", 1, "Widgets")


def test_every_documented_cloudwatch_unit_is_accepted() -> None:
    emitter, _ = _emitter()
    for unit in sorted(UNITS):
        emitter.put("Metric", 1, unit)


def test_too_many_dimensions_are_rejected() -> None:
    emitter, _ = _emitter()
    too_many = {f"D{i}": str(i) for i in range(EMF_MAX_DIMENSIONS + 1)}
    with pytest.raises(ValueError, match="at most 9 dimensions"):
        emitter.set_dimensions(**too_many)


def test_the_dimension_ceiling_itself_is_allowed() -> None:
    emitter, _ = _emitter()
    at_limit = {f"D{i}": str(i) for i in range(EMF_MAX_DIMENSIONS)}
    emitter.set_dimensions(**at_limit)


def test_a_blank_dimension_value_is_rejected_before_it_voids_the_document() -> None:
    emitter, _ = _emitter()
    with pytest.raises(ValueError, match="must not be blank: Environment"):
        emitter.set_dimensions(AdapterName="acme", Environment="")


def test_a_non_string_dimension_value_is_coerced() -> None:
    emitter, stream = _emitter()
    emitter.set_dimensions(Shard=3)  # type: ignore[arg-type]
    emitter.put("Ingested", 1, "Count")
    emitter.flush()
    (payload,) = _lines(stream)
    assert payload["Shard"] == "3"


def test_setters_return_self_so_calls_chain() -> None:
    emitter, stream = _emitter()
    emitter.set_dimensions(Environment="staging").set_properties(job="x").put(
        "Ingested", 1, "Count"
    )
    emitter.flush()
    (payload,) = _lines(stream)
    assert payload["Environment"] == "staging"
    assert payload["job"] == "x"


# --------------------------------------------------------------------------------------
# Flush behaviour
# --------------------------------------------------------------------------------------


def test_a_flush_with_no_metrics_writes_nothing() -> None:
    emitter, stream = _emitter()
    assert emitter.flush() is None
    assert stream.getvalue() == ""


def test_a_flush_returns_the_line_it_wrote() -> None:
    emitter, _stream = _emitter()
    emitter.put("Ingested", 1, "Count")
    line = emitter.flush()
    assert line is not None
    assert json.loads(line)["Ingested"] == 1.0


def test_a_flush_clears_the_values_so_a_reused_emitter_does_not_double_report() -> None:
    emitter, stream = _emitter()
    emitter.set_dimensions(Environment="staging")
    emitter.put("Ingested", 1, "Count")
    emitter.flush()
    emitter.put("Ingested", 2, "Count")
    emitter.flush()
    first, second = _lines(stream)
    assert first["Ingested"] == 1.0
    assert second["Ingested"] == 2.0
    # Dimensions survive a flush, which is what makes a per-iteration emit ergonomic.
    assert second["Environment"] == "staging"


def test_the_stream_is_flushed_so_a_lambda_freeze_cannot_lose_the_line() -> None:
    class _CountingStream(io.StringIO):
        flushes = 0

        def flush(self) -> None:
            type(self).flushes += 1

    stream = _CountingStream()
    emitter = MetricsEmitter(namespace="WebbPulse/Test", stream=stream)
    emitter.put("Ingested", 1, "Count")
    emitter.flush()
    assert _CountingStream.flushes == 1


def test_stdout_is_resolved_at_flush_time(capsys: pytest.CaptureFixture[str]) -> None:
    """No `stream` means `sys.stdout`, read when the flush happens rather than captured at
    construction, which is what lets `capsys` and a Lambda log driver both see it."""
    emitter = MetricsEmitter(namespace="WebbPulse/Test")
    emitter.put("Ingested", 5, "Count")
    emitter.flush()
    captured = capsys.readouterr()
    assert json.loads(captured.out.strip())["Ingested"] == 5.0


def test_a_stream_failure_is_logged_and_swallowed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class _BrokenStream(io.StringIO):
        def write(self, s: str) -> int:
            raise OSError("stream is closed")

    emitter = MetricsEmitter(namespace="WebbPulse/Test", stream=_BrokenStream())
    emitter.put("Ingested", 1, "Count")
    with caplog.at_level(logging.ERROR, logger="webbpulse.metrics"):
        assert emitter.flush() is None
    assert "failed to emit EMF metrics" in caplog.text


def test_a_failed_flush_still_clears_the_values() -> None:
    class _BrokenStream(io.StringIO):
        def write(self, s: str) -> int:
            raise OSError("stream is closed")

    emitter = MetricsEmitter(namespace="WebbPulse/Test", stream=_BrokenStream())
    emitter.put("Ingested", 1, "Count")
    emitter.flush()
    # Nothing is retained, so the next flush is a no-op rather than a retry that fails again.
    assert emitter.flush() is None


def test_an_unserialisable_property_falls_back_to_str_rather_than_losing_the_document() -> None:
    emitter, stream = _emitter()
    emitter.set_properties(when=object())
    emitter.put("Ingested", 1, "Count")
    emitter.flush()
    (payload,) = _lines(stream)
    assert payload["Ingested"] == 1.0
    assert isinstance(payload["when"], str)


# --------------------------------------------------------------------------------------
# The disabled switch
# --------------------------------------------------------------------------------------


def test_disabled_writes_nothing() -> None:
    emitter, stream = _emitter(enabled=False)
    emitter.set_dimensions(Environment="local")
    emitter.put("Ingested", 1, "Count")
    assert emitter.flush() is None
    assert stream.getvalue() == ""


def test_disabled_still_validates_a_bad_unit() -> None:
    """A typo should fail in a test suite, where metrics are off, not only in production."""
    emitter, _ = _emitter(enabled=False)
    with pytest.raises(ValueError, match="unit must be one of"):
        emitter.put("Ingested", 1, "Widgets")


# --------------------------------------------------------------------------------------
# The context manager
# --------------------------------------------------------------------------------------


def test_the_context_manager_flushes_on_exit() -> None:
    stream = io.StringIO()
    with MetricsEmitter(namespace="WebbPulse/Test", stream=stream) as emitter:
        emitter.put("Ingested", 1, "Count")
        assert stream.getvalue() == ""
    assert len(_lines(stream)) == 1


def test_the_context_manager_flushes_what_it_had_when_the_body_raises() -> None:
    stream = io.StringIO()
    with (
        pytest.raises(RuntimeError),
        MetricsEmitter(namespace="WebbPulse/Test", stream=stream) as emitter,
    ):
        emitter.put("Ingested", 1, "Count")
        raise RuntimeError("boom")
    (payload,) = _lines(stream)
    assert payload["Ingested"] == 1.0


# --------------------------------------------------------------------------------------
# emit
# --------------------------------------------------------------------------------------


def test_emit_writes_the_carmodpicker_crawler_document_unchanged() -> None:
    """The metric names, units, dimension names and namespace CarModPicker emits today.

    Any of these changing breaks the existing alarm, which filters on
    `RunType=live`, so the whole shape is pinned rather than sampled.
    """
    stream = io.StringIO()
    emit(
        namespace="CarModPicker/Crawlers",
        dimensions={"AdapterName": "acme", "Environment": "staging", "RunType": "live"},
        metrics={
            "Ingested": (12, "Count"),
            "ParseFailures": (3, "Count"),
            "ElapsedSeconds": (4.5, "Seconds"),
        },
        stream=stream,
        timestamp_millis=1_700_000_000_000,
    )
    (payload,) = _lines(stream)
    (metric_set,) = payload["_aws"]["CloudWatchMetrics"]
    assert metric_set["Namespace"] == "CarModPicker/Crawlers"
    assert metric_set["Dimensions"] == [["AdapterName", "Environment", "RunType"]]
    assert metric_set["Metrics"] == [
        {"Name": "ElapsedSeconds", "Unit": "Seconds"},
        {"Name": "Ingested", "Unit": "Count"},
        {"Name": "ParseFailures", "Unit": "Count"},
    ]
    assert payload["Ingested"] == 12.0
    assert payload["ParseFailures"] == 3.0
    assert payload["ElapsedSeconds"] == 4.5
    assert payload["AdapterName"] == "acme"
    assert payload["RunType"] == "live"


def test_emit_defaults_a_bare_number_to_count() -> None:
    stream = io.StringIO()
    emit(namespace="WebbPulse/Test", metrics={"Ingested": 7}, stream=stream)
    (payload,) = _lines(stream)
    (metric_set,) = payload["_aws"]["CloudWatchMetrics"]
    assert metric_set["Metrics"] == [{"Name": "Ingested", "Unit": "Count"}]


def test_emit_carries_properties_without_making_them_dimensions() -> None:
    stream = io.StringIO()
    emit(
        namespace="WebbPulse/Test",
        metrics={"Ingested": 1},
        dimensions={"Environment": "staging"},
        properties={"job_id": "a-very-unbounded-value"},
        stream=stream,
    )
    (payload,) = _lines(stream)
    (metric_set,) = payload["_aws"]["CloudWatchMetrics"]
    assert metric_set["Dimensions"] == [["Environment"]]
    assert payload["job_id"] == "a-very-unbounded-value"


def test_emit_returns_none_when_there_are_no_metrics() -> None:
    stream = io.StringIO()
    assert emit(namespace="WebbPulse/Test", metrics={}, stream=stream) is None


def test_emit_returns_none_when_disabled() -> None:
    stream = io.StringIO()
    assert (
        emit(
            namespace="WebbPulse/Test",
            metrics={"Ingested": 1},
            enabled=False,
            stream=stream,
        )
        is None
    )
    assert stream.getvalue() == ""


def test_emit_writes_to_stdout_by_default(capsys: pytest.CaptureFixture[str]) -> None:
    emit(namespace="WebbPulse/Test", metrics={"Ingested": 1})
    assert json.loads(capsys.readouterr().out.strip())["Ingested"] == 1.0


# --------------------------------------------------------------------------------------
# timed
# --------------------------------------------------------------------------------------


def test_timed_records_a_duration_in_milliseconds_by_default() -> None:
    emitter, stream = _emitter()
    with timed(emitter, "Elapsed"):
        pass
    emitter.flush()
    (payload,) = _lines(stream)
    assert payload["Elapsed"] >= 0.0
    (metric_set,) = payload["_aws"]["CloudWatchMetrics"]
    assert metric_set["Metrics"] == [{"Name": "Elapsed", "Unit": "Milliseconds"}]


def test_timed_accepts_seconds() -> None:
    emitter, stream = _emitter()
    with timed(emitter, "ElapsedSeconds", unit="Seconds"):
        pass
    emitter.flush()
    (payload,) = _lines(stream)
    (metric_set,) = payload["_aws"]["CloudWatchMetrics"]
    assert metric_set["Metrics"] == [{"Name": "ElapsedSeconds", "Unit": "Seconds"}]


def test_timed_accepts_microseconds() -> None:
    emitter, stream = _emitter()
    with timed(emitter, "Elapsed", unit="Microseconds"):
        pass
    emitter.flush()
    (payload,) = _lines(stream)
    (metric_set,) = payload["_aws"]["CloudWatchMetrics"]
    assert metric_set["Metrics"] == [{"Name": "Elapsed", "Unit": "Microseconds"}]


def test_timed_rejects_a_unit_that_is_not_a_duration() -> None:
    emitter, _ = _emitter()
    # The unit is validated before the block is entered, so `timed` raises on the `with`
    # line itself rather than on the way out. Constructing it without entering proves that.
    with pytest.raises(ValueError, match="timed unit must be a duration"):
        timed(emitter, "Elapsed", unit="Count").__enter__()


def test_timed_records_the_duration_even_when_the_block_raises() -> None:
    emitter, stream = _emitter()
    with pytest.raises(RuntimeError), timed(emitter, "Elapsed"):
        raise RuntimeError("boom")
    emitter.flush()
    (payload,) = _lines(stream)
    assert payload["Elapsed"] >= 0.0
