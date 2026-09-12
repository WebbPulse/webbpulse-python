"""Tests for `webbpulse.metrics`.

The EMF document is pinned key by key, because a malformed `_aws` block has no error
surface: the metric is silently not created and the alarm stays in INSUFFICIENT_DATA.
"""

from __future__ import annotations

import io
import json
import logging
from typing import Any

import pytest

from webbpulse.metrics import (
    DEFAULT_METRIC_ENVIRONMENTS,
    EMF_MAX_DIMENSIONS,
    UNITS,
    MetricsEmitter,
    emit,
    metrics_enabled_from_env,
    timed,
)


def _emitter(**kwargs: Any) -> tuple[MetricsEmitter, io.StringIO]:
    """Build an emitter writing to an in-memory stream, and return both."""
    stream = io.StringIO()
    kwargs.setdefault("namespace", "WebbPulse/Test")
    return MetricsEmitter(stream=stream, **kwargs), stream


def _lines(stream: io.StringIO) -> list[dict[str, Any]]:
    """Parse every non-empty line written to the stream as JSON."""
    return [json.loads(line) for line in stream.getvalue().splitlines() if line]


def test_a_namespace_is_required() -> None:
    """An empty namespace is rejected at construction."""
    with pytest.raises(ValueError, match="namespace is required"):
        MetricsEmitter(namespace="")


def test_a_blank_namespace_is_rejected() -> None:
    """A whitespace only namespace is rejected at construction."""
    with pytest.raises(ValueError, match="namespace is required"):
        MetricsEmitter(namespace="   ")


def test_dimensions_and_properties_can_be_passed_to_the_constructor() -> None:
    """Constructor dimensions and properties reach the emitted document."""
    emitter, stream = _emitter(dimensions={"Environment": "staging"}, properties={"job_id": "abc"})
    emitter.put("Ingested", 1, "Count")
    emitter.flush()
    (payload,) = _lines(stream)
    assert payload["Environment"] == "staging"
    assert payload["job_id"] == "abc"


def test_the_document_carries_the_aws_directive_cloudwatch_parses() -> None:
    """The `_aws` block carries the timestamp, namespace, dimension set and metric list."""
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
    """Each dimension value is also written as a top level key."""
    emitter, stream = _emitter()
    emitter.set_dimensions(AdapterName="acme", Environment="staging")
    emitter.put("Ingested", 1, "Count")
    emitter.flush()
    (payload,) = _lines(stream)
    assert payload["AdapterName"] == "acme"
    assert payload["Environment"] == "staging"


def test_a_single_value_is_written_as_a_scalar() -> None:
    """One `put` writes the value as a scalar, not a single element list."""
    emitter, stream = _emitter()
    emitter.put("Ingested", 12, "Count")
    emitter.flush()
    (payload,) = _lines(stream)
    assert payload["Ingested"] == 12.0


def test_repeated_puts_accumulate_into_one_array_rather_than_one_document_each() -> None:
    """Repeated puts of one metric become an array in a single document."""
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
    """A `put` with no unit omits the Unit key from the metric definition."""
    emitter, stream = _emitter()
    emitter.put("Ratio", 0.5)
    emitter.flush()
    (payload,) = _lines(stream)
    (metric_set,) = payload["_aws"]["CloudWatchMetrics"]
    assert metric_set["Metrics"] == [{"Name": "Ratio"}]


def test_the_default_storage_resolution_is_omitted() -> None:
    """StorageResolution is omitted unless it is asked for."""
    emitter, stream = _emitter()
    emitter.put("Ingested", 1, "Count")
    emitter.flush()
    (payload,) = _lines(stream)
    (metric_set,) = payload["_aws"]["CloudWatchMetrics"]
    assert "StorageResolution" not in metric_set["Metrics"][0]


def test_high_resolution_is_written_when_asked_for() -> None:
    """`storage_resolution=1` is written into the metric definition."""
    emitter, stream = _emitter()
    emitter.put("Ingested", 1, "Count", storage_resolution=1)
    emitter.flush()
    (payload,) = _lines(stream)
    (metric_set,) = payload["_aws"]["CloudWatchMetrics"]
    assert metric_set["Metrics"][0]["StorageResolution"] == 1


def test_metric_names_are_sorted_so_the_document_is_deterministic() -> None:
    """Metric definitions come out sorted by name."""
    emitter, stream = _emitter()
    emitter.put("Zebra", 1, "Count")
    emitter.put("Alpha", 2, "Count")
    emitter.flush()
    (payload,) = _lines(stream)
    (metric_set,) = payload["_aws"]["CloudWatchMetrics"]
    assert [m["Name"] for m in metric_set["Metrics"]] == ["Alpha", "Zebra"]


def test_the_timestamp_defaults_to_now_in_milliseconds() -> None:
    """With no timestamp given, the document carries epoch milliseconds, not seconds."""
    emitter, stream = _emitter()
    emitter.put("Ingested", 1, "Count")
    emitter.flush()
    (payload,) = _lines(stream)
    assert 1_600_000_000_000 < payload["_aws"]["Timestamp"] < 4_000_000_000_000


def test_the_document_is_one_line() -> None:
    """A flush writes exactly one newline terminated line."""
    emitter, stream = _emitter()
    emitter.set_properties(note="a value")
    emitter.put("Ingested", 1, "Count")
    emitter.flush()
    assert stream.getvalue().count("\n") == 1


def test_document_builds_without_writing_anything() -> None:
    """`document` returns the payload without writing to the stream."""
    emitter, stream = _emitter()
    emitter.put("Ingested", 1, "Count")
    document = emitter.document(timestamp_millis=1)
    assert document["Ingested"] == 1.0
    assert stream.getvalue() == ""


def test_an_unknown_unit_is_rejected_at_the_call_site() -> None:
    """`put` raises on a unit CloudWatch does not define."""
    emitter, _ = _emitter()
    with pytest.raises(ValueError, match="unit must be one of"):
        emitter.put("Ingested", 1, "Widgets")


def test_every_documented_cloudwatch_unit_is_accepted() -> None:
    """Every unit in `UNITS` is accepted by `put`."""
    emitter, _ = _emitter()
    for unit in sorted(UNITS):
        emitter.put("Metric", 1, unit)


def test_too_many_dimensions_are_rejected() -> None:
    """More than the EMF dimension ceiling is rejected."""
    emitter, _ = _emitter()
    too_many = {f"D{i}": str(i) for i in range(EMF_MAX_DIMENSIONS + 1)}
    with pytest.raises(ValueError, match="at most 9 dimensions"):
        emitter.set_dimensions(**too_many)


def test_the_dimension_ceiling_itself_is_allowed() -> None:
    """Exactly the EMF dimension ceiling is accepted."""
    emitter, _ = _emitter()
    at_limit = {f"D{i}": str(i) for i in range(EMF_MAX_DIMENSIONS)}
    emitter.set_dimensions(**at_limit)


def test_a_blank_dimension_value_is_rejected_before_it_voids_the_document() -> None:
    """A blank dimension value raises and names the offending dimension."""
    emitter, _ = _emitter()
    with pytest.raises(ValueError, match="must not be blank: Environment"):
        emitter.set_dimensions(AdapterName="acme", Environment="")


def test_a_non_string_dimension_value_is_coerced() -> None:
    """A non-string dimension value is written as its string form."""
    emitter, stream = _emitter()
    emitter.set_dimensions(Shard=3)  # type: ignore[arg-type]
    emitter.put("Ingested", 1, "Count")
    emitter.flush()
    (payload,) = _lines(stream)
    assert payload["Shard"] == "3"


def test_setters_return_self_so_calls_chain() -> None:
    """`set_dimensions`, `set_properties` and `put` return the emitter, so calls chain."""
    emitter, stream = _emitter()
    emitter.set_dimensions(Environment="staging").set_properties(job="x").put("Ingested", 1, "Count")
    emitter.flush()
    (payload,) = _lines(stream)
    assert payload["Environment"] == "staging"
    assert payload["job"] == "x"


def test_a_flush_with_no_metrics_writes_nothing() -> None:
    """A flush with nothing recorded returns None and writes nothing."""
    emitter, stream = _emitter()
    assert emitter.flush() is None
    assert stream.getvalue() == ""


def test_a_flush_returns_the_line_it_wrote() -> None:
    """A flush returns the JSON line it wrote."""
    emitter, _stream = _emitter()
    emitter.put("Ingested", 1, "Count")
    line = emitter.flush()
    assert line is not None
    assert json.loads(line)["Ingested"] == 1.0


def test_a_flush_clears_the_values_so_a_reused_emitter_does_not_double_report() -> None:
    """A flush clears recorded values but keeps the dimensions for the next document."""
    emitter, stream = _emitter()
    emitter.set_dimensions(Environment="staging")
    emitter.put("Ingested", 1, "Count")
    emitter.flush()
    emitter.put("Ingested", 2, "Count")
    emitter.flush()
    first, second = _lines(stream)
    assert first["Ingested"] == 1.0
    assert second["Ingested"] == 2.0
    assert second["Environment"] == "staging"


def test_the_stream_is_flushed_so_a_lambda_freeze_cannot_lose_the_line() -> None:
    """The emitter flushes the stream once per written document."""

    class _CountingStream(io.StringIO):
        """A stream that counts how many times it was flushed."""

        flushes = 0

        def flush(self) -> None:
            """Count this flush instead of performing one."""
            type(self).flushes += 1

    stream = _CountingStream()
    emitter = MetricsEmitter(namespace="WebbPulse/Test", stream=stream)
    emitter.put("Ingested", 1, "Count")
    emitter.flush()
    assert _CountingStream.flushes == 1


def test_stdout_is_resolved_at_flush_time(capsys: pytest.CaptureFixture[str]) -> None:
    """With no `stream`, `sys.stdout` is read at flush time rather than at construction."""
    emitter = MetricsEmitter(namespace="WebbPulse/Test")
    emitter.put("Ingested", 5, "Count")
    emitter.flush()
    captured = capsys.readouterr()
    assert json.loads(captured.out.strip())["Ingested"] == 5.0


def test_a_stream_failure_is_logged_and_swallowed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A stream that raises on write is logged as an error and does not propagate."""

    class _BrokenStream(io.StringIO):
        """A stream that fails every write."""

        def write(self, s: str) -> int:
            """Raise as a closed stream would."""
            raise OSError("stream is closed")

    emitter = MetricsEmitter(namespace="WebbPulse/Test", stream=_BrokenStream())
    emitter.put("Ingested", 1, "Count")
    with caplog.at_level(logging.ERROR, logger="webbpulse.metrics"):
        assert emitter.flush() is None
    assert "failed to emit EMF metrics" in caplog.text


def test_a_failed_flush_still_clears_the_values() -> None:
    """A failed flush retains nothing, so the next flush is a no-op."""

    class _BrokenStream(io.StringIO):
        """A stream that fails every write."""

        def write(self, s: str) -> int:
            """Raise as a closed stream would."""
            raise OSError("stream is closed")

    emitter = MetricsEmitter(namespace="WebbPulse/Test", stream=_BrokenStream())
    emitter.put("Ingested", 1, "Count")
    emitter.flush()
    assert emitter.flush() is None


def test_an_unserialisable_property_falls_back_to_str_rather_than_losing_the_document() -> None:
    """An unserialisable property is written as a string and the document still emits."""
    emitter, stream = _emitter()
    emitter.set_properties(when=object())
    emitter.put("Ingested", 1, "Count")
    emitter.flush()
    (payload,) = _lines(stream)
    assert payload["Ingested"] == 1.0
    assert isinstance(payload["when"], str)


def test_disabled_writes_nothing() -> None:
    """A disabled emitter records nothing and writes nothing on flush."""
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


def test_the_context_manager_flushes_on_exit() -> None:
    """Used as a context manager, the emitter writes its document on exit and not before."""
    stream = io.StringIO()
    with MetricsEmitter(namespace="WebbPulse/Test", stream=stream) as emitter:
        emitter.put("Ingested", 1, "Count")
        assert stream.getvalue() == ""
    assert len(_lines(stream)) == 1


def test_the_context_manager_flushes_what_it_had_when_the_body_raises() -> None:
    """A raising body still flushes whatever was already recorded."""
    stream = io.StringIO()
    with (
        pytest.raises(RuntimeError),
        MetricsEmitter(namespace="WebbPulse/Test", stream=stream) as emitter,
    ):
        emitter.put("Ingested", 1, "Count")
        raise RuntimeError("boom")
    (payload,) = _lines(stream)
    assert payload["Ingested"] == 1.0


def test_emit_writes_the_carmodpicker_crawler_document_unchanged() -> None:
    """`emit` writes the crawler namespace, dimension names, metric names and units intact."""
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
    """A metric given as a bare number is emitted with the Count unit."""
    stream = io.StringIO()
    emit(namespace="WebbPulse/Test", metrics={"Ingested": 7}, stream=stream)
    (payload,) = _lines(stream)
    (metric_set,) = payload["_aws"]["CloudWatchMetrics"]
    assert metric_set["Metrics"] == [{"Name": "Ingested", "Unit": "Count"}]


def test_emit_carries_properties_without_making_them_dimensions() -> None:
    """Properties reach the document as keys but are not listed as dimensions."""
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
    """`emit` with no metrics returns None."""
    stream = io.StringIO()
    assert emit(namespace="WebbPulse/Test", metrics={}, stream=stream) is None


def test_emit_returns_none_when_disabled() -> None:
    """`enabled=False` makes `emit` return None and write nothing."""
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
    """With no stream, `emit` writes its document to stdout."""
    emit(namespace="WebbPulse/Test", metrics={"Ingested": 1})
    assert json.loads(capsys.readouterr().out.strip())["Ingested"] == 1.0


def test_timed_records_a_duration_in_milliseconds_by_default() -> None:
    """`timed` records a non-negative duration with the Milliseconds unit."""
    emitter, stream = _emitter()
    with timed(emitter, "Elapsed"):
        pass
    emitter.flush()
    (payload,) = _lines(stream)
    assert payload["Elapsed"] >= 0.0
    (metric_set,) = payload["_aws"]["CloudWatchMetrics"]
    assert metric_set["Metrics"] == [{"Name": "Elapsed", "Unit": "Milliseconds"}]


def test_timed_accepts_seconds() -> None:
    """`timed` records the duration with the Seconds unit when asked."""
    emitter, stream = _emitter()
    with timed(emitter, "ElapsedSeconds", unit="Seconds"):
        pass
    emitter.flush()
    (payload,) = _lines(stream)
    (metric_set,) = payload["_aws"]["CloudWatchMetrics"]
    assert metric_set["Metrics"] == [{"Name": "ElapsedSeconds", "Unit": "Seconds"}]


def test_timed_accepts_microseconds() -> None:
    """`timed` records the duration with the Microseconds unit when asked."""
    emitter, stream = _emitter()
    with timed(emitter, "Elapsed", unit="Microseconds"):
        pass
    emitter.flush()
    (payload,) = _lines(stream)
    (metric_set,) = payload["_aws"]["CloudWatchMetrics"]
    assert metric_set["Metrics"] == [{"Name": "Elapsed", "Unit": "Microseconds"}]


def test_timed_rejects_a_unit_that_is_not_a_duration() -> None:
    """A non-duration unit raises on entering the block rather than on the way out."""
    emitter, _ = _emitter()
    with pytest.raises(ValueError, match="timed unit must be a duration"):
        timed(emitter, "Elapsed", unit="Count").__enter__()


def test_timed_records_the_duration_even_when_the_block_raises() -> None:
    """A raising block still records its duration."""
    emitter, stream = _emitter()
    with pytest.raises(RuntimeError), timed(emitter, "Elapsed"):
        raise RuntimeError("boom")
    emitter.flush()
    (payload,) = _lines(stream)
    assert payload["Elapsed"] >= 0.0


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neither variable set, so a workstation's own environment cannot decide a test."""
    monkeypatch.delenv("TESTING", raising=False)
    monkeypatch.delenv("ENVIRONMENT", raising=False)


@pytest.mark.parametrize("environment", DEFAULT_METRIC_ENVIRONMENTS)
def test_metrics_are_live_in_the_deployed_environments(clean_env: None, environment: str) -> None:
    """Each deployed environment in the default set enables metrics."""
    assert metrics_enabled_from_env(environment) is True


@pytest.mark.parametrize("environment", ["development", "dev", "local", "preview", "test"])
def test_metrics_are_silent_everywhere_else(clean_env: None, environment: str) -> None:
    """An environment outside the default set leaves metrics off."""
    assert metrics_enabled_from_env(environment) is False


@pytest.mark.parametrize("value", ["true", "True", "TRUE", " true ", "1", "yes", "on"])
def test_the_testing_variable_wins_over_an_allowed_environment(
    clean_env: None, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """A test suite emitting real EMF would put test data on the production metric."""
    monkeypatch.setenv("TESTING", value)
    assert metrics_enabled_from_env("production") is False


@pytest.mark.parametrize("value", ["false", "False", "0", "no", "", "  "])
def test_a_falsey_testing_variable_does_not_suppress_metrics(
    clean_env: None, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """A falsey TESTING value leaves metrics enabled in an allowed environment."""
    monkeypatch.setenv("TESTING", value)
    assert metrics_enabled_from_env("production") is True


def test_the_environment_is_read_from_the_environment_when_not_passed(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A service without a settings object passes nothing and still gets the right answer."""
    monkeypatch.setenv("ENVIRONMENT", "staging")
    assert metrics_enabled_from_env() is True
    monkeypatch.setenv("ENVIRONMENT", "development")
    assert metrics_enabled_from_env() is False


def test_an_unset_environment_is_silent_rather_than_live(clean_env: None) -> None:
    """A missing variable must fail closed: silence beats noise from an unknown source."""
    assert metrics_enabled_from_env() is False


@pytest.mark.parametrize("environment", ["", "   "])
def test_a_blank_environment_is_silent(clean_env: None, environment: str) -> None:
    """A blank environment name leaves metrics off."""
    assert metrics_enabled_from_env(environment) is False


@pytest.mark.parametrize("environment", ["Production", " STAGING ", "pRoDuCtIoN"])
def test_the_environment_is_matched_case_insensitively_after_a_strip(clean_env: None, environment: str) -> None:
    """These values arrive from Terraform and a task definition, not from code."""
    assert metrics_enabled_from_env(environment) is True


def test_the_allowed_set_can_be_overridden(clean_env: None) -> None:
    """An explicit `allowed` set replaces the default one."""
    assert metrics_enabled_from_env("preview", allowed=("preview",)) is True
    assert metrics_enabled_from_env("production", allowed=("preview",)) is False


def test_the_allowed_set_is_normalised_too(clean_env: None) -> None:
    """Entries in `allowed` are stripped and matched case insensitively."""
    assert metrics_enabled_from_env("preview", allowed=(" Preview ",)) is True


def test_the_variable_names_can_be_overridden(clean_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    """`testing_var` and `environment_var` select which variables the gate reads."""
    monkeypatch.setenv("PYTEST_RUNNING", "true")
    monkeypatch.setenv("APP_ENV", "production")
    assert metrics_enabled_from_env(testing_var="PYTEST_RUNNING", environment_var="APP_ENV") is False
    monkeypatch.delenv("PYTEST_RUNNING")
    assert metrics_enabled_from_env(testing_var="PYTEST_RUNNING", environment_var="APP_ENV") is True


def test_the_gate_composes_with_enabled_rather_than_replacing_it(clean_env: None) -> None:
    """The helper returns a bool and touches nothing; `enabled` still defaults to True."""
    stream = io.StringIO()
    assert (
        emit(
            namespace="WebbPulse/Test",
            metrics={"Ingested": 1},
            enabled=metrics_enabled_from_env("development"),
            stream=stream,
        )
        is None
    )
    assert stream.getvalue() == ""

    line = emit(
        namespace="WebbPulse/Test",
        metrics={"Ingested": 1},
        enabled=metrics_enabled_from_env("production"),
        stream=stream,
    )
    assert line is not None
    assert json.loads(line)["Ingested"] == 1


def test_metrics_emitter_still_defaults_to_enabled(clean_env: None) -> None:
    """0.8.0 adds a helper; it does not move the constructor default under anyone."""
    assert MetricsEmitter(namespace="WebbPulse/Test").enabled is True
