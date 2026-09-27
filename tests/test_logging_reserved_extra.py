"""Tests for how `configure_logging` handles an `extra` key that names a `LogRecord` attribute."""

from __future__ import annotations

import io
import json
import logging
from collections.abc import Iterator
from typing import Any

import pytest

from webbpulse import logging as webbpulse_logging
from webbpulse.logging import configure_logging


@pytest.fixture
def stream() -> Iterator[io.StringIO]:
    """Configure JSON logging onto a fresh buffer and yield it."""
    buffer = io.StringIO()
    configure_logging(level="DEBUG", force=True, stream=buffer)
    yield buffer
    configure_logging(level="INFO", force=True)


def _lines(buffer: io.StringIO) -> list[dict[str, Any]]:
    """Parse every JSON line written to `buffer`."""
    return [json.loads(line) for line in buffer.getvalue().splitlines() if line]


def test_a_created_key_is_renamed_rather_than_raising(stream: io.StringIO) -> None:
    """`created` would raise `KeyError` in the standard library; it lands as `extra_created`."""
    logging.getLogger("sweep").info("swept", extra={"created": 7})
    (line,) = _lines(stream)
    assert line["extra_created"] == 7
    assert line["message"] == "swept"
    assert line["timestamp"].startswith("20")


def test_the_real_record_attribute_is_left_untouched(stream: io.StringIO) -> None:
    """The renamed key does not overwrite the record's own `created` timestamp."""
    records: list[logging.LogRecord] = []

    class Capture(logging.Handler):
        """Keep every record handled."""

        def emit(self, record: logging.LogRecord) -> None:
            """Store the record."""
            records.append(record)

    logger = logging.getLogger("sweep.capture")
    handler = Capture()
    logger.addHandler(handler)
    try:
        logger.info("swept", extra={"created": 7, "name": "other"})
    finally:
        logger.removeHandler(handler)
    (record,) = records
    assert isinstance(record.created, float)
    assert record.name == "sweep.capture"
    assert record.__dict__["extra_created"] == 7
    assert record.__dict__["extra_name"] == "other"


@pytest.mark.parametrize("key", ["message", "asctime"])
def test_message_and_asctime_are_renamed(stream: io.StringIO, key: str) -> None:
    """The two keys the standard library refuses by name are renamed too."""
    logging.getLogger("sweep").info("real", extra={key: "fake"})
    (line,) = _lines(stream)
    assert line["message"] == "real"
    assert line[f"extra_{key}"] == "fake"


def test_a_logger_created_before_configure_logging_is_guarded() -> None:
    """A module-level logger from before configuration is covered by the class-level override."""
    early = logging.getLogger("early.module.logger")
    buffer = io.StringIO()
    configure_logging(level="INFO", force=True, stream=buffer)
    try:
        early.info("late", extra={"lineno": 3, "process": "p"})
    finally:
        configure_logging(level="INFO", force=True)
    (line,) = _lines(buffer)
    assert line["extra_lineno"] == 3
    assert line["extra_process"] == "p"


def test_non_colliding_extras_are_unchanged(stream: io.StringIO) -> None:
    """An ordinary key keeps its name and no prefixed copy appears."""
    logging.getLogger("sweep").info("ok", extra={"count": 2, "job_id": "j"})
    (line,) = _lines(stream)
    assert line["count"] == 2
    assert line["job_id"] == "j"
    assert not any(key.startswith("extra_") for key in line)


def test_configuring_twice_does_not_wrap_twice() -> None:
    """A forced second configuration leaves exactly one override over the original."""
    configure_logging(level="INFO", force=True)
    configure_logging(level="INFO", force=True)
    safe = webbpulse_logging._safe_make_record
    assert logging.Logger.makeRecord is safe
    assert webbpulse_logging._delegate_make_record is not safe
