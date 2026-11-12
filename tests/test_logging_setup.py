"""Tests for the JSON log format and where the lines go."""

import json
import logging
import re

import pytest

from app.logging_setup import JsonFormatter, configure_logging, error_fields, log_event

TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
REQUIRED_FIELDS = {"ts", "level", "host", "event"}
INSTANCE_ID = "i-0123456789abcdef0"


def record_for(name: str, /, error: BaseException | None = None, **fields: object):
    """Return the LogRecord that log_event() would produce, without emitting it."""
    captured: list[logging.LogRecord] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(record)

    logger = logging.getLogger("tests.logging_setup")
    handler = Capture()
    logger.addHandler(handler)
    try:
        log_event(logger, logging.WARNING, name, error=error, **fields)
    finally:
        logger.removeHandler(handler)
    return captured[0]


def formatted(name: str, /, error: BaseException | None = None, **fields: object) -> dict:
    line = JsonFormatter(INSTANCE_ID).format(record_for(name, error=error, **fields))
    assert "\n" not in line
    return json.loads(line)


def raised(error: Exception) -> Exception:
    """Return the error with a traceback, as it would be when caught."""
    try:
        raise error
    except Exception as caught:
        return caught


def test_every_line_has_the_required_fields():
    line = formatted("scan")

    assert set(line) >= REQUIRED_FIELDS
    assert (line["level"], line["event"]) == ("WARNING", "scan")
    assert TIMESTAMP.match(line["ts"])


def test_host_is_the_instance_identifier():
    line = formatted("scan")

    assert line["host"] == INSTANCE_ID


def test_fields_are_added_to_the_line():
    line = formatted("scan", path="/scan", status=200, duration_ms=38)

    assert (line["path"], line["status"], line["duration_ms"]) == ("/scan", 200, 38)


def test_a_field_cannot_overwrite_a_required_field():
    line = formatted("scan", host="spoofed", event="spoofed")

    assert (line["host"], line["event"]) == (INSTANCE_ID, "scan")


def test_an_error_adds_its_type_message_and_traceback():
    line = formatted("unhandled_error", error=raised(RuntimeError("boom")))

    assert (line["error_type"], line["error_message"]) == ("RuntimeError", "boom")
    assert "Traceback" in line["traceback"]


def test_error_fields_name_an_expected_error_briefly():
    assert error_fields(ValueError("bad port")) == {
        "error_type": "ValueError",
        "error_message": "bad port",
    }


def test_values_that_are_not_json_are_written_as_text():
    line = formatted("odd", value=frozenset({"a"}))

    assert line["value"] == "frozenset({'a'})"


def test_log_file_receives_json_lines(restore_root_logger, tmp_path):
    log_file = tmp_path / "app.log"
    configure_logging(str(log_file), INSTANCE_ID)

    log_event(logging.getLogger("tests"), logging.INFO, "scan", status=200)

    (line,) = log_file.read_text(encoding="utf-8").splitlines()
    assert json.loads(line)["status"] == 200


def test_configured_lines_carry_the_instance_identifier(restore_root_logger, tmp_path):
    log_file = tmp_path / "app.log"
    configure_logging(str(log_file), INSTANCE_ID)

    log_event(logging.getLogger("tests"), logging.INFO, "scan")

    assert json.loads(log_file.read_text(encoding="utf-8"))["host"] == INSTANCE_ID


def test_configuring_twice_does_not_duplicate_lines(restore_root_logger, tmp_path):
    log_file = tmp_path / "app.log"
    configure_logging(str(log_file), INSTANCE_ID)
    configure_logging(str(log_file), INSTANCE_ID)

    log_event(logging.getLogger("tests"), logging.INFO, "scan")

    assert len(log_file.read_text(encoding="utf-8").splitlines()) == 1


def test_empty_log_file_setting_logs_to_stdout(restore_root_logger, capsys):
    configure_logging("", INSTANCE_ID)

    log_event(logging.getLogger("tests"), logging.INFO, "scan")

    assert json.loads(capsys.readouterr().out)["event"] == "scan"


def test_unwritable_log_file_stops_startup(restore_root_logger, tmp_path):
    with pytest.raises(OSError):
        configure_logging(str(tmp_path / "missing-directory" / "app.log"), INSTANCE_ID)
