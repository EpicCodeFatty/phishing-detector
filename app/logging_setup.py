"""Structured logging: one JSON object per line.

Every line carries ts, level, host, release and event, so CloudWatch Logs
Insights can filter and count by field instead of parsing text. Extra fields
are attached with log_event().

host is the instance identifier: the same value users see as served_by, and
the name of the CloudWatch log stream the line lands in. release is the build
of the code that wrote the line, the same value /health reports.

Never pass the email body, an attachment or the database password as a field.
"""

import json
import logging
import sys
import traceback
from datetime import UTC, datetime
from logging.handlers import WatchedFileHandler

_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Name of the LogRecord attribute that carries the fields given to log_event().
_FIELDS_ATTRIBUTE = "fields"

# Marks the handler this module installs, so configuring twice replaces it rather
# than doubling every line, and handlers installed by others (pytest's) are left alone.
_OWN_HANDLER_MARK = "_json_lines"

# The development server logs its own line per request; log_event() already does.
_QUIET_LOGGERS = ("werkzeug",)


class JsonFormatter(logging.Formatter):
    """Format each record as a single line of JSON, stamped with the instance and the release."""

    def __init__(self, instance_id: str, release: str) -> None:
        super().__init__()
        self.instance_id = instance_id
        self.release = release

    def format(self, record: logging.LogRecord) -> str:
        """Return the record as JSON: ts, level, host, release, event, then the record's fields.

        A record logged with an exception also gets error_type, error_message and
        traceback, unless its fields already name the error.
        """
        required = {
            "ts": datetime.fromtimestamp(record.created, UTC).strftime(_TIMESTAMP_FORMAT),
            "level": record.levelname,
            "host": self.instance_id,
            "release": self.release,
            "event": record.getMessage(),
        }
        fields: dict[str, object] = getattr(record, _FIELDS_ATTRIBUTE, {})
        if record.exc_info and record.exc_info[1] is not None:
            error = record.exc_info[1]
            trace = "".join(traceback.format_exception(error))
            fields = error_fields(error) | {"traceback": trace} | fields
        # The required fields come first, for whoever tails the file, and a field can
        # never overwrite one of them.
        extra = {name: value for name, value in fields.items() if name not in required}
        return json.dumps(required | extra, default=str)


def configure_logging(log_file: str, instance_id: str, release: str) -> None:
    """Send every log line, as JSON, to log_file, or to stdout when log_file is ''.

    Each line's host field is instance_id and its release field is release.
    Safe to call more than once: the handler from an earlier call is replaced.
    Raises OSError when the log file cannot be opened, which is meant to stop
    the application from starting with nowhere to log.
    """
    handler = _handler_for(log_file)
    handler.setFormatter(JsonFormatter(instance_id, release))
    setattr(handler, _OWN_HANDLER_MARK, True)

    root = logging.getLogger()
    for previous in [h for h in root.handlers if getattr(h, _OWN_HANDLER_MARK, False)]:
        root.removeHandler(previous)
        previous.close()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    for name in _QUIET_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)


def log_event(
    logger: logging.Logger,
    level: int,
    event: str,
    /,
    error: BaseException | None = None,
    **fields: object,
) -> None:
    """Log one event with structured fields.

    Pass error only for a failure nobody anticipated: it adds a traceback. For an
    expected failure, pass **error_fields(error) instead, which names it briefly.
    """
    logger.log(level, event, exc_info=error, extra={_FIELDS_ATTRIBUTE: fields})


def error_fields(error: BaseException) -> dict[str, object]:
    """Return the fields that name an error in a log line: error_type and error_message."""
    return {"error_type": type(error).__name__, "error_message": str(error)}


def _handler_for(log_file: str) -> logging.Handler:
    if not log_file:
        return logging.StreamHandler(sys.stdout)
    # Reopens the file if logrotate moves it, so lines keep reaching the file the
    # CloudWatch agent reads instead of a renamed one.
    return WatchedFileHandler(log_file, encoding="utf-8")
