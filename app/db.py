"""Scan history in PostgreSQL: one table, raw SQL, one connection per call.

Every public function raises StorageError, and nothing else, when the database
cannot be reached or refuses the work. The caller decides how to degrade.

A circuit breaker stops this process calling a database that is known to be down, so its
slowness cannot spread to everything else. Once a connection cannot be made, every call
fails at once, without trying, for CIRCUIT_OPEN_SECONDS. After that one call is let
through: if it connects, calls go through again; if not, the wait starts over.
"""

import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from app import config
from app.detector.models import Finding
from app.logging_setup import error_fields, log_event

logger = logging.getLogger(__name__)

# Each instance runs two gunicorn workers, each serving one request at a time. While the
# database is unreachable, every request that needs it waits this long before failing; with
# both workers waiting, the load balancer's health check queues behind them, times out, and
# the instance is replaced for a fault that is not its own. Short, and the breaker below
# means a process pays it once per CIRCUIT_OPEN_SECONDS rather than once per request.
CONNECT_TIMEOUT_SECONDS = 3
CIRCUIT_OPEN_SECONDS = 15
DEFAULT_HISTORY_LIMIT = 50

# A StorageError's message is what gets logged. The driver's text is kept, because it is
# what tells a refused password from a timeout, but only this much of it, on one line.
MAX_ERROR_MESSAGE_LENGTH = 300
_REDACTED = "[redacted]"

# Identifies the schema-initialisation lock. Arbitrary but fixed: every instance
# must use the same value for the lock to serialise them.
INIT_LOCK_ID = 4815162342

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id          SERIAL PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    filename    TEXT        NOT NULL,
    sender      TEXT,
    subject     TEXT,
    score       INTEGER     NOT NULL,
    verdict     TEXT        NOT NULL,
    decided_by  TEXT,
    findings    JSONB       NOT NULL,
    served_by   TEXT        NOT NULL,
    cache_hit   BOOLEAN     NOT NULL DEFAULT false
)
"""

CREATE_INDEX_SQL = "CREATE INDEX IF NOT EXISTS scans_created_at_idx ON scans (created_at DESC)"

# cache_hit came after the table: CREATE TABLE IF NOT EXISTS has it, but does nothing to a
# table that already exists, as it does on RDS. The column is added there, once.
#
# Looked up before altering, because ALTER TABLE takes an exclusive lock on the table even
# when IF NOT EXISTS leaves it nothing to do, and this runs in every worker at every start.
#
# The default is what keeps a rolling deploy safe: while it runs, the previous release
# inserts rows without naming the column, and every query in both releases names its
# columns, so none reads a row by position. It is also what lets the previous release run
# again after a rollback.
CACHE_HIT_COLUMN_SQL = """
SELECT 1
FROM information_schema.columns
WHERE table_schema = current_schema() AND table_name = 'scans' AND column_name = 'cache_hit'
"""

ADD_CACHE_HIT_SQL = (
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS cache_hit BOOLEAN NOT NULL DEFAULT false"
)

# Held until the transaction ends, not released explicitly. An explicit unlock
# comes before the commit, so a second instance could take the lock, miss the
# first one's still-uncommitted table, and fail creating it again.
LOCK_SQL = "SELECT pg_advisory_xact_lock(%s)"

INSERT_SQL = """
INSERT INTO scans (
    filename, sender, subject, score, verdict, decided_by, findings, served_by, cache_hit
)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
RETURNING id
"""

RECENT_SQL = """
SELECT id, created_at, filename, sender, subject, score, verdict, decided_by, findings, served_by,
       cache_hit
FROM scans
ORDER BY created_at DESC, id DESC
LIMIT %s
"""

# The same columns as RECENT_SQL, written out again rather than shared: a statement built
# by joining strings is what a scanner, and a reviewer, is right to distrust on sight.
SCAN_SQL = """
SELECT id, created_at, filename, sender, subject, score, verdict, decided_by, findings, served_by,
       cache_hit
FROM scans
WHERE id = %s
"""

# PostgreSQL refuses NUL in TEXT and in JSONB strings, and a crafted email can put
# one in its subject. Replaced with the Unicode replacement character on the way in.
_NUL = "\x00"
_REPLACEMENT_CHARACTER = "�"

# Set once this process has made sure the table exists, so later calls skip it.
_schema_ready = False

# When this process last failed to connect, on the monotonic clock; None while connections
# are being made. Per process: gunicorn's workers are separate processes, and each finds out
# for itself, with one failed attempt, that the database is down.
_circuit_opened_at: float | None = None


class StorageError(Exception):
    """The scan history could not be read or written."""


@dataclass(frozen=True)
class ScanRecord:
    """One row of scan history."""

    filename: str
    sender: str | None  # the raw From header; None for input with no headers
    subject: str | None  # None for input with no headers
    score: int
    verdict: str
    decided_by: str
    findings: list[Finding]
    served_by: str  # identifier of the instance that ran the scan: its EC2 instance ID
    cache_hit: bool = False  # True when the result was reused from the cache, not analysed
    id: int | None = None  # assigned by the database
    created_at: datetime | None = None  # assigned by the database, in UTC


def init_schema() -> None:
    """Create the scans table and its index if they do not exist, and add any missing column.

    Safe to run from several instances at the same moment. Raises StorageError.
    """
    global _schema_ready
    with _connection() as connection:
        _create_schema(connection)
    _schema_ready = True


def save_scan(record: ScanRecord) -> int:
    """Insert a scan and return its new id. Raises StorageError."""
    with _connection() as connection:
        _ensure_schema(connection)
        row = connection.execute(INSERT_SQL, _insert_parameters(record)).fetchone()
    return row[0]


def recent_scans(limit: int = DEFAULT_HISTORY_LIMIT) -> list[ScanRecord]:
    """Return up to limit scans, most recent first. Raises StorageError."""
    with _connection() as connection:
        _ensure_schema(connection)
        rows = connection.cursor(row_factory=dict_row).execute(RECENT_SQL, (limit,)).fetchall()
    return [_record_from_row(row) for row in rows]


def get_scan(scan_id: int) -> ScanRecord | None:
    """Return the scan with this id, or None if there is none. Raises StorageError."""
    with _connection() as connection:
        _ensure_schema(connection)
        row = connection.cursor(row_factory=dict_row).execute(SCAN_SQL, (scan_id,)).fetchone()
    return _record_from_row(row) if row else None


def db_is_reachable() -> bool:
    """Tell whether the database accepts a connection. For diagnostics only, never /health."""
    try:
        with _connection() as connection:
            connection.execute("SELECT 1")
    except StorageError:
        return False
    return True


@contextmanager
def _connection() -> Iterator[psycopg.Connection]:
    """Yield a connection that commits when the block succeeds, and is always closed.

    Every database or configuration failure, here or in the block, becomes a StorageError.
    Failing to connect opens the circuit; while it is open this raises at once, without
    trying. A failure inside the block, once connected, leaves the circuit alone.
    """
    _admit_through_circuit()
    try:
        connection = _connect()
    except (psycopg.Error, config.ConfigError) as error:
        _open_circuit(error)
        raise _storage_error(error) from error
    _close_circuit()
    try:
        with connection:
            yield connection
    except (psycopg.Error, config.ConfigError) as error:
        raise _storage_error(error) from error


def _admit_through_circuit() -> None:
    """Raise StorageError while the circuit is open; once it has been open long enough, let one
    attempt through.

    The attempt re-arms the wait before it starts, so in a process serving several requests
    at once the others are still refused while it runs.
    """
    global _circuit_opened_at
    if _circuit_opened_at is None:
        return
    if time.monotonic() - _circuit_opened_at < CIRCUIT_OPEN_SECONDS:
        raise StorageError(
            f"CircuitOpen: a connection failed less than {CIRCUIT_OPEN_SECONDS} seconds ago; "
            "not trying again yet"
        )
    _circuit_opened_at = time.monotonic()


def _open_circuit(error: Exception) -> None:
    """Start the wait. Log a warning when the circuit opens, not when a trial attempt fails."""
    global _circuit_opened_at
    was_closed = _circuit_opened_at is None
    _circuit_opened_at = time.monotonic()
    if was_closed:
        log_event(
            logger,
            logging.WARNING,
            "db_circuit_open",
            open_seconds=CIRCUIT_OPEN_SECONDS,
            **error_fields(_storage_error(error)),
        )


def _close_circuit() -> None:
    global _circuit_opened_at
    _circuit_opened_at = None


def _storage_error(error: Exception) -> StorageError:
    return StorageError(f"{type(error).__name__}: {_brief(str(error))}")


def _connect() -> psycopg.Connection:
    """Open a connection, retrying once with a fresh password if the first attempt fails.

    Only the outcome of both attempts counts for the circuit: a password that went stale
    with a rotation is refreshed and retried, and does not open it.

    RDS rotates the password, and the cached one goes stale. psycopg reports a
    rejected password as a plain OperationalError with no SQLSTATE, so it cannot
    be told apart from other refusals without matching the server's message text,
    which depends on its locale. Refreshing on any refusal is cheap and safe; a
    timeout is the exception, since retrying it would double a long wait.
    """
    try:
        return _open(config.get_db_password())
    except psycopg.OperationalError as error:
        if isinstance(error, psycopg.errors.ConnectionTimeout):
            raise
    config.refresh_db_password()
    return _open(config.get_db_password())


def _open(password: str) -> psycopg.Connection:
    settings = config.get_settings()
    try:
        return psycopg.connect(
            host=settings.db_host,
            port=settings.db_port,
            dbname=settings.db_name,
            user=settings.db_user,
            password=password,
            sslmode=settings.db_sslmode,
            connect_timeout=CONNECT_TIMEOUT_SECONDS,
        )
    except psycopg.Error as error:
        # The message ends up in a log line. libpq does not quote the password in it, but
        # that is the driver's promise; raising a copy without it makes it this module's.
        # Same type, so a timeout is still told apart; `from None` keeps the original,
        # unredacted error out of any traceback.
        raise type(error)(_without(password, str(error))) from None


def _without(secret: str, message: str) -> str:
    """Return the message with every occurrence of the secret blanked out."""
    if not secret:
        return message
    return message.replace(secret, _REDACTED)


def _brief(message: str) -> str:
    """Return the message on one line, cut to MAX_ERROR_MESSAGE_LENGTH characters."""
    return " ".join(message.split())[:MAX_ERROR_MESSAGE_LENGTH]


def _create_schema(connection: psycopg.Connection) -> None:
    connection.execute(LOCK_SQL, (INIT_LOCK_ID,))
    connection.execute(CREATE_TABLE_SQL)
    connection.execute(CREATE_INDEX_SQL)
    if connection.execute(CACHE_HIT_COLUMN_SQL).fetchone() is None:
        connection.execute(ADD_CACHE_HIT_SQL)


def _ensure_schema(connection: psycopg.Connection) -> None:
    """Create the schema on this process's first use of the database, unless it is there.

    Startup tries init_schema() once and carries on if the database is
    unreachable, so the application starts, and /health answers, regardless.
    This is what makes up for a failed attempt, on the first call that gets through.
    """
    global _schema_ready
    if _schema_ready:
        return
    _create_schema(connection)
    _schema_ready = True


def _insert_parameters(record: ScanRecord) -> tuple[object, ...]:
    findings = [
        {key: _storable(value) for key, value in asdict(found).items()} for found in record.findings
    ]
    return (
        _storable(record.filename),
        _storable(record.sender),
        _storable(record.subject),
        record.score,
        record.verdict,
        _storable(record.decided_by),
        Jsonb(findings),
        _storable(record.served_by),
        record.cache_hit,
    )


def _storable[T](value: T) -> T:
    """Replace NUL characters in a string, which PostgreSQL refuses to store."""
    if isinstance(value, str):
        return value.replace(_NUL, _REPLACEMENT_CHARACTER)
    return value


def _record_from_row(row: dict[str, object]) -> ScanRecord:
    created_at = row["created_at"]
    return ScanRecord(
        filename=row["filename"],
        sender=row["sender"],
        subject=row["subject"],
        score=row["score"],
        verdict=row["verdict"],
        decided_by=row["decided_by"],
        findings=[Finding(**item) for item in row["findings"]],
        served_by=row["served_by"],
        cache_hit=row["cache_hit"],
        id=row["id"],
        created_at=created_at.astimezone(UTC) if isinstance(created_at, datetime) else None,
    )
