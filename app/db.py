"""Scan history in PostgreSQL: one table, raw SQL, one connection per call.

Every public function raises StorageError, and nothing else, when the database
cannot be reached or refuses the work. The caller decides how to degrade.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from app import config
from app.detector.models import Finding

CONNECT_TIMEOUT_SECONDS = 5
DEFAULT_HISTORY_LIMIT = 50

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
    served_by   TEXT        NOT NULL
)
"""

CREATE_INDEX_SQL = "CREATE INDEX IF NOT EXISTS scans_created_at_idx ON scans (created_at DESC)"

# Held until the transaction ends, not released explicitly. An explicit unlock
# comes before the commit, so a second instance could take the lock, miss the
# first one's still-uncommitted table, and fail creating it again.
LOCK_SQL = "SELECT pg_advisory_xact_lock(%s)"

INSERT_SQL = """
INSERT INTO scans (filename, sender, subject, score, verdict, decided_by, findings, served_by)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
RETURNING id
"""

RECENT_SQL = """
SELECT id, created_at, filename, sender, subject, score, verdict, decided_by, findings, served_by
FROM scans
ORDER BY created_at DESC, id DESC
LIMIT %s
"""

# PostgreSQL refuses NUL in TEXT and in JSONB strings, and a crafted email can put
# one in its subject. Replaced with the Unicode replacement character on the way in.
_NUL = "\x00"
_REPLACEMENT_CHARACTER = "�"

# Set once this process has made sure the table exists, so later calls skip it.
_schema_ready = False


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
    id: int | None = None  # assigned by the database
    created_at: datetime | None = None  # assigned by the database, in UTC


def init_schema() -> None:
    """Create the scans table and its index if they do not exist yet.

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
    """
    try:
        with _connect() as connection:
            yield connection
    except (psycopg.Error, config.ConfigError) as error:
        raise StorageError(f"{type(error).__name__}: {error}") from error


def _connect() -> psycopg.Connection:
    """Open a connection, retrying once with a fresh password if the first attempt fails.

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
    return psycopg.connect(
        host=settings.db_host,
        port=settings.db_port,
        dbname=settings.db_name,
        user=settings.db_user,
        password=password,
        connect_timeout=CONNECT_TIMEOUT_SECONDS,
    )


def _create_schema(connection: psycopg.Connection) -> None:
    connection.execute(LOCK_SQL, (INIT_LOCK_ID,))
    connection.execute(CREATE_TABLE_SQL)
    connection.execute(CREATE_INDEX_SQL)


def _ensure_schema(connection: psycopg.Connection) -> None:
    """Create the schema on this process's first use of the database.

    Done lazily rather than at startup, so the application starts, and /health
    answers, while the database is unreachable.
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
        id=row["id"],
        created_at=created_at.astimezone(UTC) if isinstance(created_at, datetime) else None,
    )
