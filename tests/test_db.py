"""Tests for the database layer that need no database: psycopg is replaced."""

import logging
import traceback

import psycopg
import pytest

from app import config, db
from app.detector.models import finding

# Stands in for the database password wherever a test checks that it is never repeated.
PASSWORD_MARKER = "s3cret-PASSWORD-marker-91f2"


class FakeConnection:
    """Enough of a psycopg connection to be opened, used in a with block and closed."""

    def __enter__(self) -> "FakeConnection":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None

    def execute(self, *args: object) -> "FakeConnection":
        return self


class RecordingConnection(FakeConnection):
    """A connection that remembers the SQL it was given and answers an insert with an id.

    has_cache_hit_column is what the look-up of that column finds.
    """

    NEW_ROW_ID = 7

    def __init__(self, has_cache_hit_column: bool = True) -> None:
        self.statements: list[str] = []
        self.has_cache_hit_column = has_cache_hit_column

    def execute(self, statement: str, *parameters: object) -> "RecordingConnection":
        self.statements.append(statement)
        return self

    def fetchone(self) -> tuple[int] | None:
        if self.statements[-1] == db.CACHE_HIT_COLUMN_SQL and not self.has_cache_hit_column:
            return None
        return (self.NEW_ROW_ID,)


class Clock:
    """Stands in for time.monotonic in app.db, so the circuit's wait passes without waiting."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch) -> Clock:
    fake = Clock()
    monkeypatch.setattr(db.time, "monotonic", fake)
    return fake


class Attempts(list):
    """The password of each connection attempt, plus what each attempt is answered with."""

    answers: list[Exception | FakeConnection]


@pytest.fixture
def attempts(isolated_config, monkeypatch) -> Attempts:
    """Replace psycopg.connect; each test sets the answers its attempts receive."""
    monkeypatch.setenv("DB_PASSWORD", "localdev")
    tried = Attempts()
    tried.answers = []

    def connect(**parameters):
        tried.append(parameters["password"])
        answer = tried.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(psycopg, "connect", connect)
    return tried


def test_rejected_connection_is_retried_once_with_a_refreshed_password(attempts, monkeypatch):
    passwords = iter(["stale", "rotated"])
    monkeypatch.setattr(config, "get_db_password", lambda: next(passwords))
    refreshed = []
    monkeypatch.setattr(config, "refresh_db_password", lambda: refreshed.append(True))
    attempts.answers = [
        psycopg.OperationalError("password authentication failed"),
        FakeConnection(),
    ]

    reachable = db.db_is_reachable()

    assert reachable is True
    assert list(attempts) == ["stale", "rotated"]
    assert refreshed == [True]


def test_connection_timeout_is_not_retried(attempts):
    attempts.answers = [psycopg.errors.ConnectionTimeout("connection timeout expired")]

    reachable = db.db_is_reachable()

    assert reachable is False
    assert len(attempts) == 1


def test_connection_refused_twice_is_a_storage_error(attempts):
    attempts.answers = [psycopg.OperationalError("refused"), psycopg.OperationalError("refused")]

    with pytest.raises(db.StorageError, match="OperationalError"):
        db.recent_scans()

    assert len(attempts) == 2


def test_missing_password_is_a_storage_error(isolated_config, monkeypatch):
    def never_called(**parameters):
        raise AssertionError("connected without a password")

    monkeypatch.setattr(psycopg, "connect", never_called)

    with pytest.raises(db.StorageError, match="ConfigError"):
        db.save_scan(db.ScanRecord("a.eml", None, None, 0, "Safe", "cumulative score", [], "host"))


def test_connection_uses_the_configured_settings_and_a_short_timeout(isolated_config, monkeypatch):
    monkeypatch.setenv("DB_HOST", "db.example.internal")
    monkeypatch.setenv("DB_PASSWORD", "localdev")
    seen = {}

    def connect(**parameters):
        seen.update(parameters)
        return FakeConnection()

    monkeypatch.setattr(psycopg, "connect", connect)

    db.db_is_reachable()

    assert seen == {
        "host": "db.example.internal",
        "port": 5432,
        "dbname": "phishing",
        "user": "phishing",
        "password": "localdev",
        "sslmode": "prefer",
        "connect_timeout": db.CONNECT_TIMEOUT_SECONDS,
    }


def test_connection_uses_the_configured_ssl_mode(attempts, monkeypatch):
    # On EC2 user_data sets require: the connection to RDS is encrypted or it is not made.
    monkeypatch.setenv("DB_SSLMODE", "require")
    seen = {}

    def connect(**parameters):
        seen.update(parameters)
        return FakeConnection()

    monkeypatch.setattr(psycopg, "connect", connect)

    db.db_is_reachable()

    assert seen["sslmode"] == "require"


def test_connection_error_never_quotes_the_password(attempts, monkeypatch):
    # libpq does not put the password in its messages. This is the guarantee for a driver
    # that did: here it quotes the whole connection string.
    monkeypatch.setenv("DB_PASSWORD", PASSWORD_MARKER)
    leaky = f"connection failed: host=db.internal user=phishing password={PASSWORD_MARKER}"
    attempts.answers = [psycopg.OperationalError(leaky), psycopg.OperationalError(leaky)]

    with pytest.raises(db.StorageError) as raised:
        db.recent_scans()

    # The traceback covers the error, its cause, and anything chained behind them.
    assert PASSWORD_MARKER not in "".join(traceback.format_exception(raised.value))
    assert "connection failed: host=db.internal" in str(raised.value)


def test_redacted_timeout_is_still_a_timeout_and_is_not_retried(attempts, monkeypatch):
    monkeypatch.setenv("DB_PASSWORD", PASSWORD_MARKER)
    attempts.answers = [psycopg.errors.ConnectionTimeout(f"timeout expired {PASSWORD_MARKER}")]

    with pytest.raises(db.StorageError, match="ConnectionTimeout") as raised:
        db.recent_scans()

    assert len(attempts) == 1
    assert PASSWORD_MARKER not in str(raised.value)


def test_storage_error_message_is_one_short_line(attempts):
    rambling = "Multiple connection attempts failed. All failures were:\n" + "- refused\n" * 200
    attempts.answers = [psycopg.OperationalError(rambling), psycopg.OperationalError(rambling)]

    with pytest.raises(db.StorageError) as raised:
        db.recent_scans()

    message = str(raised.value)
    assert message.startswith("OperationalError: Multiple connection attempts failed.")
    assert "\n" not in message
    assert len(message) <= len("OperationalError: ") + db.MAX_ERROR_MESSAGE_LENGTH


def test_schema_is_created_on_first_use_after_a_failed_start(attempts, monkeypatch, clock):
    # What create_app() relies on: init_schema() may fail while the database is down,
    # and the first call that gets through creates the table instead. The failure opens
    # the circuit, so that first call is one made after the circuit's wait.
    monkeypatch.setattr(db, "_schema_ready", False)
    connection = RecordingConnection()
    refused = psycopg.OperationalError("connection refused")
    attempts.answers = [refused, refused, connection]
    record = db.ScanRecord("a.eml", None, None, 0, "Safe", "cumulative score", [], "host")

    with pytest.raises(db.StorageError):
        db.init_schema()
    clock.now += db.CIRCUIT_OPEN_SECONDS
    scan_id = db.save_scan(record)

    assert scan_id == RecordingConnection.NEW_ROW_ID
    assert connection.statements == [
        db.LOCK_SQL,
        db.CREATE_TABLE_SQL,
        db.CREATE_INDEX_SQL,
        db.CACHE_HIT_COLUMN_SQL,
        db.INSERT_SQL,
    ]


def test_schema_is_not_created_again_once_startup_has_made_it(attempts, monkeypatch):
    monkeypatch.setattr(db, "_schema_ready", False)
    at_startup, at_first_scan = RecordingConnection(), RecordingConnection()
    attempts.answers = [at_startup, at_first_scan]
    record = db.ScanRecord("a.eml", None, None, 0, "Safe", "cumulative score", [], "host")

    db.init_schema()
    db.save_scan(record)

    assert at_first_scan.statements == [db.INSERT_SQL]


def test_a_table_without_the_cache_hit_column_has_it_added_after_the_lock(attempts, monkeypatch):
    monkeypatch.setattr(db, "_schema_ready", False)
    connection = RecordingConnection(has_cache_hit_column=False)
    attempts.answers = [connection]

    db.init_schema()

    assert connection.statements == [
        db.LOCK_SQL,
        db.CREATE_TABLE_SQL,
        db.CREATE_INDEX_SQL,
        db.CACHE_HIT_COLUMN_SQL,
        db.ADD_CACHE_HIT_SQL,
    ]


def test_a_table_that_has_the_cache_hit_column_is_not_altered(attempts, monkeypatch):
    # ALTER TABLE takes an exclusive lock even when it has nothing to do.
    monkeypatch.setattr(db, "_schema_ready", False)
    connection = RecordingConnection(has_cache_hit_column=True)
    attempts.answers = [connection]

    db.init_schema()

    assert db.ADD_CACHE_HIT_SQL not in connection.statements


def test_a_scan_is_saved_as_analysed_unless_marked_as_served_from_the_cache():
    analysed = db.ScanRecord("a.eml", None, None, 0, "Safe", "cumulative score", [], "host")
    cached = db.ScanRecord(**(vars(analysed) | {"cache_hit": True}))

    assert db._insert_parameters(analysed)[-1] is False
    assert db._insert_parameters(cached)[-1] is True


@pytest.mark.parametrize("statement", ["INSERT_SQL", "RECENT_SQL", "SCAN_SQL"])
def test_every_query_names_its_columns(statement):
    # During a rolling deploy two releases share the table, and after a rollback an older
    # one reads rows with a column it does not know. Only named columns survive both.
    sql = getattr(db, statement)

    assert "*" not in sql
    assert "cache_hit" in sql


def test_nul_characters_are_replaced_before_saving():
    record = db.ScanRecord(
        filename="a\x00.eml",
        sender="b\x00",
        subject=None,
        score=5,
        verdict="Safe",
        decided_by="cumulative score",
        findings=[finding("wording", "urgency", "low", "Pressure", 'evidence "\x00"')],
        served_by="host",
    )

    parameters = db._insert_parameters(record)

    assert parameters[:3] == ("a�.eml", "b�", None)
    assert parameters[6].obj[0]["evidence"] == 'evidence "�"'
    assert parameters[6].obj[0]["weight"] == 5


# ------------------------------------------------------------------- Circuit breaker
#
# Once a connection cannot be made, the process stops trying for CIRCUIT_OPEN_SECONDS, so a
# database that is down costs each request nothing rather than the connect timeout.

TIMEOUT = psycopg.errors.ConnectionTimeout("connection timeout expired")


def circuit_warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [record for record in caplog.records if record.getMessage() == "db_circuit_open"]


def test_the_connect_timeout_is_three_seconds():
    assert db.CONNECT_TIMEOUT_SECONDS == 3


def test_after_a_failed_connection_the_next_calls_fail_without_trying(attempts, clock):
    attempts.answers = [TIMEOUT]
    with pytest.raises(db.StorageError):
        db.recent_scans()

    clock.now += db.CIRCUIT_OPEN_SECONDS - 1
    for call in (db.recent_scans, lambda: db.get_scan(1), db.init_schema):
        with pytest.raises(db.StorageError, match="CircuitOpen"):
            call()

    assert len(attempts) == 1


def test_a_failed_save_opens_the_circuit_too(attempts, clock):
    attempts.answers = [TIMEOUT]
    record = db.ScanRecord("a.eml", None, None, 0, "Safe", "cumulative score", [], "host")
    with pytest.raises(db.StorageError):
        db.save_scan(record)

    with pytest.raises(db.StorageError, match="CircuitOpen"):
        db.save_scan(record)

    assert len(attempts) == 1


def test_while_the_circuit_is_open_the_database_reads_as_unreachable(attempts, clock):
    attempts.answers = [TIMEOUT]
    db.db_is_reachable()

    reachable = db.db_is_reachable()

    assert reachable is False
    assert len(attempts) == 1


def test_after_the_wait_one_attempt_is_let_through(attempts, clock):
    attempts.answers = [TIMEOUT, FakeConnection()]
    db.db_is_reachable()

    clock.now += db.CIRCUIT_OPEN_SECONDS
    reachable = db.db_is_reachable()

    assert reachable is True
    assert len(attempts) == 2


def test_a_successful_attempt_closes_the_circuit(attempts, clock):
    attempts.answers = [TIMEOUT, FakeConnection(), FakeConnection(), FakeConnection()]
    db.db_is_reachable()
    clock.now += db.CIRCUIT_OPEN_SECONDS
    db.db_is_reachable()

    later = [db.db_is_reachable(), db.db_is_reachable()]

    assert later == [True, True]
    assert len(attempts) == 4


def test_a_failed_attempt_after_the_wait_starts_the_wait_again(attempts, clock):
    attempts.answers = [TIMEOUT, TIMEOUT]
    db.db_is_reachable()
    clock.now += db.CIRCUIT_OPEN_SECONDS
    db.db_is_reachable()

    clock.now += db.CIRCUIT_OPEN_SECONDS - 1
    reachable = db.db_is_reachable()

    assert reachable is False
    assert len(attempts) == 2


def test_the_attempt_after_the_wait_is_the_only_one_let_through(attempts, clock, monkeypatch):
    # In a process serving several requests at once, the others are refused while it runs.
    attempts.answers = [TIMEOUT]
    db.db_is_reachable()
    clock.now += db.CIRCUIT_OPEN_SECONDS
    seen_during_the_attempt = []

    def connect_slowly(**parameters):
        attempts.append(parameters["password"])
        seen_during_the_attempt.append(db.db_is_reachable())
        return FakeConnection()

    monkeypatch.setattr(psycopg, "connect", connect_slowly)

    db.db_is_reachable()

    assert seen_during_the_attempt == [False]
    assert len(attempts) == 2


def test_the_circuit_opening_is_logged_once_not_once_per_call(attempts, clock, caplog):
    attempts.answers = [TIMEOUT, TIMEOUT]
    for _ in range(3):
        db.db_is_reachable()
    clock.now += db.CIRCUIT_OPEN_SECONDS
    for _ in range(3):
        db.db_is_reachable()

    (warning,) = circuit_warnings(caplog)
    assert warning.levelno == logging.WARNING
    assert warning.fields["open_seconds"] == db.CIRCUIT_OPEN_SECONDS
    assert warning.fields["error_message"].startswith("ConnectionTimeout:")


def test_a_password_that_went_stale_is_retried_and_does_not_open_the_circuit(
    attempts, monkeypatch, clock, caplog
):
    passwords = iter(["stale", "rotated", "rotated"])
    monkeypatch.setattr(config, "get_db_password", lambda: next(passwords))
    monkeypatch.setattr(config, "refresh_db_password", lambda: None)
    attempts.answers = [
        psycopg.OperationalError("password authentication failed"),
        FakeConnection(),
        FakeConnection(),
    ]

    first, second = db.db_is_reachable(), db.db_is_reachable()

    assert (first, second) == (True, True)
    assert list(attempts) == ["stale", "rotated", "rotated"]
    assert circuit_warnings(caplog) == []


def test_a_password_refused_twice_opens_the_circuit(attempts, clock):
    refused = psycopg.OperationalError("password authentication failed")
    attempts.answers = [refused, refused]
    db.db_is_reachable()

    reachable = db.db_is_reachable()

    assert reachable is False
    assert len(attempts) == 2


def test_a_password_that_cannot_be_read_opens_the_circuit(isolated_config, monkeypatch, clock):
    reads = []

    def unreadable() -> str:
        reads.append("read")
        raise config.ConfigError("Cannot read the database secret: EndpointConnectionError")

    monkeypatch.setattr(config, "get_db_password", unreadable)
    monkeypatch.setattr(config, "refresh_db_password", lambda: None)
    db.db_is_reachable()

    reachable = db.db_is_reachable()

    assert reachable is False
    assert reads == ["read"]


def test_a_failure_after_connecting_leaves_the_circuit_closed(attempts, clock):
    class FailingConnection(FakeConnection):
        def execute(self, *args: object) -> "FakeConnection":
            raise psycopg.errors.UndefinedTable("relation does not exist")

    attempts.answers = [FailingConnection(), FakeConnection()]
    db.db_is_reachable()

    reachable = db.db_is_reachable()

    assert reachable is True
    assert len(attempts) == 2
