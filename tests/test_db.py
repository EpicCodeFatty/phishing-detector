"""Tests for the database layer that need no database: psycopg is replaced."""

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
    """A connection that remembers the SQL it was given and answers an insert with an id."""

    NEW_ROW_ID = 7

    def __init__(self) -> None:
        self.statements: list[str] = []

    def execute(self, statement: str, *parameters: object) -> "RecordingConnection":
        self.statements.append(statement)
        return self

    def fetchone(self) -> tuple[int]:
        return (self.NEW_ROW_ID,)


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


def test_schema_is_created_on_first_use_after_a_failed_start(attempts, monkeypatch):
    # What create_app() relies on: init_schema() may fail while the database is down,
    # and the first call that gets through creates the table instead.
    monkeypatch.setattr(db, "_schema_ready", False)
    connection = RecordingConnection()
    refused = psycopg.OperationalError("connection refused")
    attempts.answers = [refused, refused, connection]
    record = db.ScanRecord("a.eml", None, None, 0, "Safe", "cumulative score", [], "host")

    with pytest.raises(db.StorageError):
        db.init_schema()
    scan_id = db.save_scan(record)

    assert scan_id == RecordingConnection.NEW_ROW_ID
    assert connection.statements == [
        db.LOCK_SQL,
        db.CREATE_TABLE_SQL,
        db.CREATE_INDEX_SQL,
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
