"""Tests for the database layer that need no database: psycopg is replaced."""

import psycopg
import pytest

from app import config, db
from app.detector.models import finding


class FakeConnection:
    """Enough of a psycopg connection to be opened, used in a with block and closed."""

    def __enter__(self) -> "FakeConnection":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None

    def execute(self, *args: object) -> "FakeConnection":
        return self


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
        "connect_timeout": db.CONNECT_TIMEOUT_SECONDS,
    }


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
