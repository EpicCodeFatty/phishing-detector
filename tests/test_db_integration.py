"""Database tests against the local PostgreSQL container.

    docker compose up -d --wait
    pytest -m integration

Each test runs against a fresh scans table in a database of its own,
phishing_test, so the development history in the phishing database is untouched.
"""

import threading
import traceback
from datetime import UTC

import psycopg
import pytest
from psycopg import sql

from app import config, db
from app.db import ScanRecord
from app.detector import analyze
from tests.builders import SAMPLES

pytestmark = pytest.mark.integration

# The password docker-compose.yml gives the local container. Local-only; see that file.
COMPOSE_PASSWORD = "localdev"
TEST_DATABASE = "phishing_test"
CONCURRENT_INSTANCES = 8


def connect_as_owner(dbname: str) -> psycopg.Connection:
    return psycopg.connect(
        host=config.DEFAULTS["DB_HOST"],
        port=config.DEFAULTS["DB_PORT"],
        user=config.DEFAULTS["DB_USER"],
        password=COMPOSE_PASSWORD,
        dbname=dbname,
        autocommit=True,
    )


@pytest.fixture(scope="session")
def test_database() -> str:
    """Create the test database once per run, if it does not exist yet."""
    with connect_as_owner(config.DEFAULTS["DB_NAME"]) as connection:
        exists = connection.execute(
            "SELECT 1 FROM pg_database WHERE datname = %s", (TEST_DATABASE,)
        ).fetchone()
        if not exists:
            connection.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(TEST_DATABASE)))
    return TEST_DATABASE


@pytest.fixture
def database(isolated_config, monkeypatch, test_database: str) -> None:
    """Point the application at the test database, with no scans table yet."""
    monkeypatch.setenv("DB_NAME", test_database)
    monkeypatch.setenv("DB_PASSWORD", COMPOSE_PASSWORD)
    monkeypatch.setattr(db, "_schema_ready", False)
    with connect_as_owner(test_database) as connection:
        connection.execute("DROP TABLE IF EXISTS scans")


def record_for(sample: str) -> ScanRecord:
    result = analyze((SAMPLES / sample).read_bytes())
    return ScanRecord(
        filename=sample,
        sender="sender@example.org",
        subject="Subject",
        score=result.score,
        verdict=result.verdict,
        decided_by=result.decided_by,
        findings=result.findings,
        served_by="ip-10-0-21-44",
    )


def table_exists() -> bool:
    with connect_as_owner(TEST_DATABASE) as connection:
        row = connection.execute("SELECT to_regclass('public.scans')").fetchone()
    return row[0] is not None


def test_database_is_reachable(database):
    assert db.db_is_reachable() is True


def test_init_schema_creates_the_table(database):
    db.init_schema()

    assert table_exists()


def test_init_schema_can_run_again(database):
    db.init_schema()
    db.init_schema()

    assert table_exists()


def test_instances_starting_at_once_all_initialise_the_schema(database):
    failures: list[Exception] = []
    barrier = threading.Barrier(CONCURRENT_INSTANCES)

    def start_instance() -> None:
        barrier.wait()
        try:
            db.init_schema()
        except db.StorageError as error:
            failures.append(error)

    threads = [threading.Thread(target=start_instance) for _ in range(CONCURRENT_INSTANCES)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert failures == []
    assert table_exists()


def test_first_save_creates_the_table(database):
    scan_id = db.save_scan(record_for("team-lunch.eml"))

    assert scan_id == 1


def test_save_returns_increasing_ids(database):
    first = db.save_scan(record_for("team-lunch.eml"))
    second = db.save_scan(record_for("paypal-phish.eml"))

    assert second > first


def test_saved_scan_reads_back_unchanged(database):
    record = record_for("paypal-phish.eml")
    scan_id = db.save_scan(record)

    (stored,) = db.recent_scans()

    assert stored.id == scan_id
    assert stored.findings == record.findings
    assert (stored.filename, stored.verdict, stored.score, stored.served_by) == (
        "paypal-phish.eml",
        "Phishing",
        100,
        "ip-10-0-21-44",
    )


def test_timestamps_are_read_back_in_utc(database):
    db.save_scan(record_for("team-lunch.eml"))

    (stored,) = db.recent_scans()

    assert stored.created_at.tzinfo == UTC


def test_recent_scans_come_most_recent_first(database):
    for sample in ("team-lunch.eml", "newsletter.eml", "paypal-phish.eml"):
        db.save_scan(record_for(sample))

    names = [scan.filename for scan in db.recent_scans()]

    assert names == ["paypal-phish.eml", "newsletter.eml", "team-lunch.eml"]


def test_recent_scans_respects_the_limit(database):
    for _ in range(3):
        db.save_scan(record_for("team-lunch.eml"))

    assert len(db.recent_scans(limit=2)) == 2


def test_empty_history_reads_as_an_empty_list(database):
    assert db.recent_scans() == []


def test_missing_sender_and_subject_are_stored_as_null(database):
    record = record_for("meeting-notes.txt")
    db.save_scan(ScanRecord(**(vars(record) | {"sender": None, "subject": None})))

    (stored,) = db.recent_scans()

    assert (stored.sender, stored.subject) == (None, None)


def test_text_containing_nul_characters_is_saved(database):
    record = record_for("team-lunch.eml")
    db.save_scan(ScanRecord(**(vars(record) | {"subject": "before\x00after"})))

    (stored,) = db.recent_scans()

    assert stored.subject == "before�after"


def test_rotated_password_is_picked_up_without_a_restart(database, monkeypatch):
    monkeypatch.setenv("DB_PASSWORD", "stale-password")
    config.get_db_password()
    monkeypatch.setenv("DB_PASSWORD", COMPOSE_PASSWORD)

    scan_id = db.save_scan(record_for("team-lunch.eml"))

    assert scan_id == 1


def test_wrong_password_is_a_storage_error(database, monkeypatch):
    monkeypatch.setenv("DB_PASSWORD", "wrong-password")

    with pytest.raises(db.StorageError):
        db.recent_scans()


def test_rejected_password_is_not_quoted_in_the_error(database, monkeypatch):
    # The real driver and a real refusal: what db.py logs must not repeat the password.
    wrong_password = "wrong-PASSWORD-marker-5c07"
    monkeypatch.setenv("DB_PASSWORD", wrong_password)

    with pytest.raises(db.StorageError, match="authentication failed") as raised:
        db.recent_scans()

    assert wrong_password not in "".join(traceback.format_exception(raised.value))


def test_require_refuses_a_server_without_tls(database, monkeypatch):
    # The local container has no certificate, which makes it the server that "require"
    # exists to refuse. On EC2 this is the setting: encrypted, or no connection at all.
    monkeypatch.setenv("DB_SSLMODE", "require")

    with pytest.raises(db.StorageError, match="SSL"):
        db.recent_scans()


def test_default_ssl_mode_connects_to_a_server_without_tls(database):
    assert config.get_settings().db_sslmode == "prefer"
    assert db.db_is_reachable() is True
