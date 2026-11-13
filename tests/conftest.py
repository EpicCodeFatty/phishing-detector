"""Fixtures shared by the web, configuration, logging and database tests."""

import itertools
import logging
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from flask import Flask
from flask.testing import FlaskClient

from app import config, db, web
from app.db import ScanRecord

# Every variable config.py reads. Cleared for each test, so a developer's own
# environment or .env file can never change a test's outcome.
CONFIG_VARIABLES = (
    "DB_HOST",
    "DB_PORT",
    "DB_NAME",
    "DB_USER",
    "DB_PASSWORD",
    "DB_SECRET_ARN",
    "DB_SSLMODE",
    "LOG_FILE",
    "MAX_UPLOAD_BYTES",
    "INSTANCE_ID",
    "APP_RELEASE",
)


class FakeHistory:
    """An in-memory stand-in for the scans table, so route tests need no database."""

    def __init__(self) -> None:
        self.records: list[ScanRecord] = []
        self._ids = itertools.count(1)

    def init_schema(self) -> None:
        """Nothing to create: the application's startup attempt succeeds at once."""

    def save_scan(self, record: ScanRecord) -> int:
        """Store the record as the database would: with an id and a timestamp."""
        saved = replace(record, id=next(self._ids), created_at=datetime.now(UTC))
        self.records.append(saved)
        return saved.id

    def recent_scans(self, limit: int = db.DEFAULT_HISTORY_LIMIT) -> list[ScanRecord]:
        """Return the stored records, most recent first."""
        return list(reversed(self.records))[:limit]


@pytest.fixture
def isolated_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """Configuration from the defaults and the test's own settings only."""
    monkeypatch.setattr(config, "ENV_FILE", tmp_path / "absent.env")
    for name in CONFIG_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    _forget_cached_configuration()
    yield
    _forget_cached_configuration()


def _forget_cached_configuration() -> None:
    """Drop everything config caches per process: settings, password, Secrets Manager client."""
    config.get_settings.cache_clear()
    config.refresh_db_password()
    config._secrets_client.cache_clear()


@pytest.fixture
def restore_root_logger() -> Iterator[None]:
    """Put the root logger's handlers back after a test that reconfigures logging."""
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield
    for handler in root.handlers:
        if handler not in handlers:
            handler.close()
    root.handlers, root.level = handlers, level


@pytest.fixture
def history(monkeypatch: pytest.MonkeyPatch) -> FakeHistory:
    """Replace the database functions the routes call with an in-memory history."""
    fake = FakeHistory()
    monkeypatch.setattr(db, "init_schema", fake.init_schema)
    monkeypatch.setattr(db, "save_scan", fake.save_scan)
    monkeypatch.setattr(db, "recent_scans", fake.recent_scans)
    return fake


@pytest.fixture
def app(isolated_config: None, history: FakeHistory) -> Flask:
    """The application, configured from defaults, with the in-memory history."""
    application = web.create_app()
    application.testing = True
    return application


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    """A test client for the application."""
    return app.test_client()
