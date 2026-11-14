"""Fixtures shared by the web, configuration, logging, database and cache tests."""

import itertools
import logging
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
import redis
from flask import Flask
from flask.testing import FlaskClient

from app import cache, config, db, web
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
    "ENABLE_ERROR_SIMULATION",
    "CACHE_HOST",
    "CACHE_PORT",
    "CACHE_SECRET_ARN",
    "CACHE_PASSWORD",
    "CACHE_TTL_SECONDS",
    "CACHE_TLS",
)

# Stands in for the cache's AUTH token wherever a test checks that it is never repeated.
CACHE_TOKEN = "cache-TOKEN-marker-5e81"


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

    def get_scan(self, scan_id: int) -> ScanRecord | None:
        """Return the stored record with this id, or None, as the database would."""
        return next((record for record in self.records if record.id == scan_id), None)


class FakeValkey:
    """An in-memory stand-in for the cache, answering the few commands app.cache sends.

    Records each command, and raises `failure` from every one when it is set.
    """

    def __init__(self) -> None:
        self.values: dict[str, object] = {}
        self.expiries: dict[str, int] = {}
        self.commands: list[tuple[object, ...]] = []
        self.failure: redis.RedisError | None = None
        self.clients: list[dict[str, object]] = []  # the options of each client created

    def pipeline(self, transaction: bool = True) -> "FakePipeline":
        return FakePipeline(self)

    def get(self, key: str) -> object:
        self._record("GET", key)
        return self.values.get(key)

    def incr(self, key: str) -> int:
        self._record("INCR", key)
        self.values[key] = int(self.values.get(key, 0)) + 1
        return self.values[key]

    def expire(self, key: str, seconds: int, nx: bool = False) -> bool:
        self._record("EXPIRE", key, seconds, "NX" if nx else "")
        if nx and key in self.expiries:
            return False
        self.expiries[key] = seconds
        return True

    def set(self, key: str, value: str, ex: int) -> bool:
        self._record("SET", key, ex)
        self.values[key] = value
        self.expiries[key] = ex
        return True

    def delete(self, key: str) -> int:
        self._record("DEL", key)
        return 1 if self.values.pop(key, None) is not None else 0

    def _record(self, *command: object) -> None:
        if self.failure is not None:
            raise self.failure
        self.commands.append(command)


class FakePipeline:
    """Queues commands and runs them against the fake on execute(), as one round trip."""

    def __init__(self, server: FakeValkey) -> None:
        self.server = server
        self.queued: list[tuple[str, tuple[object, ...], dict[str, object]]] = []

    def __getattr__(self, name: str):
        def queue(*args: object, **kwargs: object) -> "FakePipeline":
            self.queued.append((name, args, kwargs))
            return self

        return queue

    def execute(self) -> list[object]:
        return [getattr(self.server, name)(*args, **kwargs) for name, args, kwargs in self.queued]


@pytest.fixture
def isolated_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """Configuration from the defaults and the test's own settings only, and a fresh cache state."""
    monkeypatch.setattr(config, "ENV_FILE", tmp_path / "absent.env")
    for name in CONFIG_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(cache, "_connection", cache._Connection())
    _forget_cached_configuration()
    yield
    _forget_cached_configuration()


def _forget_cached_configuration() -> None:
    """Drop everything config caches per process: settings, secrets, Secrets Manager clients."""
    config.get_settings.cache_clear()
    config.refresh_db_password()
    config.get_cache_password.cache_clear()
    config._secrets_client.cache_clear()


@pytest.fixture
def valkey(isolated_config: None, monkeypatch: pytest.MonkeyPatch) -> FakeValkey:
    """Switch the cache on, pointed at an in-memory fake, with the token in CACHE_PASSWORD."""
    fake = FakeValkey()

    def client(**options: object) -> FakeValkey:
        fake.clients.append(options)
        return fake

    monkeypatch.setenv("CACHE_HOST", "cache.example")
    monkeypatch.setenv("CACHE_PASSWORD", CACHE_TOKEN)
    monkeypatch.setattr(cache.redis, "Redis", client)
    config.get_settings.cache_clear()
    return fake


@pytest.fixture
def error_simulation(isolated_config: None, monkeypatch: pytest.MonkeyPatch) -> None:
    """Switch /simulate-error on, as infra/app does for the demo. Off is the default."""
    monkeypatch.setenv("ENABLE_ERROR_SIMULATION", "true")
    # The route reads the settings on every request, so this works whether the application
    # was created before this fixture ran or after it.
    config.get_settings.cache_clear()


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
    monkeypatch.setattr(db, "get_scan", fake.get_scan)
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
