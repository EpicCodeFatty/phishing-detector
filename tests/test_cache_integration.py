"""Cache tests against the local Valkey container.

    docker compose up -d --wait
    pytest -m integration

The container's password is CACHE_PASSWORD, from the environment or from .env, exactly as
docker compose reads it. Each test works under a digest of its own and deletes its keys
afterwards, so nothing else in the container is touched.
"""

import os
import uuid
from collections.abc import Iterator

import pytest
import redis

from app import cache, config

pytestmark = pytest.mark.integration

LOCAL_HOST = "localhost"
LOCAL_PORT = 6379


@pytest.fixture(scope="session")
def compose_password() -> str:
    """Return the password docker compose gave the container: the environment wins over .env.

    Session-scoped, so it is read before isolated_config clears both for each test.
    """
    password = os.environ.get("CACHE_PASSWORD") or config.read_env_file(config.ENV_FILE).get(
        "CACHE_PASSWORD", ""
    )
    if not password:
        pytest.fail("CACHE_PASSWORD is not set; see the comment at the top of docker-compose.yml")
    return password


@pytest.fixture
def local_cache(compose_password: str, isolated_config, monkeypatch) -> Iterator[str]:
    """Point the application at the local container, and yield a digest no other test uses."""
    password = compose_password
    monkeypatch.setenv("CACHE_HOST", LOCAL_HOST)
    monkeypatch.setenv("CACHE_PASSWORD", password)
    monkeypatch.setenv("CACHE_TLS", "false")
    monkeypatch.setenv("APP_RELEASE", "integration")
    config.get_settings.cache_clear()
    digest = cache.content_hash(uuid.uuid4().bytes)
    yield digest
    owner = redis.Redis(host=LOCAL_HOST, port=LOCAL_PORT, password=password)
    owner.delete(f"scan:v1:integration:{digest}", f"seen:v1:{digest}")
    owner.close()


@pytest.fixture
def owner(compose_password: str) -> Iterator[redis.Redis]:
    """A client of the test's own, to look at what the application wrote."""
    client = redis.Redis(
        host=LOCAL_HOST, port=LOCAL_PORT, password=compose_password, decode_responses=True
    )
    yield client
    client.close()


def test_a_stored_result_is_found_by_the_next_lookup(local_cache):
    value = {
        "score": 0,
        "verdict": "Safe",
        "decided_by": "cumulative score",
        "findings": [],
        "sender": None,
        "subject": "Lunch",
    }

    first = cache.lookup(local_cache)
    cache.store(local_cache, value)
    second = cache.lookup(local_cache)

    assert (first.status, second.status) == (cache.Status.MISS, cache.Status.HIT)
    assert second.value == value
    assert (first.seen, second.seen) == (1, 2)


def test_the_counter_expires_a_day_after_the_first_sighting_and_is_not_extended(local_cache, owner):
    cache.lookup(local_cache)
    owner.expire(f"seen:v1:{local_cache}", 100)  # as if the first sighting were hours ago

    cache.lookup(local_cache)

    assert 0 < owner.ttl(f"seen:v1:{local_cache}") <= 100
    assert owner.get(f"seen:v1:{local_cache}") == "2"


def test_the_first_sighting_sets_a_day_of_life(local_cache, owner):
    cache.lookup(local_cache)

    assert 86000 < owner.ttl(f"seen:v1:{local_cache}") <= 86400


def test_a_wrong_password_is_an_error_not_an_exception(local_cache, monkeypatch):
    monkeypatch.setenv("CACHE_PASSWORD", "not-the-password")
    config.get_cache_password.cache_clear()

    assert cache.lookup(local_cache).status == cache.Status.ERROR


def test_a_cache_that_is_not_there_is_an_error_within_the_timeout(local_cache, monkeypatch):
    monkeypatch.setenv("CACHE_PORT", "6390")  # nothing listens here
    config.get_settings.cache_clear()

    assert cache.lookup(local_cache).status == cache.Status.ERROR
