"""Tests for the result cache and the sighting counter. No network: the client is a fake."""

import json
import logging

import pytest
import redis

from app import cache, config
from app.detector import analyze
from tests.builders import SAMPLES
from tests.conftest import CACHE_TOKEN, FakeValkey

DIGEST = "a" * 64
SECRET_ARN = "arn:aws:secretsmanager:eu-north-1:123456789012:secret:phishing-detector-cache-auth-x"


def stored_value() -> dict[str, object]:
    """A result in the shape the web layer stores: what the history keeps for a scan."""
    result = analyze((SAMPLES / "paypal-phish.eml").read_bytes())
    return {
        "score": result.score,
        "verdict": result.verdict,
        "decided_by": result.decided_by,
        "findings": [vars(found) for found in result.findings],
        "sender": "PayPal <service@paypa1.com>",
        "subject": None,
    }


class Clock:
    """Stands in for time.monotonic in app.cache, so a pause can be passed without waiting."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch) -> Clock:
    fake = Clock()
    monkeypatch.setattr(cache.time, "monotonic", fake)
    return fake


def cache_warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [record for record in caplog.records if record.getMessage() == "cache_unavailable"]


# ----------------------------------------------------------------------------- Keys


def test_the_same_bytes_have_the_same_hash():
    assert cache.content_hash(b"same email") == cache.content_hash(b"same email")


def test_different_bytes_have_different_hashes():
    assert cache.content_hash(b"one email") != cache.content_hash(b"one email.")


def test_the_hash_is_the_sha256_in_hex():
    expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    assert cache.content_hash(b"") == expected


def test_the_result_key_names_the_release_and_the_hash(valkey, monkeypatch):
    monkeypatch.setenv("APP_RELEASE", "3f9a1c2b7d10")
    config.get_settings.cache_clear()

    cache.lookup(DIGEST)

    assert ("GET", f"scan:v1:3f9a1c2b7d10:{DIGEST}") in valkey.commands


def test_a_result_stored_by_another_release_is_not_served(valkey, monkeypatch):
    monkeypatch.setenv("APP_RELEASE", "old000000000")
    config.get_settings.cache_clear()
    cache.store(DIGEST, stored_value())
    monkeypatch.setenv("APP_RELEASE", "new000000000")
    config.get_settings.cache_clear()

    found = cache.lookup(DIGEST)

    assert (found.value, found.status) == (None, cache.Status.MISS)


def test_the_counter_key_has_no_release_in_it(valkey):
    cache.lookup(DIGEST)

    assert ("INCR", f"seen:v1:{DIGEST}") in valkey.commands


# -------------------------------------------------------------------------- Counter


def test_the_first_sighting_counts_one(valkey):
    assert cache.lookup(DIGEST).seen == 1


def test_the_second_sighting_counts_two(valkey):
    cache.lookup(DIGEST)

    assert cache.lookup(DIGEST).seen == 2


def test_the_counter_expiry_is_set_at_the_first_sighting_and_never_extended(valkey):
    for _ in range(3):
        cache.lookup(DIGEST)

    expiries = [command for command in valkey.commands if command[0] == "EXPIRE"]
    assert expiries == [("EXPIRE", f"seen:v1:{DIGEST}", 86400, "NX")] * 3
    assert valkey.expiries == {f"seen:v1:{DIGEST}": 86400}


def test_lookup_is_one_round_trip_of_get_incr_and_expire(valkey):
    cache.lookup(DIGEST)

    assert [command[0] for command in valkey.commands] == ["GET", "INCR", "EXPIRE"]


def test_the_lifetime_comes_from_the_configuration(valkey, monkeypatch):
    monkeypatch.setenv("CACHE_TTL_SECONDS", "60")
    config.get_settings.cache_clear()

    cache.store(DIGEST, stored_value())

    assert ("SET", f"scan:v1:local:{DIGEST}", 60) in valkey.commands


# ------------------------------------------------------------------- Hits and misses


def test_an_email_never_stored_is_a_miss(valkey):
    found = cache.lookup(DIGEST)

    assert (found.value, found.status) == (None, cache.Status.MISS)


def test_a_stored_result_is_a_hit_and_comes_back_unchanged(valkey):
    cache.store(DIGEST, stored_value())

    found = cache.lookup(DIGEST)

    assert (found.value, found.status) == (stored_value(), cache.Status.HIT)


def test_a_result_is_stored_for_a_day_by_default(valkey):
    cache.store(DIGEST, stored_value())

    assert valkey.expiries[f"scan:v1:local:{DIGEST}"] == 86400


@pytest.mark.parametrize(
    "corrupt",
    [
        "not json",
        json.dumps(["a list"]),
        json.dumps(stored_value() | {"score": "100"}),
        json.dumps(stored_value() | {"score": True}),
        json.dumps(stored_value() | {"extra": 1}),
        json.dumps({key: value for key, value in stored_value().items() if key != "verdict"}),
        json.dumps(stored_value() | {"findings": [{"code": "ip_url"}]}),
        json.dumps(stored_value() | {"findings": ["ip_url"]}),
        json.dumps(stored_value() | {"sender": 5}),
    ],
)
def test_a_malformed_cached_value_is_a_miss_and_is_deleted(valkey, corrupt):
    key = f"scan:v1:local:{DIGEST}"
    valkey.values[key] = corrupt

    found = cache.lookup(DIGEST)

    assert (found.value, found.status) == (None, cache.Status.MISS)
    assert ("DEL", key) in valkey.commands
    assert key not in valkey.values


def test_a_malformed_value_still_counts_the_sighting(valkey):
    valkey.values[f"scan:v1:local:{DIGEST}"] = "not json"

    assert cache.lookup(DIGEST).seen == 1


# --------------------------------------------------------------------------- Disabled


def test_without_a_cache_host_the_cache_is_off_and_no_client_is_created(
    isolated_config, monkeypatch
):
    def no_client(**options):
        raise AssertionError("a client was created")

    monkeypatch.setattr(cache.redis, "Redis", no_client)

    found = cache.lookup(DIGEST)
    cache.store(DIGEST, stored_value())

    assert (found.value, found.seen, found.status) == (None, None, cache.Status.OFF)


def test_without_a_cache_host_no_token_is_fetched(isolated_config, monkeypatch):
    monkeypatch.setenv("CACHE_SECRET_ARN", SECRET_ARN)
    monkeypatch.setattr(config, "_read_secret", lambda *args: pytest.fail("token fetched"))

    cache.lookup(DIGEST)


# ------------------------------------------------------------------------- The client


def test_one_client_is_created_per_process_and_reused(valkey):
    cache.lookup(DIGEST)
    cache.store(DIGEST, stored_value())
    cache.lookup(DIGEST)

    assert len(valkey.clients) == 1


def test_the_client_verifies_the_servers_certificate_and_name(valkey):
    cache.lookup(DIGEST)

    (options,) = valkey.clients
    assert (options["ssl"], options["ssl_cert_reqs"], options["ssl_check_hostname"]) == (
        True,
        "required",
        True,
    )


def test_the_client_gives_up_after_half_a_second_and_never_retries(valkey):
    cache.lookup(DIGEST)

    (options,) = valkey.clients
    assert (options["socket_connect_timeout"], options["socket_timeout"]) == (0.5, 0.5)
    assert options["retry"].get_retries() == 0


def test_the_client_presents_the_token_and_names_the_configured_host(valkey):
    cache.lookup(DIGEST)

    (options,) = valkey.clients
    assert (options["host"], options["port"], options["password"]) == (
        "cache.example",
        6379,
        CACHE_TOKEN,
    )


def test_tls_can_be_switched_off_for_the_local_container(valkey, monkeypatch):
    monkeypatch.setenv("CACHE_TLS", "false")
    config.get_settings.cache_clear()

    cache.lookup(DIGEST)

    assert valkey.clients[0]["ssl"] is False


# --------------------------------------------------------------------- Cache failures


def test_a_cache_that_fails_is_an_error_not_an_exception(valkey):
    valkey.failure = redis.ConnectionError("Connection refused")

    found = cache.lookup(DIGEST)

    assert (found.value, found.seen, found.status) == (None, None, cache.Status.ERROR)


def test_a_failure_pauses_the_cache_for_thirty_seconds(valkey, clock):
    valkey.failure = redis.TimeoutError("Timeout reading from socket")
    cache.lookup(DIGEST)
    valkey.failure = None

    clock.now += 29
    during = cache.lookup(DIGEST)
    clock.now += 2
    after = cache.lookup(DIGEST)

    assert (during.status, after.status) == (cache.Status.ERROR, cache.Status.MISS)
    assert [command[0] for command in valkey.commands] == ["GET", "INCR", "EXPIRE"]


def test_a_failure_is_logged_once_not_once_per_request(valkey, clock, caplog):
    valkey.failure = redis.ConnectionError("Connection refused")

    for _ in range(5):
        cache.lookup(DIGEST)
        cache.store(DIGEST, stored_value())

    (warning,) = cache_warnings(caplog)
    assert warning.levelno == logging.WARNING
    assert warning.fields["error_type"] == "ConnectionError"


def test_a_failed_store_pauses_the_cache_too(valkey, clock, caplog):
    cache.lookup(DIGEST)
    valkey.failure = redis.TimeoutError("Timeout writing to socket")

    cache.store(DIGEST, stored_value())
    valkey.failure = None

    assert cache.lookup(DIGEST).status == cache.Status.ERROR
    assert len(cache_warnings(caplog)) == 1


def test_a_refused_token_is_a_failure_like_any_other(valkey):
    valkey.failure = redis.AuthenticationError("invalid username-password pair")

    assert cache.lookup(DIGEST).status == cache.Status.ERROR


# -------------------------------------------------------------------------- The token


@pytest.fixture
def unreadable_token(isolated_config, monkeypatch) -> list[str]:
    """A cache whose token cannot be fetched. Returns the list of fetch attempts."""
    attempts: list[str] = []

    def refuse(secret_arn: str, limits: config.SecretsLimits) -> str:
        attempts.append("fetch")
        raise config.ConfigError("Cannot read the secret: EndpointConnectionError")

    monkeypatch.setenv("CACHE_HOST", "cache.example")
    monkeypatch.setenv("CACHE_SECRET_ARN", SECRET_ARN)
    monkeypatch.setattr(config, "_read_secret", refuse)
    monkeypatch.setattr(cache.redis, "Redis", lambda **options: pytest.fail("client created"))
    config.get_settings.cache_clear()
    return attempts


def test_a_token_that_cannot_be_fetched_is_an_error(unreadable_token):
    assert cache.lookup(DIGEST).status == cache.Status.ERROR


def test_a_failed_token_fetch_is_not_tried_again_for_five_minutes(unreadable_token, clock):
    cache.lookup(DIGEST)
    clock.now += 299
    cache.lookup(DIGEST)
    cache.store(DIGEST, stored_value())

    assert unreadable_token == ["fetch"]


def test_the_token_fetch_is_tried_again_after_five_minutes(unreadable_token, clock):
    cache.lookup(DIGEST)
    clock.now += 301
    cache.lookup(DIGEST)

    assert unreadable_token == ["fetch", "fetch"]


def test_a_failed_token_fetch_is_logged_once(unreadable_token, clock, caplog):
    for _ in range(3):
        cache.lookup(DIGEST)

    (warning,) = cache_warnings(caplog)
    assert warning.fields["paused_seconds"] == 300


def test_the_token_never_appears_in_the_log(valkey, caplog):
    caplog.set_level(logging.DEBUG)
    valkey.failure = redis.AuthenticationError("invalid username-password pair")

    cache.lookup(DIGEST)

    assert CACHE_TOKEN not in caplog.text
    assert all(CACHE_TOKEN not in str(record.__dict__) for record in caplog.records)


def test_nothing_is_fetched_or_connected_until_the_first_use(valkey):
    assert valkey.clients == []


def test_failing_cache_reports_no_count(valkey: FakeValkey):
    valkey.failure = redis.ConnectionError("down")

    assert cache.lookup(DIGEST).seen is None
