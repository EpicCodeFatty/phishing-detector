"""The result cache and the sighting counter, on Valkey: shared by the instances, never required.

The only module that talks to the cache. Two keys per email, both named after the SHA-256
of the uploaded bytes:

    scan:v1:<release>:<sha256>    the result, as JSON; any deploy changes the release, so
                                  nothing an older version of the code computed is served
    seen:v1:<sha256>              how many times the email was scanned; no release in it,
                                  since a sighting is a sighting whatever the code version

Both expire CACHE_TTL_SECONDS after they are first written. The counter's expiry is set at
the first sighting and not extended by later ones, so "seen N times" means in the last day.

The cache fails open. Every error from the client is a miss, and after one the process
skips the cache for FAILURE_PAUSE_SECONDS, logging a single cache_unavailable warning
rather than one per request, so a dead cache does not add a timeout to every scan. When the
token itself cannot be fetched the pause is TOKEN_FAILURE_PAUSE_SECONDS. Nothing here runs
at startup: the token and the connection pool are made on the first scan that needs them.
"""

import hashlib
import json
import logging
import time
from dataclasses import dataclass, fields
from enum import StrEnum
from typing import Any

import redis
from redis.backoff import NoBackoff
from redis.retry import Retry

from app import config
from app.detector.models import Finding
from app.logging_setup import error_fields, log_event

logger = logging.getLogger(__name__)

RESULT_KEY = "scan:v1:{release}:{digest}"
SEEN_KEY = "seen:v1:{digest}"

# A cache that answers slower than the analysis it saves is worse than none.
TIMEOUT_SECONDS = 0.5

# How long a process leaves the cache alone after a failure, and after failing to get the
# token, which needs a Secrets Manager call and is not worth repeating every few seconds.
FAILURE_PAUSE_SECONDS = 30
TOKEN_FAILURE_PAUSE_SECONDS = 300

# What a cached result must hold, and of what type. A stored value that differs in any way
# is treated as a miss and deleted. The application is the only writer, and a key is the
# hash of the content, so a caller cannot choose what is stored under it: this is a second
# layer, and the guard against a value written by a different version of this module.
RESULT_FIELDS: dict[str, type | tuple[type, ...]] = {
    "score": int,
    "verdict": str,
    "decided_by": str,
    "findings": list,
    "sender": (str, type(None)),
    "subject": (str, type(None)),
}
FINDING_FIELDS: dict[str, type] = {field.name: field.type for field in fields(Finding)}


class Status(StrEnum):
    """How the cache took part in a scan. The value is the cache field of the log line."""

    HIT = "hit"  # the stored result was used
    MISS = "miss"  # the cache answered, without a result
    OFF = "off"  # no cache is configured
    ERROR = "error"  # a cache is configured, but could not be used for this scan


@dataclass(frozen=True)
class Lookup:
    """What the cache knew about an email."""

    value: dict[str, Any] | None  # the stored result, on a hit
    seen: int | None  # times scanned in the last day, this one included; None when unknown
    status: Status


@dataclass
class _Connection:
    """This process's client, and until when it leaves the cache alone after a failure."""

    client: redis.Redis | None = None
    paused_until: float = 0.0


# One per process. gunicorn's workers are separate processes, so each has its own client,
# connection pool and pause, created after the fork.
_connection = _Connection()


def content_hash(raw: bytes) -> str:
    """Return the SHA-256 of the uploaded bytes, in hex: the name of everything cached for them."""
    return hashlib.sha256(raw).hexdigest()


def lookup(digest: str) -> Lookup:
    """Return the stored result for this email, if any, and count this sighting.

    One round trip: GET the result, INCR the counter, and EXPIRE it with NX, which
    sets the expiry only when the key has none, so the day starts at the first sighting.
    Never raises: a failure is reported as Status.ERROR.
    """
    if not _is_enabled():
        return Lookup(None, None, Status.OFF)
    client = _usable_client()
    if client is None:
        return Lookup(None, None, Status.ERROR)
    result_key = _result_key(digest)
    try:
        stored, seen, _ = (
            client.pipeline(transaction=False)
            .get(result_key)
            .incr(SEEN_KEY.format(digest=digest))
            .expire(SEEN_KEY.format(digest=digest), _ttl_seconds(), nx=True)
            .execute()
        )
    except redis.RedisError as error:
        _pause(error, FAILURE_PAUSE_SECONDS)
        return Lookup(None, None, Status.ERROR)
    if stored is None:
        return Lookup(None, seen, Status.MISS)
    value = _valid_result(stored)
    if value is None:
        _discard(client, result_key)
        return Lookup(None, seen, Status.MISS)
    return Lookup(value, seen, Status.HIT)


def store(digest: str, value: dict[str, Any]) -> None:
    """Store a result for this email, to expire after CACHE_TTL_SECONDS. Never raises."""
    if not _is_enabled():
        return
    client = _usable_client()
    if client is None:
        return
    try:
        client.set(_result_key(digest), json.dumps(value), ex=_ttl_seconds())
    except redis.RedisError as error:
        _pause(error, FAILURE_PAUSE_SECONDS)


def _is_enabled() -> bool:
    return bool(config.get_settings().cache_host)


def _usable_client() -> redis.Redis | None:
    """Return this process's client, creating it on first use; None while the cache is paused."""
    if time.monotonic() < _connection.paused_until:
        return None
    if _connection.client is not None:
        return _connection.client
    try:
        password = config.get_cache_password()
    except config.ConfigError as error:
        _pause(error, TOKEN_FAILURE_PAUSE_SECONDS)
        return None
    _connection.client = _new_client(password)
    return _connection.client


def _new_client(password: str) -> redis.Redis:
    """Build the client. It connects lazily: nothing touches the network until the first command.

    With TLS, the server's certificate and host name are both verified. ElastiCache's
    certificates are issued by Amazon's public certificate authority, which the
    instance's trust store holds. If that ever fails with an unknown authority, the
    answer is ssl_ca_certs=certifi.where(), never switching verification off.
    """
    settings = config.get_settings()
    return redis.Redis(
        host=settings.cache_host,
        port=settings.cache_port,
        password=password,
        ssl=settings.cache_tls,
        ssl_cert_reqs="required",
        ssl_check_hostname=True,
        socket_connect_timeout=TIMEOUT_SECONDS,
        socket_timeout=TIMEOUT_SECONDS,
        # redis-py retries ten times with backoff by default. One attempt, then a miss.
        retry=Retry(NoBackoff(), 0),
        decode_responses=True,
    )


def _pause(error: Exception, seconds: int) -> None:
    """Leave the cache alone for a while, and say so once. The message never holds the token."""
    _connection.paused_until = time.monotonic() + seconds
    log_event(
        logger,
        logging.WARNING,
        "cache_unavailable",
        paused_seconds=seconds,
        **error_fields(error),
    )


def _discard(client: redis.Redis, key: str) -> None:
    """Delete a stored value that failed the check, so it is recomputed. Never raises."""
    try:
        client.delete(key)
    except redis.RedisError as error:
        _pause(error, FAILURE_PAUSE_SECONDS)


def _valid_result(stored: str) -> dict[str, Any] | None:
    """Return the stored result if it has exactly the expected fields and types, else None."""
    try:
        value = json.loads(stored)
    except ValueError:
        return None
    if not _has_shape(value, RESULT_FIELDS):
        return None
    if not all(_has_shape(item, FINDING_FIELDS) for item in value["findings"]):
        return None
    return value


def _has_shape(value: object, shape: dict[str, type | tuple[type, ...]]) -> bool:
    """Tell whether value is a dict with exactly these keys, each of its type.

    A bool is refused where an int is expected, although Python counts it as one.
    """
    if not isinstance(value, dict) or value.keys() != shape.keys():
        return False
    return all(
        isinstance(value[name], expected) and not isinstance(value[name], bool)
        for name, expected in shape.items()
    )


def _result_key(digest: str) -> str:
    return RESULT_KEY.format(release=config.get_settings().release, digest=digest)


def _ttl_seconds() -> int:
    return config.get_settings().cache_ttl_seconds
