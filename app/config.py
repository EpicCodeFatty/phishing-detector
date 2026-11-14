"""Configuration for the web application, read from the environment.

This is the only module that reads environment variables. Locally they may also
come from a .env file at the repository root; a variable set in the real
environment always wins over the file, and the file over the defaults.
"""

import functools
import json
import os
import socket
from dataclasses import dataclass
from pathlib import Path

import boto3
from botocore.client import BaseClient
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

# Read only if it exists. It is a local convenience: the servers set the environment directly.
ENV_FILE = Path(__file__).resolve().parent.parent / ".env"

# Values that suit local development against docker-compose.yml. On a server every
# one of them is set explicitly, except MAX_UPLOAD_BYTES, which is the same everywhere.
DEFAULTS = {
    "DB_HOST": "localhost",
    "DB_PORT": "5432",
    "DB_NAME": "phishing",
    "DB_USER": "phishing",
    # The local container has no certificate, so encryption is used only if offered. On EC2
    # user_data sets "require": the connection to RDS is encrypted or it is not made.
    "DB_SSLMODE": "prefer",
    "MAX_UPLOAD_BYTES": "5242880",  # 5 MiB
    # Which build of the code is running. On EC2 it is the hash of the release zip.
    "APP_RELEASE": "local",
    # /simulate-error answers 404 unless this is "true". Off by default: anyone who can reach
    # the route can fire the 5XX alarm. infra/app switches it on for the review's demo.
    "ENABLE_ERROR_SIMULATION": "false",
    # The result cache is off unless CACHE_HOST names one. That is the local default, so
    # development and the tests need no cache; on EC2 user_data sets it.
    "CACHE_HOST": "",
    "CACHE_PORT": "6379",
    # How long a cached result and a sighting count are kept: one day.
    "CACHE_TTL_SECONDS": "86400",
    # ElastiCache is reached over TLS only. "false" is for the local container, which has none.
    "CACHE_TLS": "true",
}

# How an on/off setting is written. Anything else is refused at startup, so a typo such as
# "ture" is an error rather than a silent "off".
SWITCH_VALUES = {"true": True, "false": False}

# The values libpq accepts for sslmode. A misspelt one is refused at startup, rather than
# failing every connection later with an error that reads like a database problem.
SSL_MODES = ("disable", "allow", "prefer", "require", "verify-ca", "verify-full")


@dataclass(frozen=True)
class SecretsLimits:
    """How long one Secrets Manager read may take: per attempt, and how many attempts."""

    connect_timeout: int  # seconds
    read_timeout: int  # seconds
    total_attempts: int  # the first attempt included


# botocore's defaults wait a minute per attempt, far longer than the 30 seconds after which
# gunicorn kills a silent worker. With these, an unreachable AWS API costs a worker at most
# (3 + 5) seconds twice, and one error line.
DB_SECRET_LIMITS = SecretsLimits(connect_timeout=3, read_timeout=5, total_attempts=2)

# Tighter still for the cache's token, and one attempt: the cache is optional, and a slow
# read here would hold up the scan that asked for it. A failure only means scanning without
# the cache for a while.
CACHE_SECRET_LIMITS = SecretsLimits(connect_timeout=1, read_timeout=2, total_attempts=1)

# The key RDS stores the password under, in the secret it manages for the master user.
SECRET_PASSWORD_KEY = "password"  # nosec B105 # the name of a JSON key, not a password

# arn:aws:secretsmanager:<region>:<account>:secret:<name>
_ARN_PREFIX = "arn"
_ARN_REGION_INDEX = 3
_ARN_MINIMUM_PARTS = 7

# The machine's hostname, used only as the local fallback for the instance identifier.
# Never used on EC2, where it is derived from the private IP address: ip-10-0-21-44.
HOSTNAME = socket.gethostname()


class ConfigError(Exception):
    """The configuration is missing, malformed, or the password cannot be fetched."""


@dataclass(frozen=True)
class Settings:
    """Everything the application is configured with, except the database password."""

    db_host: str
    db_port: int
    db_name: str
    db_user: str
    db_sslmode: str  # libpq's sslmode: one of SSL_MODES
    db_secret_arn: str  # '' when the password comes from DB_PASSWORD
    log_file: str  # '' means log to stdout
    max_upload_bytes: int
    # Which instance is serving: served_by, host in /health, and host in every log line.
    # The EC2 instance ID on a server, which user_data reads from IMDSv2 at boot; the
    # hostname locally.
    instance_id: str
    # Which build is serving: release in /health and in every log line. During a
    # deployment it is what shows the new code taking over, instance by instance.
    release: str
    # Whether /simulate-error raises its deliberate 500, or answers 404 as if absent.
    enable_error_simulation: bool
    # The result cache. cache_host is '' when there is none, which switches it off.
    cache_host: str
    cache_port: int
    cache_secret_arn: str  # '' when the token comes from CACHE_PASSWORD
    cache_ttl_seconds: int
    cache_tls: bool


@functools.cache
def get_settings() -> Settings:
    """Return the settings, read from the environment once and then cached.

    Raises ConfigError when a numeric setting is not a whole number, DB_SSLMODE
    is not one of libpq's modes, or an on/off setting is neither true nor false.
    """
    environment = _environment()
    return Settings(
        db_host=environment["DB_HOST"],
        db_port=_whole_number(environment, "DB_PORT"),
        db_name=environment["DB_NAME"],
        db_user=environment["DB_USER"],
        db_sslmode=_ssl_mode(environment),
        db_secret_arn=environment.get("DB_SECRET_ARN", ""),
        log_file=environment.get("LOG_FILE", ""),
        max_upload_bytes=_whole_number(environment, "MAX_UPLOAD_BYTES"),
        instance_id=environment.get("INSTANCE_ID") or HOSTNAME,
        release=environment["APP_RELEASE"],
        enable_error_simulation=_switch(environment, "ENABLE_ERROR_SIMULATION"),
        cache_host=environment["CACHE_HOST"],
        cache_port=_whole_number(environment, "CACHE_PORT"),
        cache_secret_arn=environment.get("CACHE_SECRET_ARN", ""),
        cache_ttl_seconds=_whole_number(environment, "CACHE_TTL_SECONDS"),
        cache_tls=_switch(environment, "CACHE_TLS"),
    )


@functools.cache
def get_db_password() -> str:
    """Return the database password.

    Locally it comes from DB_PASSWORD. On EC2 that variable is not set, and the
    password is fetched from Secrets Manager using the instance role. The value
    is cached, and refresh_db_password() clears the cache so a rotated password
    is picked up without a redeploy.

    Raises ConfigError when neither source is configured or the secret cannot
    be read. The error message never contains the password.
    """
    password = _environment().get("DB_PASSWORD", "")
    if password:
        return password
    secret_arn = get_settings().db_secret_arn
    if not secret_arn:
        raise ConfigError("No database password: set DB_PASSWORD locally, DB_SECRET_ARN on EC2")
    return _fetch_secret_password(secret_arn)


@functools.cache
def get_cache_password() -> str:
    """Return the cache's AUTH token.

    Locally it comes from CACHE_PASSWORD. On EC2 that variable is not set, and the
    token is fetched from Secrets Manager using the instance role, with
    CACHE_SECRET_LIMITS. It is kept for the life of the process: the token is not
    rotated, so there is nothing to re-read.

    Raises ConfigError when neither source is configured or the secret cannot be
    read. A failure is not cached, so a later call tries again. The error message
    never contains the token.
    """
    password = _environment().get("CACHE_PASSWORD", "")
    if password:
        return password
    secret_arn = get_settings().cache_secret_arn
    if not secret_arn:
        raise ConfigError("No cache token: set CACHE_PASSWORD locally, CACHE_SECRET_ARN on EC2")
    return _read_secret(secret_arn, CACHE_SECRET_LIMITS)


def refresh_db_password() -> None:
    """Forget the cached password, so the next get_db_password() fetches it again."""
    get_db_password.cache_clear()


def read_env_file(path: Path) -> dict[str, str]:
    """Read KEY=VALUE lines from a .env file, skipping blank lines and # comments.

    Returns {} when the file does not exist. Values are taken literally: no quotes
    are removed and no variables are expanded.
    """
    if not path.is_file():
        return {}
    lines = path.read_text(encoding="utf-8").splitlines()
    pairs = (line.partition("=") for line in lines if "=" in line and not line.startswith("#"))
    return {key.strip(): value.strip() for key, _, value in pairs}


def _environment() -> dict[str, str]:
    return DEFAULTS | read_env_file(ENV_FILE) | dict(os.environ)


def _whole_number(environment: dict[str, str], name: str) -> int:
    value = environment[name]
    try:
        return int(value)
    except ValueError:
        raise ConfigError(f"{name} must be a whole number, not {value!r}") from None


def _ssl_mode(environment: dict[str, str]) -> str:
    mode = environment["DB_SSLMODE"]
    if mode not in SSL_MODES:
        raise ConfigError(f"DB_SSLMODE must be one of {', '.join(SSL_MODES)}, not {mode!r}")
    return mode


def _switch(environment: dict[str, str], name: str) -> bool:
    value = environment[name]
    if value.lower() not in SWITCH_VALUES:
        raise ConfigError(f"{name} must be true or false, not {value!r}")
    return SWITCH_VALUES[value.lower()]


@functools.cache
def _secrets_client(region: str, limits: SecretsLimits) -> BaseClient:
    """Return the Secrets Manager client for a region and limits, created once per process.

    Creating a client loads the service's model from disk, which is too slow to
    repeat for every fetch, and the client is safe to share between threads.
    """
    timeouts = Config(
        connect_timeout=limits.connect_timeout,
        read_timeout=limits.read_timeout,
        # Counts the first attempt too, unlike max_attempts, which counts retries after it.
        retries={"total_max_attempts": limits.total_attempts},
    )
    return boto3.client("secretsmanager", region_name=region, config=timeouts)


def _read_secret(secret_arn: str, limits: SecretsLimits) -> str:
    """Return a secret's string value. Raises ConfigError naming the error type only."""
    client = _secrets_client(_region_of(secret_arn), limits)
    try:
        return client.get_secret_value(SecretId=secret_arn)["SecretString"]
    except (BotoCoreError, ClientError) as error:
        raise ConfigError(f"Cannot read the secret {secret_arn}: {type(error).__name__}") from error


def _fetch_secret_password(secret_arn: str) -> str:
    """Read the password from the RDS-managed secret, a JSON object with a password key."""
    secret = _read_secret(secret_arn, DB_SECRET_LIMITS)
    try:
        return json.loads(secret)[SECRET_PASSWORD_KEY]
    except (ValueError, KeyError, TypeError):
        # Raised without the cause: the cause's message could quote part of the secret.
        raise ConfigError("The database secret is not a JSON object with a password") from None


def _region_of(secret_arn: str) -> str:
    """Return the region named in the secret's ARN, so no separate setting can disagree."""
    parts = secret_arn.split(":")
    if len(parts) < _ARN_MINIMUM_PARTS or parts[0] != _ARN_PREFIX:
        raise ConfigError(f"DB_SECRET_ARN is not an ARN: {secret_arn!r}")
    return parts[_ARN_REGION_INDEX]
