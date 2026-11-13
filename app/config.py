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
}

# The values libpq accepts for sslmode. A misspelt one is refused at startup, rather than
# failing every connection later with an error that reads like a database problem.
SSL_MODES = ("disable", "allow", "prefer", "require", "verify-ca", "verify-full")

# Limits for the Secrets Manager call. botocore's defaults wait a minute per attempt, far
# longer than the 30 seconds after which gunicorn kills a silent worker; with these, an
# unreachable AWS API costs a worker at most (3 + 5) seconds twice, and one error line.
SECRETS_CONNECT_TIMEOUT_SECONDS = 3
SECRETS_READ_TIMEOUT_SECONDS = 5
SECRETS_TOTAL_ATTEMPTS = 2

# The key RDS stores the password under, in the secret it manages for the master user.
SECRET_PASSWORD_KEY = "password"

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


@functools.cache
def get_settings() -> Settings:
    """Return the settings, read from the environment once and then cached.

    Raises ConfigError when a numeric setting is not a whole number, or
    DB_SSLMODE is not one of libpq's modes.
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


@functools.cache
def _secrets_client(region: str) -> BaseClient:
    """Return the Secrets Manager client for a region, created once per process.

    Creating a client loads the service's model from disk, which is too slow to
    repeat for every fetch, and the client is safe to share between threads.
    """
    limits = Config(
        connect_timeout=SECRETS_CONNECT_TIMEOUT_SECONDS,
        read_timeout=SECRETS_READ_TIMEOUT_SECONDS,
        # Counts the first attempt too, unlike max_attempts, which counts retries after it.
        retries={"total_max_attempts": SECRETS_TOTAL_ATTEMPTS},
    )
    return boto3.client("secretsmanager", region_name=region, config=limits)


def _fetch_secret_password(secret_arn: str) -> str:
    """Read the password from the RDS-managed secret, a JSON object with a password key."""
    client = _secrets_client(_region_of(secret_arn))
    try:
        secret = client.get_secret_value(SecretId=secret_arn)["SecretString"]
    except (BotoCoreError, ClientError) as error:
        raise ConfigError(f"Cannot read the database secret: {type(error).__name__}") from error
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
