"""Tests for configuration and the database password. No network: boto3 is replaced."""

import json
import re
from pathlib import Path

import boto3
import pytest
from botocore.exceptions import ClientError, NoCredentialsError

from app import config

SECRET_ARN = "arn:aws:secretsmanager:eu-north-1:123456789012:secret:rds!db-abc123-XyZ"
APP_DIRECTORY = Path(config.__file__).parent


class FakeSecretsManager:
    """Answers get_secret_value from a list of secret strings, one per call."""

    def __init__(self, *secrets: str) -> None:
        self.secrets = list(secrets)
        self.requests: list[dict[str, str]] = []
        self.regions: list[str] = []  # the region of each client created for it

    def get_secret_value(self, **request: str) -> dict[str, str]:
        self.requests.append(request)
        return {"SecretString": self.secrets.pop(0)}


def rds_secret(password: str) -> str:
    """Return a secret in the shape RDS stores for a managed master user."""
    return json.dumps({"username": "phishing", "password": password})


@pytest.fixture
def secrets_manager(isolated_config, monkeypatch):
    """Point the configuration at a fake Secrets Manager holding one password."""
    fake = FakeSecretsManager(rds_secret("first"), rds_secret("rotated"))

    def client(service: str, region_name: str) -> FakeSecretsManager:
        fake.regions.append(region_name)
        return fake

    monkeypatch.setattr(boto3, "client", client)
    monkeypatch.setenv("DB_SECRET_ARN", SECRET_ARN)
    return fake


def test_defaults_suit_the_local_container(isolated_config):
    settings = config.get_settings()

    assert settings == config.Settings(
        db_host="localhost",
        db_port=5432,
        db_name="phishing",
        db_user="phishing",
        db_secret_arn="",
        log_file="",
        max_upload_bytes=5242880,
        instance_id=config.HOSTNAME,
    )


def test_instance_id_comes_from_the_environment_when_set(isolated_config, monkeypatch):
    monkeypatch.setenv("INSTANCE_ID", "i-0123456789abcdef0")

    assert config.get_settings().instance_id == "i-0123456789abcdef0"


def test_empty_instance_id_falls_back_to_the_hostname(isolated_config, monkeypatch):
    monkeypatch.setenv("INSTANCE_ID", "")

    assert config.get_settings().instance_id == config.HOSTNAME


def test_environment_overrides_the_env_file_which_overrides_the_defaults(
    isolated_config, monkeypatch, tmp_path
):
    env_file = tmp_path / ".env"
    env_file.write_text("DB_HOST=from-file\nDB_NAME=from-file\n", encoding="utf-8")
    monkeypatch.setattr(config, "ENV_FILE", env_file)
    monkeypatch.setenv("DB_HOST", "from-environment")

    settings = config.get_settings()

    assert (settings.db_host, settings.db_name, settings.db_user) == (
        "from-environment",
        "from-file",
        "phishing",
    )


def test_env_file_skips_blank_lines_and_comments(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("# local settings\n\nDB_PASSWORD = localdev \nnot a pair\n", "utf-8")

    assert config.read_env_file(env_file) == {"DB_PASSWORD": "localdev"}


def test_missing_env_file_reads_as_empty(tmp_path):
    assert config.read_env_file(tmp_path / "absent.env") == {}


def test_non_numeric_port_is_a_configuration_error(isolated_config, monkeypatch):
    monkeypatch.setenv("DB_PORT", "fifty-four")

    with pytest.raises(config.ConfigError, match="DB_PORT"):
        config.get_settings()


def test_password_comes_from_db_password_when_set(isolated_config, monkeypatch):
    monkeypatch.setenv("DB_PASSWORD", "localdev")

    assert config.get_db_password() == "localdev"


def test_password_comes_from_secrets_manager_when_db_password_is_unset(secrets_manager):
    password = config.get_db_password()

    assert password == "first"
    assert secrets_manager.requests == [{"SecretId": SECRET_ARN}]


def test_secrets_manager_is_asked_in_the_region_named_by_the_arn(secrets_manager):
    config.get_db_password()

    assert secrets_manager.regions == ["eu-north-1"]


def test_password_is_cached_after_the_first_fetch(secrets_manager):
    config.get_db_password()
    config.get_db_password()

    assert len(secrets_manager.requests) == 1


def test_refresh_picks_up_a_rotated_password(secrets_manager):
    config.get_db_password()

    config.refresh_db_password()

    assert config.get_db_password() == "rotated"


def test_no_password_source_is_a_configuration_error(isolated_config):
    with pytest.raises(config.ConfigError, match="DB_PASSWORD"):
        config.get_db_password()


@pytest.mark.parametrize(
    "error",
    [
        ClientError({"Error": {"Code": "AccessDeniedException"}}, "GetSecretValue"),
        NoCredentialsError(),
    ],
)
def test_unreadable_secret_is_a_configuration_error(secrets_manager, monkeypatch, error):
    def refuse(**request):
        raise error

    monkeypatch.setattr(secrets_manager, "get_secret_value", refuse)

    with pytest.raises(config.ConfigError, match=type(error).__name__):
        config.get_db_password()


@pytest.mark.parametrize("secret", ["not json at all", '{"username": "phishing"}', '["first"]'])
def test_malformed_secret_is_an_error_that_does_not_quote_it(secrets_manager, secret):
    secrets_manager.secrets = [secret]

    with pytest.raises(config.ConfigError) as raised:
        config.get_db_password()

    assert secret not in str(raised.value)
    assert raised.value.__cause__ is None


def test_secret_arn_that_is_not_an_arn_is_a_configuration_error(secrets_manager, monkeypatch):
    monkeypatch.setenv("DB_SECRET_ARN", "rds-master-password")

    with pytest.raises(config.ConfigError, match="not an ARN"):
        config.get_db_password()


def test_no_other_module_reads_the_environment():
    readers = [
        path.name
        for path in APP_DIRECTORY.rglob("*.py")
        if path.name != "config.py"
        and re.search(r"\bos\.environ\b|\bgetenv\(", path.read_text(encoding="utf-8"))
    ]

    assert readers == []
