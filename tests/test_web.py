"""Tests for the routes, through Flask's test client. No database is needed."""

import json
import logging

import psycopg
import pytest
import werkzeug.formparser

from app import config, db, web
from tests.builders import eml, sample_upload, upload_of
from tests.conftest import FakeHistory

API_KEYS = {"score", "verdict", "decided_by", "findings", "served_by", "scan_id"}
SAVE_WARNING = "could not be saved"

# What user_data sets INSTANCE_ID to on EC2, read from IMDSv2 at boot.
EC2_INSTANCE_ID = "i-0123456789abcdef0"


def unavailable(*args, **kwargs):
    raise db.StorageError("OperationalError: connection refused")


@pytest.fixture
def ec2_client(isolated_config, history, monkeypatch):
    """A client for the application configured as on EC2, with INSTANCE_ID set."""
    monkeypatch.setenv("INSTANCE_ID", EC2_INSTANCE_ID)
    return _client()


def request_lines(caplog: pytest.LogCaptureFixture) -> list[dict[str, object]]:
    """Return the structured fields of every per-request log line."""
    return [record.fields for record in caplog.records if "status" in getattr(record, "fields", {})]


def test_upload_form_returns_200_and_states_the_size_limit(client):
    response = client.get("/")

    assert response.status_code == 200
    assert "5 MB" in response.get_data(as_text=True)


def test_scan_of_a_phishing_sample_returns_200_and_the_verdict(client):
    response = client.post("/scan", data=sample_upload("paypal-phish.eml"))

    assert response.status_code == 200
    assert "Phishing" in response.get_data(as_text=True)


def test_scan_of_a_safe_sample_says_so(client):
    response = client.post("/scan", data=sample_upload("team-lunch.eml"))

    page = response.get_data(as_text=True)
    assert "verdict-safe" in page
    assert "No phishing indicators were found." in page


def test_scan_result_shows_which_instance_served_it(ec2_client):
    response = ec2_client.post("/scan", data=sample_upload("team-lunch.eml"))

    assert EC2_INSTANCE_ID in response.get_data(as_text=True)


@pytest.mark.parametrize("data", [{}, upload_of(b"", "")], ids=["no file field", "no file chosen"])
def test_scan_without_a_file_returns_400(client, data):
    response = client.post("/scan", data=data)

    assert response.status_code == 400
    assert "Choose an email file" in response.get_data(as_text=True)


def test_scan_of_an_empty_file_is_analysed(client):
    response = client.post("/scan", data=upload_of(b"", "empty.eml"))

    assert response.status_code == 200
    assert "Safe" in response.get_data(as_text=True)


def test_scan_is_saved_to_the_history(ec2_client, history: FakeHistory):
    ec2_client.post("/scan", data=sample_upload("paypal-phish.eml"))

    (record,) = history.records
    assert (record.filename, record.verdict, record.score) == ("paypal-phish.eml", "Phishing", 100)
    assert record.sender == '"PayPal Support" <help@paypa1-secure.com>'
    assert record.served_by == EC2_INSTANCE_ID


def test_without_an_instance_id_the_hostname_identifies_the_instance(client, history):
    client.post("/scan", data=sample_upload("team-lunch.eml"))

    (record,) = history.records
    assert record.served_by == config.HOSTNAME


def test_plain_text_scan_is_saved_without_sender_or_subject(client, history: FakeHistory):
    client.post("/scan", data=sample_upload("meeting-notes.txt"))

    (record,) = history.records
    assert (record.sender, record.subject) == (None, None)


def test_health_returns_200_with_the_instance_id(ec2_client):
    response = ec2_client.get("/health")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok", "host": EC2_INSTANCE_ID}


@pytest.mark.parametrize(
    "method,path,upload",
    [
        ("get", "/health", None),
        ("get", "/", None),
        ("post", "/scan", "paypal-phish.eml"),
        ("post", "/api/scan", "paypal-phish.eml"),
        ("get", "/history", None),
        ("get", "/no-such-page", None),
        ("get", "/simulate-error", None),
    ],
)
def test_no_response_reveals_the_hostname(ec2_client, method, path, upload):
    # On EC2 the hostname is derived from the private IP address: ip-10-0-21-44.
    ec2_client.post("/scan", data=sample_upload("team-lunch.eml"))
    data = sample_upload(upload) if upload else None

    response = getattr(ec2_client, method)(path, data=data)

    assert config.HOSTNAME not in response.get_data(as_text=True)


def test_health_does_not_touch_the_database(client, monkeypatch):
    # If anyone makes /health query the database, this is the test that stops them:
    # one RDS outage would fail every instance's check at once.
    def database_touched(*args, **kwargs):
        raise AssertionError("/health touched the database")

    # A context of its own, undone before the configuration fixture tidies up after the test.
    with monkeypatch.context() as patch:
        for name in ("init_schema", "save_scan", "recent_scans", "db_is_reachable", "_connect"):
            patch.setattr(db, name, database_touched)
        patch.setattr(psycopg, "connect", database_touched)
        patch.setattr(config, "get_db_password", database_touched)

        response = client.get("/health")

    assert response.status_code == 200


def test_failed_save_still_shows_the_result_with_a_warning(client, monkeypatch):
    monkeypatch.setattr(db, "save_scan", unavailable)

    response = client.post("/scan", data=sample_upload("paypal-phish.eml"))

    page = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Phishing" in page
    assert SAVE_WARNING in page


def test_successful_save_shows_no_warning(client):
    response = client.post("/scan", data=sample_upload("paypal-phish.eml"))

    assert SAVE_WARNING not in response.get_data(as_text=True)


def test_failed_save_is_logged_as_an_error_with_its_type(client, monkeypatch, caplog):
    monkeypatch.setattr(db, "save_scan", unavailable)

    with caplog.at_level(logging.INFO):
        client.post("/scan", data=sample_upload("paypal-phish.eml"))

    (failure,) = [record for record in caplog.records if record.getMessage() == "save_failed"]
    assert failure.levelname == "ERROR"
    assert failure.fields["error_type"] == "StorageError"


def test_history_lists_scans_with_the_instance_that_served_them(ec2_client):
    ec2_client.post("/scan", data=sample_upload("paypal-phish.eml"))

    response = ec2_client.get("/history")

    page = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "paypal-phish.eml" in page
    assert EC2_INSTANCE_ID in page


def test_api_scan_reports_the_instance_id(ec2_client):
    response = ec2_client.post("/api/scan", data=sample_upload("team-lunch.eml"))

    assert response.get_json()["served_by"] == EC2_INSTANCE_ID


def test_history_lists_the_most_recent_scan_first(client):
    client.post("/scan", data=sample_upload("team-lunch.eml"))
    client.post("/scan", data=sample_upload("paypal-phish.eml"))

    page = client.get("/history").get_data(as_text=True)

    assert page.index("paypal-phish.eml") < page.index("team-lunch.eml")


def test_empty_history_says_so(client):
    response = client.get("/history")

    assert "No scans yet." in response.get_data(as_text=True)


def test_history_returns_503_when_the_database_is_unavailable(client, monkeypatch):
    monkeypatch.setattr(db, "recent_scans", unavailable)

    response = client.get("/history")

    assert response.status_code == 503
    assert "temporarily unavailable" in response.get_data(as_text=True)


def test_api_scan_returns_the_expected_json_keys(client):
    response = client.post("/api/scan", data=sample_upload("paypal-phish.eml"))

    body = response.get_json()
    assert response.status_code == 200
    assert set(body) == API_KEYS
    assert (body["verdict"], body["score"], body["scan_id"]) == ("Phishing", 100, 1)
    assert body["findings"][0]["code"] == "href_mismatch_brand"


def test_api_scan_reports_a_null_scan_id_when_the_save_fails(client, monkeypatch):
    monkeypatch.setattr(db, "save_scan", unavailable)

    response = client.post("/api/scan", data=sample_upload("paypal-phish.eml"))

    assert response.status_code == 200
    assert response.get_json()["scan_id"] is None


def test_api_errors_are_json(client):
    response = client.post("/api/scan", data={})

    assert response.status_code == 400
    assert response.is_json
    assert set(response.get_json()) == {"error"}


def test_oversized_upload_is_rejected_with_413(client):
    too_large = b"x" * (5 * 1024 * 1024 + 1)

    response = client.post("/scan", data=upload_of(too_large, "huge.eml"))

    assert response.status_code == 413
    assert "5 MB limit" in response.get_data(as_text=True)


def test_upload_limit_comes_from_the_configuration(isolated_config, history, monkeypatch):
    monkeypatch.setenv("MAX_UPLOAD_BYTES", str(1024 * 1024))
    client = _client()

    response = client.post("/api/scan", data=upload_of(b"x" * (1024 * 1024 + 1), "a.eml"))

    assert response.status_code == 413
    assert response.get_json() == {"error": "The file is larger than the 1 MB limit."}


def test_uploaded_file_is_never_written_to_disk(client, monkeypatch):
    def written_to_disk(*args, **kwargs):
        raise AssertionError("the upload was spooled to a temporary file")

    # Werkzeug's default spools uploads over 500 KB through this class.
    monkeypatch.setattr(werkzeug.formparser, "SpooledTemporaryFile", written_to_disk)
    large = b"Subject: padding\n\n" + b"a" * (2 * 1024 * 1024)

    response = client.post("/scan", data=upload_of(large, "large.eml"))

    assert response.status_code == 200


def test_simulate_error_returns_a_generic_500(client):
    response = client.get("/simulate-error")

    page = response.get_data(as_text=True)
    assert response.status_code == 500
    assert "Something went wrong on our side" in page
    assert "Traceback" not in page
    assert "Simulated failure" not in page
    assert "RuntimeError" not in page


def test_unexpected_error_is_logged_with_its_type_and_traceback(client, caplog):
    with caplog.at_level(logging.INFO):
        client.get("/simulate-error")

    (failure,) = [record for record in caplog.records if record.getMessage() == "unhandled_error"]
    assert failure.levelname == "ERROR"
    assert failure.exc_info[0] is RuntimeError


def test_unknown_page_returns_a_friendly_404(client):
    response = client.get("/no-such-page")

    assert response.status_code == 404
    assert "There is no page at this address." in response.get_data(as_text=True)


def test_wrong_method_returns_405(client):
    response = client.get("/scan")

    assert response.status_code == 405


def test_content_from_the_email_is_escaped(client):
    hostile = eml(
        """
        From: "<script>alert('from')</script>" <a@example.org>
        Subject: <img src=x onerror=alert('subject')>

        Hello.
        """
    )

    response = client.post("/scan", data=upload_of(hostile, "<b>name</b>.eml"))

    page = response.get_data(as_text=True)
    assert "<script>" not in page
    assert "<img" not in page
    assert "<b>name</b>" not in page
    assert "&lt;script&gt;" in page
    assert "&lt;b&gt;name&lt;/b&gt;" in page


def test_each_request_is_logged_as_one_line_with_its_outcome(client, caplog):
    with caplog.at_level(logging.INFO):
        client.post("/scan", data=sample_upload("paypal-phish.eml"))

    (line,) = request_lines(caplog)
    assert line["path"] == "/scan"
    assert line["status"] == 200
    assert isinstance(line["duration_ms"], int)
    assert (line["verdict"], line["score"], line["filename"]) == (
        "Phishing",
        100,
        "paypal-phish.eml",
    )


def test_request_line_is_named_after_its_route(client, caplog):
    with caplog.at_level(logging.INFO):
        client.post("/scan", data=sample_upload("team-lunch.eml"))

    (record,) = [record for record in caplog.records if "status" in getattr(record, "fields", {})]
    assert record.getMessage() == "scan"


def test_server_error_request_line_is_logged_at_error_level(client, caplog):
    with caplog.at_level(logging.INFO):
        client.get("/simulate-error")

    (record,) = [record for record in caplog.records if "status" in getattr(record, "fields", {})]
    assert record.fields["status"] == 500
    assert record.levelname == "ERROR"


def test_log_lines_carry_the_instance_id_not_the_hostname(
    isolated_config, history, restore_root_logger, monkeypatch, tmp_path
):
    log_file = tmp_path / "app.log"
    monkeypatch.setenv("INSTANCE_ID", EC2_INSTANCE_ID)
    monkeypatch.setenv("LOG_FILE", str(log_file))

    _client().post("/scan", data=sample_upload("team-lunch.eml"))

    lines = [json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines()]
    assert {line["host"] for line in lines} == {EC2_INSTANCE_ID}
    assert config.HOSTNAME not in log_file.read_text(encoding="utf-8")


def test_email_content_never_reaches_the_log(client, caplog):
    marker = "UNIQUE-BODY-MARKER-7d41"
    email = eml(
        f"""
        From: dana@example.org
        Subject: {marker}-subject

        {marker}-body
        """
    )

    with caplog.at_level(logging.DEBUG):
        client.post("/scan", data=upload_of(email, "note.eml"))

    logged = json.dumps([getattr(record, "fields", {}) for record in caplog.records])
    logged += " ".join(record.getMessage() for record in caplog.records)
    assert marker not in logged


def _client():
    application = web.create_app()
    application.testing = True
    return application.test_client()
