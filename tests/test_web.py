"""Tests for the routes, through Flask's test client. No database is needed."""

import json
import logging
from pathlib import Path

import psycopg
import pytest
import redis
import werkzeug.formparser
from flask import request, url_for
from markupsafe import escape

from app import cache, config, db, web
from tests.builders import SAMPLES, browser_upload, eml, sample_upload, upload_of
from tests.conftest import CACHE_TOKEN, FakeHistory

API_KEYS = {
    "score",
    "verdict",
    "decided_by",
    "findings",
    "served_by",
    "scan_id",
    "cache_hit",
    "seen",
}
SAVE_WARNING = "could not be saved"

# What user_data sets INSTANCE_ID to on EC2, read from IMDSv2 at boot.
EC2_INSTANCE_ID = "i-0123456789abcdef0"

# What user_data sets APP_RELEASE to on EC2: the first 12 hex characters of the zip's hash.
RELEASE = "3f9a1c2b7d10"

# The event logged when the schema could not be created at startup.
STARTUP_FAILURE = "schema_init_failed"

# Stands in for the database password wherever a test checks that it is never repeated.
PASSWORD_MARKER = "s3cret-PASSWORD-marker-91f2"

# What every response must carry, written out here rather than imported from web.py, so a
# loosened policy fails a test instead of passing it.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}

# What the load balancer adds to a request it received over HTTPS, before passing it on to
# the application as plain HTTP.
FORWARDED_FROM_HTTPS = {"X-Forwarded-Proto": "https"}

# Stored XSS: an email whose subject, sender display name, link text and link target carry
# markup, uploaded under a filename that does too. Under tests/, not samples/: the samples
# are a verdict corpus, and scripts/load.py uploads every one of them.
XSS_FIXTURE = Path(__file__).parent / "fixtures" / "xss-subject.eml"
HOSTILE_FILENAME = '"><img src=x onerror=alert(1)>.eml'
# No tag may open on the page. "onerror=" itself is harmless once the "<img" before it is
# escaped: it is then text, not an attribute, so it is not what these look for.
RAW_MARKUP = ("<script", "<img")
ESCAPED_MARKUP = ("&lt;script&gt;alert(1)&lt;/script&gt;", "&lt;img src=x onerror=alert(1)&gt;")


def unavailable(*args, **kwargs):
    raise db.StorageError("OperationalError: connection refused")


@pytest.fixture
def ec2_client(isolated_config, history, monkeypatch):
    """A client for the application configured as on EC2: INSTANCE_ID and APP_RELEASE set."""
    monkeypatch.setenv("INSTANCE_ID", EC2_INSTANCE_ID)
    monkeypatch.setenv("APP_RELEASE", RELEASE)
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
    assert response.get_json() == {"status": "ok", "host": EC2_INSTANCE_ID, "release": RELEASE}


def test_health_reports_a_local_release_when_none_is_set(client):
    response = client.get("/health")

    assert response.get_json()["release"] == "local"


@pytest.mark.parametrize(
    "outage",
    [
        psycopg.OperationalError("connection refused"),
        psycopg.errors.ConnectionTimeout("connection timeout expired"),
        config.ConfigError("Cannot read the database secret: ConnectTimeoutError"),
    ],
    ids=["database refuses", "database times out", "secret unreadable"],
)
def test_application_starts_and_answers_health_while_the_database_is_down(
    isolated_config, monkeypatch, caplog, outage
):
    # If startup needed the database, an outage would stop gunicorn's workers from
    # starting, /health would never answer, and the group would replace instances in a loop.
    def down(*args, **kwargs):
        raise outage

    monkeypatch.setenv("DB_PASSWORD", PASSWORD_MARKER)
    monkeypatch.setattr(db, "_open", down)

    with caplog.at_level(logging.INFO):
        response = _client().get("/health")

    (failure,) = [record for record in caplog.records if record.getMessage() == STARTUP_FAILURE]
    assert response.status_code == 200
    assert failure.levelname == "ERROR"
    assert failure.fields["error_type"] == "StorageError"


def test_successful_start_logs_no_schema_failure(client, caplog):
    with caplog.at_level(logging.INFO):
        client.get("/health")

    assert STARTUP_FAILURE not in [record.getMessage() for record in caplog.records]


def test_failed_connection_never_puts_the_password_in_a_log_line_or_a_page(
    isolated_config, restore_root_logger, monkeypatch, tmp_path
):
    # The whole path, from the driver's error to the log file and the page, with a driver
    # that quotes its connection string. Covers startup, a scan and the history page.
    log_file = tmp_path / "app.log"
    monkeypatch.setenv("LOG_FILE", str(log_file))
    monkeypatch.setenv("DB_PASSWORD", PASSWORD_MARKER)

    def refuse(**parameters):
        raise psycopg.OperationalError(f"connection failed: password={parameters['password']}")

    monkeypatch.setattr(psycopg, "connect", refuse)
    client = _client()

    pages = [
        client.post("/scan", data=sample_upload("paypal-phish.eml")),
        client.post("/api/scan", data=sample_upload("paypal-phish.eml")),
        client.get("/history"),
    ]

    logged = log_file.read_text(encoding="utf-8")
    assert {"schema_init_failed", "save_failed", "history_unavailable"} <= {
        json.loads(line)["event"] for line in logged.splitlines()
    }
    assert "connection failed" in logged
    assert PASSWORD_MARKER not in logged
    assert all(PASSWORD_MARKER not in page.get_data(as_text=True) for page in pages)


@pytest.mark.parametrize(
    "method,path,upload",
    [
        ("get", "/health", None),
        ("get", "/", None),
        ("post", "/scan", "paypal-phish.eml"),
        ("post", "/api/scan", "paypal-phish.eml"),
        ("get", "/history", None),
        ("get", "/scans/1", None),
        ("get", "/no-such-page", None),
        ("get", "/simulate-error", None),
    ],
)
def test_no_response_reveals_the_hostname(error_simulation, ec2_client, method, path, upload):
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


def test_history_links_each_file_name_to_its_scan(client):
    client.post("/scan", data=sample_upload("paypal-phish.eml"))

    page = client.get("/history").get_data(as_text=True)

    assert '<a href="/scans/1">paypal-phish.eml</a>' in page


def test_scan_detail_shows_the_stored_verdict_findings_and_instance(ec2_client, history):
    ec2_client.post("/scan", data=sample_upload("paypal-phish.eml"))
    (record,) = history.records

    response = ec2_client.get("/scans/1")

    page = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "verdict-phishing" in page
    assert f"Score {record.score}/100" in page
    assert [
        found.reason for found in record.findings if str(escape(found.reason)) not in page
    ] == []
    assert EC2_INSTANCE_ID in page


def test_scan_detail_gives_the_findings_and_category_points_of_the_original_result(client):
    # The category points are not stored: the detail page works them out again.
    def findings_section(page: str) -> str:
        return page[page.index("<h2>Findings</h2>") : page.index('<p class="next-action">')]

    result_page = client.post("/scan", data=sample_upload("paypal-phish.eml"))

    detail_page = client.get("/scans/1")

    original = findings_section(result_page.get_data(as_text=True))
    assert "points" in original
    assert findings_section(detail_page.get_data(as_text=True)) == original


def test_scan_detail_says_when_it_was_scanned_and_leads_back_to_the_history(client, history):
    client.post("/scan", data=sample_upload("team-lunch.eml"))
    (record,) = history.records

    page = client.get("/scans/1").get_data(as_text=True)

    assert "Scanned at" in page
    assert record.created_at.strftime("%Y-%m-%d %H:%M:%S") + " UTC" in page
    assert '<a href="/history">Back to history</a>' in page
    assert "Scan another email" not in page
    assert SAVE_WARNING not in page


def test_result_of_a_new_scan_offers_another_scan_and_no_scan_time(client):
    response = client.post("/scan", data=sample_upload("team-lunch.eml"))

    page = response.get_data(as_text=True)
    assert "Scan another email" in page
    assert "Scanned at" not in page
    assert "Back to history" not in page


@pytest.mark.parametrize("path", ["/scans/2", "/scans/abc", "/scans/-1", "/scans/1.5", "/scans/"])
def test_scan_detail_of_an_unknown_or_malformed_id_is_a_404(client, path):
    client.post("/scan", data=sample_upload("team-lunch.eml"))

    response = client.get(path)

    assert response.status_code == 404
    assert "There is no page at this address." in response.get_data(as_text=True)


def test_scan_detail_returns_503_when_the_database_is_unavailable(client, monkeypatch):
    monkeypatch.setattr(db, "get_scan", unavailable)

    response = client.get("/scans/1")

    assert response.status_code == 503
    assert "temporarily unavailable" in response.get_data(as_text=True)


def test_unavailable_scan_detail_is_logged_as_an_error_with_its_type(client, monkeypatch, caplog):
    monkeypatch.setattr(db, "get_scan", unavailable)

    with caplog.at_level(logging.INFO):
        client.get("/scans/1")

    (failure,) = [
        record for record in caplog.records if record.getMessage() == "scan_view_unavailable"
    ]
    assert failure.levelname == "ERROR"
    assert failure.fields["error_type"] == "StorageError"


def test_each_scan_view_is_logged_as_one_line_with_the_scan_id(client, caplog):
    client.post("/scan", data=sample_upload("team-lunch.eml"))
    caplog.clear()  # the upload's own line: only what the view logs is counted

    with caplog.at_level(logging.INFO):
        client.get("/scans/1")

    (record,) = [record for record in caplog.records if hasattr(record, "fields")]
    assert record.getMessage() == "scan_view"
    assert (record.fields["scan_id"], record.fields["status"]) == (1, 200)


def test_view_of_a_missing_scan_is_logged_with_the_id_that_was_asked_for(client, caplog):
    with caplog.at_level(logging.INFO):
        client.get("/scans/7")

    (line,) = request_lines(caplog)
    assert (line["scan_id"], line["status"]) == (7, 404)


def test_hostile_email_is_shown_escaped_on_its_scan_detail_page(client):
    client.post("/scan", **browser_upload(XSS_FIXTURE.read_bytes(), HOSTILE_FILENAME))

    page = client.get("/scans/1").get_data(as_text=True)

    assert [markup for markup in RAW_MARKUP if markup in page] == []
    assert [markup for markup in ESCAPED_MARKUP if markup not in page] == []


def test_scan_detail_carries_the_security_headers(client):
    client.post("/scan", data=sample_upload("team-lunch.eml"))

    response = client.get("/scans/1")

    assert response.status_code == 200
    assert {name: response.headers.get(name) for name in SECURITY_HEADERS} == SECURITY_HEADERS


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


def test_simulate_error_returns_a_generic_500(error_simulation, client):
    response = client.get("/simulate-error")

    page = response.get_data(as_text=True)
    assert response.status_code == 500
    assert "Something went wrong on our side" in page
    assert "Traceback" not in page
    assert "Simulated failure" not in page
    assert "RuntimeError" not in page


def test_simulate_error_is_a_plain_404_when_switched_off(client):
    response = client.get("/simulate-error")

    assert response.status_code == 404
    assert "There is no page at this address." in response.get_data(as_text=True)


def test_switched_off_simulation_raises_nothing(client, caplog):
    with caplog.at_level(logging.INFO):
        client.get("/simulate-error")

    assert "unhandled_error" not in [record.getMessage() for record in caplog.records]


def test_unexpected_error_is_logged_with_its_type_and_traceback(error_simulation, client, caplog):
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


@pytest.mark.parametrize("path", ["/", "/history", "/health", "/no-such-page"])
def test_every_response_carries_the_security_headers(client, path):
    response = client.get(path)

    assert {name: response.headers.get(name) for name in SECURITY_HEADERS} == SECURITY_HEADERS


def test_a_server_error_carries_the_security_headers(error_simulation, client):
    response = client.get("/simulate-error")

    assert response.status_code == 500
    assert {name: response.headers.get(name) for name in SECURITY_HEADERS} == SECURITY_HEADERS


def test_a_header_the_response_sets_itself_is_kept(app):
    @app.get("/own-referrer-policy")
    def own_referrer_policy():
        return "", 200, {"Referrer-Policy": "same-origin"}

    response = app.test_client().get("/own-referrer-policy")

    assert response.headers["Referrer-Policy"] == "same-origin"
    assert response.headers["X-Frame-Options"] == "DENY"


def test_no_strict_transport_security_header_is_sent_even_over_https(client):
    # The certificate is self-signed: with this header a browser would refuse the site
    # instead of letting the user click through its warning.
    response = client.get("/", headers=FORWARDED_FROM_HTTPS)

    assert "Strict-Transport-Security" not in response.headers


def test_a_request_the_load_balancer_received_over_https_is_seen_as_https(client):
    with client:  # keeps the request in reach after the response has been returned
        client.get("/health", headers=FORWARDED_FROM_HTTPS)

        assert request.scheme == "https"


def test_a_request_with_no_forwarded_scheme_is_seen_as_http(client):
    with client:
        client.get("/health")

        assert request.scheme == "http"


def test_an_absolute_url_built_during_an_https_request_uses_https(client):
    with client:
        client.get("/health", headers=FORWARDED_FROM_HTTPS)

        assert url_for("pages.history", _external=True) == "https://localhost/history"


def test_only_the_address_the_load_balancer_added_is_taken_as_the_client(client):
    # The load balancer appends the address it saw to whatever X-Forwarded-For the client
    # sent, so the last entry is the only one a client cannot forge.
    with client:
        client.get("/health", headers={"X-Forwarded-For": "203.0.113.9, 198.51.100.4"})

        assert request.remote_addr == "198.51.100.4"


def test_hostile_upload_keeps_its_filename_in_the_history(client, history: FakeHistory):
    # What makes the two tests below meaningful: the hostile name reaches the page unaltered.
    client.post("/scan", **browser_upload(XSS_FIXTURE.read_bytes(), HOSTILE_FILENAME))

    (record,) = history.records
    assert record.filename == HOSTILE_FILENAME
    assert "<script>alert(1)</script>" in record.subject


def test_hostile_email_is_shown_escaped_on_the_result_page(client):
    response = client.post("/scan", **browser_upload(XSS_FIXTURE.read_bytes(), HOSTILE_FILENAME))

    page = response.get_data(as_text=True)
    assert [markup for markup in RAW_MARKUP if markup in page] == []
    assert [markup for markup in ESCAPED_MARKUP if markup not in page] == []


def test_hostile_email_is_shown_escaped_on_the_history_page(client):
    client.post("/scan", **browser_upload(XSS_FIXTURE.read_bytes(), HOSTILE_FILENAME))

    page = client.get("/history").get_data(as_text=True)

    assert [markup for markup in RAW_MARKUP if markup in page] == []
    assert [markup for markup in ESCAPED_MARKUP if markup not in page] == []


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


def test_server_error_request_line_is_logged_at_error_level(error_simulation, client, caplog):
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


def test_log_lines_carry_the_release(
    isolated_config, history, restore_root_logger, monkeypatch, tmp_path
):
    log_file = tmp_path / "app.log"
    monkeypatch.setenv("APP_RELEASE", RELEASE)
    monkeypatch.setenv("LOG_FILE", str(log_file))

    _client().post("/scan", data=sample_upload("team-lunch.eml"))

    lines = [json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines()]
    assert lines
    assert {line["release"] for line in lines} == {RELEASE}


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


# ------------------------------------------------------------------------ Result cache
#
# The valkey fixture switches the cache on, against an in-memory fake (conftest.py).

SEEN_TWICE = "Seen 2 times in the last 24 hours"
FROM_CACHE = "Served from cache (scanned before; result reused)"
CACHE_WARNING = "cache_unavailable"


def scan_lines(caplog: pytest.LogCaptureFixture) -> list[dict[str, object]]:
    return [fields for fields in request_lines(caplog) if fields["path"] in ("/scan", "/api/scan")]


def findings_part(page: str) -> str:
    return page[page.index("<h2>Findings</h2>") : page.index('<p class="next-action">')]


@pytest.fixture
def engine_calls(monkeypatch) -> list[bytes]:
    """Count the engine's runs, while still running it."""
    calls: list[bytes] = []
    original = web.analyze

    def counting_analyze(raw: bytes):
        calls.append(raw)
        return original(raw)

    monkeypatch.setattr(web, "analyze", counting_analyze)
    return calls


def test_a_first_scan_runs_the_engine_once_and_stores_the_result(valkey, client, engine_calls):
    client.post("/scan", data=sample_upload("paypal-phish.eml"))

    assert len(engine_calls) == 1
    assert [command[0] for command in valkey.commands] == ["GET", "INCR", "EXPIRE", "SET"]


def test_a_repeated_scan_is_answered_from_the_cache_without_the_engine(
    valkey, client, engine_calls
):
    client.post("/api/scan", data=sample_upload("paypal-phish.eml"))

    client.post("/api/scan", data=sample_upload("paypal-phish.eml"))

    assert len(engine_calls) == 1


def test_a_result_from_the_cache_matches_what_the_engine_returned(valkey, client):
    first = client.post("/api/scan", data=sample_upload("paypal-phish.eml")).get_json()

    second = client.post("/api/scan", data=sample_upload("paypal-phish.eml")).get_json()

    for field in ("score", "verdict", "decided_by", "findings"):
        assert second[field] == first[field]
    assert (first["cache_hit"], second["cache_hit"]) == (False, True)


def test_a_result_from_the_cache_gives_the_same_page_of_findings(valkey, client):
    first = client.post("/scan", data=sample_upload("paypal-phish.eml")).get_data(as_text=True)

    second = client.post("/scan", data=sample_upload("paypal-phish.eml")).get_data(as_text=True)

    assert findings_part(second) == findings_part(first)


def test_a_scan_from_the_cache_is_saved_to_the_history_as_such(valkey, client, history):
    client.post("/scan", data=sample_upload("paypal-phish.eml"))

    client.post("/scan", data=sample_upload("paypal-phish.eml"))

    assert [record.cache_hit for record in history.records] == [False, True]
    assert history.records[1].sender == history.records[0].sender
    assert history.records[1].subject == history.records[0].subject


def test_the_file_name_and_instance_come_from_the_request_not_the_cache(
    valkey, client, history, monkeypatch
):
    monkeypatch.setenv("INSTANCE_ID", "i-0aaaaaaaaaaaaaaaa")
    config.get_settings.cache_clear()
    client.post("/scan", data=sample_upload("paypal-phish.eml"))
    monkeypatch.setenv("INSTANCE_ID", "i-0bbbbbbbbbbbbbbbb")
    config.get_settings.cache_clear()
    raw = (SAMPLES / "paypal-phish.eml").read_bytes()

    client.post("/scan", data=upload_of(raw, "forwarded-again.eml"))

    cached = history.records[1]
    assert (cached.filename, cached.served_by) == ("forwarded-again.eml", "i-0bbbbbbbbbbbbbbbb")


def test_the_first_scan_shows_no_count_and_no_cache_line(valkey, client):
    page = client.post("/scan", data=sample_upload("paypal-phish.eml")).get_data(as_text=True)

    assert "Seen " not in page
    assert FROM_CACHE not in page


def test_the_second_scan_shows_its_count_and_that_it_came_from_the_cache(valkey, client):
    client.post("/scan", data=sample_upload("paypal-phish.eml"))

    page = client.post("/scan", data=sample_upload("paypal-phish.eml")).get_data(as_text=True)

    assert SEEN_TWICE in page
    assert FROM_CACHE in page


def test_the_api_reports_the_count(valkey, client):
    first = client.post("/api/scan", data=sample_upload("paypal-phish.eml")).get_json()

    second = client.post("/api/scan", data=sample_upload("paypal-phish.eml")).get_json()

    assert (first["seen"], second["seen"]) == (1, 2)


def test_the_count_is_shared_whatever_the_file_is_called(valkey, client):
    raw = (SAMPLES / "paypal-phish.eml").read_bytes()
    client.post("/api/scan", data=upload_of(raw, "one.eml"))

    body = client.post("/api/scan", data=upload_of(raw, "two.eml")).get_json()

    assert body["seen"] == 2


def test_the_detail_page_of_a_cached_scan_says_so_but_shows_no_count(valkey, client):
    client.post("/scan", data=sample_upload("paypal-phish.eml"))
    client.post("/scan", data=sample_upload("paypal-phish.eml"))

    page = client.get("/scans/2").get_data(as_text=True)

    assert FROM_CACHE in page
    assert "Seen " not in page


def test_the_history_marks_scans_served_from_the_cache(valkey, client):
    client.post("/scan", data=sample_upload("paypal-phish.eml"))
    client.post("/scan", data=sample_upload("paypal-phish.eml"))

    page = client.get("/history").get_data(as_text=True)

    assert page.count('class="cache-tag"') == 1


def test_the_scan_log_line_says_how_the_cache_took_part(valkey, client, caplog):
    client.post("/scan", data=sample_upload("paypal-phish.eml"))
    client.post("/scan", data=sample_upload("paypal-phish.eml"))

    lines = scan_lines(caplog)

    assert [(line["cache"], line["seen"]) for line in lines] == [("miss", 1), ("hit", 2)]
    assert all(isinstance(line["analysis_ms"], float) for line in lines)


def test_without_a_cache_the_scan_is_logged_as_off_with_no_count(client, caplog):
    client.post("/scan", data=sample_upload("paypal-phish.eml"))

    (line,) = scan_lines(caplog)

    assert line["cache"] == "off"
    assert "seen" not in line
    assert line["analysis_ms"] >= 0


def test_without_a_cache_no_client_is_created(client, monkeypatch, engine_calls):
    monkeypatch.setattr(cache.redis, "Redis", lambda **options: pytest.fail("client created"))

    response = client.post("/scan", data=sample_upload("paypal-phish.eml"))

    assert response.status_code == 200
    assert len(engine_calls) == 1


def test_scans_carry_on_when_the_cache_is_down(valkey, client, engine_calls, caplog):
    valkey.failure = redis.ConnectionError("Connection refused")

    responses = [client.post("/scan", data=sample_upload("paypal-phish.eml")) for _ in range(4)]

    assert [response.status_code for response in responses] == [200] * 4
    assert all("Phishing" in response.get_data(as_text=True) for response in responses)
    assert len(engine_calls) == 4
    assert [line["cache"] for line in scan_lines(caplog)] == ["error"] * 4
    assert [
        record.levelno for record in caplog.records if record.getMessage() == CACHE_WARNING
    ] == [logging.WARNING]


def test_after_a_cache_failure_it_is_left_alone_for_thirty_seconds(valkey, client, monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(cache.time, "monotonic", lambda: now[0])
    valkey.failure = redis.TimeoutError("Timeout reading from socket")
    client.post("/scan", data=sample_upload("paypal-phish.eml"))
    valkey.failure = None

    now[0] += 29
    client.post("/scan", data=sample_upload("paypal-phish.eml"))
    untouched = list(valkey.commands)
    now[0] += 2
    client.post("/scan", data=sample_upload("paypal-phish.eml"))

    assert untouched == []
    assert valkey.commands[0][0] == "GET"


def test_a_token_that_cannot_be_fetched_costs_neither_startup_nor_the_scan(
    isolated_config, history, monkeypatch, engine_calls
):
    fetches: list[str] = []

    def refuse(secret_arn, limits):
        fetches.append(secret_arn)
        raise config.ConfigError("Cannot read the secret: EndpointConnectionError")

    monkeypatch.setenv("CACHE_HOST", "cache.example")
    monkeypatch.setenv("CACHE_SECRET_ARN", "arn:aws:secretsmanager:eu-north-1:1:secret:c")
    monkeypatch.setattr(config, "_read_secret", refuse)
    test_client = _client()
    fetched_at_startup = list(fetches)

    responses = [
        test_client.post("/scan", data=sample_upload("paypal-phish.eml")) for _ in range(3)
    ]

    assert fetched_at_startup == []
    assert [response.status_code for response in responses] == [200] * 3
    assert len(fetches) == 1
    assert len(engine_calls) == 3


def test_health_makes_no_cache_call(valkey, client):
    response = client.get("/health")

    assert response.status_code == 200
    assert valkey.clients == []
    assert valkey.commands == []


def test_the_cache_token_never_appears_in_a_log_line_or_a_page(valkey, client, caplog):
    caplog.set_level(logging.DEBUG)
    valkey.failure = redis.AuthenticationError("invalid username-password pair")

    page = client.post("/scan", data=sample_upload("paypal-phish.eml")).get_data(as_text=True)

    assert CACHE_TOKEN not in page
    assert CACHE_TOKEN not in caplog.text
    assert all(CACHE_TOKEN not in str(record.__dict__) for record in caplog.records)


def test_a_page_from_the_cache_carries_the_security_headers(valkey, client):
    client.post("/scan", data=sample_upload("paypal-phish.eml"))

    response = client.post("/scan", data=sample_upload("paypal-phish.eml"))

    assert FROM_CACHE in response.get_data(as_text=True)
    assert {name: response.headers.get(name) for name in SECURITY_HEADERS} == SECURITY_HEADERS


def test_hostile_text_from_the_cache_is_still_escaped(valkey, client):
    raw = XSS_FIXTURE.read_bytes()
    client.post("/scan", **browser_upload(raw, HOSTILE_FILENAME))

    page = client.post("/scan", **browser_upload(raw, HOSTILE_FILENAME)).get_data(as_text=True)

    assert FROM_CACHE in page
    assert not any(markup in page for markup in RAW_MARKUP)
    assert all(escaped in page for escaped in ESCAPED_MARKUP)
