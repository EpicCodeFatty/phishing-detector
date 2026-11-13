"""HTTP layer: the upload form, scan results, scan history, a JSON API and the health check.

The engine is run as analyze(raw_bytes) and nothing more. A stored scan is shown from
its saved findings without running the engine again: the email was never kept. Every failure is
turned into a friendly page here, or a JSON error under /api/; no stack trace,
secret or database detail ever reaches a response.

Run locally:   flask --app app.web run --port 8000
Run on EC2:    gunicorn --bind 0.0.0.0:8000 'app.web:create_app()'
"""

import io
import logging
import time
from dataclasses import asdict, dataclass
from typing import IO

from flask import (
    Blueprint,
    Flask,
    Request,
    Response,
    current_app,
    g,
    jsonify,
    render_template,
    request,
)
from werkzeug.exceptions import BadRequest, HTTPException, NotFound

from app import config, db
from app.detector import analyze
from app.detector.models import Result
from app.detector.parse import parse_email
from app.detector.scoring import score_categories
from app.logging_setup import configure_logging, error_fields, log_event

logger = logging.getLogger(__name__)

UPLOAD_FIELD = "file"
API_PREFIX = "/api/"
BYTES_PER_MEGABYTE = 1024 * 1024
MILLISECONDS_PER_SECOND = 1000

# The development server's address when this module is run directly. Port 8000 is
# the one the load balancer forwards to on EC2.
DEVELOPMENT_HOST = "127.0.0.1"
DEVELOPMENT_PORT = 8000

# What each error status tells the user. Deliberately general: the detail goes to the log.
ERROR_MESSAGES = {
    400: "The upload could not be read. Choose an email file and try again.",
    404: "There is no page at this address.",
    405: "This address does not accept that kind of request.",
    413: "The file is larger than the {max_mb} MB limit.",
    503: "Scan history is temporarily unavailable. Scanning still works.",
}
CLIENT_ERROR_MESSAGE = "The request could not be completed."
SERVER_ERROR_MESSAGE = "Something went wrong on our side. Please try again in a moment."
SERVER_ERROR = 500
SERVICE_UNAVAILABLE = 503

# Event name for request lines whose route is unknown, such as a 404.
UNROUTED_EVENT = "request"

# Sent with every response, pages, JSON, errors and the stylesheet alike, unless the
# response already has its own. They are the second layer behind template escaping: if
# hostile markup from an email ever got through, the browser would still refuse to run a
# script or load anything from another origin. The policy allows files from this origin
# only, so the templates may contain no inline <script>, <style> or style="" attribute.
# No Strict-Transport-Security: the service is plain HTTP, where browsers ignore it.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    # The older form of frame-ancestors 'none', for browsers that do not read the policy.
    "X-Frame-Options": "DENY",
}

pages = Blueprint("pages", __name__)


class InMemoryRequest(Request):
    """A request whose uploaded files stay in memory and are never written to disk.

    Werkzeug spools any upload over 500 KB to a temporary file by default. A
    file that exists is a file something might open, so this one never does.
    MAX_CONTENT_LENGTH bounds the memory an upload can take.
    """

    def _get_file_stream(
        self,
        total_content_length: int | None,
        content_type: str | None,
        filename: str | None = None,
        content_length: int | None = None,
    ) -> IO[bytes]:
        return io.BytesIO()


@dataclass(frozen=True)
class ScanOutcome:
    """A finished scan: what the engine found, the record of it, and its id if saved."""

    result: Result
    record: db.ScanRecord
    scan_id: int | None  # None when the history could not be written


def create_app() -> Flask:
    """Build the application from the environment.

    Raises ConfigError when the configuration is malformed, and OSError when the
    log file cannot be opened: either should stop the process from starting.
    An unreachable database does not: see _initialise_schema().
    """
    settings = config.get_settings()
    configure_logging(settings.log_file, settings.instance_id, settings.release)
    _initialise_schema()

    app = Flask(__name__)
    app.request_class = InMemoryRequest
    app.config["MAX_CONTENT_LENGTH"] = settings.max_upload_bytes
    app.register_blueprint(pages)
    app.before_request(_start_request_log)
    app.after_request(_finish_request_log)
    app.after_request(_add_security_headers)
    app.register_error_handler(HTTPException, _handle_http_error)
    # The boundary for everything nobody anticipated: logged in full, shown generically.
    app.register_error_handler(Exception, _handle_unexpected_error)
    return app


@pages.get("/")
def upload_form() -> str:
    """Show the upload form."""
    return render_template("upload.html", max_mb=_max_upload_megabytes())


@pages.post("/scan")
def scan() -> str:
    """Analyse the uploaded file, save it to the history, and show the result."""
    outcome = _scan_upload()
    return _result_page(outcome.result, outcome.record, outcome.scan_id)


@pages.get("/scans/<int:scan_id>")
def scan_view(scan_id: int) -> str | tuple[str | Response, int]:
    """Show one stored scan in full: what the history row links to.

    A 404 page when no scan has this id, and the same 503 page as /history when
    the database is unavailable. The request's log line is the record of the view:
    its event is this route's name, scan_view, and it carries the scan id.
    """
    g.log_fields["scan_id"] = scan_id
    try:
        record = db.get_scan(scan_id)
    except db.StorageError as error:
        log_event(logger, logging.ERROR, "scan_view_unavailable", **error_fields(error))
        return _error_response(SERVICE_UNAVAILABLE)
    if record is None:
        raise NotFound()
    return _result_page(_stored_result(record), record, record.id)


@pages.get("/history")
def history() -> str | tuple[str | Response, int]:
    """Show the most recent scans, or a 503 page when the database is unavailable."""
    try:
        scans = db.recent_scans()
    except db.StorageError as error:
        log_event(logger, logging.ERROR, "history_unavailable", **error_fields(error))
        return _error_response(SERVICE_UNAVAILABLE)
    return render_template("history.html", scans=scans)


@pages.post("/api/scan")
def api_scan() -> Response:
    """Same as /scan, answered in JSON. scan_id is null when the scan was not saved."""
    outcome = _scan_upload()
    return jsonify(
        score=outcome.result.score,
        verdict=outcome.result.verdict,
        decided_by=outcome.result.decided_by,
        findings=[asdict(found) for found in outcome.result.findings],
        served_by=outcome.record.served_by,
        scan_id=outcome.scan_id,
    )


@pages.get("/health")
def health() -> tuple[dict[str, str], int]:
    """Liveness only. Deliberately does not touch the database.

    If it did, one database outage would fail both instances' checks at once:
    the load balancer would be left without targets, and the Auto Scaling Group
    would replace instances in a loop that outlives the outage. A database
    problem is visible on the 5XX alarm and the RDS metrics instead.

    host is the instance identifier, never the hostname, which on EC2 contains
    the private IP address. release is the build of the code that answered:
    during a deployment, repeated requests show the old release, then a mix,
    then only the new one.
    """
    settings = config.get_settings()
    return {"status": "ok", "host": settings.instance_id, "release": settings.release}, 200


@pages.get("/simulate-error")
def simulate_error() -> Response:
    """Deliberate 500, to demonstrate the 5XX alarm. A 404 unless ENABLE_ERROR_SIMULATION is on.

    Switched off, the route answers exactly like an address that does not exist, so it
    neither fires the alarm nor tells a stranger that it is there.
    """
    if not config.get_settings().enable_error_simulation:
        raise NotFound()
    raise RuntimeError("Simulated failure for alarm demonstration")


def _initialise_schema() -> None:
    """Create the scans table now if the database can be reached; if not, say so and carry on.

    Startup must survive a database outage. If this raised, gunicorn's workers
    would fail to start, /health would never answer, and the Auto Scaling Group
    would replace instances in a loop: exactly what the shallow health check
    exists to prevent. db creates the schema on its first successful call instead.
    """
    try:
        db.init_schema()
    except db.StorageError as error:
        log_event(logger, logging.ERROR, "schema_init_failed", **error_fields(error))


def _scan_upload() -> ScanOutcome:
    """Run the scan pipeline on the uploaded file. Raises BadRequest when there is none."""
    upload = request.files.get(UPLOAD_FIELD)
    if upload is None or not upload.filename:
        raise BadRequest()

    raw = upload.read()
    result = analyze(raw)
    email = parse_email(raw)
    record = db.ScanRecord(
        filename=upload.filename,
        sender=email.from_header or None,
        subject=email.subject or None,
        score=result.score,
        verdict=result.verdict,
        decided_by=result.decided_by,
        findings=result.findings,
        served_by=config.get_settings().instance_id,
    )
    g.log_fields |= {"verdict": result.verdict, "score": result.score, "filename": upload.filename}
    return ScanOutcome(result=result, record=record, scan_id=_save(record))


def _result_page(result: Result, record: db.ScanRecord, scan_id: int | None) -> str:
    """Render result.html, for a scan just made or for one read back from the history.

    scan_id is None when a new scan could not be saved. Only a record read back from
    the history has a created_at, and that is what tells the template which of the two
    pages it is drawing.
    """
    return render_template(
        "result.html",
        result=result,
        filename=record.filename,
        sender=record.sender or "",
        subject=record.subject or "",
        served_by=record.served_by,
        saved=scan_id is not None,
        scan_id=scan_id,
        scanned_at=record.created_at,
    )


def _stored_result(record: db.ScanRecord) -> Result:
    """Rebuild the engine's Result from a stored scan, without running the engine again.

    Score, verdict and decided_by are shown as they were stored: what the scan concluded
    at the time, whatever the engine's rules have become since. The per-category subtotals
    are the one part of a Result that is not stored. They are summed again from the stored
    findings, each of which carries the weight it had when the scan was made; only the cap
    on a category is today's.
    """
    return Result(
        score=record.score,
        verdict=record.verdict,
        decided_by=record.decided_by,
        findings=record.findings,
        category_scores=score_categories(record.findings),
    )


def _save(record: db.ScanRecord) -> int | None:
    """Save the scan and return its id, or None if the database is unavailable.

    A failed save must not lose the result: the analysis already succeeded, so the
    caller still shows it, with a notice, and the request still succeeds.
    """
    try:
        return db.save_scan(record)
    except db.StorageError as error:
        log_event(logger, logging.ERROR, "save_failed", **error_fields(error))
        return None


def _max_upload_megabytes() -> int:
    return current_app.config["MAX_CONTENT_LENGTH"] // BYTES_PER_MEGABYTE


def _start_request_log() -> None:
    g.request_started = time.perf_counter()
    g.log_fields = {}


def _finish_request_log(response: Response) -> Response:
    """Log one line for the request, once the response is ready."""
    started = g.get("request_started", time.perf_counter())
    duration_ms = round((time.perf_counter() - started) * MILLISECONDS_PER_SECOND)
    level = logging.ERROR if response.status_code >= SERVER_ERROR else logging.INFO
    log_event(
        logger,
        level,
        _event_name(),
        path=request.path,
        method=request.method,
        status=response.status_code,
        duration_ms=duration_ms,
        **g.get("log_fields", {}),
    )
    return response


def _add_security_headers(response: Response) -> Response:
    """Add SECURITY_HEADERS to the response, keeping any it already sets itself."""
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


def _event_name() -> str:
    """Name the request after its route: 'scan' for pages.scan."""
    if request.endpoint is None:
        return UNROUTED_EVENT
    return request.endpoint.rpartition(".")[2]


def _handle_http_error(error: HTTPException) -> tuple[str | Response, int]:
    return _error_response(error.code or SERVER_ERROR)


def _handle_unexpected_error(error: Exception) -> tuple[str | Response, int]:
    log_event(logger, logging.ERROR, "unhandled_error", error=error)
    return _error_response(SERVER_ERROR)


def _error_response(status: int) -> tuple[str | Response, int]:
    """Answer with a friendly error: a page, or JSON for the API."""
    message = _error_message(status)
    if request.path.startswith(API_PREFIX):
        return jsonify(error=message), status
    return render_template("error.html", status=status, message=message), status


def _error_message(status: int) -> str:
    if status in ERROR_MESSAGES:
        return ERROR_MESSAGES[status].format(max_mb=_max_upload_megabytes())
    if status < SERVER_ERROR:
        return CLIENT_ERROR_MESSAGE
    return SERVER_ERROR_MESSAGE


if __name__ == "__main__":
    create_app().run(host=DEVELOPMENT_HOST, port=DEVELOPMENT_PORT, debug=False)
