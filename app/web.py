"""HTTP layer: the scan page, scan results, scan history, a JSON API and the health check.

The engine is run as analyze(raw_bytes) and nothing more. A stored scan is shown from
its saved findings without running the engine again: the email was never kept. An email
already scanned since the last deploy is answered from the result cache (app/cache.py), when
there is one, the same way. Every failure is turned into a friendly page here, or a JSON
error under /api/; no stack trace, secret or database detail ever reaches a response.

Run locally:   flask --app app.web run --port 8000
Run on EC2:    gunicorn --bind 0.0.0.0:8000 'app.web:create_app()'
"""

import io
import logging
import mimetypes
import time
from collections import Counter
from dataclasses import asdict, dataclass
from email.utils import parseaddr
from typing import IO, Any

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
from werkzeug.middleware.proxy_fix import ProxyFix

from app import cache, config, db
from app.detector import analyze
from app.detector.models import SEVERITY_WEIGHT, Finding, Result
from app.detector.parse import parse_email
from app.detector.scoring import score_categories
from app.logging_setup import configure_logging, error_fields, log_event

logger = logging.getLogger(__name__)

UPLOAD_FIELD = "file"
# The Scan page's second form: the raw email pasted as text, scanned exactly like a file.
PASTE_FIELD = "raw_email"
# What the history calls a pasted email, which arrives with no file name of its own.
PASTED_FILENAME = "pasted-email.txt"
API_PREFIX = "/api/"
BYTES_PER_MEGABYTE = 1024 * 1024
MILLISECONDS_PER_SECOND = 1000

# analysis_ms is logged to two decimal places: the engine takes a few milliseconds and a
# cache lookup about one, so whole milliseconds would hide the difference being measured.
ANALYSIS_MS_DECIMALS = 2

# The result page says how often an email was seen only from the second time: "seen once"
# would be on every new scan, and says nothing.
MIN_SIGHTINGS_SHOWN = 2

# The development server's address when this module is run directly. Port 8000 is
# the one the load balancer forwards to on EC2.
DEVELOPMENT_HOST = "127.0.0.1"
DEVELOPMENT_PORT = 8000

# The engine's categories, in the order it reports them (detector/engine.py, CHECKS). The
# result page shows a block for each, with or without findings, so it needs all of them,
# not only those a scan happened to find something in.
CATEGORIES = ("links", "sender", "wording", "attachments")

# Which navigation link is marked as the current page, by route. A result belongs to Scan
# when it was just made, and to History when it was opened from there. Error pages mark
# neither: see _error_response().
NAV_SECTIONS = {
    "pages.upload_form": "scan",
    "pages.scan": "scan",
    "pages.history": "history",
    "pages.scan_view": "history",
}

# What each error status tells the user: a title and a sentence. Deliberately general:
# the detail goes to the log.
ERROR_TITLES = {
    400: "Nothing to scan",
    404: "Page not found",
    405: "Not allowed here",
    413: "File too large",
    500: "Something went wrong",
    503: "History unavailable",
}
ERROR_MESSAGES = {
    400: "Choose an email file or paste the raw email: one of the two, not both.",
    404: "This page does not exist.",
    405: "This address does not accept that kind of request.",
    413: "The file is larger than {max_mb} MB. Upload a smaller file or paste the raw email.",
    503: "Scan history is temporarily unavailable. Scanning still works.",
}
CLIENT_ERROR_TITLE = "Request not completed"
CLIENT_ERROR_MESSAGE = "The request could not be completed."
SERVER_ERROR_MESSAGE = "Something went wrong on our side. Please try again in a moment."
SERVER_ERROR = 500
SERVICE_UNAVAILABLE = 503

# The fonts' media type. Python takes media types from the operating system, and neither
# Windows nor every Linux image knows woff2, so the fonts would go out as
# application/octet-stream. Browsers load them regardless; the right type costs one line.
FONT_EXTENSION = ".woff2"
FONT_MEDIA_TYPE = "font/woff2"

# How many proxies stand between a client and this application on EC2: the load balancer,
# and nothing else. It is how many X-Forwarded-* values are believed, counted from the end.
TRUSTED_PROXIES = 1

# Event name for request lines whose route is unknown, such as a 404.
UNROUTED_EVENT = "request"

# Sent with every response, pages, JSON, errors and the stylesheet alike, unless the
# response already has its own. They are the second layer behind template escaping: if
# hostile markup from an email ever got through, the browser would still refuse to run a
# script or load anything from another origin. The policy allows files from this origin
# only, so the templates may contain no inline <script>, <style> or style="" attribute.
# No Strict-Transport-Security: the load balancer's certificate is self-signed, and with
# that header a browser refuses the site outright instead of letting the user click through
# its warning. With a trusted certificate the header would be added.
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
class CategoryView:
    """One category's block on the result page."""

    name: str  # as the engine names it: "links"
    findings: list[Finding]  # most severe first, as the engine returns them
    points: int  # what the category added to the score, after its cap


@dataclass(frozen=True)
class SenderView:
    """A From header split for the history table: the name, and the address after it."""

    name: str  # the display name; '' when there is none
    address: str  # '' when no address could be read, and then name is the raw header


@dataclass(frozen=True)
class ScanOutcome:
    """A scan to show: what the engine found, the record of it, and its id if saved.

    A scan just made, or one read back from the history.
    """

    result: Result
    record: db.ScanRecord
    scan_id: int | None  # None when the history could not be written
    seen: int | None = None  # times scanned in the last day; None when not known


def create_app() -> Flask:
    """Build the application from the environment.

    Raises ConfigError when the configuration is malformed, and OSError when the
    log file cannot be opened: either should stop the process from starting.
    An unreachable database does not: see _initialise_schema().
    """
    settings = config.get_settings()
    configure_logging(settings.log_file, settings.instance_id, settings.release)
    mimetypes.add_type(FONT_MEDIA_TYPE, FONT_EXTENSION)
    _initialise_schema()

    app = Flask(__name__)
    app.request_class = InMemoryRequest
    app.config["MAX_CONTENT_LENGTH"] = settings.max_upload_bytes
    # Werkzeug keeps a text field in memory up to its own limit, 500 KB by default, and
    # answers 413 above it. The pasted email is such a field: without this, a paste would be
    # refused at a tenth of the size a file is allowed.
    app.config["MAX_FORM_MEMORY_SIZE"] = settings.max_upload_bytes
    app.register_blueprint(pages)
    app.context_processor(_navigation)
    app.before_request(_start_request_log)
    app.after_request(_finish_request_log)
    app.after_request(_add_security_headers)
    app.register_error_handler(HTTPException, _handle_http_error)
    # The boundary for everything nobody anticipated: logged in full, shown generically.
    app.register_error_handler(Exception, _handle_unexpected_error)
    # TLS ends at the load balancer, so every request arrives here as plain HTTP from the
    # load balancer's own address. It passes on the scheme the client used and the client's
    # address in X-Forwarded-Proto and X-Forwarded-For; ProxyFix applies them, so
    # request.scheme is https and any absolute URL or redirect built here stays on HTTPS.
    # Believing these headers is safe only because nothing but the load balancer can reach
    # this port: the instances' security group admits the load balancer's group and no one
    # else. Reachable directly, a client could claim any scheme or address it liked.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUSTED_PROXIES, x_proto=TRUSTED_PROXIES)
    return app


@pages.get("/")
def upload_form() -> str:
    """Show the Scan page: a file upload, and a form to paste the raw email."""
    return render_template("upload.html", max_mb=_max_upload_megabytes())


@pages.post("/scan")
def scan() -> str:
    """Analyse the uploaded file or pasted email, save it to the history, and show the result."""
    return _result_page(_scan_upload())


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
    return _result_page(ScanOutcome(_stored_result(record), record, record.id))


@pages.get("/history")
def history() -> str | tuple[str | Response, int]:
    """Show the most recent scans, or a 503 page when the database is unavailable."""
    try:
        scans = db.recent_scans()
    except db.StorageError as error:
        log_event(logger, logging.ERROR, "history_unavailable", **error_fields(error))
        return _error_response(SERVICE_UNAVAILABLE)
    return render_template(
        "history.html",
        scans=scans,
        senders={scan.id: _sender_view(scan.sender) for scan in scans},
    )


@pages.post("/api/scan")
def api_scan() -> Response:
    """Same as /scan, answered in JSON.

    scan_id is null when the scan was not saved, and seen when the count is not known.
    """
    outcome = _scan_upload()
    return jsonify(
        score=outcome.result.score,
        verdict=outcome.result.verdict,
        decided_by=outcome.result.decided_by,
        findings=[asdict(found) for found in outcome.result.findings],
        served_by=outcome.record.served_by,
        scan_id=outcome.scan_id,
        cache_hit=outcome.record.cache_hit,
        seen=outcome.seen,
    )


@pages.get("/health")
def health() -> tuple[dict[str, str], int]:
    """Liveness only. Deliberately does not touch the database.

    If it did, one database outage would fail both instances' checks at once:
    the load balancer would be left without targets, and the Auto Scaling Group
    would replace instances in a loop that outlives the outage. A database
    problem is visible on the 5XX alarm and the RDS metrics instead. The same
    goes for the cache, which is not even required.

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
    """Run the scan pipeline on the submitted email. Raises BadRequest unless there is one.

    The cache is asked first. On a hit the stored result is used and the engine does
    not run; otherwise the engine runs and its result is stored. Either way the scan
    is saved to the history, marked with whether it came from the cache.

    analysis_ms in the log line is what the cache is there to save: the time spent in
    the engine on a miss, and in the cache lookup on a hit.
    """
    filename, raw = _submitted_email()
    digest = cache.content_hash(raw)
    started = time.perf_counter()
    cached = cache.lookup(digest)
    if cached.value is not None:
        record = _record_from_cache(cached.value, filename)
        result = _stored_result(record)
    else:
        started = time.perf_counter()
        result, record = _analyse(raw, filename)
        cache.store(digest, _cache_value(record))
    analysis_ms = round(_milliseconds_since(started), ANALYSIS_MS_DECIMALS)

    g.log_fields |= {
        "verdict": result.verdict,
        "score": result.score,
        "filename": filename,
        "cache": cached.status.value,
        "analysis_ms": analysis_ms,
    }
    if cached.seen is not None:
        g.log_fields["seen"] = cached.seen
    return ScanOutcome(result, record, _save(record), cached.seen)


def _submitted_email() -> tuple[str, bytes]:
    """Return the file name and bytes of the email to scan: an uploaded file, or pasted text.

    Exactly one of the two. A file input with no file chosen, and a paste that is empty
    or only whitespace, count as not given. Raises BadRequest for neither and for both.
    Pasted text is encoded as UTF-8, and from then on is scanned exactly like a file.
    MAX_CONTENT_LENGTH covers both: a request over it is refused with 413 before this runs.
    """
    upload = request.files.get(UPLOAD_FIELD)
    pasted = request.form.get(PASTE_FIELD, "")
    has_file = upload is not None and bool(upload.filename)
    has_paste = bool(pasted.strip())
    if has_file == has_paste:
        raise BadRequest()
    if has_file:
        return upload.filename, upload.read()
    return PASTED_FILENAME, pasted.encode("utf-8")


def _analyse(raw: bytes, filename: str) -> tuple[Result, db.ScanRecord]:
    """Run the engine on the upload, and build the record of the scan to save."""
    result = analyze(raw)
    email = parse_email(raw)
    record = db.ScanRecord(
        filename=filename,
        sender=email.from_header or None,
        subject=email.subject or None,
        score=result.score,
        verdict=result.verdict,
        decided_by=result.decided_by,
        findings=result.findings,
        served_by=config.get_settings().instance_id,
    )
    return result, record


def _cache_value(record: db.ScanRecord) -> dict[str, Any]:
    """Return what the cache keeps for a scan: what the history keeps, less the request's own.

    The file name and the instance that served the scan belong to each request, so they
    are never taken from the cache. Neither are the email's body or attachments: they
    are not in the record at all.
    """
    return {
        "score": record.score,
        "verdict": record.verdict,
        "decided_by": record.decided_by,
        "findings": [asdict(found) for found in record.findings],
        "sender": record.sender,
        "subject": record.subject,
    }


def _record_from_cache(value: dict[str, Any], filename: str) -> db.ScanRecord:
    """Build the record of a scan answered from the cache. The value has been checked."""
    return db.ScanRecord(
        filename=filename,
        sender=value["sender"],
        subject=value["subject"],
        score=value["score"],
        verdict=value["verdict"],
        decided_by=value["decided_by"],
        findings=[Finding(**item) for item in value["findings"]],
        served_by=config.get_settings().instance_id,
        cache_hit=True,
    )


def _result_page(outcome: ScanOutcome) -> str:
    """Render result.html, for a scan just made or for one read back from the history.

    scan_id is None when a new scan could not be saved. Only a record read back from
    the history has a created_at, and that is what tells the template which of the two
    pages it is drawing. seen is passed on only from MIN_SIGHTINGS_SHOWN up, and
    first_sighting says the count is known and is one; with neither, it is not known.
    The rest is worked out here so the template only displays it: the findings per
    severity, a block per category, and the points of all categories together.
    """
    record = outcome.record
    result = outcome.result
    seen = outcome.seen
    return render_template(
        "result.html",
        result=result,
        filename=record.filename,
        sender=record.sender or "",
        subject=record.subject or "",
        served_by=record.served_by,
        saved=outcome.scan_id is not None,
        scan_id=outcome.scan_id,
        scanned_at=record.created_at,
        cache_hit=record.cache_hit,
        seen=seen if seen is not None and seen >= MIN_SIGHTINGS_SHOWN else None,
        first_sighting=seen == 1,
        severity_counts=_severity_counts(result.findings),
        categories=_categories(result),
        points_total=sum(result.category_scores.values()),
    )


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    """Count the findings per severity, most severe first, leaving out severities with none."""
    counts = Counter(found.severity for found in findings)
    return {severity: counts[severity] for severity in SEVERITY_WEIGHT if counts[severity]}


def _categories(result: Result) -> list[CategoryView]:
    """Return a block for every category, in the engine's order, with or without findings.

    A category the list does not know is shown after the others rather than lost.
    """
    found_in = dict.fromkeys(found.category for found in result.findings)
    names = [*CATEGORIES, *(name for name in found_in if name not in CATEGORIES)]
    return [
        CategoryView(
            name=name,
            findings=[found for found in result.findings if found.category == name],
            points=result.category_scores.get(name, 0),
        )
        for name in names
    ]


def _sender_view(sender: str | None) -> SenderView:
    """Split a raw From header into its name and address, for the history table.

    A header that does not parse is shown whole, as the name: it is still what the email
    claimed, and the page must not hide it.
    """
    if not sender:
        return SenderView(name="", address="")
    name, address = parseaddr(sender)
    if not address:
        return SenderView(name=sender, address="")
    return SenderView(name=name, address=address)


def _stored_result(record: db.ScanRecord) -> Result:
    """Rebuild the engine's Result from a stored scan, without running the engine again.

    Stored means in the history, or in the cache: a scan answered from the cache is
    rebuilt here too, from a record made of the cached value.

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


def _milliseconds_since(started: float) -> float:
    return (time.perf_counter() - started) * MILLISECONDS_PER_SECOND


def _start_request_log() -> None:
    g.request_started = time.perf_counter()
    g.log_fields = {}


def _finish_request_log(response: Response) -> Response:
    """Log one line for the request, once the response is ready."""
    duration_ms = round(_milliseconds_since(g.get("request_started", time.perf_counter())))
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
    """Answer with a friendly error: a page, or JSON for the API.

    An error page marks no navigation link as current, whatever route it came from.
    """
    message = _error_message(status)
    if request.path.startswith(API_PREFIX):
        return jsonify(error=message), status
    g.error_page = True
    page = render_template("error.html", status=status, title=_error_title(status), message=message)
    return page, status


def _error_title(status: int) -> str:
    if status in ERROR_TITLES:
        return ERROR_TITLES[status]
    if status < SERVER_ERROR:
        return CLIENT_ERROR_TITLE
    return ERROR_TITLES[SERVER_ERROR]


def _navigation() -> dict[str, str | None]:
    """Give every template nav_section: which navigation link is the current page, if any."""
    if g.get("error_page"):
        return {"nav_section": None}
    return {"nav_section": NAV_SECTIONS.get(request.endpoint or "")}


def _error_message(status: int) -> str:
    if status in ERROR_MESSAGES:
        return ERROR_MESSAGES[status].format(max_mb=_max_upload_megabytes())
    if status < SERVER_ERROR:
        return CLIENT_ERROR_MESSAGE
    return SERVER_ERROR_MESSAGE


if __name__ == "__main__":
    create_app().run(host=DEVELOPMENT_HOST, port=DEVELOPMENT_PORT, debug=False)
