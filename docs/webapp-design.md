# Web application — design specification

The web layer that wraps the detection engine: a small Flask application serving both the user
interface and a JSON API, backed by PostgreSQL for scan history.

This document covers phase 2 — everything runs locally against a PostgreSQL container. The same code
runs unchanged on EC2 against RDS; the only difference is where the configuration comes from.

Read `docs/code-standards.md` first. It applies here as it does to the engine.

---

## 1. Scope and boundaries

```
app/
├── detector/          the engine (done — do not modify)
├── config.py          configuration, local and cloud
├── db.py              PostgreSQL access
├── web.py             Flask routes
├── logging_setup.py   structured JSON logging
├── templates/         base.html + upload, result, history, error
├── static/            style.css
└── requirements.txt
docker-compose.yml     local PostgreSQL only
```

The engine stays a pure function. Nothing in `app/detector/` changes in this phase, and nothing in the
engine learns about Flask, the database or the environment. The web layer calls `analyze(raw_bytes)`
and does something with the result; that is the whole relationship.

All I/O lives here: HTTP, the database, Secrets Manager, the filesystem.

---

## 2. Dependencies

Add to `app/requirements.txt`, pinned:

- `flask` — the web framework.
- `psycopg[binary]` — PostgreSQL driver, version 3. The `[binary]` extra ships a compiled wheel, so
  there is no build step on either Windows or Amazon Linux.
- `boto3` — needed to read the database password from Secrets Manager at runtime.
- `gunicorn` — the production WSGI server, used on EC2.

Note on `gunicorn`: it installs on Windows but cannot run there, because it depends on Unix process
APIs. Locally the application runs under Flask's development server. If the install itself fails on
your machine, move `gunicorn` to a separate line in `user_data` instead and leave it out of
`requirements.txt`.

---

## 3. Configuration (`config.py`)

One module reads everything from environment variables. No module anywhere else calls `os.environ`.

| Variable | Local | On EC2 |
|---|---|---|
| `DB_HOST` | `localhost` | the RDS endpoint |
| `DB_PORT` | `5432` | `5432` |
| `DB_NAME` | `phishing` | `phishing` |
| `DB_USER` | `phishing` | the RDS master user |
| `DB_PASSWORD` | from `.env` | **not set** |
| `DB_SECRET_ARN` | not set | the Secrets Manager ARN |
| `DB_SSLMODE` | not set (`prefer`) | `require` |
| `LOG_FILE` | not set (logs to stdout) | `/var/log/phishing-app/app.log` |
| `MAX_UPLOAD_BYTES` | `5242880` | `5242880` |
| `INSTANCE_ID` | not set (the hostname is used) | the EC2 instance ID, e.g. `i-0123456789abcdef0` |
| `APP_RELEASE` | not set (`local`) | the release ID, e.g. `3f9a1c2b7d10` |
| `CACHE_HOST` | not set (the cache is off), or `localhost` | the cache's primary endpoint |
| `CACHE_PORT` | `6379` | `6379` |
| `CACHE_PASSWORD` | from `.env` | **not set** |
| `CACHE_SECRET_ARN` | not set | the ARN of the secret holding the cache's AUTH token |
| `CACHE_TTL_SECONDS` | `86400` | `86400` |
| `CACHE_TLS` | `false` for the local container | `true` (the default) |

The cache settings come from `docs/bonus-cache-design.md`. The cache is off unless `CACHE_HOST` is
set. Its token is fetched like the database password, but lazily, on the first scan that uses the
cache, and with tighter limits; it is not rotated, so it is never re-read.

`APP_RELEASE` names the build of the code that is running: the first 12 hex characters of the release
zip's hash, written into the environment file by `user_data`. It is reported as `release` in `/health`
and in every log line, which is how a deployment is shown to be working: during an instance refresh,
repeated requests show the old release, then a mix, then only the new one.

`DB_SSLMODE` is passed to the driver as `sslmode`. Locally it is `prefer`, because the container has no
certificate. On EC2 it is `require`: the connection to RDS is encrypted or it is not made. A value that
is not one of libpq's modes is a configuration error at startup.

`INSTANCE_ID` identifies the instance everywhere: as `served_by`, as `host` in `/health`, and as `host`
in every log line.
`user_data` reads it from the instance metadata service (IMDSv2) at boot and writes it into the
environment file, so the application itself makes no AWS call to learn it. When it is unset, which is
the case locally, `config.py` falls back to `socket.gethostname()`.

The password is resolved by exactly one function:

```python
def get_db_password() -> str:
    """Return the database password.

    Locally it comes from DB_PASSWORD. On EC2 that variable is not set, and the
    password is fetched from Secrets Manager using the instance role. The value
    is cached, and refresh_db_password() clears the cache so a rotated password
    is picked up without a redeploy.
    """
```

Two rules that matter:

- **The password is never written to disk on the server.** `user_data` writes the secret's ARN into the
  environment file, never the secret itself. Anyone who reads the file on the instance learns only
  where the password lives, not what it is.
- **RDS rotates the password automatically.** When a connection fails with an authentication error,
  `db.py` calls `refresh_db_password()` and retries once. Without this, a rotation would silently break
  the application until the next deployment.

Locally, `.env` holds `DB_PASSWORD` and is already in `.gitignore`. Load it with a three-line reader in
`config.py` rather than adding `python-dotenv`: it is one dependency saved for a trivial amount of code.

---

## 4. Database (`db.py`)

Raw SQL throughout. No ORM: the schema is one table and three queries, and an ORM would add a
dependency, a migration tool and a layer of indirection for no benefit at this size.

### Schema

```sql
CREATE TABLE IF NOT EXISTS scans (
    id          SERIAL PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    filename    TEXT        NOT NULL,
    sender      TEXT,
    subject     TEXT,
    score       INTEGER     NOT NULL,
    verdict     TEXT        NOT NULL,
    decided_by  TEXT,
    findings    JSONB       NOT NULL,
    served_by   TEXT        NOT NULL
);

CREATE INDEX IF NOT EXISTS scans_created_at_idx ON scans (created_at DESC);
```

`findings` is `JSONB` rather than a second table. The findings are read back as a unit and never
queried field by field, so a related table would be structure without purpose. `JSONB` also leaves the
door open to querying inside it later.

`served_by` is the identifier of the instance that handled the request: its EC2 instance ID, from
`INSTANCE_ID` (see section 3). This column exists for one reason: it is how the load balancer is shown
to be working. Refreshing the history page after several scans shows both instance IDs, which is more
convincing than any diagram.

It is deliberately not the hostname. On EC2 the hostname is derived from the private IP address
(`ip-10-0-21-44`), and internal addresses must not appear in a response; see "Security requirements"
in section 5.

### Schema initialisation and the race between instances

Both EC2 instances start at the same time and both run `CREATE TABLE IF NOT EXISTS` within milliseconds
of each other. In PostgreSQL that is not safe: `IF NOT EXISTS` checks and creates in two steps, and two
sessions can both pass the check, after which one fails with a unique violation on an internal catalogue
table.

Take a transaction-scoped PostgreSQL advisory lock around initialisation:

```python
INIT_LOCK_ID = 4815162342   # arbitrary but fixed; any constant works

with psycopg.connect(...) as conn:          # commits when the block ends
    conn.execute("SELECT pg_advisory_xact_lock(%s)", (INIT_LOCK_ID,))
    conn.execute(CREATE_TABLE_SQL)
    conn.execute(CREATE_INDEX_SQL)
# the commit releases the lock
```

The second instance waits a few milliseconds, finds the table already there, and moves on. One lock and
one constant, instead of catching an exception whose exact type depends on the PostgreSQL version.

The lock must be held until the transaction commits. A session lock released with
`pg_advisory_unlock` is released *before* the commit, so the second instance can take it while the
first one's table is still uncommitted, miss it, and fail creating it again. Raced with eight threads
over twenty rounds, the session-lock version failed in every round and the transaction-scoped one in
none; `test_instances_starting_at_once_all_initialise_the_schema` keeps it that way.

Startup tries `init_schema()` once, and must survive it failing: an instance has to start, and answer
`/health`, while the database is unreachable. A failure is logged as an `ERROR` with the event
`schema_init_failed` and nothing more. The schema is then created lazily, on the process's first
database call that gets through; a module-level flag records that it is there.

### Connections

One connection per request, opened and closed around the work. No pool.

At this traffic level — a handful of scans in a demo — a pool is optimisation without a problem, and it
introduces connections that can go stale across an RDS failover. The trade-off is recorded in the README,
and `psycopg_pool` is a two-line change if load ever justified it.

Set a short connect timeout (`connect_timeout=3`). The default waits long enough that a database
problem looks like a hung page. A circuit breaker backs it (`docs/drills-phase8-design.md`,
section 2): after a failed connection each process refuses database calls at once for 15 seconds,
then lets one attempt through, so a database that is down cannot tie up both workers.

### Operations

```python
def init_schema() -> None
def save_scan(record: ScanRecord) -> int          # returns the new row id
def recent_scans(limit: int = 50) -> list[ScanRecord]
def db_is_reachable() -> bool                     # for diagnostics only, never for /health
```

### Behaviour when the database is unavailable

**A failed save must not lose the scan result.** The analysis already succeeded; the user should see it.

1. `save_scan` raises; `web.py` catches it.
2. The result page renders normally, with a visible notice that the scan could not be saved.
3. An `ERROR` line goes to the log with the exception type.
4. The HTTP status stays 200, because the analysis the user asked for did succeed.
5. `/history` returns 503 with a friendly page, because that page genuinely cannot work.

---

## 5. Web application (`web.py`)

### Routes

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Upload form |
| POST | `/scan` | Analyze an uploaded file or a pasted email, save it, render the result |
| GET | `/history` | The most recent scans |
| GET | `/scans/<id>` | One stored scan in full; 404 for an unknown id |
| POST | `/api/scan` | Same as `/scan`, returns JSON |
| GET | `/health` | Load balancer health check |
| GET | `/simulate-error` | Returns 500 on purpose |

### Application factory

`web.py` builds the application in a factory, `create_app()`, and defines no module-level `app`
object. Configuration and logging are therefore set up when a server asks for the application, not as
a side effect of importing the module, and each test builds a fresh application from its own settings.

The servers name the factory rather than a variable:

```bash
gunicorn --bind 0.0.0.0:8000 'app.web:create_app()'    # on EC2, from the directory holding app/
flask --app app.web run --port 8000                    # locally; Flask finds create_app() itself
```

The quotes around `'app.web:create_app()'` matter: without them the shell reads the parentheses.

### `/health` — shallow, by design

```python
@pages.get("/health")
def health():
    """Liveness only. Deliberately does not touch the database."""
    settings = config.get_settings()
    return {"status": "ok", "host": settings.instance_id, "release": settings.release}, 200
```

This is the most consequential decision in the file, and it will be asked about.

If the health check queried the database, an RDS problem would mark **both** instances unhealthy at the
same moment. Three things would follow: the ALB would have no healthy targets and would fail open or
return 503; the Auto Scaling Group, configured with ELB health checks, would start terminating and
replacing instances; and every replacement would also fail its health check, producing a replacement
loop that outlives the original database problem.

So a database outage must degrade the service, not destroy it. With a shallow check the instances stay
in service, `/scan` still shows its result with a notice that it was not saved, `/history` returns 503,
and the alarms fire on 5XX and on the RDS metrics — which is where a database problem should be visible.

The cost is that `/health` reports less than the whole truth. That is the right trade: the ALB needs to
know whether this process can serve traffic, and the database is monitored on its own.

### `/scan`

1. Reject a missing file with 400.
2. `MAX_CONTENT_LENGTH` is set from config, so Flask rejects oversized uploads before reading them.
3. Read the bytes into memory. **Never write an uploaded file to disk** — there is no reason to, and a
   file that exists is a file something might open.
4. Call `analyze(raw)`.
5. Build a `ScanRecord` and save it, with the failure behaviour above.
6. Render `result.html`.

### `/api/scan`

Same pipeline, returning JSON: `score`, `verdict`, `decided_by`, `findings`, `served_by`, `scan_id`.
Errors return JSON too, never an HTML page — the Gmail add-on bonus, if it is built, calls this route.

### `/simulate-error`

```python
@app.get("/simulate-error")
def simulate_error():
    """Deliberate 500, used to demonstrate the 5XX alarm during the review."""
    raise RuntimeError("Simulated failure for alarm demonstration")
```

Keep it. It is how the CloudWatch alarm and the SNS email get demonstrated in under a minute, without
breaking anything real.

### Security requirements

These are checked in phase 7, so build them in now:

- Jinja2 autoescaping stays on, and **no `|safe` anywhere**. Everything rendered — sender, subject,
  evidence strings — comes from an attacker-controlled email. This is the clearest stored-XSS path in
  the whole application.
- `MAX_CONTENT_LENGTH` is enforced.
- The uploaded filename is never used as a filesystem path. Display it escaped; do not join it to a
  directory.
- No internal IP addresses, no secrets and no stack traces in any user-facing response. `debug=False`
  always. This rules out the EC2 hostname, which is derived from the private IP address
  (`ip-10-0-21-44`), and it rules out database errors, whose messages name the RDS endpoint.
- The instance identifier *is* shown, on purpose: as `served_by` on the result and history pages and
  in the API, and as `host` in `/health`. It is what demonstrates the load balancer spreading requests
  across both instances. An instance ID such as `i-0123456789abcdef0` is not secret: it names the
  instance to AWS, but it carries no network address and grants no access on its own.
  `test_no_response_reveals_the_hostname` checks every route for the hostname.

---

## 6. Logging (`logging_setup.py`)

One JSON object per line, so that CloudWatch Logs Insights can filter by field rather than parse text.

```json
{"ts":"2026-11-12T18:04:11Z","level":"INFO","host":"i-0123456789abcdef0",
 "release":"3f9a1c2b7d10","event":"scan","path":"/scan","status":200,"duration_ms":38,
 "verdict":"Phishing","score":100,"filename":"invoice.eml"}
```

- Required on every line: `ts`, `level`, `host`, `release`, `event`.
- `release` is the build of the code that wrote the line, from `APP_RELEASE` (section 3): the same value
  `/health` reports.
- `host` is the instance identifier from `INSTANCE_ID` (section 3): the EC2 instance ID on a server,
  the hostname locally. It is the same value users see as `served_by` and that `/health` reports as
  `host`, so a scan in the history page leads straight to the log lines of the instance that ran it.
  It is also the name of the log stream: the CloudWatch agent should be configured with
  `log_stream_name` set to `{instance_id}`, so the stream, the field and `served_by` all agree.
- One line per request, emitted after the response, including `path`, `status` and `duration_ms`.
- Errors add `error_type` and `error_message`; an unexpected error, the kind that becomes a 500, also
  adds its `traceback`. **Never log the email body, an attachment, or the database password.**
  A database error's message is the driver's own text, on one line and cut to 300 characters, with the
  password blanked out of it should a driver ever quote one.
- `LOG_FILE` unset means log to stdout, which is what you want locally. Set, it means log to that file,
  which is what the CloudWatch agent reads on the instance.

The fields are what make the monitoring questions answerable later: counting verdicts by type, finding
every 5XX in a window, or seeing which instance served what.

---

## 7. Templates and styling

Plain HTML and one stylesheet. No framework, no build step, no CDN.

The interface built in this phase is deliberately plain — it has to be correct, not pretty. It is
expected to be redesigned near the end of the project, and the structure below exists so that the
redesign touches markup and CSS only, never Python.

### 7.1 Template inheritance

`base.html` holds everything shared: the `<head>`, the stylesheet link, the header with navigation, and
the footer. It defines two blocks:

```html
{% block title %}{% endblock %}
{% block content %}{% endblock %}
```

All four pages extend it and fill in `content`. Nothing else may contain a `<head>`, a `<nav>` or a
`<footer>`.

**The test of this structure:** restyling the whole application should mean editing `base.html` and
`style.css`, and nothing else. If a redesign requires touching all four page templates, the shared
structure has leaked out of `base.html` and belongs back in it.

### 7.2 The template contract

Every template begins with a Jinja comment listing exactly what it receives, so the data available to a
page can be read without opening `web.py`:

| Template | Receives |
|---|---|
| `base.html` | `nav_section: str \| None`, on every page, from the web layer's context processor |
| `upload.html` | `max_mb: int` |
| `result.html` | `result: Result`, `filename: str`, `sender: str`, `subject: str`, `served_by: str`, `saved: bool`, `scan_id: int \| None`, `scanned_at: datetime \| None`, `cache_hit: bool`, `seen: int \| None`, `first_sighting: bool`, `severity_counts: dict[str, int]`, `categories: list[CategoryView]`, `points_total: int` |
| `history.html` | `scans: list[ScanRecord]` (each with `cache_hit`), `senders: dict[int, SenderView]` |
| `error.html` | `status: int`, `title: str`, `message: str` |

**What the design needs is worked out in the web layer, never in a template.** The result page's
verdict card summarises the findings per severity (`severity_counts`: most severe first, none at
zero), the findings section shows a block for every category, with or without findings
(`categories`, each a `CategoryView` of name, findings and points, in the engine's order), and its
heading gives the points of all categories together (`points_total`). The Seen card shows the count
from 2 up, "New" when `first_sighting`, and "Count not available" otherwise: on a stored scan, or
when the cache is off or down. The history splits each From header into the display name and the
address (`senders`, keyed by scan id; a header that does not parse is shown whole). Error pages
carry a short `title` as well as the message. `nav_section` marks the current navigation link:
Scan for `/` and a fresh result, History for `/history` and `/scans/<id>`, none on error pages.

**The product is called Fish Scan.** Every page's title is "<page> · Fish Scan", or "Fish Scan"
when the title block is empty; the header shows the logo (`static/img/fishscan-logo.svg`) linking
to the Scan page, and the favicon is its tile alone (`static/img/favicon.svg`).

**The Scan page has two forms, both posting to `/scan`:** a file (`file`) and the raw email pasted
as text (`raw_email`). `/scan` takes exactly one: neither or both is a 400. Pasted text is encoded as
UTF-8 and scanned exactly like a file, and the history calls it `pasted-email.txt`. Both forms are
`multipart/form-data`, so pasted text is not percent-encoded on the way, and `MAX_CONTENT_LENGTH`
applies to both; `MAX_FORM_MEMORY_SIZE` is set to the same value, because Werkzeug would otherwise
refuse a text field over 500 KB.

A redesign that keeps this contract is a pure markup change. Keep the table in this document in step
with the code.

**`result.html` draws two pages, and `scanned_at` tells them apart.** It is `None` for a scan just
made (`POST /scan`), and the time the scan was made, in UTC, on the detail page of a stored scan
(`GET /scans/<id>`). When it is set, the page shows "Scanned at" and ends with "Back to history"
instead of "Scan another email". The detail page is built from the stored row, without running the
engine again: the web layer rebuilds the `Result`, so the template receives the same variables either
way and there is no second result template to keep in step.

**`cache_hit` and `seen` come from the result cache.** `cache_hit` is true when the result was
reused from the cache rather than analysed; the page then says "Served from cache — scanned before,
result reused.", on the result page and on the detail page of such a scan alike. `seen` is how many
times this exact email was scanned in the last 24 hours, this scan included. The web layer passes it
only when it is 2 or more, and never on the detail page, where it is not known; the Seen card then
shows "N×". In the history, a scan served from the cache is marked `cached` in its own column.

**Fonts, scripts and styles must be files under `static/`: nothing loaded from a CDN, no inline
`<script>`, no `<style>` block, no `style=""` attribute.** The design keeps to it: `static/style.css`,
the Manrope fonts in `static/fonts/` with their licence, and the images in `static/img/`, all
referred to with `url_for('static', ...)`; inside the stylesheet, `url()` paths are relative to the
stylesheet itself. `tests/test_design.py` renders every page in every state and fails on any
script, style, inline event handler or address on another origin. Every response carries a content security
policy that allows only this origin's own files (`default-src 'self'`, added in phase 7), so the
browser refuses anything else, and a redesign that breaks this rule produces a page the browser
silently declines to style or run.

### 7.3 Class names describe meaning, not appearance

`.verdict-phishing`, `.finding-critical`, `.notice-warning` — never `.red-box` or `.big-text`. Colours
and spacing then live entirely in the stylesheet, and changing the palette never requires editing a
template.

### 7.4 Assets are self-hosted

No CDN links, no remote fonts, no external scripts. Every page must render with no outbound request
beyond the application itself.

The browser would in fact be able to reach a CDN — the user's machine has internet even though the
instances do not. The reasons are different: a page that pulls resources from a third party is exactly
the pattern this project is built to be suspicious of, and a reviewer on a restricted network would see
a broken layout.

### 7.5 The pages

The pages follow the approved design (a dark bento layout, delivered as static HTML and kept out of
git in `design-handoff/`).

- **`upload.html`** — the Scan page: a drop zone for a file, a form to paste the raw email, the
  "how scans are handled" facts, and the hero slot, an empty block kept for an animation, hidden
  from assistive technology. States the accepted formats and the size limit.
- **`result.html`** — the verdict large and colour-coded with a summary per severity, the score and
  `decided_by`, the Seen count, `served_by`, the sender and subject, and a block per category with
  its points and findings. Each finding shows its severity, points, reason and evidence. Also the
  detail page of a stored scan, with the time it was scanned.
- **`history.html`** — a table: time, filename, sender, verdict, score, `served_by` and whether the
  result came from the cache. Most recent first. The whole row links to that scan's detail page.
- **`error.html`** — the status code large, a short title and a friendly message. No stack traces.

**Keep `served_by` visible on both the result and the history pages, through any redesign.** It looks
like an unimportant technical detail, and it is the only thing in the interface that demonstrates the
load balancer distributing traffic across both instances.

---

## 8. Local PostgreSQL (`docker-compose.yml`)

```yaml
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_DB: phishing
      POSTGRES_USER: phishing
      POSTGRES_PASSWORD: localdev
    ports:
      - "127.0.0.1:5432:5432"
      - "[::1]:5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U phishing -d phishing"]
      interval: 2s
      timeout: 5s
      retries: 15

volumes:
  pgdata:
```

`localdev` is a local-only password for a container bound to localhost, and it never reaches AWS. Say so
in a comment, so that nobody reading the repository mistakes it for a leaked credential.

The port is published on the loopback addresses only. A bare `"5432:5432"` publishes it on every
interface, which would put a database with a well-known password on the local network. Both loopback
addresses are needed: `localhost` resolves to `::1` first, and with only the IPv4 binding each
connection on Windows waited out the full 5-second connect timeout on `::1` before trying `127.0.0.1`.

`docker compose up -d --wait` starts it and returns once the health check passes;
`docker compose down` stops it.

---

## 9. Tests

Add to `tests/`:

- **Routes**, using Flask's test client: `/` returns 200; `/scan` with a phishing sample returns 200 and
  the word "Phishing"; `/scan` with no file returns 400; `/health` returns 200.
- **`/health` does not touch the database.** Patch `db` so that any call raises, then assert `/health`
  still returns 200. This test exists to stop someone "improving" the health check later.
- **Database failure is survivable.** Patch `save_scan` to raise, then assert `/scan` still returns 200
  and the page contains the warning.
- **No `|safe` in any template.** A test that reads the template files and asserts the string is absent.
  Crude, and it will keep an XSS hole from being reintroduced.
- **Every page extends `base.html`.** A test asserting that each of the four templates contains
  `{% extends "base.html" %}` and that none of them contains `<head>`. This is what keeps the redesign
  cheap.
- **`/api/scan`** returns the expected JSON keys.
- **Database tests** run against the local container and are marked `@pytest.mark.integration`, so that
  `pytest -m "not integration"` works with nothing running.

---

## 10. Optional: history as a detection signal

The assignment lists "History Of Actions" among the indicators to detect. The straightforward reading is
scan history, which is what section 4 provides. A second reading is that history should itself be a
signal — and that reading is cheap to implement and makes the database part of detection rather than
only storage.

Implement it in the **application layer**, after `analyze()` returns, so that the engine stays pure:

```python
def history_signal(sender_domain: str) -> Finding | None:
    """Flag a sender domain already seen in earlier phishing verdicts.

    Lives here and not in the engine: it needs the database, and the engine
    makes no I/O calls.
    """
```

One query — how many earlier scans from this sender domain were classified Phishing — and if the count
is non-zero, append a `medium` finding with code `seen_before`, then recompute the result through
`build_result`. Show the count in the evidence.

Mark it clearly in the README as the second reading of an ambiguous requirement, with both
interpretations named. Skip it if time is short; the first reading already satisfies the requirement.

---

## 11. Out of scope

- **User accounts and sessions.** Nothing in the assignment asks for them, and they would bring password
  storage, session cookies and CSRF into a project that currently has no such surface.
- **An ORM and migrations.** One table.
- **A connection pool.** See section 4.
- **A JavaScript framework.** Four pages of static HTML.
- **File storage.** Uploads are processed in memory and discarded.
