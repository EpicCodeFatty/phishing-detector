"""Tests for the pages as the design draws them, and for what the content security policy allows.

Every response carries `default-src 'self'`, so a page that used an inline script, an inline
style or anything from another origin would render broken, silently. These render every page
in every state and read them with an HTML parser, so text that merely looks like markup, such
as an escaped tag quoted from a hostile email, is not mistaken for it.
"""

import re
from fnmatch import fnmatch
from html.parser import HTMLParser
from pathlib import Path

import pytest
from flask.testing import FlaskClient

from app import db, web
from app.detector import analyze
from app.detector.models import Finding, finding
from app.detector.scoring import build_result
from tests.builders import SAMPLES, browser_upload, sample_upload, upload_of
from tests.conftest import FakeHistory

APP_DIRECTORY = Path(web.__file__).parent
STATIC = APP_DIRECTORY / "static"
STYLESHEET = STATIC / "style.css"
ARTIFACT_TF = APP_DIRECTORY.parent / "infra" / "app" / "artifact.tf"
XSS_FIXTURE = Path(__file__).parent / "fixtures" / "xss-subject.eml"
HOSTILE_FILENAME = '"><img src=x onerror=alert(1)>.eml'

# Attributes whose value the browser fetches, follows or submits to.
URL_ATTRIBUTES = {"href", "src", "srcset", "action", "formaction", "poster", "data", "xlink:href"}
# A value that leaves this origin, or runs or embeds content of its own.
FOREIGN_URL = re.compile(r"^\s*(?:[a-z][a-z0-9+.-]*:|//)", re.IGNORECASE)


class PageAudit(HTMLParser):
    """Collects everything on a page that the content security policy would refuse."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.problems: list[str] = []
        self.images: list[dict[str, str | None]] = []
        self.links: list[dict[str, str | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style"):
            self.problems.append(f"<{tag}>")
        for name, value in attrs:
            if name == "style":
                self.problems.append(f'style="" on <{tag}>')
            if name.startswith("on"):
                self.problems.append(f"{name}= on <{tag}>")
            if name in URL_ATTRIBUTES and value and FOREIGN_URL.match(value):
                self.problems.append(f'{name}="{value}" on <{tag}>')
        if tag == "img":
            self.images.append(dict(attrs))
        if tag == "link":
            self.links.append(dict(attrs))


def audit(page: str) -> PageAudit:
    parser = PageAudit()
    parser.feed(page)
    parser.close()
    return parser


def text(response) -> str:
    return response.get_data(as_text=True)


# ------------------------------------------------------------------ Every page, every state


def render_every_page(client: FlaskClient, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Return every page in every state the templates draw, by name."""
    pages = {"scan": text(client.get("/"))}
    pages["history, empty"] = text(client.get("/history"))
    pages["result with findings"] = text(
        client.post("/scan", data=sample_upload("paypal-phish.eml"))
    )
    pages["result, cached"] = text(client.post("/scan", data=sample_upload("paypal-phish.eml")))
    pages["result, safe and no findings"] = text(
        client.post("/scan", data=upload_of(b"Lunch at noon?", "lunch.txt"))
    )
    pages["result, hostile email"] = text(
        client.post("/scan", **browser_upload(XSS_FIXTURE.read_bytes(), HOSTILE_FILENAME))
    )
    pages["result, opened from history"] = text(client.get("/scans/1"))
    pages["history, with rows"] = text(client.get("/history"))
    pages["error 400"] = text(client.post("/scan", data={}))
    pages["error 404"] = text(client.get("/no-such-page"))
    pages["error 405"] = text(client.get("/scan"))
    pages["error 413"] = text(client.post("/scan", data=upload_of(b"x" * (6 * 1024 * 1024), "a")))
    pages["error 500"] = text(client.get("/simulate-error"))
    with monkeypatch.context() as patch:
        patch.setattr(db, "save_scan", _unavailable)
        patch.setattr(db, "recent_scans", _unavailable)
        pages["result, not saved"] = text(
            client.post("/scan", data=sample_upload("team-lunch.eml"))
        )
        pages["error 503"] = text(client.get("/history"))
    return pages


def _unavailable(*args, **kwargs):
    raise db.StorageError("OperationalError: connection refused")


@pytest.fixture
def every_page(valkey, error_simulation, client, monkeypatch) -> dict[str, str]:
    return render_every_page(client, monkeypatch)


def test_no_page_has_a_script_a_style_or_anything_from_another_origin(every_page):
    problems = {name: audit(page).problems for name, page in every_page.items()}

    assert {name: found for name, found in problems.items() if found} == {}


def test_every_state_was_rendered(every_page):
    # The audit above proves nothing about a state that was never drawn.
    assert "Served from cache" in every_page["result, cached"]
    assert "could not be saved" in every_page["result, not saved"]
    assert "Scanned at" in every_page["result, opened from history"]
    assert "No scans yet." in every_page["history, empty"]
    assert 'class="row-link"' in every_page["history, with rows"]
    assert "Nothing found in this category." in every_page["result, safe and no findings"]
    for status in (400, 404, 405, 413, 500, 503):
        assert (
            f'<span class="visually-hidden">Error </span>{status}' in every_page[f"error {status}"]
        )


def test_hostile_markup_from_an_email_is_text_not_tags(every_page):
    page = every_page["result, hostile email"]

    images = audit(page).images

    assert [image["src"] for image in images] == ["/static/img/fishscan-logo.svg"]
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


@pytest.mark.parametrize(
    "name", ["base.html", "upload.html", "result.html", "history.html", "error.html"]
)
def test_no_template_has_a_script_a_style_or_anything_from_another_origin(name):
    source = (APP_DIRECTORY / "templates" / name).read_text(encoding="utf-8")

    assert audit(source).problems == []


# ---------------------------------------------------------------------- The frame


def test_every_page_carries_the_logo_linking_to_the_scan_page(every_page):
    for page in every_page.values():
        assert (
            '<a class="wordmark" href="/"><img src="/static/img/fishscan-logo.svg" '
            'alt="Fish Scan" width="143" height="32"></a>'
        ) in page


def test_every_page_links_the_svg_favicon(every_page):
    for page in every_page.values():
        icons = [link for link in audit(page).links if link.get("rel") == "icon"]
        assert icons == [
            {"rel": "icon", "type": "image/svg+xml", "href": "/static/img/favicon.svg"}
        ]


@pytest.mark.parametrize(
    "name,title",
    [
        ("scan", "Scan an email · Fish Scan"),
        ("history, with rows", "Scan history · Fish Scan"),
        ("result with findings", "Scan — paypal-phish.eml · Fish Scan"),
        ("error 404", "Page not found · Fish Scan"),
        ("error 503", "History unavailable · Fish Scan"),
    ],
)
def test_page_titles_name_the_page_then_the_product(every_page, name, title):
    assert f"<title>{title}</title>" in every_page[name]


def test_the_product_is_called_fish_scan_everywhere_on_the_pages(every_page):
    for page in every_page.values():
        assert "Phishing Detector" not in page


@pytest.mark.parametrize(
    "name,current",
    [
        ("scan", "Scan"),
        ("result with findings", "Scan"),
        ("history, with rows", "History"),
        ("result, opened from history", "History"),
        ("error 404", None),
        ("error 413", None),
        ("error 503", None),
    ],
)
def test_the_navigation_marks_the_current_section_and_none_on_error_pages(
    every_page, name, current
):
    marked = re.findall(r'aria-current="page">(\w+)</a>', every_page[name])

    assert marked == ([current] if current else [])


def test_the_hero_animation_is_hidden_from_assistive_technology(every_page):
    page = every_page["scan"]

    assert '<div class="hero-slot span-5" aria-hidden="true">' in page
    assert '<svg class="fs-belt" viewBox="0 0 560 220"' in page
    svg_tag = page[page.index('<svg class="fs-belt"') :].split(">", 1)[0]
    assert 'aria-hidden="true"' in svg_tag
    assert 'focusable="false"' in svg_tag


def test_the_hero_clip_path_id_is_on_the_page_once(every_page):
    page = every_page["scan"]

    assert page.count('id="fs-belt-clip"') == 1
    assert page.count('clip-path="url(#fs-belt-clip)"') == 1


def test_the_hero_animation_has_a_still_frame_for_reduced_motion():
    css = STYLESHEET.read_text(encoding="utf-8")
    reduced = css[css.index("@media (prefers-reduced-motion: reduce)") :]

    assert "animation: none;" in reduced.split("}")[0] + "}"
    assert (
        ".fs-belt path,\n.fs-belt rect,\n.fs-belt circle { vector-effect: non-scaling-stroke; }"
        in css
    )


def test_the_static_hero_drawing_is_gone():
    assert not (STATIC / "img" / "hero-conveyor.svg").exists()
    assert "hero-conveyor" not in STYLESHEET.read_text(encoding="utf-8")


def test_the_scan_page_has_the_file_form_and_the_paste_form(every_page):
    page = every_page["scan"]

    assert page.count('action="/scan" method="post" enctype="multipart/form-data"') == 2
    assert 'name="file" type="file"' in page
    assert '<textarea class="textarea" id="raw-email" name="raw_email"' in page


def test_the_paste_heading_stands_on_its_own_like_the_upload_heading(every_page):
    page = every_page["scan"]

    assert '<h2 class="card__title">Upload a file</h2>' in page
    assert '<h2 class="card__title"><label for="raw-email">Paste the raw email</label></h2>' in page
    assert "Headers and body, as plain text" in page
    assert "or paste the raw email</label>" not in page


def test_every_page_has_the_same_footer(every_page):
    for page in every_page.values():
        footer = page[page.index('<footer class="site-footer">') : page.index("</footer>")]
        assert "<p>Hello team Upwind!</p>" in footer


def test_the_privacy_facts_stay_on_the_scan_page(every_page):
    page = every_page["scan"]

    for fact in ("Analysed in memory", "Nothing stored but the verdict"):
        assert fact in page


# ------------------------------------------------------- Values worked out for the page


def test_the_severity_summary_counts_findings_most_severe_first():
    findings = [
        finding("links", "a", "low", "x"),
        finding("links", "b", "critical", "x"),
        finding("sender", "c", "low", "x"),
        finding("wording", "d", "high", "x"),
    ]

    assert web._severity_counts(findings) == {"critical": 1, "high": 1, "low": 2}


def test_every_category_gets_a_block_in_the_engines_order_even_with_no_findings():
    result = analyze((SAMPLES / "paypal-phish.eml").read_bytes())

    categories = web._categories(result)

    assert [category.name for category in categories] == list(web.CATEGORIES)
    assert sum(len(category.findings) for category in categories) == len(result.findings)
    assert {category.name: category.points for category in categories if category.points} == (
        result.category_scores
    )


def test_a_category_the_page_does_not_know_is_shown_last_rather_than_lost():
    unknown = Finding("headers", "b", "low", 5, "x")
    result = build_result([finding("links", "a", "low", "x"), unknown])

    names = [category.name for category in web._categories(result)]

    assert names == [*web.CATEGORIES, "headers"]


def test_the_engines_categories_are_the_ones_the_page_knows():
    # The engine's category names are not exported, so they are kept in step by checking
    # every finding the sample corpus produces.
    produced = {
        found.category
        for path in SAMPLES.glob("[!.]*")
        for found in analyze(path.read_bytes()).findings
    }

    assert produced <= set(web.CATEGORIES)


def test_the_result_page_shows_the_severity_summary(client):
    page = text(client.post("/scan", data=sample_upload("paypal-phish.eml")))
    result = analyze((SAMPLES / "paypal-phish.eml").read_bytes())
    counts = web._severity_counts(result.findings)

    expected = ", ".join(f"{count} {severity}" for severity, count in counts.items())
    assert f"{len(result.findings)} findings: {expected}</p>" in page


def test_the_findings_heading_gives_the_count_and_no_points_total(client):
    # The categories' points are summed before the score's cap: "270 points" beside
    # "100 / 100" would read as a fault. Each category keeps its own points.
    page = text(client.post("/scan", data=sample_upload("paypal-phish.eml")))
    result = analyze((SAMPLES / "paypal-phish.eml").read_bytes())

    heading = page[
        page.index('<div class="section-head">') : page.index('<div class="bento findings-grid">')
    ]
    assert f'<p class="muted">{len(result.findings)} findings</p>' in heading
    assert "points" not in heading
    assert page.count('<span class="points__unit">pts</span>') == len(web.CATEGORIES)


@pytest.mark.parametrize(
    "sender,name,address",
    [
        ('"Customer Service" <alerts@example.net>', "Customer Service", "alerts@example.net"),
        ("alerts@example.net", "", "alerts@example.net"),
        (None, "", ""),
        ("", "", ""),
    ],
)
def test_a_sender_is_split_into_name_and_address_for_the_history(sender, name, address):
    assert web._sender_view(sender) == web.SenderView(name=name, address=address)


def test_a_sender_that_does_not_parse_is_shown_whole():
    view = web._sender_view("<<not an address")

    assert "not an address" in view.name + view.address


def test_the_history_shows_the_senders_name_and_address_apart(client, history: FakeHistory):
    client.post("/scan", data=sample_upload("paypal-phish.eml"))

    page = text(client.get("/history"))

    sender = history.records[0].sender
    view = web._sender_view(sender)
    assert f'{view.name} <span class="sender__addr">&lt;{view.address}&gt;</span>' in page


# --------------------------------------------------------------------------- Static files


def test_every_file_the_stylesheet_refers_to_exists():
    references = re.findall(r'url\("?([^")]+)"?\)', STYLESHEET.read_text(encoding="utf-8"))

    assert references
    assert [ref for ref in references if not (STATIC / ref).is_file()] == []


def test_every_static_file_a_page_refers_to_exists(every_page):
    referenced = {
        ref.removeprefix("/static/")
        for page in every_page.values()
        for ref in re.findall(r'(?:href|src)="(/static/[^"]+)"', page)
    }

    assert referenced
    assert [ref for ref in referenced if not (STATIC / ref).is_file()] == []


def test_the_fonts_ship_with_their_licence():
    fonts = sorted(path.name for path in (STATIC / "fonts").glob("*.woff2"))

    assert fonts == ["manrope-400.woff2", "manrope-500.woff2", "manrope-600.woff2"]
    assert "SIL Open Font License" in (STATIC / "fonts" / "OFL-LICENSE.txt").read_text("utf-8")


def test_the_release_zip_keeps_every_static_file():
    # The excludes in infra/app/artifact.tf decide what reaches the instances.
    block = re.search(r"excludes\s*=\s*\[(.*?)\]", ARTIFACT_TF.read_text("utf-8"), re.DOTALL)
    patterns = re.findall(r'"([^"]+)"', block.group(1))
    shipped = [
        path.relative_to(APP_DIRECTORY).as_posix()
        for path in STATIC.rglob("*")
        if path.is_file() and path.name != ".gitkeep"
    ]

    excluded = [name for name in shipped if any(fnmatch(name, pattern) for pattern in patterns)]

    assert "static/fonts/manrope-400.woff2" in shipped
    assert "static/img/fishscan-logo.svg" in shipped
    assert excluded == []


def test_the_favicon_is_the_logos_tile_without_the_wordmark():
    favicon = (STATIC / "img" / "favicon.svg").read_text(encoding="utf-8")

    assert 'viewBox="0 0 32 32"' in favicon
    assert 'fill="#E5FF8F"' in favicon
    assert 'fill="#FFFFFF"' not in favicon  # the wordmark's colour


def test_the_fonts_are_served_with_the_font_media_type(client):
    response = client.get("/static/fonts/manrope-400.woff2")

    assert response.status_code == 200
    assert response.mimetype == "font/woff2"


def test_the_history_shows_times_to_the_minute_and_keeps_seconds_for_machines(client):
    client.post("/scan", data=sample_upload("team-lunch.eml"))

    page = text(client.get("/history"))

    times = re.findall(r'<time datetime="([^"]+)">([^<]+)</time>', page)
    assert len(times) == 1
    machine, shown = times[0]
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", machine)
    assert re.fullmatch(r"\d{4}-\d\d-\d\d \d\d:\d\d", shown)
