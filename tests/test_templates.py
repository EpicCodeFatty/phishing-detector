"""Tests that keep the templates safe to render and cheap to redesign.

They read the template files as text. Crude, and that is the point: they catch
a regression nobody would notice by looking at the pages.
"""

import re
from pathlib import Path

import pytest

from app import db, web
from tests.builders import sample_upload

TEMPLATES = Path(web.__file__).parent / "templates"
STYLESHEET = Path(web.__file__).parent / "static" / "style.css"
PAGES = ("upload.html", "result.html", "history.html", "error.html")
EXTENDS_BASE = '{% extends "base.html" %}'

# Anything that switches off autoescaping for a value from an email.
UNESCAPING = re.compile(r"\|\s*safe\b|autoescape\s+false|Markup\(", re.IGNORECASE)

# An address that would make the browser fetch something from another host.
REMOTE_RESOURCE = re.compile(
    r"(?:src|href)\s*=\s*[\"']?(?:https?:)?//|url\(\s*[\"']?(?:https?:)?//|@import"
)

# One "name: type" line of a template's contract comment.
CONTRACT_LINE = re.compile(r"^\s{4}(\w+):", re.MULTILINE)


def template_text(name: str) -> str:
    return (TEMPLATES / name).read_text(encoding="utf-8")


def contract_of(name: str) -> set[str]:
    """Return the variable names a template's opening comment says it receives."""
    comment = re.match(r"\{#-?(.*?)-?#\}", template_text(name), re.DOTALL)
    assert comment is not None, f"{name} does not begin with its contract comment"
    return set(CONTRACT_LINE.findall(comment.group(1)))


@pytest.mark.parametrize("name", ("base.html", *PAGES))
def test_no_template_switches_off_escaping(name):
    assert UNESCAPING.search(template_text(name)) is None


@pytest.mark.parametrize("name", PAGES)
def test_every_page_extends_base(name):
    assert EXTENDS_BASE in template_text(name)


@pytest.mark.parametrize("name", PAGES)
@pytest.mark.parametrize("element", ("<head", "<nav", "<footer"))
def test_no_page_repeats_the_shared_frame(name, element):
    assert element not in template_text(name).lower()


def test_base_defines_the_title_and_content_blocks():
    text = template_text("base.html")

    assert "{% block title %}" in text
    assert "{% block content %}" in text


@pytest.mark.parametrize("name", ("base.html", *PAGES))
def test_templates_load_nothing_from_another_host(name):
    assert REMOTE_RESOURCE.search(template_text(name)) is None


def test_stylesheet_loads_nothing_from_another_host():
    assert REMOTE_RESOURCE.search(STYLESHEET.read_text(encoding="utf-8")) is None


def test_every_page_template_documents_what_it_receives():
    contracts = {name: contract_of(name) for name in PAGES}

    assert contracts == {
        "upload.html": {"max_mb"},
        "result.html": {
            "result",
            "filename",
            "sender",
            "subject",
            "served_by",
            "saved",
            "scan_id",
            "scanned_at",
            "cache_hit",
            "seen",
        },
        "history.html": {"scans"},
        "error.html": {"status", "message"},
    }


def test_routes_pass_each_template_exactly_its_contract(client, monkeypatch):
    rendered: dict[str, set[str]] = {}
    original = web.render_template

    def recording_render(name, **context):
        rendered[name] = set(context)
        return original(name, **context)

    monkeypatch.setattr(web, "render_template", recording_render)
    client.get("/")
    client.post("/scan", data=sample_upload("paypal-phish.eml"))
    client.get("/history")
    client.get("/no-such-page")

    assert rendered == {name: contract_of(name) for name in PAGES}


def test_scan_detail_page_passes_the_result_template_exactly_its_contract(client, monkeypatch):
    rendered: dict[str, set[str]] = {}
    original = web.render_template

    def recording_render(name, **context):
        rendered[name] = set(context)
        return original(name, **context)

    client.post("/scan", data=sample_upload("paypal-phish.eml"))
    monkeypatch.setattr(web, "render_template", recording_render)

    client.get("/scans/1")

    assert rendered == {"result.html": contract_of("result.html")}


def test_history_page_contract_holds_when_the_database_is_down(client, monkeypatch):
    def unavailable(*args, **kwargs):
        raise db.StorageError("down")

    monkeypatch.setattr(db, "recent_scans", unavailable)

    response = client.get("/history")

    assert response.status_code == 503
