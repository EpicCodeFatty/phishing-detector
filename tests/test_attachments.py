"""Tests for the attachment checks."""

import pytest

from app.detector.checks import attachments
from app.detector.checks.attachments import normalize_filename
from tests.builders import (
    EXECUTABLE_BYTES,
    PDF_BYTES,
    codes_and_severities,
    make_attachment,
    make_email,
    zip_archive,
)

PNG_BYTES = b"\x89PNG\r\n\x1a\n inert test bytes"
MACRO_FREE_ARCHIVE = zip_archive("[Content_Types].xml", "word/document.xml")
MACRO_ARCHIVE = zip_archive("[Content_Types].xml", "word/document.xml", "word/vbaProject.bin")


@pytest.mark.parametrize(
    "filename,payload,expected",
    [
        ("setup.exe", EXECUTABLE_BYTES, [("dangerous_ext", "critical")]),
        ("scan.pdf", EXECUTABLE_BYTES, [("type_mismatch", "critical")]),
        ("budget.xlsm", MACRO_FREE_ARCHIVE, [("macro_ext", "high")]),
        ("report.docx", MACRO_ARCHIVE, [("macro_inside", "high")]),
        # A double extension is by definition also a dangerous one.
        (
            "invoice.pdf.exe",
            EXECUTABLE_BYTES,
            [("dangerous_ext", "critical"), ("double_ext", "high")],
        ),
    ],
)
def test_each_attachment_indicator_raises_only_its_own_findings(filename, payload, expected):
    email = make_email(attachments=[make_attachment(filename, payload)])

    findings = attachments.check(email)

    assert codes_and_severities(findings) == expected


@pytest.mark.parametrize(
    "filename,payload",
    [
        ("report.pdf", PDF_BYTES),
        ("notes.docx", MACRO_FREE_ARCHIVE),
        ("photos.zip", MACRO_FREE_ARCHIVE),
        ("data.bin", b"\x00\x01\x02\x03 no known signature"),
        ("README", PDF_BYTES),
        ("empty.pdf", b""),
        ("slides.ppsx", MACRO_FREE_ARCHIVE),
        ("novel.epub", MACRO_FREE_ARCHIVE),
        ("notes.txt", EXECUTABLE_BYTES),
    ],
)
def test_legitimate_attachment_produces_no_finding(filename, payload):
    email = make_email(attachments=[make_attachment(filename, payload)])

    findings = attachments.check(email)

    assert findings == []


@pytest.mark.parametrize("filename", ["template.dotm", "budget.xltm", "novel.epub"])
def test_zip_based_format_is_not_a_type_mismatch(filename):
    email = make_email(attachments=[make_attachment(filename, MACRO_FREE_ARCHIVE)])

    findings = attachments.check(email)

    assert "type_mismatch" not in [found.code for found in findings]


def test_extension_known_under_another_signature_is_a_type_mismatch():
    email = make_email(attachments=[make_attachment("photo.jpg", PNG_BYTES)])

    findings = attachments.check(email)

    assert codes_and_severities(findings) == [("type_mismatch", "critical")]


def test_email_without_attachments_produces_no_finding():
    email = make_email(attachments=[])

    findings = attachments.check(email)

    assert findings == []


def test_right_to_left_override_does_not_hide_the_real_extension():
    disguised = make_attachment("invoice\N{RIGHT-TO-LEFT OVERRIDE}gpj.exe", EXECUTABLE_BYTES)
    email = make_email(attachments=[disguised])

    findings = attachments.check(email)

    assert codes_and_severities(findings) == [("dangerous_ext", "critical")]
    assert findings[0].evidence == "invoicegpj.exe"


@pytest.mark.parametrize(
    "filename,expected",
    [
        ("  Setup.EXE  ", "setup.exe"),
        ("setup.exe.", "setup.exe"),
        ("invoice\N{RIGHT-TO-LEFT OVERRIDE}gpj.exe", "invoicegpj.exe"),
        ("", ""),
    ],
)
def test_normalize_filename(filename, expected):
    assert normalize_filename(filename) == expected


def test_macro_project_is_found_whatever_the_extension_claims():
    email = make_email(attachments=[make_attachment("holiday-photos.zip", MACRO_ARCHIVE)])

    findings = attachments.check(email)

    assert codes_and_severities(findings) == [("macro_inside", "high")]


@pytest.mark.parametrize(
    "payload",
    [
        b"PK\x03\x04 this is not really an archive",
        MACRO_ARCHIVE[: len(MACRO_ARCHIVE) // 2],
        MACRO_ARCHIVE[:-10],
    ],
)
def test_corrupt_archive_produces_no_finding(payload):
    email = make_email(attachments=[make_attachment("report.docx", payload)])

    findings = attachments.check(email)

    assert findings == []


def test_every_attachment_is_inspected():
    email = make_email(
        attachments=[
            make_attachment("report.pdf", PDF_BYTES),
            make_attachment("setup.exe", EXECUTABLE_BYTES),
            make_attachment("update.scr", EXECUTABLE_BYTES),
        ]
    )

    findings = attachments.check(email)

    assert [found.evidence for found in findings] == ["setup.exe", "update.scr"]
