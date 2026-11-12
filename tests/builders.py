"""Builders for the minimal emails and attachments the tests are written against."""

import io
import textwrap
import zipfile

from app.detector.models import Attachment, Finding, ParsedEmail

EXECUTABLE_BYTES = b"MZ\x90\x00 inert test bytes"
PDF_BYTES = b"%PDF-1.4 inert test bytes"


def make_email(**fields: object) -> ParsedEmail:
    """Return an unremarkable email that triggers no finding, with the given fields replaced."""
    defaults: dict[str, object] = {
        "from_header": '"Dana Levi" <dana@example.org>',
        "from_display": "Dana Levi",
        "from_address": "dana@example.org",
        "reply_to": "",
        "return_path": "",
        "subject": "Notes from Thursday",
        "auth_results": "",
        "text_body": "Here are the notes we agreed on.",
        "html_body": "",
        "urls": [],
        "anchors": [],
        "attachments": [],
        "has_headers": True,
    }
    return ParsedEmail(**(defaults | fields))


def make_attachment(filename: str, payload: bytes = b"") -> Attachment:
    """Return an attachment as the parser would record it."""
    return Attachment(
        filename=filename,
        content_type="application/octet-stream",
        size=len(payload),
        head=payload[:8],
        payload=payload,
    )


def zip_archive(*entry_names: str) -> bytes:
    """Return the bytes of a ZIP archive holding one small file per entry name."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in entry_names:
            archive.writestr(name, b"inert test bytes")
    return buffer.getvalue()


def eml(text: str) -> bytes:
    """Encode an email written as an indented triple-quoted string."""
    return textwrap.dedent(text).lstrip("\n").encode()


def codes_and_severities(findings: list[Finding]) -> list[tuple[str, str]]:
    """Reduce findings to the two fields most tests assert on."""
    return [(found.code, found.severity) for found in findings]
