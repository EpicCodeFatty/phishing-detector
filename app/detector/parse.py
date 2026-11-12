"""Turn the raw bytes of an email file into a ParsedEmail.

Parsing never raises. Malformed headers, wrong encodings and truncated MIME
are the normal case for this tool, so anything that cannot be read degrades to
an empty field rather than an exception.
"""

import codecs
import email
import email.policy
import re
from collections.abc import Callable
from email.errors import MessageError
from email.message import EmailMessage
from email.utils import parseaddr

from bs4 import BeautifulSoup
from bs4.exceptions import ParserRejectedMarkup

from .models import Attachment, ParsedEmail

# What the standard library's header parser raises on malformed input. Beyond the
# documented MessageError it leaks IndexError and AttributeError from its internals,
# which fuzzing reproduces easily, so those are named here rather than left to escape.
_MALFORMED_HEADER_ERRORS = (MessageError, AttributeError, LookupError, ValueError)

_FALLBACK_CHARSET = "utf-8"
_HTML_PARSER = "html.parser"
_MAGIC_HEAD_LENGTH = 8
_ATTACHMENT_DISPOSITION = "attachment"

_URL_IN_TEXT = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
# A URL at the end of a sentence or inside brackets drags this punctuation along.
_URL_TRAILING_PUNCTUATION = ".,;:!?)]}"


def parse_email(raw: bytes) -> ParsedEmail:
    """Parse the bytes of an .eml file, or of a plain text file with no headers.

    Input with neither a From nor a Subject header is treated as plain text:
    has_headers is False and the entire content becomes text_body. Never raises;
    whatever cannot be read is left empty.
    """
    # A byte-order mark or blank lines before the first header would otherwise make
    # the whole message look like a body with no headers.
    content = raw.removeprefix(codecs.BOM_UTF8).lstrip()
    try:
        message = email.message_from_bytes(content, policy=email.policy.default)
    except _MALFORMED_HEADER_ERRORS:
        return _plain_text_email(content)

    if not _raw_headers(message, "From") and not _raw_headers(message, "Subject"):
        return _plain_text_email(content)
    return _email_from_message(message)


def _plain_text_email(content: bytes) -> ParsedEmail:
    text = content.decode(_FALLBACK_CHARSET, errors="replace")
    return ParsedEmail(
        from_header="",
        from_display="",
        from_address="",
        reply_to="",
        return_path="",
        subject="",
        auth_results="",
        text_body=text,
        html_body="",
        urls=_urls_in_text(text),
        anchors=[],
        attachments=[],
        has_headers=False,
    )


def _email_from_message(message: EmailMessage) -> ParsedEmail:
    display, address = _split_address(_decoded_header(message, "From"))
    html_body = _first_text_part(message, "text/html") or ""
    plain_body = _first_text_part(message, "text/plain")
    soup = _parse_html(html_body)
    # The separator keeps words in neighbouring elements apart: without it
    # "<p>urgent</p><p>act now</p>" reads as "urgentact now" and matches nothing.
    text_body = soup.get_text(separator=" ") if plain_body is None else plain_body
    anchors = _anchors_in(soup)

    return ParsedEmail(
        from_header="".join(_raw_headers(message, "From")[:1]),
        from_display=display,
        from_address=address,
        reply_to=_split_address(_decoded_header(message, "Reply-To"))[1],
        return_path=_split_address(_decoded_header(message, "Return-Path"))[1],
        subject=_decoded_header(message, "Subject"),
        auth_results="\n".join(_raw_headers(message, "Authentication-Results")),
        text_body=text_body,
        html_body=html_body,
        urls=_unique([href for _, href in anchors] + _urls_in_text(text_body)),
        anchors=anchors,
        attachments=[_to_attachment(part) for part in message.walk() if _is_attachment(part)],
        has_headers=True,
    )


def _guarded[T](read: Callable[[], T], fallback: T) -> T:
    """Return read(), or the fallback when the header it touches is malformed."""
    try:
        return read()
    except _MALFORMED_HEADER_ERRORS:
        return fallback


def _raw_headers(message: EmailMessage, name: str) -> list[str]:
    """Return every occurrence of a header as written in the source, unfolded.

    Reads the unparsed source text, so it cannot fail on a malformed header.
    """
    return [
        _unfold(str(value)) for key, value in message.raw_items() if key.lower() == name.lower()
    ]


def _unfold(value: str) -> str:
    # Raw 8-bit header bytes arrive as lone surrogates, which cannot be printed or
    # encoded; round-tripping restores the text they were meant to be.
    readable = value.encode(_FALLBACK_CHARSET, "surrogateescape").decode(
        _FALLBACK_CHARSET, "replace"
    )
    return " ".join(readable.split())


def _decoded_header(message: EmailMessage, name: str) -> str:
    """Return a header with its encoded words decoded, '' if absent or malformed."""
    value = _guarded(lambda: message.get(name), None)
    if value is None:
        return ""
    return _guarded(lambda: str(value), "")


def _split_address(header_value: str) -> tuple[str, str]:
    """Split an address header into (display name as written, lowercased address)."""
    display, address = _guarded(lambda: parseaddr(header_value), ("", ""))
    if "@" not in address:
        return display, ""
    return display, address.lower()


def _first_text_part(message: EmailMessage, content_type: str) -> str | None:
    """Return the first body part of the given type, or None if there is none."""
    for part in message.walk():
        if _is_attachment(part):
            continue
        if _guarded(part.get_content_type, "") == content_type:
            return _decode_text(part)
    return None


def _decode_text(part: EmailMessage) -> str:
    payload = _decoded_payload(part)
    charset = _guarded(part.get_content_charset, None) or _FALLBACK_CHARSET
    # LookupError: a charset Python does not know. ValueError: bytes that are not
    # valid in the declared charset, or a charset name that is itself malformed.
    try:
        return payload.decode(charset)
    except (LookupError, ValueError):
        return payload.decode(_FALLBACK_CHARSET, errors="replace")


def _decoded_payload(part: EmailMessage) -> bytes:
    """Return the part's bytes after transfer decoding, b'' for a container part."""
    payload = _guarded(lambda: part.get_payload(decode=True), None)
    return payload if isinstance(payload, bytes) else b""


def _is_attachment(part: EmailMessage) -> bool:
    if _guarded(part.get_filename, None) is not None:
        return True
    return _guarded(part.get_content_disposition, None) == _ATTACHMENT_DISPOSITION


def _to_attachment(part: EmailMessage) -> Attachment:
    payload = _decoded_payload(part)
    return Attachment(
        filename=_guarded(part.get_filename, None) or "",
        content_type=_guarded(part.get_content_type, ""),
        size=len(payload),
        head=payload[:_MAGIC_HEAD_LENGTH],
        payload=payload,
    )


def _parse_html(html: str) -> BeautifulSoup:
    """Parse the HTML part; markup the parser rejects is treated as an empty document."""
    try:
        return BeautifulSoup(html, _HTML_PARSER)
    except ParserRejectedMarkup:
        return BeautifulSoup("", _HTML_PARSER)


def _anchors_in(soup: BeautifulSoup) -> list[tuple[str, str]]:
    return [
        (anchor.get_text(strip=True), str(anchor["href"]).strip())
        for anchor in soup.find_all("a", href=True)
    ]


def _urls_in_text(text: str) -> list[str]:
    candidates = (url.rstrip(_URL_TRAILING_PUNCTUATION) for url in _URL_IN_TEXT.findall(text))
    return [url for url in candidates if url]


def _unique(items: list[str]) -> list[str]:
    """Drop duplicates while keeping the first occurrence of each item in place."""
    return list(dict.fromkeys(items))
