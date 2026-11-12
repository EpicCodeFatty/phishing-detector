"""Tests for the parser."""

import base64
import codecs

from app.detector.parse import parse_email
from tests.builders import eml

MULTIPART_EMAIL = eml(
    """
    From: "PayPal Support" <Help@PayPa1.com>
    Reply-To: Recovery <recovery@mail-reset.xyz>
    Return-Path: <bounce@mail-reset.xyz>
    Subject: Your account
    Authentication-Results: mx.example.org; spf=fail
    Authentication-Results: mx.example.net; dmarc=fail
    MIME-Version: 1.0
    Content-Type: multipart/mixed; boundary="outer"

    --outer
    Content-Type: multipart/alternative; boundary="inner"

    --inner
    Content-Type: text/plain; charset="utf-8"

    Plain body with https://example.org/plain and https://example.org/shared.

    --inner
    Content-Type: text/html; charset="utf-8"

    <p>HTML body</p>
    <a href="https://example.org/shared">Shared <b>link</b></a>
    <a href=" https://example.org/html ">www.example.org</a>
    <a name="top">No href</a>

    --inner--

    --outer
    Content-Type: application/pdf
    Content-Disposition: attachment; filename="report.pdf"
    Content-Transfer-Encoding: base64

    JVBERi0xLjQgaW5lcnQgdGVzdCBieXRlcw==

    --outer--
    """
)


def test_from_header_is_split_into_display_name_and_lowercased_address():
    email = parse_email(MULTIPART_EMAIL)

    assert email.from_header == '"PayPal Support" <Help@PayPa1.com>'
    assert email.from_display == "PayPal Support"
    assert email.from_address == "help@paypa1.com"


def test_reply_to_and_return_path_keep_the_address_only():
    email = parse_email(MULTIPART_EMAIL)

    assert email.reply_to == "recovery@mail-reset.xyz"
    assert email.return_path == "bounce@mail-reset.xyz"


def test_absent_address_headers_are_empty_strings():
    email = parse_email(b"From: dana@example.org\nSubject: Hello\n\nBody")

    assert (email.reply_to, email.return_path, email.auth_results) == ("", "", "")


def test_every_authentication_results_header_is_kept():
    email = parse_email(MULTIPART_EMAIL)

    assert "spf=fail" in email.auth_results
    assert "dmarc=fail" in email.auth_results


def test_first_plain_and_html_parts_become_the_bodies():
    email = parse_email(MULTIPART_EMAIL)

    assert email.text_body.startswith("Plain body with")
    assert "<p>HTML body</p>" in email.html_body


def test_anchors_pair_visible_text_with_href():
    email = parse_email(MULTIPART_EMAIL)

    assert email.anchors == [
        ("Sharedlink", "https://example.org/shared"),
        ("www.example.org", "https://example.org/html"),
    ]


def test_urls_are_collected_from_hrefs_and_text_without_duplicates():
    email = parse_email(MULTIPART_EMAIL)

    assert email.urls == [
        "https://example.org/shared",
        "https://example.org/html",
        "https://example.org/plain",
    ]


def test_attachment_records_name_type_size_head_and_payload():
    email = parse_email(MULTIPART_EMAIL)

    (attachment,) = email.attachments
    assert attachment.filename == "report.pdf"
    assert attachment.content_type == "application/pdf"
    assert attachment.payload == b"%PDF-1.4 inert test bytes"
    assert attachment.size == len(attachment.payload)
    assert attachment.head == b"%PDF-1.4"


def test_part_with_attachment_disposition_but_no_filename_is_an_attachment():
    raw = eml(
        """
        From: dana@example.org
        Subject: Unnamed file
        Content-Type: application/octet-stream
        Content-Disposition: attachment

        raw bytes
        """
    )

    email = parse_email(raw)

    assert [attachment.filename for attachment in email.attachments] == [""]


def test_text_attachment_is_not_mistaken_for_the_body():
    raw = eml(
        """
        From: dana@example.org
        Subject: Notes
        Content-Type: multipart/mixed; boundary="outer"

        --outer
        Content-Type: text/plain; name="notes.txt"
        Content-Disposition: attachment; filename="notes.txt"

        Attached notes.

        --outer
        Content-Type: text/plain

        The real body.

        --outer--
        """
    )

    email = parse_email(raw)

    assert email.text_body.strip() == "The real body."


def test_html_only_email_derives_its_text_body_from_the_html():
    raw = eml(
        """
        From: dana@example.org
        Subject: HTML only
        Content-Type: text/html; charset="utf-8"

        <p>This is urgent</p><p>act now</p>
        """
    )

    email = parse_email(raw)

    assert email.text_body.split() == ["This", "is", "urgent", "act", "now"]


def test_encoded_subject_is_decoded():
    encoded = base64.b64encode("Dringend: Überweisung".encode()).decode()

    email = parse_email(f"From: dana@example.org\nSubject: =?utf-8?b?{encoded}?=\n\nBody".encode())

    assert email.subject == "Dringend: Überweisung"


def test_plain_text_without_headers_becomes_the_text_body():
    raw = b"Your mailbox is full.\nSign in at http://192.0.2.7/login.\n"

    email = parse_email(raw)

    assert email.has_headers is False
    assert email.text_body == raw.decode()
    assert email.urls == ["http://192.0.2.7/login"]
    assert (email.from_address, email.subject, email.attachments) == ("", "", [])


def test_email_with_headers_reports_having_them():
    email = parse_email(b"Subject: Hello\n\nBody")

    assert email.has_headers is True


def test_byte_order_mark_before_the_headers_is_ignored():
    email = parse_email(codecs.BOM_UTF8 + b"From: dana@example.org\nSubject: Hello\n\nBody")

    assert email.from_address == "dana@example.org"


def test_unknown_charset_falls_back_instead_of_raising():
    headers = b"From: dana@example.org\nSubject: Hi\nContent-Type: text/plain; charset=klingon\n\n"

    email = parse_email(headers + b"caf\xc3\xa9")

    assert email.text_body == "café"


def test_malformed_charset_name_falls_back_instead_of_raising():
    headers = (
        b'From: dana@example.org\nSubject: Hi\nContent-Type: text/plain; charset="utf\x00-8"\n\n'
    )

    email = parse_email(headers + b"plain words")

    assert email.text_body == "plain words"


def test_undecodable_bytes_are_replaced_instead_of_raising():
    headers = b"From: dana@example.org\nSubject: Hi\nContent-Type: text/plain; charset=utf-8\n\n"

    email = parse_email(headers + b"\xff\xfe ok")

    assert email.text_body.endswith(" ok")


def test_from_header_without_an_address_leaves_the_address_empty():
    email = parse_email(b"From: PayPal Support\nSubject: Hello\n\nBody")

    assert email.from_address == ""


def test_empty_input_gives_an_empty_headerless_email():
    email = parse_email(b"")

    assert email.has_headers is False
    assert (email.text_body, email.urls, email.anchors, email.attachments) == ("", [], [], [])
