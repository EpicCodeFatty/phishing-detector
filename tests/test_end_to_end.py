"""End-to-end tests: raw bytes in, a Result out, over the sample corpus and hostile input."""

import socket
from pathlib import Path

import pytest

from app.detector import analyze
from app.detector.models import SEVERITY_WEIGHT, Result
from tests.builders import eml

SAMPLES = Path(__file__).parent.parent / "samples"
SAMPLE_PATTERNS = ("*.eml", "*.txt")

# Adding a sample means adding one line here.
EXPECTED_VERDICTS = {
    "bank-link-mismatch.eml": "Phishing",
    "credential-harvest.txt": "Phishing",
    "dhl-display-spoof.eml": "Phishing",
    "disguised-attachment.eml": "Phishing",
    "macro-invoice.eml": "Phishing",
    "microsoft-lookalike.eml": "Phishing",
    "paypal-phish.eml": "Phishing",
    "password-reset.txt": "Suspicious",
    "paypal-billing-notice.eml": "Suspicious",
    "supplier-reply-to.eml": "Suspicious",
    "meeting-notes.txt": "Safe",
    "newsletter.eml": "Safe",
    "paypal-receipt.eml": "Safe",
    "quarterly-report.eml": "Safe",
    "team-lunch.eml": "Safe",
}

CATEGORY_ORDER = ["links", "sender", "wording", "attachments"]

TRUNCATED_MULTIPART = eml(
    """
    From: dana@example.org
    Subject: Cut off
    Content-Type: multipart/mixed; boundary="outer"

    --outer
    Content-Type: text/plain

    The message ends before its closing bound
    """
)

BROKEN_BASE64_ATTACHMENT = eml(
    """
    From: dana@example.org
    Subject: Broken attachment
    Content-Type: application/pdf
    Content-Disposition: attachment; filename="report.pdf"
    Content-Transfer-Encoding: base64

    !!! this is not base64 ===
    """
)

CORRUPT_ZIP_ATTACHMENT = eml(
    """
    From: dana@example.org
    Subject: Corrupt archive
    Content-Type: multipart/mixed; boundary="outer"

    --outer
    Content-Type: text/plain

    See attached.

    --outer
    Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document
    Content-Disposition: attachment; filename="report.docx"
    Content-Transfer-Encoding: base64

    UEsDBBQAAAAIAGNvcnJ1cHQgYXJjaGl2ZSBieXRlcyB0aGF0IGFyZSBub3QgYSB6aXA=

    --outer--
    """
)

# Headers on which the standard library's own parser raises IndexError or AttributeError.
HEADERS_THAT_CRASH_THE_STDLIB_PARSER = (
    b'From: =?utf-8?q??=];a*"\\utf-8--filenameboundary*0*=\x00\nSubject: Hi\n\nBody',
    b"From: \x00''=?\xc2\x80%:\\-;multipart/mixed[=?_'[ <multipart/mixed=a@\nSubject: >\n\nBody",
)

HOSTILE_INPUTS = {
    "empty file": b"",
    "whitespace only": b"\n\n   \n",
    "plain text with no headers": b"Hello,\nplease call me back when you can.\n",
    "headers with no body": b"From: dana@example.org\nSubject: Hello",
    "binary noise": bytes(range(256)) * 4,
    "truncated multipart": TRUNCATED_MULTIPART,
    "broken base64 attachment": BROKEN_BASE64_ATTACHMENT,
    "corrupt zip attachment": CORRUPT_ZIP_ATTACHMENT,
    "undecodable header bytes": b"From: \xff\xfe\xfd <\xff@\xfe>\nSubject: \xff\n\n\xff",
    "stdlib parser crash 1": HEADERS_THAT_CRASH_THE_STDLIB_PARSER[0],
    "stdlib parser crash 2": HEADERS_THAT_CRASH_THE_STDLIB_PARSER[1],
}


def sample_files() -> list[Path]:
    return sorted(path for pattern in SAMPLE_PATTERNS for path in SAMPLES.glob(pattern))


@pytest.mark.parametrize("name,expected_verdict", EXPECTED_VERDICTS.items())
def test_sample_gets_its_expected_verdict(name, expected_verdict):
    raw = (SAMPLES / name).read_bytes()

    result = analyze(raw)

    assert result.verdict == expected_verdict


def test_every_sample_file_has_an_expected_verdict():
    names = {path.name for path in sample_files()}

    assert names == set(EXPECTED_VERDICTS)


@pytest.mark.parametrize("raw", HOSTILE_INPUTS.values(), ids=HOSTILE_INPUTS.keys())
def test_hostile_input_returns_a_result_instead_of_raising(raw):
    result = analyze(raw)

    assert isinstance(result, Result)
    assert result.verdict in {"Safe", "Suspicious", "Phishing"}


def test_empty_file_is_safe_with_no_findings():
    result = analyze(b"")

    assert (result.verdict, result.score, result.findings) == ("Safe", 0, [])


def test_plain_text_without_headers_still_gets_its_links_checked():
    result = analyze(b"Sign in at http://192.0.2.7/login to keep your mailbox.")

    assert [found.code for found in result.findings] == ["ip_url"]


@pytest.mark.parametrize(
    "sender_domain,expected_verdict,expected_decided_by",
    [
        ("paypa1.com", "Phishing", "1 critical finding(s)"),
        ("payppal.com", "Suspicious", "one high-severity finding"),
        ("chess.com", "Safe", "cumulative score"),
    ],
)
def test_sender_domain_alone_decides_no_more_than_its_evidence_supports(
    sender_domain, expected_verdict, expected_decided_by
):
    raw = f"From: hello@{sender_domain}\nSubject: Hello\n\nSee you on Thursday.".encode()

    result = analyze(raw)

    assert (result.verdict, result.decided_by) == (expected_verdict, expected_decided_by)


def test_findings_come_in_category_order_with_the_most_severe_first():
    raw = (SAMPLES / "paypal-phish.eml").read_bytes()

    result = analyze(raw)

    categories = [found.category for found in result.findings]
    assert categories == sorted(categories, key=CATEGORY_ORDER.index)
    for category in CATEGORY_ORDER:
        weights = [found.weight for found in result.findings if found.category == category]
        assert weights == sorted(weights, reverse=True)


def test_showcase_sample_reproduces_the_scores_in_the_design_document():
    raw = (SAMPLES / "paypal-phish.eml").read_bytes()

    result = analyze(raw)

    assert result.score == 100
    assert result.decided_by == "3 critical finding(s)"
    assert result.category_scores == {"links": 70, "sender": 120, "wording": 15, "attachments": 65}


def test_every_finding_carries_the_weight_of_its_severity():
    raw = (SAMPLES / "paypal-phish.eml").read_bytes()

    result = analyze(raw)

    assert all(found.weight == SEVERITY_WEIGHT[found.severity] for found in result.findings)


def test_same_input_always_gives_the_same_result():
    raw = (SAMPLES / "paypal-phish.eml").read_bytes()

    assert analyze(raw) == analyze(raw)


def test_engine_makes_no_network_calls(monkeypatch):
    def refuse_connection(*args, **kwargs):
        raise AssertionError("the engine tried to open a network connection")

    monkeypatch.setattr(socket.socket, "connect", refuse_connection)
    monkeypatch.setattr(socket, "getaddrinfo", refuse_connection)

    for path in sample_files():
        analyze(path.read_bytes())
