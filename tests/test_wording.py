"""Tests for the wording checks."""

import pytest

from app.detector import analyze
from app.detector.checks import wording
from app.detector.lists import WORDING
from tests.builders import codes_and_severities, make_email


@pytest.mark.parametrize(
    "text,expected_code",
    [
        ("Please respond within 24 hours.", "urgency"),
        ("Your account has been suspended.", "threat"),
        ("Please verify your account today.", "creds"),
        ("Your payment failed last night.", "money"),
    ],
)
def test_each_group_of_phrases_raises_exactly_one_finding(text, expected_code):
    email = make_email(text_body=text)

    findings = wording.check(email)

    assert codes_and_severities(findings) == [(expected_code, "low")]


def test_neutral_wording_produces_no_finding():
    email = make_email(subject="Lunch on Thursday", text_body="The table is booked for ten.")

    findings = wording.check(email)

    assert findings == []


def test_several_phrases_of_one_group_make_one_finding_with_all_of_them_as_evidence():
    email = make_email(text_body="Urgent: act now, this is your final notice.")

    findings = wording.check(email)

    assert codes_and_severities(findings) == [("urgency", "low")]
    assert findings[0].evidence == '"urgent", "final notice", "act now"'


def test_phrase_in_the_subject_is_found():
    email = make_email(subject="URGENT: read this")

    findings = wording.check(email)

    assert codes_and_severities(findings) == [("urgency", "low")]


def test_phrase_broken_across_a_line_wrap_is_found():
    email = make_email(text_body="You must respond within 24\nhours of this message.")

    findings = wording.check(email)

    assert codes_and_severities(findings) == [("urgency", "low")]


@pytest.mark.parametrize(
    "text", ["We replied urgently.", "The door was unlocked.", "A refundable fee."]
)
def test_phrase_inside_a_longer_word_is_not_matched(text):
    email = make_email(text_body=text)

    findings = wording.check(email)

    assert findings == []


@pytest.mark.parametrize(
    "artefact",
    [
        'Content-Disposition: attachment; filename="invoice attached.pdf"',
        "Content-Description: payment failed",
        "--boundary-refund-suspended",
    ],
)
def test_mime_artefact_lines_are_not_read_as_wording(artefact):
    email = make_email(text_body=f"See the file below.\n{artefact}\nRegards")

    findings = wording.check(email)

    assert findings == []


def test_wording_alone_never_lifts_the_verdict_above_safe():
    every_phrase = ". ".join(phrase for group in WORDING.values() for phrase in group)

    result = analyze(every_phrase.encode())

    assert [found.code for found in result.findings] == list(WORDING)
    assert result.verdict == "Safe"
