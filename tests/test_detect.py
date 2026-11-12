"""Tests for the command-line interface."""

import json
from pathlib import Path

import pytest

import detect

SAMPLES = Path(__file__).parent.parent / "samples"


@pytest.mark.parametrize(
    "sample,expected_exit_code",
    [
        ("team-lunch.eml", 0),
        ("paypal-billing-notice.eml", 1),
        ("paypal-phish.eml", 2),
    ],
)
def test_exit_code_carries_the_verdict(sample, expected_exit_code, capsys):
    exit_code = detect.main([str(SAMPLES / sample)])

    assert exit_code == expected_exit_code


def test_report_shows_headers_verdict_findings_and_category_scores(capsys):
    detect.main([str(SAMPLES / "paypal-phish.eml")])

    report = capsys.readouterr().out
    assert 'From:     "PayPal Support" <help@paypa1-secure.com>' in report
    assert "Subject:  Your account has been suspended" in report
    assert "Verdict:  PHISHING   (100/100)" in report
    assert "Decided:  3 critical finding(s)" in report
    assert "CRITICAL  [sender]       Domain imitates paypal.com by character substitution" in report
    assert "                         paypa1-secure.com" in report
    assert "CRITICAL  [attachments]  Executable attachment" in report
    assert "Category scores: links 70, sender 120, wording 15 (capped), attachments 65" in report


def test_report_lists_the_most_severe_findings_first(capsys):
    detect.main([str(SAMPLES / "paypal-phish.eml")])

    report = capsys.readouterr().out
    severities = [
        line.split()[0]
        for line in report.splitlines()
        if line.startswith(("CRITICAL", "HIGH", "MEDIUM", "LOW"))
    ]
    assert severities == sorted(severities, key=["CRITICAL", "HIGH", "MEDIUM", "LOW"].index)


def test_report_for_a_clean_email_says_there_are_no_findings(capsys):
    detect.main([str(SAMPLES / "team-lunch.eml")])

    report = capsys.readouterr().out
    assert "Verdict:  SAFE       (0/100)" in report
    assert "No findings." in report


def test_report_for_plain_text_marks_the_missing_headers(capsys):
    detect.main([str(SAMPLES / "meeting-notes.txt")])

    report = capsys.readouterr().out
    assert "From:     (none)" in report
    assert "Subject:  (none)" in report


def test_json_flag_prints_the_result_as_json(capsys):
    detect.main([str(SAMPLES / "paypal-phish.eml"), "--json"])

    result = json.loads(capsys.readouterr().out)
    assert set(result) == {"score", "verdict", "decided_by", "findings", "category_scores"}
    assert result["verdict"] == "Phishing"
    assert result["findings"][0]["code"] == "href_mismatch_brand"


def test_unreadable_file_fails_loudly_with_its_own_exit_code(tmp_path, capsys):
    exit_code = detect.main([str(tmp_path / "missing.eml")])

    assert exit_code == detect.EXIT_ERROR
    assert "cannot read" in capsys.readouterr().err


def test_usage_error_does_not_exit_with_a_verdict_code(capsys):
    with pytest.raises(SystemExit) as exit_info:
        detect.main([])

    assert exit_info.value.code == detect.EXIT_ERROR


def test_control_characters_from_the_email_are_escaped_in_the_report(tmp_path, capsys):
    hostile = tmp_path / "hostile.eml"
    hostile.write_bytes(b"From: dana@example.org\nSubject: =?utf-8?q?Hello=1B[2Jthere?=\n\nBody")

    detect.main([str(hostile)])

    report = capsys.readouterr().out
    assert "\x1b" not in report
    assert "Hello\\x1b[2Jthere" in report
