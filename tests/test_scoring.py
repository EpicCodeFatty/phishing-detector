"""Tests for the two-layer scoring."""

import pytest

from app.detector.models import Finding, finding
from app.detector.scoring import build_result


def make_finding(severity: str, category: str = "links") -> Finding:
    return finding(category, f"test_{severity}", severity, "A test finding.")


@pytest.mark.parametrize(
    "findings,expected_verdict,expected_decided_by",
    [
        ([make_finding("critical")], "Phishing", "critical"),
        ([make_finding("high"), make_finding("high")], "Phishing", "high-severity findings"),
        ([make_finding("high")], "Suspicious", "one high-severity finding"),
        ([make_finding("low", "wording")] * 4, "Safe", "cumulative score"),
        (
            [make_finding("medium"), make_finding("low"), make_finding("low")],
            "Safe",
            "cumulative score",
        ),
        (
            [make_finding("medium"), make_finding("medium"), make_finding("low")],
            "Suspicious",
            "cumulative score",
        ),
        ([], "Safe", "cumulative score"),
    ],
)
def test_scoring_rules(findings, expected_verdict, expected_decided_by):
    result = build_result(findings)

    assert result.verdict == expected_verdict
    assert expected_decided_by in result.decided_by


@pytest.mark.parametrize(
    "findings,expected_score",
    [
        ([make_finding("critical")], 60),
        ([make_finding("high"), make_finding("high")], 60),
        ([make_finding("high")], 30),
        ([make_finding("high"), make_finding("medium")], 40),
        ([make_finding("critical")] * 2, 80),
    ],
)
def test_reported_score_always_matches_the_verdict(findings, expected_score):
    result = build_result(findings)

    assert result.score == expected_score


def test_score_is_capped_at_one_hundred():
    findings = [make_finding("critical", category) for category in ("links", "sender")] * 2

    result = build_result(findings)

    assert result.score == 100


def test_wording_category_is_capped():
    findings = [make_finding("low", "wording")] * 4

    result = build_result(findings)

    assert result.category_scores == {"wording": 15}
    assert result.score == 15


def test_other_categories_are_not_capped():
    findings = [make_finding("high", "sender"), make_finding("medium", "sender")]

    result = build_result(findings)

    assert result.category_scores == {"sender": 40}


def test_one_high_finding_above_the_suspicious_threshold_is_decided_by_the_score():
    findings = [make_finding("high"), make_finding("medium")]

    result = build_result(findings)

    assert result.verdict == "Suspicious"
    assert result.decided_by == "cumulative score"


def test_decided_by_counts_the_critical_findings():
    findings = [make_finding("critical")] * 3

    result = build_result(findings)

    assert result.decided_by == "3 critical finding(s)"


def test_result_carries_the_findings_it_was_built_from():
    findings = [make_finding("medium"), make_finding("low", "wording")]

    result = build_result(findings)

    assert result.findings == findings


def test_weight_is_derived_from_severity():
    weights = {severity: make_finding(severity).weight for severity in ("critical", "high")}

    assert weights == {"critical": 40, "high": 25}
