"""Turn findings into a verdict.

Two layers. Severity rules decide first: one decisive indicator is enough on
its own. The additive score only decides when no rule fires. The rules can
raise a verdict but never lower one, and the reported score always matches
the verdict.

The weight of each severity lives in models.SEVERITY_WEIGHT, next to the
finding() helper that applies it.
"""

from .models import Finding, Result

# The most a category may contribute to the score. Capping wording below the
# Suspicious threshold is what stops pressure phrases alone from reaching a verdict.
CATEGORY_CAP = {"wording": 15}

# Minimum score for each verdict above Safe.
THRESHOLDS = {"phishing": 60, "suspicious": 30}

MAX_SCORE = 100

VERDICT_SAFE = "Safe"
VERDICT_SUSPICIOUS = "Suspicious"
VERDICT_PHISHING = "Phishing"

# How many high-severity findings are conclusive without any critical one.
HIGH_FINDINGS_FOR_PHISHING = 2


def build_result(findings: list[Finding]) -> Result:
    """Score the findings and return the verdict together with what decided it."""
    category_scores = score_categories(findings)
    cumulative = min(MAX_SCORE, sum(category_scores.values()))
    score, decided_by = _apply_severity_rules(cumulative, findings)

    return Result(
        score=score,
        verdict=_verdict_for(score),
        decided_by=decided_by,
        findings=findings,
        category_scores=category_scores,
    )


def score_categories(findings: list[Finding]) -> dict[str, int]:
    """Sum the weights per category, then apply the per-category caps."""
    totals: dict[str, int] = {}
    for found in findings:
        totals[found.category] = totals.get(found.category, 0) + found.weight
    return {
        category: min(total, CATEGORY_CAP.get(category, total))
        for category, total in totals.items()
    }


def _apply_severity_rules(score: int, findings: list[Finding]) -> tuple[int, str]:
    """Return the score after the severity rules, and the reason for the verdict."""
    severities = [found.severity for found in findings]
    critical_count = severities.count("critical")
    high_count = severities.count("high")

    if critical_count:
        return max(score, THRESHOLDS["phishing"]), f"{critical_count} critical finding(s)"
    if high_count >= HIGH_FINDINGS_FOR_PHISHING:
        return max(score, THRESHOLDS["phishing"]), f"{high_count} high-severity findings"
    if high_count == 1 and score < THRESHOLDS["suspicious"]:
        return THRESHOLDS["suspicious"], "one high-severity finding"
    return score, "cumulative score"


def _verdict_for(score: int) -> str:
    if score >= THRESHOLDS["phishing"]:
        return VERDICT_PHISHING
    if score >= THRESHOLDS["suspicious"]:
        return VERDICT_SUSPICIOUS
    return VERDICT_SAFE
