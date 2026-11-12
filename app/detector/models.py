"""Data model shared by the parser, the checks and the scorer.

A ParsedEmail goes into every check, each check returns Findings, and the
scorer folds the Findings into one Result. All four classes are immutable, so
a check cannot alter the email that the next check will read.
"""

from dataclasses import dataclass

# Points a finding adds to its category score. The table lives next to finding()
# because that helper is the only place a weight is ever derived from a severity.
SEVERITY_WEIGHT = {"critical": 40, "high": 25, "medium": 15, "low": 5}


@dataclass(frozen=True)
class Attachment:
    """One attached file, held in memory only."""

    filename: str
    content_type: str  # as declared in the MIME headers
    size: int  # bytes
    head: bytes  # first 8 bytes, for magic-number checks
    payload: bytes  # full bytes, needed to inspect Office archives


@dataclass(frozen=True)
class ParsedEmail:
    """Everything the checks need to know about one email."""

    from_header: str  # raw From: header, e.g. '"PayPal" <help@paypa1.com>'
    from_display: str  # display name only, e.g. 'PayPal'
    from_address: str  # address only, e.g. 'help@paypa1.com'
    reply_to: str  # address only, '' if absent
    return_path: str  # address only, '' if absent
    subject: str
    auth_results: str  # raw Authentication-Results header, '' if absent
    text_body: str  # text/plain part, or HTML stripped to text if no plain part
    html_body: str  # text/html part, '' if absent
    urls: list[str]  # every URL found, from both HTML hrefs and plain text
    anchors: list[tuple[str, str]]  # (visible_text, href) pairs from the HTML part
    attachments: list[Attachment]
    has_headers: bool  # False when the input was plain text with no email headers


@dataclass(frozen=True)
class Finding:
    """One indicator raised by a check. Build it with finding(), never directly."""

    category: str  # "links" | "sender" | "wording" | "attachments"
    code: str  # stable identifier, e.g. "ip_url"
    severity: str  # "critical" | "high" | "medium" | "low"
    weight: int  # derived from severity, see SEVERITY_WEIGHT
    reason: str  # one human-readable sentence
    evidence: str = ""  # the exact thing that matched


@dataclass(frozen=True)
class Result:
    """The verdict for one email, with the findings that led to it."""

    score: int  # 0-100
    verdict: str  # "Safe" | "Suspicious" | "Phishing"
    decided_by: str  # why the verdict came out this way, see scoring.py
    findings: list[Finding]
    category_scores: dict[str, int]


def finding(category: str, code: str, severity: str, reason: str, evidence: str = "") -> Finding:
    """Build a Finding whose weight is looked up from its severity.

    Weight is never passed by hand, so severity and weight cannot disagree.
    """
    return Finding(category, code, severity, SEVERITY_WEIGHT[severity], reason, evidence)
