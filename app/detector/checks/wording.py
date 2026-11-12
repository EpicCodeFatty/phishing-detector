"""Wording checks: pressure phrases in the subject and the body.

Wording is the weakest signal in the engine, since legitimate mail uses the same
phrases. Every finding here is low severity, and scoring caps the category so
that wording alone can never lift a verdict above Safe.
"""

import re

from ..lists import WORDING
from ..models import Finding, ParsedEmail, finding

CATEGORY = "wording"
SEVERITY = "low"

# What each group of phrases in WORDING is trying to do to the reader.
REASONS = {
    "urgency": "Pressure wording: pushes the reader to act quickly",
    "threat": "Pressure wording: threatens the loss of an account or access",
    "creds": "Pressure wording: asks the reader to enter or confirm credentials",
    "money": "Pressure wording: brings up a payment or money",
}

# Line prefixes of MIME structure that leaks into the body of malformed or
# headerless input. Left in, an attachment's own headers would match as wording.
_MIME_ARTEFACT_PREFIXES = ("content-", "--")


def _phrase_pattern(phrase: str) -> re.Pattern[str]:
    # Any run of whitespace may separate the words, because plain-text bodies are
    # hard-wrapped and a phrase can straddle a line break.
    words = r"\s+".join(re.escape(word) for word in phrase.split())
    return re.compile(rf"\b{words}\b", re.IGNORECASE)


_PHRASE_PATTERNS = {
    phrase: _phrase_pattern(phrase) for group in WORDING.values() for phrase in group
}


def check(email: ParsedEmail) -> list[Finding]:
    """Look for pressure wording in the subject and the text body.

    Produces: urgency, threat, creds, money.

    One finding per group of phrases that matched, not one per phrase; the
    matched phrases are the evidence.
    """
    text = f"{email.subject}\n{strip_mime_artefacts(email.text_body)}"
    findings = []
    for code, phrases in WORDING.items():
        matched = [phrase for phrase in phrases if _PHRASE_PATTERNS[phrase].search(text)]
        if matched:
            evidence = ", ".join(f'"{phrase}"' for phrase in matched)
            findings.append(finding(CATEGORY, code, SEVERITY, REASONS[code], evidence))
    return findings


def strip_mime_artefacts(body: str) -> str:
    """Drop Content-* header lines and MIME boundary lines from a body."""
    kept = [
        line for line in body.splitlines() if not line.lower().startswith(_MIME_ARTEFACT_PREFIXES)
    ]
    return "\n".join(kept)
