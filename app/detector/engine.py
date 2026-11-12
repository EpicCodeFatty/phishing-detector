"""The engine's entry point: parse the email, run every check, score the findings.

analyze() is a pure function of its input. It makes no network calls, reads no
configuration and keeps no state, so the same bytes always give the same Result.
"""

from .checks import attachments, links, sender, wording
from .models import Finding, Result
from .parse import parse_email
from .scoring import build_result

# The registered checks, in the order their categories are reported. Adding a
# category of check means adding its module here and nowhere else.
CHECKS = (links.check, sender.check, wording.check, attachments.check)


def analyze(raw: bytes) -> Result:
    """Analyse the raw bytes of an email file and return the verdict.

    Findings come back in category order and, within a category, most severe
    first. Never raises: input that cannot be parsed yields a Result with
    whatever could still be checked.
    """
    email = parse_email(raw)
    findings: list[Finding] = []
    for check in CHECKS:
        findings.extend(_most_severe_first(check(email)))
    return build_result(findings)


def _most_severe_first(findings: list[Finding]) -> list[Finding]:
    # The sort is stable, so findings of equal severity keep the order of their check.
    return sorted(findings, key=lambda found: found.weight, reverse=True)
