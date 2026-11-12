"""Command-line entry point: analyse one email file and print the verdict.

    python detect.py samples/paypal-phish.eml
    python detect.py samples/paypal-phish.eml --json

The exit code carries the verdict, so the tool can be used in a pipeline:
0 for Safe, 1 for Suspicious, 2 for Phishing, 3 when the file could not be analysed.
"""

import argparse
import io
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import NoReturn

from app.detector import analyze
from app.detector.models import Finding, ParsedEmail, Result
from app.detector.parse import parse_email
from app.detector.scoring import MAX_SCORE, VERDICT_PHISHING, VERDICT_SAFE, VERDICT_SUSPICIOUS

EXIT_CODES = {VERDICT_SAFE: 0, VERDICT_SUSPICIOUS: 1, VERDICT_PHISHING: 2}
# Distinct from every verdict, so a pipeline never mistakes a failed run for a
# result. argparse's own default for usage errors is 2, which would read as Phishing.
EXIT_ERROR = 3

_LABEL_WIDTH = 10
_VERDICT_WIDTH = 11
_SEVERITY_WIDTH = 10
_CATEGORY_WIDTH = 15
_ABSENT = "(none)"
_JSON_INDENT = 2


class _Parser(argparse.ArgumentParser):
    """An argument parser that reports usage errors with EXIT_ERROR."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(EXIT_ERROR, f"{self.prog}: error: {message}\n")


def main(argv: list[str] | None = None) -> int:
    """Analyse the file named on the command line and return the exit code."""
    arguments = _parse_arguments(argv)
    try:
        raw = Path(arguments.path).read_bytes()
    except OSError as error:
        print(f"detect.py: cannot read {arguments.path}: {error.strerror}", file=sys.stderr)
        return EXIT_ERROR

    result = analyze(raw)
    if arguments.json:
        _write(json.dumps(asdict(result), indent=_JSON_INDENT))
    else:
        _write(format_report(arguments.path, parse_email(raw), result))
    return EXIT_CODES[result.verdict]


def format_report(path: str, email: ParsedEmail, result: Result) -> str:
    """Render the human-readable report: headers, verdict, findings, category scores."""
    verdict = f"{result.verdict.upper():<{_VERDICT_WIDTH}}({result.score}/{MAX_SCORE})"
    lines = [
        _labelled("File:", path),
        _labelled("From:", email.from_header or _ABSENT),
        _labelled("Subject:", email.subject or _ABSENT),
        "",
        _labelled("Verdict:", verdict),
        _labelled("Decided:", result.decided_by),
        "",
        *_finding_lines(result.findings),
        "",
        f"Category scores: {_category_summary(result)}",
    ]
    return "\n".join(lines)


def _parse_arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = _Parser(description="Score an email file for phishing indicators.")
    parser.add_argument("path", help="an .eml file, or a text file containing email content")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    return parser.parse_args(argv)


def _write(text: str) -> None:
    # The report quotes text from the email, which may hold characters the console's
    # encoding cannot represent. Escaping those beats crashing halfway through.
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(errors="backslashreplace")
    print(text)


def _labelled(label: str, value: str) -> str:
    return f"{label:<{_LABEL_WIDTH}}{_printable(value)}"


def _printable(text: str) -> str:
    """Escape control and text-direction characters taken from the email.

    Printed raw, they could repaint the terminal or reorder the line being read.
    """
    return "".join(
        character if character.isprintable() else character.encode("unicode_escape").decode()
        for character in text
    )


def _finding_lines(findings: list[Finding]) -> list[str]:
    if not findings:
        return ["No findings."]
    # A stable sort: findings of equal severity stay in category order.
    most_severe_first = sorted(findings, key=lambda found: found.weight, reverse=True)
    return [line for found in most_severe_first for line in _lines_for(found)]


def _lines_for(found: Finding) -> list[str]:
    category = f"[{found.category}]"
    headline = (
        f"{found.severity.upper():<{_SEVERITY_WIDTH}}"
        f"{category:<{_CATEGORY_WIDTH}}{_printable(found.reason)}"
    )
    # Evidence the reason already quotes would only repeat itself on the next line.
    if not found.evidence or found.evidence in found.reason:
        return [headline]
    indent = " " * (_SEVERITY_WIDTH + _CATEGORY_WIDTH)
    return [headline, f"{indent}{_printable(found.evidence)}"]


def _category_summary(result: Result) -> str:
    if not result.category_scores:
        return "none"
    return ", ".join(
        f"{category} {score}{_cap_note(result, category)}"
        for category, score in result.category_scores.items()
    )


def _cap_note(result: Result, category: str) -> str:
    uncapped = sum(found.weight for found in result.findings if found.category == category)
    return " (capped)" if uncapped > result.category_scores[category] else ""


if __name__ == "__main__":
    sys.exit(main())
