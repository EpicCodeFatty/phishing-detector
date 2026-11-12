"""Link checks: where the links in an email really lead."""

import re
from dataclasses import replace

from ..lists import BRANDS, SHORTENERS, SUSPICIOUS_TLDS
from ..models import Finding, ParsedEmail, finding
from . import hostname_of, is_internationalized, is_ip_address, registrable_domain, top_level_domain

CATEGORY = "links"

# Severity per finding code, in the order findings of equal severity are reported.
SEVERITIES = {
    "href_mismatch_brand": "critical",
    "ip_url": "high",
    "href_mismatch": "medium",
    "punycode_url": "medium",
    "shortener": "low",
    "suspicious_tld": "low",
}

# Deliberately conservative: dot-separated labels ending in letters, not glued to a
# word or an email address. Whether the match is a real hostname is then decided by
# the Public Suffix List, which rules out lookalikes such as "report.pdf".
_HOSTNAME_IN_TEXT = re.compile(r"(?<![\w@.-])(?:[a-z0-9-]+\.)+[a-z]{2,}(?![\w-])", re.IGNORECASE)


def check(email: ParsedEmail) -> list[Finding]:
    """Inspect links in the message body.

    Produces: href_mismatch_brand, ip_url, href_mismatch, punycode_url,
    shortener, suspicious_tld.

    At most one finding per code; the first occurrence is reported as evidence
    and the reason mentions how many links triggered it.
    """
    hits = [hit for anchor in email.anchors if (hit := _mismatch_hit(anchor)) is not None]
    for url in email.urls:
        hits.extend(_url_hits(url))
    return _first_hit_per_code(hits)


def _found(code: str, reason: str, evidence: str) -> Finding:
    return finding(CATEGORY, code, SEVERITIES[code], reason, evidence)


def _mismatch_hit(anchor: tuple[str, str]) -> Finding | None:
    """Compare the hostname an anchor shows with the one it points to."""
    text, href = anchor
    shown_host = _hostname_in_text(text)
    target_host = hostname_of(href)
    if shown_host is None or target_host is None:
        return None

    shown = registrable_domain(shown_host)
    target = registrable_domain(target_host)
    if not target or shown == target:
        return None

    reason = f"Link text shows {shown_host} but points to {target_host}"
    if shown in BRANDS:
        return _found("href_mismatch_brand", reason, href)
    if target in BRANDS:
        return None
    return _found("href_mismatch", reason, href)


def _hostname_in_text(text: str) -> str | None:
    """Return the first hostname written in free text, or None if there is none."""
    for match in _HOSTNAME_IN_TEXT.finditer(text):
        host = match.group(0).lower()
        if registrable_domain(host):
            return host
    return None


def _url_hits(url: str) -> list[Finding]:
    """Return the findings one URL triggers on the strength of its host alone."""
    host = hostname_of(url)
    if host is None:
        return []
    # An address has no domain or suffix, so none of the remaining questions apply.
    if is_ip_address(host):
        return [_found("ip_url", "Link points to a raw IP address instead of a domain", url)]

    hits = []
    if is_internationalized(host):
        hits.append(_found("punycode_url", "Link uses an internationalised look-alike host", url))
    if registrable_domain(host) in SHORTENERS:
        hits.append(_found("shortener", "Link hides its destination behind a URL shortener", url))
    if top_level_domain(host) in SUSPICIOUS_TLDS:
        hits.append(_found("suspicious_tld", "Link uses a top-level domain common in abuse", url))
    return hits


def _first_hit_per_code(hits: list[Finding]) -> list[Finding]:
    """Keep one finding per code, so forty tracking links do not drown the report."""
    findings = []
    for code in SEVERITIES:
        matching = [hit for hit in hits if hit.code == code]
        if matching:
            findings.append(_with_count(matching[0], len(matching)))
    return findings


def _with_count(first: Finding, count: int) -> Finding:
    if count == 1:
        return first
    return replace(first, reason=f"{first.reason} (first of {count} such links)")
