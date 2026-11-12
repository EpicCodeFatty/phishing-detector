"""Sender checks: whether the headers support who the email claims to be from."""

import re

from ..lists import (
    BRAND_OWNED,
    BRANDS,
    DIGRAPH_SUBSTITUTIONS,
    DOMAIN_TOKEN_DELIMITERS,
    KNOWN_LEGITIMATE,
    MAX_LOOKALIKE_EDIT_DISTANCE,
    MAX_LOOKALIKE_LENGTH_DIFFERENCE,
    MIN_LOOSE_MATCH_NAME_LENGTH,
    SUBSTITUTIONS,
)
from ..models import Finding, ParsedEmail, finding
from . import is_internationalized, registrable_domain

CATEGORY = "sender"

# Severity per finding code, in the order findings of equal severity are reported.
SEVERITIES = {
    "lookalike_domain": "critical",
    "lookalike_domain_fuzzy": "high",
    "brand_in_domain": "high",
    "display_name_spoof": "high",
    "dmarc_fail": "high",
    "non_ascii_domain": "high",
    "reply_to_mismatch": "medium",
    "spf_fail": "medium",
    "dkim_fail": "medium",
}

# The Authentication-Results token that signals each authentication failure.
AUTHENTICATION_TOKENS = {
    "dmarc_fail": "dmarc=fail",
    "spf_fail": "spf=fail",
    "dkim_fail": "dkim=fail",
}

# How each way of resembling a brand is described; {brand} is the brand's domain.
IMITATION_REASONS = {
    "lookalike_domain": "Domain imitates {brand} by character substitution",
    "lookalike_domain_fuzzy": "Domain is spelled almost like {brand}",
    "brand_in_domain": "Domain contains the name of {brand} but does not belong to it",
}

_TOKEN_DELIMITER = re.compile(f"[{re.escape(DOMAIN_TOKEN_DELIMITERS)}]")


def check(email: ParsedEmail) -> list[Finding]:
    """Inspect the headers that say who sent the message.

    Produces: lookalike_domain, lookalike_domain_fuzzy, brand_in_domain,
    display_name_spoof, dmarc_fail, non_ascii_domain, reply_to_mismatch, spf_fail,
    dkim_fail.

    Returns nothing for plain-text input, which has no headers to inspect.
    """
    if not email.has_headers:
        return []

    findings = [
        _imitation_finding(email),
        _display_name_finding(email),
        _authentication_finding(email, "dmarc_fail"),
        _non_ascii_finding(email),
        _reply_to_finding(email),
        _authentication_finding(email, "spf_fail"),
        _authentication_finding(email, "dkim_fail"),
    ]
    return [found for found in findings if found is not None]


def classify_domain(
    domain: str, brands: list[str], brand_owned: list[str]
) -> tuple[str, str, str] | None:
    """Return (code, severity, brand) or None.

    - known-legitimate, exact brand, or brand-owned domain -> None
    - imitation by character substitution                   -> lookalike_domain, critical
    - within two edits of a brand's domain                  -> lookalike_domain_fuzzy, high
    - brand name as a whole token of an unrelated domain    -> brand_in_domain, high

    A brand whose name is shorter than MIN_LOOSE_MATCH_NAME_LENGTH is matched by
    substitution only: "ups" is inside "groups" and two edits away from "usps".
    """
    candidate = domain.lower()
    if candidate in KNOWN_LEGITIMATE or candidate in brands or candidate in brand_owned:
        return None

    # paypa1.com normalizes to paypal.com: substitution, no innocent explanation.
    # Every brand is tried for it first, so that a weaker match against one brand
    # can never hide the conclusive match against another.
    normalized = undo_substitutions(candidate)
    for brand in brands:
        if _is_spelled_by_substitution(brand_name(brand), candidate, normalized):
            return _classified("lookalike_domain", brand)

    for brand in brands:
        name = brand_name(brand)
        if len(name) < MIN_LOOSE_MATCH_NAME_LENGTH:
            continue
        # payppal.com: probably a typo-squat, but chess.com is as close to chase.com
        if _is_near_spelling(normalized, brand):
            return _classified("lookalike_domain_fuzzy", brand)
        # paypal-secure.com: suspicious, but brands do own domains like this
        if name in domain_tokens(candidate):
            return _classified("brand_in_domain", brand)
    return None


def undo_substitutions(domain: str) -> str:
    """Replace look-alike characters with the letters they imitate: paypa1 -> paypal."""
    normalized = domain
    for imitation, letter in (DIGRAPH_SUBSTITUTIONS | SUBSTITUTIONS).items():
        normalized = normalized.replace(imitation, letter)
    return normalized


def domain_tokens(domain: str) -> list[str]:
    """Split a domain into its tokens: ['paypal', 'secure', 'com'] for paypal-secure.com."""
    return _TOKEN_DELIMITER.split(domain)


def edit_distance(first: str, second: str) -> int:
    """Return the Levenshtein distance between two strings.

    That is the fewest single-character insertions, deletions and replacements
    that turn one into the other. Computed one row of the table at a time.
    """
    previous = list(range(len(second) + 1))
    for row, first_character in enumerate(first, start=1):
        current = [row]
        for column, second_character in enumerate(second, start=1):
            replacement = previous[column - 1] + (first_character != second_character)
            current.append(min(previous[column] + 1, current[column - 1] + 1, replacement))
        previous = current
    return previous[-1]


def _is_spelled_by_substitution(name: str, candidate: str, normalized: str) -> bool:
    """Tell whether undoing the look-alike characters is what produces the brand name.

    The name has to be absent before and present after. paypa1.com qualifies;
    paypal-24.com does not, because its digits are not standing in for letters
    of the name, and it is left to the weaker containment rule.
    """
    if len(name) >= MIN_LOOSE_MATCH_NAME_LENGTH:
        return name in normalized and name not in candidate
    # A short name must also come out as a whole token: up5.com spells ups, while
    # group5.com merely contains those letters once the 5 is undone.
    return name in domain_tokens(normalized) and name not in domain_tokens(candidate)


def _is_near_spelling(normalized: str, brand: str) -> bool:
    # The length test is implied by the distance test; it is here to skip the
    # distance calculation for the many domains that cannot possibly match.
    if abs(len(normalized) - len(brand)) > MAX_LOOKALIKE_LENGTH_DIFFERENCE:
        return False
    return edit_distance(normalized, brand) <= MAX_LOOKALIKE_EDIT_DISTANCE


def brand_name(brand: str) -> str:
    """Return the name part of a brand's domain: 'paypal' for 'paypal.com'."""
    return brand.split(".")[0]


def _classified(code: str, brand: str) -> tuple[str, str, str]:
    return (code, SEVERITIES[code], brand)


def _found(code: str, reason: str, evidence: str) -> Finding:
    return finding(CATEGORY, code, SEVERITIES[code], reason, evidence)


def _sender_host(email: ParsedEmail) -> str:
    return email.from_address.rpartition("@")[2]


def _sender_domain(email: ParsedEmail) -> str:
    return registrable_domain(_sender_host(email))


def _imitation_finding(email: ParsedEmail) -> Finding | None:
    domain = _sender_domain(email)
    if not domain:
        return None
    classification = classify_domain(domain, BRANDS, BRAND_OWNED)
    if classification is None:
        return None

    code, _, brand = classification
    return _found(code, IMITATION_REASONS[code].format(brand=brand), domain)


def _display_name_finding(email: ParsedEmail) -> Finding | None:
    domain = _sender_domain(email)
    if not domain:
        return None
    named_brands = [brand for brand in BRANDS if _names_brand(email.from_display, brand)]
    if not named_brands:
        return None
    if domain in named_brands or domain in BRAND_OWNED:
        return None

    reason = f"Display name claims {named_brands[0]}, domain does not belong to it"
    return _found("display_name_spoof", reason, email.from_display)


def _names_brand(display_name: str, brand: str) -> bool:
    """Tell whether the display name mentions the brand as a word of its own.

    Bare substring matching would find "ups" in "Groups" and "apple" in "Appleton".
    """
    as_word = rf"(?<![a-z]){re.escape(brand_name(brand))}(?![a-z])"
    return re.search(as_word, display_name.lower()) is not None


def _authentication_finding(email: ParsedEmail, code: str) -> Finding | None:
    token = AUTHENTICATION_TOKENS[code]
    if token not in email.auth_results.lower():
        return None
    return _found(code, f"{token} in Authentication-Results", token)


def _non_ascii_finding(email: ParsedEmail) -> Finding | None:
    host = _sender_host(email)
    if not is_internationalized(host):
        return None
    reason = "Sender domain uses non-ASCII or punycode characters that can mimic another domain"
    return _found("non_ascii_domain", reason, host)


def _reply_to_finding(email: ParsedEmail) -> Finding | None:
    domain = _sender_domain(email)
    if not domain:
        return None
    for header, address in (("Reply-To", email.reply_to), ("Return-Path", email.return_path)):
        other = registrable_domain(address.rpartition("@")[2])
        if other and other != domain:
            return _found("reply_to_mismatch", _reply_to_reason(header, other), address)
    return None


def _reply_to_reason(header: str, domain: str) -> str:
    if header == "Reply-To":
        return f"Replies would go to {domain}"
    return f"Return-Path belongs to {domain}, not to the sender's domain"
