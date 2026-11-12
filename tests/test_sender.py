"""Tests for the sender checks."""

import pytest

from app.detector.checks import sender
from app.detector.checks.sender import classify_domain, edit_distance
from app.detector.lists import BRAND_OWNED, BRANDS, KNOWN_LEGITIMATE
from tests.builders import codes_and_severities, make_email


@pytest.mark.parametrize(
    "domain,expected_code",
    [
        ("paypal.com", None),
        ("PayPal.com", None),
        ("paypalobjects.com", None),
        ("example.org", None),
        # A look-alike character standing in for a letter of the brand name.
        ("paypa1.com", "lookalike_domain"),
        ("rnicrosoft.com", "lookalike_domain"),
        ("paypa1-secure.com", "lookalike_domain"),
        # A spelling within two edits: a likely typo-squat, or an unrelated word.
        ("payppal.com", "lookalike_domain_fuzzy"),
        ("micosoft.com", "lookalike_domain_fuzzy"),
        ("paypal.co", "lookalike_domain_fuzzy"),
        ("chasm.com", "lookalike_domain_fuzzy"),
        ("goggle.com", "lookalike_domain_fuzzy"),
        ("paypal-secure.com", "brand_in_domain"),
        ("paypal.net", "brand_in_domain"),
        # A digit that is not standing in for a letter of the name proves nothing.
        ("paypal-24.com", "brand_in_domain"),
        ("amazon-web1.com", "brand_in_domain"),
        # A brand name only counts as a whole token, not as part of a longer word.
        ("pineapple.com", None),
        ("mypaypalstore.com", None),
        # Short brand names are matched by exact substitution only.
        ("up5.com", "lookalike_domain"),
        ("dh1-express.com", "lookalike_domain"),
        ("dhl-express.com", None),
        ("group5.com", None),
        ("startups2024.com", None),
        # Real domains the previous similarity ratio mistook for brands.
        ("usps.com", None),
        ("mail.com", None),
        ("groups.io", None),
        ("gmail.com", None),
    ],
)
def test_classify_domain(domain, expected_code):
    classification = classify_domain(domain, BRANDS, BRAND_OWNED)

    code = classification[0] if classification else None
    assert code == expected_code


def test_known_legitimate_domain_is_cleared_before_any_brand_comparison(monkeypatch):
    monkeypatch.setattr(sender, "KNOWN_LEGITIMATE", ["paypa1.com"])

    classification = classify_domain("paypa1.com", BRANDS, BRAND_OWNED)

    assert classification is None


@pytest.mark.parametrize("domain", KNOWN_LEGITIMATE)
def test_known_legitimate_sender_produces_no_finding(domain):
    email = make_email(from_address=f"news@{domain}", return_path=f"bounce@{domain}")

    findings = sender.check(email)

    assert findings == []


def test_known_legitimate_list_covers_the_reported_false_positives():
    assert {"usps.com", "mail.com", "groups.io"} <= set(KNOWN_LEGITIMATE)


@pytest.mark.parametrize("domain", ["chess.com", "apply.com"])
def test_real_word_on_the_allowlist_produces_no_finding(domain):
    email = make_email(from_address=f"hello@{domain}")

    findings = sender.check(email)

    assert findings == []


@pytest.mark.parametrize(
    "domain,brand",
    [
        ("payppal.com", "paypal.com"),
        # A real typo-squat of google.com, kept off the allowlist on purpose.
        ("goggle.com", "google.com"),
    ],
)
def test_near_spelling_off_the_allowlist_is_a_fuzzy_lookalike_at_high(domain, brand):
    email = make_email(from_address=f"help@{domain}")

    findings = sender.check(email)

    assert codes_and_severities(findings) == [("lookalike_domain_fuzzy", "high")]
    assert findings[0].reason == f"Domain is spelled almost like {brand}"


def test_typo_squat_is_not_on_the_allowlist():
    assert "goggle.com" not in KNOWN_LEGITIMATE


def test_character_substitution_is_a_lookalike_at_critical():
    email = make_email(from_address="help@paypa1.com")

    findings = sender.check(email)

    assert codes_and_severities(findings) == [("lookalike_domain", "critical")]
    assert findings[0].reason == "Domain imitates paypal.com by character substitution"


@pytest.mark.parametrize(
    "first,second,expected",
    [
        ("", "", 0),
        ("paypal", "paypal", 0),
        ("payppal", "paypal", 1),
        ("paypal", "paypa", 1),
        ("chess", "chase", 2),
        ("kitten", "sitting", 3),
        ("", "abc", 3),
    ],
)
def test_edit_distance(first, second, expected):
    assert edit_distance(first, second) == expected
    assert edit_distance(second, first) == expected


@pytest.mark.parametrize(
    "domain,expected",
    [
        ("paypa1.com", ("lookalike_domain", "critical", "paypal.com")),
        ("payppal.com", ("lookalike_domain_fuzzy", "high", "paypal.com")),
        ("paypal-secure.com", ("brand_in_domain", "high", "paypal.com")),
    ],
)
def test_classify_domain_reports_severity_and_the_imitated_brand(domain, expected):
    classification = classify_domain(domain, BRANDS, BRAND_OWNED)

    assert classification == expected


@pytest.mark.parametrize(
    "fields,expected",
    [
        ({"from_address": "help@paypa1.com"}, ("lookalike_domain", "critical")),
        ({"from_address": "help@micosoft.com"}, ("lookalike_domain_fuzzy", "high")),
        ({"from_address": "billing@paypal-secure.com"}, ("brand_in_domain", "high")),
        ({"from_display": "PayPal Support"}, ("display_name_spoof", "high")),
        ({"auth_results": "mx.example.org; dmarc=fail"}, ("dmarc_fail", "high")),
        ({"from_address": "dana@xn--80ak6aa92e.com"}, ("non_ascii_domain", "high")),
        ({"reply_to": "dana@example.net"}, ("reply_to_mismatch", "medium")),
        ({"return_path": "bounce@example.net"}, ("reply_to_mismatch", "medium")),
        ({"auth_results": "mx.example.org; spf=fail"}, ("spf_fail", "medium")),
        ({"auth_results": "mx.example.org; dkim=fail"}, ("dkim_fail", "medium")),
    ],
)
def test_each_sender_indicator_raises_exactly_one_finding(fields, expected):
    email = make_email(**fields)

    findings = sender.check(email)

    assert codes_and_severities(findings) == [expected]


@pytest.mark.parametrize(
    "fields",
    [
        {"from_address": "service@paypal.com"},
        {"from_address": "service@mail.paypal.com"},
        {"from_address": "images@paypalobjects.com"},
        {"from_display": "PayPal", "from_address": "service@paypal.com"},
        {"from_display": "Groups Digest"},
        {"reply_to": "dana@mail.example.org", "return_path": "bounce@example.org"},
        {"auth_results": "mx.example.org; spf=pass; dkim=pass; dmarc=pass"},
        {"auth_results": "mx.example.org; spf=softfail"},
    ],
)
def test_legitimate_sender_produces_no_finding(fields):
    email = make_email(**fields)

    findings = sender.check(email)

    assert findings == []


def test_email_without_headers_produces_no_finding():
    email = make_email(from_address="help@paypa1.com", has_headers=False)

    findings = sender.check(email)

    assert findings == []


def test_sender_domain_with_non_ascii_characters_is_flagged():
    email = make_email(from_address="help@p\N{CYRILLIC SMALL LETTER A}ypal.com")

    findings = sender.check(email)

    assert ("non_ascii_domain", "high") in codes_and_severities(findings)


def test_reply_to_mismatch_names_the_domain_replies_would_reach():
    email = make_email(reply_to="recovery@mail-reset.xyz")

    findings = sender.check(email)

    assert findings[0].reason == "Replies would go to mail-reset.xyz"
    assert findings[0].evidence == "recovery@mail-reset.xyz"


def test_authentication_failures_are_matched_case_insensitively():
    email = make_email(auth_results="mx.example.org; DMARC=FAIL")

    findings = sender.check(email)

    assert codes_and_severities(findings) == [("dmarc_fail", "high")]


@pytest.mark.parametrize("address", ["", "not-an-address", "dana@", "@", "dana@localhost"])
def test_sender_address_that_cannot_be_evaluated_produces_no_finding(address):
    email = make_email(from_address=address, from_display="PayPal", reply_to="x@example.net")

    findings = sender.check(email)

    assert findings == []
