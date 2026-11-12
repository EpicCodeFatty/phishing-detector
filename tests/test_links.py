"""Tests for the link checks."""

import pytest

from app.detector.checks import links
from app.detector.models import ParsedEmail
from tests.builders import codes_and_severities, make_email


def email_with_links(
    anchors: list[tuple[str, str]] | None = None, urls: list[str] | None = None
) -> ParsedEmail:
    """Return an email whose urls include every anchor href, as the parser guarantees."""
    anchors = anchors or []
    return make_email(anchors=anchors, urls=[href for _, href in anchors] + (urls or []))


@pytest.mark.parametrize(
    "anchors,urls,expected",
    [
        (
            [("www.paypal.com", "http://account-check.example.net/login")],
            [],
            ("href_mismatch_brand", "critical"),
        ),
        ([], ["http://192.0.2.7/login"], ("ip_url", "high")),
        (
            [("www.example.org", "https://tracker.example.net/c/1")],
            [],
            ("href_mismatch", "medium"),
        ),
        ([], ["http://xn--80ak6aa92e.com/"], ("punycode_url", "medium")),
        ([], ["https://bit.ly/3abcde"], ("shortener", "low")),
        ([], ["http://account-check.xyz/"], ("suspicious_tld", "low")),
    ],
)
def test_each_link_indicator_raises_exactly_one_finding(anchors, urls, expected):
    email = email_with_links(anchors, urls)

    findings = links.check(email)

    assert codes_and_severities(findings) == [expected]


@pytest.mark.parametrize(
    "anchor",
    [
        ("www.paypal.com", "https://www.paypal.com/signin"),
        ("example.org", "https://news.example.org/article"),
        ("Click here to read more", "https://example.org/article"),
        ("report.pdf", "https://example.org/files/report.pdf"),
        ("billing@example.org", "https://example.net/contact"),
    ],
)
def test_anchor_whose_text_and_href_agree_produces_no_finding(anchor):
    email = email_with_links([anchor])

    findings = links.check(email)

    assert findings == []


def test_brand_name_as_subdomain_of_another_domain_is_still_a_mismatch():
    email = email_with_links([("www.paypal.com", "https://login.paypal.com.evil.co.uk/")])

    findings = links.check(email)

    assert codes_and_severities(findings) == [("href_mismatch_brand", "critical")]


def test_brand_text_pointing_to_an_ip_address_is_compared_against_the_address():
    email = email_with_links([("www.paypal.com", "http://198.51.100.7/login")])

    findings = links.check(email)

    assert codes_and_severities(findings) == [
        ("href_mismatch_brand", "critical"),
        ("ip_url", "high"),
    ]
    assert findings[0].reason == "Link text shows www.paypal.com but points to 198.51.100.7"


def test_ordinary_text_pointing_to_a_brand_is_not_a_mismatch():
    email = email_with_links([("www.example.org", "https://www.google.com/maps")])

    findings = links.check(email)

    assert findings == []


def test_out_of_range_dotted_quad_is_not_an_ip_url():
    email = email_with_links(urls=["http://999.1.1.1/login"])

    findings = links.check(email)

    assert findings == []


def test_ipv6_literal_is_an_ip_url():
    email = email_with_links(urls=["http://[2001:db8::1]/login"])

    findings = links.check(email)

    assert codes_and_severities(findings) == [("ip_url", "high")]


def test_host_with_non_ascii_characters_is_a_punycode_url():
    email = email_with_links(urls=["http://p\N{CYRILLIC SMALL LETTER A}ypal.com/"])

    findings = links.check(email)

    assert codes_and_severities(findings) == [("punycode_url", "medium")]


def test_indicator_on_several_links_is_reported_once_with_the_first_as_evidence():
    urls = ["https://bit.ly/first", "https://tinyurl.com/second", "https://t.co/third"]
    email = email_with_links(urls=urls)

    findings = links.check(email)

    assert codes_and_severities(findings) == [("shortener", "low")]
    assert findings[0].evidence == "https://bit.ly/first"
    assert "3" in findings[0].reason


def test_single_link_reason_does_not_mention_a_count():
    email = email_with_links(urls=["https://bit.ly/only"])

    findings = links.check(email)

    assert "1" not in findings[0].reason


@pytest.mark.parametrize(
    "url",
    [
        "",
        "not a url",
        "mailto:dana@example.org",
        "http://",
        "http://[::1",
        "#top",
        "http://localhost/",
    ],
)
def test_url_that_cannot_be_evaluated_produces_no_finding(url):
    email = email_with_links([("www.paypal.com", url)])

    findings = links.check(email)

    assert findings == []
