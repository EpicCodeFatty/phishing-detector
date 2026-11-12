"""The four checks, one module per category, and the hostname helpers they share.

Every check module exposes check(email: ParsedEmail) -> list[Finding]. The link
and sender checks ask the same questions about hostnames, so those questions are
answered once, here.
"""

import ipaddress
from urllib.parse import urlsplit

import tldextract

# suffix_list_urls=() disables all network fetching; the Public Suffix List snapshot
# bundled with the package is used instead. Never call tldextract.extract() directly:
# that uses the default instance, which downloads the list on first use.
_extract = tldextract.TLDExtract(suffix_list_urls=())

PUNYCODE_PREFIX = "xn--"


def hostname_of(url: str) -> str | None:
    """Return the lowercased host of a URL, or None when it has none or is malformed."""
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    if not host:
        return None
    return host.rstrip(".") or None


def is_ip_address(host: str) -> bool:
    """Tell whether the host is a literal IPv4 or IPv6 address.

    Validated with ipaddress rather than a regex, so 999.1.1.1 is not an address.
    """
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def registrable_domain(host: str) -> str:
    """Return the domain a host was registered under, per the Public Suffix List.

    login.paypal.com.evil.co.uk gives evil.co.uk. An IP literal has no registrable
    domain, so the address itself is returned: it still identifies where a link
    points. Returns '' for a host with no public suffix, such as localhost.
    """
    host = host.strip().rstrip(".").lower()
    if is_ip_address(host):
        return host
    parts = _extract(host)
    if not parts.domain or not parts.suffix:
        return ""
    return f"{parts.domain}.{parts.suffix}"


def top_level_domain(host: str) -> str:
    """Return the last label of the host's public suffix: 'uk' for evil.co.uk."""
    return _extract(host.strip().rstrip(".").lower()).suffix.rpartition(".")[2]


def is_internationalized(host: str) -> bool:
    """Tell whether a host has non-ASCII characters or a punycode (xn--) label.

    Either form can render as a look-alike of an ASCII domain.
    """
    if not host.isascii():
        return True
    return any(label.startswith(PUNYCODE_PREFIX) for label in host.lower().split("."))
