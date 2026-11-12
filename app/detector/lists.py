"""Every list and threshold the checks judge an email by.

Keeping them in one module means the engine's judgement can be reviewed, and
tuned, without reading any logic.
"""

# Registrable domains of brands commonly impersonated in phishing.
# gmail.com is deliberately absent: genuine Gmail mail is far too common for the
# name to count as a sign of impersonation, and Google is covered by google.com.
BRANDS = [
    "paypal.com",
    "microsoft.com",
    "office365.com",
    "apple.com",
    "amazon.com",
    "google.com",
    "netflix.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "dropbox.com",
    "adobe.com",
    "docusign.com",
    "fedex.com",
    "dhl.com",
    "ups.com",
    "chase.com",
    "wellsfargo.com",
    "bankofamerica.com",
]

# Domains that genuinely belong to the brands above. Without this list, legitimate
# mail from paypalobjects.com would be flagged as a brand name inside another domain.
BRAND_OWNED = [
    "paypalobjects.com",
    "microsoftonline.com",
    "office.com",
    "outlook.com",
    "googlemail.com",
    "googleusercontent.com",
    "amazonses.com",
    "amazonaws.com",
    "icloud.com",
    "fb.com",
]

# Real, unrelated domains that happen to resemble a brand. Checked before any brand
# comparison, so the resemblance can never be held against them. The list handles
# the common collisions and is not exhaustive: an ordinary word a letter or two away
# from a brand cannot be told from a typo-squat by spelling alone.
KNOWN_LEGITIMATE = [
    "usps.com",
    "mail.com",
    "groups.io",
    "chess.com",
    "phase.com",
    "ripple.com",
    "maple.com",
    "apply.com",
    "amazing.com",
    "index.com",
    "abode.com",
]

# Link-shortening services, which hide the real destination of a link.
SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
]

# Suffixes over-represented in abuse reporting relative to their size.
SUSPICIOUS_TLDS = [
    "zip",
    "mov",
    "xyz",
    "top",
    "click",
    "country",
    "gq",
    "cf",
    "tk",
    "ml",
    "work",
    "fit",
    "review",
]

# Extensions that execute code when opened.
DANGEROUS_EXT = [
    "exe",
    "scr",
    "com",
    "pif",
    "bat",
    "cmd",
    "js",
    "jse",
    "vbs",
    "vbe",
    "wsf",
    "wsh",
    "hta",
    "lnk",
    "iso",
    "img",
    "jar",
    "msi",
    "ps1",
]

# Office formats that are allowed to contain macros.
MACRO_EXT = ["docm", "xlsm", "pptm", "dotm", "xltm", "potm"]

# Pressure wording, grouped by the lever it pulls. Each entry is matched as a
# whole phrase, case-insensitively.
WORDING = {
    "urgency": [
        "urgent",
        "immediately",
        "right away",
        "within 24 hours",
        "expires today",
        "final notice",
        "act now",
        "last warning",
    ],
    "threat": [
        "suspended",
        "locked",
        "disabled",
        "unusual activity",
        "unauthorized access",
        "will be closed",
        "terminated",
    ],
    "creds": [
        "verify your account",
        "confirm your password",
        "update your details",
        "sign in to continue",
        "validate your identity",
        "re-enter your",
    ],
    "money": [
        "invoice attached",
        "payment failed",
        "gift card",
        "wire transfer",
        "refund",
        "outstanding balance",
        "billing problem",
    ],
}

# Character substitutions used to make a domain look like a brand.
SUBSTITUTIONS = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"}

# Letter pairs that read as a single different letter at a glance: rnicrosoft.com.
DIGRAPH_SUBSTITUTIONS = {"rn": "m"}

# Brand names shorter than this ("ups", "dhl") turn up inside ordinary words and sit
# within two edits of many real names, so they are matched by exact substitution only.
MIN_LOOSE_MATCH_NAME_LENGTH = 5

# A domain within this many single-character edits of a brand's domain, and within
# this difference in length, counts as a deliberate near-spelling: payppal.com.
MAX_LOOKALIKE_EDIT_DISTANCE = 2
MAX_LOOKALIKE_LENGTH_DIFFERENCE = 2

# Characters that separate the tokens of a domain: paypal-secure.com is paypal, secure, com.
DOMAIN_TOKEN_DELIMITERS = "-._"

# File signatures, mapped to the extensions they are consistent with.
MAGIC = {
    b"MZ": ["exe", "dll", "scr", "com"],
    b"%PDF": ["pdf"],
    # ZIP containers: plain archives, every Office Open XML format, and OpenDocument.
    b"PK\x03\x04": [
        "zip",
        "jar",
        "docx",
        "docm",
        "dotx",
        "dotm",
        "xlsx",
        "xlsm",
        "xltx",
        "xltm",
        "xlsb",
        "xlam",
        "pptx",
        "pptm",
        "potx",
        "potm",
        "ppsx",
        "ppsm",
        "ppam",
        "sldx",
        "sldm",
        "odt",
        "ods",
        "odp",
    ],
    b"\xd0\xcf\x11\xe0": ["doc", "xls", "ppt", "msi"],
    b"\x89PNG": ["png"],
    b"\xff\xd8\xff": ["jpg", "jpeg"],
    b"GIF8": ["gif"],
    b"Rar!": ["rar"],
    b"7z\xbc\xaf": ["7z"],
}
