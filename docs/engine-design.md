# Detection engine — design specification

This document specifies the phishing detection engine: its data model, the four groups of checks, and
how findings are turned into a verdict. It is the reference for the implementation in `app/detector/`.

The engine is a pure function. It takes the raw bytes of an email file and returns a result object.
It performs no network calls, reads no configuration from the environment, and holds no state. The
same input always produces the same output, which is what makes it testable and what makes the demo
independent of any third party being reachable.

---

## 1. Module layout

```
app/
├── detector/
│   ├── __init__.py          exports analyze()
│   ├── models.py            ParsedEmail, Finding, Result
│   ├── parse.py             raw bytes -> ParsedEmail
│   ├── lists.py             brands, allowlists, keyword lists, extension lists
│   ├── scoring.py           findings -> Result
│   ├── engine.py            analyze(): parse, run checks, score
│   └── checks/
│       ├── __init__.py
│       ├── links.py
│       ├── sender.py
│       ├── wording.py
│       └── attachments.py
└── requirements.txt
detect.py                    command-line entry point
tests/                       pytest suite
samples/                     .eml and .txt fixtures
```

Each check module exposes one function with the signature `check(email: ParsedEmail) -> list[Finding]`.
Adding a new category of check means adding a module and registering it in `engine.py`; nothing else
changes.

---

## 2. Dependencies

Runtime (`app/requirements.txt`, pinned):

- `tldextract` — splits a hostname into subdomain / domain / suffix using the Public Suffix List.
  Needed because naive string matching gets `login.paypal.com.evil.co.uk` wrong: the registrable
  domain there is `evil.co.uk`, not `paypal.com`.
- `beautifulsoup4` — extracts anchors from the HTML part of an email.

Development only: `pytest`.

Everything else comes from the standard library: `email`, `re`, `ipaddress`, `urllib.parse`,
`difflib`, `zipfile`, `hashlib`.

### Important: tldextract must not download anything at runtime

By default `tldextract` fetches the Public Suffix List over the network on first use and caches it.
On an EC2 instance that is a network call during a request, and a failure mode in the demo.

Construct one module-level extractor that uses the snapshot bundled with the package:

```python
import tldextract

# suffix_list_urls=() disables all network fetching; the bundled snapshot is used.
_extract = tldextract.TLDExtract(suffix_list_urls=())
```

Use `_extract(host)` everywhere. Do not call `tldextract.extract()` directly, because that uses the
default, network-enabled instance.

---

## 3. Data model (`models.py`)

Three frozen dataclasses.

```python
from dataclasses import dataclass, field

@dataclass
class Attachment:
    filename: str
    content_type: str          # as declared in the MIME headers
    size: int                  # bytes
    head: bytes                # first 8 bytes, for magic-number checks
    payload: bytes             # full bytes, needed to inspect Office archives

@dataclass
class ParsedEmail:
    from_header: str           # raw From: header, e.g. '"PayPal" <help@paypa1.com>'
    from_display: str          # display name only, e.g. 'PayPal'
    from_address: str          # address only, e.g. 'help@paypa1.com'
    reply_to: str              # address only, '' if absent
    return_path: str           # address only, '' if absent
    subject: str
    auth_results: str          # raw Authentication-Results header, '' if absent
    text_body: str             # text/plain part, or HTML stripped to text if no plain part
    html_body: str             # text/html part, '' if absent
    urls: list[str]            # every URL found, from both HTML hrefs and plain text
    anchors: list[tuple[str, str]]   # (visible_text, href) pairs from the HTML part
    attachments: list[Attachment]
    has_headers: bool          # False when the input was plain text with no email headers

@dataclass
class Finding:
    category: str              # "links" | "sender" | "wording" | "attachments"
    code: str                  # stable identifier, e.g. "ip_url"
    severity: str              # "critical" | "high" | "medium" | "low"
    weight: int                # derived from severity, see scoring.py
    reason: str                # one human-readable sentence
    evidence: str = ""         # the exact thing that matched

@dataclass
class Result:
    score: int                 # 0-100
    verdict: str               # "Safe" | "Suspicious" | "Phishing"
    decided_by: str            # why the verdict came out this way, see scoring.py
    findings: list[Finding]
    category_scores: dict[str, int]
```

`Finding.weight` is never passed by hand. Provide a constructor helper so that severity and weight can
never disagree:

```python
SEVERITY_WEIGHT = {"critical": 40, "high": 25, "medium": 15, "low": 5}

def finding(category, code, severity, reason, evidence=""):
    return Finding(category, code, severity, SEVERITY_WEIGHT[severity], reason, evidence)
```

---

## 4. Parsing (`parse.py`)

One public function:

```python
def parse_email(raw: bytes) -> ParsedEmail
```

Use `email.message_from_bytes(raw, policy=email.policy.default)`. The modern policy decodes headers
and handles MIME properly; the legacy default does not.

Rules:

1. **Addresses.** Parse `From`, `Reply-To` and `Return-Path` with `email.utils.parseaddr`, which
   returns `(display_name, address)`. Lowercase the address; keep the display name as written.
2. **Bodies.** Walk the parts. Take the first `text/plain` as `text_body` and the first `text/html` as
   `html_body`. If there is no plain part, derive `text_body` from the HTML with BeautifulSoup's
   `get_text()`.
3. **Anchors.** From the HTML part, collect every `<a>` as `(a.get_text(strip=True), a["href"])`.
   The visible text matters: a link reading `www.paypal.com` that points somewhere else is the single
   strongest indicator in the whole engine.
4. **URLs.** Collect every anchor href, plus every URL found in the plain text with a regex. Deduplicate
   while preserving order.
5. **Attachments.** A part is an attachment when `part.get_filename()` is not `None`, or when the
   `Content-Disposition` is `attachment`. Record the declared content type, the decoded size, the first
   8 bytes, and the full payload.
6. **Plain-text input.** The assignment says the script accepts "a text file containing email content",
   so a file with no headers at all must work. Detect this: if the parsed message has no `From` and no
   `Subject`, set `has_headers = False` and treat the entire content as `text_body`. The sender checks
   then produce no findings, and the link, wording and attachment checks still run.
7. **Never raise.** Malformed input, wrong encodings and truncated MIME are expected. Wrap decoding in
   `try/except` and fall back to `errors="replace"`. A parse failure must degrade to a partially filled
   `ParsedEmail`, not an exception.

---

## 5. Lists (`lists.py`)

All constants live here, with a one-line comment explaining each list's purpose. Keeping them in one
module means the engine's judgement can be reviewed without reading any logic.

```python
# Registrable domains of brands commonly impersonated in phishing.
BRANDS = [
    "paypal.com", "microsoft.com", "office365.com", "apple.com", "amazon.com",
    "google.com", "gmail.com", "netflix.com", "facebook.com", "instagram.com",
    "linkedin.com", "dropbox.com", "adobe.com", "docusign.com", "fedex.com",
    "dhl.com", "ups.com", "chase.com", "wellsfargo.com", "bankofamerica.com",
]

# Domains that genuinely belong to the brands above. Without this list, legitimate
# mail from paypalobjects.com would be flagged as a brand name inside another domain.
BRAND_OWNED = [
    "paypalobjects.com", "microsoftonline.com", "office.com", "outlook.com",
    "googlemail.com", "googleusercontent.com", "amazonses.com", "amazonaws.com",
    "icloud.com", "fb.com",
]

SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
              "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"]

# Suffixes over-represented in abuse reporting relative to their size.
SUSPICIOUS_TLDS = ["zip", "mov", "xyz", "top", "click", "country", "gq", "cf",
                   "tk", "ml", "work", "fit", "review"]

# Extensions that execute code when opened.
DANGEROUS_EXT = ["exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs",
                 "vbe", "wsf", "wsh", "hta", "lnk", "iso", "img", "jar", "msi", "ps1"]

# Office formats that are allowed to contain macros.
MACRO_EXT = ["docm", "xlsm", "pptm", "dotm", "xltm", "potm"]

# Pressure wording, grouped by the lever it pulls. Each entry is matched as a
# whole phrase, case-insensitively.
WORDING = {
    "urgency": ["urgent", "immediately", "right away", "within 24 hours",
                "expires today", "final notice", "act now", "last warning"],
    "threat":  ["suspended", "locked", "disabled", "unusual activity",
                "unauthorized access", "will be closed", "terminated"],
    "creds":   ["verify your account", "confirm your password", "update your details",
                "sign in to continue", "validate your identity", "re-enter your"],
    "money":   ["invoice attached", "payment failed", "gift card", "wire transfer",
                "refund", "outstanding balance", "billing problem"],
}

# Character substitutions used to make a domain look like a brand.
SUBSTITUTIONS = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"}

# File signatures, mapped to the extensions they are consistent with.
MAGIC = {
    b"MZ":               ["exe", "dll", "scr", "com"],
    b"%PDF":             ["pdf"],
    b"PK\x03\x04":       ["zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "jar", "odt"],
    b"\xd0\xcf\x11\xe0": ["doc", "xls", "ppt", "msi"],
    b"\x89PNG":          ["png"],
    b"\xff\xd8\xff":     ["jpg", "jpeg"],
    b"GIF8":             ["gif"],
    b"Rar!":             ["rar"],
    b"7z\xbc\xaf":       ["7z"],
}
```

---

## 6. Checks

Every check returns a list of findings. A check never raises: if it cannot evaluate something, it
returns nothing for it.

### 6.1 Links (`checks/links.py`)

Operates on `email.anchors` and `email.urls`.

| code | severity | condition |
|---|---|---|
| `href_mismatch_brand` | critical | the anchor's visible text contains a hostname whose registrable domain is in `BRANDS`, and the href's registrable domain is different |
| `ip_url` | high | the href's host is a literal IPv4 or IPv6 address |
| `href_mismatch` | medium | the anchor's visible text contains a hostname, and the href's registrable domain differs from it, but neither is a brand |
| `punycode_url` | medium | the host starts with `xn--`, or contains non-ASCII characters |
| `shortener` | low | the registrable domain is in `SHORTENERS` |
| `suspicious_tld` | low | the suffix is in `SUSPICIOUS_TLDS` |

Implementation notes:

- Extract the host with `urllib.parse.urlsplit(href).hostname`.
- Test for an IP literal with `ipaddress.ip_address(host)` inside a `try/except ValueError`. Do not use
  a regex: `999.1.1.1` must not count as an IP address.
- For a host that is an IP literal, the "registrable domain" is the address itself. Guard against this
  when comparing domains, or the comparison produces nonsense.
- The visible text of an anchor is free text. Look for a hostname inside it with a conservative regex
  and only then compare. If there is no hostname in the text, there is no mismatch to report.
- Emit at most one finding per code per email, even when several links trigger it. Report the first
  occurrence as evidence and mention the count in `reason` when it is greater than one. Otherwise an
  email with forty tracking links drowns the output.

### 6.2 Sender (`checks/sender.py`)

Operates on the headers. Produces nothing when `has_headers` is `False`.

| code | severity | condition |
|---|---|---|
| `lookalike_domain` | critical | the sender's registrable domain imitates a brand by character substitution or by a one-or-two character difference |
| `brand_in_domain` | high | the sender's registrable domain contains a brand name but is not that brand and is not in `BRAND_OWNED` |
| `display_name_spoof` | high | the display name contains a brand name while the sender domain is not that brand's |
| `dmarc_fail` | high | `Authentication-Results` contains `dmarc=fail` |
| `non_ascii_domain` | high | the sender domain contains non-ASCII characters or starts with `xn--` |
| `reply_to_mismatch` | medium | `Reply-To` or `Return-Path` has a different registrable domain from `From` |
| `spf_fail` | medium | `Authentication-Results` contains `spf=fail` |
| `dkim_fail` | medium | `Authentication-Results` contains `dkim=fail` |

The domain classifier is the most important piece of logic in the engine. It must distinguish three
cases, because they carry different weight:

```python
from difflib import SequenceMatcher

def classify_domain(domain: str, brands: list[str], brand_owned: list[str]):
    """Return (code, severity, brand) or None.

    - exact brand, or a known brand-owned domain -> None
    - imitation by substitution or near-spelling  -> lookalike_domain, critical
    - brand name inside an unrelated domain       -> brand_in_domain, high
    """
    d = domain.lower()
    if d in brands or d in brand_owned:
        return None

    normalized = d.replace("rn", "m")
    for src, dst in SUBSTITUTIONS.items():
        normalized = normalized.replace(src, dst)

    for brand in brands:
        name = brand.split(".")[0]          # "paypal"
        # paypa1.com normalizes to paypal.com: substitution, no innocent explanation
        if normalized != d and name in normalized:
            return ("lookalike_domain", "critical", brand)
        # payppal.com: a typo-squat, close enough that it is deliberate
        if SequenceMatcher(None, normalized, brand).ratio() >= 0.85:
            return ("lookalike_domain", "critical", brand)
        # paypal-secure.com: suspicious, but brands do own domains like this
        if name in d:
            return ("brand_in_domain", "high", brand)
    return None
```

Rationale for the split: `paypa1` has no innocent explanation, because nobody registers a digit-for-letter
variant of someone else's brand by accident. `paypal-secure.com` is suspicious but the shape is one that
real companies use, which is why it is high rather than critical and why `BRAND_OWNED` exists.

Note the ordering: check substitution before plain containment, or `paypa1-secure.com` is reported as
the weaker `brand_in_domain`.

### 6.3 Wording (`checks/wording.py`)

Operates on `subject` and `text_body`.

- Match each phrase from `WORDING` case-insensitively as a whole phrase.
- Emit one finding per *category* that matched, not one per phrase, with the matched phrases as evidence.
  Codes: `urgency`, `threat`, `creds`, `money`. All `low`.
- Before matching, strip MIME artefacts from the body: lines starting with `Content-` and MIME boundary
  lines beginning with `--`. Without this, an attachment named `invoice.pdf` makes the body match
  "invoice attached" even when no such text exists.

Wording alone must never reach a verdict above Safe. This is enforced in scoring, not here.

### 6.4 Attachments (`checks/attachments.py`)

| code | severity | condition |
|---|---|---|
| `dangerous_ext` | critical | the final extension is in `DANGEROUS_EXT` |
| `type_mismatch` | critical | the file's magic bytes identify a type inconsistent with its extension |
| `double_ext` | high | the filename has two or more extensions and the last one is dangerous, e.g. `invoice.pdf.exe` |
| `macro_ext` | high | the extension is in `MACRO_EXT` |
| `macro_inside` | high | the file is a ZIP container (Office format) holding `vbaProject.bin` |

Implementation notes:

- Normalise the filename first: strip whitespace, strip right-to-left override characters (`‮`),
  lowercase it. The RLO trick renders `invoice‮gpj.exe` as `invoice exe.jpg` to the reader.
- For `type_mismatch`, look up the longest matching prefix in `MAGIC`. If the extension is absent from
  that signature's list, report it. If the signature is unknown, report nothing: an unrecognised file
  type is not evidence of anything.
- For `macro_inside`, open the payload with `zipfile.ZipFile(io.BytesIO(payload))` and look for an entry
  named `vbaProject.bin`. Wrap it in `try/except zipfile.BadZipFile`. Do not extract anything.
- Never write an attachment to disk and never execute one. The engine only reads bytes in memory.

---

## 7. Scoring (`scoring.py`)

Two layers. Severity rules decide first; the additive score only decides when no rule fires.

```python
SEVERITY_WEIGHT = {"critical": 40, "high": 25, "medium": 15, "low": 5}
CATEGORY_CAP = {"wording": 15}
THRESHOLDS = {"phishing": 60, "suspicious": 30}

def build_result(findings: list[Finding]) -> Result:
    per_category = {}
    for f in findings:
        per_category[f.category] = per_category.get(f.category, 0) + f.weight
    for category, cap in CATEGORY_CAP.items():
        if category in per_category:
            per_category[category] = min(per_category[category], cap)

    score = min(100, sum(per_category.values()))
    decided_by = "cumulative score"

    severities = [f.severity for f in findings]
    n_critical = severities.count("critical")
    n_high = severities.count("high")

    if n_critical:
        score = max(score, THRESHOLDS["phishing"])
        decided_by = f"{n_critical} critical finding(s)"
    elif n_high >= 2:
        score = max(score, THRESHOLDS["phishing"])
        decided_by = f"{n_high} high-severity findings"
    elif n_high == 1 and score < THRESHOLDS["suspicious"]:
        score = THRESHOLDS["suspicious"]
        decided_by = "one high-severity finding"

    verdict = ("Phishing"   if score >= THRESHOLDS["phishing"]
               else "Suspicious" if score >= THRESHOLDS["suspicious"]
               else "Safe")

    return Result(score=score, verdict=verdict, decided_by=decided_by,
                  findings=findings, category_scores=per_category)
```

Why two layers rather than a single sum: a purely additive score is too forgiving of one decisive
indicator. A sender domain of `paypa1-secure.com` with nothing else wrong would score 40 and come out
"Suspicious", which is the wrong answer — that domain alone is conclusive. Conversely, four pressure
phrases should not add up to a phishing verdict, which is what the `wording` cap prevents.

The rules can only raise a verdict, never lower one, and the reported score always matches the verdict.

---

## 8. Engine entry point (`engine.py`)

```python
def analyze(raw: bytes) -> Result:
    email = parse_email(raw)
    findings = []
    for check in (links.check, sender.check, wording.check, attachments.check):
        findings.extend(check(email))
    return build_result(findings)
```

Findings are returned in category order, and within a category in descending severity.

---

## 9. Command-line interface (`detect.py`)

```
python detect.py samples/paypal-phish.eml
```

Reads the file as bytes, calls `analyze`, prints a report. Exit code `0` for Safe, `1` for Suspicious,
`2` for Phishing, so the tool is usable in a pipeline. A `--json` flag prints the result as JSON instead.

Report format:

```
File:     samples/paypal-phish.eml
From:     "PayPal Support" <help@paypa1-secure.com>
Subject:  Your account has been suspended

Verdict:  PHISHING   (100/100)
Decided:  3 critical finding(s)

CRITICAL  [sender]       Domain imitates paypal.com by character substitution
                         paypa1-secure.com
CRITICAL  [links]        Link text shows www.paypal.com but points to 198.51.100.7
                         http://198.51.100.7/login
CRITICAL  [attachments]  Executable attachment
                         invoice.pdf.exe
HIGH      [sender]       Display name claims PayPal, domain does not belong to it
HIGH      [sender]       dmarc=fail in Authentication-Results
HIGH      [attachments]  Double extension disguises the real file type
MEDIUM    [sender]       Replies would go to mail-reset.xyz
LOW       [wording]      Pressure wording: "urgent", "suspended", "within 24 hours"

Category scores: links 70, sender 120, wording 15 (capped), attachments 65
```

---

## 10. Tests (`tests/`)

`pytest`, one file per check module plus one for scoring and one end-to-end.

Required coverage:

1. **Per check, the positive case.** A minimal crafted email that triggers exactly one finding, asserting
   the code and the severity.
2. **Per check, the negative case.** The legitimate equivalent produces nothing. In particular:
   `paypal.com` and `paypalobjects.com` produce no sender finding, and an anchor whose text and href
   agree produces no link finding.
3. **Scoring rules**, as a table-driven test:

   | findings | expected verdict | expected `decided_by` |
   |---|---|---|
   | one critical | Phishing | critical |
   | two high | Phishing | high-severity findings |
   | one high | Suspicious | one high-severity finding |
   | four wording (low) | Safe | cumulative score |
   | one medium + two low | Safe | cumulative score |
   | medium + medium + low | Suspicious | cumulative score |

4. **End-to-end over `samples/`.** Every file in `samples/` is asserted against its expected verdict.
   Keep the expectations in one dictionary at the top of the test so adding a sample means adding one
   line.
5. **Robustness.** Empty file, plain text with no headers, malformed MIME, and an attachment with a
   corrupt ZIP payload must all return a `Result` rather than raising.

---

## 11. Deliberately out of scope

- **Reputation lookups.** No VirusTotal, no URL reputation APIs. They introduce a secret to manage, a
  rate limit, and an outbound dependency during the demo.
- **Sandboxing or opening attachments.** Bytes are read, nothing is executed or written to disk.
- **Hebrew wording lists.** The sample corpus is English; adding a second language without samples to
  validate it would be untested code.
- **Machine-learned weights.** The weights are hand-tuned against the sample corpus. A learned model
  would need a labelled dataset and would make the verdict unexplainable, which is the opposite of what
  this tool needs to be.
- **History as a signal.** Checking whether a sender domain appeared in earlier scans belongs to the
  application layer, since it needs the database. It is specified separately with the web application.
