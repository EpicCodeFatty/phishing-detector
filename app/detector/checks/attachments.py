"""Attachment checks: what an attached file really is, judged from its name and bytes.

Attachments are only ever read in memory. Nothing is written to disk, extracted
or executed.
"""

import io
import zipfile

from ..lists import DANGEROUS_EXT, MACRO_EXT, MAGIC
from ..models import Attachment, Finding, ParsedEmail, finding

CATEGORY = "attachments"

# Severity per finding code, in the order findings of equal severity are reported.
SEVERITIES = {
    "dangerous_ext": "critical",
    "type_mismatch": "critical",
    "double_ext": "high",
    "macro_ext": "high",
    "macro_inside": "high",
}

# Invisible characters that change the direction text is drawn in. With a
# right-to-left override (U+202E) after "invoice", the name "invoicegpj.exe" is
# displayed as "invoiceexe.jpg". These are the embedding, override and isolate
# controls, U+202A to U+202E and U+2066 to U+2069, built from their code points
# because written out they would be invisible in this file too.
_BIDI_CONTROL_RANGES = (range(0x202A, 0x202F), range(0x2066, 0x206A))
_BIDI_CONTROLS = "".join(chr(code) for codes in _BIDI_CONTROL_RANGES for code in codes)
_REMOVE_BIDI_CONTROLS = str.maketrans("", "", _BIDI_CONTROLS)

# Windows ignores trailing dots and spaces, so "setup.exe." still runs as an executable.
_IGNORED_TRAILING_CHARACTERS = ". "

# The part every macro-enabled Office document stores its VBA project in.
_MACRO_ENTRY = "vbaproject.bin"

# What zipfile raises for an archive it cannot list: a damaged structure, a format
# version it does not support, or an entry name that is not valid text.
_UNREADABLE_ARCHIVE_ERRORS = (zipfile.BadZipFile, NotImplementedError, UnicodeDecodeError)

_UNNAMED = "(unnamed attachment)"

# Every extension MAGIC can vouch for, whichever signature it belongs to.
_KNOWN_EXTENSIONS = frozenset(
    extension for extensions in MAGIC.values() for extension in extensions
)


def check(email: ParsedEmail) -> list[Finding]:
    """Inspect every attachment's filename, magic bytes and archive contents.

    Produces: dangerous_ext, type_mismatch, double_ext, macro_ext, macro_inside.

    One finding per code per attachment, with the normalised filename as evidence.
    """
    findings = []
    for attachment in email.attachments:
        findings.extend(_inspect(attachment))
    return findings


def normalize_filename(filename: str) -> str:
    """Return the filename as the operating system will treat it, lowercased.

    Strips text-direction controls, surrounding whitespace and trailing dots, all
    of which can make the real extension look like something else.
    """
    visible = filename.translate(_REMOVE_BIDI_CONTROLS).strip()
    return visible.rstrip(_IGNORED_TRAILING_CHARACTERS).lower()


def _inspect(attachment: Attachment) -> list[Finding]:
    name = normalize_filename(attachment.filename)
    extensions = _extensions_of(name)
    final_extension = extensions[-1] if extensions else ""
    label = name or _UNNAMED

    findings = []
    if final_extension in DANGEROUS_EXT:
        findings.append(_found("dangerous_ext", "Executable attachment", label))
    if _contradicts_magic(final_extension, attachment.head):
        reason = f"File content does not match its .{final_extension} extension"
        findings.append(_found("type_mismatch", reason, label))
    if len(extensions) > 1 and final_extension in DANGEROUS_EXT:
        reason = "Double extension disguises the real file type"
        findings.append(_found("double_ext", reason, label))
    if final_extension in MACRO_EXT:
        findings.append(_found("macro_ext", "Office format that can carry macros", label))
    if _holds_macros(attachment.payload):
        findings.append(_found("macro_inside", "Office document contains a VBA macro", label))
    return findings


def _found(code: str, reason: str, evidence: str) -> Finding:
    return finding(CATEGORY, code, SEVERITIES[code], reason, evidence)


def _extensions_of(name: str) -> list[str]:
    """Return every extension of a filename: ['pdf', 'exe'] for 'invoice.pdf.exe'."""
    return [part for part in name.split(".")[1:] if part]


def _contradicts_magic(extension: str, head: bytes) -> bool:
    """Tell whether the magic bytes identify a different type than the extension claims.

    Only an extension that MAGIC knows under some other signature can be
    contradicted. An extension MAGIC has never heard of (.epub is a ZIP container
    too), a missing extension and an unknown signature are not evidence of anything.
    """
    if extension not in _KNOWN_EXTENSIONS:
        return False
    # Longest signature first, so a short one cannot shadow a more specific match.
    for signature in sorted(MAGIC, key=len, reverse=True):
        if head.startswith(signature):
            return extension not in MAGIC[signature]
    return False


def _holds_macros(payload: bytes) -> bool:
    """Tell whether the payload is a ZIP container with a vbaProject.bin entry.

    Only the archive's table of contents is read; nothing is extracted. A payload
    that is not a readable archive holds no macros as far as this check can tell.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            entries = archive.namelist()
    except _UNREADABLE_ARCHIVE_ERRORS:
        return False
    return any(entry.rpartition("/")[2].lower() == _MACRO_ENTRY for entry in entries)
