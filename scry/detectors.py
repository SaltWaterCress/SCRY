"""Sensitive information type (SIT) detectors.

Each info type = a regex + an optional validator (checksum) + optional
context keywords. Context keywords are what keep false positives down:
a 12-digit number that passes the Verhoeff checksum is only reported as
an Aadhaar number if the word "Aadhaar" (or similar) appears nearby.

Raw matched values are never returned to the caller. Every finding is
reduced to a masked preview and a salted SHA-256 fingerprint.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

# --------------------------------------------------------------------------
# Validators
# --------------------------------------------------------------------------
_VD = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VP = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 7, 6, 8, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def verhoeff_ok(value: str) -> bool:
    """Checksum used by Aadhaar numbers."""
    n = digits(value)
    if not n:
        return False
    c = 0
    for i, ch in enumerate(reversed(n)):
        c = _VD[c][_VP[i % 8][int(ch)]]
    return c == 0


def luhn_ok(value: str) -> bool:
    """Checksum used by payment cards and Canadian SINs."""
    n = digits(value)
    if not n:
        return False
    total = 0
    for i, ch in enumerate(reversed(n)):
        d = int(ch) * (2 if i % 2 else 1)
        total += d - 9 if d > 9 else d
    return total % 10 == 0


def card_ok(value: str) -> bool:
    n = digits(value)
    if len(n) not in (15, 16) or n[0] not in "3456":
        return False
    if len(set(n)) < 4:  # 4444444444444448 etc.
        return False
    return luhn_ok(n)


def aadhaar_ok(value: str) -> bool:
    n = digits(value)
    return len(n) == 12 and n[0] not in "01" and len(set(n)) > 3 and verhoeff_ok(n)


def sin_ok(value: str) -> bool:
    n = digits(value)
    return len(n) == 9 and n[0] not in "08" and luhn_ok(n)


# --------------------------------------------------------------------------
# Info type definitions
# --------------------------------------------------------------------------
@dataclass
class InfoType:
    key: str
    name: str
    category: str               # Government ID, Financial, Contact, Credential, HR
    sensitivity: int            # 1 (low) .. 4 (highly confidential)
    pattern: re.Pattern
    validator: Optional[Callable[[str], bool]] = None
    context: Optional[re.Pattern] = None   # keyword that must appear near the match
    window: int = 120                      # characters either side to look for context
    mask_keep: int = 4                     # trailing characters left visible
    description: str = ""
    tags: list = field(default_factory=list)


def _kw(*words: str) -> re.Pattern:
    return re.compile(r"(?i)\b(?:" + "|".join(words) + r")")


INFO_TYPES: list[InfoType] = [
    # ---- Government IDs ---------------------------------------------------
    InfoType("aadhaar", "Aadhaar number", "Government ID", 4,
             re.compile(r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b"),
             aadhaar_ok, _kw("aadha+r", "aadhar", "uidai", "enrol(?:l)?ment", "unique identification", "VID"),
             description="12-digit Indian national ID (Verhoeff checksum + keyword)"),
    InfoType("pan", "PAN (India)", "Government ID", 3,
             re.compile(r"\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b"),
             description="Indian Permanent Account Number (structure check)"),
    InfoType("passport_in", "Passport number (India)", "Government ID", 4,
             re.compile(r"\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b"),
             None, _kw("passport", "republic of india", "nationality", "place of issue"),
             description="Indian passport number (keyword required)"),
    InfoType("ssn_us", "US Social Security number", "Government ID", 4,
             re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
             None, _kw("ssn", "social security", "SS#", "taxpayer"),
             description="US SSN in NNN-NN-NNNN format (keyword required)"),
    InfoType("sin_ca", "Canadian SIN", "Government ID", 4,
             re.compile(r"\b\d{3}[ -]\d{3}[ -]\d{3}\b"),
             sin_ok, _kw("SIN", "social insurance", "numéro d'assurance sociale", "NAS"),
             description="Canadian Social Insurance Number (Luhn + keyword)"),
    InfoType("dl_in", "Driving licence (India)", "Government ID", 3,
             re.compile(r"\b[A-Z]{2}[ -]?\d{2}[ -]?(?:19|20)\d{2}[ -]?\d{7}\b"),
             None, _kw("driving", "licen[cs]e", "DL No"),
             description="Indian driving licence number (keyword required)"),

    # ---- Financial ---------------------------------------------------------
    InfoType("card", "Payment card number", "Financial", 4,
             re.compile(r"\b(?:\d[ -]?){14,15}\d\b"),
             card_ok, _kw("card", "visa", "mastercard", "amex", "rupay", "expiry", "valid thru", "cvv"),
             description="Credit/debit card (Luhn + IIN + keyword)"),
    InfoType("bank_account", "Bank account number", "Financial", 3,
             re.compile(r"(?i)\b(?:a/?c|acct|account)\s*(?:no\.?|number|#)?\s*[:\-]?\s*(\d{9,18})\b"),
             description="Account number labelled as such"),
    InfoType("ifsc", "IFSC code", "Financial", 2,
             re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
             description="Indian bank branch code"),
    InfoType("swift", "SWIFT / BIC code", "Financial", 2,
             re.compile(r"\b[A-Z]{4}(?:IN|US|CA|GB|AE|SG)[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b"),
             None, _kw("swift", "bic", "wire", "beneficiary bank", "correspondent"),
             description="International bank identifier (keyword required)"),
    InfoType("iban", "IBAN", "Financial", 3,
             re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}(?:\s?[A-Z0-9]{1,3})?\b"),
             None, _kw("iban"),
             description="International bank account number (keyword required)"),
    InfoType("gstin", "GSTIN", "Financial", 1,
             re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b"),
             description="Indian GST registration (business identifier)"),
    InfoType("salary", "Salary / compensation", "HR", 3,
             re.compile(r"(?i)\b(?:gross salary|net pay|net salary|basic salary|take[- ]home|cost to company|CTC|total earnings|payslip|pay slip)\b"),
             mask_keep=99, description="Compensation details (keyword-based)"),

    # ---- Contact / personal ------------------------------------------------
    InfoType("email", "Email address", "Contact", 1,
             re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b"),
             description="Email address"),
    InfoType("phone", "Phone number", "Contact", 1,
             re.compile(r"(?:\+91[\s-]?[6-9]\d{4}[\s-]?\d{5}\b|\b[6-9]\d{9}\b|\+1[\s-]?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{4}\b)"),
             description="Indian or North-American phone number"),
    InfoType("dob", "Date of birth", "Personal", 2,
             re.compile(r"(?i)\b(?:date of birth|DOB|D\.O\.B\.?|born on)\b\s*[:\-]?\s*\d{1,2}[/\-. ]\w{2,9}[/\-. ]\d{2,4}"),
             mask_keep=0, description="Labelled date of birth"),

    # ---- Credentials / secrets ---------------------------------------------
    InfoType("aws_key", "AWS access key", "Credential", 4,
             re.compile(r"(?<![A-Za-z0-9/+])AKIA[0-9A-Z]{16}(?![A-Za-z0-9/+=])"),
             None, _kw("aws", "access[_ ]?key", "secret", "credentials", "boto"),
             description="AWS key ID (keyword required, so base64 blobs don't match)"),
    InfoType("private_key", "Private key", "Credential", 4,
             re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
             mask_keep=0, description="PEM private key block"),
    InfoType("github_token", "GitHub token", "Credential", 4,
             re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
             description="GitHub personal access token"),
    InfoType("generic_secret", "Password / API key in text", "Credential", 3,
             re.compile(r"(?i)\b(?:password|passwd|pwd|api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['\"]?([^\s'\"<>]{6,})"),
             description="Assignment of a password or API key"),
]

INFO_TYPES_BY_KEY = {t.key: t for t in INFO_TYPES}


# --------------------------------------------------------------------------
# Masking / fingerprinting
# --------------------------------------------------------------------------
def mask(value: str, keep: int = 4) -> str:
    v = value.strip()
    if keep >= 99:
        return v[:40]
    if keep <= 0:
        return "•" * min(len(v), 12)
    if "@" in v and keep == 4:  # email: keep first char + domain
        user, _, dom = v.partition("@")
        return f"{user[:1]}•••@{dom}"
    alnum = [c for c in v if c.isalnum()]
    tail = "".join(alnum[-keep:]) if len(alnum) > keep else ""
    return "•" * max(len(alnum) - len(tail), 4) + tail


def fingerprint(value: str, salt: str) -> str:
    norm = re.sub(r"[\s\-]", "", value).upper()
    return hashlib.sha256((salt + norm).encode()).hexdigest()[:16]


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------
@dataclass
class Finding:
    info_type: str
    masked: str
    fp: str          # salted fingerprint, lets you dedupe values across files
    confidence: str  # high / medium


def scan_text(text: str, salt: str = "", types: Iterable[InfoType] = INFO_TYPES,
              max_per_type: int = 500) -> list[Finding]:
    out: list[Finding] = []
    if not text:
        return out
    for t in types:
        seen: set[str] = set()
        for m in t.pattern.finditer(text):
            raw = m.group(1) if m.groups() and m.group(1) else m.group(0)
            if t.validator and not t.validator(raw):
                continue
            conf = "high" if t.validator else "medium"
            if t.context is not None:
                lo, hi = max(0, m.start() - t.window), m.end() + t.window
                if not t.context.search(text[lo:hi]):
                    continue
                conf = "high"
            fp = fingerprint(raw, salt)
            if fp in seen:
                continue
            seen.add(fp)
            out.append(Finding(t.key, mask(raw, t.mask_keep), fp, conf))
            if len(seen) >= max_per_type:
                break
    return out
